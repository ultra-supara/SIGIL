//! Borrowed lookups for one validation. Indexing never changes the order of validation.
//!
//! A linear `find` picks the first record, even when IDs are duplicated. Keep that behavior:
//! validation reports duplicates but continues checking the rest of the session. Collections
//! used by rules that inspect *all* matching records retain those records instead.

use std::borrow::Borrow;
use std::collections::{hash_map::Entry, BTreeMap, HashMap, HashSet};

use crate::artifact::{Artifact, FileInstance, Slice};
use crate::binary::{macho_architecture, BinaryFacts, ContainerFacts, LookedUp};
use crate::binary_input::{
    is_binary_root, BINARY_CODE, BINARY_CONTAINER, BINARY_IDENTITY, NAME_AND_HASH_ONLY,
};
use crate::coverage::Coverage;
use crate::evidence::Ref;
use crate::id::SliceId;
use crate::relation::{DeclKind, Relation};
use crate::session::{ScanRoot, Session};
use crate::text::UntrustedText;

/// Small per-slice capability tables keep their first entry inline. Larger tables retain
/// sorted traversal: missing-import/call diagnostics must still appear in key order.
#[derive(Default)]
pub(crate) enum OrderedMap<K, V> {
    #[default]
    Empty,
    One((K, V)),
    Many(BTreeMap<K, V>),
}

impl<K: Ord, V> OrderedMap<K, V> {
    pub fn insert(&mut self, key: K, value: V) {
        match self {
            Self::Empty => *self = Self::One((key, value)),
            Self::One((old, v)) if *old == key => *v = value,
            Self::One(_) => {
                let Self::One(first) = std::mem::replace(self, Self::Empty) else {
                    unreachable!()
                };
                *self = Self::Many(BTreeMap::from([first, (key, value)]));
            }
            Self::Many(map) => {
                map.insert(key, value);
            }
        }
    }

    pub fn get<Q: Ord + ?Sized>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
    {
        match self {
            Self::Empty => None,
            Self::One((k, v)) => (k.borrow() == key).then_some(v),
            Self::Many(map) => map.get(key),
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        let (one, many) = match self {
            Self::Empty => (None, None),
            Self::One(entry) => (Some(entry), None),
            Self::Many(map) => (None, Some(map)),
        };
        one.into_iter()
            .map(|(k, v)| (k, v))
            .chain(many.into_iter().flat_map(|map| map.iter()))
    }
}

/// Rules which require exactly one record need its count and first entry, not a heap-allocated
/// list. Retain the count on invalid sessions too, for the existing diagnostics.
pub(crate) struct Occurrences<'a, T> {
    pub first: &'a T,
    pub count: usize,
}

impl<'a, T> Occurrences<'a, T> {
    pub fn unique(&self) -> Option<&'a T> {
        (self.count == 1).then_some(self.first)
    }
}

fn record<'a, T>(map: &mut HashMap<&'a str, Occurrences<'a, T>>, id: &'a str, value: &'a T) {
    map.entry(id)
        .and_modify(|entry| entry.count += 1)
        .or_insert(Occurrences {
            first: value,
            count: 1,
        });
}

fn first<'a, T>(
    map: &mut HashMap<&'a str, T>,
    id: &'a str,
    value: T,
    duplicates: &mut Vec<&'a str>,
) {
    match map.entry(id) {
        Entry::Vacant(entry) => {
            entry.insert(value);
        }
        Entry::Occupied(_) => duplicates.push(id),
    }
}

#[derive(Default)]
pub(crate) struct SessionIndex<'a> {
    pub roots: HashMap<&'a str, &'a ScanRoot>,
    pub artifacts: HashMap<&'a str, &'a Artifact>,
    pub instances: HashMap<&'a str, &'a FileInstance>,
    pub binaries: HashMap<&'a str, &'a BinaryFacts>,
    /// First artifact and first slice with this ID, including the artifact's position.
    pub slices: HashMap<&'a str, (usize, &'a Artifact, &'a Slice)>,
    pub duplicate_roots: Vec<&'a str>,
    pub duplicate_artifacts: Vec<&'a str>,
    pub duplicate_slices: Vec<&'a str>,
    pub duplicate_instances: Vec<&'a str>,
    /// B9 examines the last instance of an ID. C2/S1 instead examine the last *binary* instance
    /// of that ID, and report errors in ID order. Other lookups above keep the first instance.
    pub last_instances: HashMap<&'a str, &'a FileInstance>,
    pub binary_inputs: HashMap<&'a str, &'a FileInstance>,
    pub ordered_binary_inputs: Vec<&'a FileInstance>,
    pub by_root: HashMap<&'a str, Occurrences<'a, FileInstance>>,
    pub containers: HashMap<&'a str, Occurrences<'a, Coverage>>,
    pub code_coverage: HashMap<&'a str, Occurrences<'a, Coverage>>,
    pub identity_coverage: HashMap<&'a str, Occurrences<'a, Coverage>>,
    pub name_and_hash_only: HashSet<&'a str>,
    /// Import name -> how the slice's imports of that name are looked up (#105): the greatest
    /// over them. An ELF import is looked up for every name.
    pub imports: HashMap<(&'a str, &'a UntrustedText), LookedUp>,
    pub declarations: HashMap<&'a str, Vec<(DeclKind, &'a UntrustedText)>>,
    /// Distinct slice IDs per artifact position and fat-table architecture. All binary facts,
    /// including duplicate records, contribute; two records of one slice do not make it twice.
    pub fat_architectures: HashMap<(usize, (i32, u32)), HashSet<&'a str>>,
}

impl<'a> SessionIndex<'a> {
    pub fn new(s: &'a Session) -> Self {
        let mut coverage_counts = [0; 3];
        for coverage in &s.coverage {
            if matches!(coverage.scope, Ref::Instance(_)) {
                match coverage.check.as_str() {
                    BINARY_CONTAINER => coverage_counts[0] += 1,
                    BINARY_CODE => coverage_counts[1] += 1,
                    BINARY_IDENTITY => coverage_counts[2] += 1,
                    _ => {}
                }
            }
        }
        let mut index = Self {
            roots: HashMap::with_capacity(s.request.roots.len()),
            artifacts: HashMap::with_capacity(s.artifacts.len()),
            slices: HashMap::with_capacity(s.artifacts.iter().map(|a| a.slices.len()).sum()),
            instances: HashMap::with_capacity(s.instances.len()),
            last_instances: HashMap::with_capacity(s.instances.len()),
            binary_inputs: HashMap::with_capacity(
                s.instances
                    .iter()
                    .filter(|i| is_binary_root(&i.root))
                    .count(),
            ),
            by_root: HashMap::with_capacity(s.request.roots.len()),
            binaries: HashMap::with_capacity(s.binaries.len()),
            containers: HashMap::with_capacity(coverage_counts[0]),
            code_coverage: HashMap::with_capacity(coverage_counts[1]),
            identity_coverage: HashMap::with_capacity(coverage_counts[2]),
            ..Self::default()
        };
        for root in &s.request.roots {
            first(
                &mut index.roots,
                root.id.as_str(),
                root,
                &mut index.duplicate_roots,
            );
        }
        for (position, artifact) in s.artifacts.iter().enumerate() {
            first(
                &mut index.artifacts,
                artifact.id.as_str(),
                artifact,
                &mut index.duplicate_artifacts,
            );
            for slice in &artifact.slices {
                first(
                    &mut index.slices,
                    slice.id.as_str(),
                    (position, artifact, slice),
                    &mut index.duplicate_slices,
                );
            }
        }
        for instance in &s.instances {
            first(
                &mut index.instances,
                instance.id.as_str(),
                instance,
                &mut index.duplicate_instances,
            );
            index.last_instances.insert(instance.id.as_str(), instance);
            record(&mut index.by_root, instance.root.as_str(), instance);
            if is_binary_root(&instance.root) {
                index.binary_inputs.insert(instance.id.as_str(), instance);
            }
        }
        index.ordered_binary_inputs = index.binary_inputs.values().copied().collect();
        index.ordered_binary_inputs.sort_unstable_by_key(|i| &i.id);
        let mut architectures: HashMap<&str, HashSet<(i32, u32)>> = HashMap::new();
        for facts in &s.binaries {
            index.binaries.entry(facts.slice.as_str()).or_insert(facts);
            if let ContainerFacts::MachO(macho) = &facts.container {
                if let Some((cpu, subtype)) = macho.fat_cpu_type.zip(macho.fat_cpu_subtype) {
                    architectures
                        .entry(facts.slice.as_str())
                        .or_default()
                        .insert(macho_architecture(cpu, subtype));
                }
            }
        }
        for (position, artifact) in s.artifacts.iter().enumerate() {
            for slice in &artifact.slices {
                if let Some(tables) = architectures.get(slice.id.as_str()) {
                    for table in tables {
                        index
                            .fat_architectures
                            .entry((position, *table))
                            .or_default()
                            .insert(slice.id.as_str());
                    }
                }
            }
        }
        index.imports.reserve(
            index
                .binaries
                .values()
                .map(|facts| match &facts.container {
                    ContainerFacts::Elf(elf) => elf.imports.len(),
                    ContainerFacts::MachO(macho) => macho.imports.len(),
                })
                .sum(),
        );
        for (slice, facts) in &index.binaries {
            match &facts.container {
                ContainerFacts::Elf(elf) => {
                    for import in &elf.imports {
                        index.imports.insert((*slice, &import.name), LookedUp::All);
                    }
                }
                ContainerFacts::MachO(macho) => {
                    for import in &macho.imports {
                        let entry = index
                            .imports
                            .entry((*slice, &import.name))
                            .or_insert(LookedUp::No);
                        *entry = (*entry).max(import.library.looked_up());
                    }
                }
            }
        }
        for coverage in &s.coverage {
            if let Ref::Instance(instance) = &coverage.scope {
                let entries = match coverage.check.as_str() {
                    BINARY_CONTAINER => &mut index.containers,
                    BINARY_CODE => &mut index.code_coverage,
                    BINARY_IDENTITY => &mut index.identity_coverage,
                    _ => continue,
                };
                record(entries, instance.as_str(), coverage);
            }
        }
        for claim in &s.components {
            if NAME_AND_HASH_ONLY.contains(&claim.component.as_str()) {
                index.name_and_hash_only.insert(claim.subject.as_str());
            }
        }
        for relation in &s.relations {
            if let Relation::Declares { from, needed, kind } = relation {
                index
                    .declarations
                    .entry(from.as_str())
                    .or_default()
                    .push((*kind, needed));
            }
        }
        index
    }
}

/// Shared rules accept either a session alone (the existing single-input public helpers) or
/// the index already built by validation. A single-input caller need not build every index.
pub(crate) struct SessionLookup<'a> {
    pub session: &'a Session,
    pub index: Option<&'a SessionIndex<'a>>,
}

impl<'a> SessionLookup<'a> {
    pub fn artifact(&self, id: &crate::id::ArtifactId) -> Option<&'a Artifact> {
        match self.index {
            Some(index) => index.artifacts.get(id.as_str()).copied(),
            None => self.session.artifacts.iter().find(|a| a.id == *id),
        }
    }

    pub fn binary(&self, slice: &SliceId) -> Option<&'a BinaryFacts> {
        match self.index {
            Some(index) => index.binaries.get(slice.as_str()).copied(),
            None => self.session.binaries.iter().find(|b| b.slice == *slice),
        }
    }

    pub fn container_entry(&self, instance: &crate::id::InstanceId) -> Option<&'a Coverage> {
        match self.index {
            Some(index) => index.containers.get(instance.as_str())?.unique(),
            None => {
                let mut entries = self.session.coverage.iter().filter(|c| {
                    c.check.as_str() == BINARY_CONTAINER
                        && matches!(&c.scope, Ref::Instance(id) if id == instance)
                });
                let first = entries.next()?;
                entries.next().is_none().then_some(first)
            }
        }
    }

    pub fn name_and_hash_only(&self, slice: &SliceId) -> bool {
        match self.index {
            Some(index) => index.name_and_hash_only.contains(slice.as_str()),
            None => {
                self.session.components.iter().any(|c| {
                    c.subject == *slice && NAME_AND_HASH_ONLY.contains(&c.component.as_str())
                })
            }
        }
    }
}
