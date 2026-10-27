//! Borrowed lookups for one validation. Indexing never changes the order of validation.
//!
//! A linear `find` picks the first record, even when IDs are duplicated. Keep that behavior:
//! validation reports duplicates but continues checking the rest of the session. Collections
//! used by rules that inspect *all* matching records retain those records instead.

use std::collections::{BTreeMap, BTreeSet};

use crate::artifact::{Artifact, FileInstance, Slice};
use crate::binary::{macho_architecture, BinaryFacts, ContainerFacts};
use crate::binary_input::{BINARY_CONTAINER, NAME_AND_HASH_ONLY};
use crate::coverage::Coverage;
use crate::evidence::Ref;
use crate::id::SliceId;
use crate::relation::{DeclKind, Relation};
use crate::session::{ScanRoot, Session};
use crate::text::UntrustedText;

#[derive(Default)]
pub(crate) struct SessionIndex<'a> {
    pub roots: BTreeMap<&'a str, &'a ScanRoot>,
    pub artifacts: BTreeMap<&'a str, &'a Artifact>,
    pub instances: BTreeMap<&'a str, &'a FileInstance>,
    pub binaries: BTreeMap<&'a str, &'a BinaryFacts>,
    /// First artifact and first slice with this ID, including the artifact's position.
    pub slices: BTreeMap<&'a str, (usize, &'a Artifact, &'a Slice)>,
    /// All slices of every artifact with this ID (C4 also examines duplicate artifacts).
    pub artifact_slices: BTreeMap<&'a str, BTreeSet<&'a SliceId>>,
    pub containers: BTreeMap<&'a str, Vec<&'a Coverage>>,
    pub name_and_hash_only: BTreeSet<&'a str>,
    /// Import name -> whether at least one matching import's library is looked up.
    pub imports: BTreeMap<&'a str, BTreeMap<&'a UntrustedText, bool>>,
    pub declarations: BTreeMap<&'a str, Vec<(DeclKind, &'a UntrustedText)>>,
    /// Distinct slice IDs per artifact position and fat-table architecture. All binary facts,
    /// including duplicate records, contribute; two records of one slice do not make it twice.
    pub fat_architectures: BTreeMap<(usize, (i32, u32)), BTreeSet<&'a str>>,
}

impl<'a> SessionIndex<'a> {
    pub fn new(s: &'a Session) -> Self {
        let mut index = Self::default();
        for root in &s.request.roots {
            index.roots.entry(root.id.as_str()).or_insert(root);
        }
        for (position, artifact) in s.artifacts.iter().enumerate() {
            index
                .artifacts
                .entry(artifact.id.as_str())
                .or_insert(artifact);
            let all = index
                .artifact_slices
                .entry(artifact.id.as_str())
                .or_default();
            for slice in &artifact.slices {
                index
                    .slices
                    .entry(slice.id.as_str())
                    .or_insert((position, artifact, slice));
                all.insert(&slice.id);
            }
        }
        for instance in &s.instances {
            index
                .instances
                .entry(instance.id.as_str())
                .or_insert(instance);
        }
        let mut architectures: BTreeMap<&str, BTreeSet<(i32, u32)>> = BTreeMap::new();
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
        for (slice, facts) in &index.binaries {
            let imports = index.imports.entry(*slice).or_default();
            match &facts.container {
                ContainerFacts::Elf(elf) => {
                    for import in &elf.imports {
                        imports.insert(&import.name, true);
                    }
                }
                ContainerFacts::MachO(macho) => {
                    for import in &macho.imports {
                        *imports.entry(&import.name).or_default() |= import.library.looked_up();
                    }
                }
            }
        }
        for coverage in &s.coverage {
            if coverage.check.as_str() == BINARY_CONTAINER {
                if let Ref::Instance(instance) = &coverage.scope {
                    index
                        .containers
                        .entry(instance.as_str())
                        .or_default()
                        .push(coverage);
                }
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
            Some(index) => match index.containers.get(instance.as_str())?.as_slice() {
                [entry] => Some(entry),
                _ => None,
            },
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
