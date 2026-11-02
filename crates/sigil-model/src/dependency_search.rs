//! Pure source-component indexing and grounded contextual chain proofs. No I/O.
use crate::dependency_path::{checked_join, MAX_LOOKUP_BYTES, MAX_LOOKUP_COMPONENTS};
use crate::{
    BinaryFacts, ContainerFacts, InstanceId, ProcessRef, ProcessValue, Relation, SliceId, TriValue,
    ValueId, ValueKey,
};
use std::collections::{HashMap, HashSet};
use std::ops::Range;

/// The deliberately limited default directory model, shared with the analyzer.
pub const DEFAULT_DIRS: [&[u8]; 4] = [b"/lib", b"/usr/lib", b"/lib64", b"/usr/lib64"];

struct Parts<'a> {
    bytes: &'a [u8],
    spans: Vec<Range<usize>>,
}
impl<'a> Parts<'a> {
    fn new(bytes: &'a [u8], semicolon: bool) -> Self {
        let mut start = 0;
        let mut spans = vec![];
        for (i, b) in bytes.iter().enumerate() {
            if *b == b':' || (semicolon && *b == b';') {
                spans.push(start..i);
                start = i + 1;
            }
        }
        spans.push(start..bytes.len()); // empty input and final empty component are real entries
        Self { bytes, spans }
    }
    fn get(&self, component: u64) -> Option<&'a [u8]> {
        let component = usize::try_from(component).ok()?;
        self.spans
            .get(component)
            .map(|span| &self.bytes[span.clone()])
    }
}
struct ElfParts<'a> {
    needed: HashSet<&'a crate::UntrustedText>,
    rpath: Vec<Parts<'a>>,
    runpath: Vec<Parts<'a>>,
}

/// Offsets are built once per first binary/value row, never per placement or Candidate.
/// Selecting a claimed source component is constant time after ID lookup, even for a
/// million separators or u64::MAX component indices in saved JSON.
#[derive(Default)]
pub struct SearchPartsIndex<'a> {
    elf: HashMap<&'a str, ElfParts<'a>>,
    environment: HashMap<&'a str, Parts<'a>>,
}
impl<'a> SearchPartsIndex<'a> {
    pub fn new(binaries: &'a [BinaryFacts], values: &'a [ProcessValue]) -> Self {
        let mut out = Self::default();
        let mut seen = HashSet::new();
        for binary in binaries {
            if !seen.insert(binary.slice.as_str()) {
                continue;
            }
            if let ContainerFacts::Elf(elf) = &binary.container {
                out.elf.insert(
                    binary.slice.as_str(),
                    ElfParts {
                        needed: elf.needed.iter().collect(),
                        rpath: elf
                            .rpath
                            .iter()
                            .map(|s| Parts::new(s.as_bytes(), false))
                            .collect(),
                        runpath: elf
                            .runpath
                            .iter()
                            .map(|s| Parts::new(s.as_bytes(), false))
                            .collect(),
                    },
                );
            }
        }
        seen.clear();
        for value in values {
            if !seen.insert(value.id.as_str()) {
                continue;
            }
            if matches!(&value.key, ValueKey::Env(name) if name.as_bytes() == b"LD_LIBRARY_PATH") {
                if let TriValue::Known(text) = &value.value {
                    out.environment
                        .insert(value.id.as_str(), Parts::new(text.as_bytes(), true));
                }
            }
        }
        out
    }
    pub fn elf(
        &self,
        slice: &SliceId,
        runpath: bool,
        entry: u64,
        component: u64,
    ) -> Result<&'a [u8], &'static str> {
        let paths = self
            .elf
            .get(slice.as_str())
            .ok_or("search witness ELF facts unavailable")?;
        let entries = if runpath {
            &paths.runpath
        } else {
            &paths.rpath
        };
        let entry =
            usize::try_from(entry).map_err(|_| "search witness entry/component is out of range")?;
        entries
            .get(entry)
            .and_then(|p| p.get(component))
            .ok_or("search witness entry/component is out of range")
    }
    pub fn needed(&self, slice: &SliceId, needed: &crate::UntrustedText) -> bool {
        self.elf
            .get(slice.as_str())
            .is_some_and(|elf| elf.needed.contains(needed))
    }
    pub fn environment(&self, value: &ValueId, component: u64) -> Result<&'a [u8], &'static str> {
        self.environment
            .get(value.as_str())
            .and_then(|parts| parts.get(component))
            .ok_or("search witness environment component is out of range")
    }
}

/// Absolutize already expanded bytes; the caller supplies an explicitly qualified cwd.
/// The bool records whether cwd was actually needed, for exact contextual input accounting.
pub fn absolute(path: &[u8], cwd: Option<&[u8]>) -> Result<(Vec<u8>, bool), &'static str> {
    fn bounded(path: &[u8]) -> Result<(), &'static str> {
        if path.len() > MAX_LOOKUP_BYTES {
            return Err("dependency path: lookup byte limit 65536 exceeded");
        }
        if path.split(|b| *b == b'/').filter(|p| !p.is_empty()).count() > MAX_LOOKUP_COMPONENTS {
            return Err("dependency path: lookup component limit 256 exceeded");
        }
        if path.contains(&0) {
            return Err("dependency path: NUL byte");
        }
        Ok(())
    }
    bounded(path)?;
    if path.starts_with(b"/") {
        return Ok((path.to_vec(), false));
    }
    let cwd = cwd.ok_or("dependency cwd: qualified same-process cwd required")?;
    bounded(cwd)?;
    if !cwd.starts_with(b"/") || cwd.ends_with(b" (deleted)") {
        return Err("dependency cwd: qualified absolute nondeleted cwd required");
    }
    if path.is_empty() {
        return Ok((cwd.to_vec(), true));
    }
    checked_join(cwd, path)
        .map(|path| (path, true))
        .map_err(|gap| gap.message())
}

/// Only locally valid contextual Candidates may ground an additional chain node.
/// A prefix is keyed by full ProcessRef (or static None) and ordered InstanceIds.
/// Length ordering prevents mutual/cyclic claims from bootstrapping their own evidence.
pub fn ungrounded(relations: &[Relation], locally_valid: &[bool]) -> Vec<usize> {
    chain_check(relations, locally_valid, || {})
}
fn chain_check(
    relations: &[Relation],
    locally_valid: &[bool],
    mut query: impl FnMut(),
) -> Vec<usize> {
    let mut rows: Vec<_> = relations
        .iter()
        .enumerate()
        .filter_map(|(i, r)| match r {
            Relation::Candidate {
                context: Some(c), ..
            } if locally_valid.get(i) == Some(&true) && !c.loader_chain.is_empty() => {
                Some((c.loader_chain.len(), i))
            }
            _ => None,
        })
        .collect();
    rows.sort_unstable(); // length then original row; diagnostics are restored below
    let mut roots: HashMap<(Option<&ProcessRef>, &InstanceId), usize> = HashMap::new();
    let mut children: HashMap<(usize, &InstanceId), usize> = HashMap::new();
    let mut next = 0usize;
    let mut missing = vec![];
    'row: for (_, i) in rows {
        query();
        let Relation::Candidate {
            candidate,
            context: Some(c),
            ..
        } = &relations[i]
        else {
            continue;
        };
        let Some(first) = c.loader_chain.first() else {
            continue;
        };
        let mut node = *roots.entry((c.process.as_ref(), first)).or_insert_with(|| {
            let id = next;
            next += 1;
            id
        });
        for instance in &c.loader_chain[1..] {
            query();
            let Some(child) = children.get(&(node, instance)) else {
                missing.push(i);
                continue 'row;
            };
            node = *child;
        }
        // The locally validated row's requester is the chain's last node, its declaration
        // names this exact terminal Candidate, and its rule/path/input witness is valid.
        query();
        children.entry((node, candidate)).or_insert_with(|| {
            let id = next;
            next += 1;
            id
        });
    }
    missing.sort_unstable();
    missing
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_component_offsets_preserve_empties_and_separator_rules() {
        let p = Parts::new(b":$ORIGIN/x::a;b:", false);
        let got: Vec<_> = (0..5).map(|i| p.get(i).unwrap()).collect();
        assert_eq!(got, [b"".as_slice(), b"$ORIGIN/x", b"", b"a;b", b""]);
        assert_eq!(p.get(u64::MAX), None);
        let p = Parts::new(b":a;b:", true);
        assert_eq!(
            (0..4).map(|i| p.get(i).unwrap()).collect::<Vec<_>>(),
            [b"".as_slice(), b"a", b"b", b""]
        );
        assert_eq!(Parts::new(b"", false).get(0), Some(b"".as_slice()));
    }
    #[test]
    fn source_component_selection_does_not_scan_to_the_claimed_index() {
        let bytes = vec![b':'; 65_536];
        let parts = Parts::new(&bytes, false);
        for _ in 0..8_192 {
            assert_eq!(parts.get(65_536), Some(b"".as_slice()));
            assert_eq!(parts.get(u64::MAX), None);
        }
    }
    #[test]
    fn absolutization_preserves_recorded_bytes_and_requires_qualified_cwd() {
        assert_eq!(absolute(b"", Some(b"/scan")), Ok((b"/scan".to_vec(), true)));
        assert_eq!(
            absolute(b"lib/../x", Some(b"/scan/")),
            Ok((b"/scan/lib/../x".to_vec(), true))
        );
        assert!(absolute(b"lib", None).is_err());
        assert!(absolute(b"lib", Some(b"/scan (deleted)")).is_err());
        assert_eq!(absolute(b"/lib", None), Ok((b"/lib".to_vec(), false)));
    }
    fn edge(chain: &[&str], candidate: &str, process: Option<ProcessRef>) -> Relation {
        use crate::{DependencyContext, DependencySearch, SearchRule};
        let id = |name| InstanceId::new(format!("inst:install/{name}")).unwrap();
        Relation::Candidate {
            from: SliceId::new(format!("sha256:{}#x86_64@0", "1".repeat(64))).unwrap(),
            needed: "/scan/leaf".into(),
            candidate: id(candidate),
            via: SearchRule::DirectPath,
            context: Some(DependencyContext {
                requester: id(chain.last().unwrap()),
                search_dir: "/scan".into(),
                process,
                values: vec![],
                loader_chain: chain.iter().map(|name| id(name)).collect(),
                search: DependencySearch::DirectPath,
            }),
        }
    }
    #[test]
    fn chain_grounding_requires_valid_prefixes_of_the_same_process_and_order() {
        let rows = [
            edge(&["root", "mid"], "tail", None),
            edge(&["root"], "mid", None),
        ];
        assert!(ungrounded(&rows, &[true, true]).is_empty());
        assert_eq!(ungrounded(&rows, &[true, false]), vec![0]);
        let process = ProcessRef {
            pid: 1,
            start_ticks: 2,
            boot_id: "b".into(),
        };
        let rows = [
            edge(&["root", "mid"], "tail", Some(process)),
            edge(&["root"], "mid", None),
        ];
        assert_eq!(ungrounded(&rows, &[true, true]), vec![0]);
        let rows = [edge(&["a", "b"], "a", None), edge(&["b", "a"], "b", None)];
        assert_eq!(ungrounded(&rows, &[true, true]), vec![0, 1]);
    }
    fn grounding_charges(n: usize) -> usize {
        let mut rows = vec![];
        for i in 0..n {
            let root = format!("root-{i}");
            let mid = format!("mid-{i}");
            // Deliberately place the longer chain first to test length-ordered grounding.
            rows.push(edge(&[&root, &mid], "tail", None));
            rows.push(edge(&[&root], &mid, None));
        }
        let mut charges = 0;
        assert!(chain_check(&rows, &vec![true; rows.len()], || charges += 1).is_empty());
        assert_eq!(charges, 5 * n); // two row visits, one prefix step, two inserts per pair
        charges
    }
    #[test]
    fn grounded_prefix_trie_has_linear_queries_after_one_length_sort() {
        assert_eq!(grounding_charges(8_192), grounding_charges(1_024) * 8);
    }
}
