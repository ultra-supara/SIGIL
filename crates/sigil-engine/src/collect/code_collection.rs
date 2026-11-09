//! Code-enabled collection: discover every placement before selecting a run mode, then verify
//! and analyze each content once. No file descriptors or whole-file buffers survive discovery.

use std::collections::BTreeMap;
use std::path::PathBuf;

use sigil_model::{
    ArtifactId, BudgetUse, DiscoverySource, FileInstance, Format, RootId, Sha256Hex, Stability,
};

use super::binread::Scanning;
use super::fs::{FileRead, FsBudgets, ReadOutcome, ReadSpec, RelPath, SafeFs};
use crate::binary::scan::{ScanOutcome, Sought};
use crate::binary::{self, BinaryBudgets, ParsedArtifact};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionUsage {
    pub discovery_hash: BudgetUse,
    pub discovery_probe: BudgetUse,
    pub revalidation: BudgetUse,
}

impl CollectionUsage {
    /// Additional marked-session diagnostics; legacy sessions retain their original bytes.
    pub(crate) fn record(
        &self,
        budgets: &mut BTreeMap<String, u64>,
        coverage: &mut Vec<sigil_model::Coverage>,
    ) -> Result<(), String> {
        for (check, usage) in [
            ("binary.collection.hash", &self.discovery_hash),
            ("binary.collection.probe", &self.discovery_probe),
            ("binary.collection.revalidation", &self.revalidation),
        ] {
            budgets.insert(usage.budget.clone(), usage.limit);
            coverage.push(sigil_model::Coverage {
                check: sigil_model::CheckId::new(check).map_err(|e| e.to_string())?,
                scope: sigil_model::Ref::Audit,
                state: sigil_model::CoverageState::Complete,
                budget: Some(usage.clone()),
            });
        }
        Ok(())
    }
}

#[derive(Clone)]
struct Placement {
    root: RootId,
    directory: PathBuf,
    directory_id: (u64, u64),
    rel: RelPath,
    instance: FileInstance,
    artifact: ArtifactId,
    size: u64,
    scan: bool,
}

pub(crate) struct Collection {
    pub multiarch: bool,
    pub usage: CollectionUsage,
    placements: BTreeMap<ArtifactId, Vec<Placement>>,
}

impl Collection {
    pub fn new(bytes: u64) -> Self {
        let budget = |name: &str, limit| BudgetUse {
            budget: name.into(),
            used: 0,
            limit,
        };
        Self {
            multiarch: false,
            usage: CollectionUsage {
                // One extra byte is reserved for the hash reader's growth detection.
                discovery_hash: budget("binary_discovery_hash_bytes", bytes.saturating_add(1)),
                discovery_probe: budget("binary_discovery_probe_bytes", bytes),
                revalidation: budget("binary_revalidation_bytes", bytes.saturating_add(1)),
            },
            placements: BTreeMap::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn discover(
        &mut self,
        fs: &SafeFs,
        root: &RootId,
        rel: &RelPath,
        limit: u64,
        source: Vec<DiscoverySource>,
        budgets: BinaryBudgets,
        scanning: Scanning<'_>,
        during: &dyn Fn(&RelPath),
    ) -> FileRead {
        let remaining = self
            .usage
            .discovery_hash
            .limit
            .saturating_sub(self.usage.discovery_hash.used);
        if remaining == 0 {
            self.multiarch = true;
            return FileRead {
                instance: None,
                artifact: None,
                prefix: vec![],
                hash_bytes_read: 0,
                outcome: ReadOutcome::Failed("code discovery hash budget exhausted".into()),
            };
        }
        let (mut read, probe) = fs.read_entry_with(
            root,
            rel,
            ReadSpec {
                keep: 64,
                limit: Some(limit.min(remaining - 1)),
            },
            source,
            |input| {
                during(rel);
                let left = self
                    .usage
                    .discovery_probe
                    .limit
                    .saturating_sub(self.usage.discovery_probe.used);
                binary::probe_multiarch(
                    input.file,
                    input.size,
                    input.prefix,
                    budgets.parse_bytes,
                    left,
                )
            },
        );
        self.usage.discovery_hash.used += read.hash_bytes_read;
        if probe.is_none() {
            self.multiarch = true;
        }
        if let Some(probe) = probe {
            self.usage.discovery_probe.used += probe.bytes_read;
            // Unknown recognition cannot authorize historical independent x86 work caps.
            self.multiarch |= probe.recognized != Some(false);
            if let Some(artifact) = read.artifact.as_mut() {
                artifact.format = if let Some((kind, _)) = binary::header::read(&read.prefix) {
                    Format::Elf { kind }
                } else if probe.recognized == Some(true) {
                    match read.prefix.get(..4) {
                        Some(
                            [0xfe, 0xed, 0xfa, _]
                            | [0xce, 0xfa, 0xed, 0xfe]
                            | [0xcf, 0xfa, 0xed, 0xfe],
                        ) => Format::MachO,
                        _ => Format::MachOFat,
                    }
                } else {
                    Format::Other
                };
            }
        }
        if let (Some(instance), Some(artifact)) = (&read.instance, &read.artifact) {
            if instance.stability == Stability::NoChangeDetected {
                if let (Some(directory), Some(directory_id)) =
                    (fs.root_path(root), fs.root_id(root))
                {
                    self.placements
                        .entry(artifact.id.clone())
                        .or_default()
                        .push(Placement {
                            root: root.clone(),
                            directory: directory.to_path_buf(),
                            directory_id,
                            rel: rel.clone(),
                            instance: instance.clone(),
                            artifact: artifact.id.clone(),
                            size: artifact.size,
                            scan: rel
                                .name()
                                .is_none_or(|n| scanning.components.scans(n.as_bytes())),
                        });
                }
            }
        }
        read
    }

    pub fn analyze(
        &mut self,
        budgets: BinaryBudgets,
        scanning: Scanning<'_>,
        instances: &mut [FileInstance],
        parsed: &mut BTreeMap<ArtifactId, ParsedArtifact>,
    ) {
        self.analyze_with(budgets, scanning, instances, parsed, &|_| {});
    }

    fn analyze_with(
        &mut self,
        budgets: BinaryBudgets,
        scanning: Scanning<'_>,
        instances: &mut [FileInstance],
        parsed: &mut BTreeMap<ArtifactId, ParsedArtifact>,
        after_analysis: &dyn Fn(&RelPath),
    ) {
        for placements in self.placements.values_mut() {
            // A scannable placement runs the unchanged code-before-scan parser once, retaining
            // the exact cache and parse-budget state identity scanning historically observed.
            placements.sort_by_key(|p| !p.scan);
            for placement in placements {
                let left = self
                    .usage
                    .revalidation
                    .limit
                    .saturating_sub(self.usage.revalidation.used);
                if left == 0 {
                    break;
                }
                let mut fs = SafeFs::new(FsBudgets::default());
                if fs
                    .add_unlisted_root(placement.root.clone(), &placement.directory)
                    .is_err()
                {
                    continue;
                }
                if fs.root_id(&placement.root) != Some(placement.directory_id)
                    || fs.root_path(&placement.root) != Some(placement.directory.as_path())
                {
                    invalidate(instances, placement, Stability::ChangedDuringRead);
                    continue;
                }
                let mut attempted = false;
                let (read, result) = fs.read_entry_with(
                    &placement.root,
                    &placement.rel,
                    ReadSpec {
                        keep: 64,
                        limit: Some(left - 1),
                    },
                    placement.instance.discovered_by.clone(),
                    |input| {
                        if input.artifact != &placement.artifact || input.size != placement.size {
                            return None;
                        }
                        let st = rustix::fs::fstat(input.file).ok()?;
                        if super::fs::stat_info(&st) != placement.instance.stat {
                            return None;
                        }
                        let digest =
                            Sha256Hex::new(input.artifact.as_str().strip_prefix("sha256:")?)
                                .ok()?;
                        attempted = true;
                        let mut result = binary::parse_artifact_mode(
                            input.file,
                            input.size,
                            &digest,
                            input.prefix,
                            budgets,
                            placement.scan.then_some(Sought {
                                needles: scanning.needles,
                                functions: scanning.components.functions(),
                            }),
                            self.multiarch,
                        )?;
                        if !placement.scan && matches!(result.format, Format::Elf { .. }) {
                            for slice in &mut result.slices {
                                slice.scan.get_or_insert(ScanOutcome::NameAndHashOnly);
                            }
                        }
                        after_analysis(&placement.rel);
                        Some(result)
                    },
                );
                self.usage.revalidation.used += read.hash_bytes_read;
                let stable = read.instance.as_ref().is_some_and(|i| {
                    i.stability == Stability::NoChangeDetected && i.stat == placement.instance.stat
                }) && read
                    .artifact
                    .as_ref()
                    .is_some_and(|a| a.id == placement.artifact && a.size == placement.size);
                if stable {
                    if let Some(result) = result.flatten() {
                        parsed.insert(placement.artifact.clone(), result);
                    }
                } else if let Some(instance) = read.instance.as_ref().filter(|i| {
                    i.stability != Stability::NoChangeDetected || i.stat != placement.instance.stat
                }) {
                    invalidate(
                        instances,
                        placement,
                        if instance.stability == Stability::Vanished {
                            Stability::Vanished
                        } else {
                            Stability::ChangedDuringRead
                        },
                    );
                } else if read
                    .artifact
                    .as_ref()
                    .is_some_and(|a| a.id != placement.artifact || a.size != placement.size)
                {
                    invalidate(instances, placement, Stability::ChangedDuringRead);
                } else if matches!(
                    read.outcome,
                    ReadOutcome::NotFound
                        | ReadOutcome::NotRead(sigil_model::NotReadReason::Vanished)
                ) {
                    invalidate(instances, placement, Stability::Vanished);
                }
                // Even a result rejected by post-read stability checks has consumed its work.
                // Retry another alias only if no analysis was attempted on this content.
                if attempted {
                    break;
                }
            }
        }
    }
}

fn invalidate(instances: &mut [FileInstance], placement: &Placement, stability: Stability) {
    if let Some(instance) = instances.iter_mut().find(|i| i.id == placement.instance.id) {
        instance.stability = stability;
        instance.path_proof = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/code/spawn.so"),
        )
        .unwrap()
    }

    #[test]
    fn between_phase_changes_never_mix_evidence_and_stable_aliases_can_recover() {
        for change in ["content", "replace", "vanish"] {
            for duplicate in [false, true] {
                let d = tempfile::tempdir().unwrap();
                let bytes = fixture();
                let root = RootId::new("install").unwrap();
                let mut fs = SafeFs::new(FsBudgets::default());
                fs.add_root(root.clone(), d.path()).unwrap();
                let mut c = Collection::new(bytes.len() as u64 * 2);
                let budgets = BinaryBudgets {
                    code: Some(Default::default()),
                    ..Default::default()
                };
                let scanning = Scanning::embedded().unwrap();
                let mut instances = vec![];
                for name in if duplicate {
                    vec!["a.so", "b.so"]
                } else {
                    vec!["a.so"]
                } {
                    std::fs::write(d.path().join(name), &bytes).unwrap();
                    let read = c.discover(
                        &fs,
                        &root,
                        &RelPath::parse(name).unwrap(),
                        u64::MAX,
                        vec![],
                        budgets,
                        scanning,
                        &|_| {},
                    );
                    instances.push(read.instance.unwrap());
                }
                match change {
                    "content" => {
                        let mut changed = bytes.clone();
                        changed[64] ^= 1;
                        std::fs::write(d.path().join("a.so"), changed).unwrap();
                    }
                    "replace" => {
                        std::fs::write(d.path().join("replacement"), &bytes).unwrap();
                        std::fs::rename(d.path().join("replacement"), d.path().join("a.so"))
                            .unwrap();
                    }
                    "vanish" => std::fs::remove_file(d.path().join("a.so")).unwrap(),
                    _ => unreachable!(),
                }
                crate::code::CODE_ANALYSES.with(|n| n.set(0));
                let mut parsed = BTreeMap::new();
                c.analyze(budgets, scanning, &mut instances, &mut parsed);
                assert_eq!(parsed.len(), usize::from(duplicate), "{change}");
                assert_eq!(
                    crate::code::CODE_ANALYSES.with(|n| n.get()),
                    usize::from(duplicate)
                );
                assert_eq!(
                    instances[0].stability,
                    if change == "vanish" {
                        Stability::Vanished
                    } else {
                        Stability::ChangedDuringRead
                    }
                );
                let failed_bytes = if change == "vanish" {
                    0
                } else {
                    bytes.len() as u64
                };
                assert_eq!(
                    c.usage.revalidation.used,
                    failed_bytes + if duplicate { bytes.len() as u64 } else { 0 }
                );
                assert!(c.usage.revalidation.used <= c.usage.revalidation.limit);
            }
        }
    }

    #[test]
    fn rejected_analysis_is_not_repeated_and_revalidation_does_not_reset() {
        let d = tempfile::tempdir().unwrap();
        let bytes = fixture();
        let root = RootId::new("install").unwrap();
        let mut fs = SafeFs::new(FsBudgets::default());
        fs.add_root(root.clone(), d.path()).unwrap();
        let mut c = Collection::new(bytes.len() as u64 * 2);
        let budgets = BinaryBudgets {
            code: Some(Default::default()),
            ..Default::default()
        };
        let scanning = Scanning::embedded().unwrap();
        let mut instances = vec![];
        for name in ["a.so", "b.so"] {
            std::fs::write(d.path().join(name), &bytes).unwrap();
            let read = c.discover(
                &fs,
                &root,
                &RelPath::parse(name).unwrap(),
                u64::MAX,
                vec![],
                budgets,
                scanning,
                &|_| {},
            );
            instances.push(read.instance.unwrap());
        }
        crate::code::CODE_ANALYSES.with(|n| n.set(0));
        let mut parsed = BTreeMap::new();
        c.analyze_with(budgets, scanning, &mut instances, &mut parsed, &|rel| {
            std::fs::remove_file(d.path().join(rel.display())).unwrap();
        });
        assert!(parsed.is_empty());
        assert_eq!(crate::code::CODE_ANALYSES.with(|n| n.get()), 1);
        assert_eq!(c.usage.revalidation.used, bytes.len() as u64);
        assert_eq!(instances[0].stability, Stability::Vanished);
    }

    #[test]
    fn revalidation_cap_is_charged_before_attempts_and_prevents_analysis() {
        let d = tempfile::tempdir().unwrap();
        let bytes = fixture();
        let root = RootId::new("install").unwrap();
        let mut fs = SafeFs::new(FsBudgets::default());
        fs.add_root(root.clone(), d.path()).unwrap();
        let mut c = Collection::new(bytes.len() as u64);
        let budgets = BinaryBudgets {
            code: Some(Default::default()),
            ..Default::default()
        };
        let scanning = Scanning::embedded().unwrap();
        std::fs::write(d.path().join("a.so"), &bytes).unwrap();
        let read = c.discover(
            &fs,
            &root,
            &RelPath::parse("a.so").unwrap(),
            u64::MAX,
            vec![],
            budgets,
            scanning,
            &|_| {},
        );
        let mut instances = vec![read.instance.unwrap()];
        c.usage.revalidation.limit = bytes.len() as u64; // one byte too small to reserve growth detection
        crate::code::CODE_ANALYSES.with(|n| n.set(0));
        let mut parsed = BTreeMap::new();
        c.analyze(budgets, scanning, &mut instances, &mut parsed);
        assert!(parsed.is_empty());
        assert_eq!(crate::code::CODE_ANALYSES.with(|n| n.get()), 0);
        assert_eq!(c.usage.revalidation.used, 0); // rejected using fstat before I/O
    }
}
