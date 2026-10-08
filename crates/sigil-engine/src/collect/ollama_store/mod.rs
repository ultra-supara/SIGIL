//! The Ollama model store (plan §4.6.7): manifests under `manifests/`, blobs under `blobs/`.
//!
//! [`collect`] records facts only: instances and artifacts read through SafeFs, one [`Model`] per
//! manifest, and the inventory coverage. Findings and the per-model checks are derived from these
//! facts by [`crate::analyze::model_store`].
//!
//! - The model filter applies before a manifest is read (I-05).
//! - A manifest is read once, with a byte limit (I-04).
//! - A blob is looked up only for a well-formed digest (I-06). It is read once per run, and only
//!   inside the scan roots (I-07).
//! - Walking `manifests/` is bounded and ends on loops (I-03). FIFOs and other special files are
//!   not manifests.

pub mod layout;
pub mod license;
pub mod manifest;

use std::collections::BTreeMap;

use sigil_model::{
    Artifact, BudgetUse, CheckId, Coverage, CoverageState, DiscoverySource, FileInstance,
    InstanceContent, InstanceId, LicenseText, Model, ModelId, ModelLayer, NotReadReason, Ref,
    RootId, Unavailability, UntrustedText,
};

use crate::collect::fs::{FileRead, ReadOutcome, ReadSpec, RelPath, SafeFs, Skip, Walk, WalkError};

/// The check whose coverage the collector records.
pub const INVENTORY: &str = "model_store.inventory";
/// The largest manifest read (`manifest_bytes`): real manifests are a few kilobytes.
pub const DEFAULT_MANIFEST_LIMIT: u64 = 1 << 20;

/// What was found in a model store. Every list is in discovery order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoreFacts {
    pub instances: Vec<FileInstance>,
    pub artifacts: Vec<Artifact>,
    pub models: Vec<Model>,
    /// Manifests whose path under `manifests/` has fewer than three parts: not models.
    pub shallow: Vec<InstanceId>,
    /// Manifests that were read but could not be parsed, with the parser's message.
    pub unparseable: Vec<(InstanceId, String)>,
    /// `model_store.inventory`: on the root, and on single manifests that were not read.
    pub coverage: Vec<Coverage>,
    /// A filter was given and some manifest matched it.
    pub matched_filter: bool,
    /// When a filter was given and no manifest matched: the `manifests/` directory that was
    /// listed (its metadata only). It is the evidence that the model is not in the store.
    pub listed_without_match: Option<InstanceId>,
}

/// Inventories the model store at scan root `root`.
pub fn collect(
    fs: &SafeFs,
    root: &RootId,
    filter: Option<&str>,
    manifest_limit: u64,
) -> StoreFacts {
    let mut c = Collector {
        fs,
        root,
        manifest_limit,
        facts: StoreFacts::default(),
        blobs: BTreeMap::new(),
    };
    let walk = RelPath::parse("manifests")
        .map_err(|e| WalkError::Failed(e.to_string()))
        .and_then(|dir| fs.walk(root, &dir));
    match walk {
        Ok(walk) => {
            for file in &walk.files {
                c.manifest(file, filter);
            }
            if filter.is_some() && !c.facts.matched_filter {
                c.listed_without_match();
            }
            let (state, budget) = inventory(&walk);
            c.cover(Ref::Root(root.clone()), state, budget);
        }
        Err(e) => c.cover(Ref::Root(root.clone()), unavailable(e), None),
    }
    c.facts
}

/// The inventory of `manifests/` as a whole.
fn inventory(walk: &Walk) -> (CoverageState, Option<BudgetUse>) {
    if let Some(budget) = walk.exceeded.first() {
        let state = CoverageState::BudgetExceeded {
            budget: budget.budget.clone(),
            used: budget.used,
            limit: budget.limit,
        };
        return (state, Some(budget.clone()));
    }
    // A manifest that could not be listed or leads out of the roots may be a model. Special files,
    // dangling links, and directories already walked are not manifests.
    let missing: Vec<String> = walk
        .skipped
        .iter()
        .filter(|(_, why)| {
            matches!(
                why,
                Skip::PermissionDenied | Skip::Failed(_) | Skip::OutsideScanRoots
            )
        })
        .map(|(path, _)| path.display())
        .collect();
    if missing.is_empty() {
        (CoverageState::Complete, None)
    } else {
        (CoverageState::Partial { missing }, None)
    }
}

fn unavailable(e: WalkError) -> CoverageState {
    let error = |message: &str| CoverageState::Error {
        message: UntrustedText::new(message),
    };
    match e {
        WalkError::NotFound => CoverageState::Unavailable {
            why: Unavailability::NotFound,
        },
        WalkError::PermissionDenied => CoverageState::Unavailable {
            why: Unavailability::PermissionDenied,
        },
        WalkError::NotADirectory => error("manifests is not a directory"),
        WalkError::OutsideRoots => error("manifests leads outside the scan roots"),
        WalkError::Failed(message) => error(&message),
    }
}

struct Collector<'a> {
    fs: &'a SafeFs,
    root: &'a RootId,
    manifest_limit: u64,
    facts: StoreFacts,
    /// Blobs read so far, by path: the instance (if any) and the first bytes, for a license.
    blobs: BTreeMap<String, (Option<InstanceId>, Vec<u8>)>,
}

impl Collector<'_> {
    fn cover(&mut self, scope: Ref, state: CoverageState, budget: Option<BudgetUse>) {
        if let Ok(check) = CheckId::new(INVENTORY) {
            self.facts.coverage.push(Coverage {
                check,
                scope,
                state,
                budget,
            });
        }
    }

    /// Records the `manifests/` directory itself: a directory is never read, so this keeps its
    /// metadata.
    fn listed_without_match(&mut self) {
        let Ok(dir) = RelPath::parse("manifests") else {
            return;
        };
        let spec = ReadSpec {
            keep: 0,
            limit: Some(0),
        };
        let read = self
            .fs
            .read_file(self.root, &dir, spec, vec![DiscoverySource::Walk]);
        self.facts.listed_without_match = self.record(read);
    }

    /// Keeps the instance and artifact of a read, once each; returns the instance.
    fn record(&mut self, read: FileRead) -> Option<InstanceId> {
        let instance = read.instance?;
        let id = instance.id.clone();
        match self.facts.instances.iter_mut().find(|i| i.id == id) {
            Some(known) => {
                for source in instance.discovered_by {
                    if !known.discovered_by.contains(&source) {
                        known.discovered_by.push(source);
                    }
                }
            }
            None => self.facts.instances.push(instance),
        }
        if let Some(artifact) = read.artifact {
            if !self.facts.artifacts.iter().any(|a| a.id == artifact.id) {
                self.facts.artifacts.push(artifact);
            }
        }
        Some(id)
    }

    fn manifest(&mut self, rel: &RelPath, filter: Option<&str>) {
        let parts = rel.components().get(1..).unwrap_or_default();
        let path = layout::manifest_path(parts);
        match (&path, filter) {
            // A path too shallow to be a model cannot match a filter (I-05).
            (None, Some(_)) => return,
            (Some(p), Some(f)) if p.name != f => return,
            (Some(_), Some(_)) => self.facts.matched_filter = true,
            _ => {}
        }
        let limit = usize::try_from(self.manifest_limit).unwrap_or(usize::MAX);
        let spec = ReadSpec {
            keep: limit,
            limit: Some(self.manifest_limit),
        };
        let read = self
            .fs
            .read_file(self.root, rel, spec, vec![DiscoverySource::Walk]);
        let outcome = read.outcome.clone();
        let prefix = read.prefix.clone();
        let Some(id) = self.record(read) else {
            if let ReadOutcome::Failed(message) = outcome {
                let path = rel.display();
                let state = CoverageState::Error {
                    message: UntrustedText::new(format!("{path}: {message}")),
                };
                self.cover(Ref::Root(self.root.clone()), state, None);
            }
            return;
        };
        let Some(path) = path else {
            self.facts.shallow.push(id);
            return;
        };
        let not_read = match outcome {
            ReadOutcome::Complete => None,
            ReadOutcome::LimitExceeded { limit, size } => Some(CoverageState::BudgetExceeded {
                budget: "manifest_bytes".to_string(),
                used: size,
                limit,
            }),
            ReadOutcome::NotRead(NotReadReason::PermissionDenied) => {
                Some(CoverageState::Unavailable {
                    why: Unavailability::PermissionDenied,
                })
            }
            ReadOutcome::NotRead(why) => Some(CoverageState::Error {
                message: UntrustedText::new(format!("not read: {why:?}")),
            }),
            ReadOutcome::NotFound => return,
            ReadOutcome::Failed(message) => Some(CoverageState::Error {
                message: UntrustedText::new(message),
            }),
        };
        if let Some(state) = not_read {
            self.cover(Ref::Instance(id), state, None);
            return;
        }
        let entries = match manifest::parse(&prefix) {
            Ok(entries) => entries,
            Err(message) => {
                let state = CoverageState::Error {
                    message: UntrustedText::new(message.clone()),
                };
                self.cover(Ref::Instance(id.clone()), state, None);
                self.facts.unparseable.push((id, message));
                return;
            }
        };
        // `model:<root>/<path under manifests/>`, from the instance ID so that the same encoding
        // applies.
        let under = format!("inst:{}/manifests/", self.root);
        let Some(model_id) = id
            .as_str()
            .strip_prefix(&under)
            .and_then(|rest| ModelId::new(format!("model:{}/{rest}", self.root)).ok())
        else {
            let state = CoverageState::Error {
                message: UntrustedText::new("the manifest path cannot name a model"),
            };
            self.cover(Ref::Instance(id), state, None);
            return;
        };
        let layers = entries
            .into_iter()
            .map(|e| ModelLayer {
                role: e.role,
                media_type: e.media_type.map(UntrustedText::new),
                blob: layout::blob_path(&e.digest).and_then(|rel| self.blob(&rel, &id)),
                digest: UntrustedText::new(e.digest),
            })
            .collect();
        let mut model = Model {
            id: model_id,
            name: UntrustedText::new(path.name),
            manifest: id,
            provenance: path.provenance,
            layers,
            license: None,
        };
        model.license = self.license(&model);
        self.facts.models.push(model);
    }

    /// Reads the blob at `rel` once; later manifests naming it are added to how it was found.
    fn blob(&mut self, rel: &RelPath, manifest: &InstanceId) -> Option<InstanceId> {
        let source = DiscoverySource::Manifest {
            manifest: manifest.clone(),
        };
        let key = rel.display();
        if let Some((known, _)) = self.blobs.get(&key) {
            let known = known.clone()?;
            if let Some(i) = self.facts.instances.iter_mut().find(|i| i.id == known) {
                if !i.discovered_by.contains(&source) {
                    i.discovered_by.push(source);
                }
            }
            return Some(known);
        }
        let spec = ReadSpec {
            keep: license::DETECT_BYTES,
            limit: None,
        };
        let read = self.fs.read_file(self.root, rel, spec, vec![source]);
        let prefix = read.prefix.clone();
        let id = self.record(read);
        self.blobs.insert(key, (id.clone(), prefix));
        id
    }

    /// The license text, when the license layer's blob was read.
    fn license(&self, model: &Model) -> Option<LicenseText> {
        let layer = model.license_layer()?;
        let blob = layer.blob.as_ref()?;
        let placed = self.facts.instances.iter().find(|i| i.id == *blob)?;
        let InstanceContent::Read { artifact } = &placed.content else {
            return None;
        };
        let rel = layer.digest.as_str().and_then(layout::blob_path)?;
        let (_, prefix) = self.blobs.get(&rel.display())?;
        let detected = license::detect(prefix);
        Some(LicenseText {
            artifact: artifact.clone(),
            spdx: detected.spdx,
            excerpt: UntrustedText::new(detected.excerpt),
        })
    }
}
