//! Model-store findings and per-model coverage, derived from collected facts (plan §4.6.7, §6.3).
//!
//! Every finding has one condition, `Observed`, naming the files it rests on: the manifest, and
//! for a mismatch the blob and what it holds. The model is the subject, and is listed in the
//! evidence for explanation.
//!
//! | Rule | When | Coverage |
//! |---|---|---|
//! | `model.manifest_digest_malformed` | a digest is not `sha256:` + 64 lowercase hex digits | integrity `Partial` |
//! | `model.blob_missing` | a well-formed digest's blob is confirmed absent | integrity `Partial` |
//! | — | the blob's path could not be resolved (permission, links, I/O) | integrity `Partial` |
//! | `model.blob_digest_mismatch` | the blob's contents hash to another digest | integrity checked |
//! | — | the blob exists but was not read | integrity `Partial` |
//! | `model.license_missing` | no license layer | license checked |
//! | — | the license layer's digest is malformed or its blob is missing | license `Partial` |
//! | — | the license layer's blob exists but was not read, or could not be resolved | license `Error` |
//! | `model.provenance_unknown` | a manifest path too shallow to name a model | — |
//! | `model.manifest_unparseable` | a manifest that is not valid JSON or lacks a digest | (inventory `Error`, by the collector) |
//! | `model.not_found` | a filter matched no manifest (after a complete listing) | — |
//!
//! A file that SafeFs saw change or vanish while it was read (`Stability`) supports no claim:
//! - a blob: integrity `Partial`, and no mismatch finding;
//! - the license blob: license `Partial`;
//! - the manifest: no finding about the model, and its inventory, integrity, and license are
//!   all `Partial`;
//! - an unparseable manifest: no `model.manifest_unparseable`; its inventory `Error` remains.
//!
//! What was read stays in the facts.

use sigil_model::{
    digest_hex, Action, BlobLookup, CheckId, CondEvidence, CondId, CondState, Condition, Coverage,
    CoverageState, EvidenceRef, FileInstance, Finding, FindingId, InstanceContent, InstanceId,
    Model, PolicyDecision, PolicyRuleRef, Ref, RootId, RuleId, Severity, Stability, UntrustedText,
    LICENSE_MEDIA_TYPE,
};

use crate::collect::ollama_store::{StoreFacts, INVENTORY};
use crate::policy::catalog;

/// Whether every blob of a model was read and compared with its digest.
pub const INTEGRITY: &str = "model_store.integrity";
/// Whether a model's license was established (read, or known to be absent).
pub const LICENSE: &str = "model_store.license";

/// The findings and the per-model coverage of `facts`, in model order.
pub fn analyze(facts: &StoreFacts, root: &RootId) -> (Vec<Finding>, Vec<Coverage>) {
    let mut out = Out::default();
    for model in &facts.models {
        out.model(facts, model);
    }
    for manifest in &facts.shallow {
        out.on_manifest("model.provenance_unknown", manifest, "path_too_shallow");
    }
    for (manifest, _) in &facts.unparseable {
        // Bytes that were changing do not show that the manifest is malformed. The collector's
        // inventory `Error` on it keeps the gap.
        let placed = facts.instances.iter().find(|i| i.id == *manifest);
        if placed.and_then(not_stable).is_some() {
            continue;
        }
        out.on_manifest(
            "model.manifest_unparseable",
            manifest,
            "manifest_unparseable",
        );
    }
    if let Some(listing) = &facts.listed_without_match {
        let facts = vec![EvidenceRef::Instance {
            instance: listing.clone(),
        }];
        out.finding(
            "model.not_found",
            Ref::Root(root.clone()),
            "",
            "no_manifest_matched",
            facts.clone(),
            facts,
        );
    }
    (out.findings, out.coverage)
}

/// How a read file was not stable, when SafeFs saw it change or vanish.
fn not_stable(instance: &FileInstance) -> Option<String> {
    match instance.stability {
        Stability::NoChangeDetected => None,
        other => Some(format!("{other:?}")),
    }
}

#[derive(Default)]
struct Out {
    findings: Vec<Finding>,
    coverage: Vec<Coverage>,
}

impl Out {
    fn model(&mut self, facts: &StoreFacts, model: &Model) {
        let placed = |id: &InstanceId| facts.instances.iter().find(|i| i.id == *id);
        let manifest = EvidenceRef::Instance {
            instance: model.manifest.clone(),
        };
        let subject = Ref::Model(model.id.clone());
        // A manifest that changed while it was read supports no claim about its model: the
        // layers read may not be the manifest's. What was read stays in the facts.
        if let Some(how) = placed(&model.manifest).and_then(not_stable) {
            let why = vec![format!(
                "the manifest was not stable during the read ({how})"
            )];
            let gap = || CoverageState::Partial {
                missing: why.clone(),
            };
            self.cover(INVENTORY, Ref::Instance(model.manifest.clone()), gap());
            self.cover(INTEGRITY, subject.clone(), gap());
            self.cover(LICENSE, subject, gap());
            return;
        }
        let mut open = vec![];
        for (i, layer) in model.layers.iter().enumerate() {
            let at = format!("#{i}");
            let Some(hex) = layer.digest.as_str().and_then(digest_hex) else {
                open.push(format!("layer {i}: malformed digest"));
                self.about(
                    model,
                    "model.manifest_digest_malformed",
                    &at,
                    "digest_malformed",
                    vec![manifest.clone()],
                );
                continue;
            };
            let blob = match &layer.blob {
                BlobLookup::Found { instance } => instance,
                // Confirmed absent: a finding.
                BlobLookup::Absent => {
                    open.push(format!("layer {i}: no blob"));
                    self.about(
                        model,
                        "model.blob_missing",
                        &at,
                        "blob_absent",
                        vec![manifest.clone()],
                    );
                    continue;
                }
                // Not known to be absent: a gap, never `blob_missing`.
                BlobLookup::Unresolved { why } => {
                    let why = String::from_utf8_lossy(why.as_bytes());
                    open.push(format!("layer {i}: blob not resolved ({why})"));
                    continue;
                }
                // Validation allows this only for a malformed digest, handled above.
                BlobLookup::NotLookedUp => {
                    open.push(format!("layer {i}: blob not looked up"));
                    continue;
                }
            };
            let placed_blob = placed(blob);
            // Bytes read from a file that changed meanwhile are kept as evidence, but they
            // neither confirm the digest nor contradict it.
            if let Some(how) = placed_blob.and_then(not_stable) {
                open.push(format!(
                    "layer {i}: blob not stable during the read ({how})"
                ));
                continue;
            }
            match placed_blob.map(|b: &FileInstance| &b.content) {
                Some(InstanceContent::Read { artifact }) => {
                    if artifact.as_str() != format!("sha256:{}", hex.as_str()) {
                        let facts = vec![
                            manifest.clone(),
                            EvidenceRef::Instance {
                                instance: blob.clone(),
                            },
                            EvidenceRef::Artifact {
                                artifact: artifact.clone(),
                            },
                        ];
                        self.about(
                            model,
                            "model.blob_digest_mismatch",
                            &at,
                            "digest_differs",
                            facts,
                        );
                    }
                }
                Some(InstanceContent::NotRead { why }) => {
                    open.push(format!("layer {i}: blob not read ({why:?})"));
                }
                None => open.push(format!("layer {i}: blob not recorded")),
            }
        }
        let integrity = if open.is_empty() {
            CoverageState::Complete
        } else {
            CoverageState::Partial { missing: open }
        };
        self.cover(INTEGRITY, subject.clone(), integrity);

        let license = match model.license_layer() {
            None => {
                let declared = model.layers.iter().any(|l| {
                    l.media_type.as_ref().and_then(UntrustedText::as_str)
                        == Some(LICENSE_MEDIA_TYPE)
                });
                if declared {
                    // Only license layers with malformed digests.
                    CoverageState::Partial {
                        missing: vec!["license layer digest".to_string()],
                    }
                } else {
                    self.about(
                        model,
                        "model.license_missing",
                        "",
                        "license_layer_absent",
                        vec![manifest.clone()],
                    );
                    CoverageState::Complete
                }
            }
            Some(layer) => match &layer.blob {
                BlobLookup::Found { instance } => match placed(instance).map(|b| &b.content) {
                    Some(InstanceContent::Read { .. }) => {
                        match placed(instance).and_then(not_stable) {
                            None => CoverageState::Complete,
                            Some(how) => CoverageState::Partial {
                                missing: vec![format!(
                                    "license blob not stable during the read ({how})"
                                )],
                            },
                        }
                    }
                    Some(InstanceContent::NotRead { why }) => CoverageState::Error {
                        message: UntrustedText::new(format!("license blob not read ({why:?})")),
                    },
                    None => CoverageState::Error {
                        message: UntrustedText::new("license blob not recorded"),
                    },
                },
                BlobLookup::Absent | BlobLookup::NotLookedUp => CoverageState::Partial {
                    missing: vec!["license blob".to_string()],
                },
                BlobLookup::Unresolved { why } => CoverageState::Error {
                    message: UntrustedText::new(format!(
                        "license blob not resolved ({})",
                        String::from_utf8_lossy(why.as_bytes())
                    )),
                },
            },
        };
        self.cover(LICENSE, subject, license);
    }

    /// A finding about a model; `at` tells layers apart (`#<index>`).
    fn about(
        &mut self,
        model: &Model,
        rule: &str,
        at: &str,
        condition: &str,
        facts: Vec<EvidenceRef>,
    ) {
        let mut evidence = vec![EvidenceRef::Model {
            model: model.id.clone(),
        }];
        evidence.extend(facts.iter().cloned());
        self.finding(
            rule,
            Ref::Model(model.id.clone()),
            at,
            condition,
            facts,
            evidence,
        );
    }

    /// A finding about a manifest that is not a model.
    fn on_manifest(&mut self, rule: &str, manifest: &InstanceId, condition: &str) {
        let facts = vec![EvidenceRef::Instance {
            instance: manifest.clone(),
        }];
        self.finding(
            rule,
            Ref::Instance(manifest.clone()),
            "",
            condition,
            facts.clone(),
            facts,
        );
    }

    fn finding(
        &mut self,
        rule: &str,
        subject: Ref,
        at: &str,
        condition: &str,
        facts: Vec<EvidenceRef>,
        evidence: Vec<EvidenceRef>,
    ) {
        // Catalog rules and fixed names: these always validate. A failure is a catalog bug and
        // drops the finding rather than panicking.
        let Some(info) = catalog::rule(rule) else {
            return;
        };
        let on = match &subject {
            Ref::Model(m) => m.as_str().to_string(),
            Ref::Instance(i) => i.as_str().to_string(),
            Ref::Root(r) => r.as_str().to_string(),
            _ => return,
        };
        let (Ok(id), Ok(rule_id), Ok(cond_id), Ok(source)) = (
            FindingId::new(format!("finding:{rule}@{on}{at}")),
            RuleId::new(rule),
            CondId::new(condition),
            PolicyRuleRef::new(format!("default:{rule}")),
        ) else {
            return;
        };
        self.findings.push(Finding {
            id,
            rule: rule_id,
            kind: info.kind,
            subject,
            summary: info.summary.to_string(),
            conditions: vec![Condition {
                id: cond_id,
                state: CondState::Met {
                    evidence: CondEvidence::Observed { facts },
                },
                unresolved: vec![],
            }],
            evidence,
            limits: vec![],
            default_severity: info.default,
            // Replaced by policy evaluation.
            decision: PolicyDecision {
                action: match info.default {
                    Severity::Warn => Action::Warn,
                    Severity::Fail => Action::Fail,
                },
                source,
                reason: None,
                expires: None,
            },
        });
    }

    fn cover(&mut self, check: &str, scope: Ref, state: CoverageState) {
        if let Ok(check) = CheckId::new(check) {
            self.coverage.push(Coverage {
                check,
                scope,
                state,
                budget: None,
            });
        }
    }
}
