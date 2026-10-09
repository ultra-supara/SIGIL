//! Session → AI-BOM v2 (design §4). Pure and deterministic: the projection works on a
//! canonicalized copy, so the AI-BOM's lists come out in canonical order whatever the input order.

use std::collections::BTreeMap;

use crate::artifact::InstanceContent;
use crate::coverage::CoverageState;
use crate::id::{CheckId, InstanceId, Sha256Hex};
use crate::identity::ReleaseBasis;
use crate::model::BlobLookup;
use crate::session::{KnowledgeKind, SchemaVersion, Session};
use crate::text::UntrustedText;

use super::{
    AiBom, AiBomSchema, BomArtifact, BomBlob, BomComponent, BomFinding, BomLayer, BomLicense,
    BomModel, BomProcess, BomRelease, BomRuntime, BomSlice, BomViolation, CheckSummary,
    ReleaseBasisKind, SessionLink,
};

/// The coverage state names `CheckSummary.states` uses, one per `CoverageState` variant.
pub const STATE_NAMES: &[&str] = &[
    "Complete",
    "Partial",
    "NotPresent",
    "ProfileMismatch",
    "OutOfScope",
    "Skipped",
    "Unavailable",
    "Unsupported",
    "BudgetExceeded",
    "Error",
];

/// The states whose entries can close a check (`CoverageState::can_close`).
pub const CLOSING_STATES: &[&str] = &["Complete", "NotPresent", "OutOfScope"];

/// The name of a coverage state's variant (one of [`STATE_NAMES`]).
pub fn state_name(state: &CoverageState) -> &'static str {
    match state {
        CoverageState::Complete => "Complete",
        CoverageState::Partial { .. } => "Partial",
        CoverageState::NotPresent { .. } => "NotPresent",
        CoverageState::ProfileMismatch { .. } => "ProfileMismatch",
        CoverageState::OutOfScope { .. } => "OutOfScope",
        CoverageState::Skipped { .. } => "Skipped",
        CoverageState::Unavailable { .. } => "Unavailable",
        CoverageState::Unsupported { .. } => "Unsupported",
        CoverageState::BudgetExceeded { .. } => "BudgetExceeded",
        CoverageState::Error { .. } => "Error",
    }
}

/// The AI-BOM of `session`, whose canonical JSON has SHA-256 `sha256` (computed by the caller).
pub fn project(session: &Session, sha256: Sha256Hex) -> AiBom {
    let mut s = session.clone();
    s.canonicalize();
    let s = &s;
    let instance = |id: &InstanceId| s.instances.iter().find(|i| i.id == *id);

    let runtime = BomRuntime {
        processes: s
            .processes
            .iter()
            .map(|p| BomProcess {
                process: p.process.clone(),
                roles: p.roles.clone(),
                name: p.name.clone(),
                exe: p.exe.clone(),
            })
            .collect(),
        listeners: s.listeners.clone(),
        api: s.probes.clone(),
        releases: s
            .releases
            .iter()
            .map(|r| BomRelease {
                product: r.product.clone(),
                candidates: r.candidates.clone(),
                basis: match r.basis {
                    ReleaseBasis::ReferenceMatches { .. } => ReleaseBasisKind::ReferenceMatches,
                    ReleaseBasis::SelfReportedCommit { .. } => ReleaseBasisKind::SelfReportedCommit,
                },
            })
            .collect(),
    };

    let models = s
        .models
        .iter()
        .map(|m| BomModel {
            id: m.id.clone(),
            name: m.name.clone(),
            provenance: m.provenance.clone(),
            layers: m
                .layers
                .iter()
                .map(|l| BomLayer {
                    role: l.role,
                    media_type: l.media_type.clone(),
                    digest: l.digest.clone(),
                    blob: match &l.blob {
                        BlobLookup::NotLookedUp => BomBlob::NotLookedUp,
                        BlobLookup::Absent => BomBlob::Absent,
                        BlobLookup::Unresolved { why } => BomBlob::Unresolved { why: why.clone() },
                        BlobLookup::Found { instance: id } => match instance(id) {
                            Some(i) => BomBlob::Found {
                                path: i.path.clone(),
                                content: match &i.content {
                                    InstanceContent::Read { artifact } => Some(artifact.clone()),
                                    InstanceContent::NotRead { .. } => None,
                                },
                            },
                            // Not in a valid session: the instance ID is all there is.
                            None => BomBlob::Found {
                                path: UntrustedText::new(id.as_str()),
                                content: None,
                            },
                        },
                    },
                })
                .collect(),
            license: m.license.as_ref().map(|l| BomLicense {
                spdx: l.spdx.clone(),
                excerpt: l.excerpt.clone(),
            }),
        })
        .collect();

    let artifacts = s
        .artifacts
        .iter()
        .map(|a| {
            let mut paths: Vec<UntrustedText> = s
                .instances
                .iter()
                .filter(|i| matches!(&i.content, InstanceContent::Read { artifact } if *artifact == a.id))
                .map(|i| i.path.clone())
                .collect();
            paths.sort_by(|x, y| x.as_bytes().cmp(y.as_bytes()));
            paths.dedup();
            BomArtifact {
                id: a.id.clone(),
                size: a.size,
                format: a.format,
                paths,
                slices: a
                    .slices
                    .iter()
                    .map(|sl| BomSlice {
                        id: sl.id.clone(),
                        arch: sl.arch,
                        sha256: sl.sha256.clone(),
                        components: s
                            .components
                            .iter()
                            .filter(|c| c.subject == sl.id)
                            .map(|c| BomComponent {
                                component: c.component.clone(),
                                status: c.status,
                                versions: c.versions.iter().map(|v| v.value.clone()).collect(),
                            })
                            .collect(),
                    })
                    .collect(),
            }
        })
        .collect();

    AiBom {
        schema: AiBomSchema::V2,
        tool: s.tool.clone(),
        session: SessionLink {
            schema: SchemaVersion::SessionV1,
            sha256,
            mode: s.request.mode,
            started_at: s.observation.started_at.clone(),
            policy: s
                .knowledge
                .iter()
                .find(|k| k.kind == KnowledgeKind::Policy)
                .cloned(),
        },
        outcome: s.outcome.clone(),
        runtime,
        models,
        artifacts,
        findings: s
            .findings
            .iter()
            .map(|f| BomFinding {
                id: f.id.clone(),
                rule: f.rule.clone(),
                kind: f.kind,
                subject: f.subject.clone(),
                summary: f.summary.clone(),
                default_severity: f.default_severity,
                decision: f.decision.clone(),
                limits: f.limits.clone(),
            })
            .collect(),
        policy_violations: s
            .policy_violations
            .iter()
            .map(|v| BomViolation {
                policy_rule: v.policy_rule.clone(),
                subject: v.subject.clone(),
                decision: v.decision.clone(),
            })
            .collect(),
        coverage: coverage(s),
    }
}

/// One summary per check that is required or has coverage: the required checks first, in the
/// request's (canonical) order, then the others, sorted.
fn coverage(s: &Session) -> Vec<CheckSummary> {
    let required = &s.request.required_checks;
    let mut others: Vec<&CheckId> = s
        .coverage
        .iter()
        .map(|c| &c.check)
        .filter(|c| !required.contains(c))
        .collect();
    others.sort();
    others.dedup();
    required
        .iter()
        .chain(others)
        .map(|check| {
            let entries: Vec<_> = s.coverage.iter().filter(|c| c.check == *check).collect();
            let mut states = BTreeMap::new();
            for c in &entries {
                *states.entry(state_name(&c.state).to_string()).or_insert(0) += 1;
            }
            CheckSummary {
                check: check.clone(),
                required: required.contains(check),
                closed: !entries.is_empty() && entries.iter().all(|c| c.state.can_close()),
                states,
            }
        })
        .collect()
}
