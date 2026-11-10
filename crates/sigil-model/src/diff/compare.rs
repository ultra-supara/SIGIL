//! [`compare`]: the differences between two validated sessions.

use crate::diff::{Change, Diff, DiffSchema, DiffSide, NotComparable};
use crate::id::Sha256Hex;
use crate::session::{KnowledgeKind, Session, ToolInfo};
use crate::validate::ValidatedSession;

/// What a comparison has found so far.
#[derive(Default)]
pub(super) struct Found {
    pub(super) changes: Vec<Change>,
    pub(super) not_comparable: Vec<NotComparable>,
}

/// The differences between `baseline` and `current`, whose canonical JSON have the SHA-256s
/// given (computed by the caller, as for the AI-BOM). Pure and deterministic: both sessions are
/// compared in canonical order, whatever order their lists are in.
pub fn compare(
    baseline: &ValidatedSession,
    baseline_sha256: Sha256Hex,
    current: &ValidatedSession,
    current_sha256: Sha256Hex,
    tool: ToolInfo,
) -> Diff {
    let b = canonical(baseline.as_session());
    let c = canonical(current.as_session());
    let found = Found::default();
    let mut diff = Diff {
        schema: DiffSchema::V1,
        tool,
        baseline: side(&b, baseline_sha256),
        current: side(&c, current_sha256),
        changes: found.changes,
        not_comparable: found.not_comparable,
    };
    diff.canonicalize();
    diff
}

fn canonical(s: &Session) -> Session {
    let mut s = s.clone();
    s.canonicalize();
    s
}

fn side(s: &Session, sha256: Sha256Hex) -> DiffSide {
    DiffSide {
        sha256,
        tool: s.tool.clone(),
        mode: s.request.mode,
        started_at: s.observation.started_at.clone(),
        policy: s
            .knowledge
            .iter()
            .find(|k| k.kind == KnowledgeKind::Policy)
            .cloned(),
    }
}
