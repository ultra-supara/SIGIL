//! Coverage: what was checked, within what scope, and how far (plan §4.4.8).
//!
//! Every state other than `Complete`, `NotPresent`, and `OutOfScope` is a gap. In particular:
//! unsupported is not safe, a budget hit is not "no match", a permission denial is not "no
//! finding", a disabled mode is not "completed", and a profile mismatch is not a pass.

use serde::{Deserialize, Serialize};

use crate::evidence::{EvidenceRef, Ref};
use crate::id::{ArtifactId, CheckId, ObligationId, ProfileRef};
use crate::text::UntrustedText;

/// The state of one check over one scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub check: CheckId,
    pub scope: Ref,
    pub state: CoverageState,
    /// Budget consumption, when a budget applies to this check.
    pub budget: Option<BudgetUse>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum CoverageState {
    Complete,
    /// Some parts were not analyzed or not decided.
    Partial {
        missing: Vec<String>,
    },
    /// Confirmed absent within `scope`, on the stated basis.
    NotPresent {
        evidence: Vec<EvidenceRef>,
        scope: String,
        basis: AbsenceBasis,
    },
    /// Something is there, but not the implementation this profile describes. A gap, not a pass.
    /// Scoped to the slice; `failed` names obligations whose result there is `Fail`.
    ProfileMismatch {
        profile: ProfileRef,
        failed: Vec<ObligationId>,
    },
    /// Outside the requested audit scope (never a gap).
    OutOfScope {
        why: String,
    },
    Skipped {
        by: SkipReason,
    },
    Unavailable {
        why: Unavailability,
    },
    /// Format, architecture, or configuration SIGIL does not analyze.
    Unsupported {
        what: String,
    },
    BudgetExceeded {
        budget: String,
        used: u64,
        limit: u64,
    },
    Error {
        message: UntrustedText,
    },
}

impl CoverageState {
    /// Whether this state can close a check (plan §4.4.8). `NotPresent` closes a check only if
    /// the check accepts its basis; that is decided by the check's definition, outside the model.
    pub fn can_close(&self) -> bool {
        matches!(
            self,
            CoverageState::Complete
                | CoverageState::NotPresent { .. }
                | CoverageState::OutOfScope { .. }
        )
    }
}

/// Why something is known to be absent. Missing symbols are not absence of a feature by
/// themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AbsenceBasis {
    /// The named exports/imports are missing from the scoped artifacts.
    SymbolsAbsent { names: Vec<String> },
    /// A verified reference build lacks the feature.
    ReferenceBuild { reference: ArtifactId },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SkipReason {
    ModeDisabled,
    Flag { flag: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Unavailability {
    PermissionDenied,
    NotFound,
    PlatformUnsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetUse {
    pub budget: String,
    pub used: u64,
    pub limit: u64,
}
