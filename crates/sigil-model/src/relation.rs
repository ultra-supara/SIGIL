//! Relations between facts, profile matches, per-rule support, and binding premises
//! (plan §4.4.1, §4.4.5, §4.5, §4.6.4).
//!
//! Dependency relations keep their strength apart:
//! - `Declares`: a slice names a dependency (`DT_NEEDED`, `LC_LOAD_DYLIB`); nothing is resolved;
//! - `Candidate`: a file that **could** satisfy that name under modeled search rules;
//! - `SymbolCandidate`: a slice **defines** a symbol that a call site imports;
//! - [`BindingPremise`]: whether a given process role **binds** that call to the analyzed
//!   definition, which only `Verified` establishes.
//!
//! A mapping observed in a process never upgrades any of these (plan §4.6.4).

use serde::{Deserialize, Serialize};

use crate::code::{CallRef, FnRef};
use crate::evidence::{Basis, Loc, ProfileRuleRef, Support, UnknownReason};
use crate::id::{
    AssumptionId, InstanceId, ObligationId, PremiseId, ProcessRole, ProfileRef, ProfileRuleId,
    SliceId, ValueId,
};
use crate::text::UntrustedText;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Relation {
    /// A declared dependency by name. Not a resolution.
    Declares {
        from: SliceId,
        needed: UntrustedText,
        kind: DeclKind,
    },
    /// A file that could satisfy a declared name under one modeled search rule. Always a
    /// candidate, never "the file that was loaded".
    Candidate {
        from: SliceId,
        needed: UntrustedText,
        candidate: InstanceId,
        via: SearchRule,
    },
    /// `definer` defines the symbol imported at `site`. Which definition a process uses is a
    /// [`BindingPremise`].
    SymbolCandidate {
        site: CallRef,
        symbol: UntrustedText,
        definer: FnRef,
    },
    /// Which obligations of a profile hold in a slice, with locations. Matching is not
    /// verification: it never upgrades a claim's support by itself. An obligation has one result
    /// per profile and slice.
    ProfileMatch {
        profile: ProfileRef,
        slice: SliceId,
        obligations: Vec<ObligationResult>,
    },
    /// One search path of a loader in one process role, with the directory it resolves to.
    SearchPath {
        role: ProcessRole,
        search_path: String,
        rule: ProfileRuleRef,
        dir: SearchDir,
        basis: Basis,
        unresolved: Vec<PremiseId>,
    },
    /// Process topology: `parent` spawns `child` (from a topology profile rule).
    Spawns {
        parent: ProcessRole,
        child: ProcessRole,
        rule: ProfileRuleRef,
        basis: Basis,
        unresolved: Vec<PremiseId>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeclKind {
    ElfNeeded,
    MachOLoadDylib,
}

/// The modeled ELF search rule that produced a candidate (`ld.so.cache` is not modeled in M0/M1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SearchRule {
    Rpath,
    LdLibraryPath,
    Runpath,
    DefaultDir,
}

/// The directory a search path resolves to in a role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SearchDir {
    /// The directory of an executable instance.
    ExeDir {
        instance: InstanceId,
    },
    /// A process value (e.g. the role's cwd or an environment variable).
    Value {
        value: ValueId,
    },
    Unknown {
        reason: UnknownReason,
    },
}

/// One obligation's result in one slice. `Unknown` is a result of its own, not a failure and not
/// a pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObligationResult {
    pub id: ObligationId,
    pub result: ObligationState,
    /// Where it was decided. Never empty for `Pass`.
    pub at: Vec<Loc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObligationState {
    Pass,
    /// The rule becomes a `ProfileMismatch` gap for this slice.
    Fail,
    /// The rule stays at `FeatureMatch`.
    Unknown,
}

/// The support of one profile rule for one slice (plan §4.4.7). The only place a [`Support`] is
/// recorded: modeled facts and conditions refer to it by [`RuleSupportRef`], so they cannot claim
/// more than it says. `(profile, rule, slice)` is unique in a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSupport {
    pub profile: ProfileRef,
    pub rule: ProfileRuleId,
    pub slice: SliceId,
    pub support: Support,
}

/// The key of a [`RuleSupport`]: one rule of one profile on one slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSupportRef {
    pub profile: ProfileRef,
    pub rule: ProfileRuleId,
    pub slice: SliceId,
}

impl RuleSupport {
    /// Whether this record is the one `key` names.
    pub fn is(&self, key: &RuleSupportRef) -> bool {
        self.profile == key.profile && self.rule == key.rule && self.slice == key.slice
    }
}

/// Does this process role bind the call at `site` to the definition that was analyzed?
/// `(process_role, site, analyzed_definer)` is unique in a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingPremise {
    pub process_role: ProcessRole,
    pub site: CallRef,
    pub symbol: UntrustedText,
    pub analyzed_definer: InstanceId,
    pub state: BindingState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum BindingState {
    /// Established for this scope of objects (preload set known, scope prefix resolved).
    Verified {
        scope: Vec<InstanceId>,
    },
    /// Rests on an assumption; usable in a finding only if the policy accepted it.
    Assumed {
        assumption: AssumptionId,
    },
    Unknown {
        reason: UnknownReason,
    },
    /// An earlier object in the scope order defines the symbol.
    Mismatch {
        first_definer: InstanceId,
    },
}
