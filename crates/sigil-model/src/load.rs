//! Level D for loaders, and process values (plan §4.4.4, §4.4.10).
//!
//! [`LoadFacts`] are **independent facts, not a state machine**: present, candidate,
//! would-evaluate, selectable, mapped, and used-for-inference are each recorded separately.
//! There is no `loaded: bool`. An empty `mapped` list never means "not loaded".
//!
//! [`ProcessValue`] keeps where each value came from. A value configured for one process role is
//! never silently the effective value of another, and a configured value is never the effective
//! value at all: that is a `PredictedLaunch`, `ObservedProcess`, or `ChildDerived` value.

use serde::{Deserialize, Serialize};

use crate::artifact::{MappingObs, ProcessRef};
use crate::evidence::{
    Basis, ConfigRef, ObsSource, Observability, ProfileRuleRef, Tri, UnknownReason,
};
use crate::id::{InstanceId, PremiseId, ProcessRole, ValueId};
use crate::text::UntrustedText;

/// What is known about one file for one loader in one process role. `(instance, context)` is
/// unique in a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadFacts {
    pub instance: InstanceId,
    pub context: LoadContext,
    /// Existence confirmed by the scan.
    pub present: bool,
    /// The file satisfies the loader's candidate rule (search path, filter) in this context.
    pub candidate: Tri<CandidateWhy>,
    /// If the loader runs in this context, this file is opened and its score function called.
    /// Conditional, never an observation. Never stronger than `candidate`, and carries its
    /// premises.
    pub would_evaluate: Tri<EffectWhy>,
    /// Can be selected (unknown when it depends on run-time scores).
    pub selectable: Tri<()>,
    /// Observations of this file, each one recorded under its process in `processes`. Empty does
    /// not mean "not loaded".
    pub mapped: Vec<MappingObs>,
    pub mapping_observability: Observability,
    /// Whether the file was used for inference. Needs active tracing; unknown in M1.
    pub used_for_inference: Tri<()>,
}

/// One of the independent facts of a [`LoadFacts`] entry, for a condition to rest on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoadFact {
    Candidate,
    WouldEvaluate,
    Selectable,
    UsedForInference,
}

impl LoadFacts {
    /// The claim recorded for `fact`, as `(holds, basis, unresolved)`; `None` while unknown.
    pub fn fact(&self, fact: LoadFact) -> Option<(bool, &Basis, &[PremiseId])> {
        fn decided<T>(tri: &Tri<T>) -> Option<(bool, &Basis, &[PremiseId])> {
            match tri {
                Tri::Yes {
                    basis, unresolved, ..
                } => Some((true, basis, unresolved)),
                Tri::No { basis, unresolved } => Some((false, basis, unresolved)),
                Tri::Unknown { .. } => None,
            }
        }
        match fact {
            LoadFact::Candidate => decided(&self.candidate),
            LoadFact::WouldEvaluate => decided(&self.would_evaluate),
            LoadFact::Selectable => decided(&self.selectable),
            LoadFact::UsedForInference => decided(&self.used_for_inference),
        }
    }
}

/// A process role and the loader rule instance that applies in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadContext {
    pub process_role: ProcessRole,
    /// The loader entry the facts are about, e.g. `ggml.backend-loader/load_best(cpu)`.
    pub rule: String,
}

/// Why a file is a candidate: the search path and the filter it satisfied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateWhy {
    pub search_path: String,
    pub filter: String,
}

/// The loader phase an effect belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectWhy {
    pub phase: LoaderPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoaderPhase {
    Evaluate,
    Select,
    Init,
    Register,
}

/// One value of one key for one process role, from one origin. Several values with different
/// origins can exist for the same role and key (e.g. configured and observed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessValue {
    pub id: ValueId,
    pub process_role: ProcessRole,
    pub key: ValueKey,
    pub value: TriValue,
    pub origin: ValueOrigin,
    /// The load operations this value affects.
    pub applies_to: Vec<LoadContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ValueKey {
    /// An environment variable (only allowlisted names are recorded, plan §4.10).
    Env(UntrustedText),
    Cwd,
    User,
    Group,
}

/// A value: known, known to be absent, or unknown with a reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TriValue {
    Known(UntrustedText),
    Absent,
    Unknown { reason: UnknownReason },
}

/// Where a value came from (plan §4.4.10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ValueOrigin {
    /// Written in a configuration file (e.g. `Environment=` in a unit). Not an effective value.
    Configured {
        file: ConfigRef,
        directive: UntrustedText,
    },
    /// The effective value predicted by the configuration rules SIGIL models.
    PredictedLaunch {
        rules: Vec<String>,
        from: Vec<ValueId>,
    },
    /// Read from the running process (observe mode).
    ObservedProcess {
        process: ProcessRef,
        source: ObsSource,
    },
    /// Rebuilt by the parent when spawning the child (topology profile).
    ChildDerived {
        parent: ProcessRole,
        child: ProcessRole,
        by: ProfileRuleRef,
        from: Vec<ValueId>,
    },
}
