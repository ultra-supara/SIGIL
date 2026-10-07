//! Level C: code facts reconstructed from one slice (plan §4.4.5; semantics in §4.6.5).
//!
//! Code facts are grouped per slice. `FnId` and `CallId` are unique within their slice; facts in
//! other slices are referenced with [`CallRef`] / [`FnRef`].
//!
//! A [`CallSite`] says a call instruction exists at an address with the recovered arguments, on
//! normal control flow. It does not say the call executes. Behavior claims (level D) are made by
//! profile rules with a [`crate::Support`]; these facts are their evidence.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::evidence::{EvidenceRef, Loc, TriState};
use crate::id::{AtomName, CallId, FnId, ObligationId, ProfileRef, SliceId};
use crate::text::UntrustedText;

/// Every code fact derived from one slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeFacts {
    pub slice: SliceId,
    pub functions: Vec<Function>,
    pub call_sites: Vec<CallSite>,
    pub predicate_checks: Vec<PredicateCheck>,
    pub close_checks: Vec<CloseCheck>,
    pub guard_regions: Vec<GuardRegion>,
    pub must_pass: Vec<MustPass>,
    pub param_mappings: Vec<ParamMapping>,
}

/// A call site in another slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRef {
    pub slice: SliceId,
    pub call: CallId,
}

/// A function in another slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FnRef {
    pub slice: SliceId,
    pub function: FnId,
}

/// A function with its bounds and where the bounds came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Function {
    pub id: FnId,
    pub entry: u64,
    pub end: u64,
    pub bounds: BoundsSource,
    /// Symbol names at `entry`; empty for an unnamed (stripped) function.
    pub names: Vec<UntrustedText>,
}

/// Where function bounds came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BoundsSource {
    EhFrameFde,
    SymbolSize,
}

/// A call or tail jump at an address, with its target and recovered argument values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallSite {
    pub id: CallId,
    pub caller: FnId,
    pub addr: u64,
    pub kind: CallKind,
    pub target: CallTarget,
    /// In argument-register order.
    pub args: Vec<ArgValue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallKind {
    Call,
    TailJump,
}

/// What a call reaches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum CallTarget {
    /// A function in the same slice; `export_name` is `None` when it is not exported.
    Internal {
        entry: u64,
        export_name: Option<UntrustedText>,
    },
    /// The slice's own export reached through its PLT: interposable, so which definition a process
    /// uses is a [`crate::BindingPremise`].
    OwnExportViaPlt { symbol: UntrustedText, entry: u64 },
    /// An imported symbol.
    Import {
        symbol: UntrustedText,
        via: ImportVia,
    },
    /// An indirect call through a recovered value (e.g. the return value of `dl_get_sym`).
    Indirect { value: ArgValue },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportVia {
    Plt,
    PltSec,
    Got,
    Reloc,
}

/// x86_64 general-purpose register (lowercase in JSON).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reg {
    Rax,
    Rbx,
    Rcx,
    Rdx,
    Rsi,
    Rdi,
    Rbp,
    Rsp,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

/// The value a register holds at a call or branch, as far as forward propagation recovers it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ArgValue {
    ConstStr {
        reg: Reg,
        addr: u64,
        value: UntrustedText,
    },
    ConstInt {
        reg: Reg,
        value: i64,
    },
    /// The return value of a call, propagated across blocks.
    ReturnOf {
        reg: Reg,
        call: CallId,
    },
    /// The value of an entry parameter, tracked through callee-saved registers.
    Param {
        reg: Reg,
        index: u8,
    },
    /// Describes `[base+offset]` read at `site`. Names an operand; its content stays unknown.
    Load {
        reg: Reg,
        base: Box<ArgValue>,
        offset: i64,
        width: u8,
        site: u64,
    },
    /// After an 8/16-bit write: only the low `bits` are known.
    Low {
        reg: Reg,
        value: Box<ArgValue>,
        bits: u8,
    },
    /// Disagreeing values at a join (at most 4).
    Set {
        reg: Reg,
        members: Vec<ArgValue>,
    },
    Unknown {
        reg: Reg,
        reason: ValueUnknown,
    },
}

/// Why a register value was not recovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueUnknown {
    /// A caller-saved register after a call.
    ClobberedByCall,
    /// Different values merged at a join (more than a `Set` holds).
    MergedDisagreeing,
    /// Loaded from memory or a stack slot, which is not tracked.
    FromMemory,
    /// Written by an instruction the propagation does not model.
    NotModeled,
}

/// A profile obligation, by profile and ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObligationRef {
    pub profile: ProfileRef,
    pub obligation: ObligationId,
}

/// Candidate-acceptance check (plan §4.6.5): within one iteration, a target call is reached
/// exactly when the profile's predicate over the named atoms holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PredicateCheck {
    pub function: FnId,
    pub iteration_calls: Vec<CallId>,
    pub target_calls: Vec<CallId>,
    /// Profile-named operands, in the profile's order.
    pub atoms: Vec<Atom>,
    /// The obligation that defines the expected predicate (the predicate itself is profile data).
    pub expect: ObligationRef,
    /// Number of atom assignments evaluated.
    pub assignments: u32,
    pub result: CheckResult,
}

/// A profile-named operand and the value it names in this code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Atom {
    pub name: AtomName,
    pub value: ArgValue,
}

/// Close-reach check (plan §4.6.5): a close call is reached on every modeled path from a non-zero
/// open result. It never states which handle is closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseCheck {
    pub function: FnId,
    pub open_calls: Vec<CallId>,
    pub close_calls: Vec<CallId>,
    pub iteration_calls: Vec<CallId>,
    pub result: CheckResult,
}

/// The result of an analyzer check against an expectation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum CheckResult {
    Match,
    /// The code was analyzed and disagrees.
    Mismatch {
        counterexample: Option<BTreeMap<AtomName, i64>>,
        detail: String,
    },
    Unknown {
        reason: CheckUnknown,
    },
}

/// Why an analyzer check could not be decided (plan §4.6.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum CheckUnknown {
    NoFde,
    DecodeFailure(Loc),
    UnidentifiedIndirectCall(CallId),
    UnresolvedIndirectJump(Loc),
    DecidedByUnnamedCondition { assignment: BTreeMap<AtomName, i64> },
    AtomAliasing { atom: AtomName },
    AtomInsideLoop { atom: AtomName },
    NoZeroTestAfterOpen(CallId),
    Budget { what: String, limit: u64 },
}

/// Reference-only evidence: the exact guard list of one build between reaching `from` and
/// calling `to` (plan §4.6.5). Compared only against a reference artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardRegion {
    pub function: FnId,
    pub from: Loc,
    pub to: CallId,
    pub region: RegionKind,
    /// In address order.
    pub guards: Vec<GuardBranch>,
    /// Branches whose successors both still reach `to`: not guards, counted for audit.
    pub converging: u32,
    pub indirect: Vec<CallId>,
    /// `No`/`Unknown` on an unidentified indirect call or jump, a jump table, or a budget hit.
    pub complete: TriState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionKind {
    /// Back edges into `from` are cut.
    PerIteration,
    Acyclic,
}

/// A conditional branch in a guard region with exactly one successor that can still reach `to`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardBranch {
    pub at: u64,
    /// The condition under which control stays in the region.
    pub cond: GuardCond,
    /// On every region path from `from` to `to`.
    pub dominates_to: bool,
    pub exit: ExitKind,
}

/// A branch condition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum GuardCond {
    /// `value op constant`, e.g. `ReturnOf(find) == 0`.
    Compare {
        value: ArgValue,
        op: CmpOp,
        constant: i64,
    },
    /// A condition outside the modeled forms (e.g. a bit test, an operand-to-operand compare).
    Unmodeled { detail: String },
}

/// Comparison operator; `S`/`U` are signed/unsigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CmpOp {
    Eq,
    Ne,
    LtS,
    LeS,
    GtS,
    GeS,
    LtU,
    LeU,
    GtU,
    GeU,
}

/// Where control goes when a guard fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ExitKind {
    /// Back to the next iteration.
    Skip,
    /// Only into noreturn calls.
    Terminate {
        callees: Vec<UntrustedText>,
    },
    Other,
}

/// "From `from`, every normal-control-flow path passes `via` before `until`."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MustPass {
    pub function: FnId,
    pub from: Loc,
    pub via: CallId,
    pub until: Loc,
    pub holds: TriState,
}

/// How a source-level parameter is passed in this binary (plan §5.4). Source parameter numbers
/// are never used as register numbers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamMapping {
    pub function: FnId,
    pub source: SourceParamRef,
    pub binary: BinaryParam,
    pub evidence: Vec<EvidenceRef>,
}

/// A parameter of a source-level function, as named by a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceParamRef {
    pub function: String,
    pub index: u8,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum BinaryParam {
    Reg(Reg),
    Stack {
        offset: i64,
    },
    /// Optimized away (e.g. an unused debug flag).
    Eliminated,
}
