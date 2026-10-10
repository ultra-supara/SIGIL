//! `sigil-model`: the analysis-session model of SIGIL v2 (plan §4.4).
//!
//! A pure data crate. It does no I/O, no parsing of binaries or `/proc`, no policy or profile
//! evaluation, and no analysis. It defines what later stages may **say**, and keeps apart the
//! things that must not be confused:
//!
//! ```text
//! Artifact != FileInstance            Present != Candidate != Mapped != Selected
//! FeatureHint != CallSite             CallSite != Behavior (Support)
//! Behavior != Finding                 Finding != PolicyDecision
//! Verdict != Completeness             Unknown != Pass
//! Unsupported != NotPresent           Configured != Predicted != Observed
//! ReferenceVerified != TargetVerified != FeatureMatch
//! ```
//!
//! [`Session::validate`] checks the invariants the types alone cannot express. See
//! `docs/session-model.md`.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod access;
pub mod artifact;
pub mod binary;
pub mod canonical;
pub mod code;
pub mod coverage;
pub mod evidence;
pub mod finding;
pub mod hint;
pub mod id;
pub mod identity;
pub mod listener;
pub mod load;
pub mod model;
pub mod probe;
pub mod reference;
pub mod relation;
pub mod render;
pub mod session;
pub mod text;
pub mod validate;

pub use access::{
    AccessConclusion, AclEntry, AclState, AclTag, CapabilityAccess, Grant, NodeAccess, Principal,
    PrincipalClaim, WriteAccess, WriteCapability,
};
pub use artifact::{
    Arch, Artifact, DiscoverySource, ElfType, FileInstance, Format, InstanceContent, LinkHop,
    MappingObs, NotReadReason, NsInode, ProcessExe, ProcessObs, ProcessRef, Slice, Stability,
    StatInfo,
};
pub use binary::{
    BinaryFacts, ContainerFacts, DataSymbol, DataValue, ElfFacts, ElfImport, GoBuildInfo, GoModule,
    GoSetting, ARTIFACTS_CONTAINER,
};
pub use code::{
    ArgValue, Atom, BinaryParam, BoundsSource, CallKind, CallRef, CallSite, CallTarget,
    CheckResult, CheckUnknown, CloseCheck, CmpOp, CodeFacts, ExitKind, FnRef, Function,
    GuardBranch, GuardCond, GuardRegion, ImportVia, ObligationRef, ParamMapping, PredicateCheck,
    Reg, RegionKind, SourceParamRef, ValueUnknown,
};
pub use coverage::{AbsenceBasis, BudgetUse, Coverage, CoverageState, SkipReason, Unavailability};
pub use evidence::{
    Assumption, AssumptionAcceptance, Basis, ConfigRef, EvidenceRef, Loc, NotObservable, ObsSource,
    Observability, ProfileRuleRef, Ref, Support, Tri, TriState, UnknownReason,
};
pub use finding::{
    Action, Completeness, CondEvidence, CondState, Condition, Finding, FindingKind, OpenQuestion,
    OpenQuestionDecision, OqTreatment, Outcome, PolicyDecision, PolicyViolation, Settles, Severity,
    ValueNeed, Verdict,
};
pub use hint::{FeatureHint, Signal};
pub use id::{
    AccessId, AnalyzerRef, ArtifactId, AssumptionId, AtomName, AuditScope, CallId, CheckId,
    ComponentKey, CondId, Date, FeatureKey, FindingId, FnId, GroundTruthRef, IdError, IdProblem,
    InstanceId, ListenerId, ModelId, ObligationId, OpenQuestionId, PolicyRuleRef, PremiseId,
    ProbeId, ProcessRole, ProfileRef, ProfileRuleId, RefSetId, RootId, RuleId, Sha256Hex, SliceId,
    Timestamp, ValueId,
};
pub use identity::{
    ComponentClaim, ExtractMethod, IdentityAssertion, IdentityStatus, NameKind, ReleaseBasis,
    ReleaseClaim, SigState, VersionAssertion, VersionSource,
};
pub use listener::{Listener, ListenerOwner, Protocol};
pub use load::{
    CandidateWhy, EffectWhy, LoadContext, LoadFact, LoadFacts, LoaderPhase, ProcessValue, TriValue,
    ValueKey, ValueOrigin,
};
pub use model::{
    digest_hex, BlobLookup, LayerRole, LicenseText, Model, ModelLayer, ModelProvenance,
    LICENSE_MEDIA_TYPE,
};
pub use probe::{is_loopback, target, ActiveFeature, ApiProbe, ProbePhase, ProbeResult};
pub use reference::{
    EntryKind, MemberKind, MemberResult, ReferenceMatch, ARTIFACTS_DISCOVERY, ARTIFACTS_RELEASE,
    INSTALL_ROOT,
};
pub use relation::{
    BindingPremise, BindingState, DeclKind, ObligationResult, ObligationState, Relation,
    RuleSupport, RuleSupportRef, SearchDir, SearchRule,
};
pub use render::aibom::AiBom;
pub use session::{
    KnowledgeKind, KnowledgeRef, Mode, ObservationMeta, RunRequest, ScanRoot, SchemaVersion,
    Session, ToolInfo,
};
pub use text::UntrustedText;
pub use validate::ValidationError;
