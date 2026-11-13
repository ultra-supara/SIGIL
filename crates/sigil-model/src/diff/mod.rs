//! `sigil-diff/1` (#16, PR-16a): what changed between two sessions, and what could not be judged.
//!
//! [`compare`] compares two validated sessions. It is pure and deterministic, as the AI-BOM's
//! projection is. Each [`Change`] carries the IDs of its item in the session(s) that hold it, so
//! every line traces back to evidence there.
//!
//! - **Keys.** Items are matched by what survives a new run: model IDs (manifest paths),
//!   [`Placement`]s, ports, and rules with a normalized [`SubjectKey`]. A slice is keyed by its
//!   placement, its architecture and, in a Mach-O file, its [`MachOCpu`]. Listener inodes,
//!   `binary-<n>` roots and slice IDs are pointers, never keys.
//! - **Comparability.** Saying that something is absent on one side needs the check that would
//!   have recorded it to be closed on that side; otherwise the item is [`NotComparable`], never
//!   removed or resolved. Values recorded on both sides are compared directly.

mod compare;
mod files;
mod judge;
mod judged;
mod listeners;
mod markdown;
mod models;
mod outcome;
mod scope;

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use crate::artifact::Arch;
use crate::evidence::Ref;
use crate::finding::{Completeness, OpenQuestionDecision, PolicyDecision, Verdict};
use crate::id::{
    ArtifactId, CheckId, ComponentKey, FindingId, InstanceId, ListenerId, ModelId, OpenQuestionId,
    PolicyRuleRef, RootId, RuleId, Sha256Hex, SliceId, Timestamp,
};
use crate::identity::IdentityStatus;
use crate::listener::BindClass;
use crate::model::LayerRole;
use crate::render::aibom::ReleaseBasisKind;
use crate::session::{KnowledgeRef, Mode, ToolInfo};
use crate::text::UntrustedText;

pub use compare::compare;
pub use judge::{
    ChangeTreatment, CompareAction, CompareRules, DiffCompleteness, Evaluation,
    NotComparableTreatment, RulesError,
};
pub use markdown::markdown;

/// What changed between two sessions (`sigil-diff/1`). It is read through a record of the same
/// fields (unknown fields refused): a document whose recorded verdict or completeness is not
/// what its own evaluation gives does not load ([`DiffError`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "DiffRecord")]
pub struct Diff {
    pub schema: DiffSchema,
    /// The SIGIL that compared.
    pub tool: ToolInfo,
    pub baseline: DiffSide,
    pub current: DiffSide,
    /// In canonical order ([`Diff::canonicalize`]).
    pub changes: Vec<Change>,
    /// Differences that could not be judged.
    pub not_comparable: Vec<NotComparable>,
    /// How the changes, the items not comparable and the two inputs' completeness were judged
    /// (#16, PR-16b).
    pub evaluation: Evaluation,
}

/// The JSON form of a [`Diff`], before its result is checked.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiffRecord {
    schema: DiffSchema,
    tool: ToolInfo,
    baseline: DiffSide,
    current: DiffSide,
    changes: Vec<Change>,
    not_comparable: Vec<NotComparable>,
    evaluation: Evaluation,
}

/// Why a document is not a diff as SIGIL writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffError {
    /// The recorded verdict and completeness are not what the recorded evaluation's table gives
    /// for the recorded changes, items not comparable and inputs.
    Judgment {
        recorded: (Verdict, DiffCompleteness),
        judged: (Verdict, DiffCompleteness),
    },
}

impl fmt::Display for DiffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiffError::Judgment { recorded, judged } => write!(
                f,
                "the recorded result {:?} + {:?} is not what its evaluation gives: {:?} + {:?}",
                recorded.0, recorded.1, judged.0, judged.1
            ),
        }
    }
}

impl std::error::Error for DiffError {}

impl TryFrom<DiffRecord> for Diff {
    type Error = DiffError;

    /// The record in canonical order, if its evaluation's table gives the recorded result.
    fn try_from(record: DiffRecord) -> Result<Diff, DiffError> {
        let mut diff = Diff {
            schema: record.schema,
            tool: record.tool,
            baseline: record.baseline,
            current: record.current,
            changes: record.changes,
            not_comparable: record.not_comparable,
            evaluation: record.evaluation,
        };
        diff.canonicalize();
        let judged = diff.evaluation.rules().judge(
            &diff.baseline.completeness,
            &diff.current.completeness,
            &diff.changes,
            &diff.not_comparable,
        );
        if judged.verdict() != diff.evaluation.verdict()
            || judged.completeness() != diff.evaluation.completeness()
        {
            return Err(DiffError::Judgment {
                recorded: (
                    diff.evaluation.verdict(),
                    diff.evaluation.completeness().clone(),
                ),
                judged: (judged.verdict(), judged.completeness().clone()),
            });
        }
        Ok(diff)
    }
}

/// The diff schema version. Only `sigil-diff/1` is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffSchema {
    #[serde(rename = "sigil-diff/1")]
    V1,
}

/// One compared session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiffSide {
    /// The SHA-256 of the session's canonical JSON (`Session::to_canonical_json`), computed by
    /// the caller. A session SIGIL saved hashes to its file.
    pub sha256: Sha256Hex,
    pub tool: ToolInfo,
    pub mode: Mode,
    pub started_at: Timestamp,
    /// The policy applied: the session's knowledge entry of kind `Policy`.
    pub policy: Option<KnowledgeRef>,
    /// The session's own completeness, as recorded (`outcome.completeness`). An incomplete
    /// input makes the diff incomplete.
    pub completeness: Completeness,
}

/// Where a file was found, as a key that survives a new run.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Placement {
    /// An instance under `models`, `install` or `service-unit`: its ID is root-relative.
    Instance(InstanceId),
    /// The recorded path of an instance under any other root: `binary-<n>` inputs are numbered
    /// by argument order.
    Path(UntrustedText),
    /// Content that no instance read.
    Content(ArtifactId),
}

/// A Mach-O slice's CPU as lipo tells two slices apart: the CPU type, and the subtype without
/// its capability bits ([`crate::macho_architecture`]).
///
/// Two slices of one fat file can share an [`Arch`] (x86_64 and x86_64h, arm64 and arm64e), so
/// a Mach-O slice's key holds it too. It is the slice's own header's, so a thin file that becomes
/// fat keeps its slice's key, and it does not depend on content, so a rebuild keeps it too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachOCpu {
    pub cpu_type: i32,
    pub cpu_subtype: u32,
}

/// Reads an `Option` field that must be present, `null` when it is `None`: serde alone would
/// read a missing one as `None`.
fn nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// What a finding, policy violation or open question is about, with its run-dependent IDs
/// replaced by keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SubjectKey {
    Model(ModelId),
    Root(RootId),
    /// An instance, by placement.
    Placement(Placement),
    /// A listener, by port.
    Port(u16),
    /// A component claim, by where its slice was found and which slice it is there.
    Component {
        placement: Placement,
        arch: Arch,
        /// The slice's Mach-O CPU; `None` for an ELF slice, or one whose container facts were
        /// not recorded.
        #[serde(deserialize_with = "nullable")]
        macho: Option<MachOCpu>,
        component: ComponentKey,
    },
    /// A slice, by where it was found and which slice it is there.
    Slice {
        placement: Placement,
        arch: Arch,
        /// The slice's Mach-O CPU; `None` for an ELF slice, or one whose container facts were
        /// not recorded.
        #[serde(deserialize_with = "nullable")]
        macho: Option<MachOCpu>,
    },
    /// Any other subject, as recorded.
    Other(Ref),
}

/// An item whose difference could not be judged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Item {
    Model {
        model: ModelId,
    },
    License {
        model: ModelId,
    },
    File {
        placement: Placement,
    },
    Release {
        product: ComponentKey,
    },
    /// A component claim, keyed as [`SubjectKey::Component`].
    Component {
        placement: Placement,
        arch: Arch,
        #[serde(deserialize_with = "nullable")]
        macho: Option<MachOCpu>,
        component: ComponentKey,
    },
    Port {
        port: u16,
    },
    Finding {
        rule: RuleId,
        subject: SubjectKey,
        at: String,
    },
    Violation {
        policy_rule: PolicyRuleRef,
        subject: SubjectKey,
    },
    /// An open question, by rule, normalized subject and what tells it apart (#138).
    OpenQuestion {
        rule: RuleId,
        subject: SubjectKey,
        at: String,
    },
}

/// A difference that could not be judged, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotComparable {
    pub item: Item,
    pub cause: Cause,
    /// The checks involved, sorted: for [`Cause::Coverage`] the ones that would have to be closed
    /// on `open_in`; for [`Cause::Request`] the one the request bears on; none for
    /// [`Cause::Policy`].
    pub checks: Vec<CheckId>,
    /// For [`Cause::Coverage`] the side(s) where `checks` are open; for [`Cause::Request`] the
    /// side that did not ask for the item; [`Side::Both`] for [`Cause::Policy`].
    pub open_in: Side,
}

/// Why a difference could not be judged. Ordered as declared: the keys of a diff's evaluation
/// and of a policy's `[compare.not_comparable]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Cause {
    /// A check is open on `open_in`.
    Coverage,
    /// The two runs asked for different things: other model filters, or a binary input or a
    /// service unit named on one side only.
    Request,
    /// The two sessions applied different policies.
    Policy,
}

impl Cause {
    /// Every cause, in declared order.
    pub const ALL: [Cause; 3] = [Cause::Coverage, Cause::Request, Cause::Policy];

    /// The variant name, as the JSON and a policy write it.
    pub fn name(self) -> &'static str {
        match self {
            Cause::Coverage => "Coverage",
            Cause::Request => "Request",
            Cause::Policy => "Policy",
        }
    }

    /// The cause named `name`, if any.
    pub fn from_name(name: &str) -> Option<Cause> {
        Cause::ALL.into_iter().find(|c| c.name() == name)
    }
}

/// One side of a comparison, or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Side {
    Baseline,
    Current,
    Both,
}

/// What a session recorded of a model's license, with `model_store.license` closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum LicenseState {
    /// The manifest has no license layer.
    NoLayer,
    /// A license layer, read, of this SPDX license.
    Spdx { id: String },
    /// A license layer, read, whose license was not identified.
    Unidentified,
}

/// A release claim, with its basis reduced to its kind (as in the AI-BOM).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseState {
    /// Sorted.
    pub candidates: Vec<String>,
    pub basis: ReleaseBasisKind,
}

/// A component claim. `slice` points at it; it is not part of the key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentState {
    pub slice: SliceId,
    pub status: IdentityStatus,
    /// Sorted, each once.
    pub versions: Vec<UntrustedText>,
}

/// One check of one session: whether it is required, and its entries by coverage state (as the
/// AI-BOM's `CheckSummary`). No entries: open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckState {
    pub required: bool,
    pub states: BTreeMap<String, u32>,
}

/// One difference, with the IDs of its item in the session(s) that hold it. The variants are
/// declared in the Markdown's section order, which is also their canonical order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Change {
    /// The policy applied (each session's `Policy` knowledge entry) differs. Violations are then
    /// not judged, and decisions may differ.
    PolicyChanged {
        baseline: Option<KnowledgeRef>,
        current: Option<KnowledgeRef>,
    },
    VerdictChanged {
        baseline: Verdict,
        current: Verdict,
    },
    /// `Complete` against `Incomplete`; which checks are open is the checks' own change.
    CompletenessChanged {
        baseline: Completeness,
        current: Completeness,
    },
    /// Closed in the baseline, open now.
    CheckOpened {
        check: CheckId,
        baseline: CheckState,
        current: CheckState,
    },
    /// Open in the baseline, closed now.
    CheckClosed {
        check: CheckId,
        baseline: CheckState,
        current: CheckState,
    },
    /// A finding in the current session only. `decisions` are the distinct decisions of the
    /// current side's findings with this key, in canonical order (by JSON text).
    FindingNew {
        rule: RuleId,
        subject: SubjectKey,
        at: String,
        current: Vec<FindingId>,
        decisions: Vec<PolicyDecision>,
    },
    FindingResolved {
        rule: RuleId,
        subject: SubjectKey,
        at: String,
        baseline: Vec<FindingId>,
    },
    /// A finding on both sides whose set of decisions differs: a changed action, reason or
    /// expiry. `baseline` and `current` hold the distinct decisions of the key's findings, and
    /// `baseline_findings` and `current_findings` those findings' IDs in each session.
    FindingDecisionChanged {
        rule: RuleId,
        subject: SubjectKey,
        at: String,
        baseline: Vec<PolicyDecision>,
        current: Vec<PolicyDecision>,
        baseline_findings: Vec<FindingId>,
        current_findings: Vec<FindingId>,
    },
    /// A policy violation in the current session only. `decisions` are the distinct decisions of
    /// the current side's violations with this key, in canonical order (by JSON text).
    ViolationNew {
        policy_rule: PolicyRuleRef,
        subject: SubjectKey,
        current: Vec<Ref>,
        decisions: Vec<PolicyDecision>,
    },
    ViolationResolved {
        policy_rule: PolicyRuleRef,
        subject: SubjectKey,
        baseline: Vec<Ref>,
    },
    /// A violation on both sides whose set of decisions differs. `baseline_subjects` and
    /// `current_subjects` are the violations' subjects in each session.
    ViolationDecisionChanged {
        policy_rule: PolicyRuleRef,
        subject: SubjectKey,
        baseline: Vec<PolicyDecision>,
        current: Vec<PolicyDecision>,
        baseline_subjects: Vec<Ref>,
        current_subjects: Vec<Ref>,
    },
    /// An open question in the current session only (#138). `decisions` are the distinct
    /// decisions of the current side's questions with this key, in canonical order (by JSON text).
    OpenQuestionNew {
        rule: RuleId,
        subject: SubjectKey,
        at: String,
        current: Vec<OpenQuestionId>,
        decisions: Vec<OpenQuestionDecision>,
    },
    OpenQuestionResolved {
        rule: RuleId,
        subject: SubjectKey,
        at: String,
        baseline: Vec<OpenQuestionId>,
    },
    /// An open question on both sides whose set of decisions differs: another treatment, source
    /// or reason (#138). `baseline_questions` and `current_questions` are its IDs in each session.
    OpenQuestionTreatmentChanged {
        rule: RuleId,
        subject: SubjectKey,
        at: String,
        baseline: Vec<OpenQuestionDecision>,
        current: Vec<OpenQuestionDecision>,
        baseline_questions: Vec<OpenQuestionId>,
        current_questions: Vec<OpenQuestionId>,
    },
    ModelAdded {
        model: ModelId,
        name: UntrustedText,
    },
    ModelRemoved {
        model: ModelId,
        name: UntrustedText,
    },
    /// A layer, by role, media type and position among the layers with both: its digest
    /// changed, or it is on one side only.
    LayerChanged {
        model: ModelId,
        role: LayerRole,
        media_type: Option<UntrustedText>,
        ordinal: u32,
        baseline: Option<UntrustedText>,
        current: Option<UntrustedText>,
    },
    LicenseChanged {
        model: ModelId,
        baseline: LicenseState,
        current: LicenseState,
    },
    FileAdded {
        placement: Placement,
        instance: InstanceId,
        content: Option<ArtifactId>,
    },
    FileRemoved {
        placement: Placement,
        instance: InstanceId,
        content: Option<ArtifactId>,
    },
    FileContentChanged {
        placement: Placement,
        baseline: InstanceId,
        current: InstanceId,
        baseline_content: ArtifactId,
        current_content: ArtifactId,
    },
    ReleaseChanged {
        product: ComponentKey,
        baseline: Option<ReleaseState>,
        current: Option<ReleaseState>,
    },
    /// A claim, keyed as [`Item::Component`] (placement, architecture, Mach-O CPU and
    /// component): its status or versions changed, or it is on one side only.
    ComponentChanged {
        placement: Placement,
        arch: Arch,
        #[serde(deserialize_with = "nullable")]
        macho: Option<MachOCpu>,
        component: ComponentKey,
        baseline: Option<ComponentState>,
        current: Option<ComponentState>,
    },
    ListenerAdded {
        port: u16,
        class: BindClass,
        listeners: Vec<ListenerId>,
    },
    ListenerRemoved {
        port: u16,
        class: BindClass,
        listeners: Vec<ListenerId>,
    },
    BindWidened {
        port: u16,
        baseline: BindClass,
        current: BindClass,
        baseline_listeners: Vec<ListenerId>,
        current_listeners: Vec<ListenerId>,
    },
    BindNarrowed {
        port: u16,
        baseline: BindClass,
        current: BindClass,
        baseline_listeners: Vec<ListenerId>,
        current_listeners: Vec<ListenerId>,
    },
}

/// The kind of a [`Change`]: its variant without its fields, in the order `Change` declares
/// them (the canonical order). Serialized as the variant name: the keys of a diff's evaluation
/// and of a policy's `[compare.changes]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ChangeKind {
    PolicyChanged,
    VerdictChanged,
    CompletenessChanged,
    CheckOpened,
    CheckClosed,
    FindingNew,
    FindingResolved,
    FindingDecisionChanged,
    ViolationNew,
    ViolationResolved,
    ViolationDecisionChanged,
    OpenQuestionNew,
    OpenQuestionResolved,
    OpenQuestionTreatmentChanged,
    ModelAdded,
    ModelRemoved,
    LayerChanged,
    LicenseChanged,
    FileAdded,
    FileRemoved,
    FileContentChanged,
    ReleaseChanged,
    ComponentChanged,
    ListenerAdded,
    ListenerRemoved,
    BindWidened,
    BindNarrowed,
}

impl ChangeKind {
    /// Every kind, in declared order.
    pub const ALL: [ChangeKind; 27] = [
        ChangeKind::PolicyChanged,
        ChangeKind::VerdictChanged,
        ChangeKind::CompletenessChanged,
        ChangeKind::CheckOpened,
        ChangeKind::CheckClosed,
        ChangeKind::FindingNew,
        ChangeKind::FindingResolved,
        ChangeKind::FindingDecisionChanged,
        ChangeKind::ViolationNew,
        ChangeKind::ViolationResolved,
        ChangeKind::ViolationDecisionChanged,
        ChangeKind::OpenQuestionNew,
        ChangeKind::OpenQuestionResolved,
        ChangeKind::OpenQuestionTreatmentChanged,
        ChangeKind::ModelAdded,
        ChangeKind::ModelRemoved,
        ChangeKind::LayerChanged,
        ChangeKind::LicenseChanged,
        ChangeKind::FileAdded,
        ChangeKind::FileRemoved,
        ChangeKind::FileContentChanged,
        ChangeKind::ReleaseChanged,
        ChangeKind::ComponentChanged,
        ChangeKind::ListenerAdded,
        ChangeKind::ListenerRemoved,
        ChangeKind::BindWidened,
        ChangeKind::BindNarrowed,
    ];

    /// The variant name, as the JSON and a policy write it.
    pub fn name(self) -> &'static str {
        match self {
            ChangeKind::PolicyChanged => "PolicyChanged",
            ChangeKind::VerdictChanged => "VerdictChanged",
            ChangeKind::CompletenessChanged => "CompletenessChanged",
            ChangeKind::CheckOpened => "CheckOpened",
            ChangeKind::CheckClosed => "CheckClosed",
            ChangeKind::FindingNew => "FindingNew",
            ChangeKind::FindingResolved => "FindingResolved",
            ChangeKind::FindingDecisionChanged => "FindingDecisionChanged",
            ChangeKind::ViolationNew => "ViolationNew",
            ChangeKind::ViolationResolved => "ViolationResolved",
            ChangeKind::ViolationDecisionChanged => "ViolationDecisionChanged",
            ChangeKind::OpenQuestionNew => "OpenQuestionNew",
            ChangeKind::OpenQuestionResolved => "OpenQuestionResolved",
            ChangeKind::OpenQuestionTreatmentChanged => "OpenQuestionTreatmentChanged",
            ChangeKind::ModelAdded => "ModelAdded",
            ChangeKind::ModelRemoved => "ModelRemoved",
            ChangeKind::LayerChanged => "LayerChanged",
            ChangeKind::LicenseChanged => "LicenseChanged",
            ChangeKind::FileAdded => "FileAdded",
            ChangeKind::FileRemoved => "FileRemoved",
            ChangeKind::FileContentChanged => "FileContentChanged",
            ChangeKind::ReleaseChanged => "ReleaseChanged",
            ChangeKind::ComponentChanged => "ComponentChanged",
            ChangeKind::ListenerAdded => "ListenerAdded",
            ChangeKind::ListenerRemoved => "ListenerRemoved",
            ChangeKind::BindWidened => "BindWidened",
            ChangeKind::BindNarrowed => "BindNarrowed",
        }
    }

    /// The kind named `name`, if any.
    pub fn from_name(name: &str) -> Option<ChangeKind> {
        ChangeKind::ALL.into_iter().find(|k| k.name() == name)
    }
}

impl Change {
    /// The change's kind.
    pub fn kind(&self) -> ChangeKind {
        match self {
            Change::PolicyChanged { .. } => ChangeKind::PolicyChanged,
            Change::VerdictChanged { .. } => ChangeKind::VerdictChanged,
            Change::CompletenessChanged { .. } => ChangeKind::CompletenessChanged,
            Change::CheckOpened { .. } => ChangeKind::CheckOpened,
            Change::CheckClosed { .. } => ChangeKind::CheckClosed,
            Change::FindingNew { .. } => ChangeKind::FindingNew,
            Change::FindingResolved { .. } => ChangeKind::FindingResolved,
            Change::FindingDecisionChanged { .. } => ChangeKind::FindingDecisionChanged,
            Change::ViolationNew { .. } => ChangeKind::ViolationNew,
            Change::ViolationResolved { .. } => ChangeKind::ViolationResolved,
            Change::ViolationDecisionChanged { .. } => ChangeKind::ViolationDecisionChanged,
            Change::OpenQuestionNew { .. } => ChangeKind::OpenQuestionNew,
            Change::OpenQuestionResolved { .. } => ChangeKind::OpenQuestionResolved,
            Change::OpenQuestionTreatmentChanged { .. } => ChangeKind::OpenQuestionTreatmentChanged,
            Change::ModelAdded { .. } => ChangeKind::ModelAdded,
            Change::ModelRemoved { .. } => ChangeKind::ModelRemoved,
            Change::LayerChanged { .. } => ChangeKind::LayerChanged,
            Change::LicenseChanged { .. } => ChangeKind::LicenseChanged,
            Change::FileAdded { .. } => ChangeKind::FileAdded,
            Change::FileRemoved { .. } => ChangeKind::FileRemoved,
            Change::FileContentChanged { .. } => ChangeKind::FileContentChanged,
            Change::ReleaseChanged { .. } => ChangeKind::ReleaseChanged,
            Change::ComponentChanged { .. } => ChangeKind::ComponentChanged,
            Change::ListenerAdded { .. } => ChangeKind::ListenerAdded,
            Change::ListenerRemoved { .. } => ChangeKind::ListenerRemoved,
            Change::BindWidened { .. } => ChangeKind::BindWidened,
            Change::BindNarrowed { .. } => ChangeKind::BindNarrowed,
        }
    }

    /// The kind's position in the declaration: the first part of the canonical order.
    fn rank(&self) -> u8 {
        self.kind() as u8
    }

    /// The current session's decisions a change carries: a new finding's or policy violation's,
    /// and the current side of a changed decision (`FindingDecisionChanged`,
    /// `ViolationDecisionChanged`). `None` for every other kind, `VerdictChanged` included: it
    /// carries the verdicts the decisions gave ([`ChangeKind::takes_decided`]). Only findings and
    /// violations carry `PolicyDecision`s; `OpenQuestionNew` and `OpenQuestionTreatmentChanged`
    /// carry their own `OpenQuestionDecision`s, so they are `None` here too.
    pub fn decisions(&self) -> Option<&[PolicyDecision]> {
        match self {
            Change::FindingNew { decisions, .. }
            | Change::ViolationNew { decisions, .. }
            | Change::FindingDecisionChanged {
                current: decisions, ..
            }
            | Change::ViolationDecisionChanged {
                current: decisions, ..
            } => Some(decisions),
            _ => None,
        }
    }

    /// Sorts the lists a change holds.
    fn sort_lists(&mut self) {
        match self {
            Change::FindingNew {
                current: ids,
                decisions,
                ..
            } => {
                ids.sort();
                sort_decisions(decisions);
            }
            Change::FindingResolved { baseline: ids, .. } => ids.sort(),
            Change::ViolationNew {
                current: refs,
                decisions,
                ..
            } => {
                refs.sort_by_cached_key(key);
                refs.dedup();
                sort_decisions(decisions);
            }
            Change::ViolationResolved { baseline: refs, .. } => {
                refs.sort_by_cached_key(key);
                refs.dedup();
            }
            Change::FindingDecisionChanged {
                baseline,
                current,
                baseline_findings,
                current_findings,
                ..
            } => {
                for decisions in [baseline, current] {
                    sort_decisions(decisions);
                }
                for ids in [baseline_findings, current_findings] {
                    ids.sort();
                    ids.dedup();
                }
            }
            Change::ViolationDecisionChanged {
                baseline,
                current,
                baseline_subjects,
                current_subjects,
                ..
            } => {
                for decisions in [baseline, current] {
                    sort_decisions(decisions);
                }
                for refs in [baseline_subjects, current_subjects] {
                    refs.sort_by_cached_key(key);
                    refs.dedup();
                }
            }
            Change::OpenQuestionNew {
                current: ids,
                decisions,
                ..
            } => {
                ids.sort();
                ids.dedup();
                sort_decisions(decisions);
            }
            Change::OpenQuestionResolved { baseline: ids, .. } => {
                ids.sort();
                ids.dedup();
            }
            Change::OpenQuestionTreatmentChanged {
                baseline,
                current,
                baseline_questions,
                current_questions,
                ..
            } => {
                for decisions in [baseline, current] {
                    sort_decisions(decisions);
                }
                for ids in [baseline_questions, current_questions] {
                    ids.sort();
                    ids.dedup();
                }
            }
            Change::ListenerAdded { listeners, .. } | Change::ListenerRemoved { listeners, .. } => {
                listeners.sort();
            }
            Change::BindWidened {
                baseline_listeners,
                current_listeners,
                ..
            }
            | Change::BindNarrowed {
                baseline_listeners,
                current_listeners,
                ..
            } => {
                baseline_listeners.sort();
                current_listeners.sort();
            }
            Change::ReleaseChanged {
                baseline, current, ..
            } => {
                for state in [baseline, current].into_iter().flatten() {
                    state.candidates.sort();
                }
            }
            Change::ComponentChanged {
                baseline, current, ..
            } => {
                for state in [baseline, current].into_iter().flatten() {
                    state.versions.sort();
                    state.versions.dedup();
                }
            }
            Change::CompletenessChanged { baseline, current } => {
                sort_completeness(baseline);
                sort_completeness(current);
            }
            _ => {}
        }
    }
}

impl Diff {
    /// Puts the lists in canonical order: each side's completeness lists sorted, as a session's
    /// are; changes by kind, in declared order, then by their JSON text; non-comparable items by
    /// their JSON text; the lists inside each sorted. Idempotent.
    pub fn canonicalize(&mut self) {
        sort_completeness(&mut self.baseline.completeness);
        sort_completeness(&mut self.current.completeness);
        canonicalize_lists(&mut self.changes, &mut self.not_comparable);
    }

    /// The diff as SIGIL writes it: canonical order, pretty JSON, a final newline.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        let mut canonical = self.clone();
        canonical.canonicalize();
        let mut json = serde_json::to_string_pretty(&canonical)?;
        json.push('\n');
        Ok(json)
    }
}

/// A completeness's lists sorted, as `Session::canonicalize` sorts the outcome's.
fn sort_completeness(completeness: &mut Completeness) {
    if let Completeness::Incomplete {
        missing_required,
        gaps,
    } = completeness
    {
        missing_required.sort();
        gaps.sort();
    }
}

/// A diff's changes and items not comparable in canonical order ([`Diff::canonicalize`]), each
/// once.
fn canonicalize_lists(changes: &mut Vec<Change>, not_comparable: &mut Vec<NotComparable>) {
    for change in changes.iter_mut() {
        change.sort_lists();
    }
    changes.sort_by_cached_key(|c| (c.rank(), key(c)));
    changes.dedup();
    for item in not_comparable.iter_mut() {
        item.checks.sort();
        item.checks.dedup();
    }
    not_comparable.sort_by_cached_key(key);
    not_comparable.dedup();
}

/// A value's JSON text: a total, deterministic order and map key for types without `Ord`.
fn key<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// Decisions (a finding's, a violation's or an open question's) in canonical order (by their
/// JSON text), each once.
fn sort_decisions<T: Serialize + PartialEq>(decisions: &mut Vec<T>) {
    decisions.sort_by_cached_key(key);
    decisions.dedup();
}
