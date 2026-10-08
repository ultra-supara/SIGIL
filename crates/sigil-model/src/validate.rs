//! [`Session::validate`]: invariants the types alone cannot express.
//!
//! - **References resolve and keys are unique.** Every ID or key a fact, claim, condition, or
//!   evidence pointer names exists in the session. IDs are unique in their domain, and so are the
//!   keys records are referred to by: one result per obligation, profile, and slice; one support
//!   per rule and slice; one knowledge entry per kind, ID, and version; one claim per component
//!   and slice; one binding premise, load-facts entry, coverage entry, and capability per key.
//! - **Records that describe the same thing agree.** A check result agrees with the obligation
//!   result it decides; a `ProfileMismatch` names obligations that failed; a mapping listed in
//!   load facts is one recorded for its process.
//! - **Claims do not exceed their evidence.** A condition names the record that decides it and is
//!   `Met` or `NotMet` only as that record settles (plan §4.4.9, [`Session::settles`]); a finding
//!   has every condition established; an identity status is not stronger than its assertions;
//!   `TargetVerified` and `FeatureMatch` name obligations that passed, with locations;
//!   `ReferenceVerified` is about the reference artifact itself.
//! - **Premises are carried** (plan §4.4.7, AC-12). A fact or condition resting on a
//!   `FeatureMatch` carries its unverified premises as unresolved, a decided condition has no
//!   unresolved premise, and `would_evaluate` is never stronger than `candidate`.
//! - **The recorded outcome is consistent** with the recorded decisions and coverage. This does
//!   not evaluate policy: it never decides an action, a treatment, or which checks are required.
//!   It only refuses a session whose verdict, counts, or completeness contradict what it records.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::access::PrincipalClaim;
use crate::artifact::{InstanceContent, ProcessExe, ProcessRef};
use crate::code::{ArgValue, CallTarget, CheckResult, CheckUnknown, CodeFacts};
use crate::coverage::CoverageState;
use crate::evidence::{
    Basis, ConfigRef, EvidenceRef, Loc, Observability, ProfileRuleRef, Ref, Support, Tri,
    UnknownReason,
};
use crate::finding::{
    rule_support_key, Action, Completeness, CondEvidence, CondState, Condition, OqTreatment,
    PolicyDecision, Settles, Verdict,
};
use crate::id::{
    ArtifactId, AssumptionId, CheckId, ComponentKey, CondId, FindingId, InstanceId, ObligationId,
    OpenQuestionId, PremiseId, ProcessRole, ProfileRef, SliceId,
};
use crate::identity::{IdentityAssertion, IdentityStatus, ReleaseBasis};
use crate::load::ValueOrigin;
use crate::relation::{
    BindingState, ObligationState, Relation, RuleSupport, RuleSupportRef, SearchDir,
};
use crate::session::{KnowledgeKind, Session};

/// A specific reason a session is invalid. `at` names where, by list and ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Two entries of one domain share an ID.
    DuplicateId { kind: &'static str, id: String },
    /// A reference to something the session does not contain.
    Dangling {
        kind: &'static str,
        id: String,
        at: String,
    },
    /// A list that must not be empty is empty.
    Empty { what: &'static str, at: String },
    /// A slice ID disagrees with its artifact, architecture, or offset.
    SliceMismatch { slice: SliceId },
    /// `resolved` must be present exactly when `link_chain` is not empty.
    LinkChainInconsistent { instance: InstanceId },
    /// A mapping recorded under a process it does not belong to.
    MappingOfAnotherProcess { pid: u32, at: String },
    /// An identity status stronger than the assertions support.
    StatusUnsupported {
        subject: SliceId,
        component: ComponentKey,
        status: IdentityStatus,
    },
    /// `TargetVerified` names an obligation that did not pass for that profile and slice.
    ObligationNotPassed {
        profile: ProfileRef,
        slice: SliceId,
        obligation: ObligationId,
    },
    /// A check result, or a `ProfileMismatch`, that disagrees with the obligation result recorded
    /// for that profile and slice.
    ObligationResultDisagrees {
        at: String,
        profile: ProfileRef,
        slice: SliceId,
        obligation: ObligationId,
    },
    /// `ReferenceVerified` for a slice whose artifact is not the reference.
    NotTheReference {
        slice: SliceId,
        reference: ArtifactId,
    },
    /// A rule named twice that disagrees: `ReferenceVerified.rule` and its record's rule, or a
    /// relation's rule and the rule of its modeled basis.
    RuleMismatch { at: String },
    /// A coverage state that is about one slice (`ProfileMismatch`) with a scope that is not a
    /// slice.
    ScopeNotASlice { check: CheckId },
    /// A mapping listed in load facts that is about another file.
    MappingOfAnotherFile { instance: InstanceId },
    /// Load facts that list mappings but say mappings were not observable.
    MappedButNotObservable { instance: InstanceId },
    /// An unverified premise of the `FeatureMatch` (or the fact) a claim or condition rests on,
    /// missing from its unresolved premises.
    PremiseDropped { at: String, premise: PremiseId },
    /// `would_evaluate` claims more than `candidate` (plan §4.4.4).
    WouldEvaluateStrongerThanCandidate {
        instance: InstanceId,
        role: ProcessRole,
    },
    /// `Met`/`NotMet` with evidence that settles neither.
    InsufficientEvidence { at: String, condition: CondId },
    /// `Met` with evidence that settles `NotMet`, or the reverse.
    ContradictedByEvidence { at: String, condition: CondId },
    /// `Met`/`NotMet` with unresolved premises (it is `Unknown` until they are resolved).
    DecidedWithUnresolved { at: String, condition: CondId },
    /// An `Unknown` whose reason contradicts its evidence or premises.
    UnknownReasonInconsistent { at: String, condition: CondId },
    /// A finding with a condition that is not `Met` or still has unresolved premises.
    FindingNotEstablished {
        finding: FindingId,
        condition: CondId,
    },
    /// An open question with every condition established (it would be a finding).
    OpenQuestionSettled { question: OpenQuestionId },
    /// An open question with a refuted condition (the rule simply does not apply).
    OpenQuestionRefuted {
        question: OpenQuestionId,
        condition: CondId,
    },
    /// An `Ignore` decision or treatment without a reason.
    IgnoreWithoutReason { at: String },
    /// The verdict is not the maximum action of the recorded decisions.
    VerdictInconsistent {
        recorded: Verdict,
        expected: Verdict,
    },
    /// A confirmed count does not match the findings' decisions.
    CountInconsistent {
        field: &'static str,
        recorded: u32,
        expected: u32,
    },
    /// A required check is not closed but the outcome does not say so.
    RequiredCheckNotClosed { check: CheckId },
    /// `missing_required` lists a check that is not required.
    NotRequired { check: CheckId },
    /// `missing_required` lists a check whose coverage is complete or out of scope.
    ListedCheckClosed { check: CheckId },
    /// An open question treated as a gap that the outcome does not list.
    GapNotListed { question: OpenQuestionId },
    /// `gaps` lists an open question that is missing or not treated as a gap.
    GapNotCountAsGap { question: OpenQuestionId },
    /// `Incomplete` with nothing missing.
    IncompleteWithoutReason,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ValidationError::*;
        match self {
            DuplicateId { kind, id } => write!(f, "duplicate {kind} ID {id}"),
            Dangling { kind, id, at } => write!(f, "{at}: unknown {kind} {id}"),
            Empty { what, at } => write!(f, "{at}: {what} must not be empty"),
            SliceMismatch { slice } => write!(f, "slice {slice} disagrees with its artifact, arch, or offset"),
            LinkChainInconsistent { instance } => {
                write!(f, "instance {instance}: `resolved` must be set exactly when `link_chain` is not empty")
            }
            MappingOfAnotherProcess { pid, at } => write!(f, "{at}: mapping of process {pid} recorded under another process"),
            StatusUnsupported { subject, component, status } => {
                write!(f, "component {component} of {subject}: status {status:?} is stronger than its assertions")
            }
            ObligationNotPassed { profile, slice, obligation } => write!(
                f,
                "TargetVerified for {profile} on {slice} names obligation {obligation}, which did not pass there"
            ),
            ObligationResultDisagrees { at, profile, slice, obligation } => write!(
                f,
                "{at}: disagrees with the result of obligation {obligation} recorded for {profile} on {slice}"
            ),
            NotTheReference { slice, reference } => {
                write!(f, "ReferenceVerified on {slice}, whose artifact is not the reference {reference}")
            }
            RuleMismatch { at } => write!(f, "{at}: names two different rules for the same claim"),
            ScopeNotASlice { check } => write!(f, "coverage[{check}]: a ProfileMismatch must be scoped to a slice"),
            MappingOfAnotherFile { instance } => {
                write!(f, "loads[{instance}]: lists a mapping of another file")
            }
            MappedButNotObservable { instance } => {
                write!(f, "loads[{instance}]: lists mappings but says mappings were not observable")
            }
            PremiseDropped { at, premise } => {
                write!(f, "{at}: does not carry the unresolved premise {premise} of what it rests on")
            }
            WouldEvaluateStrongerThanCandidate { instance, role } => {
                write!(f, "loads[{instance} @ {role}]: would_evaluate is stronger than candidate")
            }
            InsufficientEvidence { at, condition } => {
                write!(f, "{at}: condition {condition} is decided on evidence that settles neither way")
            }
            ContradictedByEvidence { at, condition } => {
                write!(f, "{at}: condition {condition} is the opposite of what its evidence settles")
            }
            DecidedWithUnresolved { at, condition } => {
                write!(f, "{at}: condition {condition} is decided but has unresolved premises")
            }
            UnknownReasonInconsistent { at, condition } => {
                write!(f, "{at}: condition {condition} has an Unknown reason that contradicts its evidence or premises")
            }
            FindingNotEstablished { finding, condition } => write!(
                f,
                "finding {finding}: condition {condition} is not Met without unresolved premises (an open question, not a finding)"
            ),
            OpenQuestionSettled { question } => {
                write!(f, "open question {question}: every condition is established (a finding, not an open question)")
            }
            OpenQuestionRefuted { question, condition } => {
                write!(f, "open question {question}: condition {condition} is NotMet, so the rule does not apply")
            }
            IgnoreWithoutReason { at } => write!(f, "{at}: Ignore needs a reason"),
            VerdictInconsistent { recorded, expected } => {
                write!(f, "outcome: verdict {recorded:?} but the recorded decisions give {expected:?}")
            }
            CountInconsistent { field, recorded, expected } => {
                write!(f, "outcome: {field} is {recorded} but the findings' decisions give {expected}")
            }
            RequiredCheckNotClosed { check } => {
                write!(f, "outcome: required check {check} is not closed but is not reported as missing")
            }
            NotRequired { check } => write!(f, "outcome: missing_required lists {check}, which is not required"),
            ListedCheckClosed { check } => write!(f, "outcome: missing_required lists {check}, whose coverage is closed"),
            GapNotListed { question } => write!(f, "outcome: open question {question} counts as a gap but is not listed"),
            GapNotCountAsGap { question } => {
                write!(f, "outcome: gaps lists {question}, which is not an open question treated as a gap")
            }
            IncompleteWithoutReason => write!(f, "outcome: Incomplete with no missing check and no gap"),
        }
    }
}

impl std::error::Error for ValidationError {}

impl Session {
    /// Checks the invariants described in the module documentation. Returns every violation.
    pub fn validate(&self) -> Result<(), Vec<ValidationError>> {
        let mut v = Validator::new(self);
        v.run();
        if v.errors.is_empty() {
            Ok(())
        } else {
            Err(v.errors)
        }
    }
}

#[derive(Default)]
struct CodeIndex<'a> {
    functions: BTreeSet<&'a str>,
    calls: BTreeSet<&'a str>,
}

struct Validator<'a> {
    s: &'a Session,
    errors: Vec<ValidationError>,
    roots: BTreeSet<&'a str>,
    artifacts: BTreeSet<&'a str>,
    slices: BTreeSet<&'a str>,
    instances: BTreeSet<&'a str>,
    values: BTreeSet<&'a str>,
    access: BTreeSet<&'a str>,
    assumptions: BTreeSet<&'a str>,
    profiles: BTreeSet<String>,
    refsets: BTreeSet<&'a str>,
    processes: Vec<&'a ProcessRef>,
    code: BTreeMap<&'a str, CodeIndex<'a>>,
}

/// Collects IDs, reporting duplicates.
fn unique<'a>(
    errors: &mut Vec<ValidationError>,
    kind: &'static str,
    ids: impl Iterator<Item = &'a str>,
) -> BTreeSet<&'a str> {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(id) {
            errors.push(ValidationError::DuplicateId {
                kind,
                id: id.to_string(),
            });
        }
    }
    seen
}

/// Checks that composite keys are unique, reporting duplicates.
fn unique_keys(
    errors: &mut Vec<ValidationError>,
    kind: &'static str,
    keys: impl Iterator<Item = String>,
) {
    let mut seen = BTreeSet::new();
    for key in keys {
        if seen.contains(&key) {
            errors.push(ValidationError::DuplicateId { kind, id: key });
        } else {
            seen.insert(key);
        }
    }
}

impl<'a> Validator<'a> {
    fn new(s: &'a Session) -> Self {
        let mut errors = vec![];
        let roots = unique(
            &mut errors,
            "root",
            s.request.roots.iter().map(|r| r.id.as_str()),
        );
        let artifacts = unique(
            &mut errors,
            "artifact",
            s.artifacts.iter().map(|a| a.id.as_str()),
        );
        let slices = unique(
            &mut errors,
            "slice",
            s.artifacts
                .iter()
                .flat_map(|a| a.slices.iter().map(|sl| sl.id.as_str())),
        );
        let instances = unique(
            &mut errors,
            "instance",
            s.instances.iter().map(|i| i.id.as_str()),
        );
        let values = unique(&mut errors, "value", s.values.iter().map(|v| v.id.as_str()));
        let access = unique(
            &mut errors,
            "access",
            s.access.iter().map(|a| a.id.as_str()),
        );
        let assumptions = unique(
            &mut errors,
            "assumption",
            s.assumptions.iter().map(|a| a.id.as_str()),
        );
        unique(
            &mut errors,
            "finding",
            s.findings.iter().map(|f| f.id.as_str()),
        );
        unique(
            &mut errors,
            "open question",
            s.open_questions.iter().map(|q| q.id.as_str()),
        );
        unique(
            &mut errors,
            "code facts of slice",
            s.code.iter().map(|c| c.slice.as_str()),
        );
        Self::unique_record_keys(s, &mut errors);
        let profiles = s
            .knowledge
            .iter()
            .filter(|k| k.kind == KnowledgeKind::Profile)
            .map(|k| format!("{}@{}", k.id, k.version))
            .collect();
        let refsets = s
            .knowledge
            .iter()
            .filter(|k| k.kind == KnowledgeKind::ReferenceManifest)
            .map(|k| k.id.as_str())
            .collect();
        let processes = s.processes.iter().map(|p| &p.process).collect();
        let mut code = BTreeMap::new();
        for facts in &s.code {
            let index = CodeIndex {
                functions: unique(
                    &mut errors,
                    "function",
                    facts.functions.iter().map(|f| f.id.as_str()),
                ),
                calls: unique(
                    &mut errors,
                    "call site",
                    facts.call_sites.iter().map(|c| c.id.as_str()),
                ),
            };
            code.insert(facts.slice.as_str(), index);
        }
        Validator {
            s,
            errors,
            roots,
            artifacts,
            slices,
            instances,
            values,
            access,
            assumptions,
            profiles,
            refsets,
            processes,
            code,
        }
    }

    /// The keys other records are referred to by, or that must have one entry each.
    fn unique_record_keys(s: &Session, errors: &mut Vec<ValidationError>) {
        unique_keys(
            errors,
            "knowledge",
            s.knowledge
                .iter()
                .map(|k| format!("{:?} {}@{}", k.kind, k.id, k.version)),
        );
        unique_keys(
            errors,
            "obligation result",
            s.relations.iter().flat_map(|r| match r {
                Relation::ProfileMatch {
                    profile,
                    slice,
                    obligations,
                } => obligations
                    .iter()
                    .map(|o| format!("{} on {profile} {slice}", o.id))
                    .collect(),
                _ => vec![],
            }),
        );
        unique_keys(
            errors,
            "rule support",
            s.rule_support.iter().map(|r| {
                rule_support_key(&RuleSupportRef {
                    profile: r.profile.clone(),
                    rule: r.rule.clone(),
                    slice: r.slice.clone(),
                })
            }),
        );
        unique_keys(
            errors,
            "component claim",
            s.components
                .iter()
                .map(|c| format!("{} on {}", c.component, c.subject)),
        );
        unique_keys(
            errors,
            "binding premise",
            s.bindings.iter().map(|b| {
                format!(
                    "{} {} @ {} -> {}",
                    b.site.slice, b.site.call, b.process_role, b.analyzed_definer
                )
            }),
        );
        unique_keys(
            errors,
            "load facts",
            s.loads.iter().map(|l| {
                format!(
                    "{} @ {} ({})",
                    l.instance, l.context.process_role, l.context.rule
                )
            }),
        );
        unique_keys(
            errors,
            "coverage",
            s.coverage
                .iter()
                .map(|c| format!("{} on {:?}", c.check, c.scope)),
        );
        for record in &s.access {
            unique_keys(
                errors,
                "write capability",
                record
                    .capabilities
                    .iter()
                    .map(|c| format!("{}: {:?}", record.id, c.capability)),
            );
        }
    }

    fn run(&mut self) {
        let s = self.s;
        self.artifacts_and_instances();
        self.processes();
        for value in &s.values {
            let at = format!("values[{}]", value.id);
            self.origin(&value.origin, &at);
            if let crate::load::TriValue::Unknown { reason } = &value.value {
                self.reason(reason, &at);
            }
        }
        self.components();
        for release in &s.releases {
            let at = format!("releases[{}]", release.product);
            if release.candidates.is_empty() {
                self.empty("ReleaseClaim.candidates", &at);
            }
            match &release.basis {
                ReleaseBasis::ReferenceMatches { reference, files } => {
                    self.refset(reference.as_str(), &at);
                    if files.is_empty() {
                        self.empty("ReleaseBasis.files", &at);
                    }
                    for file in files {
                        self.instance(file, &at);
                    }
                }
                ReleaseBasis::SelfReportedCommit { at: evidence, .. } => {
                    self.evidence(evidence, &at)
                }
            }
        }
        for hint in &s.hints {
            let at = format!("hints[{} on {}]", hint.feature, hint.subject);
            self.slice(&hint.subject, &at);
            self.loc(&hint.subject, &hint.at, &at);
        }
        for facts in &s.code {
            self.code_facts(facts);
        }
        for relation in &s.relations {
            self.relation(relation);
        }
        for record in &s.rule_support {
            self.rule_support(record);
        }
        for binding in &s.bindings {
            let at = format!("bindings[{} @ {}]", binding.site.call, binding.process_role);
            self.call_ref(&binding.site.slice, binding.site.call.as_str(), &at);
            self.instance(&binding.analyzed_definer, &at);
            self.binding_state(&binding.state, &at);
        }
        self.loads();
        for record in &s.access {
            let at = format!("access[{}]", record.id);
            match &record.runtime {
                PrincipalClaim::Value { value } => self.value(value.as_str(), &at),
                PrincipalClaim::Unknown { reason } => self.reason(reason, &at),
            }
        }
        for coverage in &s.coverage {
            let at = format!("coverage[{}]", coverage.check);
            self.subject(&coverage.scope, &at);
            match &coverage.state {
                CoverageState::NotPresent { evidence, .. } => {
                    for e in evidence {
                        self.evidence(e, &at);
                    }
                }
                CoverageState::ProfileMismatch { profile, failed } => {
                    self.profile(profile, &at);
                    if failed.is_empty() {
                        self.empty("ProfileMismatch.failed", &at);
                    }
                    let Ref::Slice(slice) = &coverage.scope else {
                        self.errors.push(ValidationError::ScopeNotASlice {
                            check: coverage.check.clone(),
                        });
                        continue;
                    };
                    for obligation in failed {
                        self.agrees(profile, slice, obligation, ObligationState::Fail, &at);
                    }
                }
                _ => {}
            }
        }
        self.findings_and_questions();
        self.outcome();
    }

    // --- reference helpers --------------------------------------------------------------------

    fn dangling(&mut self, kind: &'static str, id: &str, at: &str) {
        self.errors.push(ValidationError::Dangling {
            kind,
            id: id.to_string(),
            at: at.to_string(),
        });
    }

    fn empty(&mut self, what: &'static str, at: &str) {
        self.errors.push(ValidationError::Empty {
            what,
            at: at.to_string(),
        });
    }

    fn artifact(&mut self, id: &ArtifactId, at: &str) {
        if !self.artifacts.contains(id.as_str()) {
            self.dangling("artifact", id.as_str(), at);
        }
    }

    fn slice(&mut self, id: &SliceId, at: &str) {
        if !self.slices.contains(id.as_str()) {
            self.dangling("slice", id.as_str(), at);
        }
    }

    fn instance(&mut self, id: &InstanceId, at: &str) {
        if !self.instances.contains(id.as_str()) {
            self.dangling("instance", id.as_str(), at);
        }
    }

    fn value(&mut self, id: &str, at: &str) {
        if !self.values.contains(id) {
            self.dangling("value", id, at);
        }
    }

    fn profile(&mut self, profile: &ProfileRef, at: &str) {
        if !self.profiles.contains(profile.as_str()) {
            self.dangling("profile", profile.as_str(), at);
        }
    }

    fn refset(&mut self, id: &str, at: &str) {
        if !self.refsets.contains(id) {
            self.dangling("reference manifest", id, at);
        }
    }

    fn assumption(&mut self, id: &AssumptionId, at: &str) {
        if !self.assumptions.contains(id.as_str()) {
            self.dangling("assumption", id.as_str(), at);
        }
    }

    fn process(&mut self, process: &ProcessRef, at: &str) {
        if !self.processes.contains(&process) {
            self.dangling("process", &process.pid.to_string(), at);
        }
    }

    fn config(&mut self, config: &ConfigRef, at: &str) {
        self.instance(&config.file, at);
    }

    fn profile_rule(&mut self, rule: &ProfileRuleRef, at: &str) {
        self.profile(&rule.profile, at);
    }

    fn function(&mut self, slice: &SliceId, id: &str, at: &str) {
        let known = self
            .code
            .get(slice.as_str())
            .is_some_and(|c| c.functions.contains(id));
        if !known {
            self.dangling("function", id, at);
        }
    }

    fn call_ref(&mut self, slice: &SliceId, id: &str, at: &str) {
        self.slice(slice, at);
        let known = self
            .code
            .get(slice.as_str())
            .is_some_and(|c| c.calls.contains(id));
        if !known {
            self.dangling("call site", id, at);
        }
    }

    fn loc(&mut self, slice: &SliceId, loc: &Loc, at: &str) {
        match loc {
            Loc::Function(f) => self.function(slice, f.as_str(), at),
            Loc::CallSite(c) => self.call_ref(slice, c.as_str(), at),
            Loc::FileOffset(_) | Loc::VAddr(_) | Loc::Section { .. } | Loc::Symbol(_) => {}
        }
    }

    fn evidence(&mut self, evidence: &EvidenceRef, at: &str) {
        match evidence {
            EvidenceRef::Artifact { artifact } => self.artifact(artifact, at),
            EvidenceRef::Code { slice, loc } => {
                self.slice(slice, at);
                self.loc(slice, loc, at);
            }
            EvidenceRef::Instance { instance } => self.instance(instance, at),
            EvidenceRef::Config(config) => self.config(config, at),
            EvidenceRef::Process { process } => self.process(process, at),
            EvidenceRef::Value { value } => self.value(value.as_str(), at),
            EvidenceRef::Access { access } => {
                if !self.access.contains(access.as_str()) {
                    self.dangling("access", access.as_str(), at);
                }
            }
            EvidenceRef::ProfileRule(rule) => self.profile_rule(rule, at),
        }
    }

    fn subject(&mut self, subject: &Ref, at: &str) {
        match subject {
            Ref::Audit | Ref::Role(_) | Ref::SearchPath { .. } => {}
            Ref::Root(root) => {
                if !self.roots.contains(root.as_str()) {
                    self.dangling("root", root.as_str(), at);
                }
            }
            Ref::Artifact(a) => self.artifact(a, at),
            Ref::Slice(sl) | Ref::Component { slice: sl, .. } => self.slice(sl, at),
            Ref::Instance(i) => self.instance(i, at),
            Ref::Process(p) => self.process(p, at),
        }
    }

    fn reason(&mut self, reason: &UnknownReason, _at: &str) {
        // Every UnknownReason is self-contained; `CheckIncomplete` may name any check, required
        // or not, so there is nothing to resolve.
        let _ = reason;
    }

    // --- facts --------------------------------------------------------------------------------

    fn artifacts_and_instances(&mut self) {
        let s = self.s;
        for artifact in &s.artifacts {
            for slice in &artifact.slices {
                if SliceId::from_parts(&artifact.id, slice.arch, slice.offset) != slice.id {
                    self.errors.push(ValidationError::SliceMismatch {
                        slice: slice.id.clone(),
                    });
                }
            }
        }
        for instance in &s.instances {
            let at = format!("instances[{}]", instance.id);
            if !self.roots.contains(instance.root.as_str()) {
                self.dangling("root", instance.root.as_str(), &at);
            }
            if let InstanceContent::Read { artifact } = &instance.content {
                self.artifact(artifact, &at);
            }
            if instance.link_chain.is_empty() != instance.resolved.is_none() {
                self.errors.push(ValidationError::LinkChainInconsistent {
                    instance: instance.id.clone(),
                });
            }
            for source in &instance.discovered_by {
                match source {
                    crate::artifact::DiscoverySource::Walk => {}
                    crate::artifact::DiscoverySource::ServiceUnit { config } => {
                        self.config(config, &at)
                    }
                    crate::artifact::DiscoverySource::ProcessExe { process } => {
                        self.process(process, &at)
                    }
                }
            }
        }
    }

    fn processes(&mut self) {
        let s = self.s;
        for obs in &s.processes {
            let at = format!("processes[{}]", obs.process.pid);
            if let ProcessExe::Instance { instance } = &obs.exe {
                self.instance(instance, &at);
            }
            for mapping in &obs.mappings {
                if mapping.process != obs.process {
                    self.errors.push(ValidationError::MappingOfAnotherProcess {
                        pid: mapping.process.pid,
                        at: at.clone(),
                    });
                }
                if let Some(instance) = &mapping.instance {
                    self.instance(instance, &at);
                }
                self.tri(&mapping.same_mount_ns, &at);
            }
        }
    }

    fn origin(&mut self, origin: &ValueOrigin, at: &str) {
        match origin {
            ValueOrigin::Configured { file, .. } => self.config(file, at),
            ValueOrigin::PredictedLaunch { from, .. } => {
                for value in from {
                    self.value(value.as_str(), at);
                }
            }
            ValueOrigin::ObservedProcess { process, .. } => self.process(process, at),
            ValueOrigin::ChildDerived { by, from, .. } => {
                self.profile_rule(by, at);
                for value in from {
                    self.value(value.as_str(), at);
                }
            }
        }
    }

    fn components(&mut self) {
        let s = self.s;
        for claim in &s.components {
            let at = format!("components[{} on {}]", claim.component, claim.subject);
            self.slice(&claim.subject, &at);
            let mut self_named = false;
            let mut required = false;
            let mut code_match = false;
            let mut hash_match = false;
            for assertion in &claim.assertions {
                match assertion {
                    IdentityAssertion::SelfName { at: e, .. } => {
                        self_named = true;
                        self.evidence(e, &at);
                    }
                    IdentityAssertion::Required { by, .. } => {
                        required = true;
                        self.slice(by, &at);
                    }
                    IdentityAssertion::Embedded { at: e, .. } => {
                        self_named = true;
                        self.evidence(e, &at);
                    }
                    IdentityAssertion::CodeCheck {
                        profile,
                        check,
                        result,
                        at: evidence,
                    } => {
                        self.profile(profile, &at);
                        self.check_result(&claim.subject, result, &at);
                        self.check_agrees(profile, &claim.subject, check, result, &at);
                        for e in evidence {
                            self.evidence(e, &at);
                        }
                        code_match |= matches!(result, CheckResult::Match);
                    }
                    IdentityAssertion::KnownHash {
                        reference, matched, ..
                    } => {
                        self.refset(reference.as_str(), &at);
                        hash_match |= *matched;
                    }
                    IdentityAssertion::Signature { .. } => {}
                }
            }
            for version in &claim.versions {
                self.evidence(&version.at, &at);
            }
            let supported = match claim.status {
                IdentityStatus::Conflicting => claim.assertions.len() + claim.versions.len() >= 2,
                IdentityStatus::ReferenceMatched => hash_match,
                IdentityStatus::Corroborated => code_match && self_named,
                IdentityStatus::NameOnly => self_named || required,
                IdentityStatus::Unidentified => true,
            };
            if !supported {
                self.errors.push(ValidationError::StatusUnsupported {
                    subject: claim.subject.clone(),
                    component: claim.component.clone(),
                    status: claim.status,
                });
            }
        }
    }

    fn arg(&mut self, slice: &SliceId, value: &ArgValue, at: &str) {
        match value {
            ArgValue::ReturnOf { call, .. } => self.call_ref(slice, call.as_str(), at),
            ArgValue::Load { base, .. } => self.arg(slice, base, at),
            ArgValue::Low { value, .. } => self.arg(slice, value, at),
            ArgValue::Set { members, .. } => {
                for member in members {
                    self.arg(slice, member, at);
                }
            }
            ArgValue::ConstStr { .. }
            | ArgValue::ConstInt { .. }
            | ArgValue::Param { .. }
            | ArgValue::Unknown { .. } => {}
        }
    }

    fn check_result(&mut self, slice: &SliceId, result: &CheckResult, at: &str) {
        if let CheckResult::Unknown { reason } = result {
            match reason {
                CheckUnknown::DecodeFailure(loc) | CheckUnknown::UnresolvedIndirectJump(loc) => {
                    self.loc(slice, loc, at)
                }
                CheckUnknown::UnidentifiedIndirectCall(call)
                | CheckUnknown::NoZeroTestAfterOpen(call) => {
                    self.call_ref(slice, call.as_str(), at)
                }
                _ => {}
            }
        }
    }

    fn code_facts(&mut self, facts: &CodeFacts) {
        let slice = &facts.slice;
        let at = format!("code[{slice}]");
        self.slice(slice, &at);
        for call in &facts.call_sites {
            let at = format!("code[{slice}].call_sites[{}]", call.id);
            self.function(slice, call.caller.as_str(), &at);
            for arg in &call.args {
                self.arg(slice, arg, &at);
            }
            if let CallTarget::Indirect { value } = &call.target {
                self.arg(slice, value, &at);
            }
        }
        let calls = |list: &[crate::id::CallId]| {
            list.iter()
                .map(|c| c.as_str().to_string())
                .collect::<Vec<_>>()
        };
        for check in &facts.predicate_checks {
            let at = format!("code[{slice}].predicate_checks[{}]", check.function);
            self.function(slice, check.function.as_str(), &at);
            for call in calls(&check.iteration_calls)
                .iter()
                .chain(calls(&check.target_calls).iter())
            {
                self.call_ref(slice, call, &at);
            }
            for atom in &check.atoms {
                self.arg(slice, &atom.value, &at);
            }
            self.profile(&check.expect.profile, &at);
            self.check_result(slice, &check.result, &at);
            self.check_agrees(
                &check.expect.profile,
                slice,
                &check.expect.obligation,
                &check.result,
                &at,
            );
        }
        for check in &facts.close_checks {
            let at = format!("code[{slice}].close_checks[{}]", check.function);
            self.function(slice, check.function.as_str(), &at);
            for list in [
                &check.open_calls,
                &check.close_calls,
                &check.iteration_calls,
            ] {
                for call in calls(list) {
                    self.call_ref(slice, &call, &at);
                }
            }
            self.check_result(slice, &check.result, &at);
        }
        for region in &facts.guard_regions {
            let at = format!(
                "code[{slice}].guard_regions[{} -> {}]",
                region.function, region.to
            );
            self.function(slice, region.function.as_str(), &at);
            self.loc(slice, &region.from, &at);
            self.call_ref(slice, region.to.as_str(), &at);
            for call in calls(&region.indirect) {
                self.call_ref(slice, &call, &at);
            }
            for guard in &region.guards {
                if let crate::code::GuardCond::Compare { value, .. } = &guard.cond {
                    self.arg(slice, value, &at);
                }
            }
        }
        for mapping in &facts.param_mappings {
            let at = format!("code[{slice}].param_mappings[{}]", mapping.function);
            self.function(slice, mapping.function.as_str(), &at);
            for e in &mapping.evidence {
                self.evidence(e, &at);
            }
        }
    }

    fn relation(&mut self, relation: &Relation) {
        match relation {
            Relation::Declares { from, .. } => {
                self.slice(from, &format!("relations[Declares from {from}]"))
            }
            Relation::Candidate {
                from, candidate, ..
            } => {
                let at = format!("relations[Candidate {candidate} for {from}]");
                self.slice(from, &at);
                self.instance(candidate, &at);
            }
            Relation::SymbolCandidate { site, definer, .. } => {
                let at = format!("relations[SymbolCandidate {}]", site.call);
                self.call_ref(&site.slice, site.call.as_str(), &at);
                self.slice(&definer.slice, &at);
                self.function(&definer.slice, definer.function.as_str(), &at);
            }
            Relation::ProfileMatch {
                profile,
                slice,
                obligations,
            } => {
                let at = format!("relations[ProfileMatch {profile} on {slice}]");
                self.profile(profile, &at);
                self.slice(slice, &at);
                for obligation in obligations {
                    let at = format!("{at}.obligations[{}]", obligation.id);
                    if obligation.result == ObligationState::Pass && obligation.at.is_empty() {
                        self.empty("ObligationResult.at", &at);
                    }
                    for loc in &obligation.at {
                        self.loc(slice, loc, &at);
                    }
                }
            }
            Relation::SearchPath {
                role,
                search_path,
                rule,
                dir,
                basis,
                unresolved,
            } => {
                let at = format!("relations[SearchPath {search_path} @ {role}]");
                self.profile_rule(rule, &at);
                self.same_rule(rule, basis, &at);
                match dir {
                    SearchDir::ExeDir { instance } => self.instance(instance, &at),
                    SearchDir::Value { value } => self.value(value.as_str(), &at),
                    SearchDir::Unknown { reason } => self.reason(reason, &at),
                }
                self.premises(basis, unresolved, &at);
            }
            Relation::Spawns {
                parent,
                child,
                rule,
                basis,
                unresolved,
            } => {
                let at = format!("relations[Spawns {parent} -> {child}]");
                self.profile_rule(rule, &at);
                self.same_rule(rule, basis, &at);
                self.premises(basis, unresolved, &at);
            }
        }
    }

    /// The result recorded for `obligation` of `profile` on `slice`. Results are unique per key
    /// (duplicates are reported), so the first is the only one.
    fn obligation_state(
        &self,
        profile: &ProfileRef,
        slice: &SliceId,
        obligation: &ObligationId,
    ) -> Option<ObligationState> {
        self.s.relations.iter().find_map(|r| match r {
            Relation::ProfileMatch {
                profile: p,
                slice: sl,
                obligations,
            } if p == profile && sl == slice => obligations
                .iter()
                .find(|o| o.id == *obligation)
                .map(|o| o.result),
            _ => None,
        })
    }

    fn passed(&self, profile: &ProfileRef, slice: &SliceId, obligation: &ObligationId) -> bool {
        self.obligation_state(profile, slice, obligation) == Some(ObligationState::Pass)
    }

    /// `obligation` is recorded with `expected` for `profile` on `slice`.
    fn agrees(
        &mut self,
        profile: &ProfileRef,
        slice: &SliceId,
        obligation: &ObligationId,
        expected: ObligationState,
        at: &str,
    ) {
        if self.obligation_state(profile, slice, obligation) != Some(expected) {
            self.errors
                .push(ValidationError::ObligationResultDisagrees {
                    at: at.to_string(),
                    profile: profile.clone(),
                    slice: slice.clone(),
                    obligation: obligation.clone(),
                });
        }
    }

    /// A check that decides `obligation` agrees with the obligation's result, if one is recorded.
    fn check_agrees(
        &mut self,
        profile: &ProfileRef,
        slice: &SliceId,
        obligation: &ObligationId,
        result: &CheckResult,
        at: &str,
    ) {
        let expected = match result {
            CheckResult::Match => ObligationState::Pass,
            CheckResult::Mismatch { .. } => ObligationState::Fail,
            CheckResult::Unknown { .. } => ObligationState::Unknown,
        };
        if self
            .obligation_state(profile, slice, obligation)
            .is_some_and(|state| state != expected)
        {
            self.agrees(profile, slice, obligation, expected, at);
        }
    }

    // --- claims -------------------------------------------------------------------------------

    /// The only place a `Support` is recorded, so the only place its claims are checked.
    fn rule_support(&mut self, record: &RuleSupport) {
        let RuleSupport {
            profile,
            rule,
            slice,
            support,
        } = record;
        let at = format!("rule_support[{profile} {rule} on {slice}]");
        self.profile(profile, &at);
        self.slice(slice, &at);
        let must_pass: &[ObligationId] = match support {
            Support::TargetVerified { obligations } => {
                if obligations.is_empty() {
                    self.empty("TargetVerified.obligations", &at);
                }
                obligations
            }
            Support::FeatureMatch {
                matched,
                unverified,
            } => {
                if unverified.is_empty() {
                    self.empty("FeatureMatch.unverified", &at);
                }
                matched
            }
            Support::ReferenceVerified {
                reference,
                rule: verified_rule,
                ..
            } => {
                if slice.artifact() != *reference {
                    self.errors.push(ValidationError::NotTheReference {
                        slice: slice.clone(),
                        reference: reference.clone(),
                    });
                }
                if verified_rule != rule {
                    self.errors
                        .push(ValidationError::RuleMismatch { at: at.clone() });
                }
                &[]
            }
            Support::Assumed { assumption } => {
                self.assumption(assumption, &at);
                &[]
            }
        };
        for obligation in must_pass {
            if !self.passed(profile, slice, obligation) {
                self.errors.push(ValidationError::ObligationNotPassed {
                    profile: profile.clone(),
                    slice: slice.clone(),
                    obligation: obligation.clone(),
                });
            }
        }
    }

    /// The rule support `key` names.
    fn rule_support_of(&mut self, key: &RuleSupportRef, at: &str) -> Option<&'a RuleSupport> {
        let s = self.s;
        let record = s.rule_support_of(key);
        if record.is_none() {
            self.dangling("rule support", &rule_support_key(key), at);
        }
        record
    }

    fn basis(&mut self, basis: &Basis, at: &str) {
        match basis {
            Basis::Observed { .. } => {}
            Basis::Derived { inputs, .. } => {
                if inputs.is_empty() {
                    self.empty("Derived.inputs", at);
                }
                for input in inputs {
                    self.evidence(input, at);
                }
            }
            Basis::Modeled(key) => {
                self.rule_support_of(key, at);
            }
            Basis::Assumed { assumption } => self.assumption(assumption, at),
        }
    }

    /// Weakest link (plan §4.4.7, AC-12): a fact resting on a `FeatureMatch` carries its
    /// unverified premises as unresolved, so it is never stronger than the support.
    fn premises(&mut self, basis: &Basis, unresolved: &[PremiseId], at: &str) {
        self.basis(basis, at);
        if let Basis::Modeled(key) = basis {
            if let Some(record) = self.s.rule_support_of(key) {
                self.carried(&record.support, unresolved, at);
            }
        }
    }

    /// Every unverified premise of a `FeatureMatch` is among `unresolved`.
    fn carried(&mut self, support: &Support, unresolved: &[PremiseId], at: &str) {
        if let Support::FeatureMatch { unverified, .. } = support {
            self.all_carried(unverified, unresolved, at);
        }
    }

    fn all_carried(&mut self, premises: &[PremiseId], unresolved: &[PremiseId], at: &str) {
        for premise in premises {
            if !unresolved.contains(premise) {
                self.errors.push(ValidationError::PremiseDropped {
                    at: at.to_string(),
                    premise: premise.clone(),
                });
            }
        }
    }

    /// A relation that names a profile rule and rests on a modeled basis names one rule.
    fn same_rule(&mut self, rule: &ProfileRuleRef, basis: &Basis, at: &str) {
        if let Basis::Modeled(key) = basis {
            if key.profile != rule.profile || key.rule != rule.rule {
                self.errors
                    .push(ValidationError::RuleMismatch { at: at.to_string() });
            }
        }
    }

    /// Whether a basis is verified, for the "never stronger than" rule: observed, derived, or a
    /// verified rule support. Acceptance of an assumption does not make it verified.
    fn verified(&self, basis: &Basis) -> bool {
        match basis {
            Basis::Observed { .. } | Basis::Derived { .. } => true,
            Basis::Modeled(key) => self
                .s
                .rule_support_of(key)
                .is_some_and(|r| r.support.is_verified()),
            Basis::Assumed { .. } => false,
        }
    }

    fn tri<T>(&mut self, tri: &Tri<T>, at: &str) {
        match tri {
            Tri::Yes {
                basis, unresolved, ..
            }
            | Tri::No { basis, unresolved } => self.premises(basis, unresolved, at),
            Tri::Unknown { reason } => self.reason(reason, at),
        }
    }

    fn binding_state(&mut self, state: &BindingState, at: &str) {
        match state {
            BindingState::Verified { scope } => {
                for instance in scope {
                    self.instance(instance, at);
                }
            }
            BindingState::Assumed { assumption } => self.assumption(assumption, at),
            BindingState::Unknown { reason } => self.reason(reason, at),
            BindingState::Mismatch { first_definer } => self.instance(first_definer, at),
        }
    }

    fn loads(&mut self) {
        let s = self.s;
        for load in &s.loads {
            let at = format!("loads[{} @ {}]", load.instance, load.context.process_role);
            self.instance(&load.instance, &at);
            self.tri(&load.candidate, &format!("{at}.candidate"));
            self.tri(&load.would_evaluate, &format!("{at}.would_evaluate"));
            self.tri(&load.selectable, &format!("{at}.selectable"));
            self.tri(
                &load.used_for_inference,
                &format!("{at}.used_for_inference"),
            );
            for mapping in &load.mapped {
                if mapping.instance.as_ref() != Some(&load.instance) {
                    self.errors.push(ValidationError::MappingOfAnotherFile {
                        instance: load.instance.clone(),
                    });
                }
                let recorded = s
                    .processes
                    .iter()
                    .any(|p| p.process == mapping.process && p.mappings.contains(mapping));
                if !recorded {
                    self.dangling(
                        "mapping observation",
                        &format!("pid {} at {}", mapping.process.pid, mapping.at),
                        &at,
                    );
                }
            }
            if !load.mapped.is_empty()
                && matches!(load.mapping_observability, Observability::NotObservable(_))
            {
                self.errors.push(ValidationError::MappedButNotObservable {
                    instance: load.instance.clone(),
                });
            }
            if let Tri::Yes {
                basis: evaluate_basis,
                unresolved: evaluate_unresolved,
                ..
            } = &load.would_evaluate
            {
                let stronger = match &load.candidate {
                    Tri::Yes {
                        basis: candidate_basis,
                        unresolved: candidate_unresolved,
                        ..
                    } => {
                        candidate_unresolved
                            .iter()
                            .any(|p| !evaluate_unresolved.contains(p))
                            || (!self.verified(candidate_basis) && self.verified(evaluate_basis))
                    }
                    Tri::No { .. } | Tri::Unknown { .. } => true,
                };
                if stronger {
                    self.errors
                        .push(ValidationError::WouldEvaluateStrongerThanCandidate {
                            instance: load.instance.clone(),
                            role: load.context.process_role.clone(),
                        });
                }
            }
        }
    }

    /// What `evidence` settles, reporting what it names that the session does not contain, and
    /// that the condition carries the unresolved premises of what it rests on.
    fn cond_evidence(
        &mut self,
        evidence: &CondEvidence,
        condition: &Condition,
        at: &str,
    ) -> Option<Settles> {
        let s = self.s;
        let at_condition = format!("{at}.conditions[{}]", condition.id);
        match evidence {
            CondEvidence::Behavior(key) => {
                if let Some(record) = self.rule_support_of(key, at) {
                    self.carried(&record.support, &condition.unresolved, &at_condition);
                }
            }
            CondEvidence::Load {
                instance,
                context,
                fact,
            } => {
                let premises = s
                    .loads
                    .iter()
                    .find(|l| l.instance == *instance && l.context == *context)
                    .and_then(|l| l.fact(*fact))
                    .map(|(_, _, unresolved)| unresolved);
                if let Some(premises) = premises {
                    self.all_carried(premises, &condition.unresolved, &at_condition);
                }
            }
            CondEvidence::Observed { facts } => {
                for fact in facts {
                    self.evidence(fact, at);
                }
            }
            CondEvidence::Access { .. }
            | CondEvidence::Value { .. }
            | CondEvidence::Binding { .. }
            | CondEvidence::Identity { .. } => {}
        }
        match s.resolve(evidence) {
            Ok(settles) => Some(settles),
            Err(missing) => {
                // A missing rule support was reported above.
                if !matches!(evidence, CondEvidence::Behavior(_)) {
                    self.dangling(missing.kind, &missing.id, at);
                }
                None
            }
        }
    }

    fn condition(&mut self, condition: &Condition, at: &str) {
        let error = |make: fn(String, CondId) -> ValidationError| {
            make(at.to_string(), condition.id.clone())
        };
        match &condition.state {
            CondState::Met { evidence } | CondState::NotMet { evidence } => {
                let met = matches!(condition.state, CondState::Met { .. });
                let settles = self.cond_evidence(evidence, condition, at);
                let problem = match settles {
                    None | Some(Settles::Either) => None,
                    Some(Settles::Met) if met => None,
                    Some(Settles::NotMet) if !met => None,
                    Some(Settles::Neither) => Some(error(|at, condition| {
                        ValidationError::InsufficientEvidence { at, condition }
                    })),
                    Some(Settles::Met | Settles::NotMet) => Some(error(|at, condition| {
                        ValidationError::ContradictedByEvidence { at, condition }
                    })),
                };
                self.errors.extend(problem);
                if !condition.unresolved.is_empty() {
                    self.errors.push(error(|at, condition| {
                        ValidationError::DecidedWithUnresolved { at, condition }
                    }));
                }
            }
            CondState::Unknown { reason, evidence } => {
                self.reason(reason, at);
                let settles = evidence
                    .as_ref()
                    .and_then(|e| self.cond_evidence(e, condition, at));
                let inconsistent = match reason {
                    // Evidence is named, and it settles neither way.
                    UnknownReason::InsufficientEvidence => match (evidence, settles) {
                        (None, _) => true,
                        (Some(_), settles) => settles.is_some_and(|s| s != Settles::Neither),
                    },
                    UnknownReason::PremiseUnresolved => condition.unresolved.is_empty(),
                    _ => false,
                };
                if inconsistent {
                    self.errors.push(error(|at, condition| {
                        ValidationError::UnknownReasonInconsistent { at, condition }
                    }));
                }
            }
        }
    }

    fn conditions(&mut self, conditions: &[Condition], at: &str) {
        if conditions.is_empty() {
            self.empty("conditions", at);
        }
        unique(
            &mut self.errors,
            "condition",
            conditions.iter().map(|c| c.id.as_str()),
        );
        for condition in conditions {
            self.condition(condition, at);
        }
    }

    fn decision(&mut self, decision: &PolicyDecision, at: &str) {
        if decision.action == Action::Ignore
            && decision
                .reason
                .as_deref()
                .is_none_or(|r| r.trim().is_empty())
        {
            self.errors
                .push(ValidationError::IgnoreWithoutReason { at: at.to_string() });
        }
    }

    fn findings_and_questions(&mut self) {
        let s = self.s;
        for finding in &s.findings {
            let at = format!("findings[{}]", finding.id);
            self.subject(&finding.subject, &at);
            self.conditions(&finding.conditions, &at);
            for condition in &finding.conditions {
                if !matches!(condition.state, CondState::Met { .. })
                    || !condition.unresolved.is_empty()
                {
                    self.errors.push(ValidationError::FindingNotEstablished {
                        finding: finding.id.clone(),
                        condition: condition.id.clone(),
                    });
                }
            }
            if finding.evidence.is_empty() {
                self.empty("Finding.evidence", &at);
            }
            for e in &finding.evidence {
                self.evidence(e, &at);
            }
            self.decision(&finding.decision, &at);
        }
        for question in &s.open_questions {
            let at = format!("open_questions[{}]", question.id);
            self.subject(&question.subject, &at);
            self.conditions(&question.conditions, &at);
            for condition in &question.conditions {
                if matches!(condition.state, CondState::NotMet { .. }) {
                    self.errors.push(ValidationError::OpenQuestionRefuted {
                        question: question.id.clone(),
                        condition: condition.id.clone(),
                    });
                }
            }
            let settled = question
                .conditions
                .iter()
                .all(|c| matches!(c.state, CondState::Met { .. }) && c.unresolved.is_empty());
            if settled && !question.conditions.is_empty() {
                self.errors.push(ValidationError::OpenQuestionSettled {
                    question: question.id.clone(),
                });
            }
            for e in &question.evidence {
                self.evidence(e, &at);
            }
            let d = &question.decision;
            if d.treatment == OqTreatment::Ignore
                && d.reason.as_deref().is_none_or(|r| r.trim().is_empty())
            {
                self.errors
                    .push(ValidationError::IgnoreWithoutReason { at: at.clone() });
            }
        }
        for violation in &s.policy_violations {
            let at = format!("policy_violations[{}]", violation.policy_rule);
            self.subject(&violation.subject, &at);
            for e in &violation.evidence {
                self.evidence(e, &at);
            }
            self.decision(&violation.decision, &at);
        }
    }

    // --- outcome ------------------------------------------------------------------------------

    fn outcome(&mut self) {
        let s = self.s;
        let outcome = &s.outcome;
        let from_action = |a: Action| match a {
            Action::Fail => Some(Verdict::Fail),
            Action::Warn => Some(Verdict::Warn),
            Action::Ignore => None,
        };
        let expected = s
            .findings
            .iter()
            .map(|f| from_action(f.decision.action))
            .chain(
                s.policy_violations
                    .iter()
                    .map(|v| from_action(v.decision.action)),
            )
            .chain(s.open_questions.iter().map(|q| match q.decision.treatment {
                OqTreatment::Fail => Some(Verdict::Fail),
                OqTreatment::Warn => Some(Verdict::Warn),
                OqTreatment::CountAsGap | OqTreatment::Ignore => None,
            }))
            .flatten()
            .max()
            .unwrap_or(Verdict::Pass);
        if outcome.verdict != expected {
            self.errors.push(ValidationError::VerdictInconsistent {
                recorded: outcome.verdict,
                expected,
            });
        }
        let count = |action| {
            u32::try_from(
                s.findings
                    .iter()
                    .filter(|f| f.decision.action == action)
                    .count(),
            )
            .unwrap_or(u32::MAX)
        };
        for (field, recorded, expected) in [
            (
                "confirmed_failures",
                outcome.confirmed_failures,
                count(Action::Fail),
            ),
            (
                "confirmed_warnings",
                outcome.confirmed_warnings,
                count(Action::Warn),
            ),
        ] {
            if recorded != expected {
                self.errors.push(ValidationError::CountInconsistent {
                    field,
                    recorded,
                    expected,
                });
            }
        }

        let closed = |check: &CheckId| {
            states(s, check).count() > 0 && states(s, check).all(CoverageState::can_close)
        };
        let definitely_closed = |check: &CheckId| {
            states(s, check).count() > 0
                && states(s, check).all(|st| {
                    matches!(
                        st,
                        CoverageState::Complete | CoverageState::OutOfScope { .. }
                    )
                })
        };
        let open_checks: Vec<&CheckId> = s
            .request
            .required_checks
            .iter()
            .filter(|c| !closed(c))
            .collect();
        let gap_questions: Vec<&OpenQuestionId> = s
            .open_questions
            .iter()
            .filter(|q| q.decision.treatment == OqTreatment::CountAsGap)
            .map(|q| &q.id)
            .collect();
        let (listed_checks, listed_gaps): (&[CheckId], &[OpenQuestionId]) =
            match &outcome.completeness {
                Completeness::Complete => (&[], &[]),
                Completeness::Incomplete {
                    missing_required,
                    gaps,
                } => {
                    if missing_required.is_empty() && gaps.is_empty() {
                        self.errors.push(ValidationError::IncompleteWithoutReason);
                    }
                    (missing_required, gaps)
                }
            };
        for check in open_checks {
            if !listed_checks.contains(check) {
                self.errors.push(ValidationError::RequiredCheckNotClosed {
                    check: check.clone(),
                });
            }
        }
        for check in listed_checks {
            if !s.request.required_checks.contains(check) {
                self.errors.push(ValidationError::NotRequired {
                    check: check.clone(),
                });
            } else if definitely_closed(check) {
                self.errors.push(ValidationError::ListedCheckClosed {
                    check: check.clone(),
                });
            }
        }
        for question in &gap_questions {
            if !listed_gaps.contains(question) {
                self.errors.push(ValidationError::GapNotListed {
                    question: (*question).clone(),
                });
            }
        }
        for question in listed_gaps {
            if !gap_questions.contains(&question) {
                self.errors.push(ValidationError::GapNotCountAsGap {
                    question: question.clone(),
                });
            }
        }
    }
}

/// The coverage states recorded for `check`.
fn states<'s>(s: &'s Session, check: &'s CheckId) -> impl Iterator<Item = &'s CoverageState> + 's {
    s.coverage
        .iter()
        .filter(move |c| c.check == *check)
        .map(|c| &c.state)
}
