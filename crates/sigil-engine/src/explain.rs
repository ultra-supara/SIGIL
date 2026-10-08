//! Deterministic explanations of a session (#21; plan §4.8): one finding, the verdict, or the
//! coverage.
//!
//! The text comes from templates. The rule's summary and remediation come from the catalog, and
//! everything else is read from the session, so the same session gives the same bytes. No model
//! or LLM takes part. Every value goes through the escape API of its format: Markdown for a review
//! ticket, or a terminal line.

use std::fmt;

use sigil_model::render::{
    action, completeness, coverage_state, kind, not_observable, severity, subject, treatment,
    verdict as verdict_name, Shown,
};
use sigil_model::{
    Action, Completeness, CondEvidence, CondState, EvidenceRef, Finding, ListenerOwner,
    OqTreatment, ProcessExe, Session, UntrustedText,
};

use crate::policy::catalog;

/// The output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Lines for a terminal.
    Text,
    /// Markdown for a review ticket.
    Markdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplainError {
    /// No finding has this ID.
    UnknownFinding {
        id: String,
        /// The IDs of the findings in the session.
        known: Vec<String>,
    },
}

impl fmt::Display for ExplainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExplainError::UnknownFinding { id, known } => {
                let id = UntrustedText::new(id.as_str()).terminal_line();
                if known.is_empty() {
                    write!(f, "no finding {id}: the session has no findings")
                } else {
                    let known: Vec<String> = known
                        .iter()
                        .map(|k| UntrustedText::new(k.as_str()).terminal_line())
                        .collect();
                    write!(
                        f,
                        "no finding {id} in the session; its findings are: {}",
                        known.join(", ")
                    )
                }
            }
        }
    }
}

impl std::error::Error for ExplainError {}

/// One finding: its rule, decision, subject, the facts each condition rests on, its limits, and
/// what removes it.
pub fn finding(s: &Session, id: &str, format: Format) -> Result<String, ExplainError> {
    let Some(f) = s.findings.iter().find(|f| f.id.as_str() == id) else {
        return Err(ExplainError::UnknownFinding {
            id: id.to_string(),
            known: s.findings.iter().map(|f| f.id.to_string()).collect(),
        });
    };
    let info = catalog::rule(f.rule.as_str());
    let mut doc = Doc::new(format);
    doc.title(Shown::own(format!("Finding {}", f.id)));
    doc.field(
        "Rule",
        Shown::own(match info {
            Some(r) => format!("{} ({})", f.rule, r.summary),
            None => format!("{} (not in this SIGIL's rule catalog)", f.rule),
        }),
    );
    doc.field("Kind", Shown::own(kind(f.kind)));
    doc.field("Default severity", Shown::own(severity(f.default_severity)));
    doc.field("Decision", decision(f));
    doc.field("Subject", Shown::own(subject(&f.subject)));
    doc.field("Summary", Shown::own(f.summary.as_str()));
    doc.end();

    doc.section("Conditions");
    for c in &f.conditions {
        let (state, evidence) = match &c.state {
            CondState::Met { evidence } => ("met", Some(evidence)),
            CondState::NotMet { evidence } => ("not met", Some(evidence)),
            CondState::Unknown { evidence, .. } => ("unknown", evidence.as_ref()),
        };
        let mut shown = Shown::own(format!("{}: {state}", c.id));
        if let Some(evidence) = evidence {
            shown = shown.and(format!(", {}", cond_evidence(evidence)));
        }
        if !c.unresolved.is_empty() {
            let premises: Vec<String> = c.unresolved.iter().map(ToString::to_string).collect();
            shown = shown.and(format!("; unresolved premises: {}", premises.join(", ")));
        }
        doc.item(shown);
    }
    doc.end();

    doc.section("Evidence");
    for e in &f.evidence {
        doc.item(evidence(s, e));
    }
    doc.end();

    if !f.limits.is_empty() {
        doc.section("Limits");
        for limit in &f.limits {
            doc.item(Shown::own(limit.as_str()));
        }
        doc.end();
    }

    doc.section("Remediation");
    doc.para(Shown::own(match info {
        Some(r) => r.remediation,
        None => "No remediation is recorded for this rule in this SIGIL.",
    }));

    doc.section("Effect on the outcome");
    doc.para(Shown::own(match f.decision.action {
        Action::Fail => "Its decision is fail, so the verdict is FAIL.",
        Action::Warn => "Its decision is warn, so the verdict is at least WARN.",
        Action::Ignore => "Its decision is ignore, so it does not affect the verdict.",
    }));
    Ok(doc.finish())
}

/// The verdict and completeness: what raised the verdict, what the policy set aside, and what
/// leaves the audit incomplete.
pub fn verdict(s: &Session, format: Format) -> String {
    let o = &s.outcome;
    let mut doc = Doc::new(format);
    doc.title(Shown::own(format!(
        "Verdict {}, completeness {}",
        verdict_name(o.verdict),
        completeness(&o.completeness)
    )));
    doc.field("Policy time", Shown::own(o.policy_time.as_str()));
    doc.field(
        "Confirmed",
        Shown::own(format!(
            "{} fail, {} warn, {} policy violations",
            o.confirmed_failures,
            o.confirmed_warnings,
            s.policy_violations.len()
        )),
    );
    doc.end();

    doc.section("What raised the verdict");
    let mut raised = 0;
    for f in s
        .findings
        .iter()
        .filter(|f| f.decision.action != Action::Ignore)
    {
        raised += 1;
        doc.item(Shown::own(format!(
            "{} ({}): {}, from {}",
            f.id,
            f.rule,
            action(f.decision.action),
            f.decision.source
        )));
    }
    for v in s
        .policy_violations
        .iter()
        .filter(|v| v.decision.action != Action::Ignore)
    {
        raised += 1;
        doc.item(Shown::own(format!(
            "policy violation {} on {}: {}",
            v.policy_rule,
            subject(&v.subject),
            action(v.decision.action)
        )));
    }
    for q in s
        .open_questions
        .iter()
        .filter(|q| matches!(q.decision.treatment, OqTreatment::Warn | OqTreatment::Fail))
    {
        raised += 1;
        doc.item(Shown::own(format!(
            "open question {} ({}): {}",
            q.id,
            q.rule,
            treatment(&q.decision.treatment)
        )));
    }
    if raised == 0 {
        doc.para(Shown::own(
            "Nothing raises the verdict: no finding, policy violation, or open question is warn or fail.",
        ));
    } else {
        doc.end();
    }

    let ignored: Vec<&Finding> = s
        .findings
        .iter()
        .filter(|f| f.decision.action == Action::Ignore)
        .collect();
    if !ignored.is_empty() {
        doc.section("Set aside by the policy");
        for f in ignored {
            doc.item(decision_item(f));
        }
        doc.end();
    }

    doc.section("Completeness");
    match &o.completeness {
        Completeness::Complete => doc.para(Shown::own(
            "Every required check is closed, and no open question counts as a gap.",
        )),
        Completeness::Incomplete {
            missing_required,
            gaps,
        } => {
            for check in missing_required {
                doc.item(Shown::own(format!("required check not closed: {check}")));
                for c in s.coverage.iter().filter(|c| c.check == *check) {
                    doc.sub_item(
                        Shown::own(format!("{}: ", subject(&c.scope)))
                            .and_shown(coverage_state(&c.state)),
                    );
                }
                if !s.coverage.iter().any(|c| c.check == *check) {
                    doc.sub_item(Shown::own("no coverage entry"));
                }
            }
            for gap in gaps {
                doc.item(Shown::own(format!("open question counted as a gap: {gap}")));
            }
            doc.end();
        }
    }
    doc.finish()
}

/// Every coverage entry, by check: required checks first, in request order.
pub fn coverage(s: &Session, format: Format) -> String {
    let mut doc = Doc::new(format);
    doc.title(Shown::own("Coverage"));
    let mut checks: Vec<&sigil_model::CheckId> = s.request.required_checks.iter().collect();
    let mut others: Vec<&sigil_model::CheckId> = s
        .coverage
        .iter()
        .map(|c| &c.check)
        .filter(|c| !s.request.required_checks.contains(c))
        .collect();
    others.sort();
    others.dedup();
    checks.extend(others);
    for check in checks {
        let entries: Vec<_> = s.coverage.iter().filter(|c| &c.check == check).collect();
        let required = s.request.required_checks.contains(check);
        let closed = !entries.is_empty() && entries.iter().all(|c| c.state.can_close());
        doc.section_shown(Shown::own(format!(
            "{check} ({}, {})",
            if required { "required" } else { "not required" },
            if closed { "closed" } else { "not closed" }
        )));
        if entries.is_empty() {
            doc.item(Shown::own("no coverage entry"));
        }
        for c in entries {
            doc.item(
                Shown::own(format!("{}: ", subject(&c.scope))).and_shown(coverage_state(&c.state)),
            );
        }
        doc.end();
    }
    doc.finish()
}

fn decision(f: &Finding) -> Shown {
    let d = &f.decision;
    let mut text = format!("{}, from {}", action(d.action), d.source);
    if let Some(reason) = &d.reason {
        text.push_str(&format!("; reason: {reason}"));
    }
    if let Some(expires) = &d.expires {
        text.push_str(&format!("; expires {expires}"));
    }
    Shown::own(text)
}

fn decision_item(f: &Finding) -> Shown {
    Shown::own(format!("{} ({}): ", f.id, f.rule)).and_shown(decision(f))
}

/// What a condition rests on, by kind.
fn cond_evidence(e: &CondEvidence) -> String {
    match e {
        CondEvidence::Observed { .. } => {
            "observed (the facts are listed under Evidence)".to_string()
        }
        CondEvidence::Behavior(r) => format!("profile rule {} of {}", r.rule, r.profile),
        CondEvidence::Load { instance, .. } => format!("load facts of {instance}"),
        CondEvidence::Access { access, .. } => format!("write access {access}"),
        CondEvidence::Value { value, .. } => format!("value {value}"),
        CondEvidence::Binding {
            process_role,
            definer,
            ..
        } => format!("binding in role {process_role} to {definer}"),
        CondEvidence::Identity { slice, component } => {
            format!("identity of {component} in {slice}")
        }
    }
}

/// One evidence reference, resolved to the session's facts where they are recorded.
fn evidence(s: &Session, e: &EvidenceRef) -> Shown {
    match e {
        EvidenceRef::Listener { listener } => {
            match s.listeners.iter().find(|l| l.id == *listener) {
                Some(l) => {
                    let owner = match &l.owner {
                        ListenerOwner::Process { process } => {
                            format!(
                                "held by process {} (start {})",
                                process.pid, process.start_ticks
                            )
                        }
                        ListenerOwner::Unknown { why } => {
                            format!("holder unknown ({})", not_observable(*why))
                        }
                        ListenerOwner::Unheld => "held by no process".to_string(),
                    };
                    Shown::own(format!(
                        "listener {listener}: bound to {} port {}, socket {}, {owner}",
                        l.address, l.port, l.socket_inode
                    ))
                }
                None => Shown::own(format!("listener {listener} (not recorded)")),
            }
        }
        EvidenceRef::Process { process } => {
            match s.processes.iter().find(|p| p.process == *process) {
                Some(p) => {
                    let mut shown = Shown::own(format!(
                        "process {} (start {})",
                        process.pid, process.start_ticks
                    ));
                    if let Some(name) = &p.name {
                        shown = shown.and(", name ").and_input(name);
                    }
                    if !p.roles.is_empty() {
                        let roles: Vec<String> = p.roles.iter().map(ToString::to_string).collect();
                        shown = shown.and(format!(", role {}", roles.join(", ")));
                    }
                    if let Some(argv) = &p.argv {
                        shown = shown.and(", arguments");
                        for arg in argv {
                            shown = shown.and(" ").and_input(arg);
                        }
                    }
                    match &p.exe {
                        ProcessExe::Path { path, deleted } => {
                            shown = shown.and(", executable ").and_input(path);
                            if *deleted {
                                shown = shown.and(" (deleted)");
                            }
                        }
                        ProcessExe::Instance { instance } => {
                            shown = shown.and(format!(", executable {instance}"));
                        }
                        ProcessExe::NotObservable(why) => {
                            shown = shown.and(format!(
                                ", executable not observable ({})",
                                not_observable(*why)
                            ));
                        }
                    }
                    shown
                }
                None => Shown::own(format!(
                    "process {} (start {}, not recorded)",
                    process.pid, process.start_ticks
                )),
            }
        }
        EvidenceRef::Instance { instance } => {
            match s.instances.iter().find(|i| i.id == *instance) {
                Some(i) => Shown::own(format!("file {instance}: ")).and_input(&i.path),
                None => Shown::own(format!("file {instance} (not recorded)")),
            }
        }
        EvidenceRef::Model { model } => match s.models.iter().find(|m| m.id == *model) {
            Some(m) => Shown::own(format!("model {model}: ")).and_input(&m.name),
            None => Shown::own(format!("model {model} (not recorded)")),
        },
        EvidenceRef::Artifact { artifact } => {
            match s.artifacts.iter().find(|a| a.id == *artifact) {
                Some(a) => Shown::own(format!("content {artifact}, {} bytes", a.size)),
                None => Shown::own(format!("content {artifact} (not recorded)")),
            }
        }
        EvidenceRef::Code { slice, .. } => Shown::own(format!("code in {slice}")),
        EvidenceRef::Config(c) => {
            Shown::own(format!("configuration {} line {}, key ", c.file, c.line)).and_input(&c.key)
        }
        EvidenceRef::Value { value } => Shown::own(format!("value {value}")),
        EvidenceRef::Access { access } => Shown::own(format!("write access {access}")),
        EvidenceRef::ProfileRule(r) => {
            Shown::own(format!("profile rule {} of {}", r.rule, r.profile))
        }
    }
}

/// A document in one format.
struct Doc {
    format: Format,
    out: String,
}

impl Doc {
    fn new(format: Format) -> Doc {
        Doc {
            format,
            out: String::new(),
        }
    }

    fn show(&self, v: &Shown) -> String {
        match self.format {
            Format::Text => v.terminal(),
            Format::Markdown => v.markdown(),
        }
    }

    fn title(&mut self, v: Shown) {
        let text = self.show(&v);
        match self.format {
            Format::Text => {
                self.out.push_str(&text);
                self.out.push_str("\n\n");
            }
            Format::Markdown => {
                self.out.push_str("# ");
                self.out.push_str(&text);
                self.out.push_str("\n\n");
            }
        }
    }

    fn section(&mut self, title: &str) {
        self.section_shown(Shown::own(title));
    }

    fn section_shown(&mut self, v: Shown) {
        let text = self.show(&v);
        match self.format {
            Format::Text => {
                self.out.push_str(&text);
                self.out.push_str(":\n");
            }
            Format::Markdown => {
                self.out.push_str("## ");
                self.out.push_str(&text);
                self.out.push_str("\n\n");
            }
        }
    }

    fn field(&mut self, label: &str, v: Shown) {
        let label = self.show(&Shown::own(label));
        let text = self.show(&v);
        match self.format {
            Format::Text => self.out.push_str(&format!("  {label}: {text}\n")),
            Format::Markdown => self.out.push_str(&format!("- **{label}:** {text}\n")),
        }
    }

    fn item(&mut self, v: Shown) {
        let text = self.show(&v);
        match self.format {
            Format::Text => self.out.push_str(&format!("  - {text}\n")),
            Format::Markdown => self.out.push_str(&format!("- {text}\n")),
        }
    }

    fn sub_item(&mut self, v: Shown) {
        let text = self.show(&v);
        match self.format {
            Format::Text => self.out.push_str(&format!("      {text}\n")),
            Format::Markdown => self.out.push_str(&format!("  - {text}\n")),
        }
    }

    fn para(&mut self, v: Shown) {
        let text = self.show(&v);
        match self.format {
            Format::Text => self.out.push_str(&format!("  {text}\n\n")),
            Format::Markdown => self.out.push_str(&format!("{text}\n\n")),
        }
    }

    /// Ends a block of fields or items.
    fn end(&mut self) {
        self.out.push('\n');
    }

    fn finish(mut self) -> String {
        while self.out.ends_with("\n\n") {
            self.out.pop();
        }
        self.out
    }
}
