//! The Markdown of a [`Diff`]: a header naming both sessions, one section per kind of change,
//! then what could not be judged. Every value is escaped ([`UntrustedText::markdown_inline`]),
//! and the same `Diff` gives the same text.

use crate::diff::{
    Cause, Change, CheckState, ComponentState, Diff, DiffSide, Item, LicenseState, NotComparable,
    Placement, ReleaseState, Side, SubjectKey,
};
use crate::evidence::Ref;
use crate::finding::PolicyDecision;
use crate::id::ArtifactId;
use crate::listener::BindClass;
use crate::model::LayerRole;
use crate::render::aibom::ReleaseBasisKind;
use crate::render::md::{esc, joined, section, table};
use crate::render::{action, completeness, identity_status, mode, subject, verdict, Shown};
use crate::session::KnowledgeRef;
use crate::text::UntrustedText;

/// A section of changes: its title and its table's header.
struct Section {
    title: &'static str,
    header: &'static [&'static str],
}

/// In the order of [`Change`]'s declaration.
const SECTIONS: [Section; 7] = [
    Section {
        title: "Outcome",
        header: &["What", "Baseline", "Current"],
    },
    Section {
        title: "Coverage",
        header: &["Change", "Check", "Baseline", "Current"],
    },
    Section {
        title: "Findings",
        header: &["Change", "Rule", "Subject", "Findings"],
    },
    Section {
        title: "Policy violations",
        header: &["Change", "Policy rule", "Subject", "In the session"],
    },
    Section {
        title: "Models",
        header: &["Change", "Model", "Baseline", "Current"],
    },
    Section {
        title: "Installation",
        header: &["Change", "Where", "Baseline", "Current"],
    },
    Section {
        title: "Listeners",
        header: &["Change", "Port", "Baseline", "Current"],
    },
];

/// What the Coverage section says about the checks it does not list. SIGIL's own text, so it
/// is written without escaping.
const COVERAGE_NOTE: &str = "Only open/closed transitions are reported. A check open on both sides whose states or gaps changed is not.";

/// The Markdown of `diff`.
pub fn markdown(diff: &Diff) -> String {
    let mut d = diff.clone();
    d.canonicalize();
    let mut out = String::from("# SIGIL comparison\n\n");
    header(&mut out, &d.baseline, &d.current);
    if d.changes.is_empty() && d.not_comparable.is_empty() {
        out.push_str("No differences.\n");
        return out;
    }
    out.push_str(&esc(&format!(
        "{} {}, {} not comparable.",
        d.changes.len(),
        if d.changes.len() == 1 {
            "change"
        } else {
            "changes"
        },
        d.not_comparable.len()
    )));
    out.push_str("\n\n");
    let mut rows: [Vec<Vec<String>>; 7] = Default::default();
    for change in &d.changes {
        let (n, cells) = row(change);
        rows[n].push(cells);
    }
    for (s, rows) in SECTIONS.iter().zip(rows) {
        if rows.is_empty() {
            continue;
        }
        section(&mut out, s.title);
        table(&mut out, s.header, rows);
        if s.title == "Coverage" {
            out.push_str(COVERAGE_NOTE);
            out.push_str("\n\n");
        }
    }
    if !d.not_comparable.is_empty() {
        section(&mut out, "Not comparable");
        let rows = d.not_comparable.iter().map(not_comparable).collect();
        table(&mut out, &["Item", "Why"], rows);
    }
    out
}

fn header(out: &mut String, b: &DiffSide, c: &DiffSide) {
    let rows = vec![
        vec![
            esc("Session"),
            esc(&format!("sha256:{}", b.sha256)),
            esc(&format!("sha256:{}", c.sha256)),
        ],
        vec![esc("Tool"), esc(&tool(b)), esc(&tool(c))],
        vec![esc("Mode"), esc(mode(b.mode)), esc(mode(c.mode))],
        vec![
            esc("Started"),
            esc(b.started_at.as_str()),
            esc(c.started_at.as_str()),
        ],
        vec![esc("Policy"), esc(&policy(b)), esc(&policy(c))],
    ];
    table(out, &["", "Baseline", "Current"], rows);
}

fn tool(s: &DiffSide) -> String {
    format!("{} {}", s.tool.name, s.tool.version)
}

fn policy(s: &DiffSide) -> String {
    s.policy
        .as_ref()
        .map_or_else(|| "none recorded".to_string(), policy_text)
}

fn policy_text(k: &KnowledgeRef) -> String {
    format!("{} {} (sha256:{})", k.id, k.version, k.sha256)
}

fn policy_ref(k: Option<&KnowledgeRef>) -> String {
    k.map_or_else(|| "none".to_string(), policy_text)
}

/// The escaped cell of a decision change: each side's decisions (the action and its source, with
/// the reason and expiry when present), then in brackets what they were made on in that session
/// (`what`: its findings or subjects, an escaped cell). Each value is cut on its own, so a long
/// reason on one side leaves the other side whole.
fn decisions_change(
    what: &str,
    baseline: (&[PolicyDecision], String),
    current: (&[PolicyDecision], String),
) -> String {
    let side = |name: &str, (d, on): (&[PolicyDecision], String)| {
        format!(
            "{}{}{}{}{}",
            esc(&format!("{name}: ")),
            decisions(d),
            esc(&format!(" [{what}: ")),
            on,
            esc("]")
        )
    };
    format!(
        "{}{}{}",
        side("baseline", baseline),
        esc("; "),
        side("current", current)
    )
}

fn decisions(d: &[PolicyDecision]) -> String {
    if d.is_empty() {
        return esc("none");
    }
    d.iter()
        .map(|d| {
            let mut text = esc(&format!("{} ({})", action(d.action), d.source));
            if let Some(reason) = &d.reason {
                text.push_str(&esc(", reason: "));
                text.push_str(&esc(reason));
            }
            if let Some(expires) = &d.expires {
                text.push_str(&esc(&format!(", expires {expires}")));
            }
            text
        })
        .collect::<Vec<_>>()
        .join(&esc("; "))
}

/// A change's section (an index into [`SECTIONS`]) and its escaped cells.
fn row(change: &Change) -> (usize, Vec<String>) {
    match change {
        Change::PolicyChanged { baseline, current } => (
            0,
            vec![
                esc("policy"),
                esc(&policy_ref(baseline.as_ref())),
                esc(&policy_ref(current.as_ref())),
            ],
        ),
        Change::VerdictChanged { baseline, current } => (
            0,
            vec![
                esc("verdict"),
                esc(verdict(*baseline)),
                esc(verdict(*current)),
            ],
        ),
        Change::CompletenessChanged { baseline, current } => (
            0,
            vec![
                esc("completeness"),
                esc(completeness(baseline)),
                esc(completeness(current)),
            ],
        ),
        Change::CheckOpened {
            check,
            baseline,
            current,
        } => (
            1,
            vec![
                esc("opened"),
                esc(check.as_str()),
                esc(&states(baseline)),
                esc(&states(current)),
            ],
        ),
        Change::CheckClosed {
            check,
            baseline,
            current,
        } => (
            1,
            vec![
                esc("closed"),
                esc(check.as_str()),
                esc(&states(baseline)),
                esc(&states(current)),
            ],
        ),
        Change::FindingNew {
            rule,
            subject: key,
            at,
            current,
        } => (
            2,
            vec![
                esc("new"),
                esc(rule.as_str()),
                on(key, at),
                cell(current, ", "),
            ],
        ),
        Change::FindingResolved {
            rule,
            subject: key,
            at,
            baseline,
        } => (
            2,
            vec![
                esc("resolved"),
                esc(rule.as_str()),
                on(key, at),
                cell(baseline, ", "),
            ],
        ),
        Change::FindingDecisionChanged {
            rule,
            subject: key,
            at,
            baseline,
            current,
            baseline_findings,
            current_findings,
        } => (
            2,
            vec![
                esc("decision changed"),
                esc(rule.as_str()),
                on(key, at),
                decisions_change(
                    "findings",
                    (baseline, cell(baseline_findings, ", ")),
                    (current, cell(current_findings, ", ")),
                ),
            ],
        ),
        Change::ViolationNew {
            policy_rule,
            subject: key,
            current,
        } => (
            3,
            vec![
                esc("new"),
                esc(policy_rule.as_str()),
                subject_key(key).markdown(),
                refs(current),
            ],
        ),
        Change::ViolationResolved {
            policy_rule,
            subject: key,
            baseline,
        } => (
            3,
            vec![
                esc("resolved"),
                esc(policy_rule.as_str()),
                subject_key(key).markdown(),
                refs(baseline),
            ],
        ),
        Change::ViolationDecisionChanged {
            policy_rule,
            subject: key,
            baseline,
            current,
            baseline_subjects,
            current_subjects,
        } => (
            3,
            vec![
                esc("decision changed"),
                esc(policy_rule.as_str()),
                subject_key(key).markdown(),
                decisions_change(
                    "subjects",
                    (baseline, cell(&subjects(baseline_subjects), ", ")),
                    (current, cell(&subjects(current_subjects), ", ")),
                ),
            ],
        ),
        Change::ModelAdded { model, name } => (
            4,
            vec![
                esc("added"),
                esc(model.as_str()),
                esc("absent"),
                name.markdown_inline(),
            ],
        ),
        Change::ModelRemoved { model, name } => (
            4,
            vec![
                esc("removed"),
                esc(model.as_str()),
                name.markdown_inline(),
                esc("absent"),
            ],
        ),
        Change::LayerChanged {
            model,
            role,
            media_type,
            ordinal,
            baseline,
            current,
        } => (
            4,
            vec![
                layer(*role, media_type.as_ref(), *ordinal).markdown(),
                esc(model.as_str()),
                text_or_absent(baseline.as_ref()),
                text_or_absent(current.as_ref()),
            ],
        ),
        Change::LicenseChanged {
            model,
            baseline,
            current,
        } => (
            4,
            vec![
                esc("license"),
                esc(model.as_str()),
                esc(license(baseline)),
                esc(license(current)),
            ],
        ),
        Change::FileAdded {
            placement, content, ..
        } => (
            5,
            vec![
                esc("file added"),
                place(placement).markdown(),
                esc("absent"),
                esc(&read(content.as_ref())),
            ],
        ),
        Change::FileRemoved {
            placement, content, ..
        } => (
            5,
            vec![
                esc("file removed"),
                place(placement).markdown(),
                esc(&read(content.as_ref())),
                esc("absent"),
            ],
        ),
        Change::FileContentChanged {
            placement,
            baseline_content,
            current_content,
            ..
        } => (
            5,
            vec![
                esc("content changed"),
                place(placement).markdown(),
                esc(baseline_content.as_str()),
                esc(current_content.as_str()),
            ],
        ),
        Change::ReleaseChanged {
            product,
            baseline,
            current,
        } => (
            5,
            vec![
                esc("release"),
                esc(product.as_str()),
                release(baseline.as_ref()),
                release(current.as_ref()),
            ],
        ),
        Change::ComponentChanged {
            placement,
            arch,
            component,
            baseline,
            current,
        } => (
            5,
            vec![
                esc(&format!("component {component} ({})", arch.name())),
                place(placement).markdown(),
                component_state(baseline.as_ref()).markdown(),
                component_state(current.as_ref()).markdown(),
            ],
        ),
        Change::ListenerAdded { port, class, .. } => (
            6,
            vec![
                esc("listener added"),
                esc(&port.to_string()),
                esc("absent"),
                esc(bind(*class)),
            ],
        ),
        Change::ListenerRemoved { port, class, .. } => (
            6,
            vec![
                esc("listener removed"),
                esc(&port.to_string()),
                esc(bind(*class)),
                esc("absent"),
            ],
        ),
        Change::BindWidened {
            port,
            baseline,
            current,
            ..
        } => (
            6,
            vec![
                esc("bind widened"),
                esc(&port.to_string()),
                esc(bind(*baseline)),
                esc(bind(*current)),
            ],
        ),
        Change::BindNarrowed {
            port,
            baseline,
            current,
            ..
        } => (
            6,
            vec![
                esc("bind narrowed"),
                esc(&port.to_string()),
                esc(bind(*baseline)),
                esc(bind(*current)),
            ],
        ),
    }
}

fn states(c: &CheckState) -> String {
    let mut text = if c.states.is_empty() {
        "no entries".to_string()
    } else {
        c.states
            .iter()
            .map(|(state, n)| format!("{state} {n}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    if c.required {
        text.push_str(" (required)");
    }
    text
}

/// The escaped cell of `refs`, each one cut on its own.
fn refs(r: &[Ref]) -> String {
    r.iter()
        .map(|r| esc(&subject(r)))
        .collect::<Vec<_>>()
        .join(&esc("; "))
}

/// How reports show each of `r`, for [`cell`].
fn subjects(r: &[Ref]) -> Vec<String> {
    r.iter().map(subject).collect()
}

/// The escaped cell of a list of values, each one cut on its own. "none" when empty.
fn cell<T: std::fmt::Display>(items: &[T], sep: &str) -> String {
    if items.is_empty() {
        return esc("none");
    }
    items
        .iter()
        .map(|i| esc(&i.to_string()))
        .collect::<Vec<_>>()
        .join(&esc(sep))
}

fn on(key: &SubjectKey, at: &str) -> String {
    subject_key(key).and(at).markdown()
}

fn subject_key(key: &SubjectKey) -> Shown {
    match key {
        SubjectKey::Model(m) => Shown::own(m.as_str()),
        SubjectKey::Root(r) => Shown::own(format!("root {r}")),
        SubjectKey::Placement(p) => place(p),
        SubjectKey::Port(p) => Shown::own(format!("port {p}")),
        SubjectKey::Component {
            placement,
            arch,
            component,
        } => Shown::own(format!("{component} ({}) at ", arch.name())).and_shown(place(placement)),
        SubjectKey::Slice { placement, arch } => {
            Shown::own(format!("{} slice at ", arch.name())).and_shown(place(placement))
        }
        SubjectKey::Other(r) => Shown::own(subject(r)),
    }
}

fn place(p: &Placement) -> Shown {
    match p {
        Placement::Instance(i) => Shown::own(i.as_str()),
        Placement::Path(path) => Shown::input(path),
        Placement::Content(a) => Shown::own(format!("content {a}")),
    }
}

fn layer(role: LayerRole, media_type: Option<&UntrustedText>, ordinal: u32) -> Shown {
    let role = match role {
        LayerRole::Config => "config",
        LayerRole::Layer => "layer",
    };
    let shown = Shown::own(format!("{role} "));
    let shown = match media_type {
        Some(m) => shown.and_input(m),
        None => shown.and("without a media type"),
    };
    shown.and(format!(" #{ordinal}"))
}

fn text_or_absent(text: Option<&UntrustedText>) -> String {
    text.map_or_else(|| esc("absent"), UntrustedText::markdown_inline)
}

fn license(l: &LicenseState) -> &str {
    match l {
        LicenseState::NoLayer => "no license layer",
        LicenseState::Spdx { id } => id,
        LicenseState::Unidentified => "not identified",
    }
}

fn read(content: Option<&ArtifactId>) -> String {
    content.map_or_else(|| "not read".to_string(), ToString::to_string)
}

fn release(r: Option<&ReleaseState>) -> String {
    let Some(r) = r else {
        return esc("no claim");
    };
    let basis = match r.basis {
        ReleaseBasisKind::ReferenceMatches => "reference matches",
        ReleaseBasisKind::SelfReportedCommit => "consistent with a reported commit",
    };
    format!(
        "{}{}",
        cell(&r.candidates, ", "),
        esc(&format!(" ({basis})"))
    )
}

fn component_state(c: Option<&ComponentState>) -> Shown {
    let Some(c) = c else {
        return Shown::own("no claim");
    };
    let mut shown = Shown::own(identity_status(c.status));
    for (n, v) in c.versions.iter().enumerate() {
        shown = shown.and(if n == 0 { " " } else { ", " }).and_input(v);
    }
    shown
}

fn bind(c: BindClass) -> &'static str {
    match c {
        BindClass::Loopback => "loopback",
        BindClass::Private => "private",
        BindClass::Global => "global",
        BindClass::Wildcard => "wildcard",
    }
}

fn not_comparable(n: &NotComparable) -> Vec<String> {
    let checks = if n.checks.is_empty() {
        "-".to_string()
    } else {
        joined(&n.checks)
    };
    let why = match n.cause {
        Cause::Coverage => format!("coverage open: {checks} in {}", side(n.open_in)),
        Cause::Request => format!("not asked in {}: {checks}", side(n.open_in)),
        Cause::Policy => "policies differ".to_string(),
    };
    vec![item(&n.item).markdown(), esc(&why)]
}

fn item(i: &Item) -> Shown {
    match i {
        Item::Model { model } => Shown::own(format!("model {model}")),
        Item::License { model } => Shown::own(format!("license of {model}")),
        Item::File { placement } => Shown::own("file ").and_shown(place(placement)),
        Item::Release { product } => Shown::own(format!("release of {product}")),
        Item::Component {
            placement,
            arch,
            component,
        } => Shown::own(format!("{component} ({}) at ", arch.name())).and_shown(place(placement)),
        Item::Port { port } => Shown::own(format!("port {port}")),
        Item::Finding {
            rule,
            subject: key,
            at,
        } => Shown::own(format!("{rule} on "))
            .and_shown(subject_key(key))
            .and(at.as_str()),
        Item::Violation {
            policy_rule,
            subject: key,
        } => Shown::own(format!("{policy_rule} on ")).and_shown(subject_key(key)),
    }
}

fn side(s: Side) -> &'static str {
    match s {
        Side::Baseline => "baseline",
        Side::Current => "current",
        Side::Both => "both",
    }
}
