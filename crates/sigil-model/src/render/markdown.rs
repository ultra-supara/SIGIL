//! A session as a Markdown report (plan §4.8, §4.10).
//!
//! Every value is shown through [`crate::UntrustedText::markdown_inline`]: input-derived text, IDs, and
//! SIGIL's own labels alike. Nothing in a session can therefore form a heading, link, table cell,
//! code span, or HTML in the report. Tables are GFM, and a cell never contains a line break.

use crate::artifact::{NsInode, ProcessObs};
use crate::evidence::Observability;
use crate::model::{BlobLookup, Model};
use crate::session::Session;

use super::md::{self, esc, joined, section, table};
use super::{
    action, active_feature, coverage_state, kind, mode, not_observable, subject, treatment,
};

/// The report: the run, the outcome, findings, open questions, policy violations, the coverage
/// that does not close, the models, listeners, and processes observed, and the runtime API when
/// it was probed. The other lists are counted. The same session gives the same bytes.
pub fn render_session(s: &Session) -> String {
    let mut out = String::from("# SIGIL session\n\n");
    run(&mut out, s);
    md::outcome(&mut out, &s.outcome, s.policy_violations.len());
    findings(&mut out, s);
    open_questions(&mut out, s);
    policy_violations(&mut out, s);
    coverage(&mut out, s);
    models(&mut out, s);
    md::listeners(&mut out, &s.listeners);
    processes(&mut out, s);
    md::probes(&mut out, &s.probes);
    others(&mut out, s);
    out
}

fn run(out: &mut String, s: &Session) {
    let r = &s.request;
    let mut rows = vec![
        vec![
            esc("Tool"),
            esc(&match &s.tool.git_rev {
                Some(rev) => format!("{} {} ({rev})", s.tool.name, s.tool.version),
                None => format!("{} {}", s.tool.name, s.tool.version),
            }),
        ],
        vec![esc("Mode"), esc(mode(r.mode))],
        vec![esc("Audit scope"), esc(&joined(&r.audit))],
        vec![esc("Required checks"), esc(&joined(&r.required_checks))],
    ];
    for root in &r.roots {
        rows.push(vec![
            esc("Root"),
            format!("{} {}", esc(root.id.as_str()), root.path.markdown_inline()),
        ]);
    }
    if let Some(model) = &r.model_filter {
        rows.push(vec![esc("Model filter"), esc(model)]);
    }
    if !r.active.is_empty() {
        let features: Vec<String> = r.active.iter().map(active_feature).collect();
        rows.push(vec![esc("Active"), esc(&features.join(", "))]);
    }
    rows.push(vec![
        esc("Observed"),
        esc(&format!(
            "{} to {}",
            s.observation.started_at.as_str(),
            s.observation.finished_at.as_str()
        )),
    ]);
    rows.push(vec![
        esc("Policy time"),
        esc(s.outcome.policy_time.as_str()),
    ]);
    table(out, &["Run", ""], rows);
}

fn findings(out: &mut String, s: &Session) {
    section(out, "Findings");
    let rows = s
        .findings
        .iter()
        .map(|f| {
            vec![
                esc(f.id.as_str()),
                esc(f.rule.as_str()),
                esc(kind(f.kind)),
                esc(action(f.decision.action)),
                esc(&subject(&f.subject)),
                esc(&f.summary),
            ]
        })
        .collect();
    table(
        out,
        &["Finding", "Rule", "Kind", "Action", "Subject", "Summary"],
        rows,
    );
}

fn open_questions(out: &mut String, s: &Session) {
    section(out, "Open questions");
    let rows = s
        .open_questions
        .iter()
        .map(|q| {
            vec![
                esc(q.id.as_str()),
                esc(q.rule.as_str()),
                esc(treatment(&q.decision.treatment)),
                esc(&subject(&q.subject)),
            ]
        })
        .collect();
    table(
        out,
        &["Open question", "Rule", "Treatment", "Subject"],
        rows,
    );
}

fn policy_violations(out: &mut String, s: &Session) {
    section(out, "Policy violations");
    let rows = s
        .policy_violations
        .iter()
        .map(|v| {
            vec![
                esc(v.policy_rule.as_str()),
                esc(action(v.decision.action)),
                esc(&subject(&v.subject)),
            ]
        })
        .collect();
    table(out, &["Policy rule", "Action", "Subject"], rows);
}

fn coverage(out: &mut String, s: &Session) {
    section(out, "Coverage");
    let open: Vec<_> = s.coverage.iter().filter(|c| !c.state.can_close()).collect();
    out.push_str(&esc(&format!(
        "Entries: {}. Not closing their check: {}.",
        s.coverage.len(),
        open.len()
    )));
    out.push_str("\n\n");
    if open.is_empty() {
        return;
    }
    let rows = open
        .iter()
        .map(|c| {
            vec![
                esc(c.check.as_str()),
                esc(&subject(&c.scope)),
                coverage_state(&c.state).markdown(),
            ]
        })
        .collect();
    table(out, &["Check", "Scope", "State"], rows);
}

fn models(out: &mut String, s: &Session) {
    section(out, "Models");
    let rows = s.models.iter().map(model_row).collect();
    table(out, &["Model", "Name", "Layers", "License"], rows);
}

fn model_row(m: &Model) -> Vec<String> {
    let found = m
        .layers
        .iter()
        .filter(|l| matches!(l.blob, BlobLookup::Found { .. }))
        .count();
    let license = match &m.license {
        Some(l) => match &l.spdx {
            Some(spdx) => esc(spdx),
            None => esc("present, not identified"),
        },
        None => esc("none read"),
    };
    vec![
        esc(m.id.as_str()),
        m.name.markdown_inline(),
        esc(&format!("{} ({found} blobs found)", m.layers.len())),
        license,
    ]
}

fn processes(out: &mut String, s: &Session) {
    section(out, "Processes");
    let rows = s.processes.iter().map(process_row).collect();
    table(
        out,
        &["Process", "Name", "Roles", "Executable", "fd table"],
        rows,
    );
}

fn process_row(p: &ProcessObs) -> Vec<String> {
    let name = md::name_cell(p.name.as_ref());
    let exe = md::exe_cell(&p.exe);
    let fd_table = match p.fd_table {
        Observability::Observed => "listed".to_string(),
        Observability::NotObservable(why) => format!("not listed ({})", not_observable(why)),
    };
    let net_ns = match &p.net_ns {
        NsInode::Inode(n) => format!("net:[{n}]"),
        NsInode::NotObservable(why) => format!("net ns {}", not_observable(*why)),
    };
    vec![
        esc(&format!(
            "{} (start {}), {net_ns}",
            p.process.pid, p.process.start_ticks
        )),
        name,
        esc(&joined(&p.roles)),
        exe,
        esc(&fd_table),
    ]
}

fn others(out: &mut String, s: &Session) {
    section(out, "Other facts");
    let counts = [
        ("artifacts", s.artifacts.len()),
        ("file instances", s.instances.len()),
        ("process values", s.values.len()),
        ("component claims", s.components.len()),
        ("release claims", s.releases.len()),
        ("feature hints", s.hints.len()),
        ("code facts", s.code.len()),
        ("relations", s.relations.len()),
        ("rule support", s.rule_support.len()),
        ("binding premises", s.bindings.len()),
        ("load facts", s.loads.len()),
        ("write access", s.access.len()),
        ("assumptions", s.assumptions.len()),
    ];
    let shown: Vec<String> = counts
        .iter()
        .map(|(what, n)| format!("{what}: {n}"))
        .collect();
    out.push_str(&esc(&shown.join("; ")));
    out.push_str("\n\n");
    out.push_str(&esc(
        "The session JSON holds every fact; this report shows the outcome and what it rests on.",
    ));
    out.push('\n');
}
