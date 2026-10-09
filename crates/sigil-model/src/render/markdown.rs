//! A session as a Markdown report (plan §4.8, §4.10).
//!
//! Every value is shown through [`crate::UntrustedText::markdown_inline`]: input-derived text, IDs, and
//! SIGIL's own labels alike. Nothing in a session can therefore form a heading, link, table cell,
//! code span, or HTML in the report. Tables are GFM, and a cell never contains a line break.

use crate::artifact::{FileInstance, InstanceContent, NotReadReason, NsInode, ProcessObs};
use crate::evidence::Observability;
use crate::model::{BlobLookup, Model};
use crate::reference::{MemberResult, ARTIFACTS_RELEASE, INSTALL_ROOT};
use crate::session::Session;
use crate::text::UntrustedText;
use crate::ReleaseBasis;

use super::md::{self, esc, joined, section, table};
use super::{
    action, active_feature, coverage_state, kind, mode, not_observable, subject, treatment,
};

/// The report: the run, the outcome, findings, open questions, policy violations, the coverage
/// that does not close, the models, the installation's files (with an install root), listeners,
/// and processes observed, and the runtime API when it was probed. The other lists are counted.
/// The same session gives the same bytes.
pub fn render_session(s: &Session) -> String {
    let mut out = String::from("# SIGIL session\n\n");
    run(&mut out, s);
    md::outcome(&mut out, &s.outcome, s.policy_violations.len());
    findings(&mut out, s);
    open_questions(&mut out, s);
    policy_violations(&mut out, s);
    coverage(&mut out, s);
    models(&mut out, s);
    runtime_artifacts(&mut out, s);
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

/// The install root's placements and their comparison with the reference set (PR-4a).
fn runtime_artifacts(out: &mut String, s: &Session) {
    let Some(root) = s
        .request
        .roots
        .iter()
        .find(|r| r.id.as_str() == INSTALL_ROOT)
    else {
        return;
    };
    section(out, "Runtime artifacts");
    let claim = s
        .releases
        .iter()
        .find(|c| matches!(c.basis, ReleaseBasis::ReferenceMatches { .. }));
    // A comparison always records `artifacts.release`, whatever its result.
    let compared = !s.reference_matches.is_empty()
        || s.coverage
            .iter()
            .any(|c| c.check.as_str() == ARTIFACTS_RELEASE);
    let release = match claim {
        Some(c) => format!("content matches {}", c.candidates.join(", ")),
        None if compared => "not established (see Coverage)".to_string(),
        None => "not compared with a reference set".to_string(),
    };
    out.push_str(&format!("{} {}\n\n", esc("Release:"), esc(&release)));
    let mut prefix = root.path.as_bytes().to_vec();
    prefix.push(b'/');
    let rows = s
        .instances
        .iter()
        .filter(|i| i.root == root.id)
        .map(|i| {
            let member = match i.path.as_bytes().strip_prefix(prefix.as_slice()) {
                Some(rest) => UntrustedText::from_bytes(rest.to_vec()),
                None => i.path.clone(),
            };
            vec![
                member.markdown_inline(),
                esc(&format!("{:?}", i.entry_kind())),
                placement_value(i),
                esc(&reference_cell(s, i, compared)),
            ]
        })
        .collect();
    table(
        out,
        &["Path", "Kind", "SHA-256 or target", "Reference"],
        rows,
    );
    for tag in claim.map(|c| c.candidates.as_slice()).unwrap_or_default() {
        let absent: Vec<&str> = s
            .reference_matches
            .iter()
            .filter(|r| r.release == *tag && matches!(r.result, MemberResult::Absent { .. }))
            .map(|r| r.member.as_str())
            .collect();
        if !absent.is_empty() {
            out.push_str(&esc(&format!(
                "Absent from the install ({tag}): {}",
                absent.join(", ")
            )));
            out.push_str("\n\n");
        }
    }
    binaries(out, s, &root.id, &prefix);
}

/// The container facts of the install's binaries (PR-4b-1): one row per record. Gaps are in the
/// Coverage section.
fn binaries(out: &mut String, s: &Session, root: &crate::id::RootId, prefix: &[u8]) {
    if s.binaries.is_empty() {
        return;
    }
    out.push_str(&esc("Binaries:"));
    out.push_str("\n\n");
    let rows = s
        .binaries
        .iter()
        .map(|b| {
            let artifact = s
                .artifacts
                .iter()
                .find(|a| a.slices.iter().any(|x| x.id == b.slice));
            let path = artifact
                .and_then(|a| {
                    s.instances
                        .iter()
                        .filter(|i| {
                            i.root == *root
                                && i.content
                                    == InstanceContent::Read {
                                        artifact: a.id.clone(),
                                    }
                        })
                        .filter_map(|i| i.path.as_bytes().strip_prefix(prefix))
                        .min()
                })
                .map(|rest| UntrustedText::from_bytes(rest.to_vec()))
                .unwrap_or_else(|| UntrustedText::new(b.slice.as_str()));
            let arch = artifact
                .and_then(|a| a.slices.iter().find(|x| x.id == b.slice))
                .map(|x| match x.arch {
                    crate::artifact::Arch::X86_64 => "x86_64",
                    crate::artifact::Arch::Aarch64 => "aarch64",
                    crate::artifact::Arch::Other => "other",
                })
                .unwrap_or("-");
            let kind = match artifact.map(|a| &a.format) {
                Some(crate::artifact::Format::Elf { kind }) => format!("{kind:?}"),
                _ => "-".to_string(),
            };
            let crate::binary::ContainerFacts::Elf(elf) = &b.container;
            let text =
                |t: &UntrustedText| t.as_str().map_or_else(|| t.terminal_line(), str::to_string);
            let soname = elf.soname.as_ref().map_or_else(|| "-".to_string(), text);
            let needed = if elf.needed.is_empty() {
                "-".to_string()
            } else {
                elf.needed.iter().map(text).collect::<Vec<_>>().join(", ")
            };
            let mut notes = vec![];
            if let Some(id) = &elf.build_id {
                notes.push(format!(
                    "build-id {}",
                    id.chars().take(12).collect::<String>()
                ));
            }
            for d in &elf.data {
                let value = match &d.value {
                    crate::binary::DataValue::Text(t) => text(t),
                    crate::binary::DataValue::Int(n) => n.to_string(),
                    crate::binary::DataValue::Unknown { .. } => "?".to_string(),
                };
                notes.push(format!("{}={value}", d.symbol));
            }
            if let Some(go) = &b.go {
                let path = go.path.as_ref().map(text).unwrap_or_default();
                notes.push(
                    format!("go {} {path}", text(&go.version))
                        .trim_end()
                        .to_string(),
                );
            }
            vec![
                path.markdown_inline(),
                esc(&format!("{kind} {arch}")),
                esc(&soname),
                esc(&needed),
                esc(&format!("{} / {}", elf.exports, elf.imports.len())),
                esc(&notes.join("; ")),
            ]
        })
        .collect();
    table(
        out,
        &[
            "Path",
            "Type",
            "SONAME",
            "NEEDED",
            "Exports / imports",
            "Notes",
        ],
        rows,
    );
}

/// A placement's short SHA-256, its first link target, or why it was not read.
fn placement_value(i: &FileInstance) -> String {
    match (&i.content, i.link_chain.first()) {
        (_, Some(hop)) => format!("{} {}", esc("→"), hop.target.markdown_inline()),
        (InstanceContent::Read { artifact }, None) => {
            esc(&artifact.as_str().chars().take(19).collect::<String>())
        }
        (
            InstanceContent::NotRead {
                why: NotReadReason::Directory,
            },
            None,
        ) => esc("-"),
        (InstanceContent::NotRead { why }, None) => esc(&format!("not read: {why:?}")),
    }
}

/// The releases a placement matches, differs from, or was not compared with.
fn reference_cell(s: &Session, i: &FileInstance, compared: bool) -> String {
    if !compared {
        return "-".to_string();
    }
    let (mut matches, mut differs, mut not_compared) = (vec![], vec![], vec![]);
    for r in s
        .reference_matches
        .iter()
        .filter(|r| r.instance.as_ref() == Some(&i.id))
    {
        let to = match &r.result {
            _ if r.result.matches() => &mut matches,
            MemberResult::NotCompared => &mut not_compared,
            _ => &mut differs,
        };
        to.push(r.release.as_str());
    }
    let mut parts = vec![];
    for (label, tags) in [
        ("matches", matches),
        ("differs from", differs),
        ("not compared with", not_compared),
    ] {
        if !tags.is_empty() {
            parts.push(format!("{label} {}", tags.join(", ")));
        }
    }
    if parts.is_empty() {
        "in no reference".to_string()
    } else {
        parts.join("; ")
    }
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
