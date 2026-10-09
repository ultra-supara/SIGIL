//! An AI-BOM v2 as a Markdown report (PR-3b-3a design §5).
//!
//! Every value goes through [`crate::UntrustedText::markdown_inline`], SIGIL's own labels and IDs
//! included, as in the session report: nothing in an AI-BOM can form a heading, link, table cell,
//! code span, or HTML. Tables are GFM, and no cell holds a line break.

use crate::artifact::ElfType;
use crate::artifact::Format;

use super::super::md::{self, esc, joined, section, table};
use super::super::{action, kind, mode, subject};
use super::{AiBom, BomBlob, BomModel, ReleaseBasisKind};

/// The report of `bom`. The same AI-BOM gives the same bytes.
pub fn markdown(bom: &AiBom) -> String {
    let mut out = String::from("# SIGIL AI-BOM\n\n");
    header(&mut out, bom);
    md::outcome(&mut out, &bom.outcome, bom.policy_violations.len());
    md::probes(&mut out, &bom.runtime.api);
    processes(&mut out, bom);
    md::listeners(&mut out, &bom.runtime.listeners);
    releases(&mut out, bom);
    models(&mut out, bom);
    artifacts(&mut out, bom);
    findings(&mut out, bom);
    violations(&mut out, bom);
    coverage(&mut out, bom);
    out.push_str(&esc(
        "Projected from the session named by its SHA-256 above; the session holds the evidence for every line.",
    ));
    out.push('\n');
    out
}

fn header(out: &mut String, bom: &AiBom) {
    let link = &bom.session;
    let tool = &bom.tool;
    let mut rows = vec![
        vec![esc("Schema"), esc("sigil-aibom/2")],
        vec![
            esc("Tool"),
            esc(&match &tool.git_rev {
                Some(rev) => format!("{} {} ({rev})", tool.name, tool.version),
                None => format!("{} {}", tool.name, tool.version),
            }),
        ],
        vec![esc("Session SHA-256"), esc(link.sha256.as_str())],
        vec![esc("Session schema"), esc("sigil-session/1")],
        vec![esc("Mode"), esc(mode(link.mode))],
        vec![esc("Observed from"), esc(link.started_at.as_str())],
    ];
    if let Some(policy) = &link.policy {
        rows.push(vec![
            esc("Policy"),
            esc(&format!(
                "{} {} (sha256 {})",
                policy.id, policy.version, policy.sha256
            )),
        ]);
    }
    table(out, &["AI-BOM", ""], rows);
}

fn processes(out: &mut String, bom: &AiBom) {
    if bom.runtime.processes.is_empty() {
        return;
    }
    section(out, "Processes");
    let rows = bom
        .runtime
        .processes
        .iter()
        .map(|p| {
            vec![
                esc(&format!(
                    "{} (start {})",
                    p.process.pid, p.process.start_ticks
                )),
                md::name_cell(p.name.as_ref()),
                esc(&joined(&p.roles)),
                md::exe_cell(&p.exe),
            ]
        })
        .collect();
    table(out, &["Process", "Name", "Roles", "Executable"], rows);
}

fn releases(out: &mut String, bom: &AiBom) {
    if bom.runtime.releases.is_empty() {
        return;
    }
    section(out, "Releases");
    let rows = bom
        .runtime
        .releases
        .iter()
        .map(|r| {
            vec![
                esc(r.product.as_str()),
                esc(&joined(&r.candidates)),
                esc(match r.basis {
                    ReleaseBasisKind::ReferenceMatches => "reference matches (closed)",
                    ReleaseBasisKind::SelfReportedCommit => "self-reported commit (open)",
                }),
            ]
        })
        .collect();
    table(out, &["Product", "Candidates", "Basis"], rows);
}

fn models(out: &mut String, bom: &AiBom) {
    section(out, "Models");
    let rows = bom.models.iter().map(model_row).collect();
    table(
        out,
        &["Model", "Name", "Provenance", "Layers", "License"],
        rows,
    );
}

fn model_row(m: &BomModel) -> Vec<String> {
    let p = &m.provenance;
    let mut provenance = p.registry.markdown_inline();
    if let Some(namespace) = &p.namespace {
        provenance.push_str(&esc("/"));
        provenance.push_str(&namespace.markdown_inline());
    }
    provenance.push_str(&esc("/"));
    provenance.push_str(&p.model.markdown_inline());
    provenance.push_str(&esc(":"));
    provenance.push_str(&p.tag.markdown_inline());
    let count = |f: fn(&BomBlob) -> bool| m.layers.iter().filter(|l| f(&l.blob)).count();
    let layers = format!(
        "{} (found {}, absent {}, unresolved {}, not looked up {})",
        m.layers.len(),
        count(|b| matches!(b, BomBlob::Found { .. })),
        count(|b| matches!(b, BomBlob::Absent)),
        count(|b| matches!(b, BomBlob::Unresolved { .. })),
        count(|b| matches!(b, BomBlob::NotLookedUp)),
    );
    let license = match &m.license {
        Some(l) => match &l.spdx {
            Some(spdx) => esc(spdx),
            None => esc("present, not identified"),
        },
        None => esc("none"),
    };
    vec![
        esc(m.id.as_str()),
        m.name.markdown_inline(),
        provenance,
        esc(&layers),
        license,
    ]
}

fn format_name(f: Format) -> String {
    match f {
        Format::Elf { kind } => format!(
            "ELF ({})",
            match kind {
                ElfType::Exec => "executable",
                ElfType::Dyn => "shared object",
                ElfType::Rel => "relocatable",
            }
        ),
        Format::MachO => "Mach-O".to_string(),
        Format::MachOFat => "Mach-O (fat)".to_string(),
        Format::Other => "other".to_string(),
    }
}

fn artifacts(out: &mut String, bom: &AiBom) {
    section(out, "Artifacts");
    let rows = bom
        .artifacts
        .iter()
        .map(|a| {
            let paths = a
                .paths
                .iter()
                .map(|p| p.markdown_inline())
                .collect::<Vec<_>>()
                .join(&esc("; "));
            let components = a
                .slices
                .iter()
                .flat_map(|s| {
                    s.components.iter().map(move |c| {
                        let mut shown = esc(&format!(
                            "{} on {} ({:?}",
                            c.component,
                            s.arch.name(),
                            c.status
                        ));
                        for v in &c.versions {
                            shown.push_str(&esc(", "));
                            shown.push_str(&v.markdown_inline());
                        }
                        shown.push_str(&esc(")"));
                        shown
                    })
                })
                .collect::<Vec<_>>()
                .join(&esc("; "));
            vec![
                esc(a.id.as_str()),
                esc(&a.size.to_string()),
                esc(&format_name(a.format)),
                paths,
                if components.is_empty() {
                    esc("none")
                } else {
                    components
                },
            ]
        })
        .collect();
    table(
        out,
        &["Artifact", "Size", "Format", "Paths", "Components"],
        rows,
    );
}

fn findings(out: &mut String, bom: &AiBom) {
    section(out, "Findings");
    let rows = bom
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

fn violations(out: &mut String, bom: &AiBom) {
    if bom.policy_violations.is_empty() {
        return;
    }
    section(out, "Policy violations");
    let rows = bom
        .policy_violations
        .iter()
        .map(|v| {
            vec![
                esc(v.policy_rule.as_str()),
                esc(action(v.decision.action)),
                esc(&subject(&v.subject)),
                esc(v.decision.reason.as_deref().unwrap_or("")),
            ]
        })
        .collect();
    table(out, &["Policy rule", "Action", "Subject", "Reason"], rows);
}

fn coverage(out: &mut String, bom: &AiBom) {
    section(out, "Coverage");
    let rows = bom
        .coverage
        .iter()
        .map(|c| {
            let states = c
                .states
                .iter()
                .map(|(state, n)| format!("{state} {n}"))
                .collect::<Vec<_>>();
            vec![
                esc(c.check.as_str()),
                esc(if c.required {
                    "required"
                } else {
                    "not required"
                }),
                esc(if c.closed { "closed" } else { "not closed" }),
                esc(&if states.is_empty() {
                    "no coverage entry".to_string()
                } else {
                    states.join(", ")
                }),
            ]
        })
        .collect();
    table(out, &["Check", "Required", "Closed", "Entries"], rows);
}
