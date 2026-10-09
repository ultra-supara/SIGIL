//! What the session report and the AI-BOM report share: escaping, sections, GFM tables, the
//! outcome block, and the listener and API probe sections. Every value goes through
//! [`UntrustedText::markdown_inline`].

use crate::artifact::ProcessExe;
use crate::finding::{Completeness, Outcome};
use crate::listener::{Listener, ListenerOwner};
use crate::probe::{target, ApiProbe};
use crate::text::UntrustedText;

use super::{completeness, not_observable, probe_result, verdict, PROBE_SCOPE_NOTE};

/// Escaped for a table cell or a line.
pub(crate) fn esc(text: &str) -> String {
    UntrustedText::new(text).markdown_inline()
}

pub(crate) fn section(out: &mut String, title: &str) {
    out.push_str("## ");
    out.push_str(&esc(title));
    out.push_str("\n\n");
}

/// A table of escaped cells. Nothing when `rows` is empty.
pub(crate) fn table(out: &mut String, header: &[&str], rows: Vec<Vec<String>>) {
    if rows.is_empty() {
        out.push_str("None.\n\n");
        return;
    }
    out.push('|');
    for h in header {
        out.push(' ');
        out.push_str(&esc(h));
        out.push_str(" |");
    }
    out.push_str("\n|");
    for _ in header {
        out.push_str("---|");
    }
    out.push('\n');
    for row in rows {
        out.push('|');
        for cell in row {
            out.push(' ');
            out.push_str(&cell);
            out.push_str(" |");
        }
        out.push('\n');
    }
    out.push('\n');
}

pub(crate) fn joined<T: std::fmt::Display>(items: &[T]) -> String {
    if items.is_empty() {
        return "none".to_string();
    }
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Verdict and completeness on one line, the counts, and what keeps the result incomplete.
pub(crate) fn outcome(out: &mut String, o: &Outcome, policy_violations: usize) {
    section(out, "Outcome");
    out.push_str(&format!(
        "**Verdict:** {} · **Completeness:** {}\n\n",
        esc(verdict(o.verdict)),
        esc(completeness(&o.completeness))
    ));
    out.push_str(&esc(&format!(
        "Confirmed: {} fail, {} warn, {} policy violations.",
        o.confirmed_failures, o.confirmed_warnings, policy_violations
    )));
    out.push_str("\n\n");
    if let Completeness::Incomplete {
        missing_required,
        gaps,
    } = &o.completeness
    {
        for check in missing_required {
            out.push_str(&format!(
                "- {} {}\n",
                esc("Required check not closed:"),
                esc(check.as_str())
            ));
        }
        for gap in gaps {
            out.push_str(&format!(
                "- {} {}\n",
                esc("Open question counted as a gap:"),
                esc(gap.as_str())
            ));
        }
        out.push('\n');
    }
}

/// A process's name, or that it was not read.
pub(crate) fn name_cell(name: Option<&UntrustedText>) -> String {
    match name {
        Some(n) => n.markdown_inline(),
        None => esc("not read"),
    }
}

/// A process's executable: the scanned instance, the path read, or why it was not observable.
pub(crate) fn exe_cell(exe: &ProcessExe) -> String {
    match exe {
        ProcessExe::Instance { instance } => esc(instance.as_str()),
        ProcessExe::Path { path, deleted } => {
            let mut shown = path.markdown_inline();
            if *deleted {
                shown.push_str(&esc(" (deleted)"));
            }
            shown
        }
        ProcessExe::NotObservable(why) => {
            esc(&format!("not observable ({})", not_observable(*why)))
        }
    }
}

pub(crate) fn listeners(out: &mut String, listeners: &[Listener]) {
    section(out, "Listeners");
    let rows = listeners
        .iter()
        .map(|l| {
            let owner = match &l.owner {
                ListenerOwner::Process { process } => {
                    format!("process {} (start {})", process.pid, process.start_ticks)
                }
                ListenerOwner::Unknown { why } => format!("unknown ({})", not_observable(*why)),
                ListenerOwner::Unheld => "held by no process".to_string(),
            };
            vec![
                esc(l.id.as_str()),
                esc(&l.address),
                esc(&l.port.to_string()),
                esc(&owner),
            ]
        })
        .collect();
    table(out, &["Listener", "Address", "Port", "Owner"], rows);
}

/// The API probes (active mode), with what they can and cannot say. Nothing when none ran.
pub(crate) fn probes(out: &mut String, probes: &[ApiProbe]) {
    if probes.is_empty() {
        return;
    }
    section(out, "Runtime API");
    let rows = probes
        .iter()
        .map(|p| {
            vec![
                esc(&target(&p.address, p.port)),
                esc(p.at.as_str()),
                probe_result(&p.result).markdown(),
            ]
        })
        .collect();
    table(out, &["Target", "Attempted at", "Outcome"], rows);
    out.push_str(&esc(PROBE_SCOPE_NOTE));
    out.push_str("\n\n");
}
