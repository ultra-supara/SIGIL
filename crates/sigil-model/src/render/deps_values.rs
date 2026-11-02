//! Stored dependency/value facts. No resolution, source upgrade, or implicit environment read.
use super::md::{esc, section, table};
use crate::{
    ConfigRef, DependencyContext, DependencySearch, InstanceId, ObsSource, ProcessRef,
    ProcessValueRead, Relation, SearchRule, Session, TriValue, UntrustedText, ValueKey,
    ValueOrigin,
};
use std::collections::{BTreeMap, BTreeSet};

type Placements<'a> = BTreeMap<&'a InstanceId, &'a UntrustedText>;
fn placements(s: &Session) -> Placements<'_> {
    s.instances.iter().map(|i| (&i.id, &i.path)).collect()
}
fn instance(id: &InstanceId, paths: &Placements<'_>) -> String {
    match paths.get(id) {
        Some(path) => format!("{} {}", path.markdown_inline(), esc(&format!("({id})"))),
        None => esc(id.as_str()),
    }
}
fn process(p: &ProcessRef) -> String {
    esc(&format!(
        "pid {} start {} boot {}",
        p.pid, p.start_ticks, p.boot_id
    ))
}
fn rule(via: SearchRule) -> &'static str {
    match via {
        SearchRule::Rpath => "RPATH",
        SearchRule::LdLibraryPath => "LD_LIBRARY_PATH",
        SearchRule::Runpath => "RUNPATH",
        SearchRule::DefaultDir => "common default directory",
        SearchRule::DirectPath => "direct path",
    }
}
fn context(c: &DependencyContext, paths: &Placements<'_>) -> String {
    let chain = c
        .loader_chain
        .iter()
        .map(|i| instance(i, paths))
        .collect::<Vec<_>>()
        .join(&esc(" -> "));
    let values = c
        .values
        .iter()
        .map(|v| esc(v.as_str()))
        .collect::<Vec<_>>()
        .join(&esc(", "));
    format!(
        "{}{}{}{}",
        esc("loader chain: "),
        chain,
        esc("; inputs: "),
        if values.is_empty() {
            esc("none")
        } else {
            values
        }
    )
}

fn search_witness(search: &DependencySearch, paths: &Placements<'_>) -> String {
    match search {
        DependencySearch::DirectPath => esc("direct path"),
        DependencySearch::DefaultDir { index } => esc(&format!("default directory index {index}")),
        DependencySearch::Runpath { entry, component } => {
            esc(&format!("entry {entry}; component {component}"))
        }
        DependencySearch::Rpath {
            owner,
            entry,
            component,
        } => format!(
            "{}{}{}",
            esc("owner: "),
            instance(owner, paths),
            esc(&format!("; entry {entry}; component {component}"))
        ),
        DependencySearch::LdLibraryPath { value, component } => {
            esc(&format!("value: {value}; component {component}"))
        }
    }
}

pub(super) fn dependencies(out: &mut String, s: &Session) {
    if !s
        .relations
        .iter()
        .any(|r| matches!(r, Relation::Declares { .. } | Relation::Candidate { .. }))
    {
        return;
    }
    let paths = placements(s);
    // Index first. Do not repeatedly scan all candidates for each declaration.
    let candidate_keys: BTreeSet<_> = s
        .relations
        .iter()
        .filter_map(|r| match r {
            Relation::Candidate { from, needed, .. } => Some((from, needed)),
            _ => None,
        })
        .collect();
    let mut rows = vec![];
    for relation in &s.relations {
        match relation {
            Relation::Candidate {
                from,
                needed,
                candidate,
                via,
                context: Some(c),
            } => rows.push(vec![
                instance(&c.requester, &paths),
                esc(from.as_str()),
                needed.markdown_inline(),
                instance(candidate, &paths),
                esc(rule(*via)),
                search_witness(&c.search, &paths),
                c.search_dir.markdown_inline(),
                c.process
                    .as_ref()
                    .map(process)
                    .unwrap_or_else(|| esc("no process context")),
                context(c, &paths),
            ]),
            Relation::Candidate {
                from,
                needed,
                candidate,
                via,
                context: None,
            } => rows.push(vec![
                esc("legacy candidate; context unavailable"),
                esc(from.as_str()),
                needed.markdown_inline(),
                instance(candidate, &paths),
                esc(rule(*via)),
                esc("unknown"),
                esc("unknown"),
                esc("unknown"),
                esc("unknown"),
            ]),
            Relation::Declares { from, needed, .. }
                if !candidate_keys.contains(&(from, needed)) =>
            {
                rows.push(vec![
                    esc("declared only"),
                    esc(from.as_str()),
                    needed.markdown_inline(),
                    esc("no modeled candidate recorded"),
                    esc("declaration"),
                    esc("unknown"),
                    esc("unknown"),
                    esc("unknown"),
                    esc("unknown"),
                ])
            }
            _ => (),
        }
    }
    section(out, "Dependencies");
    out.push_str(&esc("Each candidate is conditional under one modeled search rule. A declaration without a recorded candidate does not establish loader failure. A process mapping does not establish dependency selection or use."));
    out.push_str("\n\n");
    table(
        out,
        &[
            "Requester",
            "Slice",
            "Needed",
            "Candidate",
            "Rule",
            "Search witness",
            "Directory",
            "Process",
            "Inputs / loader chain",
        ],
        rows,
    );
}
fn key(key: &ValueKey) -> String {
    match key {
        ValueKey::Env(name) => format!("{}{}", esc("Env "), name.markdown_inline()),
        ValueKey::Cwd => esc("Cwd"),
        ValueKey::User => esc("User"),
        ValueKey::Group => esc("Group"),
    }
}
fn config(c: &ConfigRef, paths: &Placements<'_>) -> String {
    format!(
        "{}{}{}{}{}",
        instance(&c.file, paths),
        esc("; key "),
        c.key.markdown_inline(),
        esc("; line "),
        esc(&c.line.to_string())
    )
}
fn source_name(source: ObsSource) -> &'static str {
    match source {
        ObsSource::File => "file",
        ObsSource::Proc => "proc",
        ObsSource::Config => "config",
    }
}
fn read_name(read: Option<ProcessValueRead>) -> &'static str {
    match read {
        Some(ProcessValueRead::Cwd) => "readlink cwd",
        Some(ProcessValueRead::EffectiveUid) => "effective uid from status",
        Some(ProcessValueRead::EffectiveGid) => "effective gid from status",
        Some(ProcessValueRead::InitialEnvironment) => "initial environment from environ",
        None => "legacy observation; read kind unavailable",
    }
}
fn ids(ids: &[crate::ValueId]) -> String {
    if ids.is_empty() {
        esc("none")
    } else {
        ids.iter()
            .map(|id| esc(id.as_str()))
            .collect::<Vec<_>>()
            .join(&esc(", "))
    }
}
fn origin(origin: &ValueOrigin, paths: &Placements<'_>) -> String {
    match origin {
        // Only the minimized ConfigRef key/line is needed. Do not serialize/debug-print the
        // directive field: an older caller may have put a whole Environment line in it.
        ValueOrigin::Configured { file, .. } => {
            format!("{}{}", esc("Configured; "), config(file, paths))
        }
        ValueOrigin::PredictedLaunch { rules, from } => {
            let rules = rules
                .iter()
                .map(|r| esc(r))
                .collect::<Vec<_>>()
                .join(&esc(", "));
            format!(
                "{}{}{}{}",
                esc("PredictedLaunch; rules: "),
                rules,
                esc("; from: "),
                ids(from)
            )
        }
        ValueOrigin::ObservedProcess {
            process: p,
            source,
            read,
        } => format!(
            "{}{}{}{}{}{}",
            esc("ObservedProcess; "),
            process(p),
            esc("; source: "),
            esc(source_name(*source)),
            esc("; "),
            esc(read_name(*read))
        ),
        ValueOrigin::ChildDerived {
            parent,
            child,
            by,
            from,
        } => format!(
            "{}{}{}{}{}{}{}{}",
            esc("ChildDerived; parent: "),
            esc(parent.as_str()),
            esc("; child: "),
            esc(child.as_str()),
            esc("; rule: "),
            esc(&format!("{}/{}", by.profile, by.rule)),
            esc("; from: "),
            ids(from)
        ),
    }
}

pub(super) fn values(out: &mut String, s: &Session) {
    if s.values.is_empty() {
        return;
    }
    let paths = placements(s);
    let rows = s
        .values
        .iter()
        .map(|value| {
            let (state, text) = match &value.value {
                TriValue::Known(text) if text.as_bytes().is_empty() => {
                    ("Known empty", esc("empty string"))
                }
                TriValue::Known(text) => ("Known", text.markdown_inline()),
                TriValue::Absent => ("Absent", esc("known absent")),
                TriValue::Unknown { reason } => ("Unknown", esc(&super::unknown_reason(reason))),
            };
            let applies = value
                .applies_to
                .iter()
                .map(|c| esc(&format!("{}: {}", c.process_role, c.rule)))
                .collect::<Vec<_>>()
                .join(&esc(", "));
            vec![
                esc(value.id.as_str()),
                esc(value.process_role.as_str()),
                key(&value.key),
                esc(state),
                text,
                origin(&value.origin, &paths),
                if applies.is_empty() {
                    esc("no loader context claimed")
                } else {
                    applies
                },
            ]
        })
        .collect();
    section(out, "Process values");
    out.push_str(&esc("Configured values describe the supplied configuration. Unknown launch predictions do not establish effective values. An initial environment observation is not current getenv. Cwd and identity reads are separate observations, not an atomic snapshot."));
    out.push_str("\n\n");
    table(
        out,
        &[
            "Value ID",
            "Role",
            "Key",
            "State",
            "Value / reason",
            "Source",
            "Applies to",
        ],
        rows,
    );
}
