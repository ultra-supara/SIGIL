//! A session as a Markdown report (plan §4.8, §4.10).
//!
//! Every value is shown through [`crate::UntrustedText::markdown_inline`]: input-derived text, IDs, and
//! SIGIL's own labels alike. Nothing in a session can therefore form a heading, link, table cell,
//! code span, or HTML in the report. Tables are GFM, and a cell never contains a line break.

use crate::artifact::{FileInstance, InstanceContent, NotReadReason, NsInode, ProcessObs};
use crate::coverage::Coverage;
use crate::evidence::Observability;
use crate::hint::{FeatureHint, Signal};
use crate::model::{BlobLookup, Model};
use crate::reference::{MemberResult, ARTIFACTS_RELEASE, INSTALL_ROOT};
use crate::session::Session;
use crate::text::UntrustedText;
use crate::ReleaseBasis;

use super::code::{
    capability_cell, coverage_line, no_capability_imports_kept, IMPORTS_CUT_SHORT,
    IMPORTS_CUT_SHORT_NOTE, NO_CAPABILITY_IMPORTS,
};
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
    binary_inspection(&mut out, s);
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
    // Binary roots in argument order (`binary-<n>` by number); others as recorded.
    let mut roots: Vec<&crate::session::ScanRoot> = r.roots.iter().collect();
    roots.sort_by_key(|root| crate::binary_input::binary_root_index(&root.id));
    for root in roots {
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

/// What a binary inspection's report says it is not, without code analysis (spec §6.1).
pub const BINARY_CAVEAT: &str = "Container facts only. For an executable or a shared object, imports are the names it asks its loader for; for a relocatable object (.o), they are the symbols left for the linker. Neither shows that the code calls them, and no code was analyzed.";

/// [`BINARY_CAVEAT`] of an inspection with code analysis (PR-5a-2 spec §3.1, plan P-f): it names
/// the direct call sites, which the report shows before its caveats, and says that an import
/// alone does not show a call.
pub const BINARY_CAVEAT_CODE: &str = "Container facts and direct call sites. For an executable or a shared object, imports are the names it asks its loader for; for a relocatable object (.o), they are the symbols left for the linker. An import alone does not show that the code calls it; the call sites above are the direct calls found in the code.";

/// The scope of code analysis (PR-5a spec §6.1), after [`BINARY_CAVEAT_CODE`].
pub const CODE_CAVEAT: &str = "Direct call sites only. A call through a function pointer, a function linked statically into the file, and a raw system call are not found, and references from data are not followed. Only executable sections and the ranges of FDEs in .eh_frame are searched, and only code with an FDE is analyzed. In a relocatable object (.o), addresses are file offsets.";

/// The inputs of a binary inspection (PR-4b-2a spec §6.1): an overview in argument order, then
/// each content's container facts and capabilities once, in the order of its first input. With
/// code analysis (PR-5a-2), the overview has a Code column, and the caveats name the call sites.
fn binary_inspection(out: &mut String, s: &Session) {
    use super::{artifact_type, binary_inputs};
    let inputs = binary_inputs(s);
    if inputs.is_empty() {
        return;
    }
    let code = s.request.code;
    section(out, "Binaries");
    let path_of = |b: &super::BinaryInput<'_>| {
        b.instance
            .map_or_else(|| b.root.path.clone(), |i| i.path.clone())
    };
    let rows = inputs
        .iter()
        .map(|b| {
            let sha = match (b.artifact, b.instance) {
                (Some(a), _) => esc(a.id.as_str().trim_start_matches("sha256:")),
                (None, Some(i)) => match &i.content {
                    InstanceContent::NotRead { why } => esc(&format!("not read: {why:?}")),
                    InstanceContent::Read { .. } => esc("-"),
                },
                (None, None) => esc("-"),
            };
            let size = b
                .artifact
                .map(|a| a.size)
                .or(b.instance.map(|i| i.stat.size))
                .map_or_else(|| "-".to_string(), |n| n.to_string());
            let mut row = vec![
                path_of(b).markdown_inline(),
                sha,
                esc(&size),
                esc(&artifact_type(b.artifact)),
                b.coverage.map_or_else(
                    || esc("no coverage entry"),
                    |c| coverage_state(&c.state).markdown(),
                ),
            ];
            if code {
                row.push(b.code.map_or_else(
                    || esc("no coverage entry"),
                    |c| coverage_state(&c.state).markdown(),
                ));
            }
            row
        })
        .collect();
    let mut header = vec!["Path", "SHA-256", "Size", "Type", "Container facts"];
    if code {
        header.push("Code");
    }
    table(out, &header, rows);
    let mut shown: Vec<&crate::id::ArtifactId> = vec![];
    for b in &inputs {
        let Some(a) = b.artifact else { continue };
        if shown.contains(&&a.id) {
            continue;
        }
        shown.push(&a.id);
        let path = path_of(b);
        for slice in &a.slices {
            if let Some(facts) = s.binaries.iter().find(|f| f.slice == slice.id) {
                binary_facts(out, &path, a, facts);
                capabilities(out, s, &path, facts, b.code);
            }
        }
    }
    let caveats: &[&str] = if code {
        &[BINARY_CAVEAT_CODE, CODE_CAVEAT]
    } else {
        &[BINARY_CAVEAT]
    };
    for caveat in caveats {
        out.push_str(&esc(caveat));
        out.push_str("\n\n");
    }
}

/// One record's facts: a table, then its imports.
fn binary_facts(
    out: &mut String,
    path: &UntrustedText,
    a: &crate::artifact::Artifact,
    b: &crate::binary::BinaryFacts,
) {
    use crate::binary::DataValue;
    if let crate::binary::ContainerFacts::MachO(macho) = &b.container {
        let opt = |value: &Option<UntrustedText>| {
            value
                .as_ref()
                .map_or_else(|| esc("-"), UntrustedText::markdown_inline)
        };
        let list = |values: &[UntrustedText]| {
            if values.is_empty() {
                esc("-")
            } else {
                values
                    .iter()
                    .map(UntrustedText::markdown_inline)
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        };
        out.push_str(&format!(
            "{} {}{}\n\n",
            esc("Facts of"),
            path.markdown_inline(),
            esc(":")
        ));
        let mut rows = vec![
            vec![
                esc("Container"),
                esc(if macho.is_64 {
                    "Mach-O 64-bit"
                } else {
                    "Mach-O 32-bit"
                }),
            ],
            vec![esc("CPU type"), esc(&macho.cpu_type.to_string())],
            vec![esc("CPU subtype"), esc(&macho.cpu_subtype.to_string())],
            vec![esc("File type"), esc(&macho.file_type.to_string())],
            vec![esc("Flags"), esc(&format!("0x{:08x}", macho.flags))],
            vec![esc("UUID"), esc(macho.uuid.as_deref().unwrap_or("-"))],
            vec![esc("Dylib ID"), opt(&macho.id_dylib)],
            vec![esc("Loaded dylibs"), list(&macho.load_dylibs)],
            vec![esc("RPATH"), list(&macho.rpaths)],
            vec![esc("Dynamic linker"), opt(&macho.dylinker)],
        ];
        if let Some(slice) = a.slices.iter().find(|slice| slice.id == b.slice) {
            rows.extend([
                vec![esc("Architecture"), esc(slice.arch.name())],
                vec![esc("Slice offset"), esc(&slice.offset.to_string())],
                vec![esc("Slice size"), esc(&slice.size.to_string())],
                vec![esc("Slice SHA-256"), esc(slice.sha256.as_str())],
            ]);
        }
        if let Some(cpu_type) = macho.fat_cpu_type {
            rows.push(vec![esc("Fat CPU type"), esc(&cpu_type.to_string())]);
        }
        if let Some(cpu_subtype) = macho.fat_cpu_subtype {
            rows.push(vec![esc("Fat CPU subtype"), esc(&cpu_subtype.to_string())]);
        }
        if let Some(alignment) = macho.fat_alignment {
            rows.push(vec![esc("Fat alignment"), esc(&alignment.to_string())]);
        }
        table(out, &["Fact", "Value"], rows);
        return;
    }
    let crate::binary::ContainerFacts::Elf(elf) = &b.container else {
        return;
    };
    let opt = |t: &Option<UntrustedText>| {
        t.as_ref()
            .map_or_else(|| esc("-"), UntrustedText::markdown_inline)
    };
    let list = |v: &[UntrustedText]| {
        if v.is_empty() {
            esc("-")
        } else {
            v.iter()
                .map(UntrustedText::markdown_inline)
                .collect::<Vec<_>>()
                .join(", ")
        }
    };
    let relocatable = matches!(
        a.format,
        crate::artifact::Format::Elf {
            kind: crate::artifact::ElfType::Rel
        }
    );
    let label = if relocatable {
        "Undefined symbols (link time)"
    } else {
        "Imports (dynamic)"
    };
    out.push_str(&format!(
        "{} {}{}\n\n",
        esc("Facts of"),
        path.markdown_inline(),
        esc(":")
    ));
    let data = if elf.data.is_empty() {
        esc("-")
    } else {
        elf.data
            .iter()
            .map(|d| {
                let value = match &d.value {
                    DataValue::Text(t) => t.markdown_inline(),
                    DataValue::Int(n) => esc(&n.to_string()),
                    DataValue::Unknown { .. } => esc("?"),
                };
                format!("{}{}{value}", esc(&d.symbol), esc("="))
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut rows = vec![
        vec![esc("Interpreter"), opt(&elf.interp)],
        vec![esc("SONAME"), opt(&elf.soname)],
        vec![esc("NEEDED"), list(&elf.needed)],
        vec![esc("RPATH"), list(&elf.rpath)],
        vec![esc("RUNPATH"), list(&elf.runpath)],
        vec![esc("Build-id"), esc(elf.build_id.as_deref().unwrap_or("-"))],
        vec![esc("Comment"), list(&elf.comment)],
        vec![
            esc("Stripped"),
            esc(match elf.stripped {
                Some(true) => "yes",
                Some(false) => "no",
                None => "unknown",
            }),
        ],
        vec![esc("Exports"), esc(&elf.exports.to_string())],
        vec![esc(label), esc(&elf.imports.len().to_string())],
        vec![esc("Data symbols"), data],
    ];
    if let Some(go) = &b.go {
        rows.push(vec![esc("Go version"), go.version.markdown_inline()]);
        rows.push(vec![esc("Go path"), opt(&go.path)]);
        rows.push(vec![
            esc("Go main"),
            go.main.as_ref().map_or_else(
                || esc("-"),
                |m| {
                    format!(
                        "{} {}",
                        m.path.markdown_inline(),
                        m.version.markdown_inline()
                    )
                },
            ),
        ]);
        rows.push(vec![esc("Go deps"), esc(&go.deps.len().to_string())]);
        rows.push(vec![
            esc("Go settings"),
            if go.settings.is_empty() {
                esc("-")
            } else {
                go.settings
                    .iter()
                    .map(|kv| {
                        format!(
                            "{}{}{}",
                            kv.key.markdown_inline(),
                            esc("="),
                            kv.value.markdown_inline()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        ]);
    }
    table(out, &["Fact", "Value"], rows);
    if !elf.imports.is_empty() {
        out.push_str(&format!(
            "{} {}{}\n\n",
            esc(&format!("{label} of")),
            path.markdown_inline(),
            esc(&format!(" ({}):", elf.imports.len()))
        ));
        let names: Vec<String> = elf
            .imports
            .iter()
            .map(|i| {
                let mut n = i.name.markdown_inline();
                if let Some(v) = &i.version {
                    n.push_str(&esc("@"));
                    n.push_str(&v.markdown_inline());
                }
                if i.weak {
                    n.push_str(&esc(" (weak)"));
                }
                n
            })
            .collect();
        out.push_str(&names.join(", "));
        out.push_str("\n\n");
    }
}

/// The capability imports of an ELF content (PR-5a-2 spec §3.1): one row per import hint of its
/// slice, in (feature, import) order, or the line `No capability imports.` when it has none.
/// Hints come only from the imports kept within `binary_imports` (plan P-r): when the list was
/// cut short, the line counts the imports kept instead, and a table is followed by a line that
/// says so. Then, with code analysis, the line of its input's `binary.code` entry (`code`).
///
/// That entry also decides each row's call-site cell ([`capability_cell`]): its direct call
/// sites, or, without one, `none found (see binary.code)` when the input's code was searched in
/// full (complete) and `none found in the code searched; binary.code is partial (see Coverage)`
/// when partial (plans P-p, P-q); `not analyzed (see binary.code)` when it was not searched; and
/// `not analyzed (use --code)` without code analysis. A Mach-O gets nothing: 5a maps no Mach-O
/// import.
fn capabilities(
    out: &mut String,
    s: &Session,
    path: &UntrustedText,
    b: &crate::binary::BinaryFacts,
    code: Option<&Coverage>,
) {
    if !matches!(b.container, crate::binary::ContainerFacts::Elf(_)) {
        return;
    }
    let mut hints: Vec<&FeatureHint> = import_hints(s, &b.slice).collect();
    hints.sort_by(|x, y| hint_key(x).cmp(&hint_key(y)));
    let cut_short = b.imports_cut_short();
    if hints.is_empty() {
        let line = match &b.container {
            crate::binary::ContainerFacts::Elf(elf) if cut_short => {
                no_capability_imports_kept(elf.imports.len())
            }
            _ => NO_CAPABILITY_IMPORTS.to_string(),
        };
        out.push_str(&esc(&line));
        out.push_str("\n\n");
    } else {
        out.push_str(&format!(
            "{} {}{}\n\n",
            esc("Capabilities of"),
            path.markdown_inline(),
            esc(":")
        ));
        let facts = s.code.iter().find(|c| c.slice == b.slice);
        let rows = hints
            .iter()
            .map(|h| {
                vec![
                    esc(h.feature.as_str()),
                    h.value.markdown_inline(),
                    capability_cell(s.request.code, code, facts, &h.value).markdown(),
                ]
            })
            .collect();
        table(out, &["Capability", "Import", "Direct call sites"], rows);
        if cut_short {
            out.push_str(&esc(IMPORTS_CUT_SHORT));
            out.push_str("\n\n");
        }
    }
    if s.request.code {
        out.push_str(&coverage_line(code).markdown());
        out.push_str("\n\n");
    }
}

/// A slice's import hints (plan P-a): the capability rows of the binary report and the keys of
/// the install's Capabilities (imports) column.
fn import_hints<'a>(
    s: &'a Session,
    slice: &'a crate::id::SliceId,
) -> impl Iterator<Item = &'a FeatureHint> {
    s.hints
        .iter()
        .filter(move |h| h.subject == *slice && h.signal == Signal::Import)
}

/// The order of a content's capability rows: the feature key, then the import's name.
fn hint_key(h: &FeatureHint) -> (&str, &[u8]) {
    (h.feature.as_str(), h.value.as_bytes())
}

fn models(out: &mut String, s: &Session) {
    // A binary inspection has no model store (B10).
    if crate::binary_input::is_binary_inspection(&s.request) {
        return;
    }
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

/// The container facts of the install's binaries (PR-4b-1): one row per record, with its
/// capability keys (PR-5a-2). Gaps are in the Coverage section.
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
                Some(crate::artifact::Format::MachO) => "Mach-O".to_string(),
                Some(crate::artifact::Format::MachOFat) => "Mach-O fat".to_string(),
                _ => "-".to_string(),
            };
            let text =
                |t: &UntrustedText| t.as_str().map_or_else(|| t.terminal_line(), str::to_string);
            let (soname, needed, symbol_counts, notes) = match &b.container {
                crate::binary::ContainerFacts::Elf(elf) => {
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
                    let counts = if kind == "Rel" {
                        format!(
                            "{} / {} (undefined, link time)",
                            elf.exports,
                            elf.imports.len()
                        )
                    } else {
                        format!("{} / {}", elf.exports, elf.imports.len())
                    };
                    (soname, needed, counts, notes)
                }
                crate::binary::ContainerFacts::MachO(macho) => {
                    let soname = macho
                        .id_dylib
                        .as_ref()
                        .map_or_else(|| "-".to_string(), text);
                    let needed = if macho.load_dylibs.is_empty() {
                        "-".to_string()
                    } else {
                        macho
                            .load_dylibs
                            .iter()
                            .map(text)
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    let mut notes = vec![format!("{}-bit", if macho.is_64 { 64 } else { 32 })];
                    if let Some(uuid) = &macho.uuid {
                        notes.push(format!("UUID {}", &uuid[..12.min(uuid.len())]));
                    }
                    if !macho.rpaths.is_empty() {
                        notes.push(format!(
                            "RPATH {}",
                            macho.rpaths.iter().map(text).collect::<Vec<_>>().join(", ")
                        ));
                    }
                    if let Some(dylinker) = &macho.dylinker {
                        notes.push(format!("dylinker {}", text(dylinker)));
                    }
                    if let Some(slice) =
                        artifact.and_then(|a| a.slices.iter().find(|x| x.id == b.slice))
                    {
                        notes.push(format!("slice {}+{}", slice.offset, slice.size));
                    }
                    if let Some(alignment) = macho.fat_alignment {
                        notes.push(format!("fat align {alignment}"));
                    }
                    (soname, needed, "-".to_string(), notes)
                }
            };
            // The capability keys of the slice's import hints (PR-5a-2 spec §3.2).
            let mut capabilities: Vec<&str> = import_hints(s, &b.slice)
                .map(|h| h.feature.as_str())
                .collect();
            capabilities.sort_unstable();
            capabilities.dedup();
            let mut capabilities = if capabilities.is_empty() {
                "-".to_string()
            } else {
                capabilities.join(", ")
            };
            // Keys come only from the imports kept within `binary_imports` (plan P-r).
            if b.imports_cut_short() {
                capabilities.push_str(IMPORTS_CUT_SHORT_NOTE);
            }
            vec![
                path.markdown_inline(),
                esc(&format!("{kind} {arch}")),
                esc(&soname),
                esc(&needed),
                esc(&symbol_counts),
                esc(&capabilities),
                esc(&notes.join("; ")),
            ]
        })
        .collect();
    table(
        out,
        &[
            "Path",
            "Type",
            "Dylib ID / SONAME",
            "Loaded dylibs / NEEDED",
            "Exports / imports",
            "Capabilities (imports)",
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
