//! The Markdown report of a session (plan §4.8, §4.10): every golden example renders, the outcome
//! shows the verdict and completeness together, and no input-derived text can form Markdown or
//! HTML structure.

use std::fs;
use std::path::PathBuf;

use sigil_model::render::code::{
    no_capability_imports_kept, IMPORTS_CUT_SHORT, IMPORTS_CUT_SHORT_NOTE, NONE_FOUND,
    NOT_ANALYZED, NOT_SEARCHED, NO_CAPABILITY_IMPORTS,
};
use sigil_model::render::markdown::{
    render_session, BINARY_CAVEAT, BINARY_CAVEAT_CODE, CODE_CAVEAT, NOT_SCANNED, NO_IDENTITY_ENTRY,
    NO_SIGNATURES,
};
use sigil_model::*;

mod common;
use common::*;

fn examples() -> Vec<(String, Session)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas/examples/session-v1");
    let mut out = vec![];
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "json") {
            let text = fs::read_to_string(&path).unwrap();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            out.push((name, serde_json::from_str(&text).unwrap()));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

const HOSTILE: &str =
    "x|y `code` <script>alert(1)</script> [a](http://e) *b* _c_\n# heading\u{202E}";

/// A session whose model name, root path, finding summary, and coverage message are hostile.
fn hostile() -> Session {
    let mut s = complete_fail();
    s.request.roots[0].path = t(HOSTILE);
    s.findings[0].summary = HOSTILE.to_string();
    s.coverage.push(coverage(
        "model_store.integrity",
        Ref::Audit,
        CoverageState::Error {
            message: t(HOSTILE),
        },
    ));
    s.coverage.push(coverage(
        "model_store.integrity",
        Ref::Root(id("root:bytes")),
        CoverageState::Error {
            message: UntrustedText::from_bytes(vec![0xff, b'<', b'|']),
        },
    ));
    s
}

#[test]
fn every_golden_example_renders_the_same_way_twice() {
    let all = examples();
    assert_eq!(all.len(), 17);
    for (name, session) in all {
        let md = render_session(&session);
        assert_eq!(md, render_session(&session), "{name}");
        assert!(md.starts_with("# SIGIL session\n"), "{name}");
        assert!(md.contains("\n## Outcome\n"), "{name}");
    }
}

#[test]
fn the_outcome_shows_verdict_and_completeness_together() {
    let md = render_session(&incomplete_pass());
    let line = md
        .lines()
        .find(|l| l.starts_with("**Verdict:**"))
        .expect("an outcome line");
    assert!(line.contains("PASS"), "{line}");
    assert!(line.contains("INCOMPLETE"), "{line}");
    let Completeness::Incomplete {
        missing_required, ..
    } = &incomplete_pass().outcome.completeness
    else {
        panic!("the fixture is incomplete");
    };
    for check in missing_required {
        let shown = UntrustedText::new(check.as_str()).markdown_inline();
        assert!(md.contains(&shown), "{check} is not listed:\n{md}");
    }
}

#[test]
fn findings_and_coverage_that_does_not_close_are_listed() {
    let s = budget_exceeded();
    let md = render_session(&s);
    for c in s.coverage.iter().filter(|c| !c.state.can_close()) {
        let shown = UntrustedText::new(c.check.as_str()).markdown_inline();
        assert!(md.contains(&shown), "{}:\n{md}", c.check);
    }
    let s = complete_fail();
    let md = render_session(&s);
    for f in &s.findings {
        let shown = UntrustedText::new(f.id.as_str()).markdown_inline();
        assert!(md.contains(&shown), "{}:\n{md}", f.id);
    }
}

#[test]
fn hostile_text_forms_no_markdown_or_html() {
    let md = render_session(&hostile());
    // Shown escaped, character for character.
    assert!(md.contains(&t(HOSTILE).markdown_inline()), "{md}");
    for raw in ["<script>", "](http", "x|y", "`code`", "*b*", "_c_"] {
        assert!(!md.contains(raw), "{raw:?} reached the report:\n{md}");
    }
    // No line break, heading, or bidirectional override comes from the input.
    assert!(!md.contains('\u{202E}'));
    assert!(!md.lines().any(|l| l.starts_with("# heading")), "{md}");
    // Non-UTF-8 is shown as hex.
    assert!(md.contains(r"hex\:ff3c7c"), "{md}");
    // Every table row has the cells of its header.
    let mut cells = None;
    for line in md.lines() {
        if !line.starts_with('|') {
            cells = None;
            continue;
        }
        // Cell delimiters: pipes that are not escaped.
        let n = line
            .char_indices()
            .filter(|(i, c)| *c == '|' && !line[..*i].ends_with('\\'))
            .count();
        match cells {
            None => cells = Some(n),
            Some(m) => assert_eq!(n, m, "a row breaks its table: {line}"),
        }
    }
}

#[test]
fn an_empty_session_still_has_an_outcome() {
    let md = render_session(&base(&[]));
    assert!(md.contains("**Verdict:** PASS"), "{md}");
    assert!(md.contains("\n## Findings\n\nNone.\n"), "{md}");
}

/// A session that probed 127.0.0.1:11434, answered with `version`.
fn probed(version: UntrustedText) -> Session {
    let mut s = base(&[]);
    s.request.active.push(ActiveFeature::ApiProbe {
        address: "127.0.0.1".to_string(),
        port: 11434,
        allow_remote: false,
    });
    s.probes.push(ApiProbe {
        id: id("probe:api/127.0.0.1:11434"),
        address: "127.0.0.1".to_string(),
        port: 11434,
        at: ts("2026-10-07T07:00:01Z"),
        result: ProbeResult::Answered {
            status: 200,
            version: Some(version),
        },
    });
    s
}

#[test]
fn a_probe_is_shown_with_its_target_and_outcome() {
    let md = render_session(&probed(t("0.12.3")));
    assert!(md.contains("\n## Runtime API\n"), "{md}");
    let shown = |text: &str| t(text).markdown_inline();
    let row = md
        .lines()
        .find(|l| l.contains(&shown("127.0.0.1:11434")) && l.contains("answered"))
        .unwrap_or_else(|| panic!("no probe row:\n{md}"));
    assert!(row.contains(&shown("0.12.3")), "{row}");
    // The run names the active feature.
    assert!(
        md.lines().any(|l| l.starts_with("| Active |")
            && l.contains(&shown("api-probe 127.0.0.1:11434"))),
        "{md}"
    );
    assert_eq!(md, render_session(&probed(t("0.12.3"))));
    // What the probe can and cannot say is stated next to it.
    assert!(
        md.contains(&t(sigil_model::render::PROBE_SCOPE_NOTE).markdown_inline()),
        "{md}"
    );
}

#[test]
fn without_a_probe_there_is_no_runtime_api_section() {
    let md = render_session(&base(&[]));
    assert!(!md.contains("Runtime API"), "{md}");
    assert!(!md.contains("| Active |"), "{md}");
}

#[test]
fn a_hostile_version_forms_no_markdown_or_html() {
    let md = render_session(&probed(t(HOSTILE)));
    assert!(md.contains(&t(HOSTILE).markdown_inline()), "{md}");
    for raw in ["<script>", "](http", "x|y", "`code`"] {
        assert!(!md.contains(raw), "{raw:?} reached the report:\n{md}");
    }
    assert!(!md.contains('\u{202E}'));
    assert!(!md.lines().any(|l| l.starts_with("# heading")), "{md}");
}

#[test]
fn every_probe_outcome_has_a_label() {
    use sigil_model::render::probe_result;
    let cases = [
        (ProbeResult::Refused, "refused"),
        (
            ProbeResult::TimedOut {
                phase: ProbePhase::Connect,
            },
            "timed out (connect)",
        ),
        (
            ProbeResult::Answered {
                status: 404,
                version: None,
            },
            "answered (HTTP 404), no version",
        ),
        (
            ProbeResult::TooLarge { limit: 65536 },
            "response over 65536 bytes",
        ),
        (
            ProbeResult::Malformed {
                why: "transfer-encoding not supported".to_string(),
            },
            "unreadable response: transfer-encoding not supported",
        ),
        (
            ProbeResult::Failed {
                message: t("Connection reset by peer"),
            },
            "failed: Connection reset by peer",
        ),
    ];
    for (result, label) in cases {
        assert_eq!(probe_result(&result).terminal(), label);
    }
}

#[test]
fn a_refused_connection_is_shown_as_such() {
    let state = CoverageState::NotPresent {
        evidence: vec![],
        scope: "127.0.0.1:11434 from SIGIL's network namespace".to_string(),
        basis: AbsenceBasis::ConnectionRefused,
    };
    assert_eq!(
        sigil_model::render::coverage_state(&state).terminal(),
        "not present: connection refused at 127.0.0.1:11434 from SIGIL's network namespace"
    );
}

#[test]
fn a_session_with_an_install_shows_its_runtime_artifacts() {
    // Example 12: one placement matching v0.30.6, and the claim.
    let md = render_session(&conflicting_identity());
    let section = md
        .split("\n## ")
        .find(|s| s.starts_with("Runtime artifacts"))
        .unwrap_or_else(|| panic!("no section:\n{md}"));
    assert!(
        section.contains(&t("content matches v0.30.6").markdown_inline()),
        "{section}"
    );
    let cells: Vec<String> = [
        "lib/ollama/libggml-base.so.0.13.1",
        "File",
        "sha256:111111111111",
        "matches v0.30.6",
    ]
    .iter()
    .map(|c| t(c).markdown_inline())
    .collect();
    let row = format!("| {} |", cells.join(" | "));
    assert!(section.contains(&row), "{row}\n{section}");

    // An install root without a comparison says so (example 8 has none).
    let md = render_session(&profile_mismatch());
    assert!(md.contains("not compared with a reference set"), "{md}");

    // No install root, no section.
    let mut s = complete_pass();
    s.request.roots.retain(|r| r.id.as_str() != INSTALL_ROOT);
    s.instances.retain(|i| i.root.as_str() != INSTALL_ROOT);
    assert!(!render_session(&s).contains("## Runtime artifacts"));
}

#[test]
fn an_open_release_claim_is_shown_with_its_commits() {
    // Example 17 (PR-4c-2c).
    let mut s = open_release();
    let section = |s: &Session| {
        let md = render_session(s);
        md.split("\n## ")
            .find(|x| x.starts_with("Runtime artifacts"))
            .unwrap_or_else(|| panic!("no section:\n{md}"))
            .to_string()
    };
    let release = format!(
        "{} {}",
        t("Release:").markdown_inline(),
        t(
            "not established (see Coverage); consistent with v0.30.5, v0.30.6, v0.30.7 by a \
           self-reported commit (open: a custom build, a mixed install, or an unlisted release is \
           not excluded)"
        )
        .markdown_inline()
    );
    let commits = |paths: &[&str]| {
        let paths: Vec<String> = paths.iter().map(|p| t(p).markdown_inline()).collect();
        format!(
            "{} {} {} ({})",
            t("Self-reported commits:").markdown_inline(),
            t("LLAMA_COMMIT").markdown_inline(),
            t("6f3a9f3de").markdown_inline(),
            paths.join(", ")
        )
    };
    let shown = section(&s);
    assert!(shown.contains(&release), "{release}\n{shown}");
    let common = "lib/ollama/libllama-common.so.0.0.1";
    assert!(shown.contains(&commits(&[common])), "{shown}");
    // The content at a second path: both paths, in path order.
    let mut copy = s.instances[0].clone();
    copy.id = InstanceId::new("inst:lib/ollama/a-copy.so").unwrap();
    copy.path = t("/usr/local/lib/ollama/a-copy.so");
    s.instances.push(copy);
    let shown = section(&s);
    assert!(
        shown.contains(&commits(&["lib/ollama/a-copy.so", common])),
        "{shown}"
    );
    // Only the same content under the install root is a placement of a commit: other content
    // there, and the same content under another root, are not listed.
    let label = t("Self-reported commits:").markdown_inline();
    let commits_line = |s: &Session| {
        let section = section(s);
        section
            .lines()
            .find(|l| l.starts_with(&label))
            .unwrap_or_else(|| panic!("no commits line:\n{section}"))
            .to_string()
    };
    let mut other = open_release();
    let mut different = other.instances[0].clone();
    different.id = InstanceId::new("inst:lib/ollama/different.so").unwrap();
    different.path = t("/usr/local/lib/ollama/different.so");
    different.content = InstanceContent::Read {
        artifact: id(&format!("sha256:{}", hex(0x1a))),
    };
    other.instances.push(different);
    other.request.roots.push(ScanRoot {
        id: id("elsewhere"),
        path: t("/opt/elsewhere"),
    });
    let mut elsewhere = other.instances[0].clone();
    elsewhere.id = InstanceId::new("inst:lib/ollama/elsewhere.so").unwrap();
    elsewhere.root = id("elsewhere");
    elsewhere.path = t("/opt/elsewhere/lib/ollama/elsewhere.so");
    other.instances.push(elsewhere);
    assert_eq!(commits_line(&other), commits_line(&open_release()));
    assert!(
        section(&other).contains(&commits(&[common])),
        "{}",
        section(&other)
    );
    // A commit whose evidence is in a slice of content that has no placement lists no path.
    let unplaced = SliceId::from_parts(&id(&format!("sha256:{}", hex(0x19))), Arch::X86_64, 0);
    let ReleaseBasis::SelfReportedCommit { commits: reported } = &mut other.releases[0].basis
    else {
        panic!("example 17's claim is open");
    };
    let mut second = reported[0].clone();
    second.field = "ggml_commit".to_string();
    second.at = EvidenceRef::Code {
        slice: unplaced,
        loc: Loc::VAddr(0x10),
    };
    reported.push(second);
    assert_eq!(
        commits_line(&other),
        format!(
            "{}, {} {}",
            commits_line(&open_release()),
            t("ggml_commit").markdown_inline(),
            t("6f3a9f3de").markdown_inline()
        )
    );
    // A closed claim has no commits line, even beside an open claim of another product.
    let mut closed = conflicting_identity();
    let shown = section(&closed);
    assert!(!shown.contains(&label), "{shown}");
    let slice = closed.components[0].subject.clone();
    closed.releases.push(ReleaseClaim {
        product: id("llama.cpp"),
        candidates: vec!["b1".to_string()],
        basis: ReleaseBasis::SelfReportedCommit {
            commits: vec![ReportedCommit {
                field: "LLAMA_COMMIT".to_string(),
                value: t("6f3a9f3de"),
                at: EvidenceRef::Code {
                    slice,
                    loc: Loc::VAddr(0x10),
                },
            }],
        },
    });
    let shown = section(&closed);
    assert!(!shown.contains(&label), "{shown}");
    let closed_release = format!(
        "{} {}",
        t("Release:").markdown_inline(),
        t(&format!(
            "content matches {}",
            closed.releases[0].candidates.join(", ")
        ))
        .markdown_inline()
    );
    assert!(shown.contains(&closed_release), "{closed_release}\n{shown}");
}

#[test]
fn the_absent_members_of_a_candidate_are_listed() {
    let mut s = conflicting_identity();
    let mut row = s.reference_matches[0].clone();
    row.member = "bin/ollama".to_string();
    row.instance = None;
    row.result = MemberResult::Absent {
        kind: MemberKind::File,
    };
    s.reference_matches.push(row.clone());
    // Another release's absent member is not listed: it is not a candidate.
    row.release = "v0.30.7".to_string();
    row.member = "lib/ollama/other".to_string();
    s.reference_matches.push(row);
    let md = render_session(&s);
    let shown = t("Absent from the install (v0.30.6): bin/ollama").markdown_inline();
    assert!(md.contains(&shown), "{md}");
    assert!(
        !md.contains(&t("lib/ollama/other").markdown_inline()),
        "{md}"
    );
}

#[test]
fn binaries_are_tabled_under_runtime_artifacts() {
    let mut s = conflicting_identity();
    let slice = s.artifacts[0].slices[0].id.clone();
    s.binaries.push(BinaryFacts {
        slice,
        container: ContainerFacts::Elf(ElfFacts {
            interp: None,
            soname: Some(t("libggml.so.0")),
            needed: vec![t("libggml-base.so.0"), t("libc.so.6")],
            rpath: vec![],
            runpath: vec![t("$ORIGIN")],
            build_id: Some("0123456789abcdef0123".into()),
            comment: vec![],
            stripped: Some(true),
            exports: 120,
            imports: vec![],
            data: vec![DataSymbol {
                symbol: "LLAMA_COMMIT".into(),
                value: DataValue::Text(t("6f3a9f3de")),
                at: vec![],
            }],
            returns: vec![],
        }),
        go: None,
        gaps: vec![],
    });
    let md = render_session(&s);
    let section = md
        .split("\n## ")
        .find(|x| x.starts_with("Runtime artifacts"))
        .unwrap();
    for shown in [
        "Binaries",
        "libggml.so.0",
        "libggml-base.so.0, libc.so.6",
        "LLAMA_COMMIT=6f3a9f3de",
        "build-id 0123456789ab",
    ] {
        assert!(
            section.contains(&t(shown).markdown_inline()),
            "{shown}\n{section}"
        );
    }
}

fn md_esc(text: &str) -> String {
    UntrustedText::new(text).markdown_inline()
}

#[test]
fn a_binary_inspection_has_the_binaries_section_and_no_models_section() {
    let md = render_session(&binary_inspect());
    assert!(md.contains("## Binaries\n"), "{md}");
    assert!(!md.contains("## Models"), "{md}");
    assert!(md.contains(&md_esc("Imports (dynamic) of")), "{md}");
    assert!(md.contains("dlopen"), "{md}");
    assert!(md.contains(&md_esc(BINARY_UNSUPPORTED)), "{md}");
    assert!(md.contains(&md_esc("Container facts only.")), "{md}");
    // Other sessions keep their Models section.
    assert!(render_session(&store_and_runtime()).contains("## Models"));
}

#[test]
fn a_relocatable_object_shows_link_time_symbols() {
    let mut s = binary_inspect();
    s.artifacts[0].format = Format::Elf { kind: ElfType::Rel };
    let md = render_session(&s);
    assert!(
        md.contains(&md_esc("Undefined symbols (link time) of")),
        "{md}"
    );
    assert!(!md.contains(&md_esc("Imports (dynamic) of")), "{md}");
}

#[test]
fn eleven_inputs_are_shown_in_argument_order() {
    let mut s = binary_inspect();
    for n in 3..=11u32 {
        let root = binary_root(n).unwrap();
        let path = format!("/in/f{n}");
        let inst: InstanceId = id(&format!("inst:binary-{n}/f{n}"));
        let text = s.artifacts[1].id.clone();
        let mut i = instance(&inst, root.as_str(), &path, &text, 100 + u64::from(n));
        i.stat.size = 2048;
        i.discovered_by = vec![DiscoverySource::Argument];
        s.instances.push(i);
        s.request.roots.push(ScanRoot {
            id: root,
            path: t(&path),
        });
        let unsupported = CoverageState::Unsupported {
            what: BINARY_UNSUPPORTED.to_string(),
        };
        for check in [BINARY_CONTAINER, BINARY_IDENTITY] {
            s.coverage.push(coverage(
                check,
                Ref::Instance(inst.clone()),
                unsupported.clone(),
            ));
        }
    }
    s.canonicalize();
    assert_eq!(s.validate(), Ok(()));
    let md = render_session(&s);
    let (f3, f10) = (md_esc("/in/f3"), md_esc("/in/f10"));
    // The Run table, then the Binaries overview.
    assert!(md.find(&f3).unwrap() < md.find(&f10).unwrap(), "{md}");
    let binaries = &md[md.find("## Binaries").unwrap()..];
    assert!(
        binaries.find(&f3).unwrap() < binaries.find(&f10).unwrap(),
        "{binaries}"
    );
    let inputs = sigil_model::render::binary_inputs(&s);
    let order: Vec<&str> = inputs.iter().map(|b| b.root.id.as_str()).collect();
    assert_eq!(order[1], "binary-2");
    assert_eq!(order[10], "binary-11");
}

#[test]
fn a_hostile_input_path_is_escaped() {
    let mut s = binary_inspect();
    s.request.roots[0].path = t(HOSTILE);
    s.instances[0].path = t(HOSTILE);
    let md = render_session(&s);
    assert!(!md.contains("<script>"), "{md}");
    assert!(!md.contains("\n# heading"), "{md}");
}

/// Review of Part B: every value of the Binaries section that comes from the inspected file is
/// escaped. No HTML, no heading, and every `Fact | Value` row keeps exactly three bare `|`.
#[test]
fn hostile_container_facts_are_escaped() {
    let mut s = binary_inspect();
    {
        let ContainerFacts::Elf(f) = &mut s.binaries[0].container else {
            panic!()
        };
        f.soname = Some(t(HOSTILE));
        f.needed = vec![t(HOSTILE)];
        f.runpath = vec![t(HOSTILE)];
        f.comment = vec![t(HOSTILE)];
        f.imports = vec![ElfImport {
            name: t(HOSTILE),
            version: Some(t(HOSTILE)),
            weak: true,
        }];
        f.data = vec![DataSymbol {
            symbol: "LLAMA_COMMIT".to_string(),
            value: DataValue::Text(t(HOSTILE)),
            at: vec![Loc::Symbol(t("LLAMA_COMMIT"))],
        }];
    }
    s.binaries[0].go = Some(GoBuildInfo {
        at: Loc::Section {
            name: t(".go.buildinfo"),
            offset: 0,
        },
        version: t(HOSTILE),
        path: Some(t(HOSTILE)),
        main: Some(GoModule {
            path: t(HOSTILE),
            version: t(HOSTILE),
            sum: None,
            replace: None,
        }),
        deps: vec![],
        settings: vec![GoSetting {
            key: t(HOSTILE),
            value: t(HOSTILE),
        }],
    });
    let md = render_session(&s);
    assert!(!md.contains("<script>"), "{md}");
    assert!(!md.contains("\n# heading"), "{md}");
    let bare = |line: &str| {
        let b = line.as_bytes();
        (0..b.len())
            .filter(|&i| b[i] == b'|' && (i == 0 || b[i - 1] != b'\\'))
            .count()
    };
    let facts = &md[md.find("| Fact | Value |").unwrap()..];
    for line in facts.lines().take_while(|l| l.starts_with('|')) {
        assert_eq!(bare(line), 3, "{line}");
    }
}

// --- binary inspect --code (PR-5a-2) -----------------------------------------------------------

const KERNEL_PATH: &str = "/home/user/src/suspicious_kernel-gcc-O2.o";

/// Example 16 as a run without `--code`: the same input, facts, and hint, and no code facts or
/// `binary.code` entry.
fn binary_no_code() -> Session {
    let mut s = binary_code();
    s.request.code = false;
    s.request.audit.retain(|a| a.as_str() == "binary");
    let kept = |c: &CheckId| [BINARY_CONTAINER, BINARY_IDENTITY].contains(&c.as_str());
    s.request.required_checks.retain(kept);
    s.request.budgets.remove(BINARY_CODE_BYTES);
    s.code.clear();
    s.coverage.retain(|c| kept(&c.check));
    s
}

/// The Binaries section of a report.
fn binaries_section(md: &str) -> &str {
    md.split("\n## ")
        .find(|s| s.starts_with("Binaries\n"))
        .unwrap_or_else(|| panic!("no Binaries section:\n{md}"))
}

/// The table row of `section` whose first cell is `first`.
fn row_of<'m>(section: &'m str, first: &str) -> &'m str {
    let start = format!("| {} |", md_esc(first));
    section
        .lines()
        .find(|l| l.starts_with(&start))
        .unwrap_or_else(|| panic!("no row {start}:\n{section}"))
}

#[test]
fn a_code_inspection_shows_its_code_column_and_call_site() {
    let s = binary_code();
    assert_eq!(s.validate(), Ok(()));
    let md = render_session(&s);
    let section = binaries_section(&md);
    assert!(
        section.contains(
            r"| Path | SHA\-256 | Size | Type | Container facts | Signature scan | Code |"
        ),
        "{section}"
    );
    let input = row_of(section, KERNEL_PATH);
    assert!(
        input.ends_with(&format!(
            "| {} | {} | {} |",
            md_esc("complete"),
            md_esc("complete"),
            md_esc("complete")
        )),
        "{input}"
    );
    let heading = format!(
        "{} {}{}",
        md_esc("Capabilities of"),
        md_esc(KERNEL_PATH),
        md_esc(":")
    );
    assert!(section.contains(&heading), "{section}");
    assert!(
        section.contains("| Capability | Import | Direct call sites |"),
        "{section}"
    );
    assert_eq!(
        row_of(section, "posix.network"),
        format!(
            "| {} | {} | {} |",
            md_esc("posix.network"),
            md_esc("connect"),
            md_esc("1: kernel @ 0x4d: connect(rdi=0, rsi=0, rdx=0)")
        )
    );
    assert!(
        section.contains(&md_esc(
            "binary.code: complete; 78 of 268435456 code bytes read."
        )),
        "{section}"
    );
    // After the content's imports, before the caveats; the binary.code line under the table.
    let imports = section
        .find(&md_esc("Undefined symbols (link time) of"))
        .unwrap();
    let capabilities = section.find(&heading).unwrap();
    let row = section.find(row_of(section, "posix.network")).unwrap();
    let line = section.find(&md_esc("binary.code: complete;")).unwrap();
    let caveat = section.find(&md_esc(BINARY_CAVEAT_CODE)).unwrap();
    assert!(
        imports < capabilities && capabilities < row && row < line && line < caveat,
        "{section}"
    );
}

#[test]
fn the_code_column_shows_binary_code_not_the_container() {
    let mut s = binary_code();
    let partial = CoverageState::Partial {
        missing: vec![
            "code: connect referenced at 0x4e: not on an instruction decoded from 0x40".to_string(),
        ],
    };
    s.coverage
        .iter_mut()
        .find(|c| c.check.as_str() == BINARY_CODE)
        .unwrap()
        .state = partial.clone();
    let md = render_session(&s);
    let section = binaries_section(&md);
    let shown = sigil_model::render::coverage_state(&partial).markdown();
    assert!(
        row_of(section, KERNEL_PATH).ends_with(&format!("| {} | {shown} |", md_esc("complete"))),
        "{section}"
    );
    assert!(
        section.contains(&md_esc(
            "binary.code: partial (1 gap); 78 of 268435456 code bytes read. \
             Each gap is listed under Coverage."
        )),
        "{section}"
    );
    // No entry: said so, in the column and in the line.
    s.coverage.retain(|c| c.check.as_str() != BINARY_CODE);
    let md = render_session(&s);
    let section = binaries_section(&md);
    assert!(
        row_of(section, KERNEL_PATH).ends_with(&format!("| {} |", md_esc("no coverage entry"))),
        "{section}"
    );
    assert!(
        section.contains(&md_esc("binary.code: no coverage entry.")),
        "{section}"
    );
}

#[test]
fn the_caveats_follow_request_code() {
    let md = render_session(&binary_code());
    let caveat = md.find(&md_esc(BINARY_CAVEAT_CODE));
    let code = md.find(&md_esc(CODE_CAVEAT));
    assert!(
        matches!((caveat, code), (Some(a), Some(b)) if a < b),
        "{md}"
    );
    assert!(!md.contains(&md_esc(BINARY_CAVEAT)), "{md}");
    let md = render_session(&binary_no_code());
    assert!(md.contains(&md_esc(BINARY_CAVEAT)), "{md}");
    assert!(!md.contains(&md_esc(BINARY_CAVEAT_CODE)), "{md}");
    assert!(!md.contains(&md_esc(CODE_CAVEAT)), "{md}");
}

#[test]
fn without_code_a_capability_is_not_analyzed() {
    let s = binary_no_code();
    assert_eq!(s.validate(), Ok(()));
    let md = render_session(&s);
    let section = binaries_section(&md);
    assert!(
        section.contains("| Path | SHA\\-256 | Size | Type | Container facts | Signature scan |\n"),
        "{section}"
    );
    assert_eq!(
        row_of(section, "posix.network"),
        format!(
            "| {} | {} | {} |",
            md_esc("posix.network"),
            md_esc("connect"),
            md_esc(NOT_ANALYZED)
        )
    );
    assert!(!section.contains(&md_esc("binary.code: ")), "{section}");
}

#[test]
fn no_direct_call_site_is_none_found() {
    let mut s = binary_code();
    s.code.clear();
    let md = render_session(&s);
    let row = |cell: &str| {
        format!(
            "| {} | {} | {} |",
            md_esc("posix.network"),
            md_esc("connect"),
            md_esc(cell)
        )
    };
    assert_eq!(NONE_FOUND, "none found (see binary.code)");
    assert_eq!(
        row_of(binaries_section(&md), "posix.network"),
        row(NONE_FOUND)
    );
    // A partial search is a search too (plan P-p), and says it is partial (plan P-q).
    s.coverage
        .iter_mut()
        .find(|c| c.check.as_str() == BINARY_CODE)
        .unwrap()
        .state = CoverageState::Partial {
        missing: vec!["code: a gap".to_string()],
    };
    let md = render_session(&s);
    assert_eq!(
        row_of(binaries_section(&md), "posix.network"),
        row("none found in the code searched; binary.code is partial (see Coverage)")
    );
}

/// Plan P-p: an input whose code was not searched (an aarch64 object: `Unsupported`) gets
/// "not analyzed (see binary.code)", not "none found".
#[test]
fn an_input_whose_code_was_not_searched_is_not_analyzed() {
    let mut s = binary_code();
    let slice = SliceId::from_parts(&s.artifacts[0].id, Arch::Aarch64, 0);
    s.artifacts[0].slices[0].id = slice.clone();
    s.artifacts[0].slices[0].arch = Arch::Aarch64;
    s.binaries[0].slice = slice.clone();
    s.hints[0].subject = slice;
    s.code.clear();
    let entry = s
        .coverage
        .iter_mut()
        .find(|c| c.check.as_str() == BINARY_CODE)
        .unwrap();
    entry.state = CoverageState::Unsupported {
        what: CODE_UNSUPPORTED.to_string(),
    };
    entry.budget = None;
    s.outcome.completeness = Completeness::Incomplete {
        missing_required: ids(&[BINARY_CODE]),
        gaps: vec![],
    };
    s.canonicalize();
    assert_eq!(s.validate(), Ok(()));
    let md = render_session(&s);
    let section = binaries_section(&md);
    assert_eq!(
        row_of(section, "posix.network"),
        format!(
            "| {} | {} | {} |",
            md_esc("posix.network"),
            md_esc("connect"),
            md_esc(NOT_SEARCHED)
        )
    );
    assert!(
        section.contains(&md_esc(&format!(
            "binary.code: unsupported ({CODE_UNSUPPORTED})."
        ))),
        "{section}"
    );
    // No binary.code entry: not searched either.
    s.coverage.retain(|c| c.check.as_str() != BINARY_CODE);
    let md = render_session(&s);
    assert!(
        row_of(binaries_section(&md), "posix.network")
            .ends_with(&format!("| {} |", md_esc(NOT_SEARCHED))),
        "{md}"
    );
}

#[test]
fn a_content_without_capability_imports_says_so() {
    let mut s = binary_code();
    s.hints.clear();
    let md = render_session(&s);
    let section = binaries_section(&md);
    assert!(
        section.contains(&format!("\n{}\n", md_esc(NO_CAPABILITY_IMPORTS))),
        "{section}"
    );
    assert!(!section.contains(&md_esc("Capabilities of")), "{section}");
    // The binary.code line still gives the scope, under the line.
    let none = section.find(&md_esc(NO_CAPABILITY_IMPORTS));
    let line = section.find(&md_esc("binary.code: complete; "));
    assert!(
        matches!((none, line), (Some(a), Some(b)) if a < b),
        "{section}"
    );
    let mut s = binary_no_code();
    s.hints.clear();
    let md = render_session(&s);
    assert!(md.contains(&md_esc(NO_CAPABILITY_IMPORTS)), "{md}");
}

/// Example 16 whose import list was cut short at `binary_imports = kept` (plan P-r): its `kept`
/// imports map to no capability, so it has no hint.
fn cut_short_without_hints(kept: usize) -> Session {
    let mut s = binary_code();
    s.hints.clear();
    let ContainerFacts::Elf(elf) = &mut s.binaries[0].container else {
        panic!("example 16 is an ELF")
    };
    elf.imports = (0..kept)
        .map(|k| ElfImport {
            name: t(&format!("helper_{k}")),
            version: None,
            weak: false,
        })
        .collect();
    s.binaries[0].gaps.push(imports_over_gap(kept as u64));
    s
}

#[test]
fn a_cut_short_import_list_without_capability_imports_says_so() {
    for (kept, line) in [
        (
            0,
            "No capability imports among the 0 imports kept (binary_imports; see Coverage).",
        ),
        (
            1,
            "No capability imports among the 1 import kept (binary_imports; see Coverage).",
        ),
        (
            2,
            "No capability imports among the 2 imports kept (binary_imports; see Coverage).",
        ),
    ] {
        assert_eq!(no_capability_imports_kept(kept), line);
        let md = render_session(&cut_short_without_hints(kept));
        let section = binaries_section(&md);
        assert!(
            section.contains(&format!("\n{}\n", md_esc(line))),
            "{section}"
        );
        // Never "No capability imports." alone, and no table.
        assert!(
            !section.contains(&format!("\n{}\n", md_esc(NO_CAPABILITY_IMPORTS))),
            "{section}"
        );
        assert!(!section.contains(&md_esc("Capabilities of")), "{section}");
        // The binary.code line follows it.
        let at = section.find(&md_esc(line));
        let code = section.find(&md_esc("binary.code: complete; "));
        assert!(
            matches!((at, code), (Some(a), Some(b)) if a < b),
            "{section}"
        );
    }
    // Without --code too.
    let mut s = binary_no_code();
    s.hints.clear();
    s.binaries[0].gaps.push(imports_over_gap(1));
    let md = render_session(&s);
    assert!(
        md.contains(&format!("\n{}\n", md_esc(&no_capability_imports_kept(1)))),
        "{md}"
    );
}

#[test]
fn a_cut_short_import_list_with_capability_imports_says_so() {
    assert_eq!(
        IMPORTS_CUT_SHORT,
        "The import list was cut short at binary_imports; capability imports past it are not shown."
    );
    let mut s = binary_code();
    assert!(!render_session(&s).contains(&md_esc(IMPORTS_CUT_SHORT)));
    s.binaries[0].gaps.push(imports_over_gap(1));
    let md = render_session(&s);
    let section = binaries_section(&md);
    // After the table, before the binary.code line.
    let row = section.find(row_of(section, "posix.network")).unwrap();
    let cut = section.find(&format!("\n{}\n", md_esc(IMPORTS_CUT_SHORT)));
    let code = section.find(&md_esc("binary.code: complete; "));
    assert!(
        matches!((cut, code), (Some(a), Some(b)) if row < a && a < b),
        "{section}"
    );
    // Without --code too: after the table, before the caveat.
    let mut s = binary_no_code();
    s.binaries[0].gaps.push(imports_over_gap(1));
    let md = render_session(&s);
    let section = binaries_section(&md);
    let row = section.find(row_of(section, "posix.network")).unwrap();
    let cut = section.find(&format!("\n{}\n", md_esc(IMPORTS_CUT_SHORT)));
    let caveat = section.find(&md_esc(BINARY_CAVEAT));
    assert!(
        matches!((cut, caveat), (Some(a), Some(b)) if row < a && a < b),
        "{section}"
    );
}

#[test]
fn a_macho_content_gets_no_capabilities() {
    let mut s = binary_code();
    s.artifacts[0].format = Format::MachO;
    s.binaries[0].container = ContainerFacts::MachO(MachOFacts {
        is_64: true,
        cpu_type: 0x0100_0007,
        cpu_subtype: 3,
        fat_cpu_type: None,
        fat_cpu_subtype: None,
        fat_alignment: None,
        file_type: 6,
        flags: 0,
        uuid: None,
        id_dylib: None,
        load_dylibs: vec![],
        rpaths: vec![],
        dylinker: None,
        imports: vec![],
    });
    let md = render_session(&s);
    let section = binaries_section(&md);
    assert!(section.contains(&md_esc("Mach-O 64-bit")), "{section}");
    // PR-4c-3b: facts without imports (a session written before) render as before.
    assert!(!section.contains(&md_esc("Imports (dyld)")), "{section}");
    assert!(!section.contains(&md_esc("Capabilities of")), "{section}");
    assert!(
        !section.contains(&md_esc(NO_CAPABILITY_IMPORTS)),
        "{section}"
    );
    assert!(!section.contains(&md_esc("binary.code: ")), "{section}");
}

/// PR-4c-3b: a Mach-O with imports lists them, each with its library, and gets its capability rows;
/// one without (above) gets neither. An object file's are its undefined symbols, without a library.
#[test]
fn a_macho_content_with_imports_lists_them_and_gets_capability_rows() {
    let mut s = binary_no_code();
    s.artifacts[0].format = Format::MachO;
    let slice = s.binaries[0].slice.clone();
    let import = |name: &str, library: MachOLibrary, weak: bool| MachOImport {
        name: t(name),
        library,
        weak,
    };
    let facts = |file_type: u32, imports: Vec<MachOImport>| {
        ContainerFacts::MachO(MachOFacts {
            is_64: true,
            cpu_type: 0x0100_0007,
            cpu_subtype: 3,
            fat_cpu_type: None,
            fat_cpu_subtype: None,
            fat_alignment: None,
            file_type,
            flags: 0,
            uuid: None,
            id_dylib: None,
            load_dylibs: vec![t(LIBSYSTEM)],
            rpaths: vec![],
            dylinker: None,
            imports,
        })
    };
    s.binaries[0].container = facts(
        2,
        vec![
            import(
                "_connect",
                MachOLibrary::Dylib {
                    ordinal: 1,
                    name: Some(t(LIBSYSTEM)),
                },
                false,
            ),
            import("_getenv", MachOLibrary::FlatLookup, true),
            import(
                "_x",
                MachOLibrary::Dylib {
                    ordinal: 2,
                    name: None,
                },
                false,
            ),
            import("_own", MachOLibrary::SelfImage, false),
            import("_m", MachOLibrary::MainExecutable, false),
            import("_w", MachOLibrary::WeakLookup, false),
        ],
    );
    s.hints = vec![FeatureHint {
        subject: slice,
        feature: id("posix.network"),
        signal: Signal::Import,
        value: t("_connect"),
        at: Loc::Symbol(t("_connect")),
    }];
    let md = render_session(&s);
    let section = binaries_section(&md);
    assert_eq!(
        row_of(section, "Imports (dyld)"),
        fact_row("Imports (dyld)", "6")
    );
    let list = [
        format!(
            "{}{}{}",
            md_esc("_connect ("),
            md_esc(LIBSYSTEM),
            md_esc(")")
        ),
        format!("{}{}", md_esc("_getenv (flat lookup)"), md_esc(" (weak)")),
        md_esc("_x (ordinal 2)"),
        md_esc("_own (self)"),
        md_esc("_m (main executable)"),
        md_esc("_w (weak lookup)"),
    ]
    .join(", ");
    assert!(section.contains(&md_esc("Imports (dyld) of")), "{section}");
    assert!(section.contains(&format!("\n{list}\n")), "{section}");
    assert!(section.contains(&md_esc("Capabilities of")), "{section}");
    assert!(row_of(section, "posix.network").contains(&md_esc("_connect")));
    // Without a hint: the line, as for an ELF.
    s.hints.clear();
    let md = render_session(&s);
    assert!(binaries_section(&md).contains(&md_esc(NO_CAPABILITY_IMPORTS)));
    // An object file's undefined symbols.
    s.binaries[0].container = facts(1, vec![import("_dlopen", MachOLibrary::Unbound, false)]);
    let md = render_session(&s);
    let section = binaries_section(&md);
    assert_eq!(
        row_of(section, "Undefined symbols (link time)"),
        fact_row("Undefined symbols (link time)", "1")
    );
    assert!(
        section.contains(&format!("\n{}\n", md_esc("_dlopen"))),
        "{section}"
    );
    // Every import cut at `binary_imports`: the row and the cut-short line, as for an ELF.
    s.binaries[0].container = facts(2, vec![]);
    s.binaries[0].gaps.push(imports_over_gap(0));
    let md = render_session(&s);
    let section = binaries_section(&md);
    assert_eq!(
        row_of(section, "Imports (dyld)"),
        fact_row("Imports (dyld)", "0")
    );
    assert!(
        section.contains(&md_esc(&no_capability_imports_kept(0))),
        "{section}"
    );
    // A hostile import name renders escaped.
    s.binaries[0].gaps.clear();
    s.binaries[0].container = facts(
        2,
        vec![import(
            "_x|<script>",
            MachOLibrary::Dylib {
                ordinal: 1,
                name: Some(t(LIBSYSTEM)),
            },
            false,
        )],
    );
    let md = render_session(&s);
    let section = binaries_section(&md);
    assert!(!section.contains("<script>"), "{section}");
    assert!(section.contains(&md_esc("_x|<script>")), "{section}");
}

#[test]
fn capability_rows_are_import_hints_in_feature_and_import_order() {
    let mut s = binary_code();
    let slice = s.binaries[0].slice.clone();
    let hint = |feature: &str, signal: Signal, value: &str| FeatureHint {
        subject: slice.clone(),
        feature: id(feature),
        signal,
        value: t(value),
        at: Loc::Symbol(t(value)),
    };
    // An import hint of another slice is not this content's.
    let other = SliceId::from_parts(&id(&format!("sha256:{}", "cc".repeat(32))), Arch::X86_64, 0);
    let elsewhere = FeatureHint {
        subject: other,
        ..hint("posix.network", Signal::Import, "other_slice_import")
    };
    s.hints = vec![
        hint("posix.network", Signal::Import, "socket"),
        hint("posix.dynamic_loading", Signal::Import, "dlsym"),
        hint("posix.process_spawn", Signal::Export, "exported_fn"),
        elsewhere,
        hint("posix.network", Signal::Import, "connect"),
    ];
    let md = render_session(&s);
    let section = binaries_section(&md);
    let imports: Vec<&str> = section
        .lines()
        .skip_while(|l| !l.starts_with("| Capability |"))
        .skip(2)
        .take_while(|l| l.starts_with('|'))
        .map(|l| l.split(" | ").nth(1).unwrap())
        .collect();
    assert_eq!(imports, ["dlsym", "connect", "socket"], "{section}");
    // The export is a signature (PR-4c-2a), not a capability.
    let signature = row_of(section, "posix.process_spawn");
    assert!(signature.contains(&md_esc("exported_fn")), "{section}");
    assert!(!md.contains(&md_esc("other_slice_import")), "{md}");
}

#[test]
fn a_content_under_two_inputs_has_its_capabilities_once() {
    let mut s = binary_code();
    let copy: InstanceId = id("inst:binary-2/copy.o");
    let path = "/home/user/src/copy.o";
    let mut i = instance(&copy, "binary-2", path, &s.artifacts[0].id, 22);
    i.stat.size = 1248;
    i.discovered_by = vec![DiscoverySource::Argument];
    s.instances.push(i);
    s.request.roots.push(ScanRoot {
        id: binary_root(2).unwrap(),
        path: t(path),
    });
    let mut code = s
        .coverage
        .iter()
        .find(|c| c.check.as_str() == BINARY_CODE)
        .unwrap()
        .clone();
    code.scope = Ref::Instance(copy.clone());
    s.coverage.push(code);
    s.coverage.push(coverage(
        BINARY_IDENTITY,
        Ref::Instance(copy.clone()),
        CoverageState::Complete,
    ));
    s.coverage.push(coverage(
        BINARY_CONTAINER,
        Ref::Instance(copy),
        CoverageState::Complete,
    ));
    s.canonicalize();
    assert_eq!(s.validate(), Ok(()));
    let md = render_session(&s);
    let section = binaries_section(&md);
    // Two inputs in the overview, one content after it.
    assert!(row_of(section, path).ends_with(&format!(
        "| {} | {} |",
        md_esc("complete"),
        md_esc("complete")
    )));
    assert_eq!(
        section.matches(&md_esc("Capabilities of")).count(),
        1,
        "{section}"
    );
    assert_eq!(
        section.matches(&md_esc(NO_SIGNATURES)).count(),
        1,
        "{section}"
    );
    assert_eq!(
        section.matches(&md_esc("binary.code:")).count(),
        1,
        "{section}"
    );
    assert_eq!(
        section.matches(&md_esc("1: kernel @ 0x4d")).count(),
        1,
        "{section}"
    );
}

#[test]
fn hostile_capabilities_are_escaped() {
    let mut s = binary_code();
    s.hints[0].value = t(HOSTILE);
    s.code[0].functions[0].names = vec![t(HOSTILE)];
    let site = &mut s.code[0].call_sites[0];
    site.target = CallTarget::Import {
        symbol: t(HOSTILE),
        via: ImportVia::Reloc,
    };
    site.args[0] = ArgValue::ConstStr {
        reg: Reg::Rdi,
        addr: 0x2000,
        value: t(HOSTILE),
    };
    let md = render_session(&s);
    let section = binaries_section(&md);
    assert!(!section.contains("<script>"), "{section}");
    assert!(!md.lines().any(|l| l.starts_with("# heading")), "{md}");
    assert!(!section.contains('\u{202E}'));
    let bare = |line: &str| {
        let b = line.as_bytes();
        (0..b.len())
            .filter(|&i| b[i] == b'|' && (i == 0 || b[i - 1] != b'\\'))
            .count()
    };
    let table = &section[section
        .find("| Capability | Import | Direct call sites |")
        .unwrap()..];
    let rows: Vec<&str> = table.lines().take_while(|l| l.starts_with('|')).collect();
    assert_eq!(rows.len(), 3, "{table}");
    for line in rows {
        assert_eq!(bare(line), 4, "{line}");
    }
    // The call site is still counted: the import and the call target agree.
    assert!(table.contains(&md_esc("1: ")), "{table}");
}

#[test]
fn install_binaries_show_their_capability_keys() {
    let mut s = conflicting_identity();
    let slice = s.artifacts[0].slices[0].id.clone();
    s.binaries.push(BinaryFacts {
        slice: slice.clone(),
        container: ContainerFacts::Elf(ElfFacts {
            interp: None,
            soname: Some(t("libggml.so.0")),
            needed: vec![],
            rpath: vec![],
            runpath: vec![],
            build_id: None,
            comment: vec![],
            stripped: Some(true),
            exports: 120,
            imports: ["socket", "dlsym", "connect"]
                .iter()
                .map(|n| ElfImport {
                    name: t(n),
                    version: None,
                    weak: false,
                })
                .collect(),
            data: vec![],
            returns: vec![],
        }),
        go: None,
        gaps: vec![],
    });
    let hint = |feature: &str, signal: Signal, value: &str| FeatureHint {
        subject: slice.clone(),
        feature: id(feature),
        signal,
        value: t(value),
        at: Loc::Symbol(t(value)),
    };
    // An import hint of a slice that has no row: its key is not this binary's.
    let other = SliceId::from_parts(&id(&format!("sha256:{}", "cc".repeat(32))), Arch::X86_64, 0);
    let elsewhere = FeatureHint {
        subject: other,
        ..hint("posix.other_slice", Signal::Import, "other_slice_import")
    };
    // Out of key order, two of one key, a hint that is not an import, and another slice's.
    s.hints = vec![
        hint("posix.network", Signal::Import, "socket"),
        hint("posix.dynamic_loading", Signal::Import, "dlsym"),
        elsewhere,
        hint("posix.network", Signal::Import, "connect"),
        hint("posix.process_spawn", Signal::Export, "spawn_helper"),
    ];
    let cell = |s: &Session| -> String {
        let md = render_session(s);
        let section = md
            .split("\n## ")
            .find(|x| x.starts_with("Runtime artifacts"))
            .unwrap()
            .to_string();
        let table = &section[section.find(&md_esc("Binaries:")).unwrap()..];
        assert!(
            table.contains(
                r"| Exports \/ imports | Capabilities \(imports\) | Signatures | Notes |"
            ),
            "{table}"
        );
        let row = table
            .lines()
            .find(|l| l.starts_with('|') && l.contains(&md_esc("libggml.so.0")))
            .unwrap_or_else(|| panic!("{table}"));
        // Path, Type, Component (PR-4c-1), SONAME, NEEDED, counts, then the capabilities.
        row.trim_matches('|')
            .split(" | ")
            .map(str::trim)
            .nth(6)
            .unwrap()
            .to_string()
    };
    let shown = cell(&s);
    assert!(!shown.contains(&md_esc("posix.other_slice")), "{shown}");
    assert_eq!(shown, md_esc("posix.dynamic_loading, posix.network"));
    let hints = std::mem::take(&mut s.hints);
    assert_eq!(cell(&s), md_esc("-"));
    // Cut short at binary_imports (plan P-r): the keys, or `-`, say so.
    assert_eq!(IMPORTS_CUT_SHORT_NOTE, " (imports cut short)");
    s.binaries
        .iter_mut()
        .find(|b| b.slice == slice)
        .unwrap()
        .gaps
        .push(imports_over_gap(3));
    assert_eq!(cell(&s), md_esc("- (imports cut short)"));
    s.hints = hints;
    assert_eq!(
        cell(&s),
        md_esc("posix.dynamic_loading, posix.network (imports cut short)")
    );
}

// --- Component identification (PR-4c-1) -------------------------------------------------------

/// The row `| <label> | <value> |`, escaped.
fn fact_row(label: &str, value: &str) -> String {
    format!("| {} | {} |", md_esc(label), md_esc(value))
}

#[test]
fn a_content_s_facts_end_with_its_component_identity_and_versions() {
    // Example 15's claim: ggml-base, NameOnly (shown as words), the SONAME's version.
    let md = render_session(&binary_inspect());
    let section = binaries_section(&md);
    assert_eq!(
        row_of(section, "Component"),
        fact_row("Component", "ggml-base")
    );
    assert_eq!(
        row_of(section, "Identity"),
        fact_row("Identity", "name only")
    );
    assert_eq!(
        row_of(section, "Versions"),
        fact_row("Versions", "0 (SONAME)")
    );
    let at = |label: &str| section.find(&format!("| {} |", md_esc(label))).unwrap();
    assert!(at("Data symbols") < at("Component"), "{section}");
    // Without a claim, each row says `-`.
    let mut s = binary_inspect();
    s.components.clear();
    let md = render_session(&s);
    let section = binaries_section(&md);
    for label in ["Component", "Identity", "Versions"] {
        assert_eq!(row_of(section, label), fact_row(label, "-"));
    }
}

#[test]
fn each_version_is_shown_with_its_source_and_escaped() {
    let mut s = binary_inspect();
    let at = s.components[0].versions[0].at.clone();
    let claim = &mut s.components[0];
    claim.versions.insert(
        0,
        VersionAssertion {
            value: t("0.13.1"),
            source: VersionSource::SelfName {
                kind: NameKind::Filename,
            },
            at: at.clone(),
        },
    );
    claim.versions.push(VersionAssertion {
        value: t("1"),
        source: VersionSource::Embedded {
            field: "LLAMA_BUILD_NUMBER".to_string(),
        },
        at: at.clone(),
    });
    let md = render_session(&s);
    assert_eq!(
        row_of(binaries_section(&md), "Versions"),
        fact_row(
            "Versions",
            "0.13.1 (file name), 0 (SONAME), 1 (LLAMA_BUILD_NUMBER)"
        )
    );
    // The two self-name kinds that 4c-1 does not derive yet (Mach-O, string scans).
    for (kind, label) in [
        (NameKind::InstallName, "install name"),
        (NameKind::VersionString, "version string"),
    ] {
        s.components[0].versions = vec![VersionAssertion {
            value: t("2.1"),
            source: VersionSource::SelfName { kind },
            at: at.clone(),
        }];
        let md = render_session(&s);
        assert_eq!(
            row_of(binaries_section(&md), "Versions"),
            fact_row("Versions", &format!("2.1 ({label})"))
        );
    }
    s.components[0].versions = vec![VersionAssertion {
        value: t(HOSTILE),
        source: VersionSource::SelfName {
            kind: NameKind::Soname,
        },
        at,
    }];
    let md = render_session(&s);
    assert!(!md.contains("<script>"), "{md}");
    let row = row_of(binaries_section(&md), "Versions");
    let bare = row
        .char_indices()
        .filter(|&(i, c)| c == '|' && (i == 0 || row.as_bytes()[i - 1] != b'\\'))
        .count();
    assert_eq!(bare, 3, "{row}");
}

#[test]
fn a_macho_content_has_the_identity_rows_too() {
    let mut s = binary_code();
    s.artifacts[0].format = Format::MachO;
    s.binaries[0].container = ContainerFacts::MachO(MachOFacts {
        is_64: true,
        cpu_type: 0x0100_0007,
        cpu_subtype: 3,
        fat_cpu_type: None,
        fat_cpu_subtype: None,
        fat_alignment: None,
        file_type: 6,
        flags: 0,
        uuid: None,
        id_dylib: None,
        load_dylibs: vec![],
        rpaths: vec![],
        dylinker: None,
        imports: vec![],
    });
    let md = render_session(&s);
    let section = binaries_section(&md);
    assert!(section.contains(&md_esc("Mach-O 64-bit")), "{section}");
    for label in ["Component", "Identity", "Versions"] {
        assert_eq!(row_of(section, label), fact_row(label, "-"));
    }
}

#[test]
fn install_binaries_show_their_component() {
    let mut s = conflicting_identity();
    let facts = |slice: SliceId| BinaryFacts {
        slice,
        container: ContainerFacts::Elf(ElfFacts {
            interp: None,
            soname: None,
            needed: vec![],
            rpath: vec![],
            runpath: vec![],
            build_id: None,
            comment: vec![],
            stripped: Some(true),
            exports: 0,
            imports: vec![],
            data: vec![],
            returns: vec![],
        }),
        go: None,
        gaps: vec![],
    };
    let ggml = s.artifacts[0].slices[0].id.clone();
    s.binaries.push(facts(ggml));
    // A second binary, with no claim.
    let cpu = add_binary(
        &mut s,
        &hex(0x44),
        "lib/ollama/libggml-cpu-x64.so",
        Arch::X86_64,
        1003,
    );
    s.binaries.push(facts(cpu.slice));
    let md = render_session(&s);
    let section = md
        .split("\n## ")
        .find(|x| x.starts_with("Runtime artifacts"))
        .unwrap();
    let table = &section[section.find(&md_esc("Binaries:")).unwrap()..];
    assert!(
        table.contains(&format!(
            "| {} | {} | {} | {} |",
            md_esc("Path"),
            md_esc("Type"),
            md_esc("Component"),
            md_esc("Dylib ID / SONAME")
        )),
        "{table}"
    );
    let cell = |path: &str| -> String {
        let row = table
            .lines()
            .find(|l| l.starts_with(&format!("| {} |", md_esc(path))))
            .unwrap_or_else(|| panic!("{table}"));
        row.trim_matches('|')
            .split(" | ")
            .map(str::trim)
            .nth(2)
            .unwrap()
            .to_string()
    };
    assert_eq!(
        cell("lib/ollama/libggml-base.so.0.13.1"),
        md_esc("ggml-base (conflicting)")
    );
    assert_eq!(cell("lib/ollama/libggml-cpu-x64.so"), md_esc("-"));
}

/// Two claims on one slice (valid, though 4c-1 derives at most one): the labels are joined with
/// `, `, and each version is prefixed with its claim's key.
fn two_claims_on_one_slice(s: &mut Session, slice: &SliceId) {
    let mut second = s
        .components
        .iter()
        .find(|c| c.subject == *slice)
        .unwrap()
        .clone();
    second.component = id("llama.cpp/llama");
    second.status = IdentityStatus::NameOnly;
    second.versions = vec![VersionAssertion {
        value: t("1"),
        source: VersionSource::SelfName {
            kind: NameKind::Filename,
        },
        at: second.versions[0].at.clone(),
    }];
    s.components.push(second);
}

#[test]
fn several_claims_on_one_slice_are_joined_and_their_versions_keyed() {
    // The facts table of a binary inspection.
    let mut s = binary_inspect();
    let slice = s.components[0].subject.clone();
    two_claims_on_one_slice(&mut s, &slice);
    s.components[0].status = IdentityStatus::Conflicting;
    let md = render_session(&s);
    let section = binaries_section(&md);
    assert_eq!(
        row_of(section, "Component"),
        fact_row("Component", "ggml-base, llama.cpp/llama")
    );
    assert_eq!(
        row_of(section, "Identity"),
        fact_row("Identity", "conflicting, name only")
    );
    assert_eq!(
        row_of(section, "Versions"),
        fact_row(
            "Versions",
            "ggml-base: 0 (SONAME), llama.cpp/llama: 1 (file name)"
        )
    );
    // The install Binaries table.
    let mut s = conflicting_identity();
    let slice = s.artifacts[0].slices[0].id.clone();
    s.binaries.push(BinaryFacts {
        slice: slice.clone(),
        container: ContainerFacts::Elf(ElfFacts {
            interp: None,
            soname: None,
            needed: vec![],
            rpath: vec![],
            runpath: vec![],
            build_id: None,
            comment: vec![],
            stripped: Some(true),
            exports: 0,
            imports: vec![],
            data: vec![],
            returns: vec![],
        }),
        go: None,
        gaps: vec![],
    });
    two_claims_on_one_slice(&mut s, &slice);
    let md = render_session(&s);
    let section = md
        .split("\n## ")
        .find(|x| x.starts_with("Runtime artifacts"))
        .unwrap();
    let table = &section[section.find(&md_esc("Binaries:")).unwrap()..];
    let row = table
        .lines()
        .find(|l| {
            l.starts_with(&format!(
                "| {} |",
                md_esc("lib/ollama/libggml-base.so.0.13.1")
            ))
        })
        .unwrap_or_else(|| panic!("{table}"));
    assert_eq!(
        row.trim_matches('|').split(" | ").map(str::trim).nth(2),
        Some(md_esc("ggml-base (conflicting), llama.cpp/llama (name only)").as_str()),
        "{row}"
    );
}

#[test]
fn each_identity_status_is_shown_in_words() {
    // The reports show words; the session and AI-BOM JSON keep the enum names.
    for (status, words) in [
        (IdentityStatus::Conflicting, "conflicting"),
        (IdentityStatus::ReferenceMatched, "reference matched"),
        (IdentityStatus::Corroborated, "corroborated"),
        (IdentityStatus::NameOnly, "name only"),
        (IdentityStatus::Unidentified, "unidentified"),
    ] {
        assert_eq!(sigil_model::render::identity_status(status), words);
        let mut s = binary_inspect();
        s.components[0].status = status;
        let md = render_session(&s);
        assert_eq!(
            row_of(binaries_section(&md), "Identity"),
            fact_row("Identity", words)
        );
    }
}

/// The install's Signatures column (PR-4c-2a spec §6): the keys of the slice's hints that are not
/// imports, or `-`.
#[test]
fn install_binaries_show_their_signature_keys() {
    let mut s = complete_pass();
    let slice = s.artifacts[0].slices[0].id.clone();
    s.binaries.push(BinaryFacts {
        slice: slice.clone(),
        container: ContainerFacts::Elf(ElfFacts {
            interp: None,
            soname: None,
            needed: vec![],
            rpath: vec![],
            runpath: vec![],
            build_id: None,
            comment: vec![],
            stripped: Some(true),
            exports: 2,
            imports: vec![ElfImport {
                name: t("connect"),
                version: None,
                weak: false,
            }],
            data: vec![],
            returns: vec![],
        }),
        go: None,
        gaps: vec![],
    });
    let cell = |s: &Session| -> String {
        assert_eq!(s.validate(), Ok(()));
        let md = render_session(s);
        let row = md
            .lines()
            .find(|l| {
                l.starts_with('|') && l.contains(&md_esc("libggml.so.0")) && l.contains("Dyn")
            })
            .unwrap_or_else(|| panic!("{md}"))
            .to_string();
        // Path, Type, Component, SONAME, NEEDED, counts, capabilities, then the signatures.
        row.trim_matches('|')
            .split(" | ")
            .map(str::trim)
            .nth(7)
            .unwrap()
            .to_string()
    };
    assert_eq!(cell(&s), md_esc("-"));
    let rodata = Loc::Section {
        name: t(".rodata"),
        offset: 0x10,
    };
    for (feature, signal, value, at) in [
        (
            "rpc.code_present",
            Signal::Export,
            "ggml_backend_rpc_init",
            Loc::Symbol(t("ggml_backend_rpc_init")),
        ),
        (
            "rpc.code_present",
            Signal::Export,
            "ggml_backend_rpc_start",
            Loc::Symbol(t("ggml_backend_rpc_start")),
        ),
        ("a.string", Signal::String, "text", rodata),
        (
            "posix.network",
            Signal::Import,
            "connect",
            Loc::Symbol(t("connect")),
        ),
    ] {
        s.hints.push(FeatureHint {
            subject: slice.clone(),
            feature: id(feature),
            signal,
            value: t(value),
            at,
        });
    }
    assert_eq!(cell(&s), md_esc("a.string, rpc.code_present"));
}

#[test]
fn an_elf_content_lists_its_signatures_or_says_none_was_found() {
    let mut s = binary_inspect();
    assert_eq!(s.validate(), Ok(()));
    let md = render_session(&s);
    let section = binaries_section(&md);
    assert!(
        section.contains(r"| Path | SHA\-256 | Size | Type | Container facts | Signature scan |"),
        "{section}"
    );
    assert!(
        row_of(section, "/home/user/Downloads/libggml-base.so").ends_with(&format!(
            "| {} | {} |",
            md_esc("complete"),
            md_esc("complete")
        )),
        "{section}"
    );
    let unsupported = md_esc(&format!("unsupported: {BINARY_UNSUPPORTED}"));
    assert!(
        row_of(section, "/home/user/Downloads/NOTES.txt")
            .ends_with(&format!("| {unsupported} | {unsupported} |")),
        "{section}"
    );
    assert_eq!(
        section.matches(&md_esc(NO_SIGNATURES)).count(),
        1,
        "{section}"
    );
    // The column is the input's binary.identity, not its binary.container.
    let mut partial = s.clone();
    let elf = InstanceId::new(ELF_INPUT).unwrap();
    partial
        .coverage
        .iter_mut()
        .find(|c| c.check.as_str() == BINARY_IDENTITY && c.scope == Ref::Instance(elf.clone()))
        .unwrap()
        .state = CoverageState::Partial {
        missing: vec![scan_over_gap(64 << 20)],
    };
    assert_eq!(partial.validate(), Ok(()));
    let md = render_session(&partial);
    let row = row_of(
        binaries_section(&md),
        "/home/user/Downloads/libggml-base.so",
    )
    .to_string();
    assert!(
        row.ends_with(&format!(
            "| {} | {} |",
            md_esc("complete"),
            md_esc("partial: string scan: binary_scan_bytes 67108864 exceeded")
        )),
        "{row}"
    );
    // A Go function hint needs Go build info in its slice (S3).
    s.binaries[0].go = Some(GoBuildInfo {
        version: t("go1.24.1"),
        path: None,
        main: None,
        deps: vec![],
        settings: vec![],
        at: Loc::VAddr(0x4000),
    });
    let slice = s.binaries[0].slice.clone();
    for (feature, signal, value, at) in [
        (
            "ollama.llama_server_launch",
            Signal::GoFunction,
            "main.launch",
            Loc::Section {
                name: t(".gopclntab"),
                offset: 0x100,
            },
        ),
        (
            "rpc.code_present",
            Signal::Export,
            "ggml_backend_rpc_init",
            Loc::Symbol(t("ggml_backend_rpc_init")),
        ),
        (
            "a.string",
            Signal::String,
            "text",
            Loc::Section {
                name: t(".rodata.str1.1"),
                offset: 0x2a,
            },
        ),
    ] {
        s.hints.push(FeatureHint {
            subject: slice.clone(),
            feature: id(feature),
            signal,
            value: t(value),
            at,
        });
    }
    assert_eq!(s.validate(), Ok(()));
    let md = render_session(&s);
    let section = binaries_section(&md);
    assert!(!section.contains(&md_esc(NO_SIGNATURES)), "{section}");
    let heading = format!(
        "{} {}{}",
        md_esc("Signatures of"),
        md_esc("/home/user/Downloads/libggml-base.so"),
        md_esc(":")
    );
    assert!(section.contains(&heading), "{section}");
    let rows: Vec<&str> = section
        .lines()
        .skip_while(|l| !l.starts_with("| Feature | Kind | Value | Where |"))
        .skip(2)
        .take_while(|l| l.starts_with('|'))
        .collect();
    let row = |cells: [&str; 4]| {
        format!(
            "| {} |",
            cells
                .iter()
                .map(|c| md_esc(c))
                .collect::<Vec<_>>()
                .join(" | ")
        )
    };
    assert_eq!(
        rows,
        [
            row(["a.string", "string", "text", ".rodata.str1.1 + 0x2a"]),
            row([
                "ollama.llama_server_launch",
                "Go function",
                "main.launch",
                ".gopclntab + 0x100"
            ]),
            row([
                "rpc.code_present",
                "export",
                "ggml_backend_rpc_init",
                "symbol ggml_backend_rpc_init"
            ]),
        ],
        "{section}"
    );
    // The capabilities table keeps the import hints alone.
    assert!(section.contains(&md_esc("Capabilities of")), "{section}");
}

/// A binary inspection written before PR-4c-2a has no `binary.identity` entry: its Signature
/// scan column says so, and the report still renders every input.
#[test]
fn a_session_before_signature_scans_has_no_coverage_entry_in_its_column() {
    let s = without_identity(binary_inspect());
    assert_eq!(s.validate(), Ok(()));
    let md = render_session(&s);
    let section = binaries_section(&md);
    assert!(
        section.contains(r"| Path | SHA\-256 | Size | Type | Container facts | Signature scan |"),
        "{section}"
    );
    assert!(
        row_of(section, "/home/user/Downloads/libggml-base.so").ends_with(&format!(
            "| {} | {} |",
            md_esc("complete"),
            md_esc("no coverage entry")
        )),
        "{section}"
    );
    let unsupported = md_esc(&format!("unsupported: {BINARY_UNSUPPORTED}"));
    assert!(
        row_of(section, "/home/user/Downloads/NOTES.txt").ends_with(&format!(
            "| {unsupported} | {} |",
            md_esc("no coverage entry")
        )),
        "{section}"
    );
    // Its ELF was never scanned: the report does not say that no signature was found.
    assert_eq!(
        section.matches(&md_esc(NO_IDENTITY_ENTRY)).count(),
        1,
        "{section}"
    );
    assert!(!section.contains(&md_esc(NO_SIGNATURES)), "{section}");
}

/// Signature rows are in (feature, value, kind, where) order, whatever the session's order: two
/// hints of one feature and value differ by their Kind and Where cells (PR-4c-2a).
#[test]
fn signature_rows_are_in_feature_value_kind_and_where_order() {
    let mut s = binary_inspect();
    // A Go function hint needs Go build info in its slice (S3).
    s.binaries[0].go = Some(GoBuildInfo {
        version: t("go1.24.1"),
        path: None,
        main: None,
        deps: vec![],
        settings: vec![],
        at: Loc::VAddr(0x4000),
    });
    let slice = s.binaries[0].slice.clone();
    let value = "ggml_backend_rpc_init";
    let hint = |signal: Signal, value: &str, at: Loc| FeatureHint {
        subject: slice.clone(),
        feature: id("x.signature"),
        signal,
        value: t(value),
        at,
    };
    let section = |name: &str, offset: u64| Loc::Section {
        name: t(name),
        offset,
    };
    s.hints.extend([
        hint(Signal::String, value, section(".rodata", 0x20)),
        hint(Signal::String, value, section(".rodata", 0x10)),
        hint(Signal::Export, value, Loc::Symbol(t(value))),
        hint(Signal::GoFunction, value, section(".gopclntab", 0x30)),
        hint(Signal::Export, "a", Loc::Symbol(t("a"))),
    ]);
    assert_eq!(s.validate(), Ok(()));
    let rows = |s: &Session| -> Vec<String> {
        let md = render_session(s);
        binaries_section(&md)
            .lines()
            .skip_while(|l| !l.starts_with("| Feature | Kind | Value | Where |"))
            .skip(2)
            .take_while(|l| l.starts_with('|'))
            .map(str::to_string)
            .collect()
    };
    let row = |cells: [&str; 4]| {
        format!(
            "| {} |",
            cells
                .iter()
                .map(|c| md_esc(c))
                .collect::<Vec<_>>()
                .join(" | ")
        )
    };
    let expected = [
        row(["x.signature", "export", "a", "symbol a"]),
        row(["x.signature", "Go function", value, ".gopclntab + 0x30"]),
        row(["x.signature", "export", value, &format!("symbol {value}")]),
        row(["x.signature", "string", value, ".rodata + 0x10"]),
        row(["x.signature", "string", value, ".rodata + 0x20"]),
    ];
    assert_eq!(rows(&s), expected);
    // The reverse session order renders the same rows.
    s.hints.reverse();
    assert_eq!(s.validate(), Ok(()));
    assert_eq!(rows(&s), expected);
}

/// `binary_inspect` with its shared object named as NVIDIA's runtime: its claim is
/// `cuda-runtime`, and its input's `binary.identity` is `OutOfScope` (ADR-010).
fn nvidia_inspect() -> Session {
    let mut s = binary_inspect();
    let elf = InstanceId::new(ELF_INPUT).unwrap();
    s.components[0].component = id("cuda-runtime");
    s.coverage
        .iter_mut()
        .find(|c| c.check.as_str() == BINARY_IDENTITY && c.scope == Ref::Instance(elf.clone()))
        .unwrap()
        .state = CoverageState::OutOfScope {
        why: NAME_AND_HASH_ONLY_WHY.to_string(),
    };
    s
}

/// An NVIDIA library is identified by name and hash only (ADR-010): its content was not scanned,
/// so the report says so instead of `No signature found.` (PR-4c-2a).
#[test]
fn an_nvidia_library_says_it_was_not_scanned() {
    let s = nvidia_inspect();
    assert_eq!(s.validate(), Ok(()));
    let md = render_session(&s);
    let section = binaries_section(&md);
    assert!(
        row_of(section, "/home/user/Downloads/libggml-base.so").ends_with(&format!(
            "| {} | {} |",
            md_esc("complete"),
            md_esc(&format!("out of scope: {NAME_AND_HASH_ONLY_WHY}"))
        )),
        "{section}"
    );
    assert_eq!(
        section.matches(&md_esc(NOT_SCANNED)).count(),
        1,
        "{section}"
    );
    assert!(!section.contains(&md_esc(NO_SIGNATURES)), "{section}");
    assert!(!section.contains(&md_esc("Signatures of")), "{section}");
    // Its imports are the container's: its capabilities are shown.
    assert!(section.contains(&md_esc("Capabilities of")), "{section}");
}

/// A content under two inputs is shown once, under its first: the first input's
/// `binary.identity` says whether it was scanned.
#[test]
fn a_content_s_first_input_says_whether_it_was_scanned() {
    let with_copy = |first: CoverageState, copy: CoverageState| {
        let mut s = nvidia_inspect();
        let elf = InstanceId::new(ELF_INPUT).unwrap();
        s.coverage
            .iter_mut()
            .find(|c| c.check.as_str() == BINARY_IDENTITY && c.scope == Ref::Instance(elf.clone()))
            .unwrap()
            .state = first;
        let copy_id: InstanceId = id("inst:binary-3/libcudart.so.12");
        let path = "/home/user/Downloads/libcudart.so.12";
        let mut i = instance(&copy_id, "binary-3", path, &s.artifacts[0].id, 33);
        i.stat.size = 1_048_576;
        i.discovered_by = vec![DiscoverySource::Argument];
        s.instances.push(i);
        s.request.roots.push(ScanRoot {
            id: binary_root(3).unwrap(),
            path: t(path),
        });
        s.coverage.push(coverage(
            BINARY_CONTAINER,
            Ref::Instance(copy_id.clone()),
            CoverageState::Complete,
        ));
        s.coverage
            .push(coverage(BINARY_IDENTITY, Ref::Instance(copy_id), copy));
        s.canonicalize();
        assert_eq!(s.validate(), Ok(()));
        let md = render_session(&s);
        binaries_section(&md).to_string()
    };
    let out_of_scope = CoverageState::OutOfScope {
        why: NAME_AND_HASH_ONLY_WHY.to_string(),
    };
    let section = with_copy(out_of_scope.clone(), CoverageState::Complete);
    assert_eq!(
        section.matches(&md_esc(NOT_SCANNED)).count(),
        1,
        "{section}"
    );
    assert!(!section.contains(&md_esc(NO_SIGNATURES)), "{section}");
    let section = with_copy(CoverageState::Complete, out_of_scope);
    assert_eq!(
        section.matches(&md_esc(NO_SIGNATURES)).count(),
        1,
        "{section}"
    );
    assert!(!section.contains(&md_esc(NOT_SCANNED)), "{section}");
}
