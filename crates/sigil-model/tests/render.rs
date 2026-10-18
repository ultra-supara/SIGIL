//! The Markdown report of a session (plan §4.8, §4.10): every golden example renders, the outcome
//! shows the verdict and completeness together, and no input-derived text can form Markdown or
//! HTML structure.

use std::fs;
use std::path::PathBuf;

use sigil_model::render::code::{NONE_FOUND, NOT_ANALYZED, NOT_SEARCHED, NO_CAPABILITY_IMPORTS};
use sigil_model::render::markdown::{
    render_session, BINARY_CAVEAT, BINARY_CAVEAT_CODE, CODE_CAVEAT,
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
    assert_eq!(all.len(), 16);
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
        "lib/ollama/libggml.so.0.13.1",
        "File",
        "sha256:111111111111",
        "matches v0.30.6",
    ]
    .iter()
    .map(|c| t(c).markdown_inline())
    .collect();
    let row = format!("| {} |", cells.join(" | "));
    assert!(section.contains(&row), "{row}\n{section}");

    // An install root without a comparison says so.
    let md = render_session(&complete_pass());
    assert!(md.contains("not compared with a reference set"), "{md}");

    // No install root, no section.
    let mut s = complete_pass();
    s.request.roots.retain(|r| r.id.as_str() != INSTALL_ROOT);
    s.instances.retain(|i| i.root.as_str() != INSTALL_ROOT);
    assert!(!render_session(&s).contains("## Runtime artifacts"));
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
        s.coverage.push(coverage(
            BINARY_CONTAINER,
            Ref::Instance(inst),
            CoverageState::Unsupported {
                what: BINARY_UNSUPPORTED.to_string(),
            },
        ));
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
    s.request
        .required_checks
        .retain(|c| c.as_str() == BINARY_CONTAINER);
    s.request.budgets.remove(BINARY_CODE_BYTES);
    s.code.clear();
    s.coverage.retain(|c| c.check.as_str() == BINARY_CONTAINER);
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
        section.contains(r"| Path | SHA\-256 | Size | Type | Container facts | Code |"),
        "{section}"
    );
    let input = row_of(section, KERNEL_PATH);
    assert!(
        input.ends_with(&format!(
            "| {} | {} |",
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
        section.contains("| Path | SHA\\-256 | Size | Type | Container facts |\n"),
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
    let row = format!(
        "| {} | {} | {} |",
        md_esc("posix.network"),
        md_esc("connect"),
        md_esc(NONE_FOUND)
    );
    assert_eq!(row_of(binaries_section(&md), "posix.network"), row);
    // A partial search is a search too (plan P-p).
    s.coverage
        .iter_mut()
        .find(|c| c.check.as_str() == BINARY_CODE)
        .unwrap()
        .state = CoverageState::Partial {
        missing: vec!["code: a gap".to_string()],
    };
    let md = render_session(&s);
    assert_eq!(row_of(binaries_section(&md), "posix.network"), row);
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
    });
    let md = render_session(&s);
    let section = binaries_section(&md);
    assert!(section.contains(&md_esc("Mach-O 64-bit")), "{section}");
    assert!(!section.contains(&md_esc("Capabilities of")), "{section}");
    assert!(
        !section.contains(&md_esc(NO_CAPABILITY_IMPORTS)),
        "{section}"
    );
    assert!(!section.contains(&md_esc("binary.code: ")), "{section}");
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
    assert!(!section.contains(&md_esc("exported_fn")), "{section}");
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
    // Out of key order, two of one key, and a hint that is not an import.
    s.hints = vec![
        hint("posix.network", Signal::Import, "socket"),
        hint("posix.dynamic_loading", Signal::Import, "dlsym"),
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
            table.contains(r"| Exports \/ imports | Capabilities \(imports\) | Notes |"),
            "{table}"
        );
        let row = table
            .lines()
            .find(|l| l.starts_with('|') && l.contains(&md_esc("libggml.so.0")))
            .unwrap_or_else(|| panic!("{table}"));
        row.trim_matches('|')
            .split(" | ")
            .map(str::trim)
            .nth(5)
            .unwrap()
            .to_string()
    };
    assert_eq!(cell(&s), md_esc("posix.dynamic_loading, posix.network"));
    s.hints.clear();
    assert_eq!(cell(&s), md_esc("-"));
}
