//! The Markdown report of a session (plan §4.8, §4.10): every golden example renders, the outcome
//! shows the verdict and completeness together, and no input-derived text can form Markdown or
//! HTML structure.

use std::fs;
use std::path::PathBuf;

use sigil_model::render::markdown::render_session;
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
    assert_eq!(all.len(), 15);
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
        let ContainerFacts::Elf(f) = &mut s.binaries[0].container;
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
