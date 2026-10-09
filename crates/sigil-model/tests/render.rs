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
    assert_eq!(all.len(), 13);
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
        scope: "127.0.0.1:11434 from this host".to_string(),
        basis: AbsenceBasis::ConnectionRefused,
    };
    assert_eq!(
        sigil_model::render::coverage_state(&state).terminal(),
        "not present: connection refused at 127.0.0.1:11434 from this host"
    );
}
