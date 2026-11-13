//! The fixture pairs under `schemas/examples/diff-v1/` (#16, PR-16a). Each case's sessions,
//! its diff and the diff's Markdown are exactly what `tests/common/diff_cases.rs` and
//! `sigil_model::diff` produce. The sessions are written in canonical form, so each file
//! hashes to the SHA-256 its diff records.
//!
//! To regenerate after an intended change:
//! `SIGIL_BLESS=1 cargo test -p sigil-model --test diff_examples golden_pairs_match_the_builders`.

mod common;

use std::path::PathBuf;

use common::diff_cases::*;
use sigil_model::diff::markdown;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas/examples/diff-v1")
}

#[test]
fn golden_pairs_match_the_builders() {
    let bless = std::env::var_os("SIGIL_BLESS").is_some();
    for case in diff_cases() {
        let at = dir().join(case.name);
        if bless {
            std::fs::create_dir_all(&at).unwrap();
        }
        let diff = diff_of(&case.baseline, &case.current);
        for (file, expected) in [
            ("baseline.json", case.baseline.to_canonical_json().unwrap()),
            ("current.json", case.current.to_canonical_json().unwrap()),
            ("diff.json", diff.to_canonical_json().unwrap()),
            ("diff.md", markdown(&diff)),
        ] {
            let path = at.join(file);
            if bless {
                std::fs::write(&path, &expected).unwrap();
                continue;
            }
            let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                panic!(
                    "{}: {e}; run SIGIL_BLESS=1 cargo test -p sigil-model --test diff_examples golden_pairs_match_the_builders",
                    path.display()
                )
            });
            assert_eq!(
                raw, expected,
                "{}/{file} is stale; run SIGIL_BLESS=1 cargo test -p sigil-model --test diff_examples golden_pairs_match_the_builders",
                case.name
            );
        }
    }
}

#[test]
fn the_directories_are_the_cases() {
    let mut on_disk: Vec<String> = std::fs::read_dir(dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    on_disk.sort();
    let names: Vec<String> = diff_cases().iter().map(|c| c.name.to_string()).collect();
    assert_eq!(on_disk, names);
}

#[test]
fn each_case_reports_its_own_kind_exactly_once_and_these_kinds() {
    let expected: &[(&str, &[&str])] = &[
        ("01-identical", &[]),
        ("02-model-added", &["ModelAdded"]),
        ("03-blob-digest-changed", &["LayerChanged"]),
        (
            "04-license-removed",
            &[
                "VerdictChanged",
                "FindingNew",
                "LayerChanged",
                "LicenseChanged",
            ],
        ),
        (
            "05-loopback-to-wildcard",
            &["VerdictChanged", "FindingNew", "BindWidened"],
        ),
        ("06-install-file-replaced", &["FileContentChanged"]),
        ("07-claim-conflicting", &["ComponentChanged"]),
        (
            "08-new-finding",
            &[
                "VerdictChanged",
                "CompletenessChanged",
                "CheckOpened",
                "FindingNew",
            ],
        ),
        (
            "09-resolved-finding",
            &[
                "VerdictChanged",
                "CompletenessChanged",
                "CheckClosed",
                "FindingResolved",
            ],
        ),
        ("10-check-now-open", &["CompletenessChanged", "CheckOpened"]),
        ("11-new-open-question", &["OpenQuestionNew"]),
    ];
    for case in diff_cases() {
        let diff = diff_of(&case.baseline, &case.current);
        let got = kinds(&diff);
        if let Some(kind) = case.kind {
            assert_eq!(
                got.iter().filter(|k| *k == kind).count(),
                1,
                "{}: {got:?}",
                case.name
            );
        }
        let (_, want) = expected
            .iter()
            .find(|(name, _)| *name == case.name)
            .unwrap_or_else(|| panic!("{} has no expected kinds", case.name));
        assert_eq!(got, *want, "{}", case.name);
        assert!(
            diff.not_comparable.is_empty(),
            "{}: {:?}",
            case.name,
            diff.not_comparable
        );
    }
}
