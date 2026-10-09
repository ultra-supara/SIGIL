//! `ReferenceMatch` (PR-4a): the record type, its JSON, and the compatibility of sessions without
//! it.

mod common;

use sigil_model::{
    EntryKind, InstanceId, MemberKind, MemberResult, NotReadReason, RefSetId, ReferenceMatch,
    Sha256Hex,
};

fn sha(c: char) -> Sha256Hex {
    Sha256Hex::new(c.to_string().repeat(64)).unwrap()
}

#[test]
fn a_reference_match_round_trips_as_json() {
    let row = ReferenceMatch {
        reference: RefSetId::new("ollama-official").unwrap(),
        release: "v0.30.6".to_string(),
        member: "bin/ollama".to_string(),
        instance: Some(InstanceId::new("inst:install/bin/ollama").unwrap()),
        result: MemberResult::File {
            expected: sha('a'),
            observed: sha('a'),
        },
    };
    let json = serde_json::to_string(&row).unwrap();
    assert_eq!(serde_json::from_str::<ReferenceMatch>(&json).unwrap(), row);
    assert!(row.result.matches());
    for (result, matches) in [
        (MemberResult::Directory, true),
        (
            MemberResult::File {
                expected: sha('a'),
                observed: sha('b'),
            },
            false,
        ),
        (MemberResult::NotCompared, false),
        (
            MemberResult::Absent {
                kind: MemberKind::File,
            },
            false,
        ),
        (
            MemberResult::KindDiffers {
                expected: MemberKind::File,
                observed: EntryKind::Directory,
            },
            false,
        ),
    ] {
        assert_eq!(result.matches(), matches, "{result:?}");
    }
}

#[test]
fn a_session_without_reference_matches_reads_and_writes_without_them() {
    let session = common::complete_pass();
    let json = serde_json::to_value(&session).unwrap();
    assert!(
        json.get("reference_matches").is_none(),
        "an empty list is not written"
    );
    let read: sigil_model::Session = serde_json::from_value(json).unwrap();
    assert!(read.reference_matches.is_empty());
}

#[test]
fn the_new_not_read_reasons_are_json_names() {
    for (reason, name) in [
        (NotReadReason::NotFollowed, "\"NotFollowed\""),
        (NotReadReason::Directory, "\"Directory\""),
    ] {
        assert_eq!(serde_json::to_string(&reason).unwrap(), name);
    }
}

// --- validation V1–V11 -------------------------------------------------------------------------

use sigil_model::{
    CheckId, Coverage, CoverageState, InstanceContent, Ref, ReleaseBasis, Session, Stability,
    ARTIFACTS_DISCOVERY, ARTIFACTS_RELEASE,
};

/// Golden example 12 (one placement, one row, a closed claim for v0.30.6), with a valid
/// `artifacts.release` coverage added.
fn base() -> Session {
    let mut s = common::conflicting_identity();
    s.coverage.push(Coverage {
        check: CheckId::new(ARTIFACTS_RELEASE).unwrap(),
        scope: Ref::Audit,
        state: CoverageState::Complete,
        budget: None,
    });
    s.canonicalize();
    assert_eq!(s.validate(), Ok(()), "the base must be valid");
    s
}

fn rejected(s: &Session, what: &str) {
    assert!(s.validate().is_err(), "must be rejected: {what}");
}

/// Rejected by a row error whose reason contains `why`, whatever else is also reported.
fn rejected_row(s: &Session, why: &str) {
    let errors = s.validate().unwrap_err();
    assert!(
        errors.iter().any(
            |e| matches!(e, sigil_model::ValidationError::ReferenceRow { why: w, .. } if w.contains(why))
        ),
        "{why}: {errors:?}"
    );
}

fn set_state(s: &mut Session, check: &str, state: CoverageState) {
    for c in &mut s.coverage {
        if c.check.as_str() == check {
            c.state = state.clone();
        }
    }
}

#[test]
fn v1_the_reference_must_be_a_reference_manifest() {
    let mut s = base();
    s.reference_matches[0].reference = RefSetId::new("elsewhere").unwrap();
    rejected(&s, "unknown reference");
}

#[test]
fn v2_an_instance_is_present_exactly_for_non_absent_rows_and_at_the_member_path() {
    let mut s = base();
    s.reference_matches[0].instance = None;
    rejected(&s, "a File row without an instance");
    let mut s = base();
    s.reference_matches[0].member = "lib/ollama/other.so".to_string();
    rejected(&s, "the member is not the instance's path");
}

#[test]
fn v3_a_file_row_needs_a_stable_read_with_that_sha256() {
    let mut s = base();
    if let MemberResult::File { observed, .. } = &mut s.reference_matches[0].result {
        *observed = sha('2');
    }
    rejected(&s, "observed differs from the artifact");
    let mut s = base();
    s.instances[0].stability = Stability::ChangedDuringRead;
    rejected(&s, "a match on an unstable instance");
}

#[test]
fn v6_a_kind_difference_must_name_the_observed_kind() {
    let mut s = base();
    s.reference_matches[0].result = MemberResult::KindDiffers {
        expected: MemberKind::Symlink,
        observed: EntryKind::Directory, // the instance is a regular file
    };
    rejected_row(&s, "KindDiffers must name the placement's own kind");
}

#[test]
fn v7_not_compared_exactly_for_unstable_or_unread_files() {
    let mut s = base();
    s.reference_matches[0].result = MemberResult::NotCompared;
    rejected(&s, "NotCompared on a stable, read file");
}

#[test]
fn v8_absent_only_after_a_complete_discovery_and_not_where_a_placement_is() {
    let mut s = base();
    let mut row = s.reference_matches[0].clone();
    row.member = "bin/ollama".to_string();
    row.instance = None;
    row.result = MemberResult::Absent {
        kind: MemberKind::File,
    };
    s.reference_matches.push(row);
    s.canonicalize();
    rejected(&s, "release Complete with an Absent row (V11)");
    set_state(
        &mut s,
        ARTIFACTS_RELEASE,
        CoverageState::Partial {
            missing: vec!["absent".into()],
        },
    );
    assert_eq!(s.validate(), Ok(()));
    set_state(
        &mut s,
        ARTIFACTS_DISCOVERY,
        CoverageState::Partial {
            missing: vec!["x".into()],
        },
    );
    rejected_row(&s, "Absent while discovery is not complete");
    let mut s = base();
    let mut row = s.reference_matches[0].clone();
    row.instance = None;
    row.result = MemberResult::Absent {
        kind: MemberKind::File,
    };
    row.release = "v0.30.7".into();
    s.reference_matches.push(row);
    rejected_row(&s, "Absent, but a placement is at the member's path");
}

#[test]
fn v9_rows_are_unique() {
    let mut s = base();
    let row = s.reference_matches[0].clone();
    s.reference_matches.push(row);
    rejected(&s, "duplicate row");
}

#[test]
fn v10_the_candidates_are_recomputed_from_the_rows() {
    // The review's case: only the candidates changed.
    let mut s = base();
    s.releases[0].candidates = vec!["v0.30.7".to_string()];
    rejected(&s, "candidates changed to another release");
    let mut s = base();
    s.reference_matches.clear();
    rejected(&s, "a claim with no rows");
    let mut s = base();
    if let ReleaseBasis::ReferenceMatches { files, .. } = &mut s.releases[0].basis {
        files.clear();
    }
    rejected(&s, "a claim missing its placements");
    // A matching row of another release makes it a candidate too.
    let mut s = base();
    let mut row = s.reference_matches[0].clone();
    row.release = "v0.30.7".into();
    s.reference_matches.push(row);
    s.canonicalize();
    rejected(&s, "v0.30.7 matches every placement but is not a candidate");
    s.releases[0].candidates = vec!["v0.30.6".into(), "v0.30.7".into()];
    assert_eq!(s.validate(), Ok(()));
}

#[test]
fn v11_release_complete_needs_a_claim_and_a_complete_discovery() {
    let mut s = base();
    s.releases.clear();
    rejected(&s, "release Complete without a claim");
    let mut s = base();
    set_state(
        &mut s,
        ARTIFACTS_RELEASE,
        CoverageState::Partial {
            missing: vec!["x".into()],
        },
    );
    rejected(&s, "release Partial although everything holds");
}

#[test]
fn an_unread_file_is_not_compared() {
    let mut s = base();
    s.instances[0].content = InstanceContent::NotRead {
        why: NotReadReason::PermissionDenied,
    };
    s.reference_matches[0].result = MemberResult::NotCompared;
    s.releases.clear();
    s.coverage.retain(|c| c.check.as_str() != ARTIFACTS_RELEASE);
    s.components.clear();
    s.artifacts.clear();
    s.canonicalize();
    assert_eq!(s.validate(), Ok(()));
}
