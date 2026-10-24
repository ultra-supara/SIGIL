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
    // Example 8: an install root, and no reference comparison.
    let session = common::profile_mismatch();
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
    CheckId, Coverage, CoverageState, EvidenceRef, IdentityAssertion, InstanceContent, Ref,
    ReleaseBasis, ReportedCommit, RootId, Session, Stability, UntrustedText, ARTIFACTS_DISCOVERY,
    ARTIFACTS_RELEASE,
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

// --- validation V12 (PR-4c-2c) -----------------------------------------------------------------

/// Golden example 17: an open claim.
fn open() -> Session {
    let s = common::open_release();
    assert_eq!(s.validate(), Ok(()), "the open base must be valid");
    s
}

/// Rejected by a V12 error whose reason contains `why`, whatever else is also reported.
fn rejected_release(s: &Session, why: &str) {
    let errors = s.validate().unwrap_err();
    assert!(
        errors.iter().any(
            |e| matches!(e, sigil_model::ValidationError::Release { why: w, .. } if w.contains(why))
        ),
        "{why}: {errors:?}"
    );
}

/// The commits of example 17's open claim.
fn commits(s: &mut Session) -> &mut Vec<ReportedCommit> {
    match &mut s.releases[0].basis {
        ReleaseBasis::SelfReportedCommit { commits } => commits,
        ReleaseBasis::ReferenceMatches { .. } => panic!("example 17's claim is open"),
    }
}

/// Canonical order (PR-4c-2c): an open claim's commits and candidates are sorted, so what the
/// engine derives and what a saved session holds compare as written.
#[test]
fn canonicalize_sorts_an_open_claim_s_commits_and_candidates() {
    let mut s = open();
    let first = commits(&mut s)[0].clone();
    let mut second = first.clone();
    second.field = "ggml_commit".to_string();
    // "LLAMA_COMMIT" sorts before "ggml_commit" in JSON text: list them the other way round.
    *commits(&mut s) = vec![second.clone(), first.clone()];
    s.releases[0].candidates = vec!["v0.30.7".into(), "v0.30.5".into(), "v0.30.6".into()];
    s.canonicalize();
    assert_eq!(*commits(&mut s), vec![first, second]);
    assert_eq!(s.releases[0].candidates, ["v0.30.5", "v0.30.6", "v0.30.7"]);
}

#[test]
fn v12_one_claim_per_product_with_unique_candidates() {
    let mut s = open();
    let mut again = s.releases[0].clone();
    again.candidates.pop();
    s.releases.push(again);
    rejected_release(&s, "one release claim per product");
    let mut s = open();
    s.releases[0].candidates.push("v0.30.5".into());
    rejected_release(&s, "the candidates are unique");
}

#[test]
fn v12_an_open_claim_is_for_an_install_and_never_beside_a_closed_one() {
    let mut s = open();
    let closed = base().releases[0].clone();
    s.releases.insert(0, closed);
    rejected_release(&s, "never beside a claim by reference matches");
    let mut s = open();
    s.request.roots[0].id = RootId::new("models").unwrap();
    rejected_release(&s, "only for an install");
    // Plan review P2: without a reference set, no verifier would ever recompute it.
    let mut s = open();
    s.knowledge
        .retain(|k| k.kind != sigil_model::KnowledgeKind::ReferenceManifest);
    rejected_release(&s, "needs a reference set in knowledge");
}

#[test]
fn v12_an_open_claim_rests_on_the_session_s_own_commits() {
    let mut s = open();
    commits(&mut s).clear();
    rejected_release(&s, "at least one commit");
    let mut s = open();
    let again = commits(&mut s)[0].clone();
    commits(&mut s).push(again);
    rejected_release(&s, "each commit is listed once");
    let mut s = open();
    commits(&mut s)[0].value = UntrustedText::new("6f3a9f3");
    rejected_release(&s, "an Embedded assertion of a claim");
    let mut s = open();
    commits(&mut s)[0].field = "ggml_commit".to_string();
    rejected_release(&s, "an Embedded assertion of a claim");
    // Only the evidence differs from the assertion's.
    let mut s = open();
    let artifact = s.artifacts[0].id.clone();
    commits(&mut s)[0].at = EvidenceRef::Artifact { artifact };
    rejected_release(&s, "an Embedded assertion of a claim");
    // A value that is no commit, even when the claim's assertion has it.
    let mut s = open();
    commits(&mut s)[0].value = UntrustedText::new("unknown");
    for a in &mut s.components[0].assertions {
        if let IdentityAssertion::Embedded { value, .. } = a {
            *value = UntrustedText::new("unknown");
        }
    }
    rejected_release(&s, "7 to 40 lowercase hex digits");
}

#[test]
fn a_commit_is_7_to_40_lowercase_hex_digits() {
    for (text, commit) in [
        ("6f3a9f3", true),
        ("6f3a9f3de", true),
        ("6f3a9f3dee3c27545371044a3a38005721ac8a8e", true),
        ("6f3a9f", false),
        ("6f3a9f3dee3c27545371044a3a38005721ac8a8e0", false),
        ("6F3A9F3DE", false),
        ("6f3a9f3dg", false),
        ("unknown", false),
        ("", false),
    ] {
        assert_eq!(sigil_model::is_commit(text.as_bytes()), commit, "{text:?}");
    }
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
