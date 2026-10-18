//! Identity claims against their evidence (PR-4c-1 spec §5): each status fits only the
//! assertions the table allows, exactly one fits any claim but a conflicting one, and every
//! `KnownHash` is the reference row of a placement of the claim's artifact (I1).

mod common;

use common::*;
use sigil_model::*;

const NO_ROW: &str = "no reference row of a placement of the claim's artifact";
const DISAGREES: &str = "matched disagrees with the row's result";

fn unsupported(status: IdentityStatus) -> impl Fn(&ValidationError) -> bool {
    move |e| matches!(e, ValidationError::StatusUnsupported { status: s, .. } if *s == status)
}

fn known_hash(why: &'static str) -> impl Fn(&ValidationError) -> bool {
    move |e| matches!(e, ValidationError::KnownHashDisagrees { why: w, .. } if *w == why)
}

/// Whether `s` has a `StatusUnsupported` error.
fn status_refused(s: &Session) -> bool {
    errors(s)
        .iter()
        .any(|e| matches!(e, ValidationError::StatusUnsupported { .. }))
}

/// The first claim's `KnownHash`.
fn known(s: &mut Session) -> &mut IdentityAssertion {
    s.components[0]
        .assertions
        .iter_mut()
        .find(|a| matches!(a, IdentityAssertion::KnownHash { .. }))
        .unwrap()
}

/// A code check that agrees with `obligation`, which passed in the session's profile match.
fn passing_check(obligation: &str) -> IdentityAssertion {
    IdentityAssertion::CodeCheck {
        profile: id(PROFILE),
        check: id(obligation),
        result: CheckResult::Match,
        at: vec![],
    }
}

fn signature() -> IdentityAssertion {
    IdentityAssertion::Signature {
        state: SigState::NotChecked,
    }
}

/// Example 8's one name, replaced by an embedded value.
fn embedded_only() -> Session {
    let mut s = profile_mismatch();
    let g = placed(&s, "inst:lib/ollama/libggml.so");
    s.components[0].assertions = vec![IdentityAssertion::Embedded {
        field: "LLAMA_COMMIT".to_string(),
        value: t("6f3a9f3de"),
        at: EvidenceRef::Code {
            slice: g.slice,
            loc: Loc::Symbol(t("LLAMA_COMMIT")),
        },
        method: ExtractMethod::DataSymbolPointer {
            symbol: t("LLAMA_COMMIT"),
        },
    }];
    s
}

#[test]
fn reference_matched_needs_a_matched_known_hash() {
    assert_valid(&complete_pass());
    // The row differs: the hash is recorded unmatched, and the claim is name-only.
    let mut s = complete_pass();
    s.reference_matches[0].result = MemberResult::File {
        expected: id(&hex(0x12)),
        observed: id(&hex(0x11)),
    };
    if let IdentityAssertion::KnownHash { matched, .. } = known(&mut s) {
        *matched = false;
    }
    assert_rejected(
        &s,
        unsupported(IdentityStatus::ReferenceMatched),
        "ReferenceMatched on an unmatched KnownHash",
    );
    s.components[0].status = IdentityStatus::NameOnly;
    assert_valid(&s);
}

#[test]
fn name_only_needs_a_name_and_nothing_stronger() {
    let mut s = complete_pass();
    s.components[0].status = IdentityStatus::NameOnly;
    assert_rejected(
        &s,
        unsupported(IdentityStatus::NameOnly),
        "NameOnly with a matched KnownHash",
    );
    let mut s = profile_mismatch();
    s.components[0]
        .assertions
        .push(passing_check("entry.name_sequence"));
    assert_rejected(
        &s,
        unsupported(IdentityStatus::NameOnly),
        "NameOnly with a passing code check",
    );
    let mut s = profile_mismatch();
    s.components[0].assertions = vec![signature()];
    assert_rejected(
        &s,
        unsupported(IdentityStatus::NameOnly),
        "NameOnly with only a Signature",
    );
}

/// Spec §4, F-I3: an embedded value is evidence, so never `Unidentified`.
#[test]
fn an_embedded_value_alone_is_name_only() {
    let s = embedded_only();
    assert_valid(&s);
    let mut s = embedded_only();
    s.components[0].status = IdentityStatus::Unidentified;
    assert_rejected(
        &s,
        unsupported(IdentityStatus::Unidentified),
        "Unidentified with an embedded value",
    );
}

#[test]
fn corroborated_needs_a_passing_check_and_no_matched_known_hash() {
    let mut s = profile_mismatch();
    s.components[0]
        .assertions
        .push(passing_check("entry.name_sequence"));
    s.components[0].status = IdentityStatus::Corroborated;
    assert_valid(&s);
    let mut s = complete_fail();
    s.components[0]
        .assertions
        .push(passing_check("filter.reach_predicate"));
    s.components[0].status = IdentityStatus::Corroborated;
    assert_rejected(
        &s,
        unsupported(IdentityStatus::Corroborated),
        "Corroborated with a matched KnownHash",
    );
}

#[test]
fn unidentified_needs_no_evidence() {
    let mut s = profile_mismatch();
    s.components[0].status = IdentityStatus::Unidentified;
    assert_rejected(
        &s,
        unsupported(IdentityStatus::Unidentified),
        "Unidentified with a self-name",
    );
    s.components[0].assertions = vec![signature()];
    assert_valid(&s);
}

#[test]
fn conflicting_needs_two_sources_and_a_signature_is_none() {
    let mut s = profile_mismatch();
    s.components[0].status = IdentityStatus::Conflicting;
    assert_rejected(
        &s,
        unsupported(IdentityStatus::Conflicting),
        "Conflicting with one self-name",
    );
    s.components[0].assertions.push(signature());
    assert_rejected(
        &s,
        unsupported(IdentityStatus::Conflicting),
        "Conflicting with one self-name and a Signature",
    );
    s.components[0].versions.push(VersionAssertion {
        value: t("0"),
        source: VersionSource::SelfName {
            kind: NameKind::Filename,
        },
        at: EvidenceRef::Instance {
            instance: id("inst:lib/ollama/libggml.so"),
        },
    });
    assert_valid(&s);
    // Every identity assertion is a source: a self-name and a `Required` name, or a code check,
    // are two.
    let base = profile_mismatch();
    let g = placed(&base, "inst:lib/ollama/libggml.so");
    for other in [
        IdentityAssertion::Required {
            by: g.slice.clone(),
            needed: t("libggml.so"),
        },
        passing_check("entry.name_sequence"),
    ] {
        let mut s = base.clone();
        s.components[0].assertions.push(other);
        s.components[0].status = IdentityStatus::Conflicting;
        assert_valid(&s);
    }
    // So are a self-name and an unmatched KnownHash, with no version.
    let mut s = complete_pass();
    s.reference_matches[0].result = MemberResult::File {
        expected: id(&hex(0x12)),
        observed: id(&hex(0x11)),
    };
    if let IdentityAssertion::KnownHash { matched, .. } = known(&mut s) {
        *matched = false;
    }
    s.components[0].versions.clear();
    s.components[0].status = IdentityStatus::Conflicting;
    assert_valid(&s);
}

/// Spec §5: without `Conflicting`, exactly one status fits each mix of evidence, and it is the
/// one the table gives.
#[test]
fn exactly_one_status_fits_each_mix_of_evidence() {
    let base = complete_fail();
    let g = placed(&base, GGML);
    let evidence = [
        IdentityAssertion::SelfName {
            kind: NameKind::Filename,
            value: t("libggml.so.0.13.1"),
            at: EvidenceRef::Instance {
                instance: g.inst.clone(),
            },
        },
        IdentityAssertion::Embedded {
            field: "LLAMA_COMMIT".to_string(),
            value: t("6f3a9f3de"),
            at: EvidenceRef::Code {
                slice: g.slice.clone(),
                loc: Loc::Symbol(t("LLAMA_COMMIT")),
            },
            method: ExtractMethod::DataSymbolPointer {
                symbol: t("LLAMA_COMMIT"),
            },
        },
        IdentityAssertion::Required {
            by: g.slice.clone(),
            needed: t("libggml.so.0"),
        },
        IdentityAssertion::KnownHash {
            reference: id("ollama-official"),
            release: "v0.30.6".to_string(),
            member: "lib/ollama/libggml.so.0.13.1".to_string(),
            matched: true,
        },
        passing_check("filter.reach_predicate"),
    ];
    let statuses = [
        IdentityStatus::ReferenceMatched,
        IdentityStatus::Corroborated,
        IdentityStatus::NameOnly,
        IdentityStatus::Unidentified,
    ];
    for mask in 0u32..32 {
        let has = |k: u32| mask & (1 << k) != 0;
        let expected = if has(3) {
            IdentityStatus::ReferenceMatched
        } else if has(4) {
            IdentityStatus::Corroborated
        } else if has(0) || has(1) || has(2) {
            IdentityStatus::NameOnly
        } else {
            IdentityStatus::Unidentified
        };
        let mut fits = vec![];
        for status in statuses {
            let mut s = base.clone();
            let claim = &mut s.components[0];
            claim.assertions = (0..5)
                .filter(|k| has(*k))
                .map(|k| evidence[k as usize].clone())
                .collect();
            claim.assertions.push(signature());
            claim.versions.clear();
            claim.status = status;
            if !status_refused(&s) {
                fits.push(status);
            }
        }
        assert_eq!(fits, [expected], "mask {mask:05b}");
    }
}

#[test]
fn a_known_hash_needs_the_row_of_a_placement_of_its_artifact() {
    assert_valid(&complete_pass());
    let mut s = complete_pass();
    s.reference_matches.clear();
    assert_rejected(&s, known_hash(NO_ROW), "a KnownHash without a row");
    let mut s = complete_pass();
    if let IdentityAssertion::KnownHash { release, .. } = known(&mut s) {
        *release = "v0.30.7".to_string();
    }
    assert_rejected(&s, known_hash(NO_ROW), "a KnownHash of another release");
    // Another manifest, known to the session, that has no row at that release and member.
    let mut s = complete_pass();
    add_knowledge(
        &mut s,
        KnowledgeKind::ReferenceManifest,
        "elsewhere",
        "2026-10-07",
        0xa3,
    );
    if let IdentityAssertion::KnownHash { reference, .. } = known(&mut s) {
        *reference = id("elsewhere");
    }
    assert_rejected(&s, known_hash(NO_ROW), "a KnownHash of another reference");
    let mut s = complete_pass();
    if let IdentityAssertion::KnownHash { member, .. } = known(&mut s) {
        *member = "lib/ollama/libggml.so".to_string();
    }
    assert_rejected(&s, known_hash(NO_ROW), "a KnownHash of another member");
    // The row is there, but for another artifact's placement.
    let mut s = complete_pass();
    let other = add_binary(
        &mut s,
        &hex(0x33),
        "lib/ollama/libllama.so.0.0.1",
        Arch::X86_64,
        1002,
    );
    let mut claim = s.components[0].clone();
    claim.subject = other.slice;
    claim.component = id("llama.cpp");
    s.components.push(claim);
    assert_rejected(
        &s,
        known_hash(NO_ROW),
        "a KnownHash on another artifact's row",
    );
}

#[test]
fn a_known_hash_says_what_its_row_says() {
    let mut s = complete_pass();
    if let IdentityAssertion::KnownHash { matched, .. } = known(&mut s) {
        *matched = false;
    }
    assert_rejected(&s, known_hash(DISAGREES), "unmatched on a matching row");
    let mut s = complete_pass();
    s.reference_matches[0].result = MemberResult::File {
        expected: id(&hex(0x12)),
        observed: id(&hex(0x11)),
    };
    assert_rejected(&s, known_hash(DISAGREES), "matched on a differing row");
}

/// A symlink placement is not followed, so it holds no content (PR-4c-1 spec §4 note): its row is
/// not a row of the claim's artifact, even when the link names the claim's file. The engine
/// takes `KnownHash`es from the rows of the placements that hold the content only.
#[test]
fn a_known_hash_never_rests_on_a_symlink_row() {
    let mut s = complete_pass();
    let g = placed(&s, GGML);
    let link: InstanceId = id("inst:lib/ollama/libggml.so.0");
    let mut placement = instance(
        &link,
        "install",
        "/usr/local/lib/ollama/libggml.so.0",
        &g.artifact,
        1003,
    );
    placement.link_chain = vec![LinkHop {
        path: t("/usr/local/lib/ollama/libggml.so.0"),
        target: t("libggml.so.0.13.1"),
        uid: 0,
        mode: 0o120777,
    }];
    placement.resolved = Some(t("libggml.so.0.13.1"));
    placement.content = InstanceContent::NotRead {
        why: NotReadReason::NotFollowed,
    };
    s.instances.push(placement);
    s.reference_matches.push(ReferenceMatch {
        reference: id("ollama-official"),
        release: "v0.30.6".to_string(),
        member: "lib/ollama/libggml.so.0".to_string(),
        instance: Some(link),
        result: MemberResult::Symlink {
            expected: t("libggml.so.0.13.1"),
            observed: t("libggml.so.0.13.1"),
        },
    });
    // The link and its matching row are valid on their own.
    assert_valid(&s);
    if let IdentityAssertion::KnownHash { member, .. } = known(&mut s) {
        *member = "lib/ollama/libggml.so.0".to_string();
    }
    assert_rejected(&s, known_hash(NO_ROW), "a KnownHash on a symlink's row");
}
