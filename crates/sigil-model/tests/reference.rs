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
        (NotReadReason::Dangling, "\"Dangling\""),
        (NotReadReason::LinkToDirectory, "\"LinkToDirectory\""),
        (NotReadReason::Directory, "\"Directory\""),
    ] {
        assert_eq!(serde_json::to_string(&reason).unwrap(), name);
    }
}
