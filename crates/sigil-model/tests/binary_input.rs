//! A binary inspection's inputs (PR-4b-2a spec §5): `binary-<n>` roots, the state each input
//! implies (`expected_binary_container`), and B9/B10.

mod common;

use common::*;
use sigil_model::*;

#[test]
fn binary_roots_are_numbered_from_one_without_leading_zeros() {
    assert_eq!(binary_root(1).unwrap().as_str(), "binary-1");
    assert_eq!(binary_root(0), None, "binary-0 is not a binary root");
    for (text, n) in [("binary-1", Some(1)), ("binary-10", Some(10))] {
        assert_eq!(binary_root_index(&id(text)), n, "{text}");
        assert!(is_binary_root(&id(text)));
    }
    for text in [
        "binary-0",
        "binary-01",
        "binary-",
        "binary-x",
        "install",
        "models",
    ] {
        assert_eq!(binary_root_index(&id(text)), None, "{text}");
        assert!(!is_binary_root(&id(text)));
    }
}

#[test]
fn argument_is_serialized_as_its_name() {
    assert_eq!(
        serde_json::to_string(&DiscoverySource::Argument).unwrap(),
        "\"Argument\""
    );
}
