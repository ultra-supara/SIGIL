//! Sessions written before PR #76 (`tests/fixtures/pre-pr76/`, real output of the PR #75 CLI)
//! still load: `request.active` and `probes` are missing there and read as empty. A session
//! SIGIL writes always has both.

use std::fs;
use std::path::PathBuf;

use serde_json::{json, Value};
use sigil_model::Session;

const FIXTURES: &[&str] = &["pass-complete.json", "warn.json", "incomplete.json"];

fn fixture(name: &str) -> (String, Value) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/pre-pr76")
        .join(name);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let value = serde_json::from_str(&text).unwrap();
    (text, value)
}

fn session_validator() -> jsonschema::Validator {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas/session-v1.schema.json");
    let schema: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(&schema)
        .unwrap()
}

#[test]
fn the_fixtures_predate_the_probe_fields() {
    for name in FIXTURES {
        let (_, value) = fixture(name);
        assert_eq!(value["schema"], "sigil-session/1", "{name}");
        assert!(value["request"].get("active").is_none(), "{name}");
        assert!(value.get("probes").is_none(), "{name}");
    }
}

#[test]
fn a_session_written_before_pr76_validates_against_the_schema() {
    let validator = session_validator();
    for name in FIXTURES {
        let (_, value) = fixture(name);
        let errors: Vec<String> = validator
            .iter_errors(&value)
            .map(|e| e.to_string())
            .collect();
        assert!(errors.is_empty(), "{name}: {errors:#?}");
    }
}

#[test]
fn a_session_written_before_pr76_loads_with_nothing_active() {
    for name in FIXTURES {
        let (_, value) = fixture(name);
        let session: Session =
            serde_json::from_value(value).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(session.request.active.is_empty(), "{name}");
        assert!(session.probes.is_empty(), "{name}");
        if let Err(errors) = session.validate() {
            panic!("{name}: {errors:?}");
        }
    }
}

#[test]
fn written_again_it_gains_only_the_two_empty_lists() {
    for name in FIXTURES {
        let (text, old) = fixture(name);
        let session: Session = serde_json::from_str(&text).unwrap();
        let written: Value = serde_json::from_str(&session.to_canonical_json().unwrap()).unwrap();
        assert_eq!(written["request"]["active"], json!([]), "{name}");
        assert_eq!(written["probes"], json!([]), "{name}");
        let mut without = written.clone();
        without["request"].as_object_mut().unwrap().remove("active");
        without.as_object_mut().unwrap().remove("probes");
        assert_eq!(without, old, "{name}: anything else changed");
    }
}
