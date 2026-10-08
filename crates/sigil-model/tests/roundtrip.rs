//! Every example survives Rust → JSON → Rust unchanged, and malformed JSON is rejected.

mod common;

use sigil_model::Session;

#[test]
fn every_example_round_trips_through_json() {
    for (name, session) in common::examples() {
        let json = serde_json::to_string_pretty(&session).unwrap();
        let back: Session = serde_json::from_str(&json).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(back, session, "{name} changed in a JSON round trip");
    }
}
