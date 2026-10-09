//! The embedded reference set `ollama-official` (PR-4a).

use sigil_engine::reference::{official, parse_set, RefMember};

#[test]
fn the_official_set_has_three_releases_of_34_files_17_symlinks_3_directories() {
    let set = official().unwrap();
    assert_eq!(set.id.as_str(), "ollama-official");
    let tags: Vec<&str> = set.releases.iter().map(|r| r.tag.as_str()).collect();
    assert_eq!(tags, ["v0.30.5", "v0.30.6", "v0.30.7"]);
    for r in &set.releases {
        let count = |f: fn(&RefMember) -> bool| r.members.values().filter(|m| f(m)).count();
        assert_eq!(
            count(|m| matches!(m, RefMember::File { .. })),
            34,
            "{}",
            r.tag
        );
        assert_eq!(
            count(|m| matches!(m, RefMember::Symlink { .. })),
            17,
            "{}",
            r.tag
        );
        assert_eq!(count(|m| matches!(m, RefMember::Directory)), 3, "{}", r.tag);
        assert!(r.members.contains_key("bin/ollama"));
    }
}

#[test]
fn the_set_sha256_is_pinned() {
    // Any change to an embedded manifest changes this value; update it only with the manifests.
    assert_eq!(official().unwrap().sha256.as_str(), PINNED);
}

const PINNED: &str = "3fc42fb3071be36c15867b7e5a337787c5091c1a7ba91f4c461624c9d5b2690c";

#[test]
fn the_knowledge_entry_names_the_set() {
    let set = official().unwrap();
    let k = set.knowledge();
    assert_eq!(k.id, "ollama-official");
    assert_eq!(k.version, "2026-10-07");
    assert_eq!(k.sha256, set.sha256);
}

#[test]
fn malformed_manifests_are_rejected() {
    let bad = r#"{"tag":"v1","entries":[{"name":"x","type":"9","mode":"0o644"}]}"#;
    assert!(parse_set("t", "1", &[("a.json", bad)]).is_err());
    let abs = r#"{"tag":"v1","entries":[{"name":"/x","type":"5","mode":"0o755"}]}"#;
    assert!(parse_set("t", "1", &[("a.json", abs)]).is_err());
    let dots = r#"{"tag":"v1","entries":[{"name":"lib/../x","type":"5","mode":"0o755"}]}"#;
    assert!(parse_set("t", "1", &[("a.json", dots)]).is_err());
    let no_hash = r#"{"tag":"v1","entries":[{"name":"x","type":"0","mode":"0o644","size":1}]}"#;
    assert!(parse_set("t", "1", &[("a.json", no_hash)]).is_err());
    let twice = r#"{"tag":"v1","entries":[{"name":"x","type":"5","mode":"0o755"},{"name":"x/","type":"5","mode":"0o755"}]}"#;
    assert!(parse_set("t", "1", &[("a.json", twice)]).is_err());
}
