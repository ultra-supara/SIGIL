//! The embedded reference set `ollama-official` (PR-4a), and its commit data (PR-4c-2c).

use sigil_engine::analyze::components::{components, Role};
use sigil_engine::reference::{official, parse_set, RefCommit, RefMember};

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
    // Any change to an embedded file changes this value; update it only with the files.
    assert_eq!(official().unwrap().sha256.as_str(), PINNED);
}

const PINNED: &str = "a0338548f18923f59acf33064967f512b92ac9b872bb848424fda5665dc080de";

#[test]
fn the_knowledge_entry_names_the_set() {
    let set = official().unwrap();
    let k = set.knowledge();
    assert_eq!(k.id, "ollama-official");
    assert_eq!(k.version, "2026-10-24");
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

#[test]
fn every_release_reports_llama_commit_and_ggml_commit() {
    let commit = |field: &str, member: &str| RefCommit {
        field: field.to_string(),
        member: member.to_string(),
        value: "6f3a9f3de".to_string(),
    };
    for r in &official().unwrap().releases {
        assert_eq!(
            r.commits,
            [
                commit("LLAMA_COMMIT", "lib/ollama/libllama-common.so.0.0.1"),
                commit("ggml_commit", "lib/ollama/libggml-base.so.0.13.1"),
            ],
            "{}",
            r.tag
        );
    }
}

#[test]
fn every_commit_field_is_a_commit_field_of_the_component_database() {
    let db = components().unwrap();
    for r in &official().unwrap().releases {
        for c in &r.commits {
            assert_eq!(
                db.field(&c.field).map(|f| f.role),
                Some(Role::Commit),
                "{} {}",
                r.tag,
                c.field
            );
        }
    }
}

#[test]
fn malformed_commit_data_is_rejected() {
    let manifest = r#"{"tag":"v1","entries":[{"name":"lib","type":"5","mode":"0o755"},
        {"name":"lib/a.so","type":"0","mode":"0o644","size":1,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}"#;
    let set =
        |commits: &str| parse_set("t", "1", &[("a.json", manifest), ("commits.toml", commits)]);
    let entry = |tag: &str, field: &str, member: &str, value: &str| {
        format!("[[release]]\ntag = \"{tag}\"\ncommits = [{{ field = \"{field}\", member = \"{member}\", value = \"{value}\" }}]\n")
    };
    let good = entry("v1", "F", "lib/a.so", "6f3a9f3");
    assert_eq!(set(&good).unwrap().releases[0].commits.len(), 1);
    let twice = "[[release]]\ntag = \"v1\"\ncommits = [\
        { field = \"F\", member = \"lib/a.so\", value = \"6f3a9f3\" },\
        { field = \"F\", member = \"lib/a.so\", value = \"6f3a9f3\" }]\n";
    for (commits, why) in [
        (
            entry("v2", "F", "lib/a.so", "6f3a9f3"),
            "release v2 is not in the set",
        ),
        (format!("{good}{good}"), "release v1 is listed twice"),
        (
            "[[release]]\ntag = \"v1\"\ncommits = []\n".to_string(),
            "lists no commit",
        ),
        (entry("v1", "", "lib/a.so", "6f3a9f3"), "not ASCII graphic"),
        (
            entry("v1", "F G", "lib/a.so", "6f3a9f3"),
            "not ASCII graphic",
        ),
        (twice.to_string(), "the field is listed twice"),
        (
            entry("v1", "F", "lib", "6f3a9f3"),
            "lib is not a file of the release",
        ),
        (
            entry("v1", "F", "lib/b.so", "6f3a9f3"),
            "lib/b.so is not a file of the release",
        ),
        (
            entry("v1", "F", "lib/a.so", "6f3a9f"),
            "not 7 to 40 lowercase hex digits",
        ),
        (
            entry("v1", "F", "lib/a.so", "6F3A9F3"),
            "not 7 to 40 lowercase hex digits",
        ),
        (good.replace("value", "value2"), "unknown field"),
    ] {
        let error = set(&commits).unwrap_err();
        assert!(error.contains(why), "{why}: {error}");
    }
    let error = parse_set("t", "1", &[("a.json", manifest), ("notes.txt", "")]).unwrap_err();
    assert!(error.contains("neither a manifest"), "{error}");
}
