//! `analyze::release` (PR-4a): rows, attribution, completeness, and the review's cases. Synthetic
//! trees and a test reference set only.

use std::os::unix::fs::symlink;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sigil_engine::analyze::release::{analyze, ReleaseResult};
use sigil_engine::collect::install::{collect, InstallBudgets};
use sigil_engine::reference::{parse_set, RefSet};
use sigil_model::{CoverageState, EntryKind, MemberKind, MemberResult};
use tempfile::TempDir;

fn elf(e_type: u16) -> Vec<u8> {
    let mut h = vec![0u8; 64];
    h[..4].copy_from_slice(b"\x7fELF");
    h[4] = 2;
    h[5] = 1;
    h[6] = 1;
    h[16..18].copy_from_slice(&e_type.to_le_bytes());
    h[18..20].copy_from_slice(&62u16.to_le_bytes());
    h
}

fn install() -> TempDir {
    let d = TempDir::new().unwrap();
    let p = d.path();
    std::fs::create_dir_all(p.join("bin")).unwrap();
    std::fs::create_dir_all(p.join("lib/ollama/cuda_v12")).unwrap();
    std::fs::write(p.join("bin/ollama"), elf(2)).unwrap();
    std::fs::write(p.join("lib/ollama/libggml.so.0.13.1"), elf(3)).unwrap();
    symlink("libggml.so.0.13.1", p.join("lib/ollama/libggml.so.0")).unwrap();
    std::fs::write(
        p.join("lib/ollama/cuda_v12/libcudart.so.12.8.90"),
        b"not elf",
    )
    .unwrap();
    d
}

fn hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// A manifest for release `tag` describing exactly `install()`'s tree, edited by `edit`.
fn manifest(tag: &str, edit: impl Fn(&mut Vec<Value>)) -> String {
    let mut entries = vec![
        json!({"name": "bin/ollama", "type": "0", "mode": "0o755", "sha256": hex(&elf(2)), "size": 64}),
        json!({"name": "lib/ollama/cuda_v12", "type": "5", "mode": "0o755"}),
        json!({"name": "lib/ollama/cuda_v12/libcudart.so.12.8.90", "type": "0", "mode": "0o644", "sha256": hex(b"not elf"), "size": 7}),
        json!({"name": "lib/ollama/libggml.so.0", "type": "2", "mode": "0o777", "link": "libggml.so.0.13.1"}),
        json!({"name": "lib/ollama/libggml.so.0.13.1", "type": "0", "mode": "0o644", "sha256": hex(&elf(3)), "size": 64}),
    ];
    edit(&mut entries);
    json!({"tag": tag, "entries": entries}).to_string()
}

fn set(manifests: &[(&str, String)]) -> RefSet {
    let files: Vec<(&str, &str)> = manifests.iter().map(|(n, t)| (*n, t.as_str())).collect();
    parse_set("ollama-official", "test", &files).unwrap()
}

fn run(d: &TempDir, refs: &RefSet) -> ReleaseResult {
    analyze(&collect(d.path(), InstallBudgets::default()).unwrap(), refs).unwrap()
}

fn reasons(r: &ReleaseResult) -> Vec<String> {
    match &r.coverage.state {
        CoverageState::Partial { missing } => missing.clone(),
        other => panic!("not Partial: {other:?}"),
    }
}

fn zero() -> Value {
    Value::from("0".repeat(64))
}

#[test]
fn an_install_matching_one_release_is_claimed_and_complete() {
    let d = install();
    let refs = set(&[
        ("a.json", manifest("vA", |_| {})),
        ("b.json", manifest("vB", |e| e[0]["sha256"] = zero())),
    ]);
    let r = run(&d, &refs);
    assert_eq!(r.claim.as_ref().unwrap().candidates, ["vA"]);
    assert!(
        matches!(r.coverage.state, CoverageState::Complete),
        "{:?}",
        r.coverage.state
    );
}

#[test]
fn identical_releases_are_both_candidates() {
    let d = install();
    let refs = set(&[
        ("a.json", manifest("vA", |_| {})),
        ("b.json", manifest("vB", |_| {})),
    ]);
    assert_eq!(run(&d, &refs).claim.unwrap().candidates, ["vA", "vB"]);
}

#[test]
fn a_library_replaced_by_non_elf_bytes_matches_no_reference() {
    let d = install();
    // The member's size, other bytes: only the SHA-256 tells them apart.
    std::fs::write(d.path().join("lib/ollama/libggml.so.0.13.1"), [b'x'; 64]).unwrap();
    let r = run(&d, &set(&[("a.json", manifest("vA", |_| {}))]));
    assert!(r.claim.is_none());
    assert!(
        reasons(&r)
            .iter()
            .any(|m| m == "lib/ollama/libggml.so.0.13.1: matches no reference"),
        "{:?}",
        reasons(&r)
    );
}

#[test]
fn an_empty_lib_keeps_the_attribution_and_is_incomplete() {
    let d = install();
    std::fs::remove_dir_all(d.path().join("lib/ollama")).unwrap();
    std::fs::create_dir_all(d.path().join("lib/ollama")).unwrap();
    let r = run(&d, &set(&[("a.json", manifest("vA", |_| {}))]));
    assert_eq!(r.claim.as_ref().unwrap().candidates, ["vA"]);
    let absent = r
        .rows
        .iter()
        .filter(|row| matches!(row.result, MemberResult::Absent { .. }))
        .count();
    assert_eq!(absent, 4);
    assert!(
        reasons(&r)
            .iter()
            .any(|m| m == "vA: 2 files, 1 symlinks, and 1 directories absent from the install"),
        "{:?}",
        reasons(&r)
    );
}

#[test]
fn the_same_content_at_two_paths_gives_two_rows() {
    let d = install();
    std::fs::write(d.path().join("lib/ollama/copy.so"), elf(3)).unwrap();
    let refs = set(&[(
        "a.json",
        manifest("vA", |e| {
            e.push(json!({"name": "lib/ollama/copy.so", "type": "0", "mode": "0o644", "sha256": hex(&elf(3)), "size": 64}))
        }),
    )]);
    let r = run(&d, &refs);
    let ggml = hex(&elf(3));
    let files = r
        .rows
        .iter()
        .filter(|row| matches!(&row.result, MemberResult::File { observed, .. } if observed.as_str() == ggml))
        .count();
    assert_eq!(files, 2);
    assert!(r.claim.is_some());
}

#[test]
fn a_symlink_to_a_matching_file_is_compared_only_as_a_symlink() {
    let d = install();
    let r = run(&d, &set(&[("a.json", manifest("vA", |_| {}))]));
    let rows: Vec<_> = r
        .rows
        .iter()
        .filter(|row| row.member == "lib/ollama/libggml.so.0")
        .collect();
    assert_eq!(rows.len(), 1);
    assert!(matches!(rows[0].result, MemberResult::Symlink { .. }));
}

#[test]
fn a_retargeted_symlink_and_a_kind_difference_are_reported() {
    let refs = set(&[("a.json", manifest("vA", |_| {}))]);
    let d = install();
    std::fs::remove_file(d.path().join("lib/ollama/libggml.so.0")).unwrap();
    symlink(
        "cuda_v12/libcudart.so.12.8.90",
        d.path().join("lib/ollama/libggml.so.0"),
    )
    .unwrap();
    let r = run(&d, &refs);
    assert!(r.claim.is_none());
    assert!(
        reasons(&r)
            .iter()
            .any(|m| m
                .starts_with("lib/ollama/libggml.so.0: symlink to cuda_v12/libcudart.so.12.8.90")),
        "{:?}",
        reasons(&r)
    );
    let d = install();
    std::fs::remove_file(d.path().join("bin/ollama")).unwrap();
    std::fs::create_dir(d.path().join("bin/ollama")).unwrap();
    let r = run(&d, &refs);
    let row = r
        .rows
        .iter()
        .find(|row| row.member == "bin/ollama")
        .unwrap();
    assert_eq!(
        row.result,
        MemberResult::KindDiffers {
            expected: MemberKind::File,
            observed: EntryKind::Directory
        }
    );
}

#[test]
fn mixed_and_unknown_installs_have_no_claim() {
    let d = install();
    let refs = set(&[
        ("a.json", manifest("vA", |e| e[4]["sha256"] = zero())),
        ("b.json", manifest("vB", |e| e[0]["sha256"] = zero())),
    ]);
    let r = run(&d, &refs);
    assert!(r.claim.is_none());
    assert!(
        reasons(&r)
            .iter()
            .any(|m| m.starts_with("mixed install: no release matches every placement")),
        "{:?}",
        reasons(&r)
    );
    std::fs::write(d.path().join("lib/ollama/libggml-cpu-foo.so"), b"x").unwrap();
    let r = run(&d, &set(&[("a.json", manifest("vA", |_| {}))]));
    assert!(r.claim.is_none());
    assert!(
        reasons(&r)
            .iter()
            .any(|m| m == "lib/ollama/libggml-cpu-foo.so: not in any reference"),
        "{:?}",
        reasons(&r)
    );
}

#[test]
fn a_budget_stopped_walk_records_no_absent_member() {
    let d = install();
    let refs = set(&[("a.json", manifest("vA", |_| {}))]);
    let facts = collect(
        d.path(),
        InstallBudgets {
            files: 2,
            ..InstallBudgets::default()
        },
    )
    .unwrap();
    let r = analyze(&facts, &refs).unwrap();
    assert!(r
        .rows
        .iter()
        .all(|row| !matches!(row.result, MemberResult::Absent { .. })));
    assert!(r.claim.is_none());
    assert!(matches!(
        r.coverage.state,
        CoverageState::BudgetExceeded { .. }
    ));
}
