//! `SafeFs::walk_entries` and `entry_at` (PR-4a): every entry with its lstat, links recorded and
//! not followed, dangling links kept, directories entered.

use std::os::unix::fs::symlink;

use sigil_engine::collect::fs::{EntryType, FsBudgets, RelPath, SafeFs};
use sigil_model::RootId;
use tempfile::TempDir;

fn tree() -> TempDir {
    let d = TempDir::new().unwrap();
    let lib = d.path().join("lib/ollama");
    std::fs::create_dir_all(lib.join("cuda_v12")).unwrap();
    std::fs::write(lib.join("libggml.so.0.13.1"), b"\x7fELF").unwrap();
    symlink("libggml.so.0.13.1", lib.join("libggml.so.0")).unwrap();
    symlink("cuda_v12", lib.join("cuda")).unwrap();
    symlink("missing.so", lib.join("dangling.so")).unwrap();
    std::fs::write(lib.join("cuda_v12/libcudart.so.12.8.90"), b"x").unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        lib.join("fifo"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    d
}

fn fs_for(d: &TempDir, budgets: FsBudgets) -> (SafeFs, RootId) {
    let mut fs = SafeFs::new(budgets);
    let root = RootId::new("install").unwrap();
    fs.add_root(root.clone(), d.path()).unwrap();
    (fs, root)
}

fn shown(kind: &EntryType) -> String {
    match kind {
        EntryType::File => "file".to_string(),
        EntryType::Directory => "dir".to_string(),
        EntryType::Symlink { target } => format!("link->{target}"),
        EntryType::Special => "special".to_string(),
        EntryType::Vanished => "vanished".to_string(),
    }
}

#[test]
fn every_entry_is_listed_with_its_kind_and_links_are_not_followed() {
    let d = tree();
    let (fs, root) = fs_for(&d, FsBudgets::default());
    let walk = fs
        .walk_entries(&root, &RelPath::parse("lib/ollama").unwrap())
        .unwrap();
    let listed: Vec<(String, String)> = walk
        .entries
        .iter()
        .map(|e| (e.rel.display(), shown(&e.kind)))
        .collect();
    let expected: Vec<(String, String)> = [
        ("lib/ollama/cuda", "link->cuda_v12"),
        ("lib/ollama/cuda_v12", "dir"),
        ("lib/ollama/cuda_v12/libcudart.so.12.8.90", "file"),
        ("lib/ollama/dangling.so", "link->missing.so"),
        ("lib/ollama/fifo", "special"),
        ("lib/ollama/libggml.so.0", "link->libggml.so.0.13.1"),
        ("lib/ollama/libggml.so.0.13.1", "file"),
    ]
    .iter()
    .map(|(p, k)| (p.to_string(), k.to_string()))
    .collect();
    assert_eq!(listed, expected);
    assert!(walk.entries.iter().all(|e| e.stat.is_some()));
    // Links are entries, never directories to open: nothing was skipped or left unlisted.
    assert!(walk.skipped.is_empty(), "{:?}", walk.skipped);
    assert!(walk.unscanned.is_empty(), "{:?}", walk.unscanned);
    // `walk` itself is unaffected: it still lists only files.
    assert!(walk.files.is_empty());
}

#[test]
fn every_entry_counts_against_the_file_budget() {
    let d = tree();
    let (fs, root) = fs_for(
        &d,
        FsBudgets {
            max_files: 3,
            ..FsBudgets::default()
        },
    );
    let walk = fs
        .walk_entries(&root, &RelPath::parse("lib/ollama").unwrap())
        .unwrap();
    assert!(walk.entries.len() <= 3, "{:?}", walk.entries.len());
    assert!(walk.exceeded.iter().any(|b| b.budget == "files_discovered"));
    assert!(!walk.unscanned.is_empty());
}

#[test]
fn entry_at_returns_one_entry_without_following_it() {
    let d = tree();
    let (fs, root) = fs_for(&d, FsBudgets::default());
    let e = fs
        .entry_at(&root, &RelPath::parse("lib/ollama/libggml.so.0").unwrap())
        .unwrap();
    assert_eq!(
        e.kind,
        EntryType::Symlink {
            target: "libggml.so.0.13.1".into()
        }
    );
    let file = fs
        .entry_at(
            &root,
            &RelPath::parse("lib/ollama/libggml.so.0.13.1").unwrap(),
        )
        .unwrap();
    assert_eq!(file.kind, EntryType::File);
    assert!(fs
        .entry_at(&root, &RelPath::parse("bin/ollama").unwrap())
        .is_none());
}
