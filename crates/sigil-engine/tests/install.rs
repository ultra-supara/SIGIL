//! `collect::install` (PR-4a): placements, artifacts, and `artifacts.discovery`, on synthetic
//! install trees. No test reads a real installation.

use std::os::unix::fs::symlink;
use std::path::Path;

use sigil_engine::collect::install::{collect, InstallBudgets, InstallFacts};
use sigil_model::{CoverageState, EntryKind, FileInstance, Format, InstanceContent, NotReadReason};
use tempfile::TempDir;

/// `bin/ollama` (an x86_64 ELF exec) and `lib/ollama/` with a library, a symlink to it, and a
/// subdirectory with one non-ELF file. `bin/other-tool` must never be read.
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
    std::fs::write(p.join("bin/other-tool"), b"must not be read").unwrap();
    d
}

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

fn run(dir: &Path, budgets: InstallBudgets) -> InstallFacts {
    collect(dir, budgets).unwrap()
}

/// A placement's path under the root, as text.
fn member(f: &InstallFacts, i: &FileInstance) -> String {
    let root = f.root_path.as_str().unwrap();
    i.path
        .as_str()
        .unwrap()
        .strip_prefix(&format!("{root}/"))
        .unwrap()
        .to_string()
}

fn find<'a>(f: &'a InstallFacts, path: &str) -> &'a FileInstance {
    f.instances
        .iter()
        .find(|i| member(f, i) == path)
        .unwrap_or_else(|| panic!("no placement {path}"))
}

#[test]
fn bin_ollama_and_every_entry_under_lib_ollama_are_placements() {
    let d = install();
    let f = run(d.path(), InstallBudgets::default());
    let mut shown: Vec<(String, EntryKind)> = f
        .instances
        .iter()
        .map(|i| (member(&f, i), i.entry_kind()))
        .collect();
    shown.sort();
    assert_eq!(
        shown,
        [
            ("bin/ollama".into(), EntryKind::File),
            ("lib/ollama/cuda_v12".into(), EntryKind::Directory),
            (
                "lib/ollama/cuda_v12/libcudart.so.12.8.90".into(),
                EntryKind::File
            ),
            ("lib/ollama/libggml.so.0".into(), EntryKind::Symlink),
            ("lib/ollama/libggml.so.0.13.1".into(), EntryKind::File),
        ]
    );
    assert!(f
        .instances
        .iter()
        .all(|i| i.id.as_str().starts_with("inst:install/")));
    assert!(
        matches!(f.discovery.state, CoverageState::Complete),
        "{:?}",
        f.discovery.state
    );
    let elfs = f
        .artifacts
        .iter()
        .filter(|a| matches!(a.format, Format::Elf { .. }))
        .count();
    assert_eq!(elfs, 2);
    assert!(f
        .artifacts
        .iter()
        .all(|a| matches!(a.format, Format::Elf { .. }) == (a.slices.len() == 1)));
}

#[test]
fn a_dangling_link_keeps_its_target_text_and_opens_discovery() {
    let d = install();
    symlink("missing.so", d.path().join("lib/ollama/dangling.so")).unwrap();
    let f = run(d.path(), InstallBudgets::default());
    let i = find(&f, "lib/ollama/dangling.so");
    assert_eq!(i.link_chain[0].target.as_str(), Some("missing.so"));
    assert_eq!(
        i.content,
        InstanceContent::NotRead {
            why: NotReadReason::Dangling
        }
    );
    assert!(
        matches!(&f.discovery.state, CoverageState::Partial { missing } if missing.iter().any(|m| m.contains("dangling.so"))),
        "{:?}",
        f.discovery.state
    );
}

#[test]
fn a_link_to_a_directory_is_recorded_not_entered_and_is_not_a_gap() {
    let d = install();
    symlink("cuda_v12", d.path().join("lib/ollama/cuda")).unwrap();
    let f = run(d.path(), InstallBudgets::default());
    let i = find(&f, "lib/ollama/cuda");
    assert_eq!(
        i.content,
        InstanceContent::NotRead {
            why: NotReadReason::LinkToDirectory
        }
    );
    assert!(f
        .instances
        .iter()
        .all(|i| !member(&f, i).starts_with("lib/ollama/cuda/")));
    assert!(
        matches!(f.discovery.state, CoverageState::Complete),
        "{:?}",
        f.discovery.state
    );
}

#[test]
fn a_link_out_of_the_install_root_is_not_read() {
    let d = install();
    let models = TempDir::new().unwrap();
    std::fs::write(models.path().join("blob"), b"x").unwrap();
    symlink(
        models.path().join("blob"),
        d.path().join("lib/ollama/libout.so"),
    )
    .unwrap();
    let f = run(d.path(), InstallBudgets::default());
    let i = find(&f, "lib/ollama/libout.so");
    assert_eq!(
        i.content,
        InstanceContent::NotRead {
            why: NotReadReason::OutsideScanRoots
        }
    );
    assert!(matches!(f.discovery.state, CoverageState::Partial { .. }));
}

#[test]
fn install_bytes_is_cumulative() {
    let d = install();
    std::fs::write(d.path().join("lib/ollama/big1"), vec![1u8; 100]).unwrap();
    std::fs::write(d.path().join("lib/ollama/big2"), vec![2u8; 100]).unwrap();
    // Every read: bin/ollama 64, cudart 7, big1 100, big2 100, libggml 64, and the link's target
    // (libggml again) 64 = 399. Each file fits within 349; all of them together do not.
    let f = run(
        d.path(),
        InstallBudgets {
            bytes: 349,
            ..InstallBudgets::default()
        },
    );
    assert!(
        matches!(&f.discovery.state, CoverageState::BudgetExceeded { budget, .. } if budget == "install_bytes"),
        "{:?}",
        f.discovery.state
    );
    assert!(f.bytes_read <= 349);
    let unread = f
        .instances
        .iter()
        .filter(|i| {
            i.content
                == InstanceContent::NotRead {
                    why: NotReadReason::BudgetExceeded,
                }
        })
        .count();
    assert!(unread >= 1);
}

#[test]
fn a_missing_install_or_place_is_recorded() {
    let none = run(
        Path::new("/nonexistent/sigil-install"),
        InstallBudgets::default(),
    );
    assert!(matches!(
        none.discovery.state,
        CoverageState::Unavailable { .. }
    ));
    let d = install();
    std::fs::remove_file(d.path().join("bin/ollama")).unwrap();
    let f = run(d.path(), InstallBudgets::default());
    assert!(
        matches!(&f.discovery.state, CoverageState::Partial { missing } if missing.iter().any(|m| m == "bin/ollama: not found")),
        "{:?}",
        f.discovery.state
    );
    let empty = TempDir::new().unwrap();
    let f = run(empty.path(), InstallBudgets::default());
    assert!(matches!(
        f.discovery.state,
        CoverageState::Unavailable { .. }
    ));
}

#[test]
fn a_fifo_is_a_special_placement_and_a_gap() {
    let d = install();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        d.path().join("lib/ollama/fifo"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    let f = run(d.path(), InstallBudgets::default());
    assert_eq!(find(&f, "lib/ollama/fifo").entry_kind(), EntryKind::Special);
    assert!(matches!(f.discovery.state, CoverageState::Partial { .. }));
}

#[test]
fn a_budget_on_entries_is_recorded() {
    let d = install();
    let f = run(
        d.path(),
        InstallBudgets {
            files: 2,
            ..InstallBudgets::default()
        },
    );
    assert!(
        matches!(&f.discovery.state, CoverageState::BudgetExceeded { budget, .. } if budget == "install_files_discovered"),
        "{:?}",
        f.discovery.state
    );
}

#[test]
fn the_same_tree_gives_the_same_facts() {
    let d = install();
    let a = run(d.path(), InstallBudgets::default());
    let b = run(d.path(), InstallBudgets::default());
    assert_eq!(a.instances, b.instances);
    assert_eq!(a.artifacts, b.artifacts);
}
