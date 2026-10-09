//! `collect::install` (PR-4a): placements, artifacts, and `artifacts.discovery`, on synthetic
//! install trees. No test reads a real installation.

use std::os::unix::fs::symlink;
use std::path::Path;

use sha2::{Digest, Sha256};
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

/// `PREFIX/private/credentials.txt`: inside the install, outside both places. Nothing may read it.
const SECRET: &[u8] = b"credentials outside bin/ollama and lib/ollama";

fn with_private(d: &TempDir) {
    std::fs::create_dir_all(d.path().join("private")).unwrap();
    std::fs::write(d.path().join("private/credentials.txt"), SECRET).unwrap();
}

/// Nothing was read under `private/`: no placement there, and no artifact with its bytes.
fn private_untouched(f: &InstallFacts) {
    let secret = format!("sha256:{:x}", Sha256::digest(SECRET));
    assert!(f.artifacts.iter().all(|a| a.id.as_str() != secret));
    assert!(f
        .instances
        .iter()
        .all(|i| !member(f, i).starts_with("private")));
}

#[test]
fn links_are_their_target_text_and_never_followed() {
    let d = install();
    with_private(&d);
    let models = TempDir::new().unwrap();
    std::fs::write(models.path().join("blob"), b"x").unwrap();
    let lib = d.path().join("lib/ollama");
    // The review's path B: a link inside the install, to a file outside both places.
    symlink("../../private/credentials.txt", lib.join("unexpected.so")).unwrap();
    symlink("missing.so", lib.join("dangling.so")).unwrap();
    symlink("cuda_v12", lib.join("cuda")).unwrap();
    symlink(models.path().join("blob"), lib.join("libout.so")).unwrap();
    let f = run(d.path(), InstallBudgets::default());
    for (path, target) in [
        ("lib/ollama/unexpected.so", "../../private/credentials.txt"),
        ("lib/ollama/dangling.so", "missing.so"),
        ("lib/ollama/cuda", "cuda_v12"),
        ("lib/ollama/libggml.so.0", "libggml.so.0.13.1"),
    ] {
        let i = find(&f, path);
        assert_eq!(i.entry_kind(), EntryKind::Symlink, "{path}");
        assert_eq!(i.link_chain.len(), 1, "{path}");
        assert_eq!(i.link_chain[0].target.as_str(), Some(target), "{path}");
        assert_eq!(
            i.content,
            InstanceContent::NotRead {
                why: NotReadReason::NotFollowed
            },
            "{path}"
        );
        // Not followed: `resolved` is the target text itself.
        assert_eq!(
            i.resolved.as_ref().and_then(|r| r.as_str()),
            Some(target),
            "{path}"
        );
    }
    let out = find(&f, "lib/ollama/libout.so");
    assert_eq!(out.content, find(&f, "lib/ollama/cuda").content);
    // A link to a directory is not entered.
    assert!(f
        .instances
        .iter()
        .all(|i| !member(&f, i).starts_with("lib/ollama/cuda/")));
    private_untouched(&f);
    // A link is observed in full by its target text: not a gap.
    assert!(
        matches!(f.discovery.state, CoverageState::Complete),
        "{:?}",
        f.discovery.state
    );
}

#[test]
fn a_symlink_at_or_on_the_way_to_a_place_is_not_followed() {
    // The review's path A: `lib/ollama` itself is a link to a directory outside both places.
    let d = install();
    with_private(&d);
    std::fs::remove_dir_all(d.path().join("lib/ollama")).unwrap();
    symlink("../private", d.path().join("lib/ollama")).unwrap();
    let f = run(d.path(), InstallBudgets::default());
    private_untouched(&f);
    assert!(
        matches!(&f.discovery.state, CoverageState::Partial { missing } if missing.iter().any(|m| m == "lib/ollama: a symlink, not followed")),
        "{:?}",
        f.discovery.state
    );

    // A link on the way: `lib` and `bin` are links.
    let d = install();
    with_private(&d);
    std::fs::create_dir_all(d.path().join("private/ollama")).unwrap();
    std::fs::write(d.path().join("private/ollama/libx.so"), SECRET).unwrap();
    std::fs::write(d.path().join("private/ollama-bin"), SECRET).unwrap();
    std::fs::remove_dir_all(d.path().join("lib")).unwrap();
    std::fs::remove_dir_all(d.path().join("bin")).unwrap();
    symlink("private", d.path().join("lib")).unwrap();
    symlink("private", d.path().join("bin")).unwrap();
    let f = run(d.path(), InstallBudgets::default());
    private_untouched(&f);
    assert!(f.instances.is_empty(), "{:?}", f.instances);
    let CoverageState::Partial { missing } = &f.discovery.state else {
        panic!("{:?}", f.discovery.state);
    };
    assert_eq!(
        missing,
        &[
            "bin: a symlink, not followed",
            "lib: a symlink, not followed"
        ]
    );

    // `bin/ollama` itself a link: a symlink placement, its target not read.
    let d = install();
    with_private(&d);
    std::fs::remove_file(d.path().join("bin/ollama")).unwrap();
    symlink("../private/credentials.txt", d.path().join("bin/ollama")).unwrap();
    let f = run(d.path(), InstallBudgets::default());
    private_untouched(&f);
    assert_eq!(find(&f, "bin/ollama").entry_kind(), EntryKind::Symlink);
}

#[test]
fn bin_ollama_counts_against_the_file_budget() {
    // One entry under lib/ollama and bin/ollama: two entries, over a budget of one.
    let d = TempDir::new().unwrap();
    std::fs::create_dir_all(d.path().join("bin")).unwrap();
    std::fs::create_dir_all(d.path().join("lib/ollama")).unwrap();
    std::fs::write(d.path().join("bin/ollama"), elf(2)).unwrap();
    std::fs::write(d.path().join("lib/ollama/libggml.so"), elf(3)).unwrap();
    let budget = |files| InstallBudgets {
        files,
        ..InstallBudgets::default()
    };
    let f = run(d.path(), budget(1));
    assert!(
        matches!(&f.discovery.state, CoverageState::BudgetExceeded { budget, .. } if budget == "install_files_discovered"),
        "{:?}",
        f.discovery.state
    );
    assert_eq!(f.instances.len(), 1);
    let f = run(d.path(), budget(2));
    assert!(
        matches!(f.discovery.state, CoverageState::Complete),
        "{:?}",
        f.discovery.state
    );
    let f = run(d.path(), budget(0));
    assert!(f.instances.is_empty());
    assert!(matches!(
        f.discovery.state,
        CoverageState::BudgetExceeded { .. }
    ));
}

#[test]
fn a_symlink_keeps_its_kind_and_text_when_the_byte_budget_is_spent() {
    let d = install();
    let f = run(
        d.path(),
        InstallBudgets {
            bytes: 0,
            ..InstallBudgets::default()
        },
    );
    let link = find(&f, "lib/ollama/libggml.so.0");
    assert_eq!(link.entry_kind(), EntryKind::Symlink);
    assert_eq!(
        link.link_chain[0].target.as_str(),
        Some("libggml.so.0.13.1")
    );
    assert_eq!(
        find(&f, "bin/ollama").content,
        InstanceContent::NotRead {
            why: NotReadReason::BudgetExceeded
        }
    );
}

#[test]
fn install_bytes_is_cumulative() {
    let d = install();
    std::fs::write(d.path().join("lib/ollama/big1"), vec![1u8; 100]).unwrap();
    std::fs::write(d.path().join("lib/ollama/big2"), vec![2u8; 100]).unwrap();
    // Every read: bin/ollama 64, cudart 7, big1 100, big2 100, and libggml 64 = 335 (the link is
    // not read). Each file fits within 300; all of them together do not.
    let f = run(
        d.path(),
        InstallBudgets {
            bytes: 300,
            ..InstallBudgets::default()
        },
    );
    assert!(
        matches!(&f.discovery.state, CoverageState::BudgetExceeded { budget, .. } if budget == "install_bytes"),
        "{:?}",
        f.discovery.state
    );
    assert!(f.bytes_read <= 300);
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

// --- container facts (PR-4b-1) -------------------------------------------------------------

fn common_fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

#[test]
fn elf_placements_get_their_facts_once_per_content() {
    let d = install();
    let so = common_fixture("elf/libdata.so");
    std::fs::write(d.path().join("lib/ollama/libdata.so.1"), &so).unwrap();
    std::fs::write(d.path().join("lib/ollama/cuda_v12/libdata-copy.so"), &so).unwrap();
    let f = run(d.path(), InstallBudgets::default());
    let parsed: Vec<_> = f
        .binaries
        .iter()
        .filter(|b| {
            let sigil_model::ContainerFacts::Elf(e) = &b.container;
            e.soname.as_ref().and_then(|s| s.as_str()) == Some("libdata.so.1")
        })
        .collect();
    assert_eq!(parsed.len(), 1, "one record for one content");
    assert!(parsed[0].gaps.is_empty(), "{:?}", parsed[0].gaps);
    // The synthetic 64-byte ELF headers of install() are parsed too, with gaps.
    assert!(f.binaries.iter().any(|b| !b.gaps.is_empty()));
    // Non-ELF content gets no record.
    assert_eq!(f.binaries.len(), 3, "bin/ollama, libggml, libdata");
}
