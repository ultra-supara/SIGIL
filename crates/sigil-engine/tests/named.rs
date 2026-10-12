//! The inputs of `sigil binary inspect` (PR-4b-2a spec §4.1): resolved once, read one at a time
//! without following anything, fatal unless read or over `binary_bytes`.

use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use sigil_engine::collect::named::{collect, NamedBudgets};
use sigil_model::{DiscoverySource, Format, InstanceContent, NotReadReason};
use tempfile::TempDir;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/elf")
            .join(name),
    )
    .unwrap()
}

fn dir() -> (TempDir, PathBuf) {
    let d = TempDir::new().unwrap();
    let p = std::fs::canonicalize(d.path()).unwrap();
    (d, p)
}

#[test]
fn an_input_is_its_own_root_at_its_canonical_path() {
    let (_d, p) = dir();
    std::fs::write(p.join("libdata.so"), fixture("libdata.so")).unwrap();
    symlink("libdata.so", p.join("link.so")).unwrap();
    let f = collect(&[p.join("link.so")], NamedBudgets::default()).unwrap();
    assert_eq!(f.roots.len(), 1);
    assert_eq!(f.roots[0].id.as_str(), "binary-1");
    let canonical = p.join("libdata.so");
    assert_eq!(
        f.roots[0].path.as_bytes(),
        canonical.as_os_str().as_encoded_bytes()
    );
    let i = &f.instances[0];
    assert_eq!(i.id.as_str(), "inst:binary-1/libdata.so");
    assert_eq!(i.root.as_str(), "binary-1");
    assert_eq!(i.path, f.roots[0].path);
    assert_eq!(i.discovered_by, [DiscoverySource::Argument]);
    assert!(matches!(f.artifacts[0].format, Format::Elf { .. }));
    assert_eq!(f.binaries.len(), 1);
}

#[test]
fn one_file_named_twice_is_one_input_and_one_content_is_parsed_once() {
    let (_d, p) = dir();
    std::fs::write(p.join("a.so"), fixture("libdata.so")).unwrap();
    std::fs::write(p.join("b.so"), fixture("libdata.so")).unwrap();
    symlink("a.so", p.join("alias.so")).unwrap();
    let f = collect(
        &[p.join("a.so"), p.join("alias.so"), p.join("b.so")],
        NamedBudgets::default(),
    )
    .unwrap();
    let roots: Vec<&str> = f.roots.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(roots, ["binary-1", "binary-2"], "a.so and b.so");
    assert_eq!(f.artifacts.len(), 1);
    assert_eq!(f.binaries.len(), 1);
}

#[test]
fn inputs_that_cannot_be_read_are_fatal() {
    let (_d, p) = dir();
    std::fs::create_dir(p.join("dir")).unwrap();
    let fifo = p.join("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    for (path, why) in [
        (p.join("missing"), "not found"),
        (p.join("dir"), "a directory"),
        (fifo, "not a regular file"),
    ] {
        let e = collect(std::slice::from_ref(&path), NamedBudgets::default()).unwrap_err();
        assert!(e.contains(why), "{}: {e}", path.display());
    }
}

#[test]
fn a_file_that_lstat_sees_and_open_refuses_is_fatal() {
    if rustix::process::geteuid().is_root() {
        eprintln!("skipped: root opens a mode-000 file");
        return;
    }
    let (_d, p) = dir();
    let f = p.join("locked.so");
    std::fs::write(&f, b"x").unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();
    let e = collect(&[f], NamedBudgets::default()).unwrap_err();
    assert!(e.contains("permission denied"), "{e}");
}

#[test]
fn an_input_over_binary_bytes_is_recorded_and_later_inputs_are_read() {
    let (_d, p) = dir();
    std::fs::write(p.join("big.so"), fixture("libdata.so")).unwrap();
    std::fs::write(p.join("small.txt"), b"tiny").unwrap();
    let budgets = NamedBudgets {
        bytes: 100,
        ..NamedBudgets::default()
    };
    let f = collect(&[p.join("big.so"), p.join("small.txt")], budgets).unwrap();
    assert_eq!(
        f.instances[0].content,
        InstanceContent::NotRead {
            why: NotReadReason::BudgetExceeded
        }
    );
    assert_eq!(f.over.get(&f.instances[0].id), Some(&0));
    assert!(matches!(
        f.instances[1].content,
        InstanceContent::Read { .. }
    ));
    assert_eq!(f.bytes_read, 4);
}

#[test]
fn a_text_file_is_read_and_not_parsed() {
    let (_d, p) = dir();
    std::fs::write(p.join("NOTES.txt"), b"hello").unwrap();
    let f = collect(&[p.join("NOTES.txt")], NamedBudgets::default()).unwrap();
    assert_eq!(f.artifacts[0].format, Format::Other);
    assert!(f.binaries.is_empty());
}

// --- Review of Part B ------------------------------------------------------------------------

#[test]
fn the_bytes_hashed_before_an_input_over_the_budget_are_its_used() {
    let (_d, p) = dir();
    std::fs::write(p.join("small.txt"), b"tiny").unwrap();
    std::fs::write(p.join("big.so"), fixture("libdata.so")).unwrap();
    let budgets = NamedBudgets {
        bytes: 100,
        ..NamedBudgets::default()
    };
    let f = collect(&[p.join("small.txt"), p.join("big.so")], budgets).unwrap();
    assert_eq!(f.over.get(&f.instances[1].id), Some(&4));
}

#[test]
fn no_input_is_an_input_error() {
    let e = collect(&[], NamedBudgets::default()).unwrap_err();
    assert!(e.contains("no input"), "{e}");
}

#[test]
fn a_file_name_that_is_not_utf8_is_fatal() {
    use std::os::unix::ffi::OsStrExt;
    let (_d, p) = dir();
    let name = std::ffi::OsStr::from_bytes(b"\xff.so");
    std::fs::write(p.join(name), b"x").unwrap();
    let e = collect(&[p.join(name)], NamedBudgets::default()).unwrap_err();
    assert!(e.contains("not UTF-8"), "{e}");
}

/// Review of Part B (code review P3-1): a directory that may be entered but not listed (0711)
/// still gives its readable files: inputs are opened relative to an `O_PATH` directory fd.
#[test]
fn a_file_in_a_directory_that_cannot_be_listed_is_read() {
    if rustix::process::geteuid().is_root() {
        eprintln!("skipped: root lists any directory");
        return;
    }
    let (_d, p) = dir();
    let inner = p.join("inner");
    std::fs::create_dir(&inner).unwrap();
    std::fs::write(inner.join("a.so"), fixture("libdata.so")).unwrap();
    std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o311)).unwrap();
    let f = collect(&[inner.join("a.so")], NamedBudgets::default());
    std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o755)).unwrap();
    let f = f.unwrap();
    assert_eq!(f.binaries.len(), 1);
}
