//! Identification in a binary inspection (PR-4c-1 spec §7): fixtures F-I1 (a name and a SONAME
//! that disagree) and F-I3 (a stripped library with embedded values), one content at two
//! versioned names, and a policy that denies a component.

// Runs `strip` (binutils) to make fixture F-I3, as `sigil-cli/tests/cli.rs` does for #47.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod common;

use std::path::{Path, PathBuf};

use sigil_engine::collect::named::NamedBudgets;
use sigil_engine::inspect::{binary_session, BinaryRequest};
use sigil_engine::policy::Policy;
use sigil_model::*;
use tempfile::TempDir;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/elf")
        .join(name)
}

fn session_with(paths: &[PathBuf], policy: &Policy) -> Session {
    let s = binary_session(
        &BinaryRequest {
            paths: paths.to_vec(),
            budgets: NamedBudgets::default(),
        },
        policy,
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap();
    assert_eq!(s.validate(), Ok(()));
    s
}

fn session(paths: &[PathBuf]) -> Session {
    session_with(paths, &Policy::builtin_default().unwrap())
}

/// `libdata.so` with its SONAME `libdata.so.1` replaced in place by `soname`, NUL-padded.
fn with_soname(soname: &[u8]) -> Vec<u8> {
    let mut bytes = std::fs::read(fixture("libdata.so")).unwrap();
    let old: &[u8] = b"libdata.so.1\0";
    let at: Vec<usize> = bytes
        .windows(old.len())
        .enumerate()
        .filter(|(_, w)| *w == old)
        .map(|(k, _)| k)
        .collect();
    assert_eq!(at.len(), 1, "the fixture holds its SONAME once");
    assert!(soname.len() < old.len());
    let mut new = soname.to_vec();
    new.resize(old.len(), 0);
    bytes[at[0]..at[0] + old.len()].copy_from_slice(&new);
    bytes
}

fn elf(s: &Session) -> &ElfFacts {
    match &s.binaries[0].container {
        ContainerFacts::Elf(elf) => elf,
        ContainerFacts::MachO(_) => panic!("an ELF fixture"),
    }
}

fn only_claim(s: &Session) -> &ComponentClaim {
    assert_eq!(s.components.len(), 1, "{:?}", s.components);
    &s.components[0]
}

/// F-I1: a file named as libggml-base whose SONAME names libllama conflicts; the same name with
/// a SONAME the database does not know is name-only.
#[test]
fn f_i1_a_name_and_a_soname_that_disagree_conflict() {
    let d = TempDir::new().unwrap();
    let path = d.path().join("libggml-base.so.0.13.1");
    std::fs::write(&path, with_soname(b"libllama.so")).unwrap();
    let s = session(std::slice::from_ref(&path));
    assert_eq!(
        elf(&s).soname.as_ref().and_then(|t| t.as_str()),
        Some("libllama.so")
    );
    let c = only_claim(&s);
    assert_eq!(
        (c.component.as_str(), c.status),
        ("ggml-base", IdentityStatus::Conflicting)
    );
    std::fs::copy(fixture("libdata.so"), &path).unwrap();
    let s = session(&[path]);
    let c = only_claim(&s);
    assert_eq!(
        (c.component.as_str(), c.status),
        ("ggml-base", IdentityStatus::NameOnly)
    );
    assert!(c.assertions.iter().any(|a| matches!(
        a,
        IdentityAssertion::SelfName { kind: NameKind::Soname, value, .. }
            if value.as_str() == Some("libdata.so.1")
    )));
}

/// F-I3: a stripped copy of a library with its `LLAMA_*` values, named as libllama-common, is
/// name-only from its name and embedded values, never unidentified; so is the unstripped copy.
#[test]
fn f_i3_a_stripped_library_with_embedded_values_is_name_only() {
    let stripped_dir = TempDir::new().unwrap();
    let stripped = stripped_dir.path().join("libllama-common.so.0.0.1");
    let status = std::process::Command::new("strip")
        .arg("--strip-all")
        .arg("-o")
        .arg(&stripped)
        .arg(fixture("libdata.so"))
        .status()
        .unwrap_or_else(|e| panic!("strip (binutils) is required by this test: {e}"));
    assert!(status.success(), "strip failed: {status}");
    let plain_dir = TempDir::new().unwrap();
    let plain = plain_dir.path().join("libllama-common.so.0.0.1");
    std::fs::copy(fixture("libdata.so"), &plain).unwrap();
    for (path, is_stripped) in [(stripped, true), (plain, false)] {
        let s = session(&[path]);
        assert_eq!(elf(&s).stripped, Some(is_stripped));
        let c = only_claim(&s);
        assert_eq!(
            (c.component.as_str(), c.status),
            ("llama.cpp/common", IdentityStatus::NameOnly)
        );
        let embedded: Vec<(&str, &str)> = c
            .assertions
            .iter()
            .filter_map(|a| match a {
                IdentityAssertion::Embedded { field, value, .. } => {
                    Some((field.as_str(), value.as_str().unwrap()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            embedded,
            [
                ("LLAMA_BUILD_NUMBER", "1"),
                ("LLAMA_BUILD_TARGET", "x86_64-linux-gnu"),
                ("LLAMA_COMMIT", "6f3a9f3de"),
                ("LLAMA_COMPILER", "GNU 11.2.1")
            ]
        );
        let versions: Vec<&str> = c
            .versions
            .iter()
            .map(|v| v.value.as_str().unwrap())
            .collect();
        assert_eq!(versions, ["0.0.1", "1"]);
    }
}

/// One content named by two inputs whose versions start with different numbers.
#[test]
fn one_content_at_two_versioned_names_conflicts() {
    let d = TempDir::new().unwrap();
    let (a, b) = (
        d.path().join("libmtmd.so.0.0.1"),
        d.path().join("libmtmd.so.1"),
    );
    std::fs::copy(fixture("libdata.so"), &a).unwrap();
    std::fs::copy(fixture("libdata.so"), &b).unwrap();
    let s = session(&[a, b]);
    assert_eq!(s.artifacts.len(), 1);
    let c = only_claim(&s);
    assert_eq!(
        (c.component.as_str(), c.status),
        ("llama.cpp/mtmd", IdentityStatus::Conflicting)
    );
}

/// `[[components.deny]]` applies to the claims 4c-1 makes, name-only ones included.
#[test]
fn a_denied_component_is_a_policy_violation() {
    let d = TempDir::new().unwrap();
    let path = d.path().join("libllama-common.so.0.0.1");
    std::fs::copy(fixture("libdata.so"), &path).unwrap();
    let policy = Policy::load(
        "schema = \"sigil-policy/1\"\nname = \"test\"\n\n[[components.deny]]\n\
         component = \"llama.cpp/common\"\naction = \"warn\"\nreason = \"not approved\"\n",
    )
    .unwrap();
    let s = session_with(&[path], &policy);
    assert_eq!(s.policy_violations.len(), 1, "{:?}", s.policy_violations);
    assert_eq!(
        s.policy_violations[0].subject,
        Ref::Component {
            slice: s.components[0].subject.clone(),
            component: ComponentKey::new("llama.cpp/common").unwrap(),
        }
    );
    assert_eq!(s.outcome.verdict, Verdict::Warn);
}
