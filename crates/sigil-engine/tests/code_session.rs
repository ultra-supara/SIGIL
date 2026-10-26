//! Sessions with code facts, `binary.code`, hints, and the code scope (PR-5a).

mod common;

use std::path::PathBuf;

use sigil_engine::binary::BinaryBudgets;
use sigil_engine::code::CodeBudgets;
use sigil_engine::collect::fs::FsBudgets;
use sigil_engine::collect::install::InstallBudgets;
use sigil_engine::collect::named::NamedBudgets;
use sigil_engine::collect::ollama_store::DEFAULT_MANIFEST_LIMIT;
use sigil_engine::inspect::{
    binary_session, store_session, ActiveInput, BinaryRequest, InstallRequest, StoreRequest,
};
use sigil_engine::policy::Policy;
use sigil_model::{
    Arch, Coverage, CoverageState, ElfType, Format, Ref, Session, BINARY_CODE, BINARY_CODE_BYTES,
    BINARY_CONTAINER, CODE_UNSUPPORTED,
};
use tempfile::TempDir;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/code")
        .join(name)
}

/// The session's hints as (feature, value).
fn hint_pairs(s: &Session) -> Vec<(String, String)> {
    s.hints
        .iter()
        .map(|h| (h.feature.to_string(), h.value.as_str().unwrap().to_string()))
        .collect()
}

#[test]
fn a_binary_session_has_the_import_hints() {
    let req = BinaryRequest {
        paths: vec![fixture("net-plt-gcc.so")],
        budgets: Default::default(),
    };
    let s = binary_session(
        &req,
        &Policy::builtin_default().unwrap(),
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap();
    assert_eq!(
        hint_pairs(&s),
        [("posix.network".to_string(), "connect".to_string())]
    );
    assert!(s.validate().is_ok());
}

#[test]
fn an_install_session_has_the_import_hints() {
    // A synthetic tree: the fixture stands in for `bin/ollama`.
    let tree = TempDir::new().unwrap();
    std::fs::create_dir_all(tree.path().join("bin")).unwrap();
    std::fs::create_dir_all(tree.path().join("lib/ollama")).unwrap();
    std::fs::copy(fixture("net-plt-gcc.so"), tree.path().join("bin/ollama")).unwrap();
    let models = TempDir::new().unwrap();
    let req = StoreRequest {
        models_dir: models.path().to_path_buf(),
        model_filter: None,
        budgets: FsBudgets::default(),
        manifest_limit: DEFAULT_MANIFEST_LIMIT,
        install: Some(InstallRequest {
            dir: tree.path().to_path_buf(),
            budgets: InstallBudgets::default(),
        }),
    };
    let s = store_session(
        &req,
        &ActiveInput::default(),
        &Policy::builtin_default().unwrap(),
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap();
    assert_eq!(
        hint_pairs(&s),
        [("posix.network".to_string(), "connect".to_string())]
    );
    assert_eq!(s.hints[0].subject, s.binaries[0].slice);
    assert!(s.validate().is_ok());
}

/// A binary inspection of `paths` with the default code budgets.
fn with_code(paths: &[PathBuf]) -> Session {
    session_of(paths, with_code_budgets())
}

fn with_code_budgets() -> NamedBudgets {
    NamedBudgets {
        binary: BinaryBudgets {
            code: Some(CodeBudgets::default()),
            ..BinaryBudgets::default()
        },
        ..NamedBudgets::default()
    }
}

fn session_of(paths: &[PathBuf], budgets: NamedBudgets) -> Session {
    let req = BinaryRequest {
        paths: paths.to_vec(),
        budgets,
    };
    binary_session(
        &req,
        &Policy::builtin_default().unwrap(),
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap()
}

/// The `check` entry of input `k` (in instance order).
fn entry<'a>(s: &'a Session, check: &str, k: usize) -> &'a Coverage {
    let i = &s.instances[k];
    let entries: Vec<&Coverage> = s
        .coverage
        .iter()
        .filter(|c| c.check.as_str() == check && c.scope == Ref::Instance(i.id.clone()))
        .collect();
    assert_eq!(entries.len(), 1, "{check} on {}", i.id);
    entries[0]
}

fn code_state(s: &Session, k: usize) -> &Coverage {
    entry(s, BINARY_CODE, k)
}

#[test]
fn code_facts_and_a_complete_binary_code() {
    let s = with_code(&[fixture("suspicious_kernel-gcc-O2.o")]);
    assert!(s.request.code);
    assert_eq!(s.request.budgets.get(BINARY_CODE_BYTES), Some(&(256 << 20)));
    let c = code_state(&s, 0);
    assert_eq!(c.state, CoverageState::Complete);
    let b = c.budget.as_ref().unwrap();
    assert_eq!((b.budget.as_str(), b.limit), (BINARY_CODE_BYTES, 256 << 20));
    assert!(b.used > 0);
    assert_eq!(s.code.len(), 1);
    assert_eq!(s.code[0].slice, s.binaries[0].slice);
    assert_eq!(s.code[0].call_sites.len(), 1);
    assert!(!s.code[0].functions.is_empty());
    s.validate().unwrap();
}

#[test]
fn an_analyzed_input_without_call_sites_has_no_code_facts() {
    let s = with_code(&[fixture("clean_kernel-gcc-O2.o")]);
    assert_eq!(code_state(&s, 0).state, CoverageState::Complete);
    assert!(s.code.is_empty());
    s.validate().unwrap();
}

#[test]
fn gaps_make_binary_code_partial() {
    let s = with_code(&[fixture("cfg.so")]);
    let c = code_state(&s, 0);
    assert!(
        matches!(&c.state, CoverageState::Partial { missing } if missing.len() == 3),
        "{:?}",
        c.state
    );
    assert_eq!(c.budget.as_ref().unwrap().budget, BINARY_CODE_BYTES);
    // The calls confirmed are recorded all the same.
    assert_eq!(s.code.len(), 1);
    assert_eq!(s.code[0].call_sites.len(), 2);
    s.validate().unwrap();
}

#[test]
fn a_partial_binary_code_makes_the_session_incomplete() {
    let s = with_code(&[fixture("cfg.so")]);
    assert!(s
        .request
        .required_checks
        .iter()
        .any(|c| c.as_str() == BINARY_CODE));
    assert!(s.request.audit.iter().any(|a| a.as_str() == "binary_code"));
    assert!(
        matches!(&s.outcome.completeness, sigil_model::Completeness::Incomplete { missing_required, .. }
            if missing_required.iter().any(|c| c.as_str() == BINARY_CODE)),
        "{:?}",
        s.outcome.completeness
    );
    s.validate().unwrap();
    let s = with_code(&[fixture("suspicious_kernel-gcc-O2.o")]);
    assert_eq!(s.outcome.completeness, sigil_model::Completeness::Complete);
    s.validate().unwrap();
}

#[test]
fn unsupported_inputs() {
    let text = fixture("README.md");
    let arm =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/elf/libdata-aarch64.so");
    let s = with_code(&[text, arm]);
    // Not a container: the container's state, without a budget.
    let container = entry(&s, BINARY_CONTAINER, 0);
    assert!(matches!(container.state, CoverageState::Unsupported { .. }));
    assert_eq!(code_state(&s, 0).state, container.state);
    assert_eq!(code_state(&s, 0).budget, None);
    // Another machine: Unsupported, without a budget.
    assert_eq!(
        code_state(&s, 1).state,
        CoverageState::Unsupported {
            what: CODE_UNSUPPORTED.to_string()
        }
    );
    assert_eq!(code_state(&s, 1).budget, None);
    assert!(s.code.is_empty());
    s.validate().unwrap();
}

#[test]
fn an_input_over_binary_bytes_has_the_containers_state() {
    // The second input is over `binary_bytes`: its `binary.code` is the container's
    // `BudgetExceeded`, `used` included, so it is computed after the container's entry.
    let first = fixture("net-plt-gcc.so");
    let size = std::fs::metadata(&first).unwrap().len();
    let budgets = NamedBudgets {
        bytes: size + 1,
        ..with_code_budgets()
    };
    let s = session_of(&[first, fixture("cfg.so")], budgets);
    let container = entry(&s, BINARY_CONTAINER, 1);
    assert!(
        matches!(&container.state, CoverageState::BudgetExceeded { used, .. } if *used == size),
        "{:?}",
        container.state
    );
    assert_eq!(code_state(&s, 1).state, container.state);
    assert_eq!(code_state(&s, 1).budget, None);
    assert_eq!(s.code.len(), 1);
    s.validate().unwrap();
}

#[test]
fn unreadable_dynamic_symbols_make_both_checks_partial() {
    // The file of code_facts.rs' P1-1 test, built here the same way: `.dynsym`'s type changed
    // to SHT_PROGBITS.
    use object::{Object, ObjectSection};
    let mut bytes = std::fs::read(fixture("net-plt-gcc.so")).unwrap();
    let index = object::File::parse(&*bytes)
        .unwrap()
        .section_by_name(".dynsym")
        .unwrap()
        .index()
        .0;
    let shoff = u64::from_le_bytes(bytes[0x28..0x30].try_into().unwrap()) as usize;
    let shentsize = u16::from_le_bytes(bytes[0x3a..0x3c].try_into().unwrap()) as usize;
    let at = shoff + index * shentsize + 4;
    bytes[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("net.so");
    std::fs::write(&path, bytes).unwrap();
    let s = with_code(&[path]);
    assert!(
        matches!(
            entry(&s, BINARY_CONTAINER, 0).state,
            CoverageState::Partial { .. }
        ),
        "{:?}",
        entry(&s, BINARY_CONTAINER, 0).state
    );
    assert!(
        matches!(&code_state(&s, 0).state, CoverageState::Partial { missing }
            if missing.iter().any(|m| m.contains("imports not listed"))),
        "{:?}",
        code_state(&s, 0).state
    );
    assert!(s.code.is_empty());
    s.validate().unwrap();
}

/// A header-only `ET_REL` ELF for `EM_X86_64` (no sections, no program headers) of class `class`
/// (1: ELF32, 2: ELF64) and byte order `data` (1: little, 2: big).
fn header_only_x86_64_rel(class: u8, data: u8) -> Vec<u8> {
    let size: u16 = if class == 1 { 52 } else { 64 };
    let half = |v: u16| {
        if data == 1 {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        }
    };
    let word = |v: u32| {
        if data == 1 {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        }
    };
    let mut h = vec![0u8; usize::from(size)];
    h[..4].copy_from_slice(b"\x7fELF");
    h[4] = class;
    h[5] = data;
    h[6] = 1; // EI_VERSION
    h[16..18].copy_from_slice(&half(1)); // ET_REL
    h[18..20].copy_from_slice(&half(62)); // EM_X86_64
    h[20..24].copy_from_slice(&word(1)); // e_version
    let ehsize = if class == 1 { 40 } else { 52 };
    h[ehsize..ehsize + 2].copy_from_slice(&half(size));
    h
}

#[test]
fn x32_and_big_endian_inputs_are_unsupported() {
    // R-c: the model records no ELF class or byte order, so both are `x86_64` ELF slices there
    // (`Analyzable`); the code analysis reads neither, and the model admits its `Unsupported`.
    let dir = TempDir::new().unwrap();
    for (name, class, data) in [("be64.o", 2, 2), ("x32.o", 1, 1)] {
        let path = dir.path().join(name);
        std::fs::write(&path, header_only_x86_64_rel(class, data)).unwrap();
        let s = with_code(&[path]);
        let a = &s.artifacts[0];
        assert_eq!(a.format, Format::Elf { kind: ElfType::Rel }, "{name}");
        assert_eq!(a.slices.len(), 1, "{name}");
        assert_eq!(a.slices[0].arch, Arch::X86_64, "{name}");
        assert_eq!(s.binaries.len(), 1, "{name}");
        assert!(
            matches!(
                entry(&s, BINARY_CONTAINER, 0).state,
                CoverageState::Complete | CoverageState::Partial { .. }
            ),
            "{name}: {:?}",
            entry(&s, BINARY_CONTAINER, 0).state
        );
        assert_eq!(
            code_state(&s, 0).state,
            CoverageState::Unsupported {
                what: CODE_UNSUPPORTED.to_string()
            },
            "{name}"
        );
        assert_eq!(code_state(&s, 0).budget, None, "{name}");
        assert!(s.code.is_empty(), "{name}");
        s.validate().unwrap();
    }
}

#[test]
fn a_mach_o_input_is_unsupported() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/macho/hello-universal");
    let s = with_code(&[path]);
    assert_eq!(s.artifacts[0].format, Format::MachOFat);
    assert_eq!(
        code_state(&s, 0).state,
        CoverageState::Unsupported {
            what: CODE_UNSUPPORTED.to_string()
        }
    );
    assert_eq!(code_state(&s, 0).budget, None);
    assert!(s.code.is_empty());
    s.validate().unwrap();
}

#[test]
fn without_code_there_is_no_binary_code() {
    let s = session_of(&[fixture("net-plt-gcc.so")], NamedBudgets::default());
    assert!(!s.request.code);
    assert!(!s
        .request
        .required_checks
        .iter()
        .any(|c| c.as_str() == BINARY_CODE));
    assert!(!s.coverage.iter().any(|c| c.check.as_str() == BINARY_CODE));
    assert!(!s.request.budgets.contains_key(BINARY_CODE_BYTES));
    assert!(s.code.is_empty());
}

#[test]
fn one_content_named_twice_has_one_code_facts() {
    let a = fixture("net-plt-gcc.so");
    let dir = TempDir::new().unwrap();
    let b = dir.path().join("copy.so");
    std::fs::copy(&a, &b).unwrap();
    let s = with_code(&[a, b]);
    assert_eq!(s.artifacts.len(), 1);
    assert_eq!(s.code.len(), 1);
    assert_eq!(code_state(&s, 0).state, CoverageState::Complete);
    // The same state and budget use, each on its own input.
    assert_ne!(code_state(&s, 0).scope, code_state(&s, 1).scope);
    assert_eq!(
        code_state(&s, 0),
        &Coverage {
            scope: code_state(&s, 0).scope.clone(),
            ..code_state(&s, 1).clone()
        }
    );
    s.validate().unwrap();
}

/// The files of a fixture directory, as code_facts.rs' R-h test lists them.
fn fixture_files(dir: &str) -> Vec<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(dir);
    let mut out: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            let name = p.file_name().unwrap().to_str().unwrap();
            !(name.contains(".objdump")
                || name.contains(".readelf")
                || name.contains(".otool")
                || name.ends_with(".c")
                || name.ends_with(".S")
                || name.ends_with(".md")
                || name.ends_with(".sh")
                || name.ends_with(".hex")
                || name.ends_with(".tbd")
                || name == "COMPILERS"
                || name == "SHA256SUMS")
        })
        .collect();
    out.sort();
    out
}

#[test]
fn a_code_request_never_changes_the_container_coverage() {
    // R-h at the session level: for every fixture, the `binary.container` entry is the same
    // bytes, and the container facts and hints the same, with and without code; and the session
    // with code validates (C1–C6 on real outputs).
    let mut seen = 0;
    for path in fixture_files("tests/fixtures/code")
        .into_iter()
        .chain(fixture_files("tests/fixtures/elf"))
        .chain(fixture_files("tests/fixtures/macho"))
    {
        let shown = path.display();
        let without = session_of(std::slice::from_ref(&path), NamedBudgets::default());
        let with = with_code(std::slice::from_ref(&path));
        let container = |s: &Session| serde_json::to_vec(entry(s, BINARY_CONTAINER, 0)).unwrap();
        assert_eq!(container(&with), container(&without), "{shown}");
        assert_eq!(with.binaries, without.binaries, "{shown}");
        assert_eq!(with.hints, without.hints, "{shown}");
        assert_eq!(with.artifacts, without.artifacts, "{shown}");
        assert!(with.validate().is_ok(), "{shown}: {:?}", with.validate());
        let _ = code_state(&with, 0);
        for facts in &with.code {
            assert!(!facts.call_sites.is_empty(), "{shown}");
        }
        seen += 1;
    }
    // 29 code fixtures, 7 ELF fixtures, and hello-universal.
    assert!(seen >= 37, "{seen} files");
}
