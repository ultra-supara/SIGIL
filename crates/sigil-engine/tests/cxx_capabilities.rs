//! The C++ capability fixture (PR-4c-3c): a g++ 15.3.0 build that imports 9 of the `cxx.*` names
//! and 6 names that stay unmapped (`tests/fixtures/cxx-capabilities/build.sh`).

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use sigil_engine::binary::BinaryBudgets;
use sigil_engine::code::CodeBudgets;
use sigil_engine::collect::named::NamedBudgets;
use sigil_engine::inspect::{binary_session, BinaryRequest};
use sigil_engine::policy::Policy;
use sigil_model::{
    ArgValue, CallTarget, ContainerFacts, CoverageState, Loc, Reg, Session, Signal, BINARY_CODE,
};

const IFSTREAM_C1: &str = "_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC1EPKcSt13_Ios_Openmode";
const IFSTREAM_C2: &str = "_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC2EPKcSt13_Ios_Openmode";
const CREATE_DIRECTORIES: &str = "_ZNSt10filesystem18create_directoriesERKNS_7__cxx114pathE";
const REMOVE_OLD: &str = "_ZNSt10filesystem6removeERKNS_4pathE";
const REMOVE_EC: &str = "_ZNSt10filesystem6removeERKNS_7__cxx114pathERSt10error_code";
const RENAME: &str = "_ZNSt10filesystem6renameERKNS_7__cxx114pathES3_";
const COPY_FILE: &str = "_ZNSt10filesystem9copy_fileERKNS_7__cxx114pathES3_NS_12copy_optionsE";
const OFSTREAM_C1: &str = "_ZNSt14basic_ofstreamIcSt11char_traitsIcEEC1ERKNSt7__cxx1112basic_stringIcS1_SaIcEEESt13_Ios_Openmode";
const OFSTREAM_C1_OLD: &str = "_ZNSt14basic_ofstreamIcSt11char_traitsIcEEC1ERKSsSt13_Ios_Openmode";

/// The fixture's imports among the `cxx.*` names (build.sh's MAPPED), as hints in session order,
/// with their arities.
const MAPPED: [(&str, &str, usize); 9] = [
    ("cxx.file_read", IFSTREAM_C1, 3),
    ("cxx.file_read", IFSTREAM_C2, 4),
    ("cxx.file_write", CREATE_DIRECTORIES, 1),
    ("cxx.file_write", REMOVE_OLD, 1),
    ("cxx.file_write", REMOVE_EC, 2),
    ("cxx.file_write", RENAME, 2),
    ("cxx.file_write", COPY_FILE, 3),
    ("cxx.file_write", OFSTREAM_C1, 3),
    ("cxx.file_write", OFSTREAM_C1_OLD, 3),
];

/// build.sh's UNMAPPED: imports of the fixture that give no hint (spec §3).
const UNMAPPED: [&str; 6] = [
    "_ZNSt10filesystem11permissionsERKNS_7__cxx114pathENS_5permsENS_12perm_optionsE",
    "_ZNSt10filesystem15last_write_timeERKNS_7__cxx114pathE",
    "_ZNSt10filesystem6statusERKNS_7__cxx114pathE",
    "_ZNSt10filesystem7__cxx1118directory_iteratorC1ERKNS0_4pathENS_17directory_optionsEPSt10error_code",
    "_ZNSt13basic_filebufIcSt11char_traitsIcEE4openEPKcSt13_Ios_Openmode",
    "_ZNSt13basic_fstreamIcSt11char_traitsIcEEC1EPKcSt13_Ios_Openmode",
];

/// `config_file`'s VTT (`_ZTT11config_file`, `nm cxx-capabilities`).
const CONFIG_FILE_VTT: i64 = 0x6cd8;

fn session(code: bool) -> Session {
    let budgets = NamedBudgets {
        binary: BinaryBudgets {
            code: code.then(CodeBudgets::default),
            ..BinaryBudgets::default()
        },
        ..NamedBudgets::default()
    };
    let req = BinaryRequest {
        paths: vec![PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/cxx-capabilities/cxx-capabilities")],
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

#[test]
fn a_hint_per_cxx_import_and_none_for_the_unmapped_ones() {
    let s = session(false);
    let got: Vec<(&str, &str)> = s
        .hints
        .iter()
        .map(|h| (h.feature.as_str(), h.value.as_str().unwrap()))
        .collect();
    let want: Vec<(&str, &str)> = MAPPED.iter().map(|(f, n, _)| (*f, *n)).collect();
    assert_eq!(got, want);
    let slice = &s.binaries[0].slice;
    assert!(s.hints.iter().all(|h| &h.subject == slice
        && h.signal == Signal::Import
        && h.at == Loc::Symbol(h.value.clone())));
    let ContainerFacts::Elf(elf) = &s.binaries[0].container else {
        panic!("not an ELF");
    };
    for name in UNMAPPED {
        assert!(
            elf.imports.iter().any(|i| i.name.as_str() == Some(name)),
            "not imported: {name}"
        );
    }
    s.validate().unwrap();
}

#[test]
fn with_code_each_cxx_import_has_its_call_site_with_its_arity() {
    let s = session(true);
    let code = s
        .coverage
        .iter()
        .find(|c| c.check.as_str() == BINARY_CODE)
        .unwrap();
    assert_eq!(code.state, CoverageState::Complete);
    // The arguments of each import's direct call sites.
    let mut sites: BTreeMap<&str, Vec<&[ArgValue]>> = BTreeMap::new();
    for c in &s.code[0].call_sites {
        let CallTarget::Import { symbol, .. } = &c.target else {
            panic!("not an import call: {c:?}");
        };
        sites
            .entry(symbol.as_str().unwrap())
            .or_default()
            .push(&c.args);
    }
    let mut want: Vec<&str> = MAPPED.iter().map(|(_, n, _)| *n).collect();
    want.sort_unstable();
    assert_eq!(sites.keys().copied().collect::<Vec<_>>(), want);
    for (_, name, arity) in MAPPED {
        assert_eq!(sites[name].len(), 1, "{name}");
        assert_eq!(sites[name][0].len(), arity, "{name}");
    }
    // The modes and options are constants: in (8), out (16), overwrite_existing (2).
    let int = |reg, value| ArgValue::ConstInt { reg, value };
    assert_eq!(sites[IFSTREAM_C1][0][2], int(Reg::Rdx, 8));
    assert_eq!(sites[OFSTREAM_C1][0][2], int(Reg::Rdx, 16));
    assert_eq!(sites[COPY_FILE][0][2], int(Reg::Rdx, 2));
    // C2 takes the VTT second: config_file's, past its first entry (config_file's own vtable),
    // where the sub-VTT of its basic_ifstream base starts. The mode is fourth.
    assert_eq!(sites[IFSTREAM_C2][0][1], int(Reg::Rsi, CONFIG_FILE_VTT + 8));
    assert_eq!(sites[IFSTREAM_C2][0][3], int(Reg::Rcx, 8));
    s.validate().unwrap();
}
