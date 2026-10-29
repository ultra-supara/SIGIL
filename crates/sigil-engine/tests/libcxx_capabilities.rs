//! The libc++ capability fixtures (#105, `tests/fixtures/libcxx-capabilities/build.sh`): an x86-64
//! ELF built by clang 22.1.8 with `-stdlib=libc++` that imports 6 of libc++'s `cxx.*` names and 4
//! that stay unmapped, and an arm64 Mach-O linked against a `/usr/lib/libc++.1.dylib` stub.

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use sigil_engine::binary::BinaryBudgets;
use sigil_engine::code::CodeBudgets;
use sigil_engine::collect::named::NamedBudgets;
use sigil_engine::inspect::{binary_session, BinaryRequest};
use sigil_engine::policy::{evaluate, EvaluateError, Policy};
use sigil_model::{
    ArgValue, CallTarget, CondState, ContainerFacts, CoverageState, EvidenceRef, FeatureHint,
    FeatureKey, Loc, MachOLibrary, Ref, Reg, Session, Signal, UnknownReason, UntrustedText,
    Verdict, BINARY_CODE, LIBCXX, LIBSYSTEM,
};

const FILE_WRITE_FAILS: &str = "[[capabilities.deny]]\nfeature = \"cxx.file_write\"\naction = \"fail\"\nreason = \"read-only\"\n";
const NETWORK_FAILS: &str =
    "[[capabilities.deny]]\nfeature = \"posix.network\"\naction = \"fail\"\nreason = \"no network\"\n";

/// The default policy with `deny` added (as `capability_session.rs`'s).
fn policy(deny: &str) -> Policy {
    Policy::load(&format!(
        "schema = \"sigil-policy/1\"\nname = \"capabilities\"\n{deny}"
    ))
    .unwrap()
}

const IFSTREAM_OPEN: &str = "_ZNSt3__114basic_ifstreamIcNS_11char_traitsIcEEE4openEPKcj";
const OFSTREAM_OPEN: &str =
    "_ZNSt3__114basic_ofstreamIcNS_11char_traitsIcEEE4openERKNS_12basic_stringIcS2_NS_9allocatorIcEEEEj";
const COPY_FILE: &str =
    "_ZNSt3__14__fs10filesystem11__copy_fileERKNS1_4pathES4_NS1_12copy_optionsEPNS_10error_codeE";
const CREATE_DIRECTORIES: &str =
    "_ZNSt3__14__fs10filesystem20__create_directoriesERKNS1_4pathEPNS_10error_codeE";
const REMOVE: &str = "_ZNSt3__14__fs10filesystem8__removeERKNS1_4pathEPNS_10error_codeE";
const RENAME: &str = "_ZNSt3__14__fs10filesystem8__renameERKNS1_4pathES4_PNS_10error_codeE";

/// The ELF's imports among libc++'s names (build.sh's MAPPED), as hints in session order, with
/// their arities.
const MAPPED: [(&str, &str, usize); 6] = [
    ("cxx.file_read", IFSTREAM_OPEN, 3),
    ("cxx.file_write", OFSTREAM_OPEN, 3),
    ("cxx.file_write", COPY_FILE, 4),
    ("cxx.file_write", CREATE_DIRECTORIES, 2),
    ("cxx.file_write", REMOVE, 2),
    ("cxx.file_write", RENAME, 3),
];

/// build.sh's UNMAPPED: imports of the ELF that give no hint (spec §3).
const UNMAPPED: [&str; 4] = [
    "_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE4openEPKcj",
    "_ZNSt3__14__fs10filesystem13__permissionsERKNS1_4pathENS1_5permsENS1_12perm_optionsEPNS_10error_codeE",
    "_ZNSt3__14__fs10filesystem17__last_write_timeERKNS1_4pathEPNS_10error_codeE",
    "_ZNSt3__14__fs10filesystem8__statusERKNS1_4pathEPNS_10error_codeE",
];

/// The Mach-O's imports from libc++ (build.sh's MACHO_IMPORTS), as the file names them.
const MACHO_REMOVE: &str = "__ZNSt3__14__fs10filesystem8__removeERKNS1_4pathEPNS_10error_codeE";
const MACHO_PERMISSIONS: &str =
    "__ZNSt3__14__fs10filesystem13__permissionsERKNS1_4pathENS1_5permsENS1_12perm_optionsEPNS_10error_codeE";

fn session(file: &str, code: bool) -> Session {
    inspect(file, code, &Policy::builtin_default().unwrap())
}

/// `file` inspected and evaluated under `policy`; the result validates.
fn inspect(file: &str, code: bool, policy: &Policy) -> Session {
    let budgets = NamedBudgets {
        binary: BinaryBudgets {
            code: code.then(CodeBudgets::default),
            ..BinaryBudgets::default()
        },
        ..NamedBudgets::default()
    };
    let req = BinaryRequest {
        paths: vec![PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/libcxx-capabilities")
            .join(file)],
        budgets,
    };
    let s = binary_session(
        &req,
        policy,
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap();
    s.validate().unwrap();
    s
}

fn hints(s: &Session) -> Vec<(&str, &str)> {
    s.hints
        .iter()
        .map(|h| (h.feature.as_str(), h.value.as_str().unwrap()))
        .collect()
}

#[test]
fn an_elf_gets_a_hint_per_libcxx_import_and_none_for_the_unmapped_ones() {
    let s = session("libcxx-capabilities", false);
    let want: Vec<(&str, &str)> = MAPPED.iter().map(|(f, n, _)| (*f, *n)).collect();
    assert_eq!(hints(&s), want);
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
fn with_code_each_libcxx_import_has_its_call_site_with_its_arity() {
    let s = session("libcxx-capabilities", true);
    let code = s
        .coverage
        .iter()
        .find(|c| c.check.as_str() == BINARY_CODE)
        .unwrap();
    assert_eq!(code.state, CoverageState::Complete);
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
    assert_eq!(sites[IFSTREAM_OPEN][0][2], int(Reg::Rdx, 8));
    assert_eq!(sites[OFSTREAM_OPEN][0][2], int(Reg::Rdx, 16));
    assert_eq!(sites[COPY_FILE][0][2], int(Reg::Rdx, 2));
    s.validate().unwrap();
}

#[test]
fn a_macho_import_bound_to_libcxx_maps_only_libcxx_s_names() {
    let s = session("libcxx-macho", false);
    assert_eq!(
        hints(&s),
        [
            ("cxx.file_write", MACHO_REMOVE),
            ("posix.environment_access", "_getenv"),
        ]
    );
    let ContainerFacts::MachO(macho) = &s.binaries[0].container else {
        panic!("not a Mach-O");
    };
    let bound_to = |name: &str, dylib: &str| {
        macho.imports.iter().any(|i| {
            i.name.as_str() == Some(name)
                && matches!(&i.library, MachOLibrary::Dylib { name: Some(n), .. }
                    if n.as_str() == Some(dylib))
        })
    };
    // `_connect` and `__permissions` are libc++'s imports too, and give no hint.
    for name in [MACHO_REMOVE, MACHO_PERMISSIONS, "_connect"] {
        assert!(bound_to(name, LIBCXX), "{name}");
    }
    assert!(bound_to("_getenv", LIBSYSTEM));
    assert_eq!(macho.imports.len(), 4);
    s.validate().unwrap();
}

/// Plan review P2: #106's denial reaches libc++'s names. Under `cxx.file_write = fail`, the ELF
/// with code analysis FAILs with one violation citing each direct call of a libc++
/// `cxx.file_write` import (five: ofstream's open, copy_file, create_directories, remove,
/// rename), and none of the unmapped imports' calls.
#[test]
fn a_denied_libcxx_write_that_is_called_is_a_violation_citing_its_call_sites() {
    let s = inspect("libcxx-capabilities", true, &policy(FILE_WRITE_FAILS));
    let slice = s.binaries[0].slice.clone();
    assert_eq!(s.policy_violations.len(), 1, "{:?}", s.policy_violations);
    let v = &s.policy_violations[0];
    assert_eq!(
        v.policy_rule.to_string(),
        "policy:capabilities.deny.cxx.file_write"
    );
    assert_eq!(v.subject, Ref::Slice(slice.clone()));
    let writes: Vec<&str> = MAPPED
        .iter()
        .filter(|(f, _, _)| *f == "cxx.file_write")
        .map(|(_, n, _)| *n)
        .collect();
    let mut want: Vec<EvidenceRef> = s.code[0]
        .call_sites
        .iter()
        .filter(|c| {
            matches!(&c.target, CallTarget::Import { symbol, .. }
            if writes.contains(&symbol.as_str().unwrap()))
        })
        .map(|c| EvidenceRef::Code {
            slice: slice.clone(),
            loc: Loc::CallSite(c.id.clone()),
        })
        .collect();
    assert_eq!(want.len(), 5);
    let mut got = v.evidence.clone();
    want.sort_by_cached_key(|e| format!("{e:?}"));
    got.sort_by_cached_key(|e| format!("{e:?}"));
    assert_eq!(got, want);
    assert_eq!(s.outcome.verdict, Verdict::Fail);
}

/// Plan review P2, #105 end to end on the Mach-O: without code analysis, `__remove` bound to
/// libc++ is an open question under `cxx.file_write = fail`; `_connect` bound to libc++ gives no
/// hint, so `posix.network = fail` has nothing to judge.
#[test]
fn a_denial_on_the_macho_judges_libcxx_s_names_only() {
    let s = inspect("libcxx-macho", false, &policy(FILE_WRITE_FAILS));
    let slice = s.binaries[0].slice.clone();
    assert!(s.policy_violations.is_empty(), "{:?}", s.policy_violations);
    let questions: Vec<String> = s.open_questions.iter().map(|q| q.id.to_string()).collect();
    assert_eq!(questions, [format!("capability:cxx.file_write@{slice}")]);
    match &s.open_questions[0].conditions[0].state {
        CondState::Unknown { reason, .. } => assert_eq!(
            reason,
            &UnknownReason::NotModeled {
                what: "calls in code that was not analyzed".into()
            }
        ),
        other => panic!("{other:?}"),
    }
    let s = inspect("libcxx-macho", false, &policy(NETWORK_FAILS));
    assert!(s.policy_violations.is_empty() && s.open_questions.is_empty());
}

/// Plan review P2: C6 does not tie a name to its feature (the table is the engine's), so a
/// `cxx.file_write` hint forged on `_connect`, bound to libc++, validates; evaluation under a
/// capability denial refuses the session, since its hints are not the table's (#51).
#[test]
fn a_hint_the_table_does_not_give_validates_but_is_refused_under_a_denial() {
    let mut s = inspect("libcxx-macho", false, &policy(""));
    let slice = s.binaries[0].slice.clone();
    s.hints.push(FeatureHint {
        subject: slice,
        feature: FeatureKey::new("cxx.file_write").unwrap(),
        signal: Signal::Import,
        value: UntrustedText::new("_connect"),
        at: Loc::Symbol(UntrustedText::new("_connect")),
    });
    s.canonicalize();
    s.validate().unwrap();
    let before = s.clone();
    let time = s.outcome.policy_time.clone();
    assert_eq!(
        evaluate(&mut s, &policy(FILE_WRITE_FAILS), time),
        Err(EvaluateError::CapabilityHints {
            missing: 0,
            extra: 1
        })
    );
    assert_eq!(s, before, "a refused evaluation changes nothing");
}
