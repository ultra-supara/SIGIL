//! S1–S3 (PR-4c-2a spec §5, §6): `binary.identity`, `artifacts.identity`, and the signature hints
//! agree with the session.

mod common;

use sigil_model::*;

const LIMIT: u64 = 64 << 20;

/// Example 15's shared object alone, with a `binary_scan_bytes` budget, without `binary.identity`
/// (`common::without_identity`).
fn elf_session() -> Session {
    let mut s = common::without_identity(common::binary_session_one_elf());
    s.request
        .budgets
        .insert(BINARY_SCAN_BYTES.to_string(), LIMIT);
    s
}

/// `s` with one `binary.identity` entry of `state` on its first input.
fn with_identity(mut s: Session, state: CoverageState) -> Session {
    s.coverage.push(Coverage {
        check: CheckId::new(BINARY_IDENTITY).unwrap(),
        scope: Ref::Instance(s.instances[0].id.clone()),
        state,
        budget: None,
    });
    s
}

fn partial(missing: &[&str]) -> CoverageState {
    CoverageState::Partial {
        missing: missing.iter().map(|m| m.to_string()).collect(),
    }
}

fn out_of_scope() -> CoverageState {
    CoverageState::OutOfScope {
        why: NAME_AND_HASH_ONLY_WHY.to_string(),
    }
}

fn errors_of(s: &Session, kind: fn(&ValidationError) -> bool) -> Vec<String> {
    s.validate()
        .err()
        .unwrap_or_default()
        .iter()
        .filter(|e| kind(e))
        .map(ToString::to_string)
        .collect()
}

fn input_errors(s: &Session) -> Vec<String> {
    errors_of(s, |e| matches!(e, ValidationError::BinaryInput { .. }))
}

fn code_errors(s: &Session) -> Vec<String> {
    errors_of(s, |e| matches!(e, ValidationError::Code { .. }))
}

fn binary_errors(s: &Session) -> Vec<String> {
    errors_of(s, |e| matches!(e, ValidationError::Binary { .. }))
}

#[test]
fn the_scan_gaps_are_the_scan_s_own() {
    assert_eq!(
        scan_over_gap(LIMIT),
        "string scan: binary_scan_bytes 67108864 exceeded"
    );
    for gap in [SCAN_NO_SECTIONS, SCAN_NAME_NOT_READ, SCAN_READ_FAILED] {
        assert!(gap.starts_with("string scan: "), "{gap}");
        assert!(is_scan_gap(gap, LIMIT), "{gap}");
    }
    assert!(is_scan_gap(&scan_over_gap(LIMIT), LIMIT));
    assert!(!is_scan_gap(&scan_over_gap(LIMIT + 1), LIMIT));
    assert!(!is_scan_gap(SCAN_ELF_ONLY, LIMIT));
    assert!(!is_scan_gap(BINARY_NOT_PARSED, LIMIT));
    assert!(!is_scan_gap("binary_parse_bytes: 67108864 exceeded", LIMIT));
}

#[test]
fn expected_binary_identity_of_each_input() {
    let expected = |s: &Session| expected_binary_identity(s, &s.instances[0]);
    let scanned = |name_and_hash_only| {
        Ok(ExpectedIdentity::Scanned {
            limit: LIMIT,
            name_and_hash_only,
        })
    };
    // An ELF with facts.
    let s = elf_session();
    assert_eq!(expected(&s), scanned(false));
    // Claimed as an NVIDIA library.
    for key in NAME_AND_HASH_ONLY {
        let mut t = s.clone();
        t.components[0].component = ComponentKey::new(key).unwrap();
        assert_eq!(expected(&t), scanned(true), "{key}");
    }
    let mut t = s.clone();
    t.components[0].component = ComponentKey::new("ggml-backend/cuda").unwrap();
    assert_eq!(expected(&t), scanned(false));
    // An NVIDIA claim on another slice is not this input's.
    let mut t = s.clone();
    let mut other = t.components[0].clone();
    other.subject = SliceId::from_parts(
        &ArtifactId::new(format!("sha256:{}", "c".repeat(64))).unwrap(),
        Arch::X86_64,
        0,
    );
    other.component = ComponentKey::new("cuda-runtime").unwrap();
    t.components.push(other);
    assert_eq!(expected(&t), scanned(false));
    // Without the budget: no answer.
    let mut t = s.clone();
    t.request.budgets.remove(BINARY_SCAN_BYTES);
    assert_eq!(
        expected(&t),
        Err("an ELF input without a binary_scan_bytes budget".to_string())
    );
    // A slice without facts.
    let mut t = s.clone();
    t.binaries.clear();
    assert_eq!(
        expected(&t),
        Ok(ExpectedIdentity::Exactly(partial(&[BINARY_NOT_PARSED])))
    );
    // A Mach-O.
    let mut t = s.clone();
    t.artifacts[0].format = Format::MachO;
    assert_eq!(
        expected(&t),
        Ok(ExpectedIdentity::Exactly(CoverageState::Unsupported {
            what: SCAN_ELF_ONLY.to_string(),
        }))
    );
    // A file SIGIL does not parse: the container's state.
    let t = common::binary_session_one_unsupported();
    assert_eq!(
        expected(&t),
        Ok(ExpectedIdentity::Exactly(CoverageState::Unsupported {
            what: BINARY_UNSUPPORTED.to_string(),
        }))
    );
    // Over binary_bytes: its binary.container entry's state, used included.
    let mut t = s.clone();
    let over = CoverageState::BudgetExceeded {
        budget: BINARY_BYTES.to_string(),
        used: 7,
        limit: 64 << 30,
    };
    t.instances[0].content = InstanceContent::NotRead {
        why: NotReadReason::BudgetExceeded,
    };
    t.coverage
        .iter_mut()
        .find(|c| c.check.as_str() == BINARY_CONTAINER)
        .unwrap()
        .state = over.clone();
    assert_eq!(expected(&t), Ok(ExpectedIdentity::Exactly(over)));
}

#[test]
fn a_scanned_input_admits_complete_scan_gaps_and_for_nvidia_out_of_scope() {
    let scanned = |name_and_hash_only| ExpectedIdentity::Scanned {
        limit: LIMIT,
        name_and_hash_only,
    };
    for name_and_hash_only in [false, true] {
        let e = scanned(name_and_hash_only);
        assert_eq!(e.admits(&CoverageState::Complete), Ok(()));
        assert_eq!(
            e.admits(&partial(&[SCAN_NO_SECTIONS, &scan_over_gap(LIMIT)])),
            Ok(())
        );
        for wrong in [
            partial(&[]),
            partial(&[SCAN_READ_FAILED, BINARY_NOT_PARSED]),
            partial(&[&scan_over_gap(1)]),
            CoverageState::Unsupported {
                what: SCAN_ELF_ONLY.to_string(),
            },
            CoverageState::OutOfScope {
                why: "another reason".to_string(),
            },
        ] {
            assert!(e.admits(&wrong).is_err(), "{wrong:?}");
        }
    }
    assert_eq!(scanned(true).admits(&out_of_scope()), Ok(()));
    assert_eq!(
        scanned(false).admits(&out_of_scope()),
        Err(format!(
            "binary.identity is out of scope: {NAME_AND_HASH_ONLY_WHY}, but the input implies complete, or partial with scan gaps (binary_scan_bytes {LIMIT})"
        ))
    );
    let unsupported = CoverageState::Unsupported {
        what: SCAN_ELF_ONLY.to_string(),
    };
    let exactly = ExpectedIdentity::Exactly(unsupported.clone());
    assert_eq!(exactly.admits(&unsupported), Ok(()));
    assert_eq!(
        exactly.admits(&CoverageState::Complete),
        Err(
            "binary.identity is complete, but the input implies unsupported: string scan: ELF only"
                .to_string()
        )
    );
}

#[test]
fn s1_an_input_has_at_most_one_entry_in_a_state_it_implies() {
    // None: a session written before PR-4c-2a.
    assert_eq!(input_errors(&elf_session()), Vec::<String>::new());
    let s = with_identity(elf_session(), CoverageState::Complete);
    assert_eq!(input_errors(&s), Vec::<String>::new());
    let id = s.instances[0].id.clone();
    let at = format!("binary input coverage[binary.identity on {id}]");
    // Two entries.
    let t = with_identity(s.clone(), CoverageState::Complete);
    assert_eq!(
        input_errors(&t),
        [format!(
            "{at}: 2 binary.identity entries; an input has at most one"
        )]
    );
    // A state the input does not imply.
    let t = with_identity(elf_session(), out_of_scope());
    assert_eq!(input_errors(&t).len(), 1, "{:?}", input_errors(&t));
    assert!(input_errors(&t)[0].contains("but the input implies complete"));
    // Without the budget.
    let mut t = s.clone();
    t.request.budgets.remove(BINARY_SCAN_BYTES);
    assert_eq!(
        input_errors(&t),
        [format!(
            "{at}: an ELF input without a binary_scan_bytes budget"
        )]
    );
    // Scoped to something other than an input's instance.
    let mut t = s.clone();
    t.coverage.last_mut().unwrap().scope = Ref::Audit;
    assert_eq!(
        input_errors(&t),
        ["binary input coverage[binary.identity on the audit]: binary.identity must be scoped to an input's instance"]
    );
    // Outside a binary inspection.
    let mut t = common::complete_pass();
    t.coverage.push(Coverage {
        check: CheckId::new(BINARY_IDENTITY).unwrap(),
        scope: Ref::Instance(t.instances[0].id.clone()),
        state: CoverageState::Complete,
        budget: None,
    });
    assert_eq!(input_errors(&t).len(), 1, "{:?}", input_errors(&t));
    // A Mach-O input is Unsupported, never Complete.
    let mut t = elf_session();
    t.artifacts[0].format = Format::MachO;
    t.binaries.clear();
    t.components.clear();
    t.hints.clear();
    t.relations.clear();
    let t = with_identity(t, CoverageState::Complete);
    assert!(input_errors(&t)
        .iter()
        .any(|e| e.contains("binary.identity is complete, but the input implies unsupported")));
}

/// Example 1 with facts for its one install binary.
fn install_session() -> Session {
    let mut s = common::complete_pass();
    let slice = s.artifacts[0].slices[0].id.clone();
    s.binaries.push(BinaryFacts {
        slice,
        container: ContainerFacts::Elf(ElfFacts {
            interp: None,
            soname: None,
            needed: vec![],
            rpath: vec![],
            runpath: vec![],
            build_id: None,
            comment: vec![],
            stripped: Some(true),
            exports: 0,
            imports: vec![],
            data: vec![],
        }),
        go: None,
        gaps: vec![],
    });
    s
}

fn with_install_identity(mut s: Session, state: CoverageState) -> Session {
    s.coverage.push(Coverage {
        check: CheckId::new(ARTIFACTS_IDENTITY).unwrap(),
        scope: Ref::Root(RootId::new(INSTALL_ROOT).unwrap()),
        state,
        budget: None,
    });
    s
}

#[test]
fn s2_artifacts_identity_is_complete_only_when_every_binary_was_scanned() {
    let s = with_install_identity(install_session(), CoverageState::Complete);
    assert_eq!(binary_errors(&s), Vec::<String>::new());
    let complaint = vec![
        "binaries[*]: artifacts.identity is Complete, but discovery is not Complete, an install binary is a Mach-O, or a slice has no facts".to_string(),
    ];
    // Discovery not complete.
    let mut t = s.clone();
    t.coverage
        .iter_mut()
        .find(|c| c.check.as_str() == ARTIFACTS_DISCOVERY)
        .unwrap()
        .state = partial(&["lib/ollama: not listed"]);
    assert_eq!(binary_errors(&t), complaint);
    // A slice without facts.
    let mut t = s.clone();
    t.binaries.clear();
    assert_eq!(binary_errors(&t), complaint);
    // A Mach-O.
    let mut t = s.clone();
    t.artifacts[0].format = Format::MachO;
    t.binaries[0].container = ContainerFacts::MachO(MachOFacts {
        is_64: true,
        cpu_type: 0x0100_0007,
        cpu_subtype: 3,
        fat_cpu_type: None,
        fat_cpu_subtype: None,
        fat_alignment: None,
        file_type: 6,
        flags: 0,
        uuid: None,
        id_dylib: None,
        load_dylibs: vec![],
        rpaths: vec![],
        dylinker: None,
    });
    assert_eq!(binary_errors(&t), complaint);
    // Partial says what was not scanned: nothing to check.
    let t = with_install_identity(
        install_session(),
        partial(&["lib/ollama/libggml.so.0.13.1: string scan: a read failed"]),
    );
    assert_eq!(binary_errors(&t), Vec::<String>::new());
}

/// A hint on example 15's shared object.
fn with_hint(mut s: Session, signal: Signal, value: &str, at: Loc) -> Session {
    let slice = s.binaries[0].slice.clone();
    s.hints.push(FeatureHint {
        subject: slice,
        feature: FeatureKey::new("x.feature").unwrap(),
        signal,
        value: UntrustedText::new(value),
        at,
    });
    s
}

fn section(name: &str) -> Loc {
    Loc::Section {
        name: UntrustedText::new(name),
        offset: 16,
    }
}

#[test]
fn s3_a_signature_hint_is_where_its_kind_is_found() {
    let go = || {
        let mut s = elf_session();
        s.binaries[0].go = Some(GoBuildInfo {
            version: UntrustedText::new("go1.24.1"),
            path: None,
            main: None,
            deps: vec![],
            settings: vec![],
            at: Loc::VAddr(0x4000),
        });
        s
    };
    let ok = [
        with_hint(
            elf_session(),
            Signal::Export,
            "ggml_backend_rpc_init",
            Loc::Symbol(UntrustedText::new("ggml_backend_rpc_init")),
        ),
        with_hint(go(), Signal::GoFunction, "main.f", section(".gopclntab")),
        with_hint(elf_session(), Signal::String, "s", section(".rodata")),
        with_hint(
            elf_session(),
            Signal::String,
            "s",
            section(".rodata.str1.1"),
        ),
        with_hint(elf_session(), Signal::String, "s", section(".lrodata")),
    ];
    for s in &ok {
        assert_eq!(code_errors(s), Vec::<String>::new(), "{:?}", s.hints);
    }
    let slice = elf_session().binaries[0].slice.clone();
    let at = format!("hints[x.feature on {slice}]");
    for (s, why) in [
        (
            with_hint(
                elf_session(),
                Signal::Export,
                "ggml_backend_rpc_init",
                Loc::Symbol(UntrustedText::new("other")),
            ),
            "an export hint's at must be Symbol(value)",
        ),
        (
            with_hint(go(), Signal::GoFunction, "main.f", section(".rodata")),
            "a Go function hint's at must be in .gopclntab",
        ),
        (
            with_hint(
                elf_session(),
                Signal::GoFunction,
                "main.f",
                section(".gopclntab"),
            ),
            "a Go function hint needs Go build info in its slice",
        ),
        (
            with_hint(elf_session(), Signal::String, "s", section(".data")),
            "a string hint's at must be in .rodata, .rodata.*, or .lrodata",
        ),
        (
            with_hint(elf_session(), Signal::String, "s", section(".rodatax")),
            "a string hint's at must be in .rodata, .rodata.*, or .lrodata",
        ),
    ] {
        assert_eq!(code_errors(&s), [format!("{at}: {why}")], "{why}");
    }
    // A Mach-O slice has no signature hint.
    let mut s = with_hint(elf_session(), Signal::String, "s", section(".rodata"));
    s.binaries[0].container = ContainerFacts::MachO(MachOFacts {
        is_64: true,
        cpu_type: 0x0100_0007,
        cpu_subtype: 3,
        fat_cpu_type: None,
        fat_cpu_subtype: None,
        fat_alignment: None,
        file_type: 6,
        flags: 0,
        uuid: None,
        id_dylib: None,
        load_dylibs: vec![],
        rpaths: vec![],
        dylinker: None,
    });
    assert!(code_errors(&s)
        .iter()
        .any(|e| e.ends_with("a signature hint needs ELF facts for its slice")));
}
