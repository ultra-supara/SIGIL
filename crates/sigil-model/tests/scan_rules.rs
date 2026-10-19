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

/// A `binary.identity` entry of `state`, as [`ExpectedIdentity::admits`] judges it.
fn entry(state: CoverageState) -> Coverage {
    Coverage {
        check: CheckId::new(BINARY_IDENTITY).unwrap(),
        scope: Ref::Audit,
        state,
        budget: None,
    }
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

fn go_info() -> GoBuildInfo {
    GoBuildInfo {
        version: UntrustedText::new("go1.24.1"),
        path: None,
        main: None,
        deps: vec![],
        settings: vec![],
        at: Loc::VAddr(0x4000),
    }
}

fn macho() -> ContainerFacts {
    ContainerFacts::MachO(MachOFacts {
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
    })
}

/// `s` with its first binary's facts as an ELF without a section header table (`stripped`
/// `None`, with the gap B8 asks for, which a `binary.container` entry lists), and with Go build
/// info when `go`.
fn without_sections(mut s: Session, go: bool) -> Session {
    let gap = "sections: no section header table".to_string();
    let ContainerFacts::Elf(elf) = &mut s.binaries[0].container else {
        panic!("an ELF");
    };
    elf.stripped = None;
    s.binaries[0].gaps.push(gap.clone());
    if go {
        s.binaries[0].go = Some(go_info());
    }
    for c in s
        .coverage
        .iter_mut()
        .filter(|c| c.check.as_str() == BINARY_CONTAINER)
    {
        c.state = partial(&[&gap]);
    }
    s
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

/// S1's errors: those about a `binary.identity` entry.
fn identity_errors(s: &Session) -> Vec<String> {
    input_errors(s)
        .into_iter()
        .filter(|e| e.contains("coverage[binary.identity on "))
        .collect()
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
    let scanned = |name_and_hash_only, no_sections| {
        Ok(ExpectedIdentity::Scanned {
            limit: LIMIT,
            name_and_hash_only,
            no_sections,
        })
    };
    // An ELF with facts, and a section header table.
    let s = elf_session();
    assert_eq!(expected(&s), scanned(false, NoSectionsGap::Never));
    // Without a section header table: with Go build info, the Go-function needles of the
    // embedded database look for `.gopclntab`, so the scan's gap is required.
    assert_eq!(
        expected(&without_sections(s.clone(), false)),
        scanned(false, NoSectionsGap::May)
    );
    assert_eq!(
        expected(&without_sections(s.clone(), true)),
        scanned(false, NoSectionsGap::Must)
    );
    // Claimed as an NVIDIA library.
    for key in NAME_AND_HASH_ONLY {
        let mut t = s.clone();
        t.components[0].component = ComponentKey::new(key).unwrap();
        assert_eq!(expected(&t), scanned(true, NoSectionsGap::Never), "{key}");
    }
    let mut t = s.clone();
    t.components[0].component = ComponentKey::new("ggml-backend/cuda").unwrap();
    assert_eq!(expected(&t), scanned(false, NoSectionsGap::Never));
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
    assert_eq!(expected(&t), scanned(false, NoSectionsGap::Never));
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
    // An ELF without slices.
    let mut t = s.clone();
    t.artifacts[0].slices.clear();
    assert_eq!(
        expected(&t),
        Ok(ExpectedIdentity::Exactly(partial(&[BINARY_NOT_PARSED])))
    );
    // A Mach-O, and a fat Mach-O.
    for format in [Format::MachO, Format::MachOFat] {
        let mut t = s.clone();
        t.artifacts[0].format = format;
        assert_eq!(
            expected(&t),
            Ok(ExpectedIdentity::Exactly(CoverageState::Unsupported {
                what: SCAN_ELF_ONLY.to_string(),
            })),
            "{format:?}"
        );
    }
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
    let scanned = |name_and_hash_only, no_sections| ExpectedIdentity::Scanned {
        limit: LIMIT,
        name_and_hash_only,
        no_sections,
    };
    let admits = |e: &ExpectedIdentity, state: &CoverageState| e.admits(&entry(state.clone()));
    let over = scan_over_gap(LIMIT);
    for name_and_hash_only in [false, true] {
        let e = scanned(name_and_hash_only, NoSectionsGap::Never);
        assert_eq!(admits(&e, &CoverageState::Complete), Ok(()));
        // The engine's form: sorted, without repeats.
        assert_eq!(
            admits(&e, &partial(&[SCAN_NAME_NOT_READ, SCAN_READ_FAILED, &over])),
            Ok(())
        );
        for wrong in [
            partial(&[]),
            partial(&[SCAN_READ_FAILED, BINARY_NOT_PARSED]),
            partial(&[&scan_over_gap(1)]),
            // Not sorted, or a gap twice.
            partial(&[&over, SCAN_READ_FAILED]),
            partial(&[SCAN_READ_FAILED, SCAN_READ_FAILED]),
            // With a section header table, the scan never misses one.
            partial(&[SCAN_NO_SECTIONS]),
            CoverageState::Unsupported {
                what: SCAN_ELF_ONLY.to_string(),
            },
            CoverageState::OutOfScope {
                why: "another reason".to_string(),
            },
        ] {
            assert!(admits(&e, &wrong).is_err(), "{wrong:?}");
        }
        // No section header table: the gap may be there; for a Go ELF it must be.
        let may = scanned(name_and_hash_only, NoSectionsGap::May);
        for state in [
            CoverageState::Complete,
            partial(&[SCAN_READ_FAILED]),
            partial(&[SCAN_NO_SECTIONS]),
        ] {
            assert_eq!(admits(&may, &state), Ok(()), "{state:?}");
        }
        let must = scanned(name_and_hash_only, NoSectionsGap::Must);
        assert_eq!(admits(&must, &partial(&[&over, SCAN_NO_SECTIONS])), Ok(()));
        for wrong in [CoverageState::Complete, partial(&[SCAN_READ_FAILED])] {
            assert!(admits(&must, &wrong).is_err(), "{wrong:?}");
        }
        assert_eq!(
            admits(&must, &out_of_scope()).is_ok(),
            name_and_hash_only,
            "an NVIDIA library is out of scope with or without sections"
        );
    }
    assert_eq!(
        admits(&scanned(true, NoSectionsGap::Never), &out_of_scope()),
        Ok(())
    );
    assert_eq!(
        admits(&scanned(false, NoSectionsGap::Never), &out_of_scope()),
        Err(format!(
            "binary.identity is out of scope: {NAME_AND_HASH_ONLY_WHY}, but the input implies complete, or partial with sorted, unique scan gaps ({BINARY_SCAN_BYTES} {LIMIT}) other than {SCAN_NO_SECTIONS:?}"
        ))
    );
    assert_eq!(
        admits(&scanned(true, NoSectionsGap::Must), &CoverageState::Complete),
        Err(format!(
            "binary.identity is complete, but the input implies partial with sorted, unique scan gaps ({BINARY_SCAN_BYTES} {LIMIT}) among them {SCAN_NO_SECTIONS:?}, or out of scope (ADR-010)"
        ))
    );
    // The scan's limit is in its gap: the entry names no budget (P-h).
    let mut budgeted = entry(CoverageState::Complete);
    budgeted.budget = Some(BudgetUse {
        budget: BINARY_SCAN_BYTES.to_string(),
        used: 1,
        limit: LIMIT,
    });
    for e in [
        scanned(false, NoSectionsGap::Never),
        ExpectedIdentity::Exactly(CoverageState::Complete),
    ] {
        assert_eq!(
            e.admits(&budgeted),
            Err(
                "binary.identity is complete and names a budget; the scan's limit is in its gap"
                    .to_string()
            ),
            "{e:?}"
        );
    }
    let unsupported = CoverageState::Unsupported {
        what: SCAN_ELF_ONLY.to_string(),
    };
    let exactly = ExpectedIdentity::Exactly(unsupported.clone());
    assert_eq!(admits(&exactly, &unsupported), Ok(()));
    assert_eq!(
        admits(&exactly, &CoverageState::Complete),
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
    // A budget.
    let mut t = s.clone();
    t.coverage.last_mut().unwrap().budget = Some(BudgetUse {
        budget: "bogus".to_string(),
        used: 999,
        limit: 1,
    });
    assert_eq!(
        input_errors(&t),
        [format!(
            "{at}: binary.identity is complete and names a budget; the scan's limit is in its gap"
        )]
    );
    // Without the budget.
    let mut t = s.clone();
    t.request.budgets.remove(BINARY_SCAN_BYTES);
    assert_eq!(
        input_errors(&t),
        [format!(
            "{at}: an ELF input without a binary_scan_bytes budget"
        )]
    );
    // A Go ELF without section headers is never Complete: its scan could not look in
    // `.gopclntab` (review P6).
    let t = with_identity(
        without_sections(elf_session(), true),
        CoverageState::Complete,
    );
    assert_eq!(identity_errors(&t).len(), 1, "{:?}", input_errors(&t));
    assert!(identity_errors(&t)[0].contains(SCAN_NO_SECTIONS));
    let t = with_identity(
        without_sections(elf_session(), true),
        partial(&[SCAN_NO_SECTIONS]),
    );
    assert_eq!(input_errors(&t), Vec::<String>::new());
    // An ELF without slices was not parsed.
    let mut t = elf_session();
    t.artifacts[0].slices.clear();
    let complete = with_identity(t.clone(), CoverageState::Complete);
    assert!(identity_errors(&complete)[0].contains("but the input implies partial: not parsed"));
    let not_parsed = with_identity(t, partial(&[BINARY_NOT_PARSED]));
    assert_eq!(identity_errors(&not_parsed), Vec::<String>::new());
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

#[test]
fn s1_says_nothing_of_an_input_b9_cannot_judge() {
    let s = with_identity(elf_session(), CoverageState::Complete);
    // Over binary_bytes, while its binary.container entry says Complete: B9's error, once
    // (review P1).
    let mut t = s.clone();
    t.instances[0].content = InstanceContent::NotRead {
        why: NotReadReason::BudgetExceeded,
    };
    assert!(!input_errors(&t).is_empty());
    assert_eq!(identity_errors(&t), Vec::<String>::new());
    // Not read for another reason: a fatal input error, never part of a session.
    let mut t = s.clone();
    t.instances[0].content = InstanceContent::NotRead {
        why: NotReadReason::NotFollowed,
    };
    assert!(!input_errors(&t).is_empty());
    assert_eq!(identity_errors(&t), Vec::<String>::new());
    // Its artifact is not in the session.
    let mut t = s.clone();
    t.artifacts.clear();
    assert!(!input_errors(&t).is_empty());
    assert_eq!(identity_errors(&t), Vec::<String>::new());
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
        "binaries[*]: artifacts.identity is Complete, but discovery is not Complete, an install binary is a Mach-O, a slice has no facts, or a Go ELF has no section headers".to_string(),
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
    // An ELF without slices.
    let mut t = s.clone();
    t.artifacts[0].slices.clear();
    t.binaries.clear();
    t.components.clear();
    assert_eq!(binary_errors(&t), complaint);
    // A Mach-O, and a fat Mach-O.
    for format in [Format::MachO, Format::MachOFat] {
        let mut t = s.clone();
        t.artifacts[0].format = format;
        t.binaries[0].container = macho();
        assert!(binary_errors(&t).contains(&complaint[0]), "{format:?}");
    }
    // A Go ELF without section headers (review item 2), unless it is an NVIDIA library, which
    // is never scanned and adds no gap.
    let mut t = without_sections(s.clone(), true);
    assert_eq!(binary_errors(&t), complaint);
    t.components[0].component = ComponentKey::new("cuda-runtime").unwrap();
    assert_eq!(binary_errors(&t), Vec::<String>::new());
    let t = without_sections(s.clone(), false);
    assert_eq!(binary_errors(&t), Vec::<String>::new());
    // Partial says what was not scanned: nothing to check.
    let t = with_install_identity(
        install_session(),
        partial(&["lib/ollama/libggml.so.0.13.1: string scan: a read failed"]),
    );
    assert_eq!(binary_errors(&t), Vec::<String>::new());
}

#[test]
fn s2_artifacts_identity_is_one_install_entry_that_never_closes_by_another_state() {
    let install = || install_session();
    let shown = |state: &str| {
        vec![format!(
            "binaries[*]: artifacts.identity is {state}, but it is complete, partial, the discovery's state when discovery did not finish, or skipped without an install"
        )]
    };
    // Out of scope or not present would close the required check (review P3).
    let t = with_install_identity(
        install(),
        CoverageState::OutOfScope {
            why: "x".to_string(),
        },
    );
    assert_eq!(binary_errors(&t), shown("out of scope: x"));
    let t = with_install_identity(
        install(),
        CoverageState::NotPresent {
            evidence: vec![],
            scope: "the install".to_string(),
            basis: AbsenceBasis::SymbolsAbsent { names: vec![] },
        },
    );
    assert_eq!(binary_errors(&t), shown("not present in the install"));
    assert_eq!(
        binary_errors(&with_install_identity(install(), partial(&[]))),
        shown("partial: ")
    );
    // The discovery's state, when discovery did not finish: that state exactly.
    let unavailable = CoverageState::Unavailable {
        why: Unavailability::NotFound,
    };
    let mut t = install();
    t.coverage
        .iter_mut()
        .find(|c| c.check.as_str() == ARTIFACTS_DISCOVERY)
        .unwrap()
        .state = unavailable.clone();
    assert_eq!(
        binary_errors(&with_install_identity(t.clone(), unavailable)),
        Vec::<String>::new()
    );
    let error = CoverageState::Error {
        message: UntrustedText::new("x"),
    };
    assert_eq!(
        binary_errors(&with_install_identity(t, error.clone())),
        shown("error: x")
    );
    assert_eq!(
        binary_errors(&with_install_identity(install(), error)),
        shown("error: x")
    );
    // One entry, scoped to the install root.
    let t = with_install_identity(
        with_install_identity(install(), CoverageState::Complete),
        CoverageState::Complete,
    );
    assert_eq!(
        binary_errors(&t),
        ["binaries[*]: 2 artifacts.identity entries; a session has at most one"]
    );
    let mut t = with_install_identity(install(), CoverageState::Complete);
    t.coverage.last_mut().unwrap().scope = Ref::Audit;
    assert_eq!(
        binary_errors(&t),
        ["binaries[*]: artifacts.identity must be scoped to the install root"]
    );
    // Skipped, for the audit, without an install (P-m).
    let skipped = CoverageState::Skipped {
        by: SkipReason::Flag {
            flag: "--install-dir".to_string(),
        },
    };
    let mut no_install = elf_session();
    no_install.coverage.push(Coverage {
        check: CheckId::new(ARTIFACTS_IDENTITY).unwrap(),
        scope: Ref::Audit,
        state: skipped.clone(),
        budget: None,
    });
    assert_eq!(binary_errors(&no_install), Vec::<String>::new());
    let mut t = with_install_identity(install(), skipped);
    t.coverage.last_mut().unwrap().scope = Ref::Audit;
    assert_eq!(
        binary_errors(&t),
        ["binaries[*]: artifacts.identity is skipped: --install-dir, but only a session without an install skips it, for --install-dir"]
    );
    let mut t = no_install.clone();
    t.coverage.last_mut().unwrap().state = CoverageState::Skipped {
        by: SkipReason::ModeDisabled,
    };
    assert_eq!(
        binary_errors(&t),
        ["binaries[*]: artifacts.identity is skipped: not run in this mode, but only a session without an install skips it, for --install-dir"]
    );
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
        s.binaries[0].go = Some(go_info());
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
    s.binaries[0].container = macho();
    assert!(code_errors(&s)
        .iter()
        .any(|e| e.ends_with("a signature hint needs ELF facts for its slice")));
}

#[test]
fn s3_an_input_not_scanned_has_no_signature_hint() {
    // An NVIDIA library, out of scope (ADR-010): never scanned (review P4).
    let mut nvidia = elf_session();
    nvidia.components[0].component = ComponentKey::new("cuda-runtime").unwrap();
    let nvidia = with_identity(nvidia, out_of_scope());
    assert_eq!(code_errors(&nvidia), Vec::<String>::new());
    let slice = nvidia.binaries[0].slice.clone();
    let at = format!("hints[x.feature on {slice}]");
    for s in [
        with_hint(nvidia.clone(), Signal::String, "s", section(".rodata")),
        with_hint(
            nvidia.clone(),
            Signal::Export,
            "ggml_backend_rpc_init",
            Loc::Symbol(UntrustedText::new("ggml_backend_rpc_init")),
        ),
    ] {
        assert_eq!(
            code_errors(&s),
            [format!(
                "{at}: a signature hint of a slice whose input was not scanned (ADR-010)"
            )]
        );
    }
    // Its imports are the container's, not the scan's.
    let s = with_hint(
        nvidia.clone(),
        Signal::Import,
        "dlopen",
        Loc::Symbol(UntrustedText::new("dlopen")),
    );
    assert_eq!(code_errors(&s), Vec::<String>::new());
    // A scanned NVIDIA library may have them.
    let mut scanned = elf_session();
    scanned.components[0].component = ComponentKey::new("cuda-runtime").unwrap();
    let s = with_hint(
        with_identity(scanned, CoverageState::Complete),
        Signal::String,
        "s",
        section(".rodata"),
    );
    assert_eq!(code_errors(&s), Vec::<String>::new());
}
