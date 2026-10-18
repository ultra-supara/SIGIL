//! C1–C6 (PR-5a spec §5.2): code facts, `binary.code`, and hints agree with the session.

mod common;

use sigil_model::*;

/// A valid binary inspection of one x86-64 ELF input, with `binary.container` `Complete`.
fn session(code: bool) -> Session {
    let mut s = common::binary_session_one_elf();
    s.request.code = code;
    if code {
        s.request
            .budgets
            .insert(BINARY_CODE_BYTES.to_string(), 1 << 28);
        s.coverage.push(Coverage {
            check: CheckId::new(BINARY_CODE).unwrap(),
            scope: Ref::Instance(s.instances[0].id.clone()),
            state: CoverageState::Complete,
            budget: Some(BudgetUse {
                budget: BINARY_CODE_BYTES.to_string(),
                used: 0,
                limit: 1 << 28,
            }),
        });
    }
    s
}

fn errors(s: &Session) -> Vec<String> {
    s.validate()
        .err()
        .unwrap_or_default()
        .iter()
        .map(ToString::to_string)
        .collect()
}

/// The C1–C6 errors only.
fn code_errors(s: &Session) -> Vec<String> {
    s.validate()
        .err()
        .unwrap_or_default()
        .iter()
        .filter(|e| matches!(e, ValidationError::Code { .. }))
        .map(ToString::to_string)
        .collect()
}

fn binary_code(s: &mut Session) -> &mut Coverage {
    s.coverage
        .iter_mut()
        .find(|c| c.check.as_str() == BINARY_CODE)
        .unwrap()
}

fn connect_call(slice: &SliceId) -> CodeFacts {
    CodeFacts {
        slice: slice.clone(),
        functions: vec![Function {
            id: FnId::new("fn:0x1000").unwrap(),
            entry: 0x1000,
            end: 0x1020,
            bounds: BoundsSource::EhFrameFde,
            names: vec![UntrustedText::new("kernel")],
        }],
        call_sites: vec![CallSite {
            id: CallId::new("cs:0x1008").unwrap(),
            caller: FnId::new("fn:0x1000").unwrap(),
            addr: 0x1008,
            kind: CallKind::Call,
            target: CallTarget::Import {
                symbol: UntrustedText::new("connect"),
                via: ImportVia::Plt,
            },
            args: vec![
                ArgValue::Low {
                    reg: Reg::Rdi,
                    value: Box::new(ArgValue::Param {
                        reg: Reg::Rdi,
                        index: 0,
                    }),
                    bits: 32,
                },
                ArgValue::ConstInt {
                    reg: Reg::Rsi,
                    value: 0,
                },
                ArgValue::ConstInt {
                    reg: Reg::Rdx,
                    value: 0,
                },
            ],
        }],
        predicate_checks: vec![],
        close_checks: vec![],
        guard_regions: vec![],
        param_mappings: vec![],
    }
}

#[test]
fn the_helpers_are_valid_binary_inspections() {
    for (name, s) in [
        ("one ELF", common::binary_session_one_elf()),
        ("one unsupported", common::binary_session_one_unsupported()),
    ] {
        assert!(is_binary_inspection(&s.request), "{name}");
        assert_eq!(s.instances.len(), 1, "{name}");
        assert_eq!(errors(&s), Vec::<String>::new(), "{name}");
    }
    let s = common::binary_session_one_elf();
    let ContainerFacts::Elf(elf) = &s.binaries[0].container else {
        panic!("an ELF");
    };
    assert!(elf
        .imports
        .iter()
        .any(|i| i.name == UntrustedText::new("connect")));
}

#[test]
fn request_code_is_optional_on_read_and_always_written() {
    let s = session(false);
    let mut value = serde_json::to_value(&s).unwrap();
    assert_eq!(value["request"]["code"], serde_json::json!(false));
    value["request"].as_object_mut().unwrap().remove("code");
    let read: Session = serde_json::from_value(value).unwrap();
    assert!(!read.request.code);
    assert_eq!(read, s);
}

#[test]
fn a_session_with_code_validates() {
    let mut s = session(true);
    let slice = s.artifacts[0].slices[0].id.clone();
    s.code.push(connect_call(&slice));
    s.canonicalize();
    assert_eq!(errors(&s), Vec::<String>::new());
}

#[test]
fn c1_code_facts_need_request_code() {
    let mut s = session(false);
    let slice = s.artifacts[0].slices[0].id.clone();
    s.code.push(connect_call(&slice));
    assert!(
        errors(&s)
            .iter()
            .any(|e| e.contains("code facts need request.code")),
        "{:?}",
        errors(&s)
    );
}

/// C1 and C4 are about a binary inspection's code. The golden examples of an install session
/// carry the M1 analyzer's code facts (plan §4.6.5), and the model change is additive (spec §5).
#[test]
fn c1_and_c4_leave_the_code_of_an_install_session_alone() {
    let mut seen = 0;
    for (name, s) in common::examples() {
        if s.code.is_empty() || is_binary_inspection(&s.request) {
            continue;
        }
        seen += 1;
        assert!(!s.request.code, "{name}");
        assert_eq!(code_errors(&s), Vec::<String>::new(), "{name}");
    }
    assert!(seen > 0, "no install example has code facts");
}

#[test]
fn c2_one_binary_code_entry_per_input_with_code_and_none_without() {
    let mut s = session(true);
    s.coverage.retain(|c| c.check.as_str() != BINARY_CODE);
    assert!(
        errors(&s)
            .iter()
            .any(|e| e.contains("0 binary.code entries")),
        "{:?}",
        errors(&s)
    );
    let mut s = session(true);
    let again = binary_code(&mut s).clone();
    s.coverage.push(again);
    assert!(
        errors(&s)
            .iter()
            .any(|e| e.contains("2 binary.code entries")),
        "{:?}",
        errors(&s)
    );
    let mut s = session(false);
    let mut with = session(true);
    s.coverage.push(with.coverage.pop().unwrap());
    assert!(
        errors(&s)
            .iter()
            .any(|e| e.contains("binary.code without request.code")),
        "{:?}",
        errors(&s)
    );
}

#[test]
fn c2_a_binary_code_entry_is_scoped_to_an_input() {
    let mut s = session(true);
    let mut stray = binary_code(&mut s).clone();
    stray.scope = Ref::Audit;
    s.coverage.push(stray);
    assert!(
        errors(&s)
            .iter()
            .any(|e| e.contains("binary.code must be scoped to an input's instance")),
        "{:?}",
        errors(&s)
    );
}

#[test]
fn c3_an_unsupported_container_gives_the_same_state() {
    let mut s = common::binary_session_one_unsupported(); // container Unsupported
    s.request.code = true;
    s.request
        .budgets
        .insert(BINARY_CODE_BYTES.to_string(), 1 << 28);
    s.coverage.push(Coverage {
        check: CheckId::new(BINARY_CODE).unwrap(),
        scope: Ref::Instance(s.instances[0].id.clone()),
        state: CoverageState::Complete,
        budget: None,
    });
    rejected_by_c3(&s, "binary.code is complete, but the input implies unsupported: not a supported ELF or Mach-O container");
    // The container's state, exactly: valid.
    binary_code(&mut s).state = CoverageState::Unsupported {
        what: BINARY_UNSUPPORTED.to_string(),
    };
    assert_eq!(code_errors(&s), Vec::<String>::new());
    // A copied state names no budget: no code is read.
    binary_code(&mut s).budget = code_bytes(0, LIMIT);
    rejected_by_c3(&s, "names a budget");
}

#[test]
fn c3_an_analyzed_input_names_binary_code_bytes_with_the_request_limit() {
    let mut s = session(true);
    binary_code(&mut s).budget = Some(BudgetUse {
        budget: BINARY_CODE_BYTES.to_string(),
        used: 0,
        limit: 7,
    });
    rejected_by_c3(
        &s,
        "its binary_code_bytes limit is 7, not the request's 268435456",
    );
    let mut s = session(true);
    binary_code(&mut s).budget = None;
    rejected_by_c3(
        &s,
        "binary.code is complete without a binary_code_bytes budget",
    );
    // Partial is analyzed too.
    let mut s = session(true);
    binary_code(&mut s).state = CoverageState::Partial {
        missing: vec!["code: function at 0x1000: values did not settle".to_string()],
    };
    assert_eq!(code_errors(&s), Vec::<String>::new());
}

#[test]
fn c3_admits_unsupported_for_an_x86_64_elf() {
    let mut s = session(true);
    let c = binary_code(&mut s);
    c.state = CoverageState::Unsupported {
        what: CODE_UNSUPPORTED.to_string(),
    };
    c.budget = None;
    assert_eq!(errors(&s), Vec::<String>::new());
}

#[test]
fn c3_another_arch_is_unsupported() {
    let mut s = session(true);
    s.artifacts[0].slices[0].arch = Arch::Aarch64;
    rejected_by_c3(
        &s,
        "binary.code is complete, but the input implies unsupported: code analysis",
    );
    let c = binary_code(&mut s);
    c.state = CoverageState::Unsupported {
        what: CODE_UNSUPPORTED.to_string(),
    };
    c.budget = None;
    assert_eq!(code_errors(&s), Vec::<String>::new());
}

#[test]
fn c4_code_facts_only_for_analyzed_inputs() {
    let mut s = session(true);
    let slice = s.artifacts[0].slices[0].id.clone();
    let c = binary_code(&mut s);
    c.state = CoverageState::Unsupported {
        what: CODE_UNSUPPORTED.to_string(),
    };
    c.budget = None;
    s.code.push(connect_call(&slice));
    assert!(
        errors(&s).iter().any(|e| e.contains("not analyzed")),
        "{:?}",
        errors(&s)
    );
}

#[test]
fn c5_widths_low_bits_and_sets() {
    let param = || {
        Box::new(ArgValue::Param {
            reg: Reg::Rdi,
            index: 0,
        })
    };
    for (arg, why) in [
        (
            ArgValue::Load {
                reg: Reg::Rdi,
                base: param(),
                offset: 8,
                width: 12,
                site: 0x1004,
            },
            "a Load width is 8, 16, 32, or 64, not 12",
        ),
        (
            ArgValue::Low {
                reg: Reg::Rdi,
                value: param(),
                bits: 64,
            },
            "Low bits are 8, 16, or 32, not 64",
        ),
        (
            ArgValue::Low {
                reg: Reg::Rdi,
                value: Box::new(ArgValue::Low {
                    reg: Reg::Rdi,
                    value: param(),
                    bits: 8,
                }),
                bits: 32,
            },
            "a Low's value is a Low",
        ),
        (
            ArgValue::Set {
                reg: Reg::Rdi,
                members: vec![ArgValue::ConstInt {
                    reg: Reg::Rdi,
                    value: 1,
                }],
            },
            "a Set has 2 to 4 members, not 1",
        ),
        (
            ArgValue::Set {
                reg: Reg::Rdi,
                members: vec![
                    ArgValue::ConstInt {
                        reg: Reg::Rdi,
                        value: 1,
                    },
                    ArgValue::Unknown {
                        reg: Reg::Rdi,
                        reason: ValueUnknown::NotModeled,
                    },
                ],
            },
            "no Set or Unknown member, but member 1 is Unknown",
        ),
        (
            ArgValue::Set {
                reg: Reg::Rdi,
                members: vec![
                    ArgValue::ConstInt {
                        reg: Reg::Rdi,
                        value: 1,
                    },
                    ArgValue::Set {
                        reg: Reg::Rdi,
                        members: (2..4)
                            .map(|value| ArgValue::ConstInt {
                                reg: Reg::Rdi,
                                value,
                            })
                            .collect(),
                    },
                ],
            },
            "no Set or Unknown member, but member 1 is a Set",
        ),
        (
            ArgValue::Set {
                reg: Reg::Rdi,
                members: (0..5)
                    .map(|value| ArgValue::ConstInt {
                        reg: Reg::Rdi,
                        value,
                    })
                    .collect(),
            },
            "a Set has 2 to 4 members, not 5",
        ),
        (
            // Nested in an indirect call's target, inside a Load's base.
            ArgValue::Load {
                reg: Reg::Rdi,
                base: Box::new(ArgValue::Low {
                    reg: Reg::Rdi,
                    value: param(),
                    bits: 1,
                }),
                offset: 0,
                width: 64,
                site: 0x1004,
            },
            "Low bits are 8, 16, or 32, not 1",
        ),
    ] {
        let mut s = session(true);
        let slice = s.artifacts[0].slices[0].id.clone();
        let mut facts = connect_call(&slice);
        facts.call_sites[0].args[0] = arg.clone();
        s.code.push(facts);
        assert!(
            errors(&s).iter().any(|e| e.contains(why)),
            "{why}: {:?}",
            errors(&s)
        );
        // The same value as an indirect call's target.
        let mut s = session(true);
        let mut facts = connect_call(&slice);
        facts.call_sites[0].target = CallTarget::Indirect { value: arg };
        s.code.push(facts);
        assert!(
            errors(&s).iter().any(|e| e.contains(why)),
            "{why} (indirect): {:?}",
            errors(&s)
        );
    }
    // Each allowed width, and a Set of 2 to 4 known members, is valid.
    for width in [8, 16, 32, 64] {
        let mut s = session(true);
        let slice = s.artifacts[0].slices[0].id.clone();
        let mut facts = connect_call(&slice);
        facts.call_sites[0].args[0] = ArgValue::Load {
            reg: Reg::Rdi,
            base: param(),
            offset: 8,
            width,
            site: 0x1004,
        };
        facts.call_sites[0].args[1] = ArgValue::Set {
            reg: Reg::Rsi,
            members: (0..4)
                .map(|value| ArgValue::ConstInt {
                    reg: Reg::Rsi,
                    value,
                })
                .collect(),
        };
        s.code.push(facts);
        assert_eq!(errors(&s), Vec::<String>::new(), "width {width}");
    }
}

#[test]
fn c6_an_import_hint_names_an_import_of_its_slice() {
    let mut s = session(false);
    let slice = s.artifacts[0].slices[0].id.clone();
    s.hints.push(FeatureHint {
        subject: slice.clone(),
        feature: FeatureKey::new("posix.network").unwrap(),
        signal: Signal::Import,
        value: UntrustedText::new("connect"),
        at: Loc::Symbol(UntrustedText::new("connect")),
    });
    // The helper's ELF imports connect (see common): valid.
    assert_eq!(errors(&s), Vec::<String>::new());
    s.hints[0].value = UntrustedText::new("socket");
    s.hints[0].at = Loc::Symbol(UntrustedText::new("socket"));
    assert!(
        errors(&s).iter().any(|e| e.contains("not an import")),
        "{:?}",
        errors(&s)
    );
    s.hints[0].value = UntrustedText::new("connect");
    assert!(
        errors(&s).iter().any(|e| e.contains("at must be Symbol")),
        "{:?}",
        errors(&s)
    );
    // Another signal is not C6's.
    s.hints[0].signal = Signal::String;
    assert_eq!(code_errors(&s), Vec::<String>::new());
}

#[test]
fn c1_request_code_is_only_for_a_binary_inspection() {
    for s in [common::complete_pass(), common::store_and_runtime()] {
        let mut s = s;
        assert!(!is_binary_inspection(&s.request));
        assert_eq!(code_errors(&s), Vec::<String>::new());
        s.request.code = true;
        assert!(
            code_errors(&s)
                .iter()
                .any(|e| e.contains("request.code is only for a binary inspection")),
            "{:?}",
            code_errors(&s)
        );
    }
    // A binary inspection may ask for code.
    assert_eq!(errors(&session(true)), Vec::<String>::new());
}

#[test]
fn every_example_validates_with_its_loads_in_bits() {
    let mut widths = vec![];
    for (name, s) in common::examples() {
        assert_eq!(errors(&s), Vec::<String>::new(), "{name}");
        for facts in &s.code {
            for atom in facts.predicate_checks.iter().flat_map(|c| &c.atoms) {
                if let ArgValue::Load { width, .. } = atom.value {
                    widths.push((name, width));
                }
            }
        }
    }
    // The M1 examples' `T` atom is a byte load.
    assert!(!widths.is_empty());
    assert!(widths.iter().all(|(_, w)| *w == 8), "{widths:?}");
}

#[test]
fn c5_checks_predicate_atoms_and_guard_comparisons_too() {
    // The M1 examples' `T` atom loads a byte: 8 bits. As 1, it is refused.
    let mut s = common::target_verified();
    let Some(ArgValue::Load { width, .. }) = s.code[0]
        .predicate_checks
        .iter_mut()
        .flat_map(|c| c.atoms.iter_mut())
        .map(|a| &mut a.value)
        .find(|v| matches!(v, ArgValue::Load { .. }))
    else {
        panic!("the example has a Load atom");
    };
    assert_eq!(*width, 8);
    *width = 1;
    assert!(
        code_errors(&s)
            .iter()
            .any(|e| e.contains("predicate_checks") && e.contains("a Load width")),
        "{:?}",
        code_errors(&s)
    );
    // A guard comparison on a Set of one member.
    let mut s = common::target_verified();
    s.code[0].guard_regions.push(GuardRegion {
        function: FnId::new("fn:0xc590").unwrap(),
        from: Loc::CallSite(CallId::new("cs:0xd303").unwrap()),
        to: CallId::new("cs:0xe26d").unwrap(),
        region: RegionKind::PerIteration,
        guards: vec![GuardBranch {
            at: 0xd4c0,
            cond: GuardCond::Compare {
                value: ArgValue::Set {
                    reg: Reg::Rax,
                    members: vec![ArgValue::ConstInt {
                        reg: Reg::Rax,
                        value: 0,
                    }],
                },
                op: CmpOp::Eq,
                constant: 0,
            },
            dominates_to: true,
            exit: ExitKind::Skip,
        }],
        converging: 0,
        indirect: vec![],
        complete: TriState::Unknown,
    });
    assert!(
        code_errors(&s)
            .iter()
            .any(|e| e.contains("guard_regions") && e.contains("2 to 4 members")),
        "{:?}",
        code_errors(&s)
    );
    // The same guard on a known value is valid.
    let region = s.code[0].guard_regions.last_mut().unwrap();
    let GuardCond::Compare { value, .. } = &mut region.guards[0].cond else {
        unreachable!()
    };
    *value = ArgValue::ReturnOf {
        reg: Reg::Rax,
        call: CallId::new("cs:0xd5a0").unwrap(),
    };
    assert_eq!(errors(&s), Vec::<String>::new());
}

// --- C3, clause by clause ------------------------------------------------------------------------

const LIMIT: u64 = 1 << 28;

fn budget(name: &str, used: u64, limit: u64) -> Option<BudgetUse> {
    Some(BudgetUse {
        budget: name.to_string(),
        used,
        limit,
    })
}

fn code_bytes(used: u64, limit: u64) -> Option<BudgetUse> {
    budget(BINARY_CODE_BYTES, used, limit)
}

fn code_unsupported() -> CoverageState {
    CoverageState::Unsupported {
        what: CODE_UNSUPPORTED.to_string(),
    }
}

/// `s` with its `binary.code` entry in `state`, with `budget`.
fn with_code(mut s: Session, state: CoverageState, budget: Option<BudgetUse>) -> Session {
    let c = binary_code(&mut s);
    c.state = state;
    c.budget = budget;
    s
}

/// `s` with its `binary.container` entry in `state`, which leaves the required check open.
fn with_container(mut s: Session, state: CoverageState) -> Session {
    s.coverage
        .iter_mut()
        .find(|c| c.check.as_str() == BINARY_CONTAINER)
        .unwrap()
        .state = state;
    s.outcome.completeness = Completeness::Incomplete {
        missing_required: vec![CheckId::new(BINARY_CONTAINER).unwrap()],
        gaps: vec![],
    };
    s
}

/// Refused by C3, at the input's `binary.code` entry, with a reason that contains `says`.
fn rejected_by_c3(s: &Session, says: &str) {
    assert!(
        code_errors(s).iter().any(|e| e
            .strip_prefix(&format!(
                "coverage[{BINARY_CODE} on {}]: ",
                s.instances[0].id
            ))
            .is_some_and(|why| why.starts_with("binary.code is ") && why.contains(says))),
        "{says}: {:?}",
        code_errors(s)
    );
}

#[test]
fn c3_the_budget_and_reason_of_an_analyzed_elf() {
    let ok = with_code(
        session(true),
        CoverageState::Complete,
        code_bytes(LIMIT, LIMIT),
    );
    assert_eq!(
        errors(&ok),
        Vec::<String>::new(),
        "used may equal the limit"
    );
    for (state, budget, says) in [
        (
            CoverageState::Complete,
            code_bytes(LIMIT + 1, LIMIT),
            "it used 268435457 of binary_code_bytes, over the limit 268435456",
        ),
        (
            CoverageState::Complete,
            budget(BINARY_BYTES, 0, LIMIT),
            "its budget is binary_bytes, not binary_code_bytes",
        ),
        (
            code_unsupported(),
            code_bytes(0, LIMIT),
            "binary.code is unsupported: code analysis: x86-64 ELF64 little-endian only and names a budget",
        ),
        (
            CoverageState::Unsupported {
                what: BINARY_UNSUPPORTED.to_string(),
            },
            None,
            "but the input implies complete or partial with binary_code_bytes (268435456), or unsupported: code analysis",
        ),
    ] {
        rejected_by_c3(&with_code(session(true), state, budget), says);
    }
}

#[test]
fn c3_a_mach_o_is_unsupported() {
    const X86_64: i32 = 0x0100_0007;
    for format in [Format::MachO, Format::MachOFat] {
        let fat = format == Format::MachOFat;
        let mut s = session(true);
        s.artifacts[0].format = format;
        s.relations
            .retain(|r| !matches!(r, Relation::Declares { .. }));
        s.binaries[0].container = ContainerFacts::MachO(MachOFacts {
            is_64: true,
            cpu_type: X86_64,
            cpu_subtype: 3,
            fat_cpu_type: fat.then_some(X86_64),
            fat_cpu_subtype: fat.then_some(3),
            fat_alignment: fat.then_some(12),
            file_type: 2,
            flags: 0,
            uuid: None,
            id_dylib: None,
            load_dylibs: vec![],
            rpaths: vec![],
            dylinker: None,
        });
        // An x86_64 slice, analyzed: refused.
        rejected_by_c3(
            &s,
            "binary.code is complete, but the input implies unsupported: code analysis",
        );
        let s = with_code(s, code_unsupported(), None);
        assert_eq!(errors(&s), Vec::<String>::new(), "{format:?}");
    }
}

#[test]
fn c3_an_input_over_binary_bytes_has_the_container_state() {
    let limit = 64u64 << 30;
    let over_bytes = CoverageState::BudgetExceeded {
        budget: BINARY_BYTES.to_string(),
        used: limit - 10,
        limit,
    };
    let over = |state: CoverageState, budget: Option<BudgetUse>| {
        let mut s = session(true);
        assert_eq!(s.request.budgets[BINARY_BYTES], limit);
        s.artifacts.clear();
        s.binaries.clear();
        s.relations.clear();
        // The claim on the slice goes with it (PR-4c-1).
        s.components.clear();
        s.instances[0].content = InstanceContent::NotRead {
            why: NotReadReason::BudgetExceeded,
        };
        with_code(with_container(s, over_bytes.clone()), state, budget)
    };
    assert_eq!(
        errors(&over(over_bytes.clone(), None)),
        Vec::<String>::new()
    );
    rejected_by_c3(
        &over(CoverageState::Complete, code_bytes(0, LIMIT)),
        "binary.code is complete, but the input implies budget exceeded: binary_bytes",
    );
    rejected_by_c3(
        &over(over_bytes.clone(), code_bytes(0, LIMIT)),
        "names a budget",
    );
    rejected_by_c3(
        &over(
            CoverageState::BudgetExceeded {
                budget: BINARY_BYTES.to_string(),
                used: limit - 9,
                limit,
            },
            None,
        ),
        "but the input implies budget exceeded: binary_bytes (68719476726 of 68719476736)",
    );
}

#[test]
fn c3_an_input_read_with_a_change_has_the_container_error() {
    let error = |message: &str| CoverageState::Error {
        message: UntrustedText::new(message),
    };
    let changed = |state: CoverageState, budget: Option<BudgetUse>| {
        let mut s = session(true);
        s.binaries.clear();
        s.relations.clear();
        s.instances[0].stability = Stability::ChangedDuringRead;
        with_code(with_container(s, error(BINARY_CHANGED)), state, budget)
    };
    assert_eq!(
        errors(&changed(error(BINARY_CHANGED), None)),
        Vec::<String>::new()
    );
    rejected_by_c3(
        &changed(CoverageState::Complete, code_bytes(0, LIMIT)),
        "binary.code is complete, but the input implies error: changed during the read",
    );
    rejected_by_c3(
        &changed(error(BINARY_VANISHED), None),
        "binary.code is error: vanished during the read, but the input implies error: changed",
    );
    rejected_by_c3(
        &changed(error(BINARY_CHANGED), code_bytes(0, LIMIT)),
        "names a budget",
    );
}

#[test]
fn c3_an_elf_without_slices_is_partial_at_best() {
    let not_parsed = || CoverageState::Partial {
        missing: vec![BINARY_NOT_PARSED.to_string()],
    };
    let unparsed = |state: CoverageState, budget: Option<BudgetUse>| {
        let mut s = session(true);
        s.artifacts[0].slices.clear();
        s.binaries.clear();
        s.relations.clear();
        // The claim on the slice goes with it (PR-4c-1).
        s.components.clear();
        with_code(with_container(s, not_parsed()), state, budget)
    };
    for (state, budget) in [
        (not_parsed(), code_bytes(0, LIMIT)),
        (code_unsupported(), None),
    ] {
        let s = unparsed(state.clone(), budget);
        assert_eq!(errors(&s), Vec::<String>::new(), "{state:?}");
    }
    rejected_by_c3(
        &unparsed(CoverageState::Complete, code_bytes(0, LIMIT)),
        "binary.code is complete, but a slice of the input was not parsed",
    );
    rejected_by_c3(
        &unparsed(not_parsed(), None),
        "binary.code is partial: not parsed without a binary_code_bytes budget",
    );
}

#[test]
fn c3_a_slice_without_facts_is_partial_at_best() {
    let not_parsed = || CoverageState::Partial {
        missing: vec![BINARY_NOT_PARSED.to_string()],
    };
    let without_facts = |state: CoverageState, budget: Option<BudgetUse>| {
        let mut s = session(true);
        s.binaries.clear();
        s.relations.clear();
        with_code(with_container(s, not_parsed()), state, budget)
    };
    assert_eq!(
        errors(&without_facts(not_parsed(), code_bytes(0, LIMIT))),
        Vec::<String>::new()
    );
    rejected_by_c3(
        &without_facts(CoverageState::Complete, code_bytes(0, LIMIT)),
        "binary.code is complete, but a slice of the input was not parsed",
    );
}

#[test]
fn request_code_needs_a_binary_code_bytes_budget() {
    let mut s = session(true);
    s.request.budgets.remove(BINARY_CODE_BYTES);
    // One error, at the request; C3 does not repeat it per input.
    assert_eq!(
        code_errors(&s),
        vec!["request: request.code without a binary_code_bytes budget".to_string()]
    );
}

#[test]
fn c3_a_missing_container_entry_is_b9s_error_only() {
    let b9 = |s: &Session| {
        assert!(
            errors(s)
                .iter()
                .any(|e| e.contains("0 binary.container entries")),
            "{:?}",
            errors(s)
        );
        assert_eq!(code_errors(s), Vec::<String>::new());
    };
    // A container not read: its state comes from the input, not from the missing entry.
    let mut s = common::binary_session_one_unsupported();
    s.request.code = true;
    s.request
        .budgets
        .insert(BINARY_CODE_BYTES.to_string(), LIMIT);
    s.coverage.retain(|c| c.check.as_str() != BINARY_CONTAINER);
    s.coverage.push(Coverage {
        check: CheckId::new(BINARY_CODE).unwrap(),
        scope: Ref::Instance(s.instances[0].id.clone()),
        state: CoverageState::Unsupported {
            what: BINARY_UNSUPPORTED.to_string(),
        },
        budget: None,
    });
    b9(&s);
    // Over binary_bytes: the state needs the entry's `used`, so only B9 speaks, whether the
    // entry is missing or in a state B9 refuses.
    let mut s = session(true);
    let limit = s.request.budgets[BINARY_BYTES];
    s.artifacts.clear();
    s.binaries.clear();
    s.relations.clear();
    s.instances[0].content = InstanceContent::NotRead {
        why: NotReadReason::BudgetExceeded,
    };
    s.coverage.retain(|c| c.check.as_str() != BINARY_CONTAINER);
    let s = with_code(
        s,
        CoverageState::BudgetExceeded {
            budget: BINARY_BYTES.to_string(),
            used: 1,
            limit,
        },
        None,
    );
    b9(&s);
    let mut s = s;
    s.coverage.push(Coverage {
        check: CheckId::new(BINARY_CONTAINER).unwrap(),
        scope: Ref::Instance(s.instances[0].id.clone()),
        state: CoverageState::Complete,
        budget: None,
    });
    let s = with_code(s, CoverageState::Complete, code_bytes(0, LIMIT));
    assert!(
        errors(&s)
            .iter()
            .any(|e| e.contains("but the input is over binary_bytes")),
        "{:?}",
        errors(&s)
    );
    assert_eq!(code_errors(&s), Vec::<String>::new());
}

#[test]
fn expected_binary_code_of_each_input() {
    let expected = |s: &Session| expected_binary_code(s, &s.instances[0]);
    let analyzable = |parsed| {
        Ok(ExpectedCode::Analyzable {
            limit: LIMIT,
            parsed,
        })
    };
    let unsupported = Ok(ExpectedCode::Exactly(code_unsupported()));
    // An x86-64 ELF.
    let s = session(true);
    assert_eq!(expected(&s), analyzable(true));
    // Its slice without facts, then without the slice.
    let mut s = session(true);
    s.binaries.clear();
    assert_eq!(expected(&s), analyzable(false));
    s.artifacts[0].slices.clear();
    assert_eq!(expected(&s), analyzable(false));
    // Another arch, a Mach-O, a fat Mach-O.
    let mut s = session(true);
    s.artifacts[0].slices[0].arch = Arch::Aarch64;
    assert_eq!(expected(&s), unsupported);
    for format in [Format::MachO, Format::MachOFat] {
        let mut s = session(true);
        s.artifacts[0].format = format;
        assert_eq!(expected(&s), unsupported, "{format:?}");
    }
    // A container not read: the container's state.
    let mut s = common::binary_session_one_unsupported();
    s.request.code = true;
    assert_eq!(
        expected(&s),
        Ok(ExpectedCode::Exactly(CoverageState::Unsupported {
            what: BINARY_UNSUPPORTED.to_string()
        })),
        "no budget is needed for an input whose code is not read"
    );
    let mut s = session(true);
    s.instances[0].stability = Stability::ChangedDuringRead;
    assert_eq!(
        expected(&s),
        Ok(ExpectedCode::Exactly(CoverageState::Error {
            message: UntrustedText::new(BINARY_CHANGED)
        }))
    );
    // Over binary_bytes: the entry's state, which has the engine's `used`.
    let mut s = session(true);
    let limit = s.request.budgets[BINARY_BYTES];
    let over = CoverageState::BudgetExceeded {
        budget: BINARY_BYTES.to_string(),
        used: 3,
        limit,
    };
    s.instances[0].content = InstanceContent::NotRead {
        why: NotReadReason::BudgetExceeded,
    };
    let mut s = with_container(s, over.clone());
    assert_eq!(expected(&s), Ok(ExpectedCode::Exactly(over)));
    let wrong = with_container(s.clone(), CoverageState::Complete);
    assert!(expected(&wrong).is_err(), "with an entry B9 refuses");
    s.coverage.retain(|c| c.check.as_str() != BINARY_CONTAINER);
    assert!(expected(&s).is_err(), "without its entry");
    // Analyzed without the budget, or without request.code: no answer.
    let mut s = session(true);
    s.request.budgets.remove(BINARY_CODE_BYTES);
    assert_eq!(
        expected(&s),
        Err("request.code without a binary_code_bytes budget".to_string())
    );
    assert!(expected(&session(false)).is_err());
}

#[test]
fn two_inputs_each_have_their_own_entry_and_slices() {
    // Example 15: an x86-64 ELF, analyzed, and a text file whose container is not read.
    let elf = InstanceId::new(common::ELF_INPUT).unwrap();
    let text = InstanceId::new(common::TEXT_INPUT).unwrap();
    let mut s = common::binary_inspect();
    s.request.code = true;
    s.request
        .budgets
        .insert(BINARY_CODE_BYTES.to_string(), LIMIT);
    for (input, state, budget) in [
        (&elf, CoverageState::Complete, code_bytes(0, LIMIT)),
        (
            &text,
            CoverageState::Unsupported {
                what: BINARY_UNSUPPORTED.to_string(),
            },
            None,
        ),
    ] {
        s.coverage.push(Coverage {
            check: CheckId::new(BINARY_CODE).unwrap(),
            scope: Ref::Instance(input.clone()),
            state,
            budget,
        });
    }
    let slice = s.artifacts[0].slices[0].id.clone();
    s.code.push(connect_call(&slice));
    s.canonicalize();
    assert_eq!(errors(&s), Vec::<String>::new());
    // C2, per input: the text file's entry dropped.
    let mut t = s.clone();
    t.coverage
        .retain(|c| !(c.check.as_str() == BINARY_CODE && c.scope == Ref::Instance(text.clone())));
    assert_eq!(
        code_errors(&t),
        vec![format!(
            "coverage[binary.code on {text}]: 0 binary.code entries; an input has exactly one"
        )]
    );
    // C4, by slice: the ELF not analyzed, its facts are refused.
    let mut t = s.clone();
    let c = t
        .coverage
        .iter_mut()
        .find(|c| c.check.as_str() == BINARY_CODE && c.scope == Ref::Instance(elf.clone()))
        .unwrap();
    c.state = code_unsupported();
    c.budget = None;
    assert_eq!(
        code_errors(&t),
        vec![format!(
            "code[{slice}]: a slice whose input was not analyzed"
        )]
    );
}
