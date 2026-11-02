//! Additive multiarchitecture contracts; no producer or decoder is enabled here.
use serde_json::{json, Value};
use sigil_model::*;

fn legacy() -> Session {
    serde_json::from_str(include_str!(
        "../../../schemas/examples/session-v1/16-binary-code.json"
    ))
    .unwrap()
}

#[test]
fn marker_and_new_register_spellings_are_readable() {
    let mut value = serde_json::to_value(legacy()).unwrap();
    value["request"]["code_analysis"] = json!("multiarch-v1");
    assert!(
        serde_json::from_value::<Session>(value).is_ok(),
        "new marker must be readable"
    );
    for name in (0..=30).map(|n| format!("x{n}")).chain(["sp".into()]) {
        let reg: Reg = serde_json::from_value(json!(name)).unwrap();
        assert_eq!(serde_json::to_value(reg).unwrap(), json!(name));
    }
}

#[test]
fn legacy_optional_fields_stay_absent() {
    let value = serde_json::to_value(legacy()).unwrap();
    assert!(value["request"].get("code_analysis").is_none());
    for facts in value["code"].as_array().unwrap() {
        for call in facts["call_sites"].as_array().unwrap() {
            assert!(call.get("args_layout").is_none());
            if let Some(import) = call["target"].get("Import") {
                assert!(import.get("macho_import").is_none());
            }
        }
    }
}

#[test]
fn legacy_json_is_byte_identical() {
    use sha2::{Digest, Sha256};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut rows = Vec::new();
    for entry in std::fs::read_dir(root.join("schemas/examples/session-v1")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|x| x != "json") {
            continue;
        }
        let raw = std::fs::read(&path).unwrap();
        let session: Session = serde_json::from_slice(&raw).unwrap();
        session.validate().unwrap();
        let canonical = session.to_canonical_json().unwrap();
        rows.push(format!(
            "{:x}  {}",
            Sha256::digest(canonical.as_bytes()),
            path.file_name().unwrap().to_str().unwrap()
        ));
    }
    rows.sort();
    let actual = rows.join("\n") + "\n";
    assert_eq!(actual, include_str!("data/multiarch-legacy-sha256.txt"));
}

const GATE: &str = "multiarch coverage validation is not enabled";

fn marked() -> Session {
    let mut s = legacy();
    s.request.code_analysis = Some(CodeAnalysis::MultiarchV1);
    s.request.budgets.remove(BINARY_SCAN_BYTES);
    s.request
        .required_checks
        .retain(|c| c.as_str() != BINARY_IDENTITY);
    s.coverage.retain(|c| c.check.as_str() != BINARY_IDENTITY);
    s.knowledge.push(code_abi::V1.knowledge().unwrap());
    s.artifacts[0].code_slice_inventory = Some(CodeSliceInventory::Complete);
    s
}

fn arm() -> Session {
    let json = serde_json::to_string(&marked())
        .unwrap()
        .replace("x86_64", "aarch64");
    let mut s: Session = serde_json::from_str(&json).unwrap();
    let ContainerFacts::Elf(e) = &mut s.binaries[0].container else {
        unreachable!()
    };
    e.abi = Some(ElfAbi {
        is_64: true,
        little_endian: true,
        machine: 183,
    });
    s.code[0].call_sites[0].args = [Reg::X0, Reg::X1, Reg::X2]
        .into_iter()
        .map(|reg| ArgValue::Unknown {
            reg,
            reason: ValueUnknown::NotModeled,
        })
        .collect();
    s.code[0].call_sites[0].args_layout = Some(ArgumentLayout::Complete);
    s
}

fn macho(arch: Arch) -> Session {
    let mut s = if arch == Arch::Aarch64 {
        arm()
    } else {
        marked()
    };
    let witness = MachOImport {
        name: UntrustedText::new("_connect"),
        library: MachOLibrary::Dylib {
            ordinal: 1,
            name: Some(UntrustedText::new(LIBSYSTEM)),
        },
        weak: true,
    };
    s.artifacts[0].format = Format::MachO;
    s.binaries[0].container = ContainerFacts::MachO(MachOFacts {
        is_64: true,
        cpu_type: if arch == Arch::Aarch64 {
            0x0100_000c
        } else {
            0x0100_0007
        },
        cpu_subtype: if arch == Arch::Aarch64 { 0 } else { 3 },
        fat_cpu_type: None,
        fat_cpu_subtype: None,
        fat_alignment: None,
        file_type: 2,
        flags: 0,
        uuid: None,
        id_dylib: None,
        load_dylibs: vec![UntrustedText::new(LIBSYSTEM)],
        rpaths: vec![],
        dylinker: None,
        imports: vec![witness.clone()],
    });
    s.hints.clear();
    s.relations.push(Relation::Declares {
        from: s.binaries[0].slice.clone(),
        needed: UntrustedText::new(LIBSYSTEM),
        kind: DeclKind::MachOLoadDylib,
    });
    s.code[0].call_sites[0].target = CallTarget::Import {
        symbol: witness.name.clone(),
        via: ImportVia::MachOReloc,
        macho_import: Some(witness),
    };
    s.code[0].call_sites[0].args_layout = Some(ArgumentLayout::Complete);
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
fn assert_contract(s: &Session) {
    let errors = errors(s);
    assert_eq!(
        errors,
        vec![format!("request.code_analysis: {GATE}")],
        "only the temporary Task 4 gate is permitted"
    );
}
fn rejects(s: &Session, needle: &str) {
    assert!(
        errors(s).iter().any(|e| e.contains(needle)),
        "expected {needle}: {:?}",
        errors(s)
    );
}

#[test]
fn marker_is_gated_until_coverage_validation_exists() {
    for s in [marked(), arm(), macho(Arch::Aarch64), macho(Arch::X86_64)] {
        assert_contract(&s);
    }
}

#[test]
fn marker_requires_code_roots_and_exact_archived_knowledge() {
    let mut s = marked();
    s.request.code = false;
    rejects(&s, "marker needs request.code");
    let mut s = marked();
    s.request.roots.clear();
    rejects(&s, "marker needs a binary or installation root");
    for case in 0..5 {
        let mut s = marked();
        let k = s.knowledge.last_mut().unwrap();
        match case {
            0 => {
                s.knowledge.pop();
            }
            1 => k.sha256 = Sha256Hex::new("00".repeat(32)).unwrap(),
            2 => k.version = "2".into(),
            3 => {
                let k = k.clone();
                s.knowledge.push(k);
            }
            _ => k.kind = KnowledgeKind::Policy,
        }
        rejects(&s, "code-abi-signatures");
    }
}

#[test]
fn marker_cannot_be_stripped() {
    for case in 0..6 {
        let mut s = legacy();
        match case {
            0 => s.artifacts[0].code_slice_inventory = Some(CodeSliceInventory::Complete),
            1 => s.code[0].functions[0].bounds = BoundsSource::MachOCompactUnwind,
            2 => s.code[0].call_sites[0].args_layout = Some(ArgumentLayout::Complete),
            3 => {
                s.code[0].call_sites[0].args[0] = ArgValue::Unknown {
                    reg: Reg::X0,
                    reason: ValueUnknown::NotModeled,
                }
            }
            4 => {
                if let CallTarget::Import { via, .. } = &mut s.code[0].call_sites[0].target {
                    *via = ImportVia::MachOGot;
                }
            }
            _ => {
                let target = macho(Arch::X86_64).code[0].call_sites[0].target.clone();
                s.code[0].call_sites[0].target = target;
            }
        }
        rejects(&s, "needs multiarch-v1");
    }
}

#[test]
fn every_nested_register_belongs_to_its_slice() {
    for (base, bad, good) in [(arm(), Reg::Rdi, Reg::X0), (marked(), Reg::X0, Reg::Rdi)] {
        let bad_value = ArgValue::ConstInt { reg: bad, value: 1 };
        let values = vec![
            bad_value.clone(),
            ArgValue::Load {
                reg: good,
                base: Box::new(bad_value.clone()),
                offset: 0,
                width: 64,
                site: 65,
            },
            ArgValue::Low {
                reg: good,
                value: Box::new(bad_value.clone()),
                bits: 32,
            },
            ArgValue::Set {
                reg: good,
                members: vec![
                    bad_value.clone(),
                    ArgValue::ConstInt {
                        reg: good,
                        value: 2,
                    },
                ],
            },
        ];
        for value in values {
            let mut s = base.clone();
            s.code[0].call_sites[0].args[0] = value.clone();
            rejects(&s, "register architecture");
            let mut s = base.clone();
            s.code[0].call_sites[0].target = CallTarget::Indirect { value };
            rejects(&s, "register architecture");
        }
    }
    let mut s = arm();
    s.code[0].call_sites[0].args[0] = ArgValue::Param {
        reg: Reg::X0,
        index: 7,
    };
    assert_contract(&s);
    s.code[0].call_sites[0].args[0] = ArgValue::Param {
        reg: Reg::X0,
        index: 8,
    };
    rejects(&s, "parameter index");
    let mut s = macho(Arch::Aarch64);
    s.code[0].call_sites[0].args[0] = ArgValue::Load {
        reg: Reg::X0,
        base: Box::new(ArgValue::Param {
            reg: Reg::X18,
            index: 0,
        }),
        offset: 0,
        width: 64,
        site: 65,
    };
    rejects(&s, "reserved x18");
    // SP is representable as an operand; neither XZR nor WZR is a recovered register.
    assert!(serde_json::from_value::<Reg>(json!("xzr")).is_err());
    assert!(serde_json::from_value::<Reg>(json!("wzr")).is_err());
}

#[test]
fn exact_macho_witness_and_bounds_are_scoped() {
    for arch in [Arch::Aarch64, Arch::X86_64] {
        let good = macho(arch);
        assert_contract(&good);
        for case in 0..6 {
            let mut s = good.clone();
            let CallTarget::Import {
                symbol,
                via,
                macho_import,
            } = &mut s.code[0].call_sites[0].target
            else {
                unreachable!()
            };
            match case {
                0 => *macho_import = None,
                1 => macho_import.as_mut().unwrap().weak = false,
                2 => macho_import.as_mut().unwrap().library = MachOLibrary::FlatLookup,
                3 => *symbol = UntrustedText::new("connect"),
                4 => *via = ImportVia::Plt,
                _ => {
                    let ContainerFacts::MachO(m) = &mut s.binaries[0].container else {
                        unreachable!()
                    };
                    m.imports.clear();
                }
            }
            rejects(&s, "Mach-O import witness");
        }
        let mut s = good.clone();
        s.code[0].functions[0].end = s.code[0].functions[0].entry;
        rejects(&s, "function bounds");
        let mut s = good.clone();
        s.code[0].call_sites[0].addr = s.code[0].functions[0].end;
        rejects(&s, "outside caller");
        let mut s = good.clone();
        s.code[0].call_sites[0].caller = FnId::new("fn:0xffff").unwrap();
        rejects(&s, "fn:0xffff");
        let mut s = good.clone();
        s.code[0].call_sites[0].args[0] = ArgValue::ReturnOf {
            reg: if arch == Arch::Aarch64 {
                Reg::X0
            } else {
                Reg::Rdi
            },
            call: CallId::new("cs:0xffff").unwrap(),
        };
        rejects(&s, "cs:0xffff");
    }
    let mut s = arm();
    s.code[0].functions[0].bounds = BoundsSource::MachOCompactUnwind;
    rejects(&s, "compact unwind requires Mach-O");
}

#[test]
fn argument_prefix_is_honest() {
    for (abi, base, symbol, count) in [
        (
            code_abi::CodeAbi::DarwinArm64,
            macho(Arch::Aarch64),
            "_open",
            2,
        ),
        (
            code_abi::CodeAbi::DarwinArm64,
            macho(Arch::Aarch64),
            "_openat",
            3,
        ),
        (
            code_abi::CodeAbi::DarwinX86_64,
            macho(Arch::X86_64),
            "_open",
            2,
        ),
        (code_abi::CodeAbi::ElfAarch64, arm(), "open", 2),
        (code_abi::CodeAbi::ElfAarch64, arm(), "openat", 3),
        (
            code_abi::CodeAbi::DarwinArm64,
            macho(Arch::Aarch64),
            "__ZN3Foo3barE3Agg",
            0,
        ),
        (code_abi::CodeAbi::ElfAarch64, arm(), "unknown_aggregate", 0),
    ] {
        let mut s = base;
        let name = UntrustedText::new(symbol);
        let library = if matches!(abi, code_abi::CodeAbi::ElfAarch64) {
            None
        } else {
            Some(MachOLibrary::Dylib {
                ordinal: 1,
                name: Some(UntrustedText::new(LIBSYSTEM)),
            })
        };
        let plan = code_abi::V1.argument_plan(Some(abi), &name, library.as_ref());
        assert_eq!(plan.registers.len(), count);
        assert!(matches!(plan.layout, ArgumentLayout::Partial { .. }));
        let call = &mut s.code[0].call_sites[0];
        let CallTarget::Import {
            symbol,
            macho_import,
            ..
        } = &mut call.target
        else {
            unreachable!()
        };
        *symbol = name.clone();
        if let Some(m) = macho_import {
            m.name = name.clone();
        }
        match &mut s.binaries[0].container {
            ContainerFacts::Elf(e) => e.imports[0].name = name,
            ContainerFacts::MachO(m) => m.imports = macho_import.clone().into_iter().collect(),
        }
        s.hints.clear();
        call.args = plan
            .registers
            .iter()
            .map(|&reg| ArgValue::Unknown {
                reg,
                reason: ValueUnknown::FromMemory,
            })
            .collect();
        call.args_layout = Some(plan.layout);
        s.binaries[0].gaps.push(plan.gap.unwrap());
        for c in &mut s.coverage {
            if matches!(c.check.as_str(), BINARY_CONTAINER | BINARY_CODE) {
                c.state = CoverageState::Partial {
                    missing: s.binaries[0].gaps.clone(),
                };
            }
        }
        s.outcome.completeness = Completeness::Incomplete {
            missing_required: vec![
                CheckId::new(BINARY_CODE).unwrap(),
                CheckId::new(BINARY_CONTAINER).unwrap(),
            ],
            gaps: vec![],
        };
        assert_contract(&s);
        let mut bad = s.clone();
        bad.code[0].call_sites[0].args_layout = Some(ArgumentLayout::Complete);
        rejects(&bad, "argument layout");
        let mut bad = s.clone();
        bad.binaries[0].gaps.clear();
        rejects(&bad, "argument layout gap");
        let mut bad = s.clone();
        bad.code[0].call_sites[0].args.push(ArgValue::ConstInt {
            reg: Reg::X2,
            value: 0o600,
        });
        rejects(&bad, "argument prefix");
    }
    // Complete establishes positions even when all three recovered values are unknown.
    assert_contract(&arm());
    let mut s = arm();
    s.code[0].call_sites[0].args.swap(0, 1);
    rejects(&s, "argument prefix");
    let mut s = arm();
    s.code[0].call_sites[0].args_layout = None;
    rejects(&s, "argument layout");
}

#[test]
fn abi_registry_hash_and_exact_lookup_are_archived() {
    use sha2::{Digest, Sha256};
    assert_eq!(
        format!("{:x}", Sha256::digest(code_abi::V1_BYTES)),
        code_abi::V1_SHA256
    );
    assert!(code_abi::archived("1", code_abi::V1_SHA256).is_some());
    assert!(code_abi::archived("2", code_abi::V1_SHA256).is_none());
    assert!(code_abi::archived("1", &"0".repeat(64)).is_none());
    let table: toml::Value = toml::from_str(code_abi::V1_BYTES).unwrap();
    let entries = table["signature"].as_array().unwrap();
    assert_eq!(entries.len(), 9);
    for entry in entries {
        let abi = match entry["abi"].as_str().unwrap() {
            "elf-aarch64" => code_abi::CodeAbi::ElfAarch64,
            "darwin-arm64" => code_abi::CodeAbi::DarwinArm64,
            "darwin-x86-64" => code_abi::CodeAbi::DarwinX86_64,
            _ => panic!("unknown ABI"),
        };
        let library =
            (entry["library"].as_str().unwrap() == "libsystem").then(|| MachOLibrary::Dylib {
                ordinal: 1,
                name: Some(UntrustedText::new(LIBSYSTEM)),
            });
        let symbol = UntrustedText::new(entry["symbol"].as_str().unwrap());
        let sig = code_abi::V1.lookup(abi, &symbol, library.as_ref()).unwrap();
        let regs: Vec<Reg> = entry["registers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| serde_json::from_value(json!(r.as_str().unwrap())).unwrap())
            .collect();
        assert_eq!(sig.registers, regs);
        assert_eq!(sig.complete, entry["complete"].as_bool().unwrap());
        for source in ["prototype_source", "abi_source"] {
            assert!(entry[source].as_str().unwrap().starts_with("https://"));
        }
        assert!(entry["prototype"].as_str().unwrap().starts_with("int "));
    }
    for library in [
        MachOLibrary::FlatLookup,
        MachOLibrary::Unbound,
        MachOLibrary::WeakLookup,
        MachOLibrary::SelfImage,
        MachOLibrary::MainExecutable,
        MachOLibrary::Dylib {
            ordinal: 0,
            name: Some(UntrustedText::new(LIBSYSTEM)),
        },
        MachOLibrary::Dylib {
            ordinal: 1,
            name: Some(UntrustedText::new("/other.dylib")),
        },
    ] {
        assert!(code_abi::V1
            .lookup(
                code_abi::CodeAbi::DarwinArm64,
                &UntrustedText::new("_connect"),
                Some(&library)
            )
            .is_none());
    }
    assert_eq!(MachOLibrary::FlatLookup.looked_up(), LookedUp::All);
    assert_eq!(MachOLibrary::Unbound.looked_up(), LookedUp::All);
}

#[allow(unused_macros)]
#[path = "support/schema_check.rs"]
mod schema_check;

#[test]
fn new_shapes_are_strict_in_serde_and_schema() {
    let schema = schema_check::load("session-v1.schema.json");
    for s in [marked(), arm(), macho(Arch::Aarch64), macho(Arch::X86_64)] {
        let value = serde_json::to_value(&s).unwrap();
        schema_check::assert_valid_against(
            &schema_check::validator_for(&schema, "Session"),
            &value,
            "marked session shape",
        );
        let read: Session = serde_json::from_value(value).unwrap();
        assert_eq!(s, read);
    }
    let fragments: Vec<(&str, Value)> = vec![
        ("CodeAnalysis", json!("multiarch-v1")),
        ("ArgumentLayout", json!("Complete")),
        (
            "ArgumentLayout",
            json!({"Partial":{"reason":"variadic stack arguments not modeled"}}),
        ),
        ("CodeSliceInventory", json!("Complete")),
        (
            "CodeSliceInventory",
            json!({"Partial":{"missing":["code: slice inventory incomplete"]}}),
        ),
        ("BoundsSource", json!("MachOCompactUnwind")),
        ("ImportVia", json!("MachOStub")),
        ("ImportVia", json!("MachOGot")),
        ("ImportVia", json!("MachOReloc")),
    ];
    for (def, value) in fragments {
        schema_check::assert_valid_against(&schema_check::validator_for(&schema, def), &value, def);
    }
    for name in (0..=30).map(|n| format!("x{n}")).chain(["sp".into()]) {
        schema_check::assert_valid_against(
            &schema_check::validator_for(&schema, "Reg"),
            &json!(name),
            "register",
        );
    }
    let validate = schema_check::validator_for(&schema, "Session");
    let base = serde_json::to_value(macho(Arch::Aarch64)).unwrap();
    for (pointer, invalid) in [
        ("/request/code_analysis", json!(null)),
        ("/request/code_analysis", json!("multiarch-v2")),
        ("/artifacts/0/code_slice_inventory", json!(null)),
        (
            "/artifacts/0/code_slice_inventory",
            json!({"Partial":{"missing":[],"extra":0}}),
        ),
        ("/code/0/call_sites/0/args_layout", json!(null)),
        (
            "/code/0/call_sites/0/args_layout",
            json!({"Partial":{"reason":"x","extra":0}}),
        ),
        (
            "/code/0/call_sites/0/target/Import/macho_import",
            json!(null),
        ),
        (
            "/code/0/call_sites/0/target/Import/macho_import/library",
            json!({"Dylib":{"ordinal":1,"name":LIBSYSTEM,"extra":0}}),
        ),
    ] {
        let mut v = base.clone();
        *v.pointer_mut(pointer).unwrap() = invalid;
        assert!(
            serde_json::from_value::<Session>(v.clone()).is_err(),
            "serde {pointer}"
        );
        assert!(!validate.is_valid(&v), "schema {pointer}");
    }
}

#[test]
fn predicates_guards_and_parameter_mappings_check_their_registers() {
    let mut s = arm();
    s.knowledge.push(KnowledgeRef {
        kind: KnowledgeKind::Profile,
        id: "test-profile".into(),
        version: "1".into(),
        sha256: Sha256Hex::new("01".repeat(32)).unwrap(),
    });
    let function = s.code[0].functions[0].id.clone();
    let call = s.code[0].call_sites[0].id.clone();
    let bad = ArgValue::Unknown {
        reg: Reg::Rax,
        reason: ValueUnknown::NotModeled,
    };
    s.code[0].predicate_checks.push(PredicateCheck {
        function: function.clone(),
        iteration_calls: vec![call.clone()],
        target_calls: vec![call.clone()],
        atoms: vec![Atom {
            name: AtomName::new("A").unwrap(),
            value: bad.clone(),
        }],
        expect: ObligationRef {
            profile: ProfileRef::new("test-profile@1").unwrap(),
            obligation: ObligationId::new("example").unwrap(),
        },
        assignments: 0,
        result: CheckResult::Unknown {
            reason: CheckUnknown::NoFde,
        },
    });
    rejects(&s, "predicate_checks");
    rejects(&s, "register architecture");
    s.code[0].predicate_checks[0].atoms[0].value = ArgValue::Unknown {
        reg: Reg::X0,
        reason: ValueUnknown::NotModeled,
    };
    assert_contract(&s);
    s.code[0].guard_regions.push(GuardRegion {
        function: function.clone(),
        from: Loc::CallSite(call.clone()),
        to: call,
        region: RegionKind::Acyclic,
        guards: vec![GuardBranch {
            at: 65,
            cond: GuardCond::Compare {
                value: bad,
                op: CmpOp::Eq,
                constant: 0,
            },
            dominates_to: false,
            exit: ExitKind::Other,
        }],
        converging: 0,
        indirect: vec![],
        complete: TriState::Unknown,
    });
    rejects(&s, "guard_regions");
    rejects(&s, "register architecture");
    s.code[0].guard_regions.clear();
    s.code[0].param_mappings.push(ParamMapping {
        function,
        source: SourceParamRef {
            function: "kernel".into(),
            index: 0,
            name: "fd".into(),
        },
        binary: BinaryParam::Reg(Reg::Rdi),
        evidence: vec![],
    });
    rejects(&s, "param_mappings");
    rejects(&s, "register architecture");
    let mut s = macho(Arch::Aarch64);
    let function = s.code[0].functions[0].id.clone();
    s.code[0].param_mappings.push(ParamMapping {
        function,
        source: SourceParamRef {
            function: "kernel".into(),
            index: 0,
            name: "fd".into(),
        },
        binary: BinaryParam::Reg(Reg::X18),
        evidence: vec![],
    });
    rejects(&s, "reserved x18");
}

#[test]
fn nonlegacy_facts_cannot_hide_without_new_fields() {
    let mut s = arm();
    s.request.code_analysis = None;
    s.artifacts[0].code_slice_inventory = None;
    s.code[0].call_sites.clear();
    rejects(&s, "code facts need multiarch-v1");
}

#[test]
fn partial_reason_and_unproved_abi_cannot_claim_completeness() {
    let mut s = arm();
    s.code[0].call_sites[0].args_layout = Some(ArgumentLayout::Partial {
        reason: UntrustedText::new(" \t"),
    });
    rejects(&s, "nonempty reason");
    let mut s = arm();
    let ContainerFacts::Elf(e) = &mut s.binaries[0].container else {
        unreachable!()
    };
    e.abi = None;
    rejects(&s, "argument layout");
    let mut s = arm();
    s.code[0].call_sites[0].args.push(ArgValue::Unknown {
        reg: Reg::Sp,
        reason: ValueUnknown::FromMemory,
    });
    rejects(&s, "argument prefix");
    let mut s = arm();
    s.binaries.clear();
    rejects(&s, "parsed slice");
    let mut s = arm();
    let duplicate = s.code[0].call_sites[0].clone();
    s.code[0].call_sites.push(duplicate);
    rejects(&s, "duplicate");
}

#[test]
#[ignore = "Task 0 frozen captures live outside git; run explicitly in the implementation worktree"]
fn frozen_task0_canonical_bytes_and_reports_are_identical() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp/issue48");
    use sha2::{Digest, Sha256};
    let canonical_dir = root.join("task3/old-canonical");
    let mut count = 0;
    for entry in std::fs::read_dir(&canonical_dir).unwrap() {
        let path = entry.unwrap().path();
        let raw = std::fs::read(&path).unwrap();
        let session: Session = serde_json::from_slice(&raw).unwrap();
        session.validate().unwrap();
        assert!(
            session.to_canonical_json().unwrap().as_bytes() == raw,
            "canonical bytes {}",
            path.display()
        );
        count += 1;
    }
    assert_eq!(count, 26);
    let mut reports = 0;
    for entry in std::fs::read_dir(root.join("baseline")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap();
        if !name.ends_with(".session.json") {
            continue;
        }
        let session: Session = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        session.validate().unwrap();
        let canonical = session.to_canonical_json().unwrap();
        assert!(
            canonical.as_bytes() == std::fs::read(canonical_dir.join(name)).unwrap(),
            "original input -> canonical {name}"
        );
        let hash = format!("{:x}", Sha256::digest(canonical.as_bytes()));
        if name.starts_with("pre-127-") {
            assert_eq!(
                hash,
                "fb83b4d4742a772fb5ff17557a638b4153550ddbb589bc693ca77c26ed974ff6"
            );
        }
        let bom = sigil_model::render::aibom::project(&session, Sha256Hex::new(hash).unwrap());
        let bom_json = serde_json::to_string_pretty(&bom).unwrap() + "\n";
        assert!(
            bom_json.as_bytes()
                == std::fs::read(path.with_file_name(name.replace(".session.json", ".aibom.json")))
                    .unwrap(),
            "AI-BOM {name}"
        );
        let md = path.with_file_name(name.replace(".session.json", ".md"));
        assert!(
            sigil_model::render::markdown::render_session(&session).as_bytes()
                == std::fs::read(md).unwrap(),
            "Markdown {name}"
        );
        reports += 1;
    }
    assert_eq!(reports, 4);
    let absent: Session = serde_json::from_slice(
        &std::fs::read(root.join("legacy-absent/pre-127-no-code.json")).unwrap(),
    )
    .unwrap();
    absent.validate().unwrap();
    assert!(!absent.request.code && absent.request.code_analysis.is_none());
    assert!(
        sigil_model::render::markdown::render_session(&absent).as_bytes()
            == std::fs::read(root.join("legacy-absent/pre-127-no-code.md")).unwrap()
    );
    println!("Compared {count} original-model canonical outputs, {reports} Markdown/AI-BOM pairs and the missing-code legacy report byte-for-byte");
}

#[test]
fn returns_and_imports_in_another_slice_do_not_supply_a_witness() {
    let mut s = macho(Arch::Aarch64);
    let original_hash = s.artifacts[0].id.as_str().strip_prefix("sha256:").unwrap();
    let json = serde_json::to_string(&s)
        .unwrap()
        .replace(original_hash, &"bb".repeat(32))
        .replace("binary-1", "binary-2")
        .replace("cs:0x4d", "cs:0x50");
    let mut second: Session = serde_json::from_str(&json).unwrap();
    second.code[0].call_sites[0].addr = 80;
    let ContainerFacts::MachO(m) = &mut second.binaries[0].container else {
        unreachable!()
    };
    m.imports[0].weak = false;
    let CallTarget::Import {
        macho_import: Some(m),
        ..
    } = &mut second.code[0].call_sites[0].target
    else {
        unreachable!()
    };
    m.weak = false;
    s.request.roots.extend(second.request.roots);
    s.artifacts.extend(second.artifacts);
    s.binaries.extend(second.binaries);
    s.instances.extend(second.instances);
    s.code.extend(second.code);
    s.coverage.extend(second.coverage);
    s.relations.extend(second.relations);
    assert_contract(&s);
    let mut bad = s.clone();
    bad.code[0].call_sites[0].args[0] = ArgValue::ReturnOf {
        reg: Reg::X0,
        call: CallId::new("cs:0x50").unwrap(),
    };
    rejects(&bad, "cs:0x50");
    let CallTarget::Import {
        macho_import: Some(m),
        ..
    } = &mut s.code[0].call_sites[0].target
    else {
        unreachable!()
    };
    m.weak = false;
    rejects(&s, "Mach-O import witness");
}

#[test]
fn marked_legacy_calls_still_respect_the_register_abi_limit() {
    let mut s = marked();
    s.code[0].call_sites[0].args = (0..7)
        .map(|_| ArgValue::Unknown {
            reg: Reg::Rdi,
            reason: ValueUnknown::NotModeled,
        })
        .collect();
    rejects(&s, "argument-register ABI limit");
    // A marker-free historical session keeps its prior validation semantics.
    s.request.code_analysis = None;
    s.artifacts[0].code_slice_inventory = None;
    assert!(s.validate().is_ok());
}
