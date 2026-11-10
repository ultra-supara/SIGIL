use sigil_engine::{
    binary::{parse_artifact, BinaryBudgets},
    code::{CodeBudgets, CodeOutcome},
};
use sigil_model::{CallTarget, ImportVia, Sha256Hex};
use std::io::Write;
fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/code-macho/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}
fn analyze(bytes: &[u8], code: CodeBudgets) -> sigil_engine::binary::ParsedArtifact {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(bytes).unwrap();
    parse_artifact(
        f.as_file(),
        bytes.len() as u64,
        &Sha256Hex::new(common::hex(bytes)).unwrap(),
        &bytes[..4],
        BinaryBudgets {
            code: Some(code),
            ..Default::default()
        },
        None,
    )
    .unwrap()
}
#[test]
fn real_thin_stubs_join_exact_import_witnesses() {
    for name in [
        "arm64-classic",
        "arm64-chained",
        "x86-classic",
        "x86-chained",
    ] {
        let p = analyze(&fixture(name), Default::default());
        let CodeOutcome::Analyzed {
            functions,
            call_sites,
            gaps,
            ..
        } = p.slices[0].code.as_ref().unwrap()
        else {
            panic!("{name}: code unsupported")
        };
        assert_eq!(functions.len(), 2, "{name}: {gaps:?}");
        assert_eq!(call_sites.len(), 2, "{name}: {gaps:?}");
        assert!(gaps.is_empty(), "{name}: {gaps:?}");
        for (n, call) in call_sites.iter().enumerate() {
            assert_eq!(call.args.len(), 3, "{name}: {call:?}");
            assert!(
                matches!(call.args[0],sigil_model::ArgValue::ConstInt {value,..} if value==n as i64),
                "{name}: {call:?}"
            );
            assert!(
                call.args[1..]
                    .iter()
                    .all(|a| matches!(a, sigil_model::ArgValue::ConstInt { value: 0, .. })),
                "{name}: {call:?}"
            );
            assert_eq!(
                call.args_layout,
                Some(sigil_model::ArgumentLayout::Complete)
            );
            assert!(
                matches!(&call.target, CallTarget::Import { symbol, via: ImportVia::MachOStub, macho_import: Some(w) } if symbol.as_bytes()==b"_connect" && w.name==*symbol && !w.weak)
            );
        }
    }
}

#[test]
fn real_mh_execute_calls_match_independent_oracle_and_public_session() {
    use sigil_model::{ArgumentLayout, CallTarget, ContainerFacts, CoverageState, MachOLibrary};
    let policy = sigil_engine::policy::Policy::load(
        "schema = \"sigil-policy/1\"\nname = \"exec-network\"\n\
         [[capabilities.deny]]\nfeature = \"posix.network\"\naction = \"fail\"\nreason = \"test\"\n",
    )
    .unwrap();
    for name in ["arm64-executable", "x86-executable"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/code-macho-exec")
            .join(name);
        let session = sigil_engine::inspect::binary_session(
            &sigil_engine::inspect::BinaryRequest {
                paths: vec![path],
                deps_budgets: Default::default(),
                budgets: sigil_engine::collect::named::NamedBudgets {
                    binary: BinaryBudgets {
                        code: Some(Default::default()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            },
            &policy,
            common::tool(),
            common::observation(),
            common::policy_time(),
        )
        .unwrap();
        let ContainerFacts::MachO(macho) = &session.binaries[0].container else {
            panic!("expected Mach-O executable")
        };
        assert_eq!(macho.file_type, 2, "MH_EXECUTE, not a dylib mutation");
        assert_eq!(
            session.artifacts[0].slices[0].arch,
            if name == "arm64-executable" {
                sigil_model::Arch::Aarch64
            } else {
                sigil_model::Arch::X86_64
            }
        );
        assert_eq!(session.code.len(), 1);
        let code = &session.code[0];
        assert_eq!(code.call_sites.len(), 2);
        let rows: Vec<_> = include_str!("fixtures/code-macho-exec/oracle.tsv")
            .lines()
            .skip(1)
            .map(|line| line.split('\t').collect::<Vec<_>>())
            .filter(|row| row[0] == name)
            .collect();
        assert_eq!(rows.len(), 2);
        for row in rows {
            let addr =
                |value: &str| u64::from_str_radix(value.trim_start_matches("0x"), 16).unwrap();
            let call = code
                .call_sites
                .iter()
                .find(|c| c.addr == addr(row[5]))
                .unwrap();
            let function = code.functions.iter().find(|f| f.id == call.caller).unwrap();
            assert_eq!((function.entry, function.end), (addr(row[3]), addr(row[4])));
            assert!(matches!(&call.target,
                CallTarget::Import { symbol, via: ImportVia::MachOStub, macho_import: Some(w) }
                if symbol.as_bytes() == row[6].as_bytes() && w.name == *symbol && !w.weak
                    && matches!(&w.library, MachOLibrary::Dylib { ordinal: 1, name: Some(lib) }
                        if lib.as_bytes() == row[7].as_bytes())));
            assert_eq!(call.args_layout, Some(ArgumentLayout::Complete));
            assert_eq!(call.args.len(), 3);
            for (arg, expected) in call.args.iter().zip(&row[8..11]) {
                assert!(matches!(arg, sigil_model::ArgValue::ConstInt { value, .. }
                    if *value == expected.parse::<i64>().unwrap()));
            }
        }
        let coverage: Vec<_> = session
            .coverage
            .iter()
            .filter(|c| c.check.as_str() == "binary.code")
            .collect();
        assert_eq!(coverage.len(), 2, "one child and one input summary");
        assert!(coverage.iter().all(|c| c.state == CoverageState::Complete));
        assert_eq!(coverage[0].budget, coverage[1].budget);
        assert_eq!(session.policy_violations.len(), 1);
        assert_eq!(session.policy_violations[0].evidence.len(), 2);
        session.validate().unwrap();
        let saved: sigil_model::Session =
            serde_json::from_str(&session.to_canonical_json().unwrap()).unwrap();
        saved.validate().unwrap();
        sigil_engine::policy::verify(&saved, &policy).unwrap();
    }
}

fn code(
    p: &sigil_engine::binary::ParsedArtifact,
    index: usize,
) -> (
    &[sigil_model::Function],
    &[sigil_model::CallSite],
    &[String],
    u64,
) {
    let CodeOutcome::Analyzed {
        functions,
        call_sites,
        gaps,
        budget,
    } = p.slices[index].code.as_ref().unwrap()
    else {
        panic!("unsupported slice {index}");
    };
    (functions, call_sites, gaps, budget.used)
}
#[test]
fn args_and_exact_same_name_dylib_are_honest() {
    let p = analyze(&fixture("duplicate-name-dylibs"), Default::default());
    let (_, calls, gaps, _) = code(&p, 0);
    assert_eq!(calls.len(), 3, "{gaps:?}");
    for (n, c) in calls.iter().enumerate() {
        let CallTarget::Import {
            macho_import: Some(w),
            ..
        } = &c.target
        else {
            panic!()
        };
        let sigil_model::MachOLibrary::Dylib {
            name: Some(lib), ..
        } = &w.library
        else {
            panic!()
        };
        if n < 2 {
            assert_eq!(lib.as_bytes(), sigil_model::LIBSYSTEM.as_bytes());
            assert_eq!(c.args.len(), 3);
            assert!(
                matches!(c.args[0],sigil_model::ArgValue::ConstInt {value,..} if value==n as i64)
            );
            assert_eq!(c.args_layout, Some(sigil_model::ArgumentLayout::Complete));
        } else {
            assert_eq!(lib.as_bytes(), b"/sigil/libfoo.dylib");
            assert!(c.args.is_empty());
            assert!(matches!(
                c.args_layout,
                Some(sigil_model::ArgumentLayout::Partial { .. })
            ));
            assert!(gaps.iter().any(|g| g.contains(c.id.as_str())));
        }
    }
}
#[test]
fn object_branches_keep_unbound_identity_without_guessed_prototype() {
    for name in ["arm64-object.o", "x86-object.o", "compact-object.o"] {
        let p = analyze(&fixture(name), Default::default());
        let (functions, calls, gaps, _) = code(&p, 0);
        assert_eq!(calls.len(), 2, "{name}: {gaps:?}");
        assert_eq!(functions.len(), 2);
        for c in calls {
            assert!(
                matches!(&c.target,CallTarget::Import {via:ImportVia::MachOReloc,macho_import:Some(w),..} if w.library==sigil_model::MachOLibrary::Unbound)
            );
            assert!(c.args.is_empty());
            assert!(matches!(
                c.args_layout,
                Some(sigil_model::ArgumentLayout::Partial { .. })
            ));
            assert!(gaps.iter().any(|g| g.contains(c.id.as_str())));
        }
    }
}
#[test]
fn unsupported_fat_child_preserves_proved_sibling_and_shared_budget() {
    for name in ["universal", "universal-mixed"] {
        let p = analyze(&fixture(name), Default::default());
        assert_eq!(p.slices.len(), 2);
        let mut total = 0;
        let mut count = 0;
        for s in &p.slices {
            match s.code.as_ref().unwrap() {
                CodeOutcome::Analyzed {
                    call_sites,
                    gaps,
                    budget,
                    ..
                } => {
                    assert_eq!(call_sites.len(), 2, "{name}: {gaps:?}");
                    assert!(gaps.is_empty());
                    count += call_sites.len();
                    total += budget.used;
                }
                CodeOutcome::Unsupported => assert_eq!(name, "universal-mixed"),
            }
        }
        assert_eq!(count, if name == "universal" { 4 } else { 2 });
        assert!(total > 0);
    }
    let bytes = fixture("universal");
    let p = analyze(
        &bytes,
        CodeBudgets {
            instructions: 1,
            ..Default::default()
        },
    );
    let (_, calls, gaps, used) = code(&p, 1);
    assert!(calls.is_empty());
    assert_eq!(used, 0);
    assert_eq!(gaps, ["code: artifact budget exhausted before slice"]);
}
#[test]
fn absent_or_folded_native_bounds_never_invent_functions() {
    for name in ["no-unwind", "unwind-folded"] {
        let p = analyze(&fixture(name), Default::default());
        let (f, c, g, _) = code(&p, 0);
        assert!(f.is_empty() && c.is_empty(), "{name}");
        assert!(!g.is_empty());
    }
}
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
#[test]
fn malformed_stubs_and_middle_entries_cannot_name_calls() {
    for (at, word) in [
        (0x568, 0xd503201f),
        (0x56c, 0xf9400230),
        (0x534, 0x9400000e),
        (0x56c, 0xf9400610),
    ] {
        let mut bytes = fixture("arm64-classic");
        put32(&mut bytes, at, word);
        let p = analyze(&bytes, Default::default());
        let (_, c, g, _) = code(&p, 0);
        assert!(c.iter().all(|c| c.addr != 0x534), "{at:#x}: {g:?}");
        assert!(!g.is_empty());
    }
    let mut bytes = fixture("x86-classic");
    bytes[0x558] = 0x90;
    let p = analyze(&bytes, Default::default());
    let (_, c, g, _) = code(&p, 0);
    assert!(c.is_empty());
    assert!(!g.is_empty());
}
#[test]
fn nonzero_branch_addend_discards_only_affected_object_function() {
    for (name, at, word) in [
        ("arm64-object.o", 0x1ec, 0x94000001),
        ("x86-object.o", 0x1e3, 1),
    ] {
        let mut bytes = fixture(name);
        put32(&mut bytes, at, word);
        let p = analyze(&bytes, Default::default());
        let (f, c, g, _) = code(&p, 0);
        assert_eq!(f.len(), 1, "{name}: {g:?}");
        assert_eq!(c.len(), 1);
        assert!(c[0].addr > at as u64);
        assert!(!g.is_empty());
    }
}
#[test]
fn architecture_cfg_join_and_caller_clobbers_use_real_oracle() {
    for name in ["arm64-cases", "x86-cases"] {
        let p = analyze(&fixture(name), Default::default());
        let (_, c, g, _) = code(&p, 0);
        assert_eq!(c.len(), 5, "{name}: {g:?}");
        assert!(
            matches!(c[3].args[0], sigil_model::ArgValue::Set { .. }),
            "{name}: {:?}",
            c[3]
        );
        assert!(
            c[4].args
                .iter()
                .all(|a| matches!(a, sigil_model::ArgValue::Unknown { .. })),
            "{name}: {:?}",
            c[4]
        );
        assert!(!g.is_empty());
    }
}

#[path = "common/mod.rs"]
mod common;
#[test]
fn named_universal_session_accepts_exact_witnesses_and_library_aware_policy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("universal");
    std::fs::write(&path, fixture("universal")).unwrap();
    let request = sigil_engine::inspect::BinaryRequest {
        paths: vec![path],
        deps_budgets: Default::default(),
        budgets: sigil_engine::collect::named::NamedBudgets {
            binary: BinaryBudgets {
                code: Some(Default::default()),
                ..Default::default()
            },
            ..Default::default()
        },
    };
    let policy = sigil_engine::policy::Policy::builtin_default().unwrap();
    let result = sigil_engine::inspect::binary_session(
        &request,
        &policy,
        common::tool(),
        common::observation(),
        common::policy_time(),
    );
    let session = result.unwrap();
    session.validate().unwrap();
    assert_eq!(session.code.len(), 2);
    assert!(session.code.iter().all(|f| f.call_sites.len() == 2));
    let denied=sigil_engine::policy::Policy::load("schema = \"sigil-policy/1\"\nname = \"denied\"\n[[capabilities.deny]]\nfeature = \"posix.network\"\naction = \"fail\"\nreason = \"test\"\n").unwrap();
    let result = sigil_engine::inspect::binary_session(
        &request,
        &denied,
        common::tool(),
        common::observation(),
        common::policy_time(),
    );
    let session = result.unwrap();
    session.validate().unwrap();
    assert_eq!(session.policy_violations.len(), 2);
    assert!(session
        .policy_violations
        .iter()
        .all(|v| v.evidence.len() == 2));
    sigil_engine::policy::verify(&session, &denied).unwrap();
}
#[test]
fn tail_calls_and_got_calls_require_actual_decoded_targets() {
    for (name, at, op) in [
        ("arm64-classic", 0x534, 0x1400000d),
        ("x86-classic", 0x52a, 0xe9),
    ] {
        let mut bytes = fixture(name);
        if name.starts_with("arm") {
            put32(&mut bytes, at, op);
        } else {
            bytes[at] = op as u8;
        }
        let p = analyze(&bytes, Default::default());
        let (_, calls, gaps, _) = code(&p, 0);
        assert_eq!(calls.len(), 2, "{name}: {gaps:?}");
        assert_eq!(calls[0].kind, sigil_model::CallKind::TailJump);
    }
    let mut arm = fixture("arm64-classic");
    for (n, w) in [
        0x90000050, 0xf9400210, 0x52800000, 0xd2800001, 0x52800002, 0xd63f0200, 0xd503201f,
        0xd503201f, 0xd65f03c0,
    ]
    .iter()
    .enumerate()
    {
        put32(&mut arm, 0x520 + n * 4, *w);
    }
    let mut x86 = fixture("x86-classic");
    let instructions = [
        0x55, 0x48, 0x89, 0xe5, 0x31, 0xff, 0x31, 0xf6, 0x31, 0xd2, 0xff, 0x15, 0xd0, 0x2a, 0, 0,
        0x5d, 0xc3, 0x90,
    ];
    x86[0x520..0x533].copy_from_slice(&instructions);
    for bytes in [arm, x86] {
        let p = analyze(&bytes, Default::default());
        let (_, calls, gaps, _) = code(&p, 0);
        assert_eq!(calls.len(), 2, "{gaps:?}");
        assert!(matches!(
            calls[0].target,
            CallTarget::Import {
                via: ImportVia::MachOGot,
                ..
            }
        ));
        assert!(calls[0]
            .args
            .iter()
            .all(|v| matches!(v, sigil_model::ArgValue::ConstInt { value: 0, .. })));
        assert!(gaps.is_empty(), "{gaps:?}");
    }
}
#[test]
fn real_healthy_fat_sibling_survives_unparsed_lost_or_budget_limited_sibling() {
    use common::macho::{fat32, AARCH64, X86_64};
    let thin = fixture("x86-classic");
    for failure in ["unparsed", "lost", "budget"] {
        let invalid = failure == "lost";
        let second = if failure == "budget" {
            common::macho::thin(
                true,
                false,
                X86_64,
                3,
                &[common::macho::command(0x777, 1 << 20, false)],
            )
        } else {
            thin[..8].to_vec()
        };
        let mut bytes = fat32(&[(fixture("arm64-chained"), AARCH64, 0), (second, X86_64, 3)]);
        if invalid {
            bytes[40..44].copy_from_slice(&0u32.to_be_bytes());
        }
        let parse_limit = if failure == "budget" {
            64 << 10
        } else {
            64 << 20
        };
        let p = {
            let mut f = tempfile::NamedTempFile::new().unwrap();
            f.write_all(&bytes).unwrap();
            parse_artifact(
                f.as_file(),
                bytes.len() as u64,
                &Sha256Hex::new(common::hex(&bytes)).unwrap(),
                &bytes[..4],
                BinaryBudgets {
                    parse_bytes: parse_limit,
                    code: Some(Default::default()),
                    ..Default::default()
                },
                None,
            )
            .unwrap()
        };
        assert!(
            p.slices[0].gaps.is_empty(),
            "{failure}: {:?}",
            p.slices[0].gaps
        );
        assert!(
            matches!(&p.slices[0].container, Some(sigil_model::ContainerFacts::MachO(m)) if !m.fat_gaps.is_empty())
        );
        let (_, calls, gaps, _) = code(&p, 0);
        assert_eq!(calls.len(), 2, "{gaps:?}");
        assert!(
            gaps.is_empty(),
            "sibling gaps must not poison healthy code: {gaps:?}"
        );
        assert_eq!(p.slices.len(), if invalid { 1 } else { 2 });
        if invalid || failure == "budget" {
            assert!(matches!(
                p.code_inventory,
                sigil_model::CodeSliceInventory::Partial { .. }
            ));
        }
        if failure == "unparsed" {
            let (_, c, g, used) = code(&p, 1);
            assert!(c.is_empty());
            assert_eq!(g, ["code: slice not parsed"]);
            assert_eq!(used, 0);
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("bin")).unwrap();
        std::fs::create_dir_all(dir.path().join("lib/ollama")).unwrap();
        std::fs::write(dir.path().join("bin/ollama"), bytes).unwrap();
        let mut budgets = sigil_engine::collect::install::InstallBudgets::default();
        budgets.binary.code = Some(Default::default());
        budgets.binary.parse_bytes = parse_limit;
        let facts = sigil_engine::collect::install::collect_with_code(dir.path(), budgets).unwrap();
        assert!(facts.code.iter().any(
            |(_, c)| matches!(c,CodeOutcome::Analyzed {call_sites,..} if call_sites.len()==2)
        ));
        let coverage =
            sigil_engine::analyze::install_code::coverage(&facts, CodeBudgets::default().bytes)
                .unwrap();
        assert!(coverage
            .iter()
            .filter(|c| matches!(
                c.scope,
                sigil_model::Ref::Root(_) | sigil_model::Ref::Artifact(_)
            ))
            .all(|c| matches!(c.state, sigil_model::CoverageState::Partial { .. })));
        let policy = sigil_engine::policy::Policy::builtin_default().unwrap();
        let named = sigil_engine::inspect::binary_session(
            &sigil_engine::inspect::BinaryRequest {
                paths: vec![dir.path().join("bin/ollama")],
                deps_budgets: Default::default(),
                budgets: sigil_engine::collect::named::NamedBudgets {
                    binary: budgets.binary,
                    ..Default::default()
                },
            },
            &policy,
            common::tool(),
            common::observation(),
            common::policy_time(),
        )
        .unwrap();
        let models = tempfile::tempdir().unwrap();
        let install = sigil_engine::inspect::store_session(
            &sigil_engine::inspect::StoreRequest {
                deps_budgets: Default::default(),
                models_dir: models.path().to_path_buf(),
                model_filter: None,
                budgets: Default::default(),
                manifest_limit: sigil_engine::collect::ollama_store::DEFAULT_MANIFEST_LIMIT,
                install: Some(sigil_engine::inspect::InstallRequest {
                    source: sigil_engine::inspect::InstallSource::Dir(dir.path().to_path_buf()),
                    budgets,
                }),
            },
            &Default::default(),
            &policy,
            common::tool(),
            common::observation(),
            common::policy_time(),
        )
        .unwrap();
        assert_eq!(named.code, install.code);
        for (session, check) in [(named, "binary.code"), (install, "artifacts.code")] {
            assert_eq!(session.code[0].call_sites.len(), 2);
            let good = session.artifacts[0]
                .slices
                .iter()
                .find(|s| s.arch == sigil_model::Arch::Aarch64)
                .unwrap();
            assert!(session
                .binaries
                .iter()
                .find(|b| b.slice == good.id)
                .unwrap()
                .gaps
                .is_empty());
            assert!(session.coverage.iter().any(|c| c.check.as_str() == check
                && c.scope == sigil_model::Ref::Slice(good.id.clone())
                && c.state == sigil_model::CoverageState::Complete));
            assert!(session
                .coverage
                .iter()
                .filter(|c| {
                    c.check.as_str() == check && !matches!(c.scope, sigil_model::Ref::Slice(_))
                })
                .all(|c| matches!(c.state, sigil_model::CoverageState::Partial { .. })));
            session.validate().unwrap();
            if failure == "budget" {
                let mut forged = session.clone();
                forged.artifacts[0].code_slice_inventory =
                    Some(sigil_model::CodeSliceInventory::Complete);
                assert!(
                    forged.validate().is_err(),
                    "shared parse refusal requires Partial inventory"
                );
            }
            let json = session.to_canonical_json().unwrap();
            let saved: sigil_model::Session = serde_json::from_str(&json).unwrap();
            saved.validate().unwrap();
            sigil_engine::policy::verify(&saved, &policy).unwrap();
            assert_eq!(json, saved.to_canonical_json().unwrap());
        }
    }
}
#[test]
fn stub_cannot_overwrite_argument_registers_before_the_import() {
    let mut bytes = fixture("arm64-classic");
    put32(&mut bytes, 0x568, 0x90000040); // ADRP x0, 0x8000
    put32(&mut bytes, 0x56c, 0xf9400000); // LDR x0,[x0]
    put32(&mut bytes, 0x570, 0xd61f0000); // BR x0
    let p = analyze(&bytes, Default::default());
    let (_, c, g, _) = code(&p, 0);
    assert!(c.is_empty());
    assert!(!g.is_empty());
}
fn section_relocations(bytes: &[u8]) -> usize {
    let mut at = 32;
    for _ in 0..u32::from_le_bytes(bytes[16..20].try_into().unwrap()) {
        let cmd = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if cmd == 0x19 {
            return u32::from_le_bytes(bytes[at + 72 + 56..at + 72 + 60].try_into().unwrap())
                as usize;
        }
        at += len;
    }
    panic!("text section");
}
#[test]
fn invalid_relocation_forms_do_not_become_encoded_self_calls() {
    for name in ["arm64-object.o", "x86-object.o"] {
        let original = fixture(name);
        let reloc = section_relocations(&original);
        let info = u32::from_le_bytes(original[reloc + 4..reloc + 8].try_into().unwrap());
        for mutant in [
            info & !(1 << 24),
            info & !(1 << 27),
            info ^ (1 << 25),
            (info & 0x0fffffff) | (5 << 28),
            (info & 0xff000000) | 0xffffff,
        ] {
            let mut bytes = original.clone();
            put32(&mut bytes, reloc + 4, mutant);
            let p = analyze(&bytes, Default::default());
            let (_, c, g, _) = code(&p, 0);
            assert_eq!(c.len(), 1, "{name} {mutant:#x}: {g:?}");
            assert!(!g.is_empty());
        }
        let mut bytes = original;
        put32(&mut bytes, reloc, 0x80000000);
        let p = analyze(&bytes, Default::default());
        let (_, c, g, _) = code(&p, 0);
        assert!(c.is_empty());
        assert!(!g.is_empty());
    }
}
#[test]
fn value_and_call_limits_rollback_only_uncommitted_function() {
    let bytes = fixture("arm64-classic");
    let p = analyze(
        &bytes,
        CodeBudgets {
            call_sites: 1,
            ..Default::default()
        },
    );
    let (f, c, g, _) = code(&p, 0);
    assert_eq!(f.len(), 1);
    assert_eq!(c.len(), 1);
    assert!(!g.is_empty());
    let p = analyze(
        &bytes,
        CodeBudgets {
            value_steps: 1,
            ..Default::default()
        },
    );
    let (f, c, g, _) = code(&p, 0);
    assert!(f.is_empty() && c.is_empty());
    assert!(!g.is_empty());
}
#[test]
fn two_pending_calls_are_rolled_back_after_reachable_unsupported_instruction() {
    let mut bytes = fixture("arm64-classic");
    put32(&mut bytes, 0x538, 0x9400000c); // second BL to the validated stub
    put32(&mut bytes, 0x53c, 0); // unsupported reachable UDF after both calls
    let p = analyze(&bytes, Default::default());
    let (f, c, g, _) = code(&p, 0);
    assert_eq!(f.len(), 1, "{g:?}");
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].addr, 0x558);
    assert!(g.iter().any(|g| g.contains("transaction discarded")));
}
#[test]
fn object_weak_local_and_overlapping_relocations_stay_gaps() {
    for name in ["arm64-object.o", "x86-object.o"] {
        let bytes = fixture(name);
        let reloc = section_relocations(&bytes);
        let mut duplicate = bytes.clone();
        let address = duplicate[reloc..reloc + 4].to_vec();
        duplicate[reloc + 8..reloc + 12].copy_from_slice(&address);
        let p = analyze(&duplicate, Default::default());
        let (_, c, g, _) = code(&p, 0);
        assert!(c.is_empty());
        assert!(!g.is_empty());
        let index = u32::from_le_bytes(bytes[reloc + 4..reloc + 8].try_into().unwrap()) & 0xffffff;
        let mut at = 32;
        let symoff = loop {
            let cmd = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            if cmd == 2 {
                break u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()) as usize;
            }
            at += u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        };
        for (offset, flag) in [(4, 0u8), (6, 0x40u8)] {
            let mut mutant = bytes.clone();
            mutant[symoff + index as usize * 16 + offset] = flag;
            let p = analyze(&mutant, Default::default());
            let (_, c, g, _) = code(&p, 0);
            assert!(c.is_empty(), "{name}: {g:?}");
            assert!(!g.is_empty());
        }
    }
}

#[test]
fn x86_conditional_stub_edges_discard_the_function_without_becoming_calls() {
    for condition in [0x84, 0x85] {
        // JZ / JNZ: predicates are not capability-call evidence.
        let mut bytes = fixture("x86-classic");
        bytes[0x528..0x52f].copy_from_slice(&[0x0f, condition, 0x2a, 0, 0, 0, 0x90]);
        let p = analyze(&bytes, Default::default());
        let (functions, calls, gaps, _) = code(&p, 0);
        assert_eq!(
            calls.len(),
            1,
            "condition {condition:#x}: {calls:?}; {gaps:?}"
        );
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].entry, 0x540);
        assert_eq!(calls[0].addr, 0x54d);
        assert_eq!(calls[0].kind, sigil_model::CallKind::Call);
        assert!(
            gaps.iter()
                .any(|g| g.contains("external conditional branch at 0x528")),
            "{gaps:?}"
        );
        assert!(
            gaps.iter()
                .any(|g| g.contains("function at 0x520: recording transaction discarded")),
            "{gaps:?}"
        );
    }
}
