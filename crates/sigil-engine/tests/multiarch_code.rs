#[allow(dead_code)]
#[path = "../../sigil-model/tests/support/multiarch.rs"]
mod support;
use sigil_engine::policy::{evaluate, Policy, ScopeInput};
use sigil_model::*;

fn policy(deny: bool) -> Policy {
    let mut text = "schema = \"sigil-policy/1\"\nname = \"coverage\"\n[scope]\nbinary_audit = []\nbinary_code_audit = [\"binary_code\"]\n".to_string();
    if deny {
        text.push_str("[[capabilities.deny]]\nfeature = \"posix.network\"\naction = \"fail\"\nreason = \"test\"\n");
    }
    Policy::load(&text).unwrap()
}

fn evaluate_denied(s: &mut Session, install: bool, opt_out: bool) -> Policy {
    s.hints = sigil_engine::analyze::hints::derive(&s.binaries).unwrap();
    let scope = if install {
        "install_code_audit"
    } else {
        "binary_code_audit"
    };
    let audit = if install {
        "installation_code"
    } else {
        "binary_code"
    };
    let selected = if opt_out {
        String::new()
    } else {
        format!("\"{audit}\"")
    };
    let p = Policy::load(&format!(
        r#"schema = "sigil-policy/1"
name = "coverage"
[scope]
audit = []
install_audit = []
binary_audit = []
{scope} = [{selected}]
[[capabilities.deny]]
feature = "posix.network"
action = "fail"
reason = "test"
"#
    ))
    .unwrap();
    let (audit, checks) = p.scope(&ScopeInput::of(&s.request));
    s.request.audit = audit;
    s.request.required_checks = checks;
    evaluate(s, &p, Timestamp::new("2026-11-03T00:00:00Z").unwrap()).unwrap();
    p
}

#[test]
fn marked_elf_capability_questions_use_the_slice_search_state() {
    for install in [false, true] {
        for opt_out in [false, true] {
            for partial in [false, true] {
                let mut s = support::named();
                if partial {
                    support::child(&mut s, 0).state = CoverageState::Partial {
                        missing: vec!["code: budget gap".into()],
                    };
                    let state = support::incomplete(&s, &[0], false);
                    support::parent(&mut s, state, Some(4));
                } else {
                    // A partial content inventory must not override a complete local search.
                    support::inventory_partial(&mut s);
                    let state = support::incomplete(&s, &[], true);
                    support::parent(&mut s, state, Some(4));
                }
                if install {
                    s = support::installation(s);
                }
                let p = evaluate_denied(&mut s, install, opt_out);
                assert!(s.policy_violations.is_empty());
                let q = &s.open_questions[0];
                let CondState::Unknown { reason, .. } = &q.conditions[0].state else {
                    panic!()
                };
                assert_eq!(
                    matches!(reason, UnknownReason::CheckIncomplete { .. }),
                    partial
                );
                s.validate().unwrap();
                let round: Session = serde_json::from_str(&s.to_canonical_json().unwrap()).unwrap();
                sigil_engine::policy::verify(&round, &p).unwrap();
                let mut forged = round;
                let wrong_check = if install { BINARY_CODE } else { ARTIFACTS_CODE };
                forged.open_questions[0].conditions[0].state = CondState::Unknown {
                    reason: UnknownReason::CheckIncomplete {
                        check: CheckId::new(wrong_check).unwrap(),
                    },
                    evidence: None,
                };
                assert!(
                    forged.validate().is_err(),
                    "wrong slice check reason accepted"
                );
                if partial {
                    forged.open_questions[0].conditions[0].state = CondState::Unknown {
                        reason: UnknownReason::NotModeled { what: "calls that are not direct (through a function pointer, or from data)".into() }, evidence: None,
                    };
                    assert!(
                        forged.validate().is_err(),
                        "partial slice described as complete"
                    );
                }
            }
        }
    }
}

#[test]
fn marked_aarch64_call_confirms_denial_even_with_partial_search() {
    for install in [false, true] {
        for partial in [false, true] {
            for has_call in [false, true] {
                let mut s = inspect_paths(
                    vec![a64_fixture("elf-clang-plt.so")],
                    Some(Default::default()),
                );
                let slice = s.code[0].slice.clone();
                if partial {
                    for c in &mut s.coverage {
                        if c.check.as_str() == BINARY_CODE {
                            c.state = CoverageState::Partial {
                                missing: vec![match &c.scope {
                                    Ref::Slice(_) => "code: budget gap".into(),
                                    _ => format!("code: incomplete slice {slice}"),
                                }],
                            };
                        }
                    }
                }
                if !has_call {
                    s.code.clear();
                }
                if install {
                    s = support::installation(s);
                }
                let p = evaluate_denied(&mut s, install, false);
                assert_eq!(s.policy_violations.len(), usize::from(has_call));
                assert_eq!(s.open_questions.len(), usize::from(!has_call));
                if has_call {
                    assert!(s.policy_violations[0].evidence.iter().all(|e| matches!(e, EvidenceRef::Code { slice: of, loc: Loc::CallSite(_) } if *of == slice)));
                }
                s.validate().unwrap();
                let round: Session = serde_json::from_str(&s.to_canonical_json().unwrap()).unwrap();
                sigil_engine::policy::verify(&round, &p).unwrap();
            }
        }
    }
}

#[test]
fn marked_elf_markdown_uses_local_search_and_escapes_call_text() {
    let mut s = support::named();
    support::inventory_partial(&mut s);
    let state = support::incomplete(&s, &[], true);
    support::parent(&mut s, state, Some(4));
    evaluate_denied(&mut s, false, false);
    let md = sigil_model::render::markdown::render_session(&s);
    assert!(sigil_model::render::html::from_markdown(&md).contains("none found (see binary.code)"));
    assert!(!md.contains("none found in the code searched"));
    let mut s = inspect_paths(
        vec![a64_fixture("elf-clang-plt.so")],
        Some(Default::default()),
    );
    s.code[0].functions[0].names = vec![UntrustedText::new("<script>\x1b[31m|bad")];
    let md = sigil_model::render::markdown::render_session(&s);
    assert!(
        sigil_model::render::html::from_markdown(&md).contains("x0=0, x1=0, x2=0"),
        "{md}"
    );
    assert!(!md.contains("<script>"));
    assert!(!md.contains('\x1b'));
    let html = sigil_model::render::html::from_markdown(&md);
    assert!(!html.contains("<script>"));
    assert!(html.contains("&lt;script&gt;"));
    assert!(!html.contains('\x1b'));
    let mut partial = support::named();
    support::child(&mut partial, 0).state = CoverageState::Partial {
        missing: vec!["code: budget gap".into()],
    };
    let state = support::incomplete(&partial, &[0], false);
    support::parent(&mut partial, state, Some(4));
    let mut partial = support::installation(partial);
    evaluate_denied(&mut partial, true, false);
    let md = sigil_model::render::markdown::render_session(&partial);
    assert!(md.contains("none found in searched code"), "{md}");
}

#[test]
fn marked_unsupported_elf_does_not_confirm_a_call() {
    let mut s = support::named();
    support::child(&mut s, 0).state = CoverageState::Unsupported {
        what: "code: unsupported ELF ABI".into(),
    };
    support::child(&mut s, 0).budget = None;
    if let ContainerFacts::Elf(e) = &mut s.binaries[0].container {
        e.abi.as_mut().unwrap().little_endian = false;
    }
    support::parent(
        &mut s,
        CoverageState::Unsupported {
            what: "code: no supported slice".into(),
        },
        None,
    );
    let p = evaluate_denied(&mut s, false, false);
    assert!(s.policy_violations.is_empty());
    assert!(matches!(
        s.open_questions[0].conditions[0].state,
        CondState::Unknown {
            reason: UnknownReason::CheckIncomplete { .. },
            ..
        }
    ));
    sigil_engine::policy::verify(&s, &p).unwrap();
}

#[test]
fn marked_macho_capability_evaluation_remains_gated_without_mutation() {
    let mut s = support::fat();
    if let ContainerFacts::MachO(m) = &mut s.binaries[0].container {
        m.imports.push(MachOImport {
            name: UntrustedText::new("_connect"),
            library: MachOLibrary::Unbound,
            weak: false,
        });
    }
    s.hints = sigil_engine::analyze::hints::derive(&s.binaries).unwrap();
    assert!(!s.hints.is_empty());
    let p = policy(true);
    let (audit, checks) = p.scope(&ScopeInput::of(&s.request));
    s.request.audit = audit;
    s.request.required_checks = checks;
    let before = s.clone();
    assert!(
        evaluate(&mut s, &p, Timestamp::new("2026-11-03T00:00:00Z").unwrap())
            .unwrap_err()
            .to_string()
            .contains("multiarch capability policy is not enabled")
    );
    assert_eq!(s, before);
}

#[test]
fn required_code_check_includes_every_slice_and_supports_explicit_opt_out() {
    for s in support::matrix() {
        for opt_out in [false, true] {
            let p = if opt_out {
                Policy::load("schema = \"sigil-policy/1\"\nname = \"coverage\"\n[scope]\nbinary_audit = []\nbinary_code_audit = []\n").unwrap()
            } else {
                policy(false)
            };
            let mut s = s.clone();
            let expected_complete = opt_out
                || s.coverage
                    .iter()
                    .filter(|c| c.check.as_str() == BINARY_CODE)
                    .all(|c| c.state.can_close());
            let (audit, checks) = p.scope(&ScopeInput::of(&s.request));
            s.request.audit = audit;
            s.request.required_checks = checks;
            evaluate(&mut s, &p, Timestamp::new("2026-11-03T00:00:00Z").unwrap()).unwrap();
            assert_eq!(
                s.outcome.completeness == Completeness::Complete,
                expected_complete
            );
            assert!(s.validate().is_ok(), "{:?}", s.validate());
        }
    }
}

#[test]
fn legacy_capability_policy_remains_enabled() {
    let mut s: Session = serde_json::from_str(include_str!(
        "../../../schemas/examples/session-v1/16-binary-code.json"
    ))
    .unwrap();
    let p = policy(true);
    let (audit, checks) = p.scope(&ScopeInput::of(&s.request));
    s.request.audit = audit;
    s.request.required_checks = checks;
    evaluate(&mut s, &p, Timestamp::new("2026-11-03T00:00:00Z").unwrap()).unwrap();
    assert!(!s.policy_violations.is_empty());
    s.validate().unwrap();
}

#[test]
fn empty_install_and_extra_required_checks_keep_existing_completeness() {
    for extra in [false, true] {
        let text = format!("schema = \"sigil-policy/1\"\nname = \"coverage\"\n[scope]\naudit = []\ninstall_audit = []\ninstall_code_audit = [\"installation_code\"]\nextra_required = [{}]\n", if extra { "\"exposure.binds\"" } else { "" });
        let p = Policy::load(&text).unwrap();
        let mut s = support::installation(support::named());
        s.artifacts.clear();
        s.binaries.clear();
        s.instances.clear();
        s.coverage.retain(|c| matches!(c.scope, Ref::Root(_)));
        let (audit, checks) = p.scope(&ScopeInput::of(&s.request));
        s.request.audit = audit;
        s.request.required_checks = checks;
        evaluate(&mut s, &p, Timestamp::new("2026-11-03T00:00:00Z").unwrap()).unwrap();
        assert_eq!(s.outcome.completeness == Completeness::Complete, !extra);
        s.validate().unwrap();
    }
}

#[test]
fn legacy_macho_parser_does_not_invent_a_code_byte_order_observation() {
    use sha2::{Digest, Sha256};
    use sigil_engine::binary::{parse_artifact, BinaryBudgets};
    let directory = tempfile::tempdir().unwrap();
    let mut containers = Vec::new();
    for big in [false, true] {
        let words = [0xfeed_facfu32, 0x0100_0007, 3, 2, 0, 0, 0, 0];
        let bytes: Vec<_> = words
            .iter()
            .flat_map(|word| {
                if big {
                    word.to_be_bytes()
                } else {
                    word.to_le_bytes()
                }
            })
            .collect();
        let path = directory.path().join(if big { "big" } else { "little" });
        std::fs::write(&path, &bytes).unwrap();
        let file = std::fs::File::open(path).unwrap();
        let digest = Sha256Hex::new(format!("{:x}", Sha256::digest(&bytes))).unwrap();
        let parsed = parse_artifact(
            &file,
            bytes.len() as u64,
            &digest,
            &bytes[..4],
            BinaryBudgets::default(),
            None,
        )
        .unwrap();
        let container = parsed.slices[0].container.clone().unwrap();
        assert!(matches!(&container,ContainerFacts::MachO(m) if m.little_endian.is_none()));
        let mut marked = support::named();
        marked.artifacts[0].format = Format::MachO;
        marked.binaries[0].container = container.clone();
        assert!(marked
            .validate()
            .unwrap_err()
            .iter()
            .any(|e| e.to_string().contains("supported parsed ABI")));
        containers.push(container);
    }
    assert_eq!(
        containers[0], containers[1],
        "legacy saved facts cannot prove byte order"
    );
}

mod common;
fn a64_fixture(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/code-aarch64")
        .join(name)
}
fn inspect_paths(
    paths: Vec<std::path::PathBuf>,
    code: Option<sigil_engine::code::CodeBudgets>,
) -> Session {
    inspect_with_binary_budgets(
        paths,
        sigil_engine::binary::BinaryBudgets {
            code,
            ..Default::default()
        },
    )
}
fn inspect_with_binary_budgets(
    paths: Vec<std::path::PathBuf>,
    binary: sigil_engine::binary::BinaryBudgets,
) -> Session {
    let budgets = sigil_engine::collect::named::NamedBudgets {
        binary,
        ..Default::default()
    };
    sigil_engine::inspect::binary_session(
        &sigil_engine::inspect::BinaryRequest {
            paths,
            budgets,
            deps_budgets: Default::default(),
        },
        &policy(false),
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap()
}

#[test]
fn incomplete_imports_produce_partial_code_session() {
    let s = inspect_with_binary_budgets(
        vec![std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/issue129/import-data.o")],
        sigil_engine::binary::BinaryBudgets {
            imports: 0,
            code: Some(Default::default()),
            ..Default::default()
        },
    );
    assert!(s
        .binaries
        .iter()
        .any(|b| b.gaps.iter().any(|g| g.starts_with("imports:"))));
    assert!(s.coverage.iter().any(|c| c.check.as_str() == BINARY_CODE
        && matches!(c.scope, Ref::Slice(_))
        && matches!(c.state, CoverageState::Partial { .. })));
    s.validate().unwrap();
}

#[test]
fn authenticated_got_branch_is_incomplete() {
    use object::{Object, ObjectSection};
    let original = std::fs::read(a64_fixture("elf-clang-got.so")).unwrap();
    let file = object::File::parse(original.as_slice()).unwrap();
    let section = file.section_by_name(".text").unwrap();
    let off = section.file_range().unwrap().0 + (0x10370 - section.address());
    for word in [
        0xd73f0911, 0xd73f0d11, 0xd71f0911, 0xd71f0d11, 0xd63f091f, 0xd63f0d1f, 0xd61f091f,
        0xd61f0d1f,
    ] {
        let mut bytes = original.clone();
        put32(&mut bytes, off as usize, word);
        let s = inspect_bytes(&bytes);
        assert!(s.coverage.iter().any(|c| c.check.as_str() == BINARY_CODE && matches!(c.scope, Ref::Slice(_)) && matches!(&c.state, CoverageState::Partial { missing } if missing.iter().any(|g| g.contains("authenticated")))), "{word:#x}");
        assert_eq!(calls(&s), [0x1039c]);
        s.validate().unwrap();
    }
}
#[test]
fn real_aarch64_elf_calls_match_independent_oracle() {
    for name in [
        "elf-clang-plt.so",
        "elf-gcc-plt.so",
        "elf-clang-got.so",
        "elf-gcc-got.so",
        "elf-clang-o0.o",
        "elf-clang-o2.o",
        "elf-gcc-o0.o",
        "elf-gcc-o2.o",
    ] {
        let s = inspect_paths(vec![a64_fixture(name)], Some(Default::default()));
        assert_eq!(
            s.request.code_analysis,
            Some(CodeAnalysis::MultiarchV1),
            "{name}"
        );
        assert_eq!(s.code.len(), 1, "{name}: {:?}", s.coverage);
        let rows: Vec<_> = include_str!("fixtures/code-aarch64/oracle.tsv")
            .lines()
            .skip(1)
            .map(|l| l.split('\t').collect::<Vec<_>>())
            .filter(|r| r[0] == name && r[5] != "-")
            .collect();
        assert_eq!(
            s.code[0].call_sites.len(),
            rows.len(),
            "{name}: {:?}",
            s.code
        );
        for row in rows {
            let hex = |v: &str| u64::from_str_radix(v.trim_start_matches("0x"), 16).unwrap();
            let call = s.code[0]
                .call_sites
                .iter()
                .find(|c| c.addr == hex(row[5]))
                .unwrap();
            let f = s.code[0]
                .functions
                .iter()
                .find(|f| f.id == call.caller)
                .unwrap();
            assert_eq!((f.entry, f.end), (hex(row[3]), hex(row[4])), "{name}");
            let via = if name.ends_with(".o") {
                ImportVia::Reloc
            } else if name.contains("got") {
                ImportVia::Got
            } else {
                ImportVia::Plt
            };
            assert!(
                matches!(&call.target, CallTarget::Import { symbol, via: actual, macho_import: None } if symbol.as_bytes() == b"connect" && *actual == via),
                "{name}: {:?}",
                call.target
            );
            assert_eq!(call.args_layout, Some(ArgumentLayout::Complete));
            for (index, reg) in [Reg::X0, Reg::X1, Reg::X2].iter().enumerate() {
                if row[8 + index] != "-" {
                    assert_eq!(
                        call.args[index],
                        ArgValue::ConstInt {
                            reg: *reg,
                            value: row[8 + index].parse().unwrap()
                        },
                        "{name}"
                    );
                }
            }
        }
        assert_eq!(
            s.coverage
                .iter()
                .filter(|c| c.check.as_str() == BINARY_CODE && matches!(c.scope, Ref::Slice(_)))
                .count(),
            1
        );
        s.validate().unwrap();
        let json = s.to_canonical_json().unwrap();
        let saved: Session = serde_json::from_str(&json).unwrap();
        saved.validate().unwrap();
        assert_eq!(s, saved);
    }
}

fn install_session(tree: &std::path::Path, budgets: sigil_engine::code::CodeBudgets) -> Session {
    use sigil_engine::{
        collect::{fs::FsBudgets, install::InstallBudgets},
        inspect::*,
    };
    let models = tempfile::tempdir().unwrap();
    let mut install_budgets = InstallBudgets::default();
    install_budgets.binary.code = Some(budgets);
    store_session(
        &StoreRequest {
            models_dir: models.path().into(),
            model_filter: None,
            budgets: FsBudgets::default(),
            manifest_limit: 1 << 20,
            deps_budgets: Default::default(),
            install: Some(InstallRequest {
                source: InstallSource::Dir(tree.into()),
                budgets: install_budgets,
            }),
        },
        &ActiveInput::default(),
        &Policy::builtin_default().unwrap(),
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap()
}
#[test]
fn stable_duplicates_share_code_and_children_in_binary_and_installation() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tree.path().join("bin")).unwrap();
    std::fs::create_dir_all(tree.path().join("lib/ollama")).unwrap();
    let first = tree.path().join("bin/ollama");
    let second = tree.path().join("lib/ollama/copy.so");
    std::fs::copy(a64_fixture("elf-gcc-plt.so"), &first).unwrap();
    std::fs::copy(&first, &second).unwrap();
    let named = inspect_paths(vec![first, second], Some(Default::default()));
    let install = install_session(tree.path(), Default::default());
    assert_eq!(named.code, install.code);
    for (s, check, parents) in [(&named, BINARY_CODE, 2), (&install, ARTIFACTS_CODE, 1)] {
        assert_eq!(s.request.code_analysis, Some(CodeAnalysis::MultiarchV1));
        assert_eq!(s.code.len(), 1);
        let children: Vec<_> = s
            .coverage
            .iter()
            .filter(|c| c.check.as_str() == check && matches!(c.scope, Ref::Slice(_)))
            .collect();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].state, CoverageState::Complete);
        let parents: Vec<_> = s
            .coverage
            .iter()
            .filter(|c| {
                c.check.as_str() == check && matches!(c.scope, Ref::Instance(_) | Ref::Artifact(_))
            })
            .take(parents + 1)
            .collect();
        assert_eq!(parents.len(), if check == BINARY_CODE { 2 } else { 1 });
        for parent in parents {
            assert_eq!(parent.budget, children[0].budget);
            assert_eq!(parent.state, CoverageState::Complete);
        }
        assert_eq!(
            s.artifacts
                .iter()
                .filter(|a| a.code_slice_inventory.is_some())
                .count(),
            1
        );
        s.validate().unwrap();
        let p = if check == BINARY_CODE {
            policy(false)
        } else {
            Policy::builtin_default().unwrap()
        };
        sigil_engine::policy::verify(s, &p).unwrap();
    }
}
#[test]
fn code_failures_preserve_container_and_healthy_functions() {
    use sigil_engine::code::CodeBudgets;
    let healthy = inspect_paths(
        vec![a64_fixture("elf-clang-plt.so")],
        Some(Default::default()),
    );
    for budget in [
        CodeBudgets {
            bytes: 0,
            ..Default::default()
        },
        CodeBudgets {
            value_steps: 0,
            ..Default::default()
        },
        CodeBudgets {
            references: 1,
            ..Default::default()
        },
        CodeBudgets {
            call_sites: 1,
            ..Default::default()
        },
    ] {
        let s = inspect_paths(vec![a64_fixture("elf-clang-plt.so")], Some(budget));
        assert_eq!(s.binaries, healthy.binaries);
        let c = s
            .coverage
            .iter()
            .find(|c| c.check.as_str() == BINARY_CODE && matches!(c.scope, Ref::Slice(_)))
            .unwrap();
        assert!(matches!(c.state, CoverageState::Partial { .. }), "{c:?}");
        if budget.bytes == 0 {
            assert_eq!(c.budget.as_ref().unwrap().used, 0);
        }
        if budget.references == 1 || budget.call_sites == 1 {
            assert_eq!(s.code[0].call_sites.len(), 1, "{s:?}");
        } else {
            assert!(s.code.is_empty());
        }
    }
    let no_fde = inspect_paths(vec![a64_fixture("elf-no-fde.so")], Some(Default::default()));
    assert!(no_fde.code.is_empty());
    assert!(no_fde.coverage.iter().any(|c| c.check.as_str()==BINARY_CODE && matches!(&c.state,CoverageState::Partial{missing} if missing.iter().any(|m|m.contains("bounds")))));
}
#[test]
fn marker_follows_recognition_and_code_flag() {
    let x86 = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/code/net-plt-gcc.so");
    for (paths, code, marked) in [
        (vec![x86.clone()], Some(Default::default()), false),
        (vec![a64_fixture("elf-clang-plt.so")], None, false),
        (
            vec![x86, a64_fixture("elf-clang-plt.so")],
            Some(Default::default()),
            true,
        ),
    ] {
        let s = inspect_paths(paths, code);
        assert_eq!(s.request.code_analysis.is_some(), marked);
        assert_eq!(
            s.knowledge
                .iter()
                .any(|k| k.id == sigil_model::code_abi::ID),
            marked
        );
        if !marked {
            assert!(s.artifacts.iter().all(|a| a.code_slice_inventory.is_none()));
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let malformed = dir.path().join("recognized-macho");
    std::fs::write(&malformed, [0xcf, 0xfa, 0xed, 0xfe]).unwrap();
    let s = inspect_paths(vec![malformed], Some(Default::default()));
    assert_eq!(s.request.code_analysis, Some(CodeAnalysis::MultiarchV1));
    assert!(s.artifacts[0].slices.is_empty());
    assert!(s.code.is_empty());
    assert!(matches!(
        s.artifacts[0].code_slice_inventory,
        Some(CodeSliceInventory::Partial { .. })
    ));
    assert!(s.coverage.iter().any(
        |c| c.check.as_str() == BINARY_CODE && matches!(c.state, CoverageState::Partial { .. })
    ));
}

fn section_at(bytes: &[u8], name: &str) -> usize {
    use object::{Object, ObjectSection};
    object::File::parse(bytes)
        .unwrap()
        .section_by_name(name)
        .unwrap()
        .file_range()
        .unwrap()
        .0 as usize
}
fn put32(bytes: &mut [u8], at: usize, word: u32) {
    bytes[at..at + 4].copy_from_slice(&word.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, word: u64) {
    bytes[at..at + 8].copy_from_slice(&word.to_le_bytes());
}
fn inspect_bytes(bytes: &[u8]) -> Session {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input");
    std::fs::write(&path, bytes).unwrap();
    inspect_paths(vec![path], Some(Default::default()))
}
fn calls(s: &Session) -> Vec<u64> {
    s.code
        .iter()
        .flat_map(|c| c.call_sites.iter().map(|c| c.addr))
        .collect()
}
#[test]
fn object_symbolic_tail_and_defined_branch_use_relocations() {
    let original = std::fs::read(a64_fixture("elf-clang-o2.o")).unwrap();
    let rel = section_at(&original, ".rela.text");
    let mut tail = original.clone();
    put32(&mut tail, 0x54, 0x14000000);
    put64(&mut tail, rel + 8, 0x60000011a);
    let s = inspect_bytes(&tail);
    assert_eq!(calls(&s), [0x54, 0x78]);
    assert_eq!(s.code[0].call_sites[0].kind, CallKind::TailJump);
    // A defined relocation to the second function, encoded BL+0, is an internal call.
    // Preserve its return as connect's x0 by replacing a later argument setup instruction.
    let mut internal = original.clone();
    put64(&mut internal, rel, 8);
    put64(&mut internal, rel + 8, 0x70000011b);
    put32(&mut internal, 0x48, 0x94000000);
    put32(&mut internal, 0x54, 0x94000009); // raw direct call to second entry (no import relocation)
                                            // Move second import relocation back to first call; function two now has no target candidate.
    put64(&mut internal, rel + 24, 0x14);
    put32(&mut internal, 0x54, 0x94000000);
    let s = inspect_bytes(&internal);
    assert_eq!(calls(&s), [0x48, 0x54]);
    assert!(matches!(
        s.code[0].call_sites[0].target,
        CallTarget::Internal { entry: 0x64, .. }
    ));
    assert!(matches!(
        s.code[0].call_sites[1].args[0],
        ArgValue::ReturnOf { .. }
    ));
    assert!(matches!(
        s.code[0].call_sites[0].args_layout,
        Some(ArgumentLayout::Partial { .. })
    ));
    s.validate().unwrap();
}
#[test]
fn bad_object_relocations_and_weak_symbols_do_not_create_calls() {
    let original = std::fs::read(a64_fixture("elf-clang-o2.o")).unwrap();
    let rel = section_at(&original, ".rela.text");
    let sym = section_at(&original, ".symtab");
    for case in 0..6 {
        let mut bytes = original.clone();
        match case {
            0 => put64(&mut bytes, rel + 16, 4),
            1 => put64(&mut bytes, rel + 8, 0xffff0000011b),
            2 => put32(&mut bytes, 0x54, 0x94000001),
            3 => bytes[sym + 6 * 24 + 4] = 0x20,
            4 => put64(&mut bytes, rel + 24, 0x14),
            _ => {
                put64(&mut bytes, rel, 0x20);
                put64(&mut bytes, rel + 8, 0x600000101);
            } // ABS64 crosses next entry
        }
        let s = inspect_bytes(&bytes);
        assert!(!calls(&s).contains(&0x54), "case {case}: {:?}", calls(&s));
        if case < 3 {
            assert_eq!(calls(&s), [0x78], "healthy sibling case {case}");
        } else {
            assert!(calls(&s).is_empty(), "case {case}");
        }
        assert!(
            s.coverage.iter().any(|c| c.check.as_str() == BINARY_CODE
                && matches!(c.state, CoverageState::Partial { .. })),
            "case {case}"
        );
    }
}
#[test]
fn object_got_pairs_and_import_tail_require_exact_provenance() {
    let mut original = std::fs::read(a64_fixture("elf-clang-o2.o")).unwrap();
    let rel = section_at(&original, ".rela.text");
    put32(&mut original, 0x48, 0x90000008);
    put32(&mut original, 0x50, 0xf9400108);
    put32(&mut original, 0x54, 0xd63f0100);
    put64(&mut original, rel, 8);
    put64(&mut original, rel + 8, 0x600000137);
    put64(&mut original, rel + 24, 16);
    put64(&mut original, rel + 32, 0x600000138);
    for tail in [false, true] {
        let mut bytes = original.clone();
        if tail {
            put32(&mut bytes, 0x54, 0xd61f0100);
        }
        let s = inspect_bytes(&bytes);
        assert_eq!(calls(&s), [0x54]);
        assert_eq!(
            s.code[0].call_sites[0].kind,
            if tail {
                CallKind::TailJump
            } else {
                CallKind::Call
            }
        );
        assert!(
            matches!(
                s.code[0].call_sites[0].args[0],
                ArgValue::Param { index: 0, .. }
            ),
            "raw ADRP is not x0=0"
        );
        for case in 0..4 {
            let mut bad = bytes.clone();
            match case {
                0 => put32(&mut bad, 0x4c, 0x52800008),
                1 => put64(&mut bad, rel + 32, 0x700000138),
                2 => put64(&mut bad, rel + 40, 4),
                _ => put32(&mut bad, 0x54, if tail { 0xd61f0120 } else { 0xd63f0120 }),
            }
            let s = inspect_bytes(&bad);
            assert!(calls(&s).is_empty(), "tail {tail} case {case}");
            assert!(s.coverage.iter().any(|c| c.check.as_str() == BINARY_CODE
                && matches!(c.state, CoverageState::Partial { .. })));
        }
    }
}

#[test]
fn aarch64_wrong_abi_and_truncated_recognition_never_fabricate_calls() {
    for (class, big) in [(1, false), (2, true)] {
        let size = if class == 1 { 52 } else { 64 };
        let mut b = vec![0u8; size];
        b[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', class, if big { 2 } else { 1 }, 1]);
        let half = |v: u16| {
            if big {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let word = |v: u32| {
            if big {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        b[16..18].copy_from_slice(&half(1));
        b[18..20].copy_from_slice(&half(183));
        b[20..24].copy_from_slice(&word(1));
        let at = if class == 1 { 40 } else { 52 };
        b[at..at + 2].copy_from_slice(&half(size as u16));
        let s = inspect_bytes(&b);
        assert!(s.code.is_empty());
        assert!(s.request.code_analysis.is_some());
        assert!(s.coverage.iter().any(|c| c.check.as_str() == BINARY_CODE
            && matches!(c.scope, Ref::Slice(_))
            && matches!(c.state, CoverageState::Unsupported { .. })
            && c.budget.is_none()));
    }
    let mut b = std::fs::read(a64_fixture("elf-clang-plt.so")).unwrap();
    b.truncate(64);
    let s = inspect_bytes(&b);
    assert!(s.request.code_analysis.is_some());
    assert!(s.code.is_empty());
    assert!(s.coverage.iter().any(
        |c| c.check.as_str() == BINARY_CODE && matches!(c.state, CoverageState::Partial { .. })
    ));
    b.truncate(24); // Existing recognition requires a whole ELF header.
    let s = inspect_bytes(&b);
    assert!(s.request.code_analysis.is_none());
    assert!(s.code.is_empty());
}
#[test]
fn stack_load_is_unknown_and_unlisted_signature_keeps_its_layout_gap() {
    let mut b = std::fs::read(a64_fixture("elf-clang-o2.o")).unwrap();
    put32(&mut b, 0x48, 0xb9400be0);
    let s = inspect_bytes(&b);
    assert!(matches!(
        s.code[0].call_sites[0].args[0],
        ArgValue::Unknown {
            reg: Reg::X0,
            reason: ValueUnknown::FromMemory
        }
    ));
    let mut b = std::fs::read(a64_fixture("elf-clang-o2.o")).unwrap();
    let offset = b.windows(8).position(|w| w == b"connect\0").unwrap();
    b[offset..offset + 8].copy_from_slice(b"execve\0\0");
    let s = inspect_bytes(&b);
    assert_eq!(calls(&s), [0x54, 0x78]);
    for c in &s.code[0].call_sites {
        assert!(c.args.is_empty());
        assert!(matches!(
            c.args_layout,
            Some(ArgumentLayout::Partial { .. })
        ));
    }
    assert!(s.coverage.iter().any(|c|c.check.as_str()==BINARY_CODE && matches!(&c.state,CoverageState::Partial{missing} if missing.iter().any(|g|g.contains("argument layout incomplete at cs:0x54")))));
}

#[test]
fn failed_reachable_instruction_rolls_back_its_whole_function() {
    let mut b = std::fs::read(a64_fixture("elf-clang-o2.o")).unwrap();
    // The candidate at 0x54 is followed by reachable unsupported bytes. No record
    // from that function may survive; the separate function at 0x64 still commits.
    put32(&mut b, 0x58, 0xffff_ffff);
    let s = inspect_bytes(&b);
    assert_eq!(calls(&s), [0x78]);
    assert_eq!(s.code[0].functions.len(), 1);
    assert_eq!(s.code[0].functions[0].entry, 0x64);
    assert!(s.coverage.iter().any(
        |c| c.check.as_str() == BINARY_CODE && matches!(c.state, CoverageState::Partial { .. })
    ));
    s.validate().unwrap();
}

#[test]
fn unavailable_container_or_import_evidence_never_completes_code() {
    use sigil_engine::binary::BinaryBudgets;
    for limited in [
        BinaryBudgets {
            parse_bytes: 0,
            ..Default::default()
        },
        BinaryBudgets {
            imports: 0,
            ..Default::default()
        },
    ] {
        let path = a64_fixture("elf-clang-plt.so");
        let off = inspect_with_binary_budgets(vec![path.clone()], limited);
        let on = inspect_with_binary_budgets(
            vec![path],
            BinaryBudgets {
                code: Some(Default::default()),
                ..limited
            },
        );
        assert_eq!(on.binaries, off.binaries);
        assert!(on.code.is_empty());
        assert_eq!(on.request.code_analysis, Some(CodeAnalysis::MultiarchV1));
        assert!(on.coverage.iter().any(|c| c.check.as_str() == BINARY_CODE
            && matches!(c.scope, Ref::Instance(_))
            && matches!(c.state, CoverageState::Partial { .. })));
        assert_eq!(
            on.coverage
                .iter()
                .filter(|c| c.check.as_str() == BINARY_CONTAINER)
                .collect::<Vec<_>>(),
            off.coverage
                .iter()
                .filter(|c| c.check.as_str() == BINARY_CONTAINER)
                .collect::<Vec<_>>()
        );
        on.validate().unwrap();
    }
}

#[test]
fn newly_scannable_alias_preserves_the_original_code_outcome() {
    let d = tempfile::tempdir().unwrap();
    let hidden = d.path().join("libcudart.so.12");
    let scanned = d.path().join("ordinary.so");
    for path in [&hidden, &scanned] {
        std::fs::copy(a64_fixture("elf-clang-plt.so"), path).unwrap();
    }
    let one = inspect_paths(vec![hidden.clone()], Some(Default::default()));
    let both = inspect_paths(vec![hidden, scanned], Some(Default::default()));
    assert_eq!(one.code, both.code);
    let children = |s: &Session| {
        s.coverage
            .iter()
            .filter(|c| c.check.as_str() == BINARY_CODE && matches!(c.scope, Ref::Slice(_)))
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(children(&one), children(&both));
    assert_eq!(both.code.len(), 1);
    assert_eq!(both.instances.len(), 2);
    both.validate().unwrap();
}

#[test]
fn marked_collection_io_usage_round_trips_and_rejects_forged_limits() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("arm.so");
    std::fs::copy(a64_fixture("elf-clang-plt.so"), &path).unwrap();
    let size = std::fs::metadata(&path).unwrap().len();
    let s = inspect_paths(vec![path], Some(Default::default()));
    for (check, used) in [
        ("binary.collection.hash", size),
        ("binary.collection.probe", 0),
        ("binary.collection.revalidation", size),
    ] {
        let c = s
            .coverage
            .iter()
            .find(|c| c.check.as_str() == check)
            .unwrap();
        assert_eq!(c.budget.as_ref().unwrap().used, used);
        assert!(c.budget.as_ref().unwrap().used <= c.budget.as_ref().unwrap().limit);
    }
    let json = s.to_canonical_json().unwrap();
    let reread: Session = serde_json::from_str(&json).unwrap();
    reread.validate().unwrap();
    let mut forged = s.clone();
    let c = forged
        .coverage
        .iter_mut()
        .find(|c| c.check.as_str() == "binary.collection.revalidation")
        .unwrap();
    c.budget.as_mut().unwrap().used = c.budget.as_ref().unwrap().limit + 1;
    assert!(forged.validate().is_err());
    let mut missing = s;
    missing
        .coverage
        .retain(|c| c.check.as_str() != "binary.collection.probe");
    assert!(missing.validate().is_err());
}

#[test]
fn macho_descriptor_loss_and_unparsed_children_stay_distinct_without_dispatch() {
    let original = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/macho/hello-universal"),
    )
    .unwrap();
    let complete = inspect_bytes(&original);
    assert!(complete.code.is_empty());
    assert_eq!(
        complete.artifacts[0].code_slice_inventory,
        Some(CodeSliceInventory::Complete)
    );
    assert!(complete
        .coverage
        .iter()
        .filter(|c| c.check.as_str() == BINARY_CODE)
        .all(|c| matches!(c.state, CoverageState::Unsupported { .. }) && c.budget.is_none()));
    for lost_descriptor in [false, true] {
        let mut b = original.clone();
        if lost_descriptor {
            // The first fat descriptor is outside the file; the second is independent.
            let beyond = b.len() as u32 + 4096;
            b[16..20].copy_from_slice(&beyond.to_be_bytes());
        } else {
            // The hashed descriptor remains present, but its thin magic is unparsed.
            b[4096..4100].fill(0);
        }
        let s = inspect_bytes(&b);
        assert!(s.code.is_empty());
        assert_eq!(
            s.artifacts[0].slices.len(),
            if lost_descriptor { 1 } else { 2 }
        );
        assert_eq!(
            matches!(
                s.artifacts[0].code_slice_inventory,
                Some(CodeSliceInventory::Partial { .. })
            ),
            lost_descriptor
        );
        assert!(s.coverage.iter().any(|c| c.check.as_str() == BINARY_CODE
            && matches!(c.scope, Ref::Instance(_))
            && matches!(c.state, CoverageState::Partial { .. })
            && c.budget.as_ref().is_some_and(|b| b.used == 0)));
        if !lost_descriptor {
            assert!(s.coverage.iter().any(|c| c.check.as_str() == BINARY_CODE && matches!(c.scope, Ref::Slice(_)) && matches!(&c.state, CoverageState::Partial { missing } if missing == &[sigil_model::code_coverage::CODE_SLICE_NOT_PARSED]) && c.budget.as_ref().is_some_and(|b| b.used == 0)));
        }
        s.validate().unwrap();
    }
}

#[test]
fn mandatory_layout_gap_boundaries_preserve_earlier_function() {
    for (count, cap, retained) in [
        (255, 256, 256),
        (256, 256, 257),
        (257, 256, 1),
        (255, 0, 1),
        (255, 254, 1),
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "tests/fixtures/code-aarch64-gap-limit/calls-{count}.o"
        ));
        let s = inspect_paths(
            vec![path],
            Some(sigil_engine::code::CodeBudgets {
                gaps: cap,
                ..Default::default()
            }),
        );
        assert_eq!(
            s.code[0].call_sites.len(),
            retained,
            "count={count}, cap={cap}"
        );
        assert_eq!(s.code[0].functions.len(), if retained == 1 { 1 } else { 2 });
        let healthy = s.code[0].call_sites.iter().find(|c| matches!(&c.target, CallTarget::Import { symbol, .. } if symbol.as_bytes() == b"connect")).unwrap();
        assert_eq!(healthy.args_layout, Some(ArgumentLayout::Complete));
        assert!(s.coverage.iter().any(|c| c.check.as_str() == BINARY_CODE && matches!(&c.state,CoverageState::Partial { missing } if retained > 1 || missing.contains(&format!("code: gaps limit {cap} reached")))));
        s.validate().unwrap();
        let json = s.to_canonical_json().unwrap();
        let decoded: Session = serde_json::from_str(&json).unwrap();
        decoded.validate().unwrap();
        assert_eq!(json, decoded.to_canonical_json().unwrap());
    }
}
