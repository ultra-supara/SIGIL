#[path = "support/multiarch.rs"]
mod support;
use sigil_model::*;
use support::*;
#[allow(unused_macros)]
#[path = "support/schema_check.rs"]
mod schema_check;

fn valid(s: &Session) {
    assert!(s.validate().is_ok(), "{:?}", s.validate());
    let json = s.to_canonical_json().unwrap();
    static SCHEMA: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    let schema = SCHEMA.get_or_init(|| {
        schema_check::validator_for(&schema_check::load("session-v1.schema.json"), "Session")
    });
    schema_check::assert_valid_against(
        schema,
        &serde_json::from_str(&json).unwrap(),
        "coverage matrix",
    );
    let round: Session = serde_json::from_str(&json).unwrap();
    assert!(round.validate().is_ok());
}

#[test]
#[ignore = "write synthetic marked sessions for explicit CLI/actual WASM parity checks"]
fn export_coverage_matrix() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/tmp/issue48/task4-sessions");
    std::fs::create_dir_all(&path).unwrap();
    for (i, s) in matrix().into_iter().enumerate() {
        for (kind, s) in [("named", s.clone()), ("install", installation(s))] {
            valid(&s);
            std::fs::write(
                path.join(format!("{i}-{kind}.json")),
                s.to_canonical_json().unwrap(),
            )
            .unwrap();
        }
    }
}

fn code_error(s: &Session) {
    assert!(
        s.validate()
            .unwrap_err()
            .iter()
            .any(|e| matches!(e, ValidationError::Code { .. })),
        "{:?}",
        s.validate()
    );
}

#[test]
fn coverage_matrix_and_lost_descriptor_precedence() {
    for mut s in matrix() {
        valid(&s);
        let canonical = s.to_canonical_json().unwrap();
        s.coverage.reverse();
        s.artifacts[0].slices.reverse();
        s.binaries.reverse();
        valid(&s);
        assert_eq!(canonical, s.to_canonical_json().unwrap());
    }
}

#[test]
fn rejects_missing_duplicate_wrong_scope_and_forged_budgets() {
    for case in 0..12 {
        let mut s = fat();
        match case {
            0 => {
                s.artifacts[0].code_slice_inventory = None;
            }
            1 => {
                s.coverage
                    .retain(|c| c.scope != Ref::Slice(s.artifacts[0].slices[1].id.clone()));
            }
            2 => {
                let c = child(&mut s, 0).clone();
                s.coverage.push(c);
            }
            3 => {
                child(&mut s, 0).check = CheckId::new(ARTIFACTS_CODE).unwrap();
            }
            4 => {
                child(&mut s, 0).budget.as_mut().unwrap().used = 6;
            }
            5 => {
                child(&mut s, 0).budget.as_mut().unwrap().limit = 11;
            }
            6 => {
                child(&mut s, 0).budget = None;
            }
            7 => {
                parent(&mut s, CoverageState::Complete, Some(8));
            }
            8 => {
                inventory_partial(&mut s);
            }
            9 => {
                child(&mut s, 0).state = CoverageState::Partial { missing: vec![] };
            }
            10 => {
                child(&mut s, 0).state = CoverageState::OutOfScope {
                    why: "forged".into(),
                };
            }
            11 => {
                s.binaries.pop();
            }
            _ => unreachable!(),
        }
        completeness(&mut s);
        code_error(&s);
    }
}

#[test]
fn inventory_and_unparsed_mutations_are_independent_code_errors() {
    for case in 0..11 {
        let mut s = named();
        match case {
            0..=3 => {
                let missing = match case {
                    0 => vec![],
                    1 => vec!["code: slice inventory incomplete".into(); 2],
                    2 => vec!["z".into(), "code: slice inventory incomplete".into()],
                    _ => vec!["unrelated import gap".into()],
                };
                s.artifacts[0].code_slice_inventory = Some(CodeSliceInventory::Partial { missing });
            }
            4 => {
                s.artifacts[0].slices.clear();
                s.binaries.clear();
                s.coverage.retain(|c| !matches!(c.scope, Ref::Slice(_)));
            }
            5 | 6 => {
                s.binaries.clear();
                let c = child(&mut s, 0);
                c.state = if case == 5 {
                    CoverageState::Unsupported {
                        what: "no header".into(),
                    }
                } else {
                    CoverageState::Complete
                };
                c.budget = None;
            }
            7 => {
                let c = child(&mut s, 0);
                c.state = CoverageState::Partial {
                    missing: vec!["b".into(), "a".into()],
                };
            }
            8 => {
                let c = child(&mut s, 0);
                c.state = CoverageState::Partial {
                    missing: vec!["a".into(); 2],
                };
            }
            9 => {
                let c = child(&mut s, 0);
                c.state = CoverageState::Partial {
                    missing: vec!["code: artifact budget exhausted before slice".into()],
                };
            }
            _ => {
                if let ContainerFacts::Elf(e) = &mut s.binaries[0].container {
                    e.abi = None;
                }
            }
        }
        completeness(&mut s);
        code_error(&s);
    }
}

#[test]
fn installation_folds_content_and_discovery_without_losing_siblings() {
    for s in [fat(), {
        let mut s = fat();
        inventory_partial(&mut s);
        let state = incomplete(&s, &[], true);
        parent(&mut s, state, Some(9));
        s
    }] {
        let s = installation(s);
        valid(&s);
        let mut duplicate = s.clone();
        let mut i = duplicate.instances[0].clone();
        i.id = InstanceId::new("inst:install/lib/copy").unwrap();
        i.path = UntrustedText::new("/installation/lib/copy");
        duplicate.instances.push(i);
        valid(&duplicate);
        for state in [
            CoverageState::Partial {
                missing: vec!["unread directory".into()],
            },
            CoverageState::Error {
                message: UntrustedText::new("read failed"),
            },
            CoverageState::Unavailable {
                why: Unavailability::PermissionDenied,
            },
        ] {
            let mut changed = s.clone();
            changed
                .coverage
                .iter_mut()
                .find(|c| c.check.as_str() == ARTIFACTS_DISCOVERY)
                .unwrap()
                .state = state.clone();
            let expected = match state {
                CoverageState::Partial { .. } => {
                    let mut missing = vec!["discovery incomplete".into()];
                    if changed.coverage.iter().any(|c| {
                        c.check.as_str() == ARTIFACTS_CODE
                            && matches!(c.scope, Ref::Artifact(_))
                            && !c.state.can_close()
                    }) {
                        missing.push(
                            "one or more binary contents have incomplete code coverage".into(),
                        );
                    }
                    CoverageState::Partial { missing }
                }
                state => state,
            };
            changed
                .coverage
                .iter_mut()
                .find(|c| c.check.as_str() == ARTIFACTS_CODE && matches!(c.scope, Ref::Root(_)))
                .unwrap()
                .state = expected;
            completeness(&mut changed);
            valid(&changed);
            changed
                .coverage
                .iter_mut()
                .find(|c| c.check.as_str() == ARTIFACTS_CODE && matches!(c.scope, Ref::Root(_)))
                .unwrap()
                .state = CoverageState::Complete;
            completeness(&mut changed);
            code_error(&changed);
        }
    }
}

#[test]
fn duplicate_named_placements_share_children_and_failed_reads_do_not_supply_inventory() {
    for stable_duplicate in [false, true] {
        let mut s = named();
        if stable_duplicate {
            let raw = serde_json::to_string(&s)
                .unwrap()
                .replace("binary-1", "binary-2");
            let second: Session = serde_json::from_str(&raw).unwrap();
            s.request.roots.extend(second.request.roots);
            s.instances.extend(second.instances);
            s.coverage.extend(
                second
                    .coverage
                    .into_iter()
                    .filter(|c| !matches!(c.scope, Ref::Slice(_))),
            );
        } else {
            s.artifacts[0].code_slice_inventory = None;
            s.binaries.clear();
            s.coverage.retain(|c| !matches!(c.scope, Ref::Slice(_)));
        }
        s.instances[0].stability = Stability::ChangedDuringRead;
        let id = s.instances[0].id.clone();
        for c in &mut s.coverage {
            if c.scope == Ref::Instance(id.clone()) {
                c.state = CoverageState::Error {
                    message: UntrustedText::new(BINARY_CHANGED),
                };
                c.budget = None;
            }
        }
        completeness(&mut s);
        valid(&s);
        if !stable_duplicate {
            s.artifacts[0].code_slice_inventory = Some(CodeSliceInventory::Complete);
            code_error(&s);
        }
    }
}

#[test]
fn unrelated_inventory_and_wrong_applicable_check_are_rejected() {
    let mut s = installation(named());
    valid(&s);
    let c = s
        .coverage
        .iter_mut()
        .find(|c| matches!(c.scope, Ref::Slice(_)))
        .unwrap();
    c.check = CheckId::new(BINARY_CODE).unwrap();
    code_error(&s);
    let mut s = named();
    s.instances.clear();
    s.request.roots.clear();
    code_error(&s);
    let mut s = named();
    s.artifacts[0].format = Format::Other;
    code_error(&s);
}

#[test]
fn child_budgets_use_checked_sums_and_no_synthetic_slice_ids() {
    let mut s = fat();
    let original = s.artifacts[0].slices.clone();
    inventory_partial(&mut s);
    let children: Vec<_> = s
        .coverage
        .iter()
        .filter(|c| matches!(c.scope, Ref::Slice(_)))
        .collect();
    let (state, budget) =
        code_coverage::aggregate_code_slices(&s.artifacts[0], &children, 10).unwrap();
    assert_eq!(state, incomplete(&s, &[], true));
    assert_eq!(budget.unwrap().used, 9);
    assert_eq!(s.artifacts[0].slices, original);
    for n in 0..2 {
        child(&mut s, n).budget = Some(BudgetUse {
            budget: BINARY_CODE_BYTES.into(),
            used: u64::MAX,
            limit: u64::MAX,
        });
    }
    let children: Vec<_> = s
        .coverage
        .iter()
        .filter(|c| matches!(c.scope, Ref::Slice(_)))
        .collect();
    assert!(
        code_coverage::aggregate_code_slices(&s.artifacts[0], &children, u64::MAX)
            .unwrap_err()
            .contains("overflow")
    );
}

#[test]
fn shared_exhaustion_follows_slice_offsets_not_input_order() {
    let mut s = fat();
    child(&mut s, 0).state = CoverageState::Partial {
        missing: vec!["code: artifact budget exhausted before slice".into()],
    };
    child(&mut s, 0).budget = Some(budget(0));
    for reverse in [false, true] {
        if reverse {
            s.coverage.reverse();
            s.artifacts[0].slices.reverse();
        }
        let children: Vec<_> = s
            .coverage
            .iter()
            .filter(|c| matches!(c.scope, Ref::Slice(_)))
            .collect();
        assert!(
            code_coverage::aggregate_code_slices(&s.artifacts[0], &children, 10).is_err(),
            "a later complete child cannot follow shared exhaustion"
        );
    }
}

#[test]
fn healthy_function_evidence_survives_unparsed_and_discarded_siblings() {
    for discarded in [false, true] {
        let mut s = fat();
        let legacy: Session = serde_json::from_str(include_str!(
            "../../../schemas/examples/session-v1/16-binary-code.json"
        ))
        .unwrap();
        let mut facts = legacy.code[0].clone();
        facts.slice = s.artifacts[0].slices[0].id.clone();
        facts.call_sites.clear();
        s.code.push(facts.clone());
        s.binaries.pop();
        if discarded {
            let removed = s.artifacts[0].slices.pop().unwrap();
            s.coverage
                .retain(|c| c.scope != Ref::Slice(removed.id.clone()));
            inventory_partial(&mut s);
        } else {
            child(&mut s, 1).state = CoverageState::Partial {
                missing: vec!["code: slice not parsed".into()],
            };
            child(&mut s, 1).budget = Some(budget(0));
        }
        let state = incomplete(&s, if discarded { &[] } else { &[1] }, discarded);
        parent(&mut s, state, Some(4));
        let container = expected_binary_container(&s, &s.instances[0])
            .unwrap()
            .into_state(0);
        s.coverage
            .iter_mut()
            .find(|c| c.check.as_str() == BINARY_CONTAINER)
            .unwrap()
            .state = container;
        completeness(&mut s);
        valid(&s);
        valid(&installation(s.clone()));
        assert_eq!(s.code, vec![facts.clone()]);
        if !discarded {
            facts.slice = s.artifacts[0].slices[1].id.clone();
            s.code.push(facts);
            code_error(&s);
        }
    }
}

#[test]
fn unstable_install_and_hash_budget_failure_keep_legacy_failure_semantics() {
    let mut s = installation(named());
    s.instances[0].stability = Stability::Vanished;
    s.artifacts[0].code_slice_inventory = None;
    s.binaries.clear();
    s.coverage.retain(|c| !matches!(c.scope, Ref::Slice(_)));
    for c in &mut s.coverage {
        if c.check.as_str() == ARTIFACTS_CODE {
            if matches!(c.scope, Ref::Artifact(_)) {
                c.state = CoverageState::Partial {
                    missing: vec![BINARY_NOT_PARSED.into()],
                };
                c.budget = Some(budget(0));
            } else {
                c.state = CoverageState::Partial {
                    missing: vec![
                        "one or more binary contents have incomplete code coverage".into()
                    ],
                };
            }
        }
    }
    completeness(&mut s);
    valid(&s);
    s.artifacts[0].code_slice_inventory = Some(CodeSliceInventory::Complete);
    code_error(&s);
    let mut s = named();
    s.instances[0].content = InstanceContent::NotRead {
        why: NotReadReason::BudgetExceeded,
    };
    s.artifacts.clear();
    s.binaries.clear();
    s.coverage.retain(|c| !matches!(c.scope, Ref::Slice(_)));
    for c in &mut s.coverage {
        c.state = CoverageState::BudgetExceeded {
            budget: BINARY_BYTES.into(),
            used: 0,
            limit: s.request.budgets[BINARY_BYTES],
        };
        c.budget = None;
    }
    completeness(&mut s);
    valid(&s);
}

#[test]
fn unsupported_children_cannot_carry_code_facts() {
    let mut s = named();
    let legacy: Session = serde_json::from_str(include_str!(
        "../../../schemas/examples/session-v1/16-binary-code.json"
    ))
    .unwrap();
    s.code = legacy.code;
    let c = child(&mut s, 0);
    c.state = CoverageState::Unsupported {
        what: "code: unsupported input".into(),
    };
    c.budget = None;
    parent(
        &mut s,
        CoverageState::Unsupported {
            what: "code: no supported slice".into(),
        },
        None,
    );
    code_error(&s);
}

#[test]
fn exhausted_artifact_keeps_a_later_unparsed_child_exact() {
    let mut s = fat();
    child(&mut s, 0).state = CoverageState::Partial {
        missing: vec!["code: artifact budget exhausted before slice".into()],
    };
    child(&mut s, 0).budget = Some(budget(0));
    s.binaries.pop();
    child(&mut s, 1).state = CoverageState::Partial {
        missing: vec!["code: slice not parsed".into()],
    };
    child(&mut s, 1).budget = Some(budget(0));
    let state = incomplete(&s, &[0, 1], false);
    parent(&mut s, state, Some(0));
    let container = expected_binary_container(&s, &s.instances[0])
        .unwrap()
        .into_state(0);
    s.coverage
        .iter_mut()
        .find(|c| c.check.as_str() == BINARY_CONTAINER)
        .unwrap()
        .state = container;
    completeness(&mut s);
    valid(&s);
}

#[test]
fn unstarted_slice_cannot_carry_preexisting_code_facts() {
    let mut s = named();
    let legacy: Session = serde_json::from_str(include_str!(
        "../../../schemas/examples/session-v1/16-binary-code.json"
    ))
    .unwrap();
    s.code = legacy.code;
    child(&mut s, 0).state = CoverageState::Partial {
        missing: vec!["code: artifact budget exhausted before slice".into()],
    };
    child(&mut s, 0).budget = Some(budget(0));
    let state = incomplete(&s, &[0], false);
    parent(&mut s, state, Some(0));
    code_error(&s);
}

#[test]
fn out_of_scope_inventory_and_foreign_slice_ids_are_code_errors() {
    let mut s = named();
    let raw = serde_json::to_string(&s).unwrap().replace(
        s.artifacts[0].id.as_str().strip_prefix("sha256:").unwrap(),
        &"bb".repeat(32),
    );
    let other: Session = serde_json::from_str(&raw).unwrap();
    s.artifacts.push(other.artifacts[0].clone());
    code_error(&s);
    let mut s = named();
    s.artifacts[0].slices[0].id = other.artifacts[0].slices[0].id.clone();
    code_error(&s);
    let raw = serde_json::to_string(&named()).unwrap();
    let duplicate = raw.replace(
        "\"code_slice_inventory\":\"Complete\"",
        "\"code_slice_inventory\":\"Complete\",\"code_slice_inventory\":\"Complete\"",
    );
    assert!(serde_json::from_str::<Session>(&duplicate)
        .unwrap_err()
        .to_string()
        .contains("duplicate field"));
}

#[test]
fn macho_analyzed_children_need_explicit_little_endian_observations() {
    let mut value = serde_json::to_value(fat()).unwrap();
    for binary in value["binaries"].as_array_mut().unwrap() {
        binary["container"]["MachO"]
            .as_object_mut()
            .unwrap()
            .remove("little_endian");
    }
    let absent: Session = serde_json::from_value(value.clone()).unwrap();
    code_error(&absent);
    for binary in value["binaries"].as_array_mut().unwrap() {
        binary["container"]["MachO"]["little_endian"] = serde_json::json!(true);
    }
    let present: Session =
        serde_json::from_value(value.clone()).expect("new byte-order observation is additive");
    valid(&present);
    value["binaries"][0]["container"]["MachO"]["little_endian"] = serde_json::json!(false);
    code_error(&serde_json::from_value::<Session>(value.clone()).unwrap());
    for order in [Some(false), None] {
        let mut s = present.clone();
        if let ContainerFacts::MachO(m) = &mut s.binaries[0].container {
            m.little_endian = order;
        }
        let c = child(&mut s, 0);
        c.state = CoverageState::Unsupported {
            what: "code: unproved or unsupported Mach-O byte order".into(),
        };
        c.budget = None;
        let state = incomplete(&s, &[0], false);
        parent(&mut s, state, Some(5));
        valid(&s);
    }
    let mut downgrade = present.clone();
    downgrade.request.code_analysis = None;
    assert!(downgrade.validate().unwrap_err().iter().any(|e| e
        .to_string()
        .contains("Mach-O byte-order observation needs multiarch-v1")));
    value["binaries"][0]["container"]["MachO"]["little_endian"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<Session>(value).is_err());
}

fn refresh_container(s: &mut Session) {
    let state = expected_binary_container(s, &s.instances[0])
        .unwrap()
        .into_state(0);
    s.coverage
        .iter_mut()
        .find(|c| c.check.as_str() == BINARY_CONTAINER)
        .unwrap()
        .state = state;
    completeness(s);
}

#[test]
fn typed_fat_cpu_conflicts_cannot_claim_complete_inventory_or_code() {
    for duplicate in [false, true] {
        let mut s = fat();
        if duplicate {
            let old = s.artifacts[0].slices[1].id.clone();
            s.artifacts[0].slices[1].arch = Arch::X86_64;
            s.artifacts[0].slices[1].id =
                SliceId::new(format!("{}#x86_64@2048", s.artifacts[0].id)).unwrap();
            s.binaries[1].slice = s.artifacts[0].slices[1].id.clone();
            s.binaries[1].container = s.binaries[0].container.clone();
            for c in &mut s.coverage {
                if c.scope == Ref::Slice(old.clone()) {
                    c.scope = Ref::Slice(s.binaries[1].slice.clone());
                }
            }
            for b in &mut s.binaries {
                b.gaps.push(FAT_DUPLICATE_ARCH_GAP.into());
            }
        } else {
            if let ContainerFacts::MachO(m) = &mut s.binaries[1].container {
                m.cpu_subtype = 1;
            }
            s.binaries[1].gaps.push(FAT_CPU_MISMATCH_GAP.into());
        }
        refresh_container(&mut s);
        code_error(&s);
        inventory_partial(&mut s);
        // Fixing the inventory alone cannot lend Complete to ambiguous children.
        let state = incomplete(&s, &[], true);
        parent(&mut s, state, Some(9));
        refresh_container(&mut s);
        code_error(&s);
        let affected: &[usize] = if duplicate { &[0, 1] } else { &[1] };
        for &n in affected {
            let c = child(&mut s, n);
            c.state = CoverageState::Partial {
                missing: vec!["code: ambiguous fat CPU descriptor".into()],
            };
            c.budget = Some(budget(0));
        }
        let state = incomplete(&s, affected, true);
        parent(&mut s, state, Some(if duplicate { 0 } else { 4 }));
        refresh_container(&mut s);
        valid(&s);
        let legacy: Session = serde_json::from_str(include_str!(
            "../../../schemas/examples/session-v1/16-binary-code.json"
        ))
        .unwrap();
        let mut facts = legacy.code[0].clone();
        facts.call_sites.clear();
        if duplicate {
            let healthy = fat();
            let mut slice = healthy.artifacts[0].slices[1].clone();
            slice.offset = 3072;
            slice.id = SliceId::new(format!("{}#aarch64@3072", s.artifacts[0].id)).unwrap();
            let mut binary = healthy.binaries[1].clone();
            binary.slice = slice.id.clone();
            s.coverage.push(Coverage {
                check: CheckId::new(BINARY_CODE).unwrap(),
                scope: Ref::Slice(slice.id.clone()),
                state: CoverageState::Complete,
                budget: Some(budget(4)),
            });
            facts.slice = slice.id.clone();
            s.code.push(facts.clone());
            s.artifacts[0].slices.push(slice);
            s.binaries.push(binary);
            let state = incomplete(&s, affected, true);
            parent(&mut s, state, Some(4));
            refresh_container(&mut s);
            valid(&s);
        } else {
            facts.slice = s.artifacts[0].slices[0].id.clone();
            s.code.push(facts.clone());
            valid(&s);
        }
        facts.slice = s.artifacts[0].slices[1].id.clone();
        s.code.push(facts);
        code_error(&s);
    }
}

#[test]
fn retained_overlapping_descriptors_are_not_a_complete_inventory() {
    let mut s = fat();
    let old = s.artifacts[0].slices[1].id.clone();
    s.artifacts[0].slices[1].offset = 512;
    let new = SliceId::new(format!("{}#aarch64@512", s.artifacts[0].id)).unwrap();
    s.artifacts[0].slices[1].id = new.clone();
    s.binaries[1].slice = new.clone();
    for c in &mut s.coverage {
        if c.scope == Ref::Slice(old.clone()) {
            c.scope = Ref::Slice(new.clone());
        }
    }
    code_error(&s);
}
