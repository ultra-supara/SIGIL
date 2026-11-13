//! `sigil_model::diff` (#16, PR-16a): what `sigil compare` reports between two sessions.

mod common;

use common::diff_cases::*;
use common::*;
use sigil_model::diff::*;
use sigil_model::render::aibom::ReleaseBasisKind;
use sigil_model::*;

#[test]
fn identical_sessions_give_no_differences() {
    for (name, s) in [
        ("complete_pass", complete_pass()),
        ("store_and_runtime", store_and_runtime()),
        ("binary_inspect", binary_inspect()),
    ] {
        let diff = diff_of(&s, &s);
        assert!(diff.changes.is_empty(), "{name}: {:?}", diff.changes);
        assert!(
            diff.not_comparable.is_empty(),
            "{name}: {:?}",
            diff.not_comparable
        );
        assert_eq!(diff.schema, DiffSchema::V1);
        assert_eq!(diff.baseline, diff.current);
        assert_eq!(diff.baseline.sha256, session_sha256(&s));
    }
}

#[test]
fn a_side_names_its_session_mode_start_and_policy() {
    let s = store_and_runtime();
    let diff = diff_of(&complete_pass(), &s);
    assert_eq!(diff.current.mode, Mode::Observe);
    assert_eq!(diff.baseline.mode, Mode::Static);
    assert_eq!(diff.current.started_at, s.observation.started_at);
    assert_eq!(
        diff.current.policy.as_ref().map(|k| k.id.as_str()),
        Some("default")
    );
    assert_eq!(diff.current.tool, s.tool);
    assert_eq!(diff.tool, example_tool());
}

#[test]
fn canonical_json_orders_changes_by_kind_then_text() {
    let mut diff = diff_of(&complete_pass(), &complete_pass());
    diff.changes = vec![
        Change::ModelAdded {
            model: id("model:models/registry.ollama.ai/library/n/latest"),
            name: t("n:latest"),
        },
        Change::VerdictChanged {
            baseline: Verdict::Pass,
            current: Verdict::Warn,
        },
        Change::ModelAdded {
            model: id("model:models/registry.ollama.ai/library/a/latest"),
            name: t("a:latest"),
        },
    ];
    // Hand-made changes are judged again: a diff reads back only as judged.
    diff.evaluation = builtin_rules().judge(
        &diff.baseline.completeness,
        &diff.current.completeness,
        &diff.changes,
        &diff.not_comparable,
    );
    let json = diff.to_canonical_json().unwrap();
    assert!(json.ends_with("}\n"), "{json}");
    let back: Diff = serde_json::from_str(&json).unwrap();
    assert_eq!(kinds(&back), ["VerdictChanged", "ModelAdded", "ModelAdded"]);
    let Change::ModelAdded { name, .. } = &back.changes[1] else {
        unreachable!()
    };
    assert_eq!(name, &t("a:latest"));
    assert_eq!(back.to_canonical_json().unwrap(), json);
}

/// An incomplete outcome with two required checks open and two gaps, its lists in canonical
/// order or reversed.
fn incomplete(reversed: bool) -> Completeness {
    let mut missing_required: Vec<CheckId> = ids(&["loader.search_paths", "model_store.license"]);
    let mut gaps: Vec<OpenQuestionId> = vec![
        id(&format!(
            "oq:loader.search_path_untrusted_creator@cwd/{ROLE}"
        )),
        id(&format!(
            "oq:loader.search_path_untrusted_creator@exe_dir/{ROLE}"
        )),
    ];
    if reversed {
        missing_required.reverse();
        gaps.reverse();
    }
    Completeness::Incomplete {
        missing_required,
        gaps,
    }
}

#[test]
fn a_side_s_completeness_lists_are_written_in_canonical_order() {
    let mut sorted = diff_of(&complete_pass(), &complete_pass());
    sorted.baseline.completeness = incomplete(false);
    sorted.current.completeness = incomplete(false);
    sorted.evaluation = builtin_rules().judge(
        &sorted.baseline.completeness,
        &sorted.current.completeness,
        &sorted.changes,
        &sorted.not_comparable,
    );
    let mut canonical = sorted.clone();
    canonical.canonicalize();
    assert_eq!(canonical, sorted, "the sorted lists are canonical");
    let mut reversed = sorted.clone();
    reversed.baseline.completeness = incomplete(true);
    reversed.current.completeness = incomplete(true);
    assert_ne!(reversed, sorted);
    assert_eq!(
        reversed.to_canonical_json().unwrap(),
        sorted.to_canonical_json().unwrap()
    );
    // A file with the lists reversed reads back, and is written back, in canonical order.
    let back: Diff = serde_json::from_str(&serde_json::to_string(&reversed).unwrap()).unwrap();
    assert_eq!(back, sorted);
    assert_eq!(
        back.to_canonical_json().unwrap(),
        sorted.to_canonical_json().unwrap()
    );
}

#[test]
fn a_completeness_change_s_lists_are_written_in_canonical_order() {
    let changes = |reversed: bool| {
        vec![
            Change::CompletenessChanged {
                baseline: Completeness::Complete,
                current: incomplete(reversed),
            },
            Change::CompletenessChanged {
                baseline: incomplete(reversed),
                current: Completeness::Complete,
            },
        ]
    };
    let mut sorted = diff_of(&complete_pass(), &complete_pass());
    sorted.changes = changes(false);
    sorted.evaluation = builtin_rules().judge(
        &sorted.baseline.completeness,
        &sorted.current.completeness,
        &sorted.changes,
        &sorted.not_comparable,
    );
    sorted.canonicalize();
    let mut canonical = sorted.clone();
    canonical.canonicalize();
    assert_eq!(canonical, sorted, "the sorted lists are canonical");
    let mut reversed = sorted.clone();
    reversed.changes = changes(true);
    reversed.changes.reverse();
    assert_ne!(reversed, sorted);
    assert_eq!(
        reversed.to_canonical_json().unwrap(),
        sorted.to_canonical_json().unwrap()
    );
    // A file with the lists reversed reads back, and is written back, in canonical order.
    let back: Diff = serde_json::from_str(&serde_json::to_string(&reversed).unwrap()).unwrap();
    assert_eq!(back, sorted);
    assert_eq!(
        back.to_canonical_json().unwrap(),
        sorted.to_canonical_json().unwrap()
    );
}

#[test]
fn every_comparison_builder_gives_a_valid_session() {
    for case in diff_cases() {
        assert_valid(&case.baseline);
        assert_valid(&case.current);
    }
    let mut more = vec![
        static_store(),
        binary_denied(),
        relabel_binary_inputs(&binary_inspect()),
        ggml_base_matched(),
        install_with_ggml(0x11),
    ];
    let mut two = compare_store();
    add_model_n(&mut two);
    more.push(two.clone());
    let mut open = compare_store();
    inventory_partial(&mut open);
    more.push(open);
    let mut relicensed = two;
    license_unstable(&mut relicensed);
    relicense(&mut relicensed, MODEL_N, "Apache-2.0");
    more.push(relicensed);
    let mut extra = install_with_ggml(0x11);
    add_extra_library(&mut extra);
    more.push(extra);
    let mut undiscovered = install_with_ggml(0x11);
    discovery_partial(&mut undiscovered);
    more.push(undiscovered);
    let mut moved = compare_store();
    new_socket(&mut moved, 7999);
    more.push(moved);
    let mut lan = compare_store();
    add_listener(&mut lan, "10.0.0.5", 8080, 9001);
    more.push(lan);
    let mut unlicensed_n = compare_store();
    add_model_n(&mut unlicensed_n);
    license_removed_from(&mut unlicensed_n, MODEL_N);
    more.push(unlicensed_n);
    let mut unstable = compare_store();
    manifest_unstable(&mut unstable, MODEL_M);
    weights_replaced(&mut unstable);
    more.push(unstable);
    let mut install_dir = service_unit();
    without_service_unit(&mut install_dir);
    more.push(install_dir);
    let mut edited = service_unit();
    unit_rewritten(&mut edited, 0x1b);
    more.push(edited);
    let mut unidentified = binary_inspect();
    cut_short(
        &mut unidentified,
        BINARY_IDENTITY,
        &Ref::Instance(id(ELF_INPUT)),
        SCAN_READ_FAILED,
    );
    more.push(unidentified);
    let mut unanalyzed = binary_code();
    cut_short(
        &mut unanalyzed,
        BINARY_CODE,
        &Ref::Instance(id(KERNEL_INPUT)),
        "code: cut short",
    );
    more.push(unanalyzed);
    for s in &more {
        assert_valid(s);
    }
}

#[test]
fn the_verdict_changes_on_its_own() {
    let mut warn = compare_store();
    license_removed(&mut warn);
    let diff = diff_of(&compare_store(), &warn);
    assert!(diff.changes.contains(&Change::VerdictChanged {
        baseline: Verdict::Pass,
        current: Verdict::Warn,
    }));
    assert!(!has(&diff, "CompletenessChanged"), "{:?}", kinds(&diff));
}

#[test]
fn completeness_changes_only_when_its_kind_does() {
    let mut license_open = compare_store();
    license_unstable(&mut license_open);
    let mut integrity_open = compare_store();
    blob_missing(&mut integrity_open);
    // Incomplete on both sides, for different checks: the checks say it.
    let diff = diff_of(&license_open, &integrity_open);
    assert!(!has(&diff, "CompletenessChanged"), "{:?}", kinds(&diff));
    assert!(diff
        .changes
        .iter()
        .any(|c| matches!(c, Change::CheckOpened { check, .. } if check.as_str() == INTEGRITY)));
    assert!(diff
        .changes
        .iter()
        .any(|c| matches!(c, Change::CheckClosed { check, .. } if check.as_str() == LICENSE)));
    let diff = diff_of(&compare_store(), &license_open);
    assert!(diff.changes.contains(&Change::CompletenessChanged {
        baseline: Completeness::Complete,
        current: license_open.outcome.completeness.clone(),
    }));
}

#[test]
fn a_check_with_no_entries_is_open() {
    let diff = diff_of(&static_store(), &compare_store());
    let (baseline, current) = diff
        .changes
        .iter()
        .find_map(|c| match c {
            Change::CheckClosed {
                check,
                baseline,
                current,
            } if check.as_str() == BINDS => Some((baseline.clone(), current.clone())),
            _ => None,
        })
        .expect("exposure.binds is closed now");
    assert!(baseline.states.is_empty() && !baseline.required);
    assert_eq!(current.states.get("Complete"), Some(&2));
    assert!(current.required);
}

fn store_with_n() -> Session {
    let mut s = compare_store();
    add_model_n(&mut s);
    s
}

#[test]
fn a_model_added_or_removed_is_reported_when_the_store_was_inventoried() {
    let added = diff_of(&compare_store(), &store_with_n());
    assert_eq!(kinds(&added), ["ModelAdded"]);
    assert!(added.changes.contains(&Change::ModelAdded {
        model: id(MODEL_N),
        name: t("n:latest"),
    }));
    let removed = diff_of(&store_with_n(), &compare_store());
    assert_eq!(kinds(&removed), ["ModelRemoved"]);
}

#[test]
fn an_open_inventory_on_the_absent_side_is_not_comparable() {
    let mut open = compare_store();
    inventory_partial(&mut open);
    let diff = diff_of(&store_with_n(), &open);
    assert!(!has(&diff, "ModelRemoved"), "{:?}", kinds(&diff));
    assert!(diff.not_comparable.contains(&NotComparable {
        item: Item::Model { model: id(MODEL_N) },
        cause: Cause::Coverage,
        checks: ids(&[INVENTORY]),
        open_in: Side::Current,
    }));
}

#[test]
fn models_inventoried_under_different_filters_are_not_comparable() {
    let mut one = compare_store();
    one.request.model_filter = Some("m:latest".to_string());
    let diff = diff_of(&store_with_n(), &one);
    assert!(!has(&diff, "ModelRemoved"), "{:?}", kinds(&diff));
    assert!(diff.not_comparable.contains(&NotComparable {
        item: Item::Model { model: id(MODEL_N) },
        cause: Cause::Request,
        checks: ids(&[INVENTORY]),
        open_in: Side::Current,
    }));
}

#[test]
fn a_layer_is_matched_by_role_media_type_and_position() {
    let mut replaced = compare_store();
    weights_replaced(&mut replaced);
    let diff = diff_of(&compare_store(), &replaced);
    assert_eq!(
        diff.changes,
        [Change::LayerChanged {
            model: id(MODEL_M),
            role: LayerRole::Layer,
            media_type: Some(t(MODEL_MEDIA)),
            ordinal: 0,
            baseline: Some(t(&format!("sha256:{}", hex(0x12)))),
            current: Some(t(&format!("sha256:{}", hex(0x14)))),
        }]
    );
}

#[test]
fn layers_of_an_unstable_manifest_are_not_comparable() {
    let mut unstable = compare_store();
    manifest_unstable(&mut unstable, MODEL_M);
    // The same layers read: nothing to judge.
    let diff = diff_of(&compare_store(), &unstable);
    assert!(!has(&diff, "LayerChanged"), "{:?}", kinds(&diff));
    assert!(diff.not_comparable.is_empty(), "{:?}", diff.not_comparable);
    // Other layers read from a manifest that changed meanwhile support no claim.
    weights_replaced(&mut unstable);
    let item = Item::Model { model: id(MODEL_M) };
    for (baseline, current, open_in) in [
        (&compare_store(), &unstable, Side::Current),
        (&unstable, &compare_store(), Side::Baseline),
        (&unstable, &unstable_with(compare_store()), Side::Both),
    ] {
        let diff = diff_of(baseline, current);
        assert!(!has(&diff, "LayerChanged"), "{:?}", kinds(&diff));
        assert!(
            diff.not_comparable.contains(&NotComparable {
                item: item.clone(),
                cause: Cause::Coverage,
                checks: ids(&[INVENTORY]),
                open_in,
            }),
            "{:?}",
            diff.not_comparable
        );
    }
}

fn unstable_with(mut s: Session) -> Session {
    manifest_unstable(&mut s, MODEL_M);
    s
}

#[test]
fn a_removed_license_layer_is_a_license_change() {
    let mut removed = compare_store();
    license_removed(&mut removed);
    let diff = diff_of(&compare_store(), &removed);
    assert!(diff.changes.contains(&Change::LicenseChanged {
        model: id(MODEL_M),
        baseline: LicenseState::Spdx {
            id: "MIT".to_string()
        },
        current: LicenseState::NoLayer,
    }));
}

#[test]
fn a_partial_model_does_not_hide_a_change_of_another() {
    let mut after = store_with_n();
    license_unstable(&mut after); // model m's license check is open now
    relicense(&mut after, MODEL_N, "Apache-2.0");
    let diff = diff_of(&store_with_n(), &after);
    assert!(diff.changes.contains(&Change::LicenseChanged {
        model: id(MODEL_N),
        baseline: LicenseState::Spdx {
            id: "MIT".to_string()
        },
        current: LicenseState::Spdx {
            id: "Apache-2.0".to_string()
        },
    }));
    // m recorded the same license on both sides: nothing to judge.
    assert!(
        !diff
            .not_comparable
            .iter()
            .any(|n| n.item == Item::License { model: id(MODEL_M) }),
        "{:?}",
        diff.not_comparable
    );
}

#[test]
fn an_open_license_check_with_another_recorded_license_is_not_comparable() {
    let mut after = compare_store();
    license_unstable(&mut after);
    relicense(&mut after, MODEL_M, "Apache-2.0");
    let diff = diff_of(&compare_store(), &after);
    assert!(!has(&diff, "LicenseChanged"), "{:?}", kinds(&diff));
    assert!(diff.not_comparable.contains(&NotComparable {
        item: Item::License { model: id(MODEL_M) },
        cause: Cause::Coverage,
        checks: ids(&[LICENSE]),
        open_in: Side::Current,
    }));
}

fn ggml_at(rel: &str) -> Placement {
    Placement::Instance(id(&format!("inst:{rel}")))
}

#[test]
fn a_replaced_installation_file_keeps_its_placement_and_claim() {
    // The slice ID changes with the content; the claim is keyed by placement, so it is the same.
    let diff = diff_of(&install_with_ggml(0x11), &install_with_ggml(0x22));
    let inst: InstanceId = id("inst:lib/ollama/libggml.so.0.13.1");
    assert_eq!(
        diff.changes,
        [Change::FileContentChanged {
            placement: Placement::Instance(inst.clone()),
            baseline: inst.clone(),
            current: inst,
            baseline_content: id(&format!("sha256:{}", hex(0x11))),
            current_content: id(&format!("sha256:{}", hex(0x22))),
        }]
    );
    assert!(diff.not_comparable.is_empty(), "{:?}", diff.not_comparable);
}

#[test]
fn an_installation_file_on_one_side_needs_discovery_closed_on_the_other() {
    let mut more = install_with_ggml(0x11);
    add_extra_library(&mut more);
    let added = diff_of(&install_with_ggml(0x11), &more);
    assert!(added.changes.contains(&Change::FileAdded {
        placement: ggml_at("lib/ollama/libextra.so"),
        instance: id("inst:lib/ollama/libextra.so"),
        content: Some(id(&format!("sha256:{}", hex(0x33)))),
    }));
    let mut open = install_with_ggml(0x11);
    discovery_partial(&mut open);
    let diff = diff_of(&more, &open);
    assert!(!has(&diff, "FileRemoved"), "{:?}", kinds(&diff));
    assert!(diff.not_comparable.contains(&NotComparable {
        item: Item::File {
            placement: ggml_at("lib/ollama/libextra.so"),
        },
        cause: Cause::Coverage,
        checks: ids(&["artifacts.discovery"]),
        open_in: Side::Current,
    }));
}

#[test]
fn reordered_binary_inputs_give_no_changes() {
    let s = binary_inspect();
    let diff = diff_of(&s, &relabel_binary_inputs(&s));
    assert!(diff.changes.is_empty(), "{:?}", diff.changes);
    assert!(diff.not_comparable.is_empty(), "{:?}", diff.not_comparable);
}

#[test]
fn a_binary_input_on_one_side_only_is_not_comparable() {
    let diff = diff_of(&binary_inspect(), &binary_session_one_elf());
    assert!(!has(&diff, "FileRemoved"), "{:?}", kinds(&diff));
    assert!(diff.not_comparable.contains(&NotComparable {
        item: Item::File {
            placement: Placement::Path(t("/home/user/Downloads/NOTES.txt")),
        },
        cause: Cause::Request,
        checks: ids(&["binary.container"]),
        open_in: Side::Current,
    }));
}

#[test]
fn a_service_unit_on_one_side_only_is_not_comparable() {
    let unit = Placement::Instance(id("inst:service-unit/ollama.service"));
    let given = service_unit();
    let mut install_dir = service_unit();
    without_service_unit(&mut install_dir);
    for (baseline, current, open_in) in [
        (&given, &install_dir, Side::Current),
        (&install_dir, &given, Side::Baseline),
    ] {
        let diff = diff_of(baseline, current);
        assert!(!has(&diff, "FileRemoved"), "{:?}", kinds(&diff));
        assert!(!has(&diff, "FileAdded"), "{:?}", kinds(&diff));
        assert!(
            diff.not_comparable.contains(&NotComparable {
                item: Item::File {
                    placement: unit.clone(),
                },
                // No check records a unit the run was not given.
                cause: Cause::Request,
                checks: vec![],
                open_in,
            }),
            "{:?}",
            diff.not_comparable
        );
    }
    // The unit given on both sides, edited: its content changed.
    let mut edited = service_unit();
    unit_rewritten(&mut edited, 0x1b);
    let diff = diff_of(&given, &edited);
    assert_eq!(
        diff.changes,
        [Change::FileContentChanged {
            placement: unit,
            baseline: id("inst:service-unit/ollama.service"),
            current: id("inst:service-unit/ollama.service"),
            baseline_content: id(&format!("sha256:{}", hex(0x19))),
            current_content: id(&format!("sha256:{}", hex(0x1b))),
        }]
    );
}

#[test]
fn release_claims_on_both_sides_are_compared() {
    let diff = diff_of(&conflicting_identity(), &open_release());
    let releases: Vec<&Change> = diff
        .changes
        .iter()
        .filter(|c| matches!(c, Change::ReleaseChanged { .. }))
        .collect();
    assert_eq!(
        releases,
        [&Change::ReleaseChanged {
            product: id("ollama"),
            baseline: Some(ReleaseState {
                candidates: vec!["v0.30.6".to_string()],
                basis: ReleaseBasisKind::ReferenceMatches,
            }),
            current: Some(ReleaseState {
                candidates: OPEN_RELEASES.iter().map(|r| r.to_string()).collect(),
                basis: ReleaseBasisKind::SelfReportedCommit,
            }),
        }]
    );
}

#[test]
fn a_release_claim_on_one_side_needs_the_release_check_closed_on_the_other() {
    let diff = diff_of(&conflicting_identity(), &complete_pass());
    assert!(!has(&diff, "ReleaseChanged"), "{:?}", kinds(&diff));
    assert!(diff.not_comparable.contains(&NotComparable {
        item: Item::Release {
            product: id("ollama"),
        },
        cause: Cause::Coverage,
        checks: ids(&["artifacts.release"]),
        open_in: Side::Current,
    }));
}

#[test]
fn a_claim_that_turns_conflicting_is_a_component_change() {
    let diff = diff_of(&ggml_base_matched(), &conflicting_identity());
    assert_eq!(kinds(&diff), ["ComponentChanged"]);
    let Change::ComponentChanged {
        placement,
        arch,
        component,
        baseline,
        current,
    } = &diff.changes[0]
    else {
        unreachable!()
    };
    assert_eq!(placement, &ggml_at("lib/ollama/libggml-base.so.0.13.1"));
    assert_eq!((*arch, component.as_str()), (Arch::X86_64, "ggml-base"));
    let (baseline, current) = (baseline.as_ref().unwrap(), current.as_ref().unwrap());
    assert_eq!(baseline.status, IdentityStatus::ReferenceMatched);
    assert_eq!(current.status, IdentityStatus::Conflicting);
    assert_eq!(current.versions, [t("0.12.0"), t("0.13.1")]);
}

#[test]
fn a_claim_gone_where_identity_was_not_closed_is_not_comparable() {
    let mut unclaimed = install_with_ggml(0x11);
    unclaimed.components.clear();
    let diff = diff_of(&install_with_ggml(0x11), &unclaimed);
    assert!(!has(&diff, "ComponentChanged"), "{:?}", kinds(&diff));
    assert_eq!(
        diff.not_comparable,
        [NotComparable {
            item: Item::Component {
                placement: ggml_at("lib/ollama/libggml.so.0.13.1"),
                arch: Arch::X86_64,
                component: id("ggml"),
            },
            cause: Cause::Coverage,
            checks: ids(&["artifacts.identity"]),
            open_in: Side::Current,
        }]
    );
}

#[test]
fn a_removed_file_s_claim_is_judged_under_the_root_it_was_found_in() {
    // libggml was at `inst:lib/ollama/…` under the root `install`: its ID names no root of
    // the current run, so the root is the baseline's record of the instance.
    let mut before = install_with_ggml(0x11);
    ggml_denied(&mut before);
    let mut after = install_with_ggml(0x11);
    ggml_uninstalled(&mut after);
    identity_closed(&mut after);
    let diff = diff_of(&before, &after);
    assert!(diff.not_comparable.is_empty(), "{:?}", diff.not_comparable);
    let inst: InstanceId = id(GGML);
    let placement = Placement::Instance(inst.clone());
    assert!(diff.changes.contains(&Change::FileRemoved {
        placement: placement.clone(),
        instance: inst,
        content: Some(id(&format!("sha256:{}", hex(0x11)))),
    }));
    assert!(diff.changes.iter().any(|c| matches!(
        c,
        Change::ComponentChanged { placement: p, component, baseline: Some(_), current: None, .. }
            if *p == placement && component.as_str() == "ggml"
    )));
    // The violation on the claim is judged by the same identity check.
    assert!(diff.changes.iter().any(|c| matches!(
        c,
        Change::ViolationResolved { policy_rule, .. }
            if policy_rule.as_str() == "policy:components.deny.ggml"
    )));
}

#[test]
fn loopback_to_wildcard_is_a_wider_bind_and_back_a_narrower_one() {
    let mut wide = compare_store();
    bind_wildcard(&mut wide, 7002);
    let diff = diff_of(&compare_store(), &wide);
    assert!(diff.changes.contains(&Change::BindWidened {
        port: 11434,
        baseline: BindClass::Loopback,
        current: BindClass::Wildcard,
        baseline_listeners: vec![id("listener:tcp/127.0.0.1:11434#7001")],
        current_listeners: vec![id("listener:tcp/0.0.0.0:11434#7002")],
    }));
    assert!(has(&diff_of(&wide, &compare_store()), "BindNarrowed"));
}

#[test]
fn a_new_socket_on_the_same_address_is_no_change() {
    let mut moved = compare_store();
    new_socket(&mut moved, 7999);
    let diff = diff_of(&compare_store(), &moved);
    assert!(diff.changes.is_empty(), "{:?}", diff.changes);
    assert!(diff.not_comparable.is_empty(), "{:?}", diff.not_comparable);
}

#[test]
fn a_listener_added_where_binds_were_closed_is_reported() {
    let mut more = compare_store();
    add_listener(&mut more, "10.0.0.5", 8080, 9001);
    let diff = diff_of(&compare_store(), &more);
    assert!(diff.changes.contains(&Change::ListenerAdded {
        port: 8080,
        class: BindClass::Private,
        listeners: vec![id("listener:tcp/10.0.0.5:8080#9001")],
    }));
}

#[test]
fn listeners_of_an_observe_run_are_not_comparable_with_a_static_run() {
    let diff = diff_of(&static_store(), &compare_store());
    assert!(!has(&diff, "ListenerAdded"), "{:?}", kinds(&diff));
    assert!(diff.not_comparable.contains(&NotComparable {
        item: Item::Port { port: 11434 },
        cause: Cause::Coverage,
        checks: ids(&[BINDS]),
        open_in: Side::Baseline,
    }));
}

#[test]
fn a_new_finding_is_reported_beside_partial_current_coverage() {
    let mut missing = compare_store();
    blob_missing(&mut missing); // model m's integrity is Partial in the current run
    let diff = diff_of(&compare_store(), &missing);
    assert!(diff.changes.contains(&Change::FindingNew {
        rule: id("model.blob_missing"),
        subject: SubjectKey::Model(id(MODEL_M)),
        at: "#1".to_string(),
        current: vec![id(&format!("finding:model.blob_missing@{MODEL_M}#1"))],
        decisions: vec![decision(Action::Warn, "default:model.blob_missing")],
    }));
}

#[test]
fn a_resolved_finding_needs_the_current_side_closed() {
    let mut missing = compare_store();
    blob_missing(&mut missing);
    assert!(has(&diff_of(&missing, &compare_store()), "FindingResolved"));
    // Model m's integrity is open now: its blobs were not all checked.
    let mut open = compare_store();
    cut_short(
        &mut open,
        INTEGRITY,
        &Ref::Model(id(MODEL_M)),
        "layer 1: read failed",
    );
    let diff = diff_of(&missing, &open);
    assert!(!has(&diff, "FindingResolved"), "{:?}", kinds(&diff));
    assert_eq!(
        diff.not_comparable,
        [NotComparable {
            item: Item::Finding {
                rule: id("model.blob_missing"),
                subject: SubjectKey::Model(id(MODEL_M)),
                at: "#1".to_string(),
            },
            cause: Cause::Coverage,
            checks: ids(&[INTEGRITY]),
            open_in: Side::Current,
        }]
    );
}

#[test]
fn integrity_not_run_leaves_a_missing_blob_not_comparable() {
    // The inventory is complete and model m is there, but no blob of it was checked.
    let mut missing = compare_store();
    blob_missing(&mut missing);
    let mut unchecked = compare_store();
    integrity_not_run(&mut unchecked);
    let diff = diff_of(&missing, &unchecked);
    assert!(!has(&diff, "FindingResolved"), "{:?}", kinds(&diff));
    assert_eq!(
        diff.not_comparable,
        [NotComparable {
            item: Item::Finding {
                rule: id("model.blob_missing"),
                subject: SubjectKey::Model(id(MODEL_M)),
                at: "#1".to_string(),
            },
            cause: Cause::Coverage,
            checks: ids(&[INTEGRITY]),
            open_in: Side::Current,
        }]
    );
    // The other way round: no new finding either.
    let diff = diff_of(&unchecked, &missing);
    assert!(!has(&diff, "FindingNew"), "{:?}", kinds(&diff));
    assert!(diff
        .not_comparable
        .iter()
        .any(|n| n.checks == ids(&[INTEGRITY])
            && n.open_in == Side::Baseline
            && n.cause == Cause::Coverage));
}

#[test]
fn a_model_finding_needs_only_the_check_of_its_rule() {
    // A missing license is judged by the license check: an open integrity check, or an open
    // listing of the store, does not hold it back.
    let mut unlicensed = compare_store();
    license_removed(&mut unlicensed);
    let mut integrity_open = compare_store();
    cut_short(
        &mut integrity_open,
        INTEGRITY,
        &Ref::Model(id(MODEL_M)),
        "layer 1: read failed",
    );
    let mut listing_open = compare_store();
    inventory_partial(&mut listing_open);
    for current in [&integrity_open, &listing_open] {
        let diff = diff_of(&unlicensed, current);
        assert!(has(&diff, "FindingResolved"), "{:?}", kinds(&diff));
        // (Under an open listing the license layer itself is not comparable: a layer change.)
        assert!(
            !diff
                .not_comparable
                .iter()
                .any(|n| matches!(n.item, Item::Finding { .. })),
            "{:?}",
            diff.not_comparable
        );
    }
    // A missing blob of a model still listed is judged by integrity alone.
    let mut missing = compare_store();
    blob_missing(&mut missing);
    assert!(has(&diff_of(&missing, &listing_open), "FindingResolved"));
}

#[test]
fn another_model_rule_needs_every_model_store_check_with_an_entry() {
    let rule = "model.layer_unexpected";
    let mut found = compare_store();
    other_model_finding(&mut found, rule, MODEL_M);
    // The license check did not run: integrity and the inventory alone do not judge the rule.
    let mut unlicensed_run = compare_store();
    license_not_run(&mut unlicensed_run);
    let diff = diff_of(&found, &unlicensed_run);
    assert!(!has(&diff, "FindingResolved"), "{:?}", kinds(&diff));
    assert_eq!(
        diff.not_comparable,
        [NotComparable {
            item: Item::Finding {
                rule: id(rule),
                subject: SubjectKey::Model(id(MODEL_M)),
                at: String::new(),
            },
            cause: Cause::Coverage,
            checks: ids(&[INTEGRITY, INVENTORY, LICENSE]),
            open_in: Side::Current,
        }]
    );
    // All three closed: resolved.
    assert!(has(&diff_of(&found, &compare_store()), "FindingResolved"));
}

#[test]
fn a_model_gone_with_its_findings_needs_only_the_inventory() {
    // Model n is gone; the current run has no integrity or license entry of it, and needs none.
    let mut unlicensed_n = store_with_n();
    license_removed_from(&mut unlicensed_n, MODEL_N);
    let diff = diff_of(&unlicensed_n, &compare_store());
    assert!(has(&diff, "ModelRemoved"), "{:?}", kinds(&diff));
    assert!(diff.changes.contains(&Change::FindingResolved {
        rule: id("model.license_missing"),
        subject: SubjectKey::Model(id(MODEL_N)),
        at: String::new(),
        baseline: vec![id(&format!("finding:model.license_missing@{MODEL_N}"))],
    }));
    // With the store's listing cut short, model n may be there unlisted.
    let mut open = compare_store();
    inventory_partial(&mut open);
    let diff = diff_of(&unlicensed_n, &open);
    assert!(!has(&diff, "FindingResolved"), "{:?}", kinds(&diff));
    assert!(diff.not_comparable.contains(&NotComparable {
        item: Item::Finding {
            rule: id("model.license_missing"),
            subject: SubjectKey::Model(id(MODEL_N)),
            at: String::new(),
        },
        cause: Cause::Coverage,
        checks: ids(&[INVENTORY]),
        open_in: Side::Current,
    }));
}

#[test]
fn a_gone_model_s_findings_are_judged_by_its_manifest() {
    // The current run could not read model n's manifest: the gap is on the manifest alone, and
    // the store's listing is complete. Model n is not gone; it is unread.
    let mut unlicensed_n = store_with_n();
    license_removed_from(&mut unlicensed_n, MODEL_N);
    let mut unreadable = store_with_n();
    manifest_unreadable(&mut unreadable, MODEL_N);
    let item = Item::Finding {
        rule: id("model.license_missing"),
        subject: SubjectKey::Model(id(MODEL_N)),
        at: String::new(),
    };
    for (baseline, current, open_in) in [
        (&unlicensed_n, &unreadable, Side::Current),
        (&unreadable, &unlicensed_n, Side::Baseline),
    ] {
        let diff = diff_of(baseline, current);
        assert!(!has(&diff, "FindingResolved"), "{:?}", kinds(&diff));
        assert!(!has(&diff, "FindingNew"), "{:?}", kinds(&diff));
        assert!(
            diff.not_comparable.contains(&NotComparable {
                item: item.clone(),
                cause: Cause::Coverage,
                checks: ids(&[INVENTORY]),
                open_in,
            }),
            "{:?}",
            diff.not_comparable
        );
        // The model itself is not comparable either.
        assert!(diff
            .not_comparable
            .iter()
            .any(|n| n.item == Item::Model { model: id(MODEL_N) }));
    }
    // A manifest really deleted, with the listing complete: the finding is resolved.
    assert!(has(
        &diff_of(&unlicensed_n, &compare_store()),
        "FindingResolved"
    ));
}

#[test]
fn claims_and_violations_of_a_binary_input_named_on_one_side_are_a_request_difference() {
    // `binary inspect libggml-base.so NOTES.txt` with ggml-base denied, then
    // `binary inspect NOTES.txt` under the same policy.
    let baseline = binary_denied();
    let current = binary_session_one_unsupported();
    let placement = Placement::Path(t("/home/user/Downloads/libggml-base.so"));
    let diff = diff_of(&baseline, &current);
    assert!(!has(&diff, "ComponentChanged"), "{:?}", kinds(&diff));
    assert!(!has(&diff, "ViolationResolved"), "{:?}", kinds(&diff));
    let request = |item| NotComparable {
        item,
        cause: Cause::Request,
        checks: ids(&["binary.container"]),
        open_in: Side::Current,
    };
    for expected in [
        request(Item::Component {
            placement: placement.clone(),
            arch: Arch::X86_64,
            component: id("ggml-base"),
        }),
        request(Item::Violation {
            policy_rule: id("policy:components.deny.ggml-base"),
            subject: SubjectKey::Component {
                placement: placement.clone(),
                arch: Arch::X86_64,
                component: id("ggml-base"),
            },
        }),
        request(Item::File { placement }),
    ] {
        assert!(
            diff.not_comparable.contains(&expected),
            "{expected:?} in {:?}",
            diff.not_comparable
        );
    }
}

#[test]
fn a_model_finding_a_model_filter_left_out_is_not_comparable() {
    let mut unlicensed = store_with_n();
    license_removed_from(&mut unlicensed, MODEL_N);
    let mut filtered = compare_store();
    filtered.request.model_filter = Some("m:latest".to_string());
    let item = Item::Finding {
        rule: id("model.license_missing"),
        subject: SubjectKey::Model(id(MODEL_N)),
        at: String::new(),
    };
    for (baseline, current, open_in) in [
        (&unlicensed, &filtered, Side::Current),
        (&filtered, &unlicensed, Side::Baseline),
    ] {
        let diff = diff_of(baseline, current);
        assert!(!has(&diff, "FindingResolved"), "{:?}", kinds(&diff));
        assert!(!has(&diff, "FindingNew"), "{:?}", kinds(&diff));
        assert!(
            diff.not_comparable.contains(&NotComparable {
                item: item.clone(),
                cause: Cause::Request,
                checks: ids(&[INVENTORY]),
                open_in,
            }),
            "{:?}",
            diff.not_comparable
        );
    }
    // A model both filters kept is judged as before.
    let mut m_unlicensed = store_with_n();
    license_removed(&mut m_unlicensed);
    let diff = diff_of(&m_unlicensed, &filtered);
    assert!(has(&diff, "FindingResolved"), "{:?}", kinds(&diff));
}

#[test]
fn an_exposure_finding_on_a_new_socket_is_the_same_finding() {
    let mut a = compare_store();
    bind_wildcard(&mut a, 7002);
    let mut b = compare_store();
    bind_wildcard(&mut b, 7003);
    let diff = diff_of(&a, &b);
    assert!(diff.changes.is_empty(), "{:?}", diff.changes);
    assert!(diff.not_comparable.is_empty(), "{:?}", diff.not_comparable);
}

#[test]
fn a_violation_is_new_or_resolved_on_its_placement() {
    let subject = SubjectKey::Component {
        placement: Placement::Path(t("/home/user/Downloads/libggml-base.so")),
        arch: Arch::X86_64,
        component: id("ggml-base"),
    };
    let slice = binary_inspect().components[0].subject.clone();
    let diff = diff_of(&binary_inspect(), &binary_denied());
    assert!(diff.changes.contains(&Change::ViolationNew {
        policy_rule: id("policy:components.deny.ggml-base"),
        subject: subject.clone(),
        current: vec![Ref::Component {
            slice,
            component: id("ggml-base"),
        }],
        decisions: vec![decision(Action::Fail, "policy:components.deny.ggml-base")],
    }));
    let back = diff_of(&binary_denied(), &binary_inspect());
    assert!(back.changes.iter().any(|c| matches!(
        c,
        Change::ViolationResolved { subject: s, .. } if *s == subject
    )));
}

#[test]
fn a_violation_s_absence_is_judged_by_the_check_of_its_placement() {
    // A component denial on a binary input: that input's identity check alone.
    let mut unidentified = binary_inspect();
    cut_short(
        &mut unidentified,
        BINARY_IDENTITY,
        &Ref::Instance(id(ELF_INPUT)),
        SCAN_READ_FAILED,
    );
    let diff = diff_of(&binary_denied(), &unidentified);
    assert!(!has(&diff, "ViolationResolved"), "{:?}", kinds(&diff));
    assert!(
        diff.not_comparable.contains(&NotComparable {
            item: Item::Violation {
                policy_rule: id("policy:components.deny.ggml-base"),
                subject: SubjectKey::Component {
                    placement: Placement::Path(t("/home/user/Downloads/libggml-base.so")),
                    arch: Arch::X86_64,
                    component: id("ggml-base"),
                },
            },
            cause: Cause::Coverage,
            checks: ids(&[BINARY_IDENTITY]),
            open_in: Side::Current,
        }),
        "{:?}",
        diff.not_comparable
    );
    // A capability denial on a binary input: that input's code check alone. Example 18 applies
    // its own policy; the current run applies it too, or the violation is not judged at all.
    let mut unanalyzed = binary_code();
    cut_short(
        &mut unanalyzed,
        BINARY_CODE,
        &Ref::Instance(id(KERNEL_INPUT)),
        "code: cut short",
    );
    adopt_policy(&mut unanalyzed, &capability_policy());
    let diff = diff_of(&capability_policy(), &unanalyzed);
    assert!(!has(&diff, "ViolationResolved"), "{:?}", kinds(&diff));
    assert!(
        diff.not_comparable.contains(&NotComparable {
            item: Item::Violation {
                policy_rule: id("policy:capabilities.deny.posix.network"),
                subject: SubjectKey::Slice {
                    placement: Placement::Path(t("/home/user/src/suspicious_kernel-gcc-O2.o")),
                    arch: Arch::X86_64,
                },
            },
            cause: Cause::Coverage,
            checks: ids(&[BINARY_CODE]),
            open_in: Side::Current,
        }),
        "{:?}",
        diff.not_comparable
    );
}

fn default_policy(byte: u8) -> KnowledgeRef {
    KnowledgeRef {
        kind: KnowledgeKind::Policy,
        id: "default".to_string(),
        version: "1".to_string(),
        sha256: id(&hex(byte)),
    }
}

#[test]
fn a_not_comparable_item_names_its_cause_after_the_item() {
    let mut filtered = compare_store();
    filtered.request.model_filter = Some("m:latest".to_string());
    let diff = diff_of(&store_with_n(), &filtered);
    let json = serde_json::to_string(&diff.not_comparable[0]).unwrap();
    assert_eq!(
        json,
        format!(
            r#"{{"item":{{"Model":{{"model":"{MODEL_N}"}}}},"cause":"Request","checks":["{INVENTORY}"],"open_in":"Current"}}"#
        )
    );
}

#[test]
fn a_changed_policy_is_the_first_change() {
    let mut edited = compare_store();
    policy_edited(&mut edited, 0xa5);
    license_removed(&mut edited);
    let diff = diff_of(&compare_store(), &edited);
    assert_eq!(
        diff.changes[0],
        Change::PolicyChanged {
            baseline: Some(default_policy(0xa3)),
            current: Some(default_policy(0xa5)),
        }
    );
    assert!(has(&diff, "VerdictChanged"), "{:?}", kinds(&diff));
    // A session that recorded no policy.
    let mut none = compare_store();
    none.knowledge.retain(|k| k.kind != KnowledgeKind::Policy);
    let diff = diff_of(&none, &compare_store());
    assert_eq!(
        diff.changes,
        [Change::PolicyChanged {
            baseline: None,
            current: Some(default_policy(0xa3)),
        }]
    );
    // The same policy: nothing.
    assert!(!has(&diff_of(&edited, &edited), "PolicyChanged"));
}

#[test]
fn a_deny_rule_removed_from_the_policy_is_not_a_resolved_violation() {
    // The same binary; the policy no longer denies ggml-base, so the violation is gone.
    let mut allowed = binary_inspect();
    policy_edited(&mut allowed, 0xa5);
    let diff = diff_of(&binary_denied(), &allowed);
    assert!(!has(&diff, "ViolationResolved"), "{:?}", kinds(&diff));
    assert!(diff.changes.contains(&Change::PolicyChanged {
        baseline: Some(default_policy(0xa3)),
        current: Some(default_policy(0xa5)),
    }));
    assert_eq!(
        diff.not_comparable,
        [NotComparable {
            item: Item::Violation {
                policy_rule: id("policy:components.deny.ggml-base"),
                subject: SubjectKey::Component {
                    placement: Placement::Path(t("/home/user/Downloads/libggml-base.so")),
                    arch: Arch::X86_64,
                    component: id("ggml-base"),
                },
            },
            cause: Cause::Policy,
            checks: vec![],
            open_in: Side::Both,
        }]
    );
    // And the other way round: a deny rule added is not a new violation.
    let diff = diff_of(&allowed, &binary_denied());
    assert!(!has(&diff, "ViolationNew"), "{:?}", kinds(&diff));
    assert!(diff.not_comparable.iter().any(|n| n.cause == Cause::Policy));
}

#[test]
fn sessions_that_record_no_policy_did_not_apply_the_same_one() {
    // PR #136 review P2-2: no `Policy` knowledge entry on either side says nothing about the
    // rules each run applied, so a violation on one side only is not judged.
    let no_policy = |mut s: Session| {
        s.knowledge.retain(|k| k.kind != KnowledgeKind::Policy);
        s
    };
    // With the policy recorded, the current run's identity check is closed: resolved.
    assert!(has(
        &diff_of(&binary_denied(), &binary_inspect()),
        "ViolationResolved"
    ));
    let (denied, allowed) = (no_policy(binary_denied()), no_policy(binary_inspect()));
    let expected = NotComparable {
        item: Item::Violation {
            policy_rule: id("policy:components.deny.ggml-base"),
            subject: SubjectKey::Component {
                placement: Placement::Path(t("/home/user/Downloads/libggml-base.so")),
                arch: Arch::X86_64,
                component: id("ggml-base"),
            },
        },
        cause: Cause::Policy,
        checks: vec![],
        open_in: Side::Both,
    };
    for (baseline, current) in [(&denied, &allowed), (&allowed, &denied)] {
        let diff = diff_of(baseline, current);
        for kind in ["ViolationResolved", "ViolationNew", "PolicyChanged"] {
            assert!(!has(&diff, kind), "{kind}: {:?}", kinds(&diff));
        }
        assert_eq!(diff.not_comparable, std::slice::from_ref(&expected));
    }
}

#[test]
fn an_action_changed_by_the_policy_is_a_violation_decision_change() {
    let rule = "policy:components.deny.ggml-base";
    let mut warned = binary_denied();
    policy_edited(&mut warned, 0xa5);
    decide_violations(&mut warned, rule, decision(Action::Warn, rule));
    let subject = SubjectKey::Component {
        placement: Placement::Path(t("/home/user/Downloads/libggml-base.so")),
        arch: Arch::X86_64,
        component: id("ggml-base"),
    };
    let diff = diff_of(&binary_denied(), &warned);
    assert_eq!(
        kinds(&diff),
        [
            "PolicyChanged",
            "VerdictChanged",
            "ViolationDecisionChanged"
        ]
    );
    // PR #136 review P2-3: each side's subjects point at the violation in its session.
    let claim = Ref::Component {
        slice: binary_inspect().components[0].subject.clone(),
        component: id("ggml-base"),
    };
    assert!(diff.changes.contains(&Change::ViolationDecisionChanged {
        policy_rule: id(rule),
        subject,
        baseline: vec![decision(Action::Fail, rule)],
        current: vec![decision(Action::Warn, rule)],
        baseline_subjects: vec![claim.clone()],
        current_subjects: vec![claim],
    }));
    // A violation on both sides is judged under either policy: nothing is not comparable.
    assert!(diff.not_comparable.is_empty(), "{:?}", diff.not_comparable);
}

#[test]
fn an_override_of_a_finding_is_a_finding_decision_change() {
    let rule = "model.license_missing";
    let mut unlicensed = compare_store();
    license_removed(&mut unlicensed);
    let mut waived = unlicensed.clone();
    let override_ = waiver(rule, "relicensing in progress", "2026-12-31");
    decide_findings(&mut waived, rule, override_.clone());
    // The same policy file on both sides: decisions are compared all the same.
    let diff = diff_of(&unlicensed, &waived);
    assert_eq!(kinds(&diff), ["VerdictChanged", "FindingDecisionChanged"]);
    // PR #136 review P2-3: each side's finding IDs point at the finding in its session.
    let finding: FindingId = id(&format!("finding:{rule}@{MODEL_M}"));
    assert!(diff.changes.contains(&Change::FindingDecisionChanged {
        rule: id(rule),
        subject: SubjectKey::Model(id(MODEL_M)),
        at: String::new(),
        baseline: vec![decision(Action::Warn, &format!("default:{rule}"))],
        current: vec![override_.clone()],
        baseline_findings: vec![finding.clone()],
        current_findings: vec![finding],
    }));
    // The same decisions: nothing.
    assert!(diff_of(&waived, &waived).changes.is_empty());
}

#[test]
fn a_long_value_does_not_cut_the_other_side_of_a_decision_change() {
    let rule = "model.license_missing";
    let long = "x".repeat(600);
    let mut base = diff_of(&compare_store(), &compare_store());
    base.changes = vec![Change::FindingDecisionChanged {
        rule: id(rule),
        subject: SubjectKey::Model(id(MODEL_M)),
        at: String::new(),
        baseline: vec![waiver(rule, &long, "2026-12-31")],
        current: vec![waiver(rule, "short reason", "2027-01-31")],
        baseline_findings: vec![id(&format!("finding:{rule}@{MODEL_M}"))],
        current_findings: vec![id(&format!("finding:{rule}@{MODEL_M}#current"))],
    }];
    let md = markdown(&base);
    assert!(md.contains(&esc_md("; current: ")), "{md}");
    assert!(md.contains(&esc_md("short reason")), "{md}");
    assert!(md.contains(&esc_md("2027-01-31")), "{md}");
    assert!(md.contains(&esc_md("#current")), "{md}");
}

#[test]
fn a_decision_change_s_pointers_are_sorted_and_each_once() {
    let rule = "model.license_missing";
    let f = |n: u8| -> FindingId { id(&format!("finding:{rule}@{MODEL_M}#{n}")) };
    let decided = vec![decision(Action::Warn, &format!("default:{rule}"))];
    let claim = |byte: u8| Ref::Component {
        slice: SliceId::from_parts(&id(&format!("sha256:{}", hex(byte))), Arch::X86_64, 0),
        component: id("ggml-base"),
    };
    let mut diff = diff_of(&compare_store(), &compare_store());
    diff.changes = vec![
        Change::FindingDecisionChanged {
            rule: id(rule),
            subject: SubjectKey::Model(id(MODEL_M)),
            at: String::new(),
            baseline: decided.clone(),
            current: vec![],
            baseline_findings: vec![f(2), f(1), f(2)],
            current_findings: vec![f(3), f(1)],
        },
        Change::ViolationDecisionChanged {
            policy_rule: id("policy:components.deny.ggml-base"),
            subject: SubjectKey::Other(claim(0x11)),
            baseline: decided,
            current: vec![],
            baseline_subjects: vec![claim(0x22), claim(0x11), claim(0x22)],
            current_subjects: vec![claim(0x22), claim(0x11)],
        },
    ];
    diff.canonicalize();
    assert_eq!(
        diff.changes[0],
        Change::FindingDecisionChanged {
            rule: id(rule),
            subject: SubjectKey::Model(id(MODEL_M)),
            at: String::new(),
            baseline: vec![decision(Action::Warn, &format!("default:{rule}"))],
            current: vec![],
            baseline_findings: vec![f(1), f(2)],
            current_findings: vec![f(1), f(3)],
        }
    );
    let Change::ViolationDecisionChanged {
        baseline_subjects,
        current_subjects,
        ..
    } = &diff.changes[1]
    else {
        panic!("{:?}", diff.changes);
    };
    assert_eq!(*baseline_subjects, [claim(0x11), claim(0x22)]);
    assert_eq!(*current_subjects, [claim(0x11), claim(0x22)]);
}

#[test]
fn a_new_item_s_decisions_are_sorted_and_each_once() {
    let rule = "model.license_missing";
    let claim = Ref::Component {
        slice: SliceId::from_parts(&id(&format!("sha256:{}", hex(0x11))), Arch::X86_64, 0),
        component: id("ggml-base"),
    };
    let warn = decision(Action::Warn, &format!("default:{rule}"));
    let fail = decision(Action::Fail, "policy:components.deny.ggml-base");
    let mut sorted = [warn.clone(), fail.clone()];
    sorted.sort_by_key(|d| serde_json::to_string(d).unwrap());
    let reversed: Vec<_> = sorted.iter().rev().cloned().collect();
    let messy = vec![reversed[0].clone(), sorted[0].clone(), reversed[0].clone()];
    let mut diff = diff_of(&compare_store(), &compare_store());
    diff.changes = vec![
        Change::FindingNew {
            rule: id(rule),
            subject: SubjectKey::Model(id(MODEL_M)),
            at: String::new(),
            current: vec![],
            decisions: messy.clone(),
        },
        Change::ViolationNew {
            policy_rule: id("policy:components.deny.ggml-base"),
            subject: SubjectKey::Other(claim),
            current: vec![],
            decisions: messy,
        },
    ];
    diff.canonicalize();
    for change in &diff.changes {
        assert_eq!(change.decisions(), Some(&sorted[..]), "{change:?}");
    }
}

#[test]
fn one_change_is_not_called_changes() {
    let mut diff = diff_of(&compare_store(), &compare_store());
    diff.changes = vec![Change::ModelAdded {
        model: id(MODEL_M),
        name: UntrustedText::new("m"),
    }];
    let md = markdown(&diff);
    assert!(md.contains(&esc_md("1 change, 0 not comparable.")), "{md}");
    assert!(!md.contains(&esc_md("1 changes")), "{md}");
}

/// `s` with every set-like list reversed (manifest layer order is evidence, so it stays).
fn reversed(s: &Session) -> Session {
    let mut s = s.clone();
    s.artifacts.reverse();
    s.instances.reverse();
    s.models.reverse();
    s.listeners.reverse();
    s.coverage.reverse();
    s.findings.reverse();
    s.components.reverse();
    s.releases.reverse();
    s.policy_violations.reverse();
    s.request.required_checks.reverse();
    s
}

#[test]
fn the_order_of_a_session_s_lists_does_not_matter() {
    for case in diff_cases() {
        let straight = diff_of(&case.baseline, &case.current);
        let turned = diff_of(&reversed(&case.baseline), &reversed(&case.current));
        assert_eq!(straight, turned, "{}", case.name);
    }
}

#[test]
fn the_same_inputs_give_the_same_bytes() {
    for case in diff_cases() {
        let once = diff_of(&case.baseline, &case.current)
            .to_canonical_json()
            .unwrap();
        let twice = diff_of(&case.baseline, &case.current)
            .to_canonical_json()
            .unwrap();
        assert_eq!(once, twice, "{}", case.name);
    }
}

#[test]
fn identical_sessions_say_no_differences() {
    let md = markdown(&diff_of(&compare_store(), &compare_store()));
    assert!(md.starts_with("# SIGIL comparison\n\n"), "{md}");
    assert!(md.ends_with("No differences.\n"), "{md}");
    assert!(
        md.contains(session_sha256(&compare_store()).as_str()),
        "{md}"
    );
}

#[test]
fn sections_come_in_order_and_only_with_rows() {
    let mut diff = diff_of(&compare_store(), &compare_store());
    diff.changes = every_change();
    diff.not_comparable = every_not_comparable();
    let md = markdown(&diff);
    let at = |title: &str| {
        md.find(&format!("\n## {title}\n"))
            .unwrap_or_else(|| panic!("no {title}:\n{md}"))
    };
    let order = [
        "Outcome",
        "Coverage",
        "Findings",
        "Policy violations",
        "Models",
        "Installation",
        "Listeners",
        "Not comparable",
    ]
    .map(at);
    assert!(order.windows(2).all(|w| w[0] < w[1]), "{md}");
    diff.changes
        .retain(|c| matches!(c, Change::VerdictChanged { .. }));
    diff.not_comparable.clear();
    let md = markdown(&diff);
    assert!(md.contains("\n## Outcome\n"), "{md}");
    assert!(!md.contains("\n## Models\n"), "{md}");
    assert!(!md.contains("Not comparable"), "{md}");
    assert!(!md.contains("open/closed"), "{md}");
}

#[test]
fn input_derived_text_is_escaped() {
    let mut diff = diff_of(&compare_store(), &compare_store());
    diff.changes = vec![Change::FileAdded {
        placement: Placement::Path(t("/tmp/a|b`<x>")),
        instance: id("inst:binary-1/x"),
        content: None,
    }];
    let md = markdown(&diff);
    assert!(md.contains(r"\/tmp\/a\|b\`\<x\>"), "{md}");
    assert!(!md.contains("a|b"), "{md}");
}

#[test]
fn every_change_renders_with_its_key_text() {
    let base = diff_of(&compare_store(), &compare_store());
    let want: &[(&str, &[&str])] = &[
        ("PolicyChanged", &["policy", "default 1"]),
        ("VerdictChanged", &["verdict"]),
        ("CompletenessChanged", &["completeness"]),
        ("CheckOpened", &["opened", "Partial 2"]),
        ("CheckClosed", &["closed", "Complete 1"]),
        ("FindingNew", &["model.blob_missing"]),
        ("FindingResolved", &["exposure.bind_public", "port 11434"]),
        (
            "FindingDecisionChanged",
            &[
                "model.license_missing",
                "warn",
                "fail",
                "finding:model.license_missing@model:models/registry.ollama.ai/library/m/latest",
            ],
        ),
        ("ViolationNew", &["components.deny.ggml-base"]),
        ("ViolationResolved", &["posix.process_spawn"]),
        (
            "ViolationDecisionChanged",
            &[
                "ignore",
                "vendored until 0.14",
                "2026-12-31",
                "ggml-base in sha256:4141",
                "ggml-base in sha256:4242",
            ],
        ),
        ("ModelAdded", &["added"]),
        ("ModelRemoved", &["removed"]),
        ("LayerChanged", &["layer"]),
        ("LicenseChanged", &["license", "no license layer"]),
        ("FileAdded", &["file added"]),
        ("FileRemoved", &["file removed"]),
        ("FileContentChanged", &["content changed"]),
        ("ReleaseChanged", &["release", "v0.30.5"]),
        ("ComponentChanged", &["component ggml"]),
        ("ListenerAdded", &["listener added", "private"]),
        ("ListenerRemoved", &["listener removed", "global"]),
        ("BindWidened", &["bind widened", "wildcard"]),
        ("BindNarrowed", &["bind narrowed", "loopback"]),
    ];
    let all = every_change();
    let mut none = base.clone();
    none.changes = vec![all[1].clone()];
    assert!(markdown(&none).contains("none"), "policy removed");
    for change in all {
        let kind = kinds(&Diff {
            changes: vec![change.clone()],
            ..base.clone()
        })
        .remove(0);
        let mut diff = base.clone();
        diff.changes = vec![change];
        let md = markdown(&diff);
        let (_, keys) = want
            .iter()
            .find(|(k, _)| *k == kind)
            .unwrap_or_else(|| panic!("no keys for {kind}"));
        for key in *keys {
            assert!(md.contains(&esc_md(key)), "{kind}: {key}\n{md}");
        }
    }
}

/// `text` as `render::md::esc` writes it, for the characters these tests use.
fn esc_md(text: &str) -> String {
    t(text).markdown_inline()
}

#[test]
fn every_cause_renders_its_reason() {
    let mut diff = diff_of(&compare_store(), &compare_store());
    diff.not_comparable = every_not_comparable();
    let md = markdown(&diff);
    assert!(md.contains(&esc_md("coverage open: ")), "{md}");
    assert!(md.contains("in baseline"), "{md}");
    assert!(md.contains("in both"), "{md}");
    assert!(md.contains(&esc_md("not asked in current: ")), "{md}");
    assert!(md.contains("policies differ"), "{md}");
    for n in &diff.not_comparable {
        let mut one = diff.clone();
        one.not_comparable = vec![n.clone()];
        let md = markdown(&one);
        let reason = match n.cause {
            Cause::Coverage => "coverage open",
            Cause::Request => "not asked in",
            Cause::Policy => "policies differ",
        };
        assert!(md.contains(&esc_md(reason)), "{:?}\n{md}", n.cause);
    }
}

#[test]
fn coverage_section_says_only_transitions_are_reported() {
    let mut diff = diff_of(&compare_store(), &compare_store());
    diff.changes = every_change()
        .into_iter()
        .filter(|c| matches!(c, Change::CheckOpened { .. }))
        .collect();
    let md = markdown(&diff);
    // SIGIL's own text: not escaped (`open/closed`, not `open\/closed`).
    assert!(
        md.contains("Only open/closed transitions are reported. A check open on both sides"),
        "{md}"
    );
}

#[test]
fn a_held_model_s_finding_is_judged_by_its_manifest_s_stability() {
    let rule = "model.manifest_digest_malformed";
    let mut malformed = compare_store();
    other_model_finding(&mut malformed, rule, MODEL_M);
    let mut unstable = compare_store();
    manifest_unstable(&mut unstable, MODEL_M);
    let item = Item::Finding {
        rule: id(rule),
        subject: SubjectKey::Model(id(MODEL_M)),
        at: String::new(),
    };
    for (baseline, current, open_in) in [
        (&malformed, &unstable, Side::Current),
        (&unstable, &malformed, Side::Baseline),
    ] {
        let diff = diff_of(baseline, current);
        assert!(!has(&diff, "FindingResolved"), "{:?}", kinds(&diff));
        assert!(!has(&diff, "FindingNew"), "{:?}", kinds(&diff));
        assert!(
            diff.not_comparable.contains(&NotComparable {
                item: item.clone(),
                cause: Cause::Coverage,
                checks: ids(&[INVENTORY]),
                open_in,
            }),
            "{:?}",
            diff.not_comparable
        );
    }
    // A manifest read stably with the malformed digest fixed: the finding is resolved, and new
    // the other way.
    assert!(has(
        &diff_of(&malformed, &compare_store()),
        "FindingResolved"
    ));
    assert!(has(&diff_of(&compare_store(), &malformed), "FindingNew"));
}
