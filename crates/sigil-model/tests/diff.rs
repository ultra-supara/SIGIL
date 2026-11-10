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
        checks: ids(&["binary.container"]),
        open_in: Side::Current,
    }));
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
            checks: ids(&["artifacts.identity"]),
            open_in: Side::Current,
        }]
    );
}
