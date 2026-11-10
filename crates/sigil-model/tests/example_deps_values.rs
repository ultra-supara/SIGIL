mod common;
use common::*;
use sigil_model::render::aibom::project;
use sigil_model::*;

fn session_sha(s: &Session) -> Sha256Hex {
    Sha256Hex::new(sha256_hex(s.to_canonical_json().unwrap())).unwrap()
}
#[test]
fn example_21_is_valid_canonical_and_preserves_process_source_identity() {
    let mut s = dependencies_and_values();
    assert_valid(&s);
    s.canonicalize();
    let json = s.to_canonical_json().unwrap();
    let read: Session = serde_json::from_str(&json).unwrap();
    assert_eq!(read, s);
    assert_valid(&read);
    assert_eq!(s.processes.len(), 2);
    assert_eq!(s.values.len(), 37);
    assert_eq!(
        s.instances
            .iter()
            .filter(|i| i.root.as_str() == SERVICE_UNIT_ROOT)
            .count(),
        1
    );
    assert_eq!(
        s.instances
            .iter()
            .filter(|i| i.id.as_str() == "inst:install/bin/ollama")
            .count(),
        1
    );
    for p in &s.processes {
        assert_eq!(p.mnt_ns, Some(NsInode::Inode(42)));
        let values: Vec<_> = s
            .values
            .iter()
            .filter(|v| {
                matches!(&v.origin,
            ValueOrigin::ObservedProcess { process, .. } if *process == p.process)
            })
            .collect();
        assert_eq!(values.len(), 12);
        assert_eq!(
            values
                .iter()
                .filter(|v| matches!(v.key, ValueKey::Env(_)))
                .count(),
            9
        );
        assert!(values
            .iter()
            .all(|v| !matches!(v.value, TriValue::Unknown { .. })));
        let expected = example_observed_role(&p.process, &p.roles);
        assert!(values.iter().all(|v| v.process_role == expected));
        if p.process.pid == 4300 {
            assert!(p.roles.is_empty());
            assert!(expected.as_str().starts_with("observed:"));
        }
    }
    assert_eq!(s.observation.mnt_ns, Some(42));
    assert!(s.request.observe_env);
    let install: Vec<_> = s
        .instances
        .iter()
        .filter(|file| file.root.as_str() == INSTALL_ROOT)
        .collect();
    assert_eq!(install.len(), 3);
    for file in install {
        let root = s
            .request
            .roots
            .iter()
            .find(|root| root.id == file.root)
            .unwrap();
        let proof = file.path_proof.as_ref().unwrap();
        assert_eq!((proof.root_dev, proof.root_ino), (2049, 49));
        assert!(dependency_path::valid_proof(root, file, proof));
    }
    let unit = s
        .instances
        .iter()
        .find(|file| file.root.as_str() == SERVICE_UNIT_ROOT)
        .unwrap();
    assert_eq!(unit.path_proof, None); // exact named-file anchor, not a directory proof
    assert!(s
        .instances
        .iter()
        .filter(|file| file.root.as_str() != INSTALL_ROOT)
        .all(|file| file.path_proof.is_none()));
}

#[test]
fn example_predictions_and_coverage_explain_supplied_unit_and_loader_limits() {
    let s = dependencies_and_values();
    let predictions: Vec<_> = s
        .values
        .iter()
        .filter(|v| matches!(v.origin, ValueOrigin::PredictedLaunch { .. }))
        .collect();
    assert_eq!(predictions.len(), 12);
    assert!(predictions
        .iter()
        .all(|v| matches!(v.value, TriValue::Unknown { .. })));
    assert!(s
        .coverage
        .iter()
        .any(|c| c.check.as_str() == VALUES_CONFIGURED
            && c.scope == Ref::Root(id(SERVICE_UNIT_ROOT))
            && matches!(c.state, CoverageState::Partial { .. })));
    assert!(s
        .coverage
        .iter()
        .any(|c| c.check.as_str() == ARTIFACTS_DEPENDENCIES
            && c.scope == Ref::Root(id(INSTALL_ROOT))
            && matches!(c.state, CoverageState::Partial { .. })));
    for process in &s.processes {
        assert!(s
            .coverage
            .iter()
            .any(|c| c.check.as_str() == VALUES_OBSERVED
                && c.scope == Ref::Process(process.process.clone())
                && c.state == CoverageState::Complete));
    }
    assert!(matches!(
        s.outcome.completeness,
        Completeness::Incomplete { .. }
    ));
    assert_eq!(s.outcome.verdict, Verdict::Pass);
}

#[test]
fn example_candidates_keep_static_and_same_process_inputs_separate() {
    let s = dependencies_and_values();
    let candidates: Vec<_> = s
        .relations
        .iter()
        .filter_map(|r| match r {
            Relation::Candidate {
                context: Some(context),
                via,
                ..
            } => Some((via, context)),
            _ => None,
        })
        .collect();
    assert_eq!(candidates.len(), 3);
    assert_eq!(
        candidates
            .iter()
            .filter(|(_, c)| c.process.is_none())
            .count(),
        1
    );
    let ld = candidates
        .iter()
        .find(|(via, _)| **via == SearchRule::LdLibraryPath)
        .unwrap()
        .1;
    assert_eq!(ld.process.as_ref().unwrap().pid, 4300);
    assert_eq!(ld.values.len(), 1);
    let input = s.values.iter().find(|v| v.id == ld.values[0]).unwrap();
    assert!(matches!(&input.key, ValueKey::Env(name) if name.as_bytes() == b"LD_LIBRARY_PATH"));
    assert!(
        matches!(&input.origin, ValueOrigin::ObservedProcess { process, read: Some(ProcessValueRead::InitialEnvironment), .. }
        if Some(process) == ld.process.as_ref())
    );
    assert_eq!(
        ld.loader_chain,
        vec![id::<InstanceId>("inst:install/lib/ollama/llama-server")]
    );
    assert_eq!(ld.requester, ld.loader_chain[0]);
    assert!(s.binaries.iter().all(|b| matches!(
        &b.container,
        ContainerFacts::Elf(ElfFacts { abi: Some(_), .. })
    )));
}

#[test]
fn aibom_changes_its_session_digest_without_copying_raw_values_or_relations() {
    let s = dependencies_and_values();
    let first_sha = session_sha(&s);
    let first = project(&s, first_sha.clone());
    let mut changed = s.clone();
    let row = changed
        .values
        .iter_mut()
        .find(|v| matches!(v.value, TriValue::Known(_)))
        .unwrap();
    row.value = TriValue::Known(t("SIGIL_PROJECTION_VALUE_CANARY"));
    for relation in &mut changed.relations {
        if let Relation::Candidate { needed, .. } = relation {
            *needed = t("SIGIL_PROJECTION_RELATION_CANARY");
        }
    }
    // Deliberately fix the link digest to isolate the projection boundary. The changed
    // snapshot need not validate: projection must not acquire any raw relation/value field.
    assert_eq!(project(&changed, first_sha), first);
    let changed_sha = session_sha(&changed);
    assert_ne!(changed_sha, first.session.sha256);
    let changed_bom = project(&changed, changed_sha);
    let json = serde_json::to_string(&changed_bom).unwrap();
    assert!(!json.contains("SIGIL_PROJECTION_VALUE_CANARY"));
    assert!(!json.contains("SIGIL_PROJECTION_RELATION_CANARY"));
    let v = serde_json::to_value(changed_bom).unwrap();
    assert!(v.get("values").is_none());
    assert!(v.get("relations").is_none());
}

#[test]
fn example_source_metadata_keeps_lines_without_retaining_unit_source_or_unrelated_environment() {
    let s = dependencies_and_values();
    let configured = s
        .values
        .iter()
        .find(|v| matches!(v.origin, ValueOrigin::Configured { .. }))
        .unwrap();
    assert!(
        matches!(&configured.origin, ValueOrigin::Configured { file, .. }
        if file.file.as_str() == "inst:service-unit/ollama.service" && file.line == 7 && file.key.as_bytes() == b"User")
    );
    let text = s.to_canonical_json().unwrap();
    for forbidden in [
        "API_TOKEN",
        "LD_PRELOAD",
        "EnvironmentFile contents",
        "[Service]",
        "ExecStart=",
    ] {
        assert!(!text.contains(forbidden), "{forbidden}");
    }
    assert!(s
        .instances
        .iter()
        .find(|i| i.id.as_str() == "inst:install/bin/ollama")
        .unwrap()
        .discovered_by
        .iter()
        .any(|d| matches!(d, DiscoverySource::ServiceUnit { config } if config.line == 6)));
}
