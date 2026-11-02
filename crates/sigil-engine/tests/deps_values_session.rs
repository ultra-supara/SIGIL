mod common;

use common::elf::{
    dynamic, ElfImage, DT_NEEDED, DT_NULL, DT_STRSZ, DT_STRTAB, PF_R, PT_DYNAMIC, PT_LOAD,
};
use common::proc::{FakeProc, Proc, BOOT_ID, OWN_MNT_NS};
use sigil_engine::analyze::deps::DepsBudgets;
use sigil_engine::collect::fs::FsBudgets;
use sigil_engine::collect::install::InstallBudgets;
use sigil_engine::collect::named::NamedBudgets;
use sigil_engine::collect::ollama_store::DEFAULT_MANIFEST_LIMIT;
use sigil_engine::collect::service_unit::{self, DEFAULT_UNIT_BYTES};
use sigil_engine::inspect::{
    binary_session, observe_session, store_session, ActiveInput, BinaryRequest, InstallRequest,
    InstallSource, ObserveRequest, StoreRequest,
};
use sigil_engine::observe::proc::ProcBudgets;
use sigil_engine::policy::{self, Policy, ScopeInput};
use sigil_model::*;
use std::path::Path;
use tempfile::TempDir;

fn request(models: &Path, install: Option<InstallSource>) -> StoreRequest {
    StoreRequest {
        models_dir: models.to_path_buf(),
        model_filter: None,
        budgets: FsBudgets::default(),
        manifest_limit: DEFAULT_MANIFEST_LIMIT,
        install: install.map(|source| InstallRequest {
            source,
            budgets: InstallBudgets::default(),
        }),
        deps_budgets: DepsBudgets::default(),
    }
}

fn store(req: &StoreRequest) -> Session {
    store_session(
        req,
        &ActiveInput::default(),
        &Policy::builtin_default().unwrap(),
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap()
}

fn entry<'a>(s: &'a Session, check: &str, scope: &Ref) -> &'a Coverage {
    s.coverage
        .iter()
        .find(|c| c.check.as_str() == check && &c.scope == scope)
        .unwrap_or_else(|| panic!("missing {check} on {scope:?}"))
}

/// A declared dependency on a colocated library, through DT_RUNPATH=$ORIGIN. The section table
/// is intentionally absent: existing container/identity checks record their own limitations.
fn elf(kind: u16, needs_library: bool) -> Vec<u8> {
    let mut image = ElfImage::new(kind);
    let strings = b"\0libpeer.so\0$ORIGIN\0";
    image.put(0x1000, strings);
    let mut entries = vec![(DT_STRTAB, 0x401000), (DT_STRSZ, strings.len() as u64)];
    if needs_library {
        entries.extend([(DT_NEEDED, 1), (29, 12)]);
    }
    entries.push((DT_NULL, 0));
    let bytes = dynamic(&entries);
    image.put(0x2000, &bytes);
    image.put(0x2fff, &[0]); // the PT_LOAD extent is fully present
    image.seg(PT_LOAD, PF_R, 0, 0x400000, 0x3000, 0x3000);
    image.seg(
        PT_DYNAMIC,
        PF_R,
        0x2000,
        0x402000,
        bytes.len() as u64,
        bytes.len() as u64,
    );
    image.build()
}

#[test]
fn catalogs_require_exact_new_checks_only_in_their_existing_scopes() {
    let policy = Policy::builtin_default().unwrap();
    let checks = |mode, install, binary| {
        policy
            .scope(&ScopeInput {
                mode,
                active: false,
                install,
                binary,
                code: false,
            })
            .1
    };
    let has = |checks: &[CheckId], name: &str| checks.iter().any(|c| c.as_str() == name);
    let static_store = checks(Mode::Static, false, false);
    assert!(!has(&static_store, VALUES_OBSERVED));
    assert!(!has(&static_store, VALUES_CONFIGURED));
    assert!(!has(&static_store, ARTIFACTS_DEPENDENCIES));
    let observed = checks(Mode::Observe, false, false);
    assert!(has(&observed, VALUES_OBSERVED));
    let install = checks(Mode::Static, true, false);
    assert!(has(&install, VALUES_CONFIGURED));
    assert!(has(&install, ARTIFACTS_DEPENDENCIES));
    let binary = checks(Mode::Static, false, true);
    assert!(has(&binary, BINARY_DEPENDENCIES));
    assert!(!has(&binary, VALUES_CONFIGURED));
}

#[test]
fn a_supplied_unit_adds_source_values_unknown_predictions_and_partial_root_coverage() {
    let d = TempDir::new().unwrap();
    let install = d.path().join("inst");
    let models = d.path().join("models");
    std::fs::create_dir_all(install.join("bin")).unwrap();
    std::fs::create_dir_all(install.join("lib/ollama")).unwrap();
    std::fs::create_dir_all(&models).unwrap();
    std::fs::write(install.join("bin/ollama"), elf(2, false)).unwrap();
    let unit = d.path().join("ollama.service");
    std::fs::write(&unit, format!("[Service]\nExecStart={} serve\nUser=ollama\nWorkingDirectory=/models\nEnvironment=LD_LIBRARY_PATH=/unit-only PATH=CANARY_CONFIG_SECRET\n", install.join("bin/ollama").display())).unwrap();
    let unit = service_unit::collect(&unit, DEFAULT_UNIT_BYTES).unwrap();
    let expected = unit.values.clone();
    let s = store(&request(
        &models,
        Some(InstallSource::ServiceUnit(Box::new(unit))),
    ));
    assert_eq!(s.values, {
        let mut v = expected;
        v.sort_by_key(|v| serde_json::to_string(v).unwrap());
        v
    });
    assert!(s
        .values
        .iter()
        .any(|v| matches!(v.origin, ValueOrigin::Configured { .. })));
    assert!(s
        .values
        .iter()
        .filter(|v| matches!(v.origin, ValueOrigin::PredictedLaunch { .. }))
        .all(|v| matches!(v.value, TriValue::Unknown { .. })));
    assert!(matches!(
        entry(
            &s,
            VALUES_CONFIGURED,
            &Ref::Root(RootId::new(SERVICE_UNIT_ROOT).unwrap())
        )
        .state,
        CoverageState::Partial { .. }
    ));
    assert_eq!(s.request.budgets.get("service_unit_values"), Some(&16_384));
    assert!(!s.request.observe_env);
    assert!(!serde_json::to_string(&s)
        .unwrap()
        .contains("CANARY_CONFIG_SECRET"));
    assert!(s.values.iter().all(|v| v.applies_to.is_empty()));
    assert_eq!(s.validate(), Ok(()));
    assert_eq!(
        policy::verify(&s, &Policy::builtin_default().unwrap()),
        Ok(())
    );
    let mut forged = s.clone();
    forged
        .values
        .iter_mut()
        .find(|v| matches!(v.origin, ValueOrigin::PredictedLaunch { .. }))
        .unwrap()
        .value = TriValue::Known(UntrustedText::new("/"));
    assert!(forged
        .validate()
        .unwrap_err()
        .iter()
        .any(|e| e.to_string().contains("predictions must remain Unknown")));
    let mut forged = s;
    forged
        .coverage
        .iter_mut()
        .find(|c| c.check.as_str() == VALUES_CONFIGURED)
        .unwrap()
        .state = CoverageState::Complete;
    assert!(forged
        .validate()
        .unwrap_err()
        .iter()
        .any(|e| e.to_string().contains("must remain Partial")));
}

#[test]
fn directory_install_has_out_of_scope_unit_values_and_static_store_has_no_value_audit() {
    let d = TempDir::new().unwrap();
    let install = d.path().join("inst");
    std::fs::create_dir_all(install.join("bin")).unwrap();
    std::fs::create_dir_all(install.join("lib/ollama")).unwrap();
    std::fs::write(install.join("bin/ollama"), elf(2, false)).unwrap();
    let models = d.path().join("models");
    std::fs::create_dir(&models).unwrap();
    let s = store(&request(&models, Some(InstallSource::Dir(install))));
    assert!(matches!(
        entry(&s, VALUES_CONFIGURED, &Ref::Audit).state,
        CoverageState::OutOfScope { .. }
    ));
    assert!(s.values.is_empty());
    let s = store(&request(&models, None));
    assert!(!s
        .coverage
        .iter()
        .any(|c| c.check.as_str() == VALUES_CONFIGURED
            || c.check.as_str() == VALUES_OBSERVED
            || c.check.as_str() == ARTIFACTS_DEPENDENCIES));
    assert!(!s.request.budgets.contains_key("dependency_contexts"));
}

#[test]
fn binary_inputs_get_contextual_candidates_and_individual_dependency_coverage() {
    let d = TempDir::new().unwrap();
    let requester = d.path().join("requester");
    let library = d.path().join("libpeer.so");
    std::fs::write(&requester, elf(2, true)).unwrap();
    std::fs::write(&library, elf(3, false)).unwrap();
    let s = binary_session(
        &BinaryRequest {
            paths: vec![requester, library],
            budgets: NamedBudgets::default(),
            deps_budgets: DepsBudgets::default(),
        },
        &Policy::builtin_default().unwrap(),
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap();
    assert!(s.relations.iter().any(|r| matches!(
        r,
        Relation::Candidate {
            context: Some(_),
            via: SearchRule::Runpath,
            ..
        }
    )));
    for instance in &s.instances {
        let c = entry(&s, BINARY_DEPENDENCIES, &Ref::Instance(instance.id.clone()));
        assert!(!matches!(c.state, CoverageState::NotPresent { .. }));
    }
    assert_eq!(s.request.budgets.get("dependency_contexts"), Some(&8192));
    assert_eq!(s.request.budgets.get("dependency_candidates"), Some(&65536));
    assert_eq!(
        s.request.budgets.get("dependency_search_paths"),
        Some(&65536)
    );
    assert_eq!(s.validate(), Ok(()));
    let mut false_complete = s.clone();
    let requester = false_complete
        .relations
        .iter()
        .find_map(|r| match r {
            Relation::Candidate {
                context: Some(context),
                ..
            } => Some(context.requester.clone()),
            _ => None,
        })
        .unwrap();
    false_complete
        .coverage
        .iter_mut()
        .find(|c| {
            c.check.as_str() == BINARY_DEPENDENCIES && c.scope == Ref::Instance(requester.clone())
        })
        .unwrap()
        .state = CoverageState::Complete;
    assert!(false_complete
        .validate()
        .unwrap_err()
        .iter()
        .any(|e| e.to_string().contains("omit unmodeled resolution stages")));
    let mut stripped = s.clone();
    for relation in &mut stripped.relations {
        if let Relation::Candidate { context, .. } = relation {
            *context = None;
        }
    }
    assert!(stripped.validate().unwrap_err().iter().any(|e| e
        .to_string()
        .contains("new dependency checks require Candidate context")));
    let mut missing = s.clone();
    missing
        .coverage
        .retain(|c| c.check.as_str() != BINARY_DEPENDENCIES);
    assert!(missing.validate().unwrap_err().iter().any(|e| e
        .to_string()
        .contains("requires exactly one coverage entry")));
    let mut forged = s;
    forged
        .coverage
        .iter_mut()
        .find(|c| c.check.as_str() == BINARY_DEPENDENCIES)
        .unwrap()
        .state = CoverageState::OutOfScope {
        why: "forged omission".into(),
    };
    assert!(forged
        .validate()
        .unwrap_err()
        .iter()
        .any(|e| e.to_string().contains("contextual Candidate contradicts")));
}

#[test]
fn observe_opt_in_and_failed_read_intent_survive_session_assembly() {
    for observe_env in [false, true] {
        let models = TempDir::new().unwrap();
        let fake = FakeProc::new();
        fake.process(&Proc {
            pid: 4242,
            comm: "ollama",
            argv: &["/usr/local/bin/ollama", "serve"],
            exe: Some("/usr/local/bin/ollama"),
            start_ticks: 4000,
            environ: b"LD_LIBRARY_PATH=/observed\0PATH=CANARY_OBSERVED_SECRET\0",
            ..Proc::default()
        });
        if observe_env {
            std::fs::remove_file(fake.pid_dir(4242).join("environ")).unwrap();
        }
        let mut meta = common::observation();
        meta.boot_id = BOOT_ID.to_string();
        let s = observe_session(
            &ObserveRequest {
                store: request(models.path(), None),
                proc_root: fake.path().to_path_buf(),
                proc_budgets: ProcBudgets::default(),
                observe_env,
            },
            &ActiveInput::default(),
            &Policy::builtin_default().unwrap(),
            common::tool(),
            meta,
            common::policy_time(),
        )
        .unwrap();
        assert_eq!(s.request.observe_env, observe_env);
        assert_eq!(s.observation.mnt_ns, Some(OWN_MNT_NS));
        assert!(s.values.iter().any(|v| v.key == ValueKey::Cwd));
        assert_eq!(
            s.values.iter().any(|v| matches!(v.key, ValueKey::Env(_))),
            observe_env
        );
        assert_eq!(
            s.request.budgets.contains_key("proc_environ_bytes"),
            observe_env
        );
        assert_eq!(
            s.request.budgets.contains_key("proc_environ_total_bytes"),
            observe_env
        );
        assert!(s.request.budgets.contains_key("proc_status_bytes"));
        assert!(s.request.budgets.contains_key("process_values"));
        let process = &s
            .processes
            .iter()
            .find(|p| p.process.pid == 4242)
            .unwrap()
            .process;
        let c = entry(&s, VALUES_OBSERVED, &Ref::Process(process.clone()));
        if observe_env {
            assert!(!c.state.can_close());
        } else {
            assert_eq!(c.state, CoverageState::Complete);
        }
        assert!(!serde_json::to_string(&s)
            .unwrap()
            .contains("CANARY_OBSERVED_SECRET"));
        assert_eq!(s.validate(), Ok(()));
        if observe_env {
            let mut stripped = s.clone();
            let value = stripped
                .values
                .iter_mut()
                .find(|v| matches!(v.origin, ValueOrigin::ObservedProcess { .. }))
                .unwrap();
            if let ValueOrigin::ObservedProcess { read, .. } = &mut value.origin {
                *read = None;
            }
            assert!(stripped
                .validate()
                .unwrap_err()
                .iter()
                .any(|e| e.to_string().contains("requires explicit read provenance")));
        }
    }
}

#[test]
fn new_required_value_coverage_cannot_drop_a_process_or_claim_unknown_reads_complete() {
    let models = TempDir::new().unwrap();
    let fake = FakeProc::new();
    fake.process(&Proc {
        pid: 4242,
        comm: "ollama",
        argv: &["/usr/local/bin/ollama", "serve"],
        exe: Some("/usr/local/bin/ollama"),
        start_ticks: 4000,
        ..Proc::default()
    });
    let mut meta = common::observation();
    meta.boot_id = BOOT_ID.to_string();
    let s = observe_session(
        &ObserveRequest {
            store: request(models.path(), None),
            proc_root: fake.path().to_path_buf(),
            proc_budgets: ProcBudgets::default(),
            observe_env: false,
        },
        &ActiveInput::default(),
        &Policy::builtin_default().unwrap(),
        common::tool(),
        meta,
        common::policy_time(),
    )
    .unwrap();
    let process = s
        .processes
        .iter()
        .find(|p| p.process.pid == 4242)
        .unwrap()
        .process
        .clone();
    let mut missing = s.clone();
    missing.coverage.retain(|c| {
        !(c.check.as_str() == VALUES_OBSERVED && c.scope == Ref::Process(process.clone()))
    });
    assert!(missing.validate().unwrap_err().iter().any(|e| e
        .to_string()
        .contains("requires exactly one coverage entry")));
    let mut forged = s;
    forged
        .values
        .iter_mut()
        .find(|v| v.key == ValueKey::User)
        .unwrap()
        .value = TriValue::Unknown {
        reason: UnknownReason::InsufficientEvidence,
    };
    assert!(forged.validate().unwrap_err().iter().any(|e| e
        .to_string()
        .contains("Complete values.observed has unknown or missing requested values")));
}

#[test]
fn legacy_predicted_known_remains_valid_but_new_unit_predictions_cannot_be_decided() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/examples/session-v1/13-loader-slice-spec-example.json");
    let legacy: Session = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(legacy.validate(), Ok(()));
    // The supplied-unit assembly test above separately asserts every new prediction Unknown.
}

#[test]
fn process_value_budget_omission_cannot_close_the_check() {
    let models = TempDir::new().unwrap();
    let fake = FakeProc::new();
    fake.process(&Proc {
        pid: 4242,
        comm: "ollama",
        argv: &["/usr/local/bin/ollama", "serve"],
        exe: Some("/usr/local/bin/ollama"),
        start_ticks: 4000,
        ..Proc::default()
    });
    let mut meta = common::observation();
    meta.boot_id = BOOT_ID.to_string();
    let s = observe_session(
        &ObserveRequest {
            store: request(models.path(), None),
            proc_root: fake.path().to_path_buf(),
            proc_budgets: ProcBudgets {
                max_process_values: 0,
                ..ProcBudgets::default()
            },
            observe_env: true,
        },
        &ActiveInput::default(),
        &Policy::builtin_default().unwrap(),
        common::tool(),
        meta,
        common::policy_time(),
    )
    .unwrap();
    assert!(s.request.observe_env);
    assert!(s.values.is_empty());
    assert!(s
        .coverage
        .iter()
        .filter(|c| c.check.as_str() == VALUES_OBSERVED)
        .any(|c| !c.state.can_close()));
    assert!(serde_json::to_string(&s.coverage)
        .unwrap()
        .contains("process_values"));
    assert_eq!(s.validate(), Ok(()));
}

#[test]
fn descendant_without_listener_has_independent_process_value_coverage_and_no_role() {
    let models = TempDir::new().unwrap();
    let fake = FakeProc::new();
    fake.process(&Proc {
        pid: 4242,
        comm: "ollama",
        argv: &["/usr/local/bin/ollama", "serve"],
        exe: Some("/usr/local/bin/ollama"),
        start_ticks: 4000,
        ..Proc::default()
    });
    fake.process(&Proc {
        pid: 4300,
        ppid: 4242,
        comm: "runner",
        argv: &["/usr/local/bin/runner"],
        exe: Some("/usr/local/bin/runner"),
        start_ticks: 4100,
        ..Proc::default()
    });
    let mut meta = common::observation();
    meta.boot_id = BOOT_ID.to_string();
    let s = observe_session(
        &ObserveRequest {
            store: request(models.path(), None),
            proc_root: fake.path().to_path_buf(),
            proc_budgets: ProcBudgets::default(),
            observe_env: false,
        },
        &ActiveInput::default(),
        &Policy::builtin_default().unwrap(),
        common::tool(),
        meta,
        common::policy_time(),
    )
    .unwrap();
    let child = s.processes.iter().find(|p| p.process.pid == 4300).unwrap();
    assert!(child.roles.is_empty());
    assert_eq!(
        entry(&s, VALUES_OBSERVED, &Ref::Process(child.process.clone())).state,
        CoverageState::Complete
    );
    let rows: Vec<_> = s.values.iter().filter(|v| matches!(&v.origin, ValueOrigin::ObservedProcess { process, .. } if *process == child.process)).collect();
    assert_eq!(rows.len(), 3);
    assert!(rows
        .iter()
        .all(|v| v.process_role.as_str().starts_with("observed:")));
    assert!(rows.iter().all(|v| v.applies_to.is_empty()));
}

fn assert_skipped_audit(s: &Session, check: &str, by: SkipReason) {
    let rows: Vec<_> = s
        .coverage
        .iter()
        .filter(|c| c.check.as_str() == check)
        .collect();
    assert_eq!(rows.len(), 1, "{check}: {rows:?}");
    assert_eq!(rows[0].scope, Ref::Audit);
    assert_eq!(rows[0].state, CoverageState::Skipped { by });
    assert_eq!(rows[0].budget, None);
}

#[test]
fn static_store_custom_values_check_is_skipped_without_process_values_or_budgets() {
    let models = TempDir::new().unwrap();
    let policy = Policy::load("schema = \"sigil-policy/1\"\nname = \"inactive-values\"\n[scope]\naudit = []\nextra_required = [\"values.observed\"]\n").unwrap();
    let s = store_session(
        &request(models.path(), None),
        &ActiveInput::default(),
        &policy,
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap();
    assert_skipped_audit(&s, VALUES_OBSERVED, SkipReason::ModeDisabled);
    assert!(s.processes.is_empty());
    assert!(s.values.is_empty());
    assert!(!s.request.observe_env);
    assert!(!s.request.budgets.keys().any(|key| key.starts_with("proc_")
        || key == "process_values"
        || key.starts_with("dependency_")));
    assert_eq!(
        s.outcome.completeness,
        Completeness::Incomplete {
            missing_required: vec![CheckId::new(VALUES_OBSERVED).unwrap()],
            gaps: vec![],
        }
    );
    assert_eq!(s.validate(), Ok(()));
    assert_eq!(policy::verify(&s, &policy), Ok(()));
}

#[test]
fn nonbinary_custom_dependency_check_and_missing_install_checks_are_skipped_once() {
    let models = TempDir::new().unwrap();
    let policy = Policy::load("schema = \"sigil-policy/1\"\nname = \"inactive-inputs\"\n[scope]\naudit = []\nextra_required = [\"binary.dependencies\", \"artifacts.dependencies\", \"values.configured\"]\n").unwrap();
    let s = store_session(
        &request(models.path(), None),
        &ActiveInput::default(),
        &policy,
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap();
    assert_skipped_audit(&s, BINARY_DEPENDENCIES, SkipReason::ModeDisabled);
    for check in [ARTIFACTS_DEPENDENCIES, VALUES_CONFIGURED] {
        assert_skipped_audit(
            &s,
            check,
            SkipReason::Flag {
                flag: "--install-dir".into(),
            },
        );
    }
    assert!(!s
        .request
        .roots
        .iter()
        .any(|r| r.id.as_str() == INSTALL_ROOT || is_binary_root(&r.id)));
    assert!(s.values.is_empty());
    assert!(!s
        .request
        .budgets
        .keys()
        .any(|key| key.starts_with("dependency_") || key.starts_with("service_unit_")));
    assert_eq!(
        s.outcome.completeness,
        Completeness::Incomplete {
            missing_required: [
                ARTIFACTS_DEPENDENCIES,
                BINARY_DEPENDENCIES,
                VALUES_CONFIGURED
            ]
            .into_iter()
            .map(|check| CheckId::new(check).unwrap())
            .collect(),
            gaps: vec![],
        }
    );
    assert_eq!(s.validate(), Ok(()));
    assert_eq!(policy::verify(&s, &policy), Ok(()));
}

fn binary_for_custom_scope(scope: &str) -> Result<Session, sigil_engine::inspect::InspectError> {
    let d = TempDir::new().unwrap();
    let path = d.path().join("input");
    std::fs::write(&path, elf(2, false)).unwrap();
    let policy = Policy::load(&format!("schema = \"sigil-policy/1\"\nname = \"inactive-binary-scope\"\n[scope]\nbinary_audit = [\"{scope}\"]\n")).unwrap();
    binary_session(
        &BinaryRequest {
            paths: vec![path],
            budgets: NamedBudgets::default(),
            deps_budgets: DepsBudgets::default(),
        },
        &policy,
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
}

#[test]
fn binary_custom_install_scope_skips_new_checks_without_install_or_value_inputs() {
    let s = binary_for_custom_scope("runtime_artifacts").unwrap();
    for check in [ARTIFACTS_DEPENDENCIES, VALUES_CONFIGURED] {
        assert_skipped_audit(
            &s,
            check,
            SkipReason::Flag {
                flag: "--install-dir".into(),
            },
        );
    }
    assert!(s.request.roots.iter().all(|r| is_binary_root(&r.id)));
    assert!(s.processes.is_empty());
    assert!(s.values.is_empty());
    assert!(!s.request.observe_env);
    assert_eq!(s.request.budgets.get("dependency_contexts"), Some(&8192));
    assert!(!s
        .request
        .budgets
        .keys()
        .any(|key| key.starts_with("install_")
            || key.starts_with("service_unit_")
            || key.starts_with("proc_")
            || key == "process_values"));
    assert!(!matches!(
        entry(
            &s,
            BINARY_DEPENDENCIES,
            &Ref::Instance(s.instances[0].id.clone())
        )
        .state,
        CoverageState::Skipped { .. }
    ));
    assert_eq!(
        s.outcome.completeness,
        Completeness::Incomplete {
            missing_required: [
                ARTIFACTS_CONTAINER,
                ARTIFACTS_DEPENDENCIES,
                ARTIFACTS_DISCOVERY,
                ARTIFACTS_IDENTITY,
                ARTIFACTS_RELEASE,
                VALUES_CONFIGURED
            ]
            .into_iter()
            .map(|check| CheckId::new(check).unwrap())
            .collect(),
            gaps: vec![],
        }
    );
    assert_eq!(s.validate(), Ok(()));
}

#[test]
fn binary_custom_process_scope_keeps_only_the_preexisting_process_coverage_error() {
    let err = binary_for_custom_scope("runtime_processes").unwrap_err();
    let sigil_engine::inspect::InspectError::Invalid(errors) = err else {
        panic!("{err:?}");
    };
    assert_eq!(errors, ["coverage[processes.observed on audit]: processes.observed is required but has no entry for the audit"]);
}
