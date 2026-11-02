mod common;
use common::*;
use sigil_model::render::{html::from_markdown, markdown::render_session};
use sigil_model::*;

fn process() -> ProcessRef {
    ProcessRef {
        pid: 4242,
        start_ticks: 1000,
        boot_id: "00000000-0000-4000-8000-000000000000".into(),
    }
}
fn value(
    key: ValueKey,
    state: TriValue,
    read: Option<ProcessValueRead>,
    suffix: &str,
) -> ProcessValue {
    ProcessValue {
        id: id(&format!("value:render-{suffix}")),
        process_role: id(RUNTIME_ROLE),
        key,
        value: state,
        origin: ValueOrigin::ObservedProcess {
            process: process(),
            source: ObsSource::Proc,
            read,
        },
        applies_to: vec![],
    }
}
fn dependency() -> Session {
    let mut s = with_install_path_proofs(observed_processes());
    let from = placed(&s, "inst:install/bin/ollama");
    let target = placed(&s, "inst:install/lib/ollama/libggml-cpu-haswell.so");
    for p in [&from, &target] {
        s.binaries.push(BinaryFacts {
            slice: p.slice.clone(),
            go: None,
            gaps: vec![],
            container: ContainerFacts::Elf(ElfFacts {
                abi: Some(ElfAbi {
                    is_64: true,
                    little_endian: true,
                    machine: 62,
                }),
                interp: None,
                soname: None,
                needed: if p.inst == from.inst {
                    vec![t("libggml-cpu-haswell.so")]
                } else {
                    vec![]
                },
                rpath: vec![],
                runpath: if p.inst == from.inst {
                    vec![t("/usr/local/lib/ollama")]
                } else {
                    vec![]
                },
                build_id: None,
                comment: vec![],
                stripped: Some(true),
                exports: 0,
                imports: vec![],
                data: vec![],
                returns: vec![],
            }),
        });
    }
    add_capability_table(&mut s);
    s.relations.push(Relation::Declares {
        from: from.slice.clone(),
        needed: t("libggml-cpu-haswell.so"),
        kind: DeclKind::ElfNeeded,
    });
    s.relations.push(Relation::Candidate {
        from: from.slice,
        needed: t("libggml-cpu-haswell.so"),
        candidate: target.inst,
        via: SearchRule::Runpath,
        context: Some(DependencyContext {
            search: DependencySearch::Runpath {
                entry: 0,
                component: 0,
            },
            requester: from.inst.clone(),
            search_dir: t("/usr/local/lib/ollama"),
            process: None,
            values: vec![],
            loader_chain: vec![from.inst],
        }),
    });
    assert_valid(&s);
    s
}
fn section<'a>(md: &'a str, heading: &str) -> &'a str {
    let start = md.find(&format!("\n## {heading}\n")).unwrap();
    let tail = &md[start + 1..];
    tail.find("\n## ").map_or(tail, |end| &tail[..end])
}

#[test]
fn sections_are_omitted_only_when_their_fact_lists_are_empty() {
    let md = render_session(&base(&[]));
    assert!(!md.contains("\n## Dependencies\n"));
    assert!(!md.contains("\n## Process values\n"));
    let md = render_session(&dependency());
    assert!(md.contains("\n## Dependencies\n"));
    assert!(!md.contains("\n## Process values\n"));
}

#[test]
fn candidate_rows_explain_requester_rule_directory_process_chain_and_inputs() {
    let mut s = dependency();
    s.request.observe_env = true;
    s.values.push(value(
        ValueKey::Env(t("LD_LIBRARY_PATH")),
        TriValue::Known(t("/usr/local/lib/ollama")),
        Some(ProcessValueRead::InitialEnvironment),
        "env",
    ));
    let Relation::Candidate {
        context: Some(c), ..
    } = &mut s.relations[1]
    else {
        panic!()
    };
    c.process = Some(process());
    c.values = vec![id("value:render-env")];
    c.search = DependencySearch::LdLibraryPath {
        value: id("value:render-env"),
        component: 0,
    };
    let Relation::Candidate { via, .. } = &mut s.relations[1] else {
        panic!()
    };
    *via = SearchRule::LdLibraryPath;
    s.observation.mnt_ns = Some(42);
    for p in &mut s.processes {
        p.mnt_ns = Some(NsInode::Inode(42));
    }
    assert_valid(&s);
    let md = render_session(&s);
    let table = section(&md, "Dependencies");
    for expected in [
        "Requester",
        "Candidate",
        "LD\\_LIBRARY\\_PATH",
        "Directory",
        "Process",
        "loader chain",
        "pid 4242",
        "start 1000",
        "boot 00000000",
        "value\\:render\\-env",
        "conditional",
    ] {
        assert!(table.contains(expected), "{expected}: {table}");
    }
    assert!(table.contains(&format!(
        "| {} |",
        t("/usr/local/lib/ollama").markdown_inline()
    )));
    assert!(!table.contains("selected"));
    assert!(!table.contains("missing library"));
    assert!(!table.contains("loaded by"));
}

#[test]
fn declarations_without_candidates_are_declared_only_and_are_not_duplicated_for_existing_candidates(
) {
    let mut s = dependency();
    let Relation::Declares { from, .. } = &s.relations[0] else {
        panic!()
    };
    s.relations.push(Relation::Declares {
        from: from.clone(),
        needed: t("unresolved.so"),
        kind: DeclKind::ElfNeeded,
    });
    let md = render_session(&s);
    let table = section(&md, "Dependencies");
    assert_eq!(
        table
            .matches(&format!(
                "| {} |",
                t("libggml-cpu-haswell.so").markdown_inline()
            ))
            .count(),
        1
    );
    assert_eq!(
        table
            .matches(&format!("| {} |", t("unresolved.so").markdown_inline()))
            .count(),
        1
    );
    assert!(table.contains("declared only"));
    assert!(table.contains("no modeled candidate recorded"));
    assert!(!table.contains("missing library"));
}

#[test]
fn a_legacy_candidate_retains_an_explicit_unknown_context() {
    let mut s = dependency();
    let Relation::Candidate { context, .. } = &mut s.relations[1] else {
        panic!()
    };
    *context = None;
    let md = render_session(&s);
    assert!(section(&md, "Dependencies").contains("legacy candidate\\; context unavailable"));
    assert!(section(&md, "Dependencies").contains("unknown"));
}

#[test]
fn values_distinguish_known_empty_absent_unknown_and_initial_environment() {
    let mut s = base(&[]);
    s.values.extend([
        value(
            ValueKey::Env(t("GGML_EMPTY")),
            TriValue::Known(t("")),
            Some(ProcessValueRead::InitialEnvironment),
            "empty",
        ),
        value(
            ValueKey::Env(t("GGML_ABSENT")),
            TriValue::Absent,
            Some(ProcessValueRead::InitialEnvironment),
            "absent",
        ),
        value(
            ValueKey::Cwd,
            TriValue::Unknown {
                reason: UnknownReason::NotObservable(NotObservable::PermissionDenied),
            },
            Some(ProcessValueRead::Cwd),
            "unknown",
        ),
        value(
            ValueKey::User,
            TriValue::Known(t("1001")),
            Some(ProcessValueRead::EffectiveUid),
            "uid",
        ),
        value(
            ValueKey::Group,
            TriValue::Known(t("1002")),
            Some(ProcessValueRead::EffectiveGid),
            "gid",
        ),
    ]);
    let md = render_session(&s);
    let table = section(&md, "Process values");
    for expected in [
        "Known empty",
        "empty string",
        "Absent",
        "Unknown",
        "permission denied",
        "initial environment",
        "effective uid",
        "effective gid",
        "readlink cwd",
        "current getenv",
    ] {
        assert!(table.contains(expected), "{expected}: {table}");
    }
    assert!(table.contains("pid 4242"));
    assert!(table.contains("start 1000"));
}

#[test]
fn sources_preserve_configuration_lines_predictions_derivation_and_legacy_read_limits() {
    let mut s = base(&[]);
    let mut configured = value(
        ValueKey::User,
        TriValue::Known(t("ollama")),
        None,
        "configured",
    );
    configured.origin = ValueOrigin::Configured {
        file: ConfigRef {
            file: id("inst:ollama.service"),
            key: t("User"),
            line: 7,
        },
        directive: t("User="),
    };
    let mut predicted = value(
        ValueKey::User,
        TriValue::Unknown {
            reason: UnknownReason::NotModeled {
                what: "drop-ins unexamined".into(),
            },
        },
        None,
        "predicted",
    );
    predicted.origin = ValueOrigin::PredictedLaunch {
        rules: vec!["systemd.User".into()],
        from: vec![configured.id.clone()],
    };
    let mut derived = value(
        ValueKey::User,
        TriValue::Unknown {
            reason: UnknownReason::InsufficientEvidence,
        },
        None,
        "derived",
    );
    derived.origin = ValueOrigin::ChildDerived {
        parent: id("parent"),
        child: id("child"),
        by: ProfileRuleRef {
            profile: id(PROFILE),
            rule: id("inherit-user"),
        },
        from: vec![predicted.id.clone()],
    };
    s.values.extend([
        configured,
        predicted,
        derived,
        value(ValueKey::Cwd, TriValue::Known(t("/tmp")), None, "legacy"),
    ]);
    let md = render_session(&s);
    let table = section(&md, "Process values");
    for text in [
        "Configured",
        "line 7",
        "PredictedLaunch",
        "ChildDerived",
        "legacy observation\\; read kind unavailable",
    ] {
        assert!(table.contains(text), "{text}: {table}");
    }
    assert!(table.contains(&t("inst:ollama.service").markdown_inline()));
    assert!(table.contains(&t("systemd.User").markdown_inline()));
}

#[test]
fn injection_in_each_new_source_is_escaped_in_markdown_and_html() {
    let attack =
        "<img src=x onerror=alert(1)>|[tap](javascript:alert(1))\n## injected\u{1b}\u{202e}";
    let mut s = dependency();
    let Relation::Candidate {
        needed,
        context: Some(context),
        ..
    } = &mut s.relations[1]
    else {
        panic!()
    };
    *needed = t(attack);
    context.search_dir = t(attack);
    context.process = Some(ProcessRef {
        boot_id: attack.into(),
        ..process()
    });
    s.instances[0].path = t(attack);
    s.values.push(value(
        ValueKey::Env(t("GGML_ATTACK")),
        TriValue::Known(t(attack)),
        Some(ProcessValueRead::InitialEnvironment),
        "attack",
    ));
    let mut unknown = value(
        ValueKey::Cwd,
        TriValue::Unknown {
            reason: UnknownReason::NotModeled {
                what: attack.into(),
            },
        },
        None,
        "unknown",
    );
    unknown.process_role = id("role:[tap](javascript:alert(1))");
    s.values.push(unknown);
    let md = render_session(&s);
    assert!(md.contains(&t(attack).markdown_inline()));
    assert!(!md.contains("\n## injected"));
    assert!(!md.contains('\u{1b}'));
    assert!(!md.contains('\u{202e}'));
    let html = from_markdown(&md);
    assert!(!html.contains("<img"));
    assert!(!html.contains("<a "));
    assert!(!html.contains("<script"));
    assert!(html.contains("&lt;img"));
    assert!(!html.contains("<h2>injected"));
}

#[test]
fn distinct_placements_and_origins_remain_distinct_rows_and_loader_order_is_retained() {
    let mut s = dependency();
    let mut second = s.relations[1].clone();
    let Relation::Candidate {
        context: Some(c), ..
    } = &mut second
    else {
        panic!()
    };
    c.requester = id("inst:second-placement");
    c.search_dir = t("/second/lib");
    c.loader_chain = vec![id("inst:z-parent"), c.requester.clone()];
    c.process = Some(ProcessRef {
        pid: 999,
        ..process()
    });
    s.relations.push(second);
    let md = render_session(&s);
    let table = section(&md, "Dependencies");
    assert_eq!(table.matches("RUNPATH").count(), 2);
    let z = table.find(&t("inst:z-parent").markdown_inline()).unwrap();
    let end = table[z..]
        .find(&t("inst:second-placement").markdown_inline())
        .unwrap();
    assert!(end > 0);
    assert!(table.contains("pid 999"));
}

#[test]
fn configured_sources_do_not_serialize_a_raw_environment_directive_or_unrelated_canary() {
    let mut s = base(&[]);
    let mut row = value(
        ValueKey::Env(t("GGML_BACKEND_PATH")),
        TriValue::Known(t("/scan/lib")),
        None,
        "configured",
    );
    row.origin = ValueOrigin::Configured {
        file: ConfigRef {
            file: id("inst:unit"),
            key: t("Environment"),
            line: 8,
        },
        directive: t(
            "Environment=GGML_BACKEND_PATH=/scan/lib API_TOKEN=SIGIL_RENDER_SECRET_CANARY",
        ),
    };
    s.values.push(row);
    let md = render_session(&s);
    assert!(md.contains("Configured"));
    assert!(md.contains("line 8"));
    assert!(!md.contains("SIGIL_RENDER_SECRET_CANARY"));
    assert!(!from_markdown(&md).contains("SIGIL_RENDER_SECRET_CANARY"));
    assert!(!md.contains("Utf8("));
}

#[test]
fn contextual_render_fixture_records_real_parent_proofs_without_changing_legacy_builder() {
    let s = dependency();
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
        assert!(dependency_path::valid_proof(
            root,
            file,
            file.path_proof.as_ref().unwrap()
        ));
    }
    assert!(observed_processes()
        .instances
        .iter()
        .all(|file| file.path_proof.is_none()));
}

#[test]
fn search_witnesses_preserve_source_indices_and_references() {
    // Rendering must retain even inconsistent in-memory witnesses without reanalysis.
    let cases = [
        (
            DependencySearch::DirectPath,
            vec!["direct path".to_string()],
        ),
        (
            DependencySearch::DefaultDir { index: 3 },
            vec!["default directory index 3".to_string()],
        ),
        (
            DependencySearch::Runpath {
                entry: 7,
                component: 11,
            },
            vec!["entry 7".to_string(), "component 11".to_string()],
        ),
        (
            DependencySearch::Rpath {
                owner: id("inst:owner-<script>|[link](javascript:alert(1))"),
                entry: 5,
                component: 9,
            },
            vec![
                t("inst:owner-<script>|[link](javascript:alert(1))").markdown_inline(),
                "entry 5".to_string(),
                "component 9".to_string(),
            ],
        ),
        (
            DependencySearch::LdLibraryPath {
                value: id("value:source-<img>|[link](javascript:alert(1))"),
                component: 13,
            },
            vec![
                t("value:source-<img>|[link](javascript:alert(1))").markdown_inline(),
                "component 13".to_string(),
            ],
        ),
    ];
    for (search, expected) in cases {
        let mut s = dependency();
        let Relation::Candidate {
            context: Some(c), ..
        } = &mut s.relations[1]
        else {
            panic!()
        };
        c.search = search;
        let md = render_session(&s);
        let table = section(&md, "Dependencies");
        assert!(table.contains("Search witness"));
        for text in expected {
            assert!(table.contains(&text), "{text}: {table}");
        }
        let html = from_markdown(&md);
        assert!(!html.contains("<script"));
        assert!(!html.contains("<img"));
        assert!(!html.contains("<a "));
    }
}
