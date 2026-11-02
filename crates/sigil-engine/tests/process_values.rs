use sigil_engine::observe::proc::{observe, observe_values, ProcBudgets, ProcFacts, RUNTIME_ROLE};
use sigil_model::*;
use std::os::unix::fs::symlink;
mod common;
use common::proc::*;

fn at() -> Timestamp {
    Timestamp::new("2026-11-02T00:00:00Z").unwrap()
}
fn setup(env: &[u8]) -> FakeProc {
    let f = FakeProc::new();
    f.process(&Proc {
        pid: 4242,
        comm: "ollama",
        argv: &["/usr/local/bin/ollama", "serve"],
        exe: Some("/usr/local/bin/ollama"),
        start_ticks: 4000,
        environ: env,
        ..Proc::default()
    });
    f
}
fn run(f: &FakeProc, opt: bool, b: ProcBudgets) -> ProcFacts {
    observe_values(f.path(), &at(), BOOT_ID, b, opt)
}
fn get<'a>(f: &'a ProcFacts, pid: u32, key: &ValueKey) -> &'a ProcessValue {
    f.values
        .iter()
        .find(|v| {
            &v.key == key
                && matches!(&v.origin,
            ValueOrigin::ObservedProcess { process, .. } if process.pid == pid)
        })
        .unwrap_or_else(|| panic!("missing key {key:?} for {pid}: {:?}", f.values))
}
fn env(name: &str) -> ValueKey {
    ValueKey::Env(UntrustedText::new(name))
}
fn known(text: &str) -> TriValue {
    TriValue::Known(UntrustedText::new(text))
}
fn assert_unknown(v: &ProcessValue, reason: NotObservable) {
    assert_eq!(
        v.value,
        TriValue::Unknown {
            reason: UnknownReason::NotObservable(reason)
        },
        "{v:?}"
    );
}
fn is_incomplete(v: &ProcessValue) {
    assert_unknown(v, NotObservable::ReadIncomplete);
}
fn missing(f: &ProcFacts, pid: u32) -> String {
    f.value_details
        .iter()
        .find(|d| d.process.pid == pid)
        .unwrap()
        .missing
        .join(";")
}

#[test]
fn value_effective_ids_cwd_and_initial_environment_have_precise_origins() {
    let f = setup(b"LD_LIBRARY_PATH=/x\0GGML_BACKEND_PATH=\0OLLAMA_MODELS=/models\0");
    let facts = run(&f, true, ProcBudgets::default());
    for (key, value, read) in [
        (ValueKey::Cwd, "/work", ProcessValueRead::Cwd),
        (ValueKey::User, "1001", ProcessValueRead::EffectiveUid),
        (ValueKey::Group, "2001", ProcessValueRead::EffectiveGid),
        (
            env("LD_LIBRARY_PATH"),
            "/x",
            ProcessValueRead::InitialEnvironment,
        ),
        (
            env("GGML_BACKEND_PATH"),
            "",
            ProcessValueRead::InitialEnvironment,
        ),
    ] {
        let v = get(&facts, 4242, &key);
        assert_eq!(v.value, known(value));
        assert_eq!(v.process_role, ProcessRole::new(RUNTIME_ROLE).unwrap());
        assert!(v.applies_to.is_empty());
        assert!(matches!(&v.origin, ValueOrigin::ObservedProcess {
            process, source: ObsSource::Proc, read: Some(actual)
        } if process.pid == 4242 && actual == &read));
    }
    assert_eq!(
        get(&facts, 4242, &env("DYLD_LIBRARY_PATH")).value,
        TriValue::Absent
    );
    assert_eq!(
        get(&facts, 4242, &env("GGML_BACKEND_DIR")).value,
        TriValue::Absent
    );
    assert_eq!(facts.processes[0].mnt_ns, Some(NsInode::Inode(OWN_MNT_NS)));
    assert!(missing(&facts, 4242).is_empty());
}

#[test]
fn value_only_allowlisted_names_survive_and_url_credentials_are_removed() {
    let f = setup(
        b"PATH=CANARY_PATH\0API_TOKEN=CANARY_SECRET\0LD_PRELOAD=CANARY_PRELOAD\0\
OLLAMA_HOST=https://user:CANARY_PASSWORD@localhost:11434/v1?token=CANARY_QUERY#CANARY_FRAGMENT\0\
GGML_BACKEND_PATH=/backends\0",
    );
    let facts = run(&f, true, ProcBudgets::default());
    let text = format!("{facts:?}");
    for canary in [
        "CANARY_PATH",
        "CANARY_SECRET",
        "CANARY_PRELOAD",
        "CANARY_PASSWORD",
        "CANARY_QUERY",
        "CANARY_FRAGMENT",
    ] {
        assert!(!text.contains(canary), "{text}");
    }
    assert_eq!(
        get(&facts, 4242, &env("OLLAMA_HOST")).value,
        known("https://localhost:11434/v1")
    );
    assert!(!facts
        .values
        .iter()
        .any(|v| matches!(&v.key, ValueKey::Env(n)
        if [b"PATH".as_slice(), b"API_TOKEN", b"LD_PRELOAD"].contains(&n.as_bytes()))));
}

#[test]
fn value_old_wrapper_and_no_opt_in_do_not_open_environ_or_cwd_targets() {
    let f = setup(b"LD_LIBRARY_PATH=CANARY_NO_OPTIN\0");
    let target = f.path().join("cwd-target");
    std::fs::write(&target, b"CANARY_CWD_TARGET").unwrap();
    std::fs::remove_file(f.pid_dir(4242).join("cwd")).unwrap();
    symlink(&target, f.pid_dir(4242).join("cwd")).unwrap();
    let opens = Opens::watch(&[f.pid_dir(4242).join("environ"), target]);
    for facts in [
        observe(f.path(), &at(), BOOT_ID, ProcBudgets::default()),
        run(&f, false, ProcBudgets::default()),
    ] {
        assert!(!facts
            .values
            .iter()
            .any(|v| matches!(v.key, ValueKey::Env(_))));
        assert!(!format!("{facts:?}").contains("CANARY_NO_OPTIN"));
        assert!(matches!(
            get(&facts, 4242, &ValueKey::Cwd).value,
            TriValue::Known(_)
        ));
    }
    assert_eq!(opens.counts(), [0, 0]);
}

#[test]
fn value_status_requires_exactly_four_decimal_fields_and_uses_the_effective_field() {
    for status in [
        b"Uid:\t1 2 3\nGid:\t5 6 7 8\n".as_slice(),
        b"Uid:\t1 2 3 4 5\nGid:\t5 6 7 8\n",
        b"Uid:\t1 -2 3 4\nGid:\t5 6 7 8\n",
        b"Uid:\t1 +2 3 4\nGid:\t5 6 7 8\n",
        b"Uid:\t1 4294967296 3 4\nGid:\t5 6 7 8\n",
        b"Uid:\t1 2 3 4\nUid:\t1 2 3 4\nGid:\t5 6 7 8\n",
        b"Gid:\t5 6 7 8\n",
    ] {
        let f = setup(b"");
        std::fs::write(f.pid_dir(4242).join("status"), status).unwrap();
        let facts = run(&f, false, ProcBudgets::default());
        is_incomplete(get(&facts, 4242, &ValueKey::User));
        assert_eq!(get(&facts, 4242, &ValueKey::Group).value, known("6"));
        assert!(missing(&facts, 4242).contains("status: Uid"));
    }
}

#[test]
fn value_incomplete_or_corrupt_environment_invalidates_all_entries_with_read_incomplete() {
    for bytes in [
        b"LD_LIBRARY_PATH=/x".as_slice(), // missing final NUL
        b"LD_LIBRARY_PATH=/x\0LD_LIBRARY_PATH=/y\0",
        b"UNRELATED=x\0UNRELATED=y\0",
        b"BAD_CANARY_WITHOUT_EQUALS\0",
        b"LD_LIBRARY_PATH=/first\0GGML_FRESH=/seen\0BAD_CANARY_WITHOUT_EQUALS\0",
        b"LD_LIBRARY_PATH=/first\0UNRELATED=x\0UNRELATED=y\0",
        b"=BAD_CANARY_EMPTY_NAME\0",
        b"\0",
    ] {
        let f = setup(bytes);
        let facts = run(&f, true, ProcBudgets::default());
        for value in facts
            .values
            .iter()
            .filter(|v| matches!(v.key, ValueKey::Env(_)))
        {
            is_incomplete(value);
        }
        assert!(
            missing(&facts, 4242).contains("environ: duplicate, malformed, or unterminated entry")
        );
        let entries = sigil_engine::analyze::values::observed_coverage(&facts);
        assert!(entries.iter().any(|c| matches!(&c.scope, Ref::Process(p) if p.pid == 4242)
            && matches!(&c.state, CoverageState::Partial { missing }
                if missing.iter().any(|m| m.contains("environ: duplicate, malformed, or unterminated entry")))));
        assert!(!format!("{facts:?}").contains("BAD_CANARY"));
    }
}

#[test]
fn value_empty_environment_is_complete_but_empty_value_is_known() {
    for (bytes, want) in [
        (b"".as_slice(), TriValue::Absent),
        (b"LD_LIBRARY_PATH=\0".as_slice(), known("")),
        (b"LD_LIBRARY_PATH=a=b\0".as_slice(), known("a=b")),
    ] {
        let f = setup(bytes);
        let facts = run(&f, true, ProcBudgets::default());
        assert_eq!(get(&facts, 4242, &env("LD_LIBRARY_PATH")).value, want);
    }
}

#[test]
fn value_status_and_environment_limits_name_the_exhausted_budget() {
    let f = setup(b"LD_LIBRARY_PATH=/longer-than-budget\0");
    let facts = run(
        &f,
        true,
        ProcBudgets {
            max_status_bytes: 8,
            max_environ_bytes: 4,
            ..ProcBudgets::default()
        },
    );
    is_incomplete(get(&facts, 4242, &ValueKey::User));
    is_incomplete(get(&facts, 4242, &ValueKey::Group));
    for v in facts
        .values
        .iter()
        .filter(|v| matches!(v.key, ValueKey::Env(_)))
    {
        is_incomplete(v);
    }
    assert!(missing(&facts, 4242).contains("proc_status_bytes"));
    assert!(missing(&facts, 4242).contains("proc_environ_bytes"));
    // These independent failures must not turn process/mapping coverage into a gap.
    assert!(facts
        .details
        .iter()
        .find(|d| d.process.pid == 4242)
        .unwrap()
        .missing
        .is_empty());
}

#[test]
fn value_total_environment_budget_and_output_budget_are_shared() {
    let f = setup(b"LD_LIBRARY_PATH=/x\0");
    f.process(&Proc {
        pid: 4300,
        ppid: 4242,
        comm: "runner",
        environ: b"LD_LIBRARY_PATH=/y\0",
        start_ticks: 4100,
        ..Proc::default()
    });
    let first_len = b"LD_LIBRARY_PATH=/x\0".len() as u64;
    let facts = run(
        &f,
        true,
        ProcBudgets {
            max_environ_total_bytes: first_len,
            ..ProcBudgets::default()
        },
    );
    assert_eq!(
        get(&facts, 4242, &env("LD_LIBRARY_PATH")).value,
        known("/x")
    );
    is_incomplete(get(&facts, 4300, &env("LD_LIBRARY_PATH")));
    assert!(missing(&facts, 4300).contains("proc_environ_total_bytes"));
    let facts = run(
        &f,
        true,
        ProcBudgets {
            max_process_values: 12,
            ..ProcBudgets::default()
        },
    );
    assert_eq!(facts.values.len(), 12);
    assert!(missing(&facts, 4300).contains("process_values"));
    assert!(facts.values.iter().all(|v| matches!(&v.origin,
        ValueOrigin::ObservedProcess { process, .. } if process.pid == 4242)));
}

#[test]
fn value_distinct_processes_keep_distinct_ids_and_no_descendant_role() {
    let f = setup(b"LD_LIBRARY_PATH=/parent\0");
    f.process(&Proc {
        pid: 4300,
        ppid: 4242,
        comm: "runner",
        start_ticks: 4100,
        environ: b"LD_LIBRARY_PATH=/child\0",
        mnt_ns: OWN_MNT_NS + 1,
        ..Proc::default()
    });
    let facts = run(&f, true, ProcBudgets::default());
    let parent = get(&facts, 4242, &env("LD_LIBRARY_PATH"));
    let child = get(&facts, 4300, &env("LD_LIBRARY_PATH"));
    assert_eq!(parent.value, known("/parent"));
    assert_eq!(child.value, known("/child"));
    assert_ne!(parent.id, child.id);
    assert_ne!(parent.process_role, child.process_role);
    assert!(child.process_role.as_str().starts_with("observed:"));
    let child_obs = facts
        .processes
        .iter()
        .find(|p| p.process.pid == 4300)
        .unwrap();
    assert!(child_obs.roles.is_empty());
    assert_eq!(child_obs.mnt_ns, Some(NsInode::Inode(OWN_MNT_NS + 1)));
    assert!(child_obs.mappings.is_empty()); // namespace survives without mappings
    assert_eq!(get(&facts, 4300, &ValueKey::Cwd).value, known("/work"));
    // Task 4, not this collector, refuses host lookup with this foreign namespace.
}

#[test]
fn value_unrelated_recorded_listener_holder_is_out_of_scope_and_not_opened() {
    let mut f = setup(b"");
    f.process(&Proc {
        pid: 4500,
        comm: "nginx",
        sockets: &[7777],
        ..Proc::default()
    });
    f.listen("0.0.0.0", 8080, 7777);
    let opens = Opens::watch(&[
        f.pid_dir(4500).join("status"),
        f.pid_dir(4500).join("environ"),
    ]);
    let facts = run(&f, true, ProcBudgets::default());
    assert!(facts.processes.iter().any(|p| p.process.pid == 4500));
    assert!(facts.value_outside.iter().any(|p| p.pid == 4500));
    assert!(!facts.value_details.iter().any(|p| p.process.pid == 4500));
    assert!(!facts.values.iter().any(|v| matches!(&v.origin,
        ValueOrigin::ObservedProcess { process, .. } if process.pid == 4500)));
    assert_eq!(opens.counts(), [0, 0]);
}

#[test]
fn value_truncated_tail_revokes_completed_known_entries_and_all_absence_candidates() {
    let prefix = b"LD_LIBRARY_PATH=/first\0GGML_FRESH=/seen\0";
    let mut bytes = prefix.to_vec();
    bytes.extend_from_slice(b"UNRELATED=");
    bytes.extend_from_slice(&vec![b'x'; 9000]);
    bytes.extend_from_slice(b"\0LD_LIBRARY_PATH=/later\0");
    let f = setup(&bytes);
    let facts = run(
        &f,
        true,
        ProcBudgets {
            // The first 8192-byte read completes both retained entries. A later buffer crosses
            // the byte limit before the potentially redefining tail is seen.
            max_environ_bytes: 8196,
            ..ProcBudgets::default()
        },
    );
    assert!(facts.values.iter().any(|v| v.key == env("GGML_FRESH")));
    for value in facts
        .values
        .iter()
        .filter(|v| matches!(v.key, ValueKey::Env(_)))
    {
        assert_unknown(value, NotObservable::ReadIncomplete);
    }
    assert_eq!(get(&facts, 4242, &ValueKey::Cwd).value, known("/work"));
    assert!(missing(&facts, 4242).contains("environ: proc_environ_bytes exhausted"));
    let entries = sigil_engine::analyze::values::observed_coverage(&facts);
    assert!(entries
        .iter()
        .any(|c| matches!(&c.scope, Ref::Process(p) if p.pid == 4242)
            && matches!(&c.state, CoverageState::Partial { missing }
            if missing.iter().any(|m| m.contains("proc_environ_bytes")))));
}

#[test]
fn value_missing_sources_with_live_stat_are_read_incomplete_and_not_no_process() {
    let f = setup(b"");
    for source in ["cwd", "status", "environ"] {
        std::fs::remove_file(f.pid_dir(4242).join(source)).unwrap();
    }
    let facts = run(&f, true, ProcBudgets::default());
    for value in &facts.values {
        assert_unknown(value, NotObservable::ReadIncomplete);
    }
    for source in ["cwd", "status", "environ"] {
        assert!(missing(&facts, 4242).contains(&format!(
            "{source}: cannot be read (ReadIncomplete; source error {:?})",
            rustix::io::Errno::NOENT
        )));
    }
    assert!(facts.processes.iter().any(|p| p.process.pid == 4242));
}

#[test]
fn value_denied_status_preserves_independent_sources_and_typed_permission() {
    let f = setup(b"LD_LIBRARY_PATH=/readable\0");
    if !f.deny(4242, "status") {
        eprintln!("skipped: root reads mode-000 status");
        return;
    }
    let facts = run(&f, true, ProcBudgets::default());
    for key in [ValueKey::User, ValueKey::Group] {
        assert_unknown(get(&facts, 4242, &key), NotObservable::PermissionDenied);
    }
    assert_eq!(get(&facts, 4242, &ValueKey::Cwd).value, known("/work"));
    assert_eq!(
        get(&facts, 4242, &env("LD_LIBRARY_PATH")).value,
        known("/readable")
    );
    assert!(missing(&facts, 4242).contains("status: cannot be read (PermissionDenied)"));
    let entries = sigil_engine::analyze::values::observed_coverage(&facts);
    assert!(entries
        .iter()
        .any(|c| matches!(&c.scope, Ref::Process(p) if p.pid == 4242)
            && matches!(&c.state, CoverageState::Partial { missing }
            if missing.iter().any(|m| m.contains("status: cannot be read (PermissionDenied)")))));
}

#[test]
fn value_denied_environment_does_not_become_absent() {
    let f = setup(b"LD_LIBRARY_PATH=CANARY_DENIED\0");
    if !f.deny(4242, "environ") {
        eprintln!("skipped: root reads mode-000 environ");
        return;
    }
    let facts = run(&f, true, ProcBudgets::default());
    for v in facts
        .values
        .iter()
        .filter(|v| matches!(v.key, ValueKey::Env(_)))
    {
        assert_unknown(v, NotObservable::PermissionDenied);
    }
    assert!(missing(&facts, 4242).contains("environ: cannot be read (PermissionDenied)"));
    let entries = sigil_engine::analyze::values::observed_coverage(&facts);
    assert!(entries
        .iter()
        .any(|c| matches!(&c.scope, Ref::Process(p) if p.pid == 4242)
            && matches!(&c.state, CoverageState::Partial { missing }
            if missing.iter().any(|m| m.contains("environ: cannot be read (PermissionDenied)")))));
    assert!(!format!("{facts:?}").contains("CANARY_DENIED"));
}

#[test]
fn value_streaming_filters_secrets_across_buffer_boundaries_and_handles_raw_bytes() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let mut bytes = b"SECRET=".to_vec();
    bytes.extend_from_slice(&b"CANARY_STREAM".repeat(800));
    bytes.extend_from_slice(b"\0LD_LIBRARY_PATH=/ok=\0GGML_RAW=\xff\0");
    let f = setup(&bytes);
    let cwd = f.pid_dir(4242).join("cwd");
    std::fs::remove_file(&cwd).unwrap();
    symlink(OsString::from_vec(b"/work/\xff".to_vec()), &cwd).unwrap();
    let facts = run(&f, true, ProcBudgets::default());
    assert_eq!(
        get(&facts, 4242, &env("LD_LIBRARY_PATH")).value,
        known("/ok=")
    );
    assert_eq!(
        get(&facts, 4242, &env("GGML_RAW")).value,
        TriValue::Known(UntrustedText::from_bytes(vec![0xff]))
    );
    assert_eq!(
        get(&facts, 4242, &ValueKey::Cwd).value,
        TriValue::Known(UntrustedText::from_bytes(b"/work/\xff".to_vec()))
    );
    assert!(!format!("{facts:?}").contains("CANARY_STREAM"));
    let facts = run(
        &f,
        true,
        ProcBudgets {
            max_environ_bytes: (bytes.len() - 1) as u64,
            ..ProcBudgets::default()
        },
    );
    for v in facts
        .values
        .iter()
        .filter(|v| matches!(v.key, ValueKey::Env(_)))
    {
        is_incomplete(v);
    }
    assert!(!format!("{facts:?}").contains("CANARY_STREAM"));
}

#[test]
fn value_maybe_runtime_holder_has_unknown_values_without_any_value_reads() {
    let mut f = setup(b"");
    f.process(&Proc {
        pid: 4500,
        comm: "nginx",
        sockets: &[7777],
        ..Proc::default()
    });
    std::fs::write(f.pid_dir(4500).join("comm"), [b'x'; 65]).unwrap();
    f.listen("0.0.0.0", 8080, 7777);
    let opens = Opens::watch(&[
        f.pid_dir(4500).join("status"),
        f.pid_dir(4500).join("environ"),
    ]);
    let facts = run(&f, true, ProcBudgets::default());
    assert!(!facts.value_outside.iter().any(|p| p.pid == 4500));
    assert!(missing(&facts, 4500).contains("may be the runtime"));
    for key in [
        ValueKey::Cwd,
        ValueKey::User,
        ValueKey::Group,
        env("LD_LIBRARY_PATH"),
    ] {
        is_incomplete(get(&facts, 4500, &key));
    }
    assert_eq!(opens.counts(), [0, 0]);
}

#[test]
fn value_namespace_evidence_is_the_original_self_namespace_read() {
    let f = setup(b"");
    let facts = run(&f, false, ProcBudgets::default());
    assert_eq!(facts.own_mnt_ns, Some(OWN_MNT_NS));
    assert_eq!(facts.processes[0].mnt_ns, Some(NsInode::Inode(OWN_MNT_NS)));
    std::fs::remove_file(f.path().join("self/ns/mnt")).unwrap();
    let facts = run(&f, false, ProcBudgets::default());
    assert_eq!(facts.own_mnt_ns, None);
    assert_eq!(facts.processes[0].mnt_ns, Some(NsInode::Inode(OWN_MNT_NS)));
    assert_eq!(get(&facts, 4242, &ValueKey::Cwd).value, known("/work"));
    // A missing observer namespace forbids host lookup in Task4, despite readable cwd.
}

#[test]
fn value_output_exhaustion_does_not_open_an_environment_for_unrecordable_rows() {
    let f = setup(b"GGML_A=/one\0GGML_B=/two\0GGML_C=/three\0");
    let opens = Opens::watch(&[f.pid_dir(4242).join("environ")]);
    let facts = run(
        &f,
        true,
        ProcBudgets {
            max_process_values: 0,
            ..ProcBudgets::default()
        },
    );
    assert!(facts.values.is_empty());
    assert!(missing(&facts, 4242).contains("process_values"));
    assert_eq!(opens.counts(), [0]);
    let facts = run(
        &f,
        true,
        ProcBudgets {
            max_process_values: 13,
            ..ProcBudgets::default()
        },
    );
    assert_eq!(facts.values.len(), 13); //12 reserved plus GGML_A
    assert!(missing(&facts, 4242).contains("process_values"));
    for v in facts
        .values
        .iter()
        .filter(|v| matches!(v.key, ValueKey::Env(_)))
    {
        is_incomplete(v);
    }
}

#[test]
fn value_coverage_is_partial_even_when_budget_cannot_emit_any_row() {
    use sigil_engine::analyze::values::observed_coverage;
    let f = setup(b"");
    for n in [0, 1, 2] {
        let facts = run(
            &f,
            false,
            ProcBudgets {
                max_process_values: n,
                ..ProcBudgets::default()
            },
        );
        assert_eq!(facts.values.len(), n as usize);
        let entries = observed_coverage(&facts);
        for scope in [Ref::Audit, Ref::Process(facts.processes[0].process.clone())] {
            let c = entries.iter().find(|e| e.scope == scope).unwrap();
            assert!(
                matches!(&c.state, CoverageState::Partial { missing }
                if missing.iter().any(|m| m.contains("process_values"))),
                "{c:?}"
            );
        }
    }
}
#[test]
fn value_coverage_distinguishes_complete_selected_and_outside_holders() {
    use sigil_engine::analyze::values::observed_coverage;
    let mut f = setup(b"");
    f.process(&Proc {
        pid: 4500,
        comm: "nginx",
        sockets: &[7777],
        ..Proc::default()
    });
    f.listen("0.0.0.0", 8080, 7777);
    let facts = run(&f, false, ProcBudgets::default());
    let entries = observed_coverage(&facts);
    assert!(entries
        .iter()
        .all(|e| e.check.as_str() == "values.observed"));
    for (pid, outside) in [(4242, false), (4500, true)] {
        let p = facts
            .processes
            .iter()
            .find(|p| p.process.pid == pid)
            .unwrap();
        let e = entries
            .iter()
            .find(|e| e.scope == Ref::Process(p.process.clone()))
            .unwrap();
        if outside {
            assert!(matches!(e.state, CoverageState::OutOfScope { .. }));
        } else {
            assert_eq!(e.state, CoverageState::Complete);
        }
    }
}
