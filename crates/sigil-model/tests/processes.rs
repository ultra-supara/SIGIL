//! The observed processes' links (PR-4d-2): an executable and its instance name each other (P1),
//! a mapping's instance is the object mapped (P2), `processes.observed` is about the audit or a
//! recorded process, once each (P3), a process is recorded once (P4), a required
//! `processes.observed` covers the audit and every recorded process, and the runtime is never out
//! of its scope (P5), and `maps_read` agrees with the mappings and the process's entry (P6).

mod common;

use common::*;
use sigil_model::*;

fn valid() -> Session {
    let s = observed_processes();
    assert_valid(&s);
    s
}

fn rejected_for(s: &Session, why: &str) {
    assert_rejected(
        s,
        |e| matches!(e, ValidationError::Process { why: w, .. } if w.contains(why)),
        why,
    );
}

/// Makes `p` a listener's holder.
fn hold(s: &mut Session, p: &ProcessRef) {
    s.listeners.push(Listener {
        id: id(&format!("listener:tcp/127.0.0.1:11434#{}", p.pid)),
        protocol: Protocol::Tcp,
        address: "127.0.0.1".to_string(),
        port: 11434,
        socket_inode: u64::from(p.pid),
        owner: ListenerOwner::Process { process: p.clone() },
    });
}

fn inst<'a>(s: &'a mut Session, id: &str) -> &'a mut FileInstance {
    s.instances
        .iter_mut()
        .find(|i| i.id.as_str() == id)
        .unwrap()
}

#[test]
fn example_20_is_valid() {
    valid();
}

#[test]
fn an_executable_and_its_instance_name_each_other() {
    // The source is gone: the process's executable names an instance that does not name it.
    let mut s = valid();
    inst(&mut s, "inst:install/bin/ollama")
        .discovered_by
        .retain(|d| !matches!(d, DiscoverySource::ProcessExe { .. }));
    rejected_for(&s, "has no ProcessExe source naming it");
    // The source names a process whose executable is another instance.
    let mut s = valid();
    s.processes[0].exe = ProcessExe::Path {
        path: t("/usr/local/bin/ollama"),
        deleted: false,
    };
    rejected_for(&s, "whose executable is not this instance");
    // One instance names one process twice.
    let mut s = valid();
    let serve = s.processes[0].process.clone();
    inst(&mut s, "inst:install/bin/ollama")
        .discovered_by
        .push(DiscoverySource::ProcessExe { process: serve });
    rejected_for(&s, "names process 4242 twice");
}

#[test]
fn a_mapping_s_instance_is_the_object_mapped() {
    let mut s = valid();
    s.processes[1].mappings[1].ino = 9999;
    rejected_for(
        &s,
        "is linked to inst:install/lib/ollama/libggml-cpu-haswell.so",
    );
    let mut s = valid();
    s.processes[1].mappings[1].dev = 1;
    rejected_for(&s, "is linked to");
}

#[test]
fn processes_observed_is_about_the_audit_or_a_recorded_process_once() {
    let mut s = valid();
    let mut other = s.processes[0].process.clone();
    other.pid = 7;
    s.coverage.push(coverage(
        "processes.observed",
        Ref::Process(other),
        CoverageState::Complete,
    ));
    rejected_for(&s, "about a process that is not recorded");
    let mut s = valid();
    let serve = s.processes[0].process.clone();
    s.coverage.push(coverage(
        "processes.observed",
        Ref::Process(serve),
        CoverageState::Complete,
    ));
    rejected_for(&s, "twice");
    let mut s = valid();
    s.coverage.push(coverage(
        "processes.observed",
        Ref::Root(id(INSTALL_ROOT)),
        CoverageState::Complete,
    ));
    rejected_for(&s, "neither the audit nor a process");
}

#[test]
fn a_required_processes_observed_covers_the_audit_and_each_recorded_process() {
    let mut s = valid();
    let runner = s.processes[1].process.clone();
    s.coverage.retain(|c| {
        !(c.check.as_str() == PROCESSES_OBSERVED && c.scope == Ref::Process(runner.clone()))
    });
    rejected_for(&s, "has no entry for this process");
    let mut s = valid();
    s.coverage
        .retain(|c| !(c.check.as_str() == PROCESSES_OBSERVED && c.scope == Ref::Audit));
    rejected_for(&s, "has no entry for the audit");
    // Not required: no entry is needed.
    let mut s = valid();
    s.request
        .required_checks
        .retain(|c| c.as_str() != PROCESSES_OBSERVED);
    s.coverage
        .retain(|c| c.check.as_str() != PROCESSES_OBSERVED);
    assert_valid(&s);
}

#[test]
fn a_process_is_recorded_once() {
    let mut s = valid();
    let mut again = s.processes[1].clone();
    again.exe = ProcessExe::Path {
        path: t("/x"),
        deleted: false,
    };
    again.mappings.clear();
    s.processes.push(again);
    rejected_for(&s, "recorded twice");
}

/// A recorded process that is neither the runtime, nor mapping, nor linked: a listener's holder
/// or a descendant the second pass read.
fn bare(s: &Session, pid: u32) -> ProcessObs {
    let mut p = s.processes[1].clone();
    p.process.pid = pid;
    p.roles = vec![];
    p.exe = ProcessExe::Path {
        path: t("/x"),
        deleted: false,
    };
    p.mappings.clear();
    p.maps_read = MapsRead::NotRead;
    p
}

fn drop_entry(s: &mut Session, p: &ProcessRef) {
    s.coverage.retain(|c| {
        !(c.check.as_str() == PROCESSES_OBSERVED && c.scope == Ref::Process(p.clone()))
    });
}

/// Code review of PR-4d-2, R-C (P5): a required `processes.observed` has an entry for every
/// recorded process, whatever it is. The reviewer's case: a descendant that holds a listener,
/// with no role, no mapping, and an executable not linked, escaped every term of the former P5.
#[test]
fn every_recorded_process_needs_an_entry() {
    let mut s = valid();
    let runner = s.processes[1].process.clone();
    s.processes[1].mappings.clear();
    s.processes[1].maps_read = MapsRead::NotRead;
    s.processes[1].exe = ProcessExe::Path {
        path: t("/usr/local/lib/ollama/llama-server"),
        deleted: false,
    };
    inst(&mut s, "inst:install/lib/ollama/llama-server")
        .discovered_by
        .retain(|d| !matches!(d, DiscoverySource::ProcessExe { .. }));
    hold(&mut s, &runner);
    set_state(
        &mut s,
        &runner,
        CoverageState::Partial {
            missing: vec!["maps: cannot be read (PermissionDenied)".into()],
        },
    );
    assert_valid(&s);
    drop_entry(&mut s, &runner);
    rejected_for(&s, "has no entry for this process");

    // The runtime, with no mapping and no linked executable.
    let mut s = valid();
    let serve = s.processes[0].process.clone();
    s.processes[0].exe = ProcessExe::NotObservable(NotObservable::PermissionDenied);
    s.processes[0].mappings.clear();
    s.processes[0].maps_read = MapsRead::NotRead;
    inst(&mut s, "inst:install/bin/ollama")
        .discovered_by
        .retain(|d| !matches!(d, DiscoverySource::ProcessExe { .. }));
    hold(&mut s, &serve);
    drop_entry(&mut s, &serve);
    rejected_for(&s, "has no entry for this process");

    // A process that holds no listener.
    let mut s = valid();
    let bare = bare(&s, 7);
    s.processes.push(bare);
    rejected_for(&s, "has no entry for this process");
}

/// Code review of PR-4d-2, R-C (P5): a listener's holder outside the runtime's tree has an entry
/// too, `OutOfScope`, as the engine gives it.
#[test]
fn a_listener_holder_needs_an_out_of_scope_entry() {
    let mut s = valid();
    let holder = bare(&s, 7);
    hold(&mut s, &holder.process);
    s.processes.push(holder.clone());
    rejected_for(&s, "has no entry for this process");
    s.coverage.push(coverage(
        PROCESSES_OBSERVED,
        Ref::Process(holder.process),
        CoverageState::OutOfScope {
            why: "not found among the runtime and its descendants".into(),
        },
    ));
    assert_valid(&s);
}

/// Code review of PR-4d-2, R-C (P5): the runtime is never out of scope.
#[test]
fn the_runtime_is_never_out_of_scope() {
    let mut s = valid();
    let serve = s.processes[0].process.clone();
    s.processes[0].mappings.clear();
    s.processes[0].maps_read = MapsRead::NotRead;
    for c in &mut s.coverage {
        if c.check.as_str() == PROCESSES_OBSERVED && c.scope == Ref::Process(serve.clone()) {
            c.state = CoverageState::OutOfScope {
                why: "not found among the runtime and its descendants".into(),
            };
        }
    }
    rejected_for(&s, "is OutOfScope, but the process is the runtime");
}

/// Code review of PR-4d-2, R-A (P6): `NotRead` has no mapping.
#[test]
fn maps_not_read_has_no_mapping() {
    let mut s = valid();
    let runner = s.processes[1].process.clone();
    s.processes[1].maps_read = MapsRead::NotRead;
    set_state(
        &mut s,
        &runner,
        CoverageState::Partial {
            missing: vec!["maps: cut short".into()],
        },
    );
    rejected_for(&s, "maps_read is NotRead, but it has mappings");
}

/// Code review of PR-4d-2, R-A (P6): a `Complete` entry is about a process whose `maps` was read
/// whole.
#[test]
fn a_complete_entry_needs_maps_read_whole() {
    let mut s = valid();
    s.processes[1].maps_read = MapsRead::Part;
    rejected_for(&s, "is Complete, but the process's maps_read is Part");
    let mut s = valid();
    s.processes[0].mappings.clear();
    s.processes[0].maps_read = MapsRead::NotRead;
    rejected_for(&s, "is Complete, but the process's maps_read is NotRead");
}

/// Code review of PR-4d-2, R-A (P6): an `Unavailable` or `OutOfScope` entry is about a process
/// whose `maps` was not read.
#[test]
fn an_unavailable_or_out_of_scope_entry_needs_maps_not_read() {
    let mut s = valid();
    let serve = s.processes[0].process.clone();
    set_state(
        &mut s,
        &serve,
        CoverageState::Unavailable {
            why: Unavailability::PermissionDenied,
        },
    );
    rejected_for(&s, "is Unavailable, but the process's maps_read is Whole");
    let mut s = valid();
    let runner = s.processes[1].process.clone();
    set_state(
        &mut s,
        &runner,
        CoverageState::OutOfScope {
            why: "outside".into(),
        },
    );
    rejected_for(&s, "is OutOfScope, but the process's maps_read is Whole");
}

#[test]
fn the_processes_table_counts_mappings_and_links() {
    let md = sigil_model::render::markdown::render_session(&valid());
    assert!(md.contains("| Mappings |"), "{md}");
    // `ollama serve`: its executable and libc, one linked. The runner: four, three linked.
    assert!(md.contains("| 2 \\(1 linked\\) |"), "{md}");
    assert!(md.contains("| 4 \\(3 linked\\) |"), "{md}");
    assert!(
        md.contains("inst\\:install\\/lib\\/ollama\\/llama\\-server"),
        "{md}"
    );
}

fn set_state(s: &mut Session, p: &ProcessRef, state: CoverageState) {
    for c in &mut s.coverage {
        if c.check.as_str() == PROCESSES_OBSERVED && c.scope == Ref::Process(p.clone()) {
            c.state = state.clone();
        }
    }
    // A required check that is not complete is reported as missing.
    s.outcome.completeness = Completeness::Incomplete {
        missing_required: vec![CheckId::new(PROCESSES_OBSERVED).unwrap()],
        gaps: vec![],
    };
}

/// The Markdown of `s`, which is valid.
fn markdown(s: &Session) -> String {
    assert_valid(s);
    sigil_model::render::markdown::render_session(s)
}

/// The Mappings cell counts only what `maps_read` says was read, and says why when nothing was
/// (code review of PR-4d-2, R-A): never a count for `NotRead`.
#[test]
fn a_process_whose_maps_was_not_read_is_not_shown_as_a_zero() {
    // The reviewer's case: the executable's identity was read and linked, `maps` was refused.
    // The entry is `Partial`, as for a read in part: only `maps_read` tells them apart.
    let mut s = valid();
    let serve = s.processes[0].process.clone();
    set_state(
        &mut s,
        &serve,
        CoverageState::Partial {
            missing: vec!["maps: cannot be read (PermissionDenied)".into()],
        },
    );
    s.processes[0].mappings.clear();
    s.processes[0].maps_read = MapsRead::NotRead;
    let md = markdown(&s);
    assert!(md.contains("| not observed |"), "{md}");
    assert!(!md.contains("0 \\(0 linked"), "{md}");

    // A partial read says so.
    let mut s = valid();
    let runner = s.processes[1].process.clone();
    set_state(
        &mut s,
        &runner,
        CoverageState::Partial {
            missing: vec!["maps: cut short".into()],
        },
    );
    s.processes[1].maps_read = MapsRead::Part;
    let md = markdown(&s);
    assert!(md.contains("4 \\(3 linked\\; partial\\)"), "{md}");

    // A listener's holder outside the runtime's tree: out of scope, not read.
    let mut s = valid();
    let holder = bare(&s, 7);
    hold(&mut s, &holder.process.clone());
    s.coverage.push(coverage(
        PROCESSES_OBSERVED,
        Ref::Process(holder.process.clone()),
        CoverageState::OutOfScope {
            why: "not found among the runtime and its descendants".into(),
        },
    ));
    s.processes.push(holder);
    let md = markdown(&s);
    assert!(md.contains("| not read |"), "{md}");
    assert!(!md.contains("0 \\(0 linked"), "{md}");

    // Denied: serve could not be read at all.
    let mut s = valid();
    let serve = s.processes[0].process.clone();
    set_state(
        &mut s,
        &serve,
        CoverageState::Unavailable {
            why: Unavailability::PermissionDenied,
        },
    );
    s.processes[0].mappings.clear();
    s.processes[0].maps_read = MapsRead::NotRead;
    s.processes[0].exe = ProcessExe::NotObservable(NotObservable::PermissionDenied);
    inst(&mut s, "inst:install/bin/ollama")
        .discovered_by
        .retain(|d| !matches!(d, DiscoverySource::ProcessExe { .. }));
    let md = markdown(&s);
    assert!(md.contains("not observed \\(permission denied\\)"), "{md}");
    assert!(!md.contains("0 \\(0 linked"), "{md}");
}

/// Example 14 as a session from before `maps_read` holds it: its JSON without the field.
fn before_maps_read() -> Session {
    fn strip(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(map) => {
                map.remove("maps_read");
                map.values_mut().for_each(strip);
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(strip),
            _ => {}
        }
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/examples/session-v1/14-store-and-runtime.json");
    let mut value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    strip(&mut value);
    assert!(!value.to_string().contains("maps_read"));
    serde_json::from_value(value).unwrap()
}

/// Review of R1: `maps_read` is optional on read. A session from before it never read `maps`, so
/// the field reads as `NotRead`, and it is written again.
#[test]
fn a_session_from_before_maps_read_reads_it_as_not_read() {
    let s = before_maps_read();
    assert_eq!(s.processes[0].maps_read, MapsRead::NotRead);
    assert_valid(&s);
    let written = serde_json::to_value(&s).unwrap();
    assert_eq!(
        written["processes"][0]["maps_read"],
        serde_json::json!("NotRead")
    );
}

#[test]
fn a_runtime_from_before_the_check_is_not_shown_as_a_zero() {
    // Example 14, from before `maps_read`: the runtime has no mappings and no entry.
    let md = markdown(&before_maps_read());
    assert!(md.contains("| not read |"), "{md}");
    assert!(!md.contains("0 \\(0 linked"), "{md}");
}
