//! The observed processes' links (PR-4d-2): an executable and its instance name each other (P1),
//! a mapping's instance is the object mapped (P2), `processes.observed` is about the audit or a
//! recorded process, once each (P3), a process is recorded once (P4), and a required
//! `processes.observed` covers the audit and each process read (P5).

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
fn a_required_processes_observed_covers_the_audit_and_each_process_read() {
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
