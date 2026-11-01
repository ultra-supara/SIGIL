//! The runtime's and its descendants' executables and mappings (PR-4d-2): linked to the scanned
//! instances, and covered by `processes.observed`.
//!
//! **Links.** By `dev:ino` only, never by path. A `dev:ino` that exactly one instance has links
//! to it. One that no instance has, or more than one (a hard link seen twice), stays unlinked: a
//! link is never guessed. The executable's instance gains `DiscoverySource::ProcessExe`. A
//! mapping is an observation only (F-T1).
//!
//! **`processes.observed`.**
//!
//! | Scope | State | When |
//! |---|---|---|
//! | `Audit` | `Unavailable(PermissionDenied)` | The process list was denied, or PID 1 is missing from a complete list (`hidepid`) |
//! | `Audit` | `Partial` | The list was cut short, or a process gap (`ProcFacts::process_gaps`): a process that cannot be read or read again, whose parent cannot be read, or that may be the runtime |
//! | `Audit` | `Complete` | Otherwise |
//! | a process | `Unavailable(PermissionDenied)` | Both its executable's identity and `maps` were refused, and the checks for an exec found no gap; or it cannot be read again for want of permission |
//! | a process | `Partial` | Anything else not observed (`Detail::missing`), as for a listener's holder outside the runtime's tree that may be the runtime, whose executable and mappings are not read |
//! | a process | `Complete` | Its executable's identity, all of `maps`, and `ns/mnt` were read |
//! | a process | `OutOfScope` ([`OUTSIDE_THE_RUNTIME`]) | In `ProcFacts::outside`: a listener's holder outside the runtime's tree, whose executable and mappings are not read |
//!
//! A recorded process with neither a `Detail` nor a place in `outside` gets no entry: validation
//! then refuses the session, rather than it being out of scope unseen.

use std::collections::BTreeMap;

use sigil_model::{
    CheckId, Coverage, CoverageState, DiscoverySource, FileInstance, NotObservable, Observability,
    ProcessExe, ProcessObs, Ref, Unavailability, PROCESSES_OBSERVED,
};

use crate::observe::proc::{Detail, ProcFacts};

/// Why a recorded process the second pass did not read has `processes.observed` `OutOfScope`: a
/// listener's holder, outside the runtime's tree, whose executable and mappings are not read. It
/// says what was observed: the descendants are found through the parents that `stat` gives, so a
/// process under one that cannot be read is not found among them, though it may be one. The
/// audit's entry is then `Partial` (a process gap).
pub const OUTSIDE_THE_RUNTIME: &str = "not found among the runtime and its descendants";

/// Links each process's executable and mappings to the one instance with the same `dev:ino`.
pub fn link(processes: &mut [ProcessObs], details: &[Detail], instances: &mut [FileInstance]) {
    let mut by_id: BTreeMap<(u64, u64), Vec<usize>> = BTreeMap::new();
    for (i, instance) in instances.iter().enumerate() {
        by_id
            .entry((instance.stat.dev, instance.stat.ino))
            .or_default()
            .push(i);
    }
    let one = |id: (u64, u64)| match by_id.get(&id).map(Vec::as_slice) {
        Some([i]) => Some(*i),
        _ => None,
    };
    for p in processes.iter_mut() {
        let exe = details
            .iter()
            .find(|d| d.process == p.process)
            .and_then(|d| d.exe_id)
            .and_then(one);
        if let Some(i) = exe {
            p.exe = ProcessExe::Instance {
                instance: instances[i].id.clone(),
            };
            // Once per process, however often it is linked (as the store merges its sources).
            let source = DiscoverySource::ProcessExe {
                process: p.process.clone(),
            };
            if !instances[i].discovered_by.contains(&source) {
                instances[i].discovered_by.push(source);
            }
        }
        for m in &mut p.mappings {
            m.instance = one((m.dev, m.ino)).map(|i| instances[i].id.clone());
        }
    }
}

/// `processes.observed`: one entry for the audit, one for each [`Detail`], and `OutOfScope`
/// ([`OUTSIDE_THE_RUNTIME`]) for each process the observation placed outside the runtime's tree
/// (`ProcFacts::outside`). A recorded process with neither gets none, which validation refuses.
pub fn coverage(facts: &ProcFacts) -> Vec<Coverage> {
    let Ok(check) = CheckId::new(PROCESSES_OBSERVED) else {
        return vec![];
    };
    let entry = |scope, state| Coverage {
        check: check.clone(),
        scope,
        state,
        budget: None,
    };
    let denied = CoverageState::Unavailable {
        why: Unavailability::PermissionDenied,
    };
    let audit = match facts.process_list {
        Observability::NotObservable(NotObservable::PermissionDenied) => denied.clone(),
        Observability::Observed if !facts.pid1_visible => denied.clone(),
        list => {
            let mut missing = vec![];
            if let Observability::NotObservable(why) = list {
                missing.push(format!(
                    "the process list was not read to its end ({why:?}): a descendant may be missing"
                ));
            }
            missing.extend(facts.process_gaps.iter().cloned());
            if missing.is_empty() {
                CoverageState::Complete
            } else {
                CoverageState::Partial { missing }
            }
        }
    };
    let mut out = vec![entry(Ref::Audit, audit)];
    for d in &facts.details {
        let state = if d.denied {
            denied.clone()
        } else if d.missing.is_empty() {
            CoverageState::Complete
        } else {
            CoverageState::Partial {
                missing: d.missing.clone(),
            }
        };
        out.push(entry(Ref::Process(d.process.clone()), state));
    }
    // Code review of PR-4d-2, R-C: a listener's holder outside the runtime's tree, whose
    // executable and mappings are not read. Out of scope, not a gap.
    for p in &facts.outside {
        let state = CoverageState::OutOfScope {
            why: OUTSIDE_THE_RUNTIME.to_string(),
        };
        out.push(entry(Ref::Process(p.clone()), state));
    }
    out
}

#[cfg(test)]
mod tests {
    use sigil_model::{
        DiscoverySource, FileInstance, InstanceContent, InstanceId, MappingObs, MapsRead,
        NotObservable, NsInode, Observability, ProcessExe, ProcessObs, ProcessRef, RootId,
        Stability, StatInfo, Timestamp, Tri, UnknownReason, UntrustedText,
    };

    use sigil_model::{CoverageState, Ref};

    use super::{coverage, link, OUTSIDE_THE_RUNTIME};
    use crate::observe::proc::{Detail, ProcFacts};

    fn process(pid: u32) -> ProcessRef {
        ProcessRef {
            pid,
            start_ticks: 1,
            boot_id: "b".into(),
        }
    }

    fn placed(id: &str, ino: u64) -> FileInstance {
        FileInstance {
            id: InstanceId::new(id).unwrap(),
            root: RootId::new("install").unwrap(),
            path: UntrustedText::new(id),
            link_chain: vec![],
            resolved: None,
            content: InstanceContent::NotRead {
                why: sigil_model::NotReadReason::BudgetExceeded,
            },
            stat: StatInfo {
                dev: 7,
                ino,
                mode: 0o100644,
                uid: 0,
                gid: 0,
                size: 1,
                mtime_ns: 0,
                nlink: 1,
            },
            stability: Stability::NoChangeDetected,
            discovered_by: vec![DiscoverySource::Walk],
        }
    }

    fn obs(pid: u32, inos: &[u64]) -> ProcessObs {
        let at = Timestamp::new("2026-11-01T00:00:00Z").unwrap();
        ProcessObs {
            process: process(pid),
            at: at.clone(),
            roles: vec![],
            exe: ProcessExe::Path {
                path: UntrustedText::new("/x"),
                deleted: false,
            },
            mappings: inos
                .iter()
                .map(|ino| MappingObs {
                    process: process(pid),
                    at: at.clone(),
                    dev: 7,
                    ino: *ino,
                    path_text: UntrustedText::new("/m"),
                    deleted: false,
                    instance: None,
                    same_mount_ns: Tri::Unknown {
                        reason: UnknownReason::NotObservable(NotObservable::ReadIncomplete),
                    },
                })
                .collect(),
            maps_read: if inos.is_empty() {
                MapsRead::NotRead
            } else {
                MapsRead::Whole
            },
            name: None,
            argv: None,
            net_ns: NsInode::Inode(1),
            fd_table: Observability::Observed,
        }
    }

    #[test]
    fn a_dev_ino_one_instance_has_is_linked_and_no_other() {
        let mut instances = vec![
            placed("inst:a", 1),
            placed("inst:b", 2),
            placed("inst:c", 2),
        ];
        let mut processes = vec![obs(10, &[1, 2, 3]), obs(11, &[])];
        let details = vec![
            Detail {
                process: process(10),
                exe_id: Some((7, 1)),
                denied: false,
                missing: vec![],
            },
            // Its executable is the file two instances share: no link.
            Detail {
                process: process(11),
                exe_id: Some((7, 2)),
                denied: false,
                missing: vec![],
            },
        ];
        link(&mut processes, &details, &mut instances);
        assert_eq!(
            processes[0].exe,
            ProcessExe::Instance {
                instance: InstanceId::new("inst:a").unwrap()
            }
        );
        assert_eq!(
            instances[0].discovered_by,
            vec![
                DiscoverySource::Walk,
                DiscoverySource::ProcessExe {
                    process: process(10)
                }
            ]
        );
        let linked: Vec<Option<&str>> = processes[0]
            .mappings
            .iter()
            .map(|m| m.instance.as_ref().map(|i| i.as_str()))
            .collect();
        assert_eq!(linked, [Some("inst:a"), None, None]);
        assert!(matches!(processes[1].exe, ProcessExe::Path { .. }));
        assert_eq!(instances[1].discovered_by, vec![DiscoverySource::Walk]);
        assert_eq!(instances[2].discovered_by, vec![DiscoverySource::Walk]);
    }

    /// Review of a93bfef: linking twice names a process once, as the store merges its sources.
    #[test]
    fn linking_twice_names_the_process_once() {
        let mut instances = vec![placed("inst:a", 1)];
        let mut processes = vec![obs(10, &[1])];
        let details = vec![Detail {
            process: process(10),
            exe_id: Some((7, 1)),
            denied: false,
            missing: vec![],
        }];
        link(&mut processes, &details, &mut instances);
        link(&mut processes, &details, &mut instances);
        assert_eq!(
            instances[0].discovered_by,
            vec![
                DiscoverySource::Walk,
                DiscoverySource::ProcessExe {
                    process: process(10)
                }
            ]
        );
        assert_eq!(
            processes[0].mappings[0].instance,
            Some(InstanceId::new("inst:a").unwrap())
        );
    }

    /// Review of R1: `OutOfScope` is only for a process the observation placed outside the
    /// runtime's tree. A recorded process with neither a `Detail` nor that place has no entry, so
    /// P5 refuses the session instead of it being out of scope unseen.
    #[test]
    fn out_of_scope_is_only_for_a_process_placed_outside_the_tree() {
        let facts = ProcFacts {
            processes: vec![obs(10, &[]), obs(11, &[]), obs(12, &[])],
            listeners: vec![],
            own_net_ns: None,
            process_list: Observability::Observed,
            pid1_visible: true,
            gaps: vec![],
            details: vec![Detail {
                process: process(10),
                exe_id: None,
                denied: false,
                missing: vec![],
            }],
            process_gaps: vec![],
            outside: vec![process(11)],
        };
        let entries: Vec<(Ref, CoverageState)> = coverage(&facts)
            .into_iter()
            .map(|c| (c.scope, c.state))
            .collect();
        assert_eq!(
            entries,
            [
                (Ref::Audit, CoverageState::Complete),
                (Ref::Process(process(10)), CoverageState::Complete),
                (
                    Ref::Process(process(11)),
                    CoverageState::OutOfScope {
                        why: OUTSIDE_THE_RUNTIME.to_string()
                    }
                ),
            ]
        );
    }

    #[test]
    fn a_dev_ino_on_another_device_is_not_linked() {
        let mut instances = vec![placed("inst:a", 1)];
        let mut processes = vec![obs(10, &[1])];
        processes[0].mappings[0].dev = 8;
        let details = vec![Detail {
            process: process(10),
            exe_id: Some((8, 1)),
            denied: false,
            missing: vec![],
        }];
        link(&mut processes, &details, &mut instances);
        assert!(matches!(processes[0].exe, ProcessExe::Path { .. }));
        assert_eq!(processes[0].mappings[0].instance, None);
    }
}
