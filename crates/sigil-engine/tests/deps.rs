//! Recorded snapshot tests and a local fixture install collector regression. No target execution or proc reads.
//! World elf/link/dir calls explicitly declare observed normal parent proofs; they never create parent FileInstances.
use sigil_engine::analyze::deps::{self, DependencyState, DepsAnalysis, DepsBudgets, DepsOptions};
use sigil_model::*;

struct World {
    roots: Vec<ScanRoot>,
    instances: Vec<FileInstance>,
    artifacts: Vec<Artifact>,
    binaries: Vec<BinaryFacts>,
    processes: Vec<ProcessObs>,
    values: Vec<ProcessValue>,
}

fn abi() -> ElfAbi {
    ElfAbi {
        is_64: true,
        little_endian: true,
        machine: 62,
    }
}
fn id(path: &str) -> InstanceId {
    InstanceId::new(format!("inst:{path}")).unwrap()
}
fn pref(pid: u32) -> ProcessRef {
    ProcessRef {
        pid,
        start_ticks: u64::from(pid) * 10,
        boot_id: "boot-deps".into(),
    }
}
fn stat(mode: u32, ino: u64) -> StatInfo {
    StatInfo {
        dev: 1,
        ino,
        mode,
        uid: 1000,
        gid: 1000,
        size: 64,
        mtime_ns: 0,
        nlink: 1,
    }
}
fn observed_directory_ino(path: &[u8]) -> u64 {
    // Stable across fixture insertion order, unlike instances.len(). Parent observations in
    // different proofs of the same synthetic directory must agree.
    path.iter().fold(0xcbf29ce484222325u64, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
    })
}
impl World {
    fn recorded_normal_path(&self, path: &str) -> (RootId, Option<RecordedPathProof>) {
        let root = self
            .roots
            .iter()
            .filter(|r| {
                let b = r.path.as_bytes();
                let p = path.as_bytes();
                p == b || b == b"/" || (p.starts_with(b) && p.get(b.len()) == Some(&b'/'))
            })
            .max_by_key(|r| r.path.as_bytes().len())
            .expect("fixture path inside explicit root");
        if path.as_bytes() == root.path.as_bytes() {
            return (root.id.clone(), None);
        }
        let base = root.path.as_str().unwrap().trim_end_matches('/');
        let relative = path.strip_prefix(base).unwrap().trim_start_matches('/');
        let parts: Vec<_> = relative.split('/').collect();
        let mut at = base.to_owned();
        let mut parents = vec![];
        for name in &parts[..parts.len() - 1] {
            at.push('/');
            at.push_str(name);
            parents.push(RecordedDirectory {
                name: (*name).into(),
                dev: 1,
                ino: observed_directory_ino(at.as_bytes()),
            });
        }
        let proof = (parents.len() <= sigil_model::dependency_path::MAX_PROOF_PARENTS).then_some(
            RecordedPathProof {
                root_dev: 1,
                root_ino: observed_directory_ino(root.path.as_bytes()),
                parents,
            },
        );
        (root.id.clone(), proof)
    }
    fn strip_path_proofs(&mut self) {
        for i in &mut self.instances {
            i.path_proof = None;
        }
    }
}

impl World {
    fn new() -> Self {
        Self {
            roots: vec![ScanRoot {
                id: RootId::new("install").unwrap(),
                path: "/scan".into(),
            }],
            instances: vec![],
            artifacts: vec![],
            binaries: vec![],
            processes: vec![],
            values: vec![],
        }
    }
    fn dir(&mut self, path: &str) {
        if self
            .instances
            .iter()
            .any(|i| i.path.as_bytes() == path.as_bytes())
        {
            return;
        }
        let (root, path_proof) = self.recorded_normal_path(path);
        self.instances.push(FileInstance {
            id: id(path),
            root,
            path: path.into(),
            link_chain: vec![],
            resolved: None,
            content: InstanceContent::NotRead {
                why: NotReadReason::Directory,
            },
            stat: stat(0o040755, observed_directory_ino(path.as_bytes())),
            stability: Stability::NoChangeDetected,
            discovered_by: vec![DiscoverySource::Walk],
            path_proof,
        });
    }
    fn elf(
        &mut self,
        path: &str,
        kind: ElfType,
        needed: &[&str],
        rpath: &[&str],
        runpath: &[&str],
    ) {
        let (root, path_proof) = self.recorded_normal_path(path);
        let hash = format!("{:064x}", self.artifacts.len() + 1);
        let artifact = ArtifactId::new(format!("sha256:{hash}")).unwrap();
        let slice = SliceId::new(format!("{artifact}#x86_64@0")).unwrap();
        self.artifacts.push(Artifact {
            id: artifact.clone(),
            size: 64,
            format: Format::Elf { kind },
            slices: vec![Slice {
                id: slice.clone(),
                arch: Arch::X86_64,
                offset: 0,
                size: 64,
                sha256: Sha256Hex::new(hash).unwrap(),
            }],
        });
        self.instances.push(FileInstance {
            id: id(path),
            root,
            path: path.into(),
            link_chain: vec![],
            resolved: None,
            content: InstanceContent::Read { artifact },
            stat: stat(0o100755, self.instances.len() as u64 + 1),
            stability: Stability::NoChangeDetected,
            discovered_by: vec![DiscoverySource::Walk],
            path_proof,
        });
        self.binaries.push(BinaryFacts {
            slice,
            container: ContainerFacts::Elf(ElfFacts {
                abi: Some(abi()),
                interp: None,
                soname: None,
                needed: needed.iter().map(|s| (*s).into()).collect(),
                rpath: rpath.iter().map(|s| (*s).into()).collect(),
                runpath: runpath.iter().map(|s| (*s).into()).collect(),
                build_id: None,
                comment: vec![],
                stripped: Some(true),
                exports: 0,
                imports: vec![],
                data: vec![],
                returns: vec![],
            }),
            go: None,
            gaps: vec![],
        });
    }
    fn facts(&mut self, path: &str) -> &mut ElfFacts {
        let i = self.instances.iter().find(|i| i.id == id(path)).unwrap();
        let InstanceContent::Read { artifact } = &i.content else {
            panic!("not read")
        };
        let a = self.artifacts.iter().find(|a| &a.id == artifact).unwrap();
        let b = self
            .binaries
            .iter_mut()
            .find(|b| b.slice == a.slices[0].id)
            .unwrap();
        let ContainerFacts::Elf(e) = &mut b.container else {
            panic!("not ELF")
        };
        e
    }
    fn link(&mut self, path: &str, target: &str) {
        let (root, path_proof) = self.recorded_normal_path(path);
        self.instances.push(FileInstance {
            id: id(path),
            root,
            path: path.into(),
            link_chain: vec![LinkHop {
                path: path.into(),
                target: target.into(),
                uid: 1000,
                mode: 0o120777,
            }],
            resolved: Some(target.into()),
            content: InstanceContent::NotRead {
                why: NotReadReason::NotFollowed,
            },
            stat: stat(0o120777, self.instances.len() as u64 + 1),
            stability: Stability::NoChangeDetected,
            discovered_by: vec![DiscoverySource::Walk],
            path_proof,
        });
    }
    fn process(&mut self, pid: u32, exe: &str, mnt: Option<u64>) {
        self.processes.push(ProcessObs {
            process: pref(pid),
            at: Timestamp::new("2026-11-02T00:00:00Z").unwrap(),
            roles: vec![],
            exe: ProcessExe::Instance { instance: id(exe) },
            mappings: vec![],
            maps_read: MapsRead::Whole,
            name: None,
            argv: None,
            net_ns: NsInode::Inode(1),
            mnt_ns: mnt.map(NsInode::Inode),
            fd_table: Observability::Observed,
        });
    }
    fn value(
        &mut self,
        pid: u32,
        key: ValueKey,
        value: TriValue,
        read: ProcessValueRead,
    ) -> ValueId {
        let value_id = ValueId::new(format!("value:deps-{}-{}", pid, self.values.len())).unwrap();
        self.values.push(ProcessValue {
            id: value_id.clone(),
            process_role: sigil_engine::analyze::values::observed_role(&pref(pid), &[]).unwrap(),
            key,
            value,
            origin: ValueOrigin::ObservedProcess {
                process: pref(pid),
                source: ObsSource::Proc,
                read: Some(read),
            },
            applies_to: vec![],
        });
        value_id
    }
    fn run(&self) -> DepsAnalysis {
        self.with(
            DepsOptions {
                observe_env: false,
                observer_mnt_ns: Some(7),
            },
            DepsBudgets::default(),
        )
    }
    fn with(&self, options: DepsOptions, budgets: DepsBudgets) -> DepsAnalysis {
        deps::analyze(
            &self.roots,
            &self.instances,
            &self.artifacts,
            &self.binaries,
            &self.processes,
            &self.values,
            options,
            budgets,
        )
    }
}
fn edges<'a>(
    a: &'a DepsAnalysis,
    requester: &str,
    needed_name: &str,
    via_rule: SearchRule,
) -> Vec<(&'a InstanceId, &'a DependencyContext)> {
    a.relations
        .iter()
        .filter_map(|r| match r {
            Relation::Candidate {
                needed,
                candidate,
                via,
                context: Some(c),
                ..
            } if c.requester == id(requester)
                && needed.as_bytes() == needed_name.as_bytes()
                && *via == via_rule =>
            {
                Some((candidate, c))
            }
            _ => None,
        })
        .collect()
}
fn gaps<'a>(a: &'a DepsAnalysis, requester: &str) -> Vec<&'a str> {
    a.requesters
        .iter()
        .find(|r| r.requester == id(requester))
        .unwrap()
        .gaps
        .iter()
        .map(String::as_str)
        .collect()
}

#[test]
fn rpath_is_suppressed_by_runpath_and_every_rule_retains_candidates() {
    let mut w = World::new();
    w.elf(
        "/scan/bin/app",
        ElfType::Exec,
        &["lib.so"],
        &["/scan/old"],
        &["/scan/new"],
    );
    w.elf("/scan/old/lib.so", ElfType::Dyn, &[], &[], &[]);
    w.elf("/scan/new/lib.so", ElfType::Dyn, &[], &[], &[]);
    let a = w.run();
    assert!(edges(&a, "/scan/bin/app", "lib.so", SearchRule::Rpath).is_empty());
    assert_eq!(
        edges(&a, "/scan/bin/app", "lib.so", SearchRule::Runpath).len(),
        1
    );
    w.facts("/scan/bin/app").runpath.clear();
    assert_eq!(
        edges(&w.run(), "/scan/bin/app", "lib.so", SearchRule::Rpath).len(),
        1
    );
}

#[test]
fn inherited_rpath_uses_its_owners_origin_and_keeps_separate_ambiguous_chains() {
    let mut w = World::new();
    w.elf(
        "/scan/a/app",
        ElfType::Exec,
        &["mid.so"],
        &["$ORIGIN/libs"],
        &[],
    );
    w.elf(
        "/scan/b/app",
        ElfType::Exec,
        &["mid.so"],
        &["${ORIGIN}/libs"],
        &[],
    );
    w.elf("/scan/a/libs/mid.so", ElfType::Dyn, &["leaf.so"], &[], &[]);
    w.elf("/scan/b/libs/mid.so", ElfType::Dyn, &["leaf.so"], &[], &[]);
    w.elf("/scan/a/libs/leaf.so", ElfType::Dyn, &[], &[], &[]);
    w.elf("/scan/b/libs/leaf.so", ElfType::Dyn, &[], &[], &[]);
    let a = w.run();
    let e = edges(&a, "/scan/a/libs/mid.so", "leaf.so", SearchRule::Rpath);
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].0, &id("/scan/a/libs/leaf.so"));
    assert_eq!(
        e[0].1.loader_chain,
        vec![id("/scan/a/app"), id("/scan/a/libs/mid.so")]
    );
    assert_eq!(e[0].1.search_dir.as_bytes(), b"/scan/a/libs");
    assert!(
        edges(&a, "/scan/b/libs/mid.so", "leaf.so", SearchRule::Rpath)
            .iter()
            .all(|(i, c)| **i == id("/scan/b/libs/leaf.so")
                && c.loader_chain[0] == id("/scan/b/app"))
    );
}

#[test]
fn runpath_does_not_propagate_and_a_child_runpath_suppresses_ancestor_rpath() {
    let mut w = World::new();
    w.elf(
        "/scan/bin/app",
        ElfType::Exec,
        &["mid.so"],
        &[],
        &["/scan/lib"],
    );
    w.elf("/scan/lib/mid.so", ElfType::Dyn, &["leaf.so"], &[], &[]);
    w.elf("/scan/lib/leaf.so", ElfType::Dyn, &[], &[], &[]);
    let a = w.run();
    assert!(edges(&a, "/scan/lib/mid.so", "leaf.so", SearchRule::Runpath).is_empty());
    assert!(edges(&a, "/scan/lib/mid.so", "leaf.so", SearchRule::Rpath).is_empty());
    w.facts("/scan/bin/app").rpath = vec!["/scan/lib".into()];
    w.facts("/scan/bin/app").runpath.clear();
    w.facts("/scan/lib/mid.so").runpath = vec!["/scan/other".into()];
    assert!(edges(&w.run(), "/scan/lib/mid.so", "leaf.so", SearchRule::Rpath).is_empty());
}

#[test]
fn one_slice_at_two_placements_has_two_distinct_origins() {
    let mut w = World::new();
    w.elf(
        "/scan/a/app",
        ElfType::Exec,
        &["lib.so"],
        &[],
        &["$ORIGIN/lib"],
    );
    let mut second = w
        .instances
        .iter()
        .find(|i| i.id == id("/scan/a/app"))
        .unwrap()
        .clone();
    let (root, path_proof) = w.recorded_normal_path("/scan/b/app");
    second.root = root;
    second.path_proof = path_proof;
    second.id = id("/scan/b/app");
    second.path = "/scan/b/app".into();
    w.instances.push(second);
    w.elf("/scan/a/lib/lib.so", ElfType::Dyn, &[], &[], &[]);
    w.elf("/scan/b/lib/lib.so", ElfType::Dyn, &[], &[], &[]);
    let a = w.run();
    for dir in ["a", "b"] {
        let requester = format!("/scan/{dir}/app");
        let e = edges(&a, &requester, "lib.so", SearchRule::Runpath);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].0, &id(&format!("/scan/{dir}/lib/lib.so")));
        assert_eq!(e[0].1.loader_chain, vec![id(&requester)]);
    }
}

#[test]
fn initial_environment_is_same_process_and_requires_the_explicit_option() {
    let mut w = World::new();
    w.elf("/scan/bin/app", ElfType::Exec, &["lib.so"], &[], &[]);
    w.elf("/scan/p1/lib.so", ElfType::Dyn, &[], &[], &[]);
    w.elf("/scan/p2/lib.so", ElfType::Dyn, &[], &[], &[]);
    w.process(10, "/scan/bin/app", Some(7));
    w.process(11, "/scan/bin/app", Some(7));
    let v1 = w.value(
        10,
        ValueKey::Env("LD_LIBRARY_PATH".into()),
        TriValue::Known("/scan/p1".into()),
        ProcessValueRead::InitialEnvironment,
    );
    let v2 = w.value(
        11,
        ValueKey::Env("LD_LIBRARY_PATH".into()),
        TriValue::Known("/scan/p2".into()),
        ProcessValueRead::InitialEnvironment,
    );
    assert!(edges(
        &w.run(),
        "/scan/bin/app",
        "lib.so",
        SearchRule::LdLibraryPath
    )
    .is_empty());
    let a = w.with(
        DepsOptions {
            observe_env: true,
            observer_mnt_ns: Some(7),
        },
        DepsBudgets::default(),
    );
    let e = edges(&a, "/scan/bin/app", "lib.so", SearchRule::LdLibraryPath);
    assert_eq!(e.len(), 2);
    for (candidate, context) in e {
        let pid = context.process.as_ref().unwrap().pid;
        assert_eq!(
            candidate,
            &id(if pid == 10 {
                "/scan/p1/lib.so"
            } else {
                "/scan/p2/lib.so"
            })
        );
        assert_eq!(
            context.values,
            vec![if pid == 10 { v1.clone() } else { v2.clone() }]
        );
    }
    assert!(gaps(&a, "/scan/bin/app")
        .iter()
        .any(|g| g.contains("secure execution")));
}

#[test]
fn relative_and_empty_entries_need_a_known_cwd_in_the_same_mount_namespace() {
    let mut w = World::new();
    w.elf(
        "/scan/bin/app",
        ElfType::Exec,
        &["here.so", "sub/there.so"],
        &[],
        &[":rel"],
    );
    w.elf("/scan/work/here.so", ElfType::Dyn, &[], &[], &[]);
    w.elf("/scan/work/sub/there.so", ElfType::Dyn, &[], &[], &[]);
    w.process(10, "/scan/bin/app", Some(7));
    let cwd = w.value(
        10,
        ValueKey::Cwd,
        TriValue::Known("/scan/work".into()),
        ProcessValueRead::Cwd,
    );
    let a = w.run();
    assert!(edges(&a, "/scan/bin/app", "here.so", SearchRule::Runpath)
        .iter()
        .any(|(_, c)| c.values == vec![cwd.clone()]));
    let e = edges(&a, "/scan/bin/app", "sub/there.so", SearchRule::DirectPath);
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].1.values, vec![cwd]);
    w.processes[0].mnt_ns = Some(NsInode::Inode(99));
    let a = w.run();
    assert!(edges(&a, "/scan/bin/app", "here.so", SearchRule::Runpath).is_empty());
    assert!(edges(&a, "/scan/bin/app", "sub/there.so", SearchRule::DirectPath).is_empty());
    assert!(gaps(&a, "/scan/bin/app").iter().any(|g| g.contains("cwd")));
}

#[test]
fn direct_absolute_names_bypass_directory_search_and_soname_alone_is_not_a_match() {
    let mut w = World::new();
    w.elf(
        "/scan/bin/app",
        ElfType::Exec,
        &["/scan/real/lib.so", "other.so"],
        &["/scan/decoy"],
        &[],
    );
    w.elf("/scan/real/lib.so", ElfType::Dyn, &[], &[], &[]);
    w.elf("/scan/decoy/lib.so", ElfType::Dyn, &[], &[], &[]);
    w.facts("/scan/real/lib.so").soname = Some("other.so".into());
    let a = w.run();
    assert_eq!(
        edges(
            &a,
            "/scan/bin/app",
            "/scan/real/lib.so",
            SearchRule::DirectPath
        )
        .len(),
        1
    );
    assert!(edges(&a, "/scan/bin/app", "/scan/real/lib.so", SearchRule::Rpath).is_empty());
    assert!(a.relations.iter().all(
        |r| !matches!(r, Relation::Candidate { needed, .. } if needed.as_bytes() == b"other.so")
    ));
}

#[test]
fn candidates_require_dyn_stability_architecture_class_byte_order_and_machine() {
    for mutation in 0..7 {
        let mut w = World::new();
        w.elf("/scan/app", ElfType::Exec, &["lib.so"], &[], &["/scan/lib"]);
        w.elf("/scan/lib/lib.so", ElfType::Dyn, &[], &[], &[]);
        match mutation {
            0 => {
                w.artifacts[1].format = Format::Elf {
                    kind: ElfType::Exec,
                }
            }
            1 => {
                let i = w
                    .instances
                    .iter_mut()
                    .find(|i| i.id == id("/scan/lib/lib.so"))
                    .unwrap();
                i.stability = Stability::ChangedDuringRead;
                i.path_proof = None;
            }
            2 => w.facts("/scan/lib/lib.so").abi.as_mut().unwrap().is_64 = false,
            3 => {
                w.facts("/scan/lib/lib.so")
                    .abi
                    .as_mut()
                    .unwrap()
                    .little_endian = false
            }
            4 => w.facts("/scan/lib/lib.so").abi.as_mut().unwrap().machine = 183,
            5 => w.facts("/scan/lib/lib.so").abi = None,
            6 => w.artifacts[1].slices[0].arch = Arch::Other,
            _ => unreachable!(),
        }
        assert!(
            edges(&w.run(), "/scan/app", "lib.so", SearchRule::Runpath).is_empty(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn all_candidates_are_kept_and_cycles_do_not_extend_the_chain() {
    let mut w = World::new();
    w.elf(
        "/scan/app",
        ElfType::Exec,
        &["mid.so"],
        &[],
        &["/scan/a:/scan/b"],
    );
    w.elf(
        "/scan/a/mid.so",
        ElfType::Dyn,
        &["mid.so"],
        &["/scan/a"],
        &[],
    );
    w.elf("/scan/b/mid.so", ElfType::Dyn, &[], &[], &[]);
    let a = w.run();
    assert_eq!(
        edges(&a, "/scan/app", "mid.so", SearchRule::Runpath).len(),
        2
    );
    assert!(gaps(&a, "/scan/a/mid.so")
        .iter()
        .any(|g| g.contains("loader-chain cycle")));
    for r in &a.relations {
        if let Relation::Candidate {
            context: Some(c), ..
        } = r
        {
            let mut chain = c.loader_chain.clone();
            chain.sort();
            chain.dedup();
            assert_eq!(chain.len(), c.loader_chain.len());
            assert_eq!(c.loader_chain.last(), Some(&c.requester));
        }
    }
}

#[test]
fn recorded_links_are_resolved_before_dotdot_and_unknown_ancestors_are_not_collapsed() {
    let mut w = World::new();
    w.elf(
        "/scan/app",
        ElfType::Exec,
        &["/scan/alias/../lib.so", "/scan/missing/../lib.so"],
        &[],
        &[],
    );
    w.dir("/scan/deep");
    w.dir("/scan/deep/dir");
    w.link("/scan/alias", "deep/dir");
    w.elf("/scan/deep/lib.so", ElfType::Dyn, &[], &[], &[]);
    w.elf("/scan/lib.so", ElfType::Dyn, &[], &[], &[]);
    let a = w.run();
    let e = edges(
        &a,
        "/scan/app",
        "/scan/alias/../lib.so",
        SearchRule::DirectPath,
    );
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].0, &id("/scan/deep/lib.so"));
    assert!(edges(
        &a,
        "/scan/app",
        "/scan/missing/../lib.so",
        SearchRule::DirectPath
    )
    .is_empty());
    assert!(gaps(&a, "/scan/app").contains(&"dependency path: unknown ancestor"));
}

#[test]
fn stable_recorded_file_links_work_but_loops_escape_and_more_than_40_hops_do_not() {
    for hops in [1, 40, 41] {
        let mut w = World::new();
        w.elf("/scan/app", ElfType::Exec, &["/scan/link0"], &[], &[]);
        for n in 0..hops {
            let target = if n + 1 == hops {
                "lib.so".to_owned()
            } else {
                format!("link{}", n + 1)
            };
            w.link(&format!("/scan/link{n}"), &target);
        }
        w.elf("/scan/lib.so", ElfType::Dyn, &[], &[], &[]);
        let a = w.run();
        assert_eq!(
            edges(&a, "/scan/app", "/scan/link0", SearchRule::DirectPath).len(),
            usize::from(hops <= 40)
        );
        if hops == 41 {
            assert!(
                gaps(&a, "/scan/app").contains(&"dependency path: symlink hop limit 40 exceeded")
            );
        }
    }
    let mut w = World::new();
    w.elf(
        "/scan/app",
        ElfType::Exec,
        &["/scan/loop", "/scan/outside"],
        &[],
        &[],
    );
    w.link("/scan/loop", "loop");
    w.link("/scan/outside", "/uncollected/lib.so");
    let a = w.run();
    assert!(a.relations.is_empty());
    assert!(gaps(&a, "/scan/app").contains(&"dependency path: symlink loop"));
    assert!(gaps(&a, "/scan/app").contains(&"dependency path: outside collected roots"));
}

#[test]
fn unknown_dynamic_tokens_and_resolution_gaps_are_explicit() {
    let mut w = World::new();
    w.elf(
        "/scan/app",
        ElfType::Exec,
        &["lib.so"],
        &[],
        &["/scan/$LIB:/scan/${PLATFORM}:/scan/$ORIGINX"],
    );
    w.elf("/scan/lib/lib.so", ElfType::Dyn, &[], &[], &[]);
    let a = w.run();
    assert!(a.relations.is_empty());
    let g = gaps(&a, "/scan/app");
    assert!(g.contains(&"dependency token: only ORIGIN is modeled"));
    assert!(g.iter().any(|g| g.contains("ld.so.cache")));
    assert!(g.iter().any(|g| g.contains("hardware-capability")));
}

#[test]
fn attempts_without_matches_exhaust_the_exact_budget_and_partial_work_never_looks_complete() {
    let mut w = World::new();
    w.elf(
        "/scan/app",
        ElfType::Exec,
        &["missing.so"],
        &[],
        &["/scan/one:/scan/two:/scan/three"],
    );
    // /scan/one plus the joined missing.so consumes three components, even on a miss.
    // The next raw /scan/two precharge refuses its second component at the limit.
    let a = w.with(
        DepsOptions::default(),
        DepsBudgets {
            search_paths: 4,
            ..DepsBudgets::default()
        },
    );
    assert!(a.relations.is_empty());
    assert!(gaps(&a, "/scan/app").contains(&"dependency_search_paths: 4 exceeded"));
    let a = w.with(
        DepsOptions::default(),
        DepsBudgets {
            contexts: 0,
            ..DepsBudgets::default()
        },
    );
    assert!(gaps(&a, "/scan/app").contains(&"dependency_contexts: 0 exceeded"));
    w.elf("/scan/one/missing.so", ElfType::Exec, &[], &[], &[]);
    let a = w.with(
        DepsOptions::default(),
        DepsBudgets {
            candidates: 0,
            ..DepsBudgets::default()
        },
    );
    assert!(gaps(&a, "/scan/app").contains(&"dependency_candidates: 0 exceeded"));
}

#[test]
fn component_budget_counts_full_direct_paths_and_origin_expansion() {
    for needed in ["/scan/bin/deep/lib.so", "$ORIGIN/deep/lib.so"] {
        let mut w = World::new();
        w.elf("/scan/bin/app", ElfType::Exec, &[needed], &[], &[]);
        w.elf("/scan/bin/deep/lib.so", ElfType::Dyn, &[], &[], &[]);
        // Both expanded paths contain scan/bin/deep/lib.so: exactly four units.
        // ORIGIN's raw three-component spelling must pay one extra after expansion.
        let a = w.with(
            DepsOptions::default(),
            DepsBudgets {
                search_paths: 3,
                ..DepsBudgets::default()
            },
        );
        assert!(a.relations.is_empty());
        assert!(gaps(&a, "/scan/bin/app").contains(&"dependency_search_paths: 3 exceeded"));
        let a = w.with(
            DepsOptions::default(),
            DepsBudgets {
                search_paths: 4,
                ..DepsBudgets::default()
            },
        );
        assert_eq!(
            edges(&a, "/scan/bin/app", needed, SearchRule::DirectPath).len(),
            1
        );
        assert!(!gaps(&a, "/scan/bin/app")
            .iter()
            .any(|gap| gap.contains("dependency_search_paths:")));
    }
}

#[test]
fn component_budget_counts_link_target_additions_and_stops_all_requesters() {
    for (target, total) in [("physical/deep", 5), ("/scan/physical/deep", 6)] {
        let mut w = World::new();
        w.elf(
            "/scan/app",
            ElfType::Exec,
            &["/scan/alias/lib.so"],
            &[],
            &[],
        );
        w.link("/scan/alias", target);
        w.elf("/scan/physical/deep/lib.so", ElfType::Dyn, &[], &[], &[]);
        let a = w.with(
            DepsOptions::default(),
            DepsBudgets {
                search_paths: total - 1,
                ..DepsBudgets::default()
            },
        );
        assert!(a.relations.is_empty());
        let exact = format!("dependency_search_paths: {} exceeded", total - 1);
        assert!(a
            .requesters
            .iter()
            .filter(|r| r.state == DependencyState::Modeled)
            .all(|r| r.gaps.contains(&exact)));
        assert!(gaps(&a, "/scan/app").contains(&"dependency path: component budget exhausted"));
        let a = w.with(
            DepsOptions::default(),
            DepsBudgets {
                search_paths: total,
                ..DepsBudgets::default()
            },
        );
        assert_eq!(
            edges(
                &a,
                "/scan/app",
                "/scan/alias/lib.so",
                SearchRule::DirectPath
            )
            .len(),
            1
        );
    }
}

#[test]
fn unused_empty_and_unsupported_raw_attempts_are_charged_without_refunds() {
    for setting in ["::::", "$LIB:$LIB:$LIB:$LIB", "/$LIB/a:/$LIB/b"] {
        let mut w = World::new();
        w.elf("/scan/app", ElfType::Exec, &["missing.so"], &[], &[setting]);
        let a = w.with(
            DepsOptions::default(),
            DepsBudgets {
                search_paths: 2,
                ..DepsBudgets::default()
            },
        );
        assert!(a.relations.is_empty());
        assert!(gaps(&a, "/scan/app").contains(&"dependency_search_paths: 2 exceeded"));
        assert!(!gaps(&a, "/scan/app").contains(&"dependency path: component budget exhausted"));
        assert!(!gaps(&a, "/scan/app").contains(&"dependency path: outside collected roots"));
        let expected = if setting.starts_with(':') {
            "dependency cwd: no known same-process cwd in observer mount namespace"
        } else {
            "dependency token: only ORIGIN is modeled"
        };
        assert!(gaps(&a, "/scan/app").contains(&expected));
    }
}

#[test]
fn identical_snapshot_order_does_not_change_analysis_or_chain_order() {
    let mut w = World::new();
    w.elf("/scan/app", ElfType::Exec, &["mid.so"], &["/scan/lib"], &[]);
    w.elf("/scan/lib/mid.so", ElfType::Dyn, &["leaf.so"], &[], &[]);
    w.elf("/scan/lib/leaf.so", ElfType::Dyn, &[], &[], &[]);
    let a = w.run();
    w.instances.reverse();
    w.artifacts.reverse();
    w.binaries.reverse();
    w.roots.reverse();
    assert_eq!(a, w.run());
}

#[test]
fn rel_is_out_of_scope_and_macho_stays_declared_only() {
    let mut w = World::new();
    w.elf("/scan/object.o", ElfType::Rel, &["must-not.so"], &[], &[]);
    let mut macho = w.artifacts[0].clone();
    macho.id = ArtifactId::new(format!("sha256:{:064x}", 999)).unwrap();
    macho.format = Format::MachO;
    macho.slices.clear();
    let mut placed = w.instances[0].clone();
    placed.id = id("/scan/macho");
    placed.path = "/scan/macho".into();
    placed.content = InstanceContent::Read {
        artifact: macho.id.clone(),
    };
    w.artifacts.push(macho);
    w.instances.push(placed);
    let a = w.run();
    assert!(a.relations.is_empty());
    assert!(a
        .requesters
        .iter()
        .any(|r| r.requester == id("/scan/object.o")
            && matches!(r.state, DependencyState::OutOfScope(_))));
    assert!(a
        .requesters
        .iter()
        .any(|r| r.requester == id("/scan/macho")
            && matches!(r.state, DependencyState::Unsupported(_))));
}

#[test]
fn configured_legacy_and_wrong_process_sources_do_not_supply_a_library_path() {
    for mutation in 0..4 {
        let mut w = World::new();
        w.elf("/scan/app", ElfType::Exec, &["lib.so"], &[], &[]);
        w.elf("/scan/env/lib.so", ElfType::Dyn, &[], &[], &[]);
        w.process(10, "/scan/app", Some(7));
        w.value(
            10,
            ValueKey::Env("LD_LIBRARY_PATH".into()),
            TriValue::Known("/scan/env".into()),
            ProcessValueRead::InitialEnvironment,
        );
        w.values[0].origin = match mutation {
            0 => ValueOrigin::Configured {
                file: ConfigRef {
                    file: id("/scan/app"),
                    key: "Environment".into(),
                    line: 9,
                },
                directive: "Environment".into(),
            },
            1 => ValueOrigin::ObservedProcess {
                process: pref(10),
                source: ObsSource::Proc,
                read: None,
            },
            2 => ValueOrigin::ObservedProcess {
                process: pref(11),
                source: ObsSource::Proc,
                read: Some(ProcessValueRead::InitialEnvironment),
            },
            3 => ValueOrigin::PredictedLaunch {
                rules: vec!["unverified-unit".into()],
                from: vec![],
            },
            _ => unreachable!(),
        };
        let a = w.with(
            DepsOptions {
                observe_env: true,
                observer_mnt_ns: Some(7),
            },
            DepsBudgets::default(),
        );
        assert!(
            edges(&a, "/scan/app", "lib.so", SearchRule::LdLibraryPath).is_empty(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn absent_environment_is_not_empty_and_duplicate_observations_are_ambiguous() {
    let mut w = World::new();
    w.elf("/scan/app", ElfType::Exec, &["lib.so"], &[], &[]);
    w.elf("/scan/work/lib.so", ElfType::Dyn, &[], &[], &[]);
    w.process(10, "/scan/app", Some(7));
    let env = w.value(
        10,
        ValueKey::Env("LD_LIBRARY_PATH".into()),
        TriValue::Absent,
        ProcessValueRead::InitialEnvironment,
    );
    let cwd = w.value(
        10,
        ValueKey::Cwd,
        TriValue::Known("/scan/work".into()),
        ProcessValueRead::Cwd,
    );
    let options = DepsOptions {
        observe_env: true,
        observer_mnt_ns: Some(7),
    };
    assert!(edges(
        &w.with(options, DepsBudgets::default()),
        "/scan/app",
        "lib.so",
        SearchRule::LdLibraryPath
    )
    .is_empty());
    w.values[0].value = TriValue::Known("".into());
    let a = w.with(options, DepsBudgets::default());
    let e = edges(&a, "/scan/app", "lib.so", SearchRule::LdLibraryPath);
    assert_eq!(e.len(), 1);
    let mut expected = vec![env, cwd];
    expected.sort();
    assert_eq!(e[0].1.values, expected);
    w.value(
        10,
        ValueKey::Env("LD_LIBRARY_PATH".into()),
        TriValue::Known("/scan/work".into()),
        ProcessValueRead::InitialEnvironment,
    );
    let a = w.with(options, DepsBudgets::default());
    assert!(edges(&a, "/scan/app", "lib.so", SearchRule::LdLibraryPath).is_empty());
    assert!(gaps(&a, "/scan/app").contains(&"dependency value: ambiguous observed inputs"));
}

#[test]
fn a_mapping_does_not_transfer_another_processs_environment_or_create_loader_ancestry() {
    let mut w = World::new();
    w.elf("/scan/app", ElfType::Exec, &["lib.so"], &[], &[]);
    w.elf("/scan/mapped.so", ElfType::Dyn, &["lib.so"], &[], &[]);
    w.elf("/scan/env/lib.so", ElfType::Dyn, &[], &[], &[]);
    w.process(10, "/scan/app", Some(7));
    w.value(
        10,
        ValueKey::Env("LD_LIBRARY_PATH".into()),
        TriValue::Known("/scan/env".into()),
        ProcessValueRead::InitialEnvironment,
    );
    let at = w.processes[0].at.clone();
    w.processes[0].mappings.push(MappingObs {
        process: pref(10),
        at,
        dev: 1,
        ino: 99,
        path_text: "/scan/mapped.so".into(),
        deleted: false,
        instance: Some(id("/scan/mapped.so")),
        same_mount_ns: Tri::Yes {
            why: (),
            basis: Basis::Observed {
                source: ObsSource::Proc,
            },
            unresolved: vec![],
        },
    });
    let a = w.with(
        DepsOptions {
            observe_env: true,
            observer_mnt_ns: Some(7),
        },
        DepsBudgets::default(),
    );
    assert!(edges(&a, "/scan/mapped.so", "lib.so", SearchRule::LdLibraryPath).is_empty());
    assert_eq!(
        edges(&a, "/scan/app", "lib.so", SearchRule::LdLibraryPath).len(),
        1
    );
}

#[test]
fn rpath_environment_and_default_candidates_are_all_retained_without_a_winner() {
    let mut w = World::new();
    w.roots.push(ScanRoot {
        id: RootId::new("system-lib").unwrap(),
        path: "/lib".into(),
    });
    w.elf(
        "/scan/app",
        ElfType::Exec,
        &["lib.so"],
        &["/scan/rpath"],
        &[],
    );
    w.elf("/scan/rpath/lib.so", ElfType::Dyn, &[], &[], &[]);
    w.elf("/scan/env/lib.so", ElfType::Dyn, &[], &[], &[]);
    w.elf("/lib/lib.so", ElfType::Dyn, &[], &[], &[]);
    w.instances
        .iter_mut()
        .find(|i| i.id == id("/lib/lib.so"))
        .unwrap()
        .root = RootId::new("system-lib").unwrap();
    w.process(10, "/scan/app", Some(7));
    w.value(
        10,
        ValueKey::Env("LD_LIBRARY_PATH".into()),
        TriValue::Known("/scan/env".into()),
        ProcessValueRead::InitialEnvironment,
    );
    let a = w.with(
        DepsOptions {
            observe_env: true,
            observer_mnt_ns: Some(7),
        },
        DepsBudgets::default(),
    );
    for (rule, path) in [
        (SearchRule::Rpath, "/scan/rpath/lib.so"),
        (SearchRule::LdLibraryPath, "/scan/env/lib.so"),
        (SearchRule::DefaultDir, "/lib/lib.so"),
    ] {
        assert!(edges(&a, "/scan/app", "lib.so", rule)
            .iter()
            .any(|(candidate, _)| **candidate == id(path)));
    }
}

#[test]
fn a_shared_child_retains_both_known_ancestries_instead_of_merging_them() {
    let mut w = World::new();
    w.elf(
        "/scan/app",
        ElfType::Exec,
        &["left.so", "right.so"],
        &["/scan/lib"],
        &[],
    );
    w.elf("/scan/lib/left.so", ElfType::Dyn, &["shared.so"], &[], &[]);
    w.elf("/scan/lib/right.so", ElfType::Dyn, &["shared.so"], &[], &[]);
    w.elf("/scan/lib/shared.so", ElfType::Dyn, &["leaf.so"], &[], &[]);
    w.elf("/scan/lib/leaf.so", ElfType::Dyn, &[], &[], &[]);
    let a = w.run();
    let e = edges(&a, "/scan/lib/shared.so", "leaf.so", SearchRule::Rpath);
    assert_eq!(e.len(), 2);
    let mut middle: Vec<_> = e.iter().map(|(_, c)| c.loader_chain[1].clone()).collect();
    middle.sort();
    assert_eq!(
        middle,
        vec![id("/scan/lib/left.so"), id("/scan/lib/right.so")]
    );
    assert!(e
        .iter()
        .all(|(_, c)| c.loader_chain.len() == 3 && c.loader_chain[0] == id("/scan/app")));
}

#[test]
fn paths_match_raw_non_utf8_and_long_bytes_beyond_the_display_limit() {
    let mut w = World::new();
    w.elf(
        "/scan/app",
        ElfType::Exec,
        &["placeholder"],
        &[],
        &["/scan/lib"],
    );
    w.elf("/scan/lib/placeholder", ElfType::Dyn, &[], &[], &[]);
    let name = vec![b'l', b'i', b'b', 0xff, b'.', b's', b'o'];
    w.facts("/scan/app").needed = vec![UntrustedText::from_bytes(name.clone())];
    let mut path = b"/scan/lib/".to_vec();
    path.extend_from_slice(&name);
    w.instances
        .iter_mut()
        .find(|i| i.id == id("/scan/lib/placeholder"))
        .unwrap()
        .path = UntrustedText::from_bytes(path);
    let a = w.run();
    assert!(a.relations.iter().any(
        |r| matches!(r, Relation::Candidate { needed, candidate, .. }
        if needed.as_bytes() == name && *candidate == id("/scan/lib/placeholder"))
    ));
    let directory = format!("/scan/{}", vec!["a".repeat(100); 6].join("/"));
    w.elf(
        "/scan/long-app",
        ElfType::Exec,
        &["long.so"],
        &[],
        &[&directory],
    );
    w.elf(&format!("{directory}/long.so"), ElfType::Dyn, &[], &[], &[]);
    let a = w.run();
    let e = edges(&a, "/scan/long-app", "long.so", SearchRule::Runpath);
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].1.search_dir.as_bytes(), directory.as_bytes());
    assert!(e[0].1.search_dir.as_bytes().len() > sigil_model::text::MAX_DISPLAY_CHARS);
}

#[test]
fn absolute_links_can_enter_another_collected_root_but_relative_links_cannot_escape_their_anchor() {
    let mut w = World::new();
    w.roots.push(ScanRoot {
        id: RootId::new("other").unwrap(),
        path: "/other".into(),
    });
    w.elf(
        "/scan/app",
        ElfType::Exec,
        &["/scan/absolute", "/scan/relative"],
        &[],
        &[],
    );
    w.elf("/other/lib.so", ElfType::Dyn, &[], &[], &[]);
    w.link("/scan/absolute", "/other/lib.so");
    w.link("/scan/relative", "../other/lib.so");
    let a = w.run();
    assert_eq!(
        edges(&a, "/scan/app", "/scan/absolute", SearchRule::DirectPath).len(),
        1
    );
    assert!(edges(&a, "/scan/app", "/scan/relative", SearchRule::DirectPath).is_empty());
    assert!(gaps(&a, "/scan/app").contains(&"dependency path: outside collected roots"));
}

#[test]
fn unobserved_namespace_deleted_cwd_and_unknown_cwd_never_use_the_analyzers_cwd() {
    for mutation in 0..4 {
        let mut w = World::new();
        w.elf("/scan/app", ElfType::Exec, &["lib.so"], &[], &[""]);
        w.elf("/scan/work/lib.so", ElfType::Dyn, &[], &[], &[]);
        w.process(10, "/scan/app", Some(7));
        w.value(
            10,
            ValueKey::Cwd,
            TriValue::Known("/scan/work".into()),
            ProcessValueRead::Cwd,
        );
        match mutation {
            0 => w.processes[0].mnt_ns = None,
            1 => w.values[0].value = TriValue::Known("/scan/work (deleted)".into()),
            2 => {
                w.values[0].value = TriValue::Unknown {
                    reason: UnknownReason::NotObservable(NotObservable::PermissionDenied),
                }
            }
            3 => w.values[0].value = TriValue::Known("relative".into()),
            _ => unreachable!(),
        }
        assert!(
            edges(&w.run(), "/scan/app", "lib.so", SearchRule::Runpath).is_empty(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn rejected_lookups_and_duplicate_contexts_are_charged_before_deduplication() {
    let mut w = World::new();
    w.elf(
        "/scan/app",
        ElfType::Exec,
        &["lib.so"],
        &[],
        &["/scan/lib:/scan/lib:/scan/lib"],
    );
    w.elf("/scan/lib/lib.so", ElfType::Dyn, &[], &[], &[]);
    let a = w.with(
        DepsOptions::default(),
        DepsBudgets {
            candidates: 2,
            ..DepsBudgets::default()
        },
    );
    assert!(gaps(&a, "/scan/app").contains(&"dependency_candidates: 2 exceeded"));
    assert_eq!(
        edges(&a, "/scan/app", "lib.so", SearchRule::Runpath).len(),
        1
    );
    assert_eq!(
        edges(&a, "/scan/app", "lib.so", SearchRule::Runpath)[0]
            .1
            .search,
        DependencySearch::Runpath {
            entry: 0,
            component: 0
        }
    );
    // Two seeds + two repeated child attempts consume four contexts; the third attempt is
    // refused even though the relation and queued child would have been duplicates.
    let a = w.with(
        DepsOptions::default(),
        DepsBudgets {
            contexts: 4,
            ..DepsBudgets::default()
        },
    );
    assert!(gaps(&a, "/scan/app").contains(&"dependency_contexts: 4 exceeded"));
}

#[test]
fn real_header_abi_records_class_endian_and_machine_and_malformed_headers_have_none() {
    use std::io::Write;
    for (is_64, little_endian, machine) in
        [(false, true, 3u16), (true, false, 183), (true, true, 62)]
    {
        let mut bytes = vec![0u8; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = if is_64 { 2 } else { 1 };
        bytes[5] = if little_endian { 1 } else { 2 };
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&if little_endian {
            3u16.to_le_bytes()
        } else {
            3u16.to_be_bytes()
        });
        bytes[18..20].copy_from_slice(&if little_endian {
            machine.to_le_bytes()
        } else {
            machine.to_be_bytes()
        });
        bytes[20..24].copy_from_slice(&if little_endian {
            1u32.to_le_bytes()
        } else {
            1u32.to_be_bytes()
        });
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&bytes).unwrap();
        let parsed = sigil_engine::binary::parse(&file, bytes.len() as u64, Default::default());
        let ContainerFacts::Elf(facts) = parsed.container else {
            panic!("ELF header")
        };
        assert_eq!(
            facts.abi,
            Some(ElfAbi {
                is_64,
                little_endian,
                machine
            })
        );
    }
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(b"not ELF").unwrap();
    let parsed = sigil_engine::binary::parse(&file, 7, Default::default());
    let ContainerFacts::Elf(facts) = parsed.container else {
        panic!("ELF fallback")
    };
    assert_eq!(facts.abi, None);
}

#[test]
fn environment_origin_belongs_to_the_process_executable_through_child_searches() {
    let mut w = World::new();
    w.elf("/scan/bin/app", ElfType::Exec, &["mid.so"], &[], &[]);
    w.elf(
        "/scan/bin/libs/mid.so",
        ElfType::Dyn,
        &["leaf.so"],
        &[],
        &[],
    );
    w.elf("/scan/bin/libs/leaf.so", ElfType::Dyn, &[], &[], &[]);
    w.process(10, "/scan/bin/app", Some(7));
    let input = w.value(
        10,
        ValueKey::Env("LD_LIBRARY_PATH".into()),
        TriValue::Known("$ORIGIN/libs".into()),
        ProcessValueRead::InitialEnvironment,
    );
    let a = w.with(
        DepsOptions {
            observe_env: true,
            observer_mnt_ns: Some(7),
        },
        DepsBudgets::default(),
    );
    let e = edges(
        &a,
        "/scan/bin/libs/mid.so",
        "leaf.so",
        SearchRule::LdLibraryPath,
    );
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].0, &id("/scan/bin/libs/leaf.so"));
    assert_eq!(e[0].1.search_dir.as_bytes(), b"/scan/bin/libs");
    assert_eq!(e[0].1.values, vec![input]);
    assert_eq!(
        e[0].1.loader_chain,
        vec![id("/scan/bin/app"), id("/scan/bin/libs/mid.so")]
    );
}

#[test]
fn explicit_sibling_file_roots_are_exact_leaf_anchors_without_invented_parent_entries() {
    let mut w = World::new();
    w.elf(
        "/scan/app",
        ElfType::Exec,
        &["libpeer.so"],
        &[],
        &["$ORIGIN"],
    );
    w.elf("/scan/libpeer.so", ElfType::Dyn, &[], &[], &[]);
    w.roots = vec![
        ScanRoot {
            id: id_root("binary-1"),
            path: "/scan/app".into(),
        },
        ScanRoot {
            id: id_root("binary-2"),
            path: "/scan/libpeer.so".into(),
        },
    ];
    w.instances[0].root = id_root("binary-1");
    w.instances[1].root = id_root("binary-2");
    w.instances[0].path_proof = None;
    w.instances[1].path_proof = None;
    assert_eq!(w.instances.len(), 2);
    let a = w.run();
    let e = edges(&a, "/scan/app", "libpeer.so", SearchRule::Runpath);
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].0, &id("/scan/libpeer.so"));
    fn id_root(name: &str) -> RootId {
        RootId::new(name).unwrap()
    }
}

#[test]
fn parser_records_real_elf_abi_instead_of_guessing_from_arch() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/elf/libdata.so");
    let file = std::fs::File::open(path).unwrap();
    let parsed =
        sigil_engine::binary::parse(&file, file.metadata().unwrap().len(), Default::default());
    let ContainerFacts::Elf(facts) = parsed.container else {
        panic!("fixture is ELF")
    };
    assert_eq!(facts.abi, Some(abi()));
}

#[test]
fn actual_install_output_resolves_without_synthetic_parent_instances() {
    use sigil_engine::collect::install::{collect, InstallBudgets};
    use sigil_model::dependency_path::PathIndex;
    let tree = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(tree.path().join("bin")).unwrap();
    std::fs::create_dir_all(tree.path().join("lib/ollama")).unwrap();
    let fixture = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/elf/libdata.so"),
    )
    .unwrap();
    std::fs::write(tree.path().join("bin/ollama"), &fixture).unwrap();
    std::fs::write(tree.path().join("lib/ollama/libdata.so"), &fixture).unwrap();
    std::fs::write(tree.path().join("lib/ollama/libm.so.6"), &fixture).unwrap();
    let mut facts = collect(tree.path(), InstallBudgets::default()).unwrap();
    let root = facts.root_path.as_str().unwrap().to_owned();
    let roots = vec![ScanRoot {
        id: RootId::new("install").unwrap(),
        path: facts.root_path.clone(),
    }];
    let app_path = format!("{root}/lib/ollama/libdata.so");
    let target_path = format!("{root}/lib/ollama/libm.so.6");
    let app = facts
        .instances
        .iter()
        .find(|i| i.path.as_bytes() == app_path.as_bytes())
        .unwrap();
    let target = facts
        .instances
        .iter()
        .find(|i| i.path.as_bytes() == target_path.as_bytes())
        .unwrap();
    let app_id = app.id.clone();
    let target_id = target.id.clone();
    for parent in ["bin", "lib", "lib/ollama"] {
        let absent = format!("{root}/{parent}");
        assert!(facts
            .instances
            .iter()
            .all(|i| i.path.as_bytes() != absent.as_bytes()));
    }
    assert_eq!(
        app.path_proof
            .as_ref()
            .unwrap()
            .parents
            .iter()
            .map(|p| p.name.as_bytes())
            .collect::<Vec<_>>(),
        [b"lib".as_slice(), b"ollama".as_slice()]
    );
    assert!(PathIndex::new(&roots, &facts.instances)
        .reaches(target_path.as_bytes(), &target_id)
        .unwrap());
    let analysis = deps::analyze(
        &roots,
        &facts.instances,
        &facts.artifacts,
        &facts.binaries,
        &[],
        &[],
        DepsOptions::default(),
        DepsBudgets::default(),
    );
    assert!(analysis
        .relations
        .iter()
        .any(|r| matches!(r, Relation::Candidate {
        needed,candidate,via:SearchRule::Runpath,context:Some(c),..
    } if needed.as_bytes()==b"libm.so.6" && candidate==&target_id && c.requester==app_id)));
    // Remove only the evidence. Never fabricate parent FileInstances to make this pass.
    for i in &mut facts.instances {
        i.path_proof = None;
    }
    let stripped = deps::analyze(
        &roots,
        &facts.instances,
        &facts.artifacts,
        &facts.binaries,
        &[],
        &[],
        DepsOptions::default(),
        DepsBudgets::default(),
    );
    assert!(!stripped
        .relations
        .iter()
        .any(|r| matches!(r,Relation::Candidate { candidate,.. }
        if candidate==&target_id)));
    assert!(stripped
        .requesters
        .iter()
        .filter(|r| r.requester == app_id)
        .flat_map(|r| &r.gaps)
        .any(|g| g == "dependency path: unknown ancestor"));
}

#[test]
fn no_parent_instances_are_fabricated_and_missing_or_tampered_proofs_stay_gaps() {
    let mut w = World::new();
    w.elf(
        "/scan/bin/app",
        ElfType::Exec,
        &["lib.so"],
        &[],
        &["/scan/lib/ollama"],
    );
    w.elf("/scan/lib/ollama/lib.so", ElfType::Dyn, &[], &[], &[]);
    assert_eq!(w.instances.len(), 2);
    assert!(w
        .instances
        .iter()
        .all(|i| i.stat.mode & 0o170000 != 0o040000));
    assert_eq!(
        edges(&w.run(), "/scan/bin/app", "lib.so", SearchRule::Runpath).len(),
        1
    );
    let target = id("/scan/lib/ollama/lib.so");
    w.instances
        .iter_mut()
        .find(|i| i.id == target)
        .unwrap()
        .path_proof
        .as_mut()
        .unwrap()
        .parents[0]
        .name = "unrecorded".into();
    assert!(edges(&w.run(), "/scan/bin/app", "lib.so", SearchRule::Runpath).is_empty());
    w.strip_path_proofs();
    assert!(edges(&w.run(), "/scan/bin/app", "lib.so", SearchRule::Runpath).is_empty());
    assert!(gaps(&w.run(), "/scan/bin/app").contains(&"dependency path: unknown ancestor"));
}
#[test]
fn over_depth_missing_proofs_report_the_exact_gap_without_inventing_directories() {
    let mut w = World::new();
    let directory = format!(
        "/scan/{}",
        (0..41)
            .map(|i| format!("d{i}"))
            .collect::<Vec<_>>()
            .join("/")
    );
    let target = format!("{directory}/lib.so");
    w.elf("/scan/app", ElfType::Exec, &["lib.so"], &[], &[&directory]);
    w.elf(&target, ElfType::Dyn, &[], &[], &[]);
    assert_eq!(w.instances.len(), 2);
    assert!(w
        .instances
        .iter()
        .find(|i| i.id == id(&target))
        .unwrap()
        .path_proof
        .is_none());
    let a = w.run();
    assert!(edges(&a, "/scan/app", "lib.so", SearchRule::Runpath).is_empty());
    for path in ["/scan/app", target.as_str()] {
        assert!(gaps(&a, path).contains(&"dependency path: parent proof depth 40 exceeded"));
    }
}
#[test]
fn bare_dollars_have_explicit_gaps_and_never_invalid_direct_path_relations() {
    for name in [
        "$",
        "$ORIGIN",
        "${ORIGIN}",
        "$LIB",
        "${UNKNOWN}",
        "lib$ORIGIN.so",
    ] {
        let mut w = World::new();
        w.elf("/scan/app", ElfType::Exec, &[name], &[], &["/scan/lib"]);
        w.elf("/scan/lib/lib.so", ElfType::Dyn, &[], &[], &[]);
        let result = w.run();
        assert!(result.relations.is_empty());
        assert!(gaps(&result, "/scan/app")
            .contains(&"dependency name: tokens in slash-free names are not modeled"));
    }
}

#[test]
fn duplicate_binary_facts_keep_the_first_source_witness() {
    let mut w = World::new();
    w.elf(
        "/scan/app",
        ElfType::Exec,
        &["lib.so"],
        &[],
        &["/scan/first"],
    );
    w.elf("/scan/first/lib.so", ElfType::Dyn, &[], &[], &[]);
    let mut duplicate = w.binaries[0].clone();
    let ContainerFacts::Elf(elf) = &mut duplicate.container else {
        panic!("ELF fixture")
    };
    elf.runpath = vec!["/scan/unrecorded".into()];
    w.binaries.push(duplicate);
    let a = w.run();
    let e = edges(&a, "/scan/app", "lib.so", SearchRule::Runpath);
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].0, &id("/scan/first/lib.so"));
    assert_eq!(e[0].1.search_dir.as_bytes(), b"/scan/first");
    assert_eq!(
        e[0].1.search,
        DependencySearch::Runpath {
            entry: 0,
            component: 0
        }
    );
}

#[test]
fn duplicate_artifacts_keep_the_first_object_classification() {
    let mut w = World::new();
    w.elf("/scan/app", ElfType::Exec, &["lib.so"], &[], &["/scan/lib"]);
    w.elf("/scan/lib/lib.so", ElfType::Dyn, &[], &[], &[]);
    let mut duplicate = w.artifacts[0].clone();
    duplicate.format = Format::Other;
    w.artifacts.push(duplicate);
    let a = w.run();
    assert_eq!(
        edges(&a, "/scan/app", "lib.so", SearchRule::Runpath).len(),
        1
    );
}

#[test]
fn observed_library_path_ambiguity_precedes_source_qualification() {
    for (source, read) in [
        (ObsSource::Proc, None),
        (ObsSource::Proc, Some(ProcessValueRead::Cwd)),
        (ObsSource::File, Some(ProcessValueRead::InitialEnvironment)),
        (
            ObsSource::Config,
            Some(ProcessValueRead::InitialEnvironment),
        ),
    ] {
        let mut w = World::new();
        w.elf("/scan/app", ElfType::Exec, &["lib.so"], &[], &[]);
        w.elf("/scan/work/lib.so", ElfType::Dyn, &[], &[], &[]);
        w.process(10, "/scan/app", Some(7));
        let key = ValueKey::Env("LD_LIBRARY_PATH".into());
        w.value(
            10,
            key.clone(),
            TriValue::Known("/scan/work".into()),
            ProcessValueRead::InitialEnvironment,
        );
        w.value(
            10,
            key,
            TriValue::Known("/scan/work".into()),
            ProcessValueRead::InitialEnvironment,
        );
        w.values[1].origin = ValueOrigin::ObservedProcess {
            process: pref(10),
            source,
            read,
        };
        let a = w.with(
            DepsOptions {
                observe_env: true,
                observer_mnt_ns: Some(7),
            },
            DepsBudgets::default(),
        );
        assert!(
            edges(&a, "/scan/app", "lib.so", SearchRule::LdLibraryPath).is_empty(),
            "duplicate {source:?}/{read:?}"
        );
        assert!(gaps(&a, "/scan/app").contains(&"dependency value: ambiguous observed inputs"));
    }
}

#[test]
fn observed_cwd_ambiguity_precedes_source_qualification() {
    for (source, read) in [
        (ObsSource::Proc, None),
        (ObsSource::Proc, Some(ProcessValueRead::InitialEnvironment)),
        (ObsSource::File, Some(ProcessValueRead::Cwd)),
        (ObsSource::Config, Some(ProcessValueRead::Cwd)),
    ] {
        let mut w = World::new();
        w.elf("/scan/app", ElfType::Exec, &["lib.so"], &[], &[""]);
        w.elf("/scan/work/lib.so", ElfType::Dyn, &[], &[], &[]);
        w.process(10, "/scan/app", Some(7));
        w.value(
            10,
            ValueKey::Cwd,
            TriValue::Known("/scan/work".into()),
            ProcessValueRead::Cwd,
        );
        w.value(
            10,
            ValueKey::Cwd,
            TriValue::Known("/scan/work".into()),
            ProcessValueRead::Cwd,
        );
        w.values[1].origin = ValueOrigin::ObservedProcess {
            process: pref(10),
            source,
            read,
        };
        let a = w.run();
        assert!(
            edges(&a, "/scan/app", "lib.so", SearchRule::Runpath).is_empty(),
            "duplicate {source:?}/{read:?}"
        );
        assert!(gaps(&a, "/scan/app").contains(&"dependency value: ambiguous observed inputs"));
    }
}

#[test]
fn observed_unused_cwd_ambiguity_preserves_absolute_runpath_candidates() {
    let mut w = World::new();
    w.elf(
        "/scan/app",
        ElfType::Exec,
        &["lib.so"],
        &[],
        &["/scan/work"],
    );
    w.elf("/scan/work/lib.so", ElfType::Dyn, &[], &[], &[]);
    w.process(10, "/scan/app", Some(7));
    w.value(
        10,
        ValueKey::Cwd,
        TriValue::Known("/scan/work".into()),
        ProcessValueRead::Cwd,
    );
    w.value(
        10,
        ValueKey::Cwd,
        TriValue::Known("/scan/other".into()),
        ProcessValueRead::Cwd,
    );
    let a = w.run();
    let e = edges(&a, "/scan/app", "lib.so", SearchRule::Runpath);
    assert_eq!(e.len(), 2);
    assert!(e
        .iter()
        .any(|(_, c)| c.process == Some(pref(10)) && c.values.is_empty()));
    assert!(!gaps(&a, "/scan/app").contains(&"dependency value: ambiguous observed inputs"));
}

#[test]
fn observed_ambiguity_is_isolated_from_other_process_keys_and_nonobserved_rows() {
    for mutation in 0..5 {
        let mut w = World::new();
        w.elf("/scan/app", ElfType::Exec, &["lib.so"], &[], &[]);
        w.elf("/scan/work/lib.so", ElfType::Dyn, &[], &[], &[]);
        w.process(10, "/scan/app", Some(7));
        let key = ValueKey::Env("LD_LIBRARY_PATH".into());
        let used = w.value(
            10,
            key.clone(),
            TriValue::Known("/scan/work".into()),
            ProcessValueRead::InitialEnvironment,
        );
        w.value(
            10,
            key,
            TriValue::Known("/scan/other".into()),
            ProcessValueRead::InitialEnvironment,
        );
        match mutation {
            0 => {
                w.values[1].origin = ValueOrigin::Configured {
                    file: ConfigRef {
                        file: id("/scan/app"),
                        key: "Environment".into(),
                        line: 9,
                    },
                    directive: "Environment".into(),
                }
            }
            1 => {
                w.values[1].origin = ValueOrigin::PredictedLaunch {
                    rules: vec!["unverified-unit".into()],
                    from: vec![],
                }
            }
            2 | 3 => {
                let ValueOrigin::ObservedProcess { process, .. } = &mut w.values[1].origin else {
                    panic!("observed fixture")
                };
                if mutation == 2 {
                    process.start_ticks += 1;
                } else {
                    process.boot_id = "other-boot".into();
                }
            }
            4 => w.values[1].key = ValueKey::Cwd,
            _ => unreachable!(),
        }
        let a = w.with(
            DepsOptions {
                observe_env: true,
                observer_mnt_ns: Some(7),
            },
            DepsBudgets::default(),
        );
        let e = edges(&a, "/scan/app", "lib.so", SearchRule::LdLibraryPath);
        assert_eq!(e.len(), 1, "mutation {mutation}");
        assert_eq!(e[0].1.values, vec![used]);
        assert!(!gaps(&a, "/scan/app").contains(&"dependency value: ambiguous observed inputs"));
    }
}
