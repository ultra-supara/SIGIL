//! Session builders for the tests and the golden examples under `schemas/examples/session-v1/`.
//!
//! Every session here is a **specification example, not a SIGIL measurement**: `tool.version`
//! is `0.0.0-example`, hashes are synthetic (except the loader-slice example, which reuses the
//! plan's §5.8 values), and nothing was observed on a real system.

#![allow(dead_code)]

use std::collections::BTreeMap;

use sigil_model::*;

pub const EXAMPLE_VERSION: &str = "0.0.0-example";
/// The libggml hash the plan's §5.8 example uses (official Ollama v0.30.6, from PR-0).
pub const R1_GGML_HEX: &str = "40e1f9070eee43ad95a8f3151b691368ac64db9f826fc5796d5ba84836a1305f";

pub const ROLE: &str = "llama-server (per model)";
pub const PROFILE: &str = "ggml.backend-loader@2";

pub fn errors(s: &Session) -> Vec<ValidationError> {
    s.validate().err().unwrap_or_default()
}

pub fn render(errors: &[ValidationError]) -> String {
    errors.iter().map(|e| format!("  - {e}\n")).collect()
}

pub fn assert_valid(s: &Session) {
    if let Err(errors) = s.validate() {
        panic!("expected a valid session, got:\n{}", render(&errors));
    }
}

pub fn assert_rejected(s: &Session, matches: impl Fn(&ValidationError) -> bool, what: &str) {
    let errors = errors(s);
    assert!(
        errors.iter().any(matches),
        "expected {what}, got:\n{}",
        render(&errors)
    );
}

/// The placement, artifact, and first slice of the instance `inst`.
pub fn placed(s: &Session, inst: &str) -> Placed {
    let instance = s.instances.iter().find(|i| i.id.as_str() == inst).unwrap();
    let InstanceContent::Read { artifact } = &instance.content else {
        panic!("{inst} was not read");
    };
    let slice = s
        .artifacts
        .iter()
        .find(|a| a.id == *artifact)
        .unwrap()
        .slices[0]
        .id
        .clone();
    Placed {
        artifact: artifact.clone(),
        slice,
        inst: instance.id.clone(),
    }
}

pub const GGML: &str = "inst:lib/ollama/libggml.so.0.13.1";

pub fn id<T: TryFrom<String, Error = IdError>>(value: &str) -> T {
    T::try_from(value.to_string()).unwrap_or_else(|e| panic!("{e}"))
}

pub fn t(text: &str) -> UntrustedText {
    UntrustedText::new(text)
}

pub fn hex(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

pub fn ts(value: &str) -> Timestamp {
    id(value)
}

pub fn ids<T: TryFrom<String, Error = IdError>>(values: &[&str]) -> Vec<T> {
    values.iter().map(|v| id(v)).collect()
}

/// A minimal valid static-mode session: one scan root, the given required checks (no coverage
/// yet), PASS + COMPLETE.
pub fn base(required: &[&str]) -> Session {
    Session {
        schema: SchemaVersion::SessionV1,
        tool: ToolInfo {
            name: "sigil".to_string(),
            version: EXAMPLE_VERSION.to_string(),
            git_rev: None,
        },
        knowledge: vec![KnowledgeRef {
            kind: KnowledgeKind::Policy,
            id: "default".to_string(),
            version: "1".to_string(),
            sha256: id(&hex(0xa3)),
        }],
        request: RunRequest {
            mode: Mode::Static,
            roots: vec![ScanRoot {
                id: id("install"),
                path: t("/usr/local"),
            }],
            audit: ids(&["backend_loader"]),
            required_checks: ids(required),
            budgets: BTreeMap::from([("files".to_string(), 4096)]),
            observe_env: false,
            model_filter: None,
        },
        observation: ObservationMeta {
            started_at: ts("2026-10-07T07:00:00Z"),
            finished_at: ts("2026-10-07T07:00:02Z"),
            uid: 1000,
            gid: 1000,
            capabilities: vec![],
            boot_id: "00000000-0000-4000-8000-000000000000".to_string(),
            kernel: "6.8.0".to_string(),
            net_ns: None,
            mnt_ns: None,
        },
        artifacts: vec![],
        instances: vec![],
        models: vec![],
        processes: vec![],
        values: vec![],
        components: vec![],
        releases: vec![],
        hints: vec![],
        code: vec![],
        relations: vec![],
        rule_support: vec![],
        bindings: vec![],
        loads: vec![],
        access: vec![],
        assumptions: vec![],
        coverage: vec![],
        findings: vec![],
        open_questions: vec![],
        policy_violations: vec![],
        outcome: Outcome {
            verdict: Verdict::Pass,
            completeness: Completeness::Complete,
            confirmed_failures: 0,
            confirmed_warnings: 0,
            policy_time: ts("2026-10-07T07:00:00Z"),
        },
    }
}

/// A binary placed under the install root.
pub struct Placed {
    pub artifact: ArtifactId,
    pub slice: SliceId,
    pub inst: InstanceId,
}

pub fn add_binary(s: &mut Session, sha_hex: &str, rel_path: &str, arch: Arch, ino: u64) -> Placed {
    let artifact: ArtifactId = id(&format!("sha256:{sha_hex}"));
    let slice = SliceId::from_parts(&artifact, arch, 0);
    let inst: InstanceId = id(&format!("inst:{rel_path}"));
    s.artifacts.push(Artifact {
        id: artifact.clone(),
        size: 1_048_576,
        format: Format::Elf { kind: ElfType::Dyn },
        slices: vec![Slice {
            id: slice.clone(),
            arch,
            offset: 0,
            size: 1_048_576,
            sha256: id(sha_hex),
        }],
    });
    s.instances.push(instance(
        &inst,
        "install",
        &format!("/usr/local/{rel_path}"),
        &artifact,
        ino,
    ));
    Placed {
        artifact,
        slice,
        inst,
    }
}

pub fn instance(
    inst: &InstanceId,
    root: &str,
    path: &str,
    artifact: &ArtifactId,
    ino: u64,
) -> FileInstance {
    FileInstance {
        id: inst.clone(),
        root: id(root),
        path: t(path),
        link_chain: vec![],
        resolved: None,
        content: InstanceContent::Read {
            artifact: artifact.clone(),
        },
        stat: StatInfo {
            dev: 2049,
            ino,
            mode: 0o100644,
            uid: 0,
            gid: 0,
            size: 1_048_576,
            mtime_ns: 1_791_331_200_000_000_000,
            nlink: 1,
        },
        stability: Stability::NoChangeDetected,
        discovered_by: vec![DiscoverySource::Walk],
    }
}

pub fn add_knowledge(s: &mut Session, kind: KnowledgeKind, kid: &str, version: &str, byte: u8) {
    s.knowledge.push(KnowledgeRef {
        kind,
        id: kid.to_string(),
        version: version.to_string(),
        sha256: id(&hex(byte)),
    });
}

pub fn add_profile_knowledge(s: &mut Session) {
    add_knowledge(s, KnowledgeKind::Profile, "ggml.backend-loader", "2", 0xa2);
}

/// libggml at `lib/ollama/libggml.so.0.13.1`, reference-matched against the official manifest.
pub fn add_ggml(s: &mut Session, sha_hex: &str) -> Placed {
    let g = add_binary(
        s,
        sha_hex,
        "lib/ollama/libggml.so.0.13.1",
        Arch::X86_64,
        1001,
    );
    add_knowledge(
        s,
        KnowledgeKind::ReferenceManifest,
        "ollama-official",
        "2026-10-07",
        0xa1,
    );
    s.components.push(ComponentClaim {
        subject: g.slice.clone(),
        component: id("ggml"),
        assertions: vec![
            IdentityAssertion::SelfName {
                kind: NameKind::Filename,
                value: t("libggml.so.0.13.1"),
                at: EvidenceRef::Instance {
                    instance: g.inst.clone(),
                },
            },
            IdentityAssertion::KnownHash {
                reference: id("ollama-official"),
                release: "v0.30.6".to_string(),
                member: "lib/ollama/libggml.so.0.13.1".to_string(),
                matched: true,
            },
            IdentityAssertion::Signature {
                state: SigState::NotChecked,
            },
        ],
        status: IdentityStatus::ReferenceMatched,
        versions: vec![VersionAssertion {
            value: t("0.13.1"),
            source: VersionSource::SelfName {
                kind: NameKind::Filename,
            },
            at: EvidenceRef::Instance {
                instance: g.inst.clone(),
            },
        }],
    });
    g
}

pub fn coverage(check: &str, scope: Ref, state: CoverageState) -> Coverage {
    Coverage {
        check: id(check),
        scope,
        state,
        budget: None,
    }
}

pub fn complete(check: &str) -> Coverage {
    coverage(check, Ref::Audit, CoverageState::Complete)
}

fn loc_fn(f: &str) -> Loc {
    Loc::Function(id(f))
}

fn loc_cs(c: &str) -> Loc {
    Loc::CallSite(id(c))
}

fn call(cid: &str, caller: &str, addr: u64, target: CallTarget, args: Vec<ArgValue>) -> CallSite {
    CallSite {
        id: id(cid),
        caller: id(caller),
        addr,
        kind: CallKind::Call,
        target,
        args,
    }
}

fn import(symbol: &str) -> CallTarget {
    CallTarget::Import {
        symbol: t(symbol),
        via: ImportVia::Plt,
    }
}

fn own_plt(symbol: &str, entry: u64) -> CallTarget {
    CallTarget::OwnExportViaPlt {
        symbol: t(symbol),
        entry,
    }
}

fn ret(reg: Reg, c: &str) -> ArgValue {
    ArgValue::ReturnOf { reg, call: id(c) }
}

pub const DL_LOAD_LIBRARY: &str = "_Z15dl_load_libraryRKNSt10filesystem7__cxx114pathE";

/// Code facts, the profile match, and the per-rule support of the loader in `g`, as the M1
/// analyzer would record them when every obligation passes (addresses from plan §0.5/§5.8).
pub fn add_loader_code(s: &mut Session, g: &Placed) {
    add_profile_knowledge(s);
    let backend_names = ["blas", "cuda", "cpu"];
    let mut call_sites = vec![];
    for (i, name) in backend_names.iter().enumerate() {
        let addr = 0xecbe + 0x10 * i as u64;
        call_sites.push(call(
            &format!("cs:{addr:#x}"),
            "fn:0xecb0",
            addr,
            CallTarget::Internal {
                entry: 0xc590,
                export_name: None,
            },
            vec![
                ArgValue::ConstStr {
                    reg: Reg::Rdi,
                    addr: 0x2a010 + 8 * i as u64,
                    value: t(name),
                },
                ArgValue::Param {
                    reg: Reg::Rsi,
                    index: 0,
                },
            ],
        ));
    }
    call_sites.extend([
        call(
            "cs:0xd303",
            "fn:0xc590",
            0xd303,
            import("_ZNKSt10filesystem7__cxx1118directory_iteratordeEv"),
            vec![],
        ),
        call(
            "cs:0xd5a0",
            "fn:0xc590",
            0xd5a0,
            import("_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4findEPKcmm"),
            vec![],
        ),
        call(
            "cs:0xd640",
            "fn:0xc590",
            0xd640,
            import("_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareEPKc"),
            vec![],
        ),
        call(
            "cs:0xe26d",
            "fn:0xc590",
            0xe26d,
            own_plt(DL_LOAD_LIBRARY, 0xb790),
            vec![ArgValue::Unknown {
                reg: Reg::Rdi,
                reason: ValueUnknown::FromMemory,
            }],
        ),
        call(
            "cs:0xe29a",
            "fn:0xc590",
            0xe29a,
            own_plt("_Z10dl_get_symPvPKc", 0xb7f0),
            vec![
                ret(Reg::Rdi, "cs:0xe26d"),
                ArgValue::ConstStr {
                    reg: Reg::Rsi,
                    addr: 0x2a200,
                    value: t("ggml_backend_score"),
                },
            ],
        ),
        call(
            "cs:0xe2b1",
            "fn:0xc590",
            0xe2b1,
            CallTarget::Indirect {
                value: ret(Reg::Rax, "cs:0xe29a"),
            },
            vec![],
        ),
        call(
            "cs:0xe2ce",
            "fn:0xc590",
            0xe2ce,
            import("dlclose"),
            vec![ArgValue::Unknown {
                reg: Reg::Rdi,
                reason: ValueUnknown::FromMemory,
            }],
        ),
    ]);
    let profile: ProfileRef = id(PROFILE);
    s.code.push(CodeFacts {
        slice: g.slice.clone(),
        functions: vec![
            Function {
                id: id("fn:0xc590"),
                entry: 0xc590,
                end: 0xe400,
                bounds: BoundsSource::EhFrameFde,
                names: vec![],
            },
            Function {
                id: id("fn:0xecb0"),
                entry: 0xecb0,
                end: 0xedc0,
                bounds: BoundsSource::EhFrameFde,
                names: vec![t("ggml_backend_load_all_from_path")],
            },
        ],
        call_sites,
        predicate_checks: vec![PredicateCheck {
            function: id("fn:0xc590"),
            iteration_calls: ids(&["cs:0xd303"]),
            target_calls: ids(&["cs:0xe26d"]),
            atoms: vec![
                Atom {
                    name: id("T"),
                    value: ArgValue::Load {
                        reg: Reg::Rax,
                        base: Box::new(ret(Reg::Rax, "cs:0xd303")),
                        offset: 0x28,
                        width: 1,
                        site: 0xd31a,
                    },
                },
                Atom {
                    name: id("F"),
                    value: ret(Reg::Rax, "cs:0xd5a0"),
                },
                Atom {
                    name: id("C"),
                    value: ret(Reg::Rax, "cs:0xd640"),
                },
            ],
            expect: ObligationRef {
                profile: profile.clone(),
                obligation: id("filter.reach_predicate"),
            },
            assignments: 162,
            result: CheckResult::Match,
        }],
        close_checks: vec![CloseCheck {
            function: id("fn:0xc590"),
            open_calls: ids(&["cs:0xe26d"]),
            close_calls: ids(&["cs:0xe2ce"]),
            iteration_calls: ids(&["cs:0xd303"]),
            result: CheckResult::Match,
        }],
        guard_regions: vec![],
        param_mappings: vec![ParamMapping {
            function: id("fn:0xecb0"),
            source: SourceParamRef {
                function: "ggml_backend_load_all_from_path".to_string(),
                index: 0,
                name: "dir_path".to_string(),
            },
            binary: BinaryParam::Reg(Reg::Rdi),
            evidence: vec![EvidenceRef::Code {
                slice: g.slice.clone(),
                loc: loc_cs("cs:0xecbe"),
            }],
        }],
    });
    let pass = |oid: &str, at: Vec<Loc>| ObligationResult {
        id: id(oid),
        result: ObligationState::Pass,
        at,
    };
    s.relations.push(Relation::ProfileMatch {
        profile: profile.clone(),
        slice: g.slice.clone(),
        obligations: vec![
            pass(
                "entry.name_sequence",
                vec![
                    loc_fn("fn:0xecb0"),
                    loc_cs("cs:0xecbe"),
                    loc_cs("cs:0xecce"),
                    loc_cs("cs:0xecde"),
                ],
            ),
            pass(
                "filter.reach_predicate",
                vec![
                    loc_fn("fn:0xc590"),
                    loc_cs("cs:0xd303"),
                    loc_cs("cs:0xe26d"),
                ],
            ),
            pass(
                "evaluate.score_call",
                vec![loc_cs("cs:0xe29a"), loc_cs("cs:0xe2b1")],
            ),
            pass(
                "evaluate.close_reached",
                vec![loc_cs("cs:0xe26d"), loc_cs("cs:0xe2ce")],
            ),
        ],
    });
    let support = |rule: &str, obligations: &[&str]| RuleSupport {
        profile: profile.clone(),
        rule: id(rule),
        slice: g.slice.clone(),
        support: Support::TargetVerified {
            obligations: ids(obligations),
        },
    };
    s.rule_support.extend([
        support("entry", &["entry.name_sequence"]),
        support("filter", &["filter.reach_predicate"]),
        support(
            "evaluate",
            &["evaluate.score_call", "evaluate.close_reached"],
        ),
    ]);
}

/// The unit file, the configured user, and the predicted user of the per-model `llama-server`.
pub fn add_runtime_user(s: &mut Session) -> ValueId {
    s.request.roots.push(ScanRoot {
        id: id("config"),
        path: t("/etc/systemd/system"),
    });
    let unit_artifact: ArtifactId = id(&format!("sha256:{}", hex(0x55)));
    s.artifacts.push(Artifact {
        id: unit_artifact.clone(),
        size: 512,
        format: Format::Other,
        slices: vec![],
    });
    let unit: InstanceId = id("inst:ollama.service");
    let mut unit_instance = instance(
        &unit,
        "config",
        "/etc/systemd/system/ollama.service",
        &unit_artifact,
        2001,
    );
    unit_instance.stat.size = 512;
    s.instances.push(unit_instance);
    let configured: ValueId = id("val:ollama serve/user/configured");
    let predicted: ValueId = id("val:llama-server (per model)/user/predicted");
    s.values.extend([
        ProcessValue {
            id: configured.clone(),
            process_role: id("ollama serve"),
            key: ValueKey::User,
            value: TriValue::Known(t("ollama")),
            origin: ValueOrigin::Configured {
                file: ConfigRef {
                    file: unit,
                    key: t("User"),
                    line: 7,
                },
                directive: t("User="),
            },
            applies_to: vec![],
        },
        ProcessValue {
            id: predicted.clone(),
            process_role: id(ROLE),
            key: ValueKey::User,
            value: TriValue::Known(t("ollama")),
            origin: ValueOrigin::PredictedLaunch {
                rules: vec![
                    "systemd.User".to_string(),
                    "topology.user_inherited".to_string(),
                ],
                from: vec![configured],
            },
            applies_to: vec![],
        },
    ]);
    predicted
}

/// A world-writable library directory: anyone can replace `libggml.so.0.13.1`.
pub fn add_world_writable_libdir(s: &mut Session, runtime: &ValueId) -> AccessId {
    let access: AccessId = id("access:lib/ollama");
    let node = |path: &str, mode: u32| NodeAccess {
        path: t(path),
        uid: 0,
        gid: 0,
        mode,
        sticky: false,
        is_symlink: false,
        acl: AclState::Absent,
        read_only_mount: TriState::No,
    };
    s.access.push(WriteAccess {
        id: access.clone(),
        target: t("/usr/local/lib/ollama"),
        runtime: PrincipalClaim::Value {
            value: runtime.clone(),
        },
        chain: vec![
            node("/usr/local/lib/ollama", 0o40777),
            node("/usr/local/lib", 0o40755),
            node("/usr/local", 0o40755),
            node("/usr", 0o40755),
            node("/", 0o40755),
        ],
        capabilities: vec![CapabilityAccess {
            capability: replace_libggml(),
            conclusion: anyone_via_libdir(),
        }],
    });
    access
}

pub fn replace_libggml() -> WriteCapability {
    WriteCapability::ReplaceEntry {
        dir: t("/usr/local/lib/ollama"),
        entry: t("libggml.so.0.13.1"),
    }
}

pub fn anyone_via_libdir() -> AccessConclusion {
    AccessConclusion::UntrustedHolder {
        who: Principal::Anyone,
        via: t("/usr/local/lib/ollama"),
        how: Grant::ModeOther,
    }
}

/// The support of a loader-profile rule on the loader slice.
pub fn loader_rule(g: &Placed, rule: &str) -> RuleSupportRef {
    RuleSupportRef {
        profile: id(PROFILE),
        rule: id(rule),
        slice: g.slice.clone(),
    }
}

/// Whether the per-model `llama-server` binds the loader's `dlopen` call to the analyzed libggml.
pub fn binding_of_loader(g: &Placed) -> CondEvidence {
    CondEvidence::Binding {
        process_role: id(ROLE),
        site: CallRef {
            slice: g.slice.clone(),
            call: id("cs:0xe26d"),
        },
        definer: g.inst.clone(),
    }
}

pub fn runtime_user_known() -> CondEvidence {
    CondEvidence::Value {
        value: id("val:llama-server (per model)/user/predicted"),
        needs: ValueNeed::Known,
    }
}

pub fn met(cid: &str, evidence: CondEvidence) -> Condition {
    Condition {
        id: id(cid),
        state: CondState::Met { evidence },
        unresolved: vec![],
    }
}

pub fn decision(action: Action, source: &str) -> PolicyDecision {
    PolicyDecision {
        action,
        source: id(source),
        reason: None,
        expires: None,
    }
}

/// Confirmed finding: anyone can replace the loader library that the per-model `llama-server`
/// binds to. Every condition is `Met` with sufficient evidence.
pub fn replaceable_library_finding(g: &Placed, access: &AccessId, runtime: &ValueId) -> Finding {
    Finding {
        id: id("finding:loader.candidate_or_library_replaceable@lib/ollama/libggml.so.0.13.1"),
        rule: id("loader.candidate_or_library_replaceable"),
        kind: FindingKind::Loader,
        subject: Ref::Instance(g.inst.clone()),
        summary: "Anyone can replace libggml.so.0.13.1, which the per-model llama-server binds to (specification example)".to_string(),
        conditions: vec![
            met("rule_supported:evaluate", CondEvidence::Behavior(loader_rule(g, "evaluate"))),
            met(
                "untrusted_write:library",
                CondEvidence::Access { access: access.clone(), capability: replace_libggml() },
            ),
            met("runtime_principal_known", CondEvidence::Value { value: runtime.clone(), needs: ValueNeed::Known }),
            met(&format!("binding:{ROLE}"), binding_of_loader(g)),
        ],
        evidence: vec![
            EvidenceRef::Instance { instance: g.inst.clone() },
            EvidenceRef::Access { access: access.clone() },
            EvidenceRef::Value { value: runtime.clone() },
            EvidenceRef::Code { slice: g.slice.clone(), loc: loc_cs("cs:0xe26d") },
        ],
        limits: vec!["ACLs were evaluated only where readable".to_string()],
        default_severity: Severity::Fail,
        decision: decision(Action::Fail, "default:loader.candidate_or_library_replaceable"),
    }
}

pub fn add_binding(s: &mut Session, g: &Placed, state: BindingState) {
    s.bindings.push(BindingPremise {
        process_role: id(ROLE),
        site: CallRef {
            slice: g.slice.clone(),
            call: id("cs:0xe26d"),
        },
        symbol: t(DL_LOAD_LIBRARY),
        analyzed_definer: g.inst.clone(),
        state,
    });
}

fn pass_complete(s: &mut Session) {
    for check in s.request.required_checks.clone() {
        s.coverage.push(coverage(
            check.as_str(),
            Ref::Audit,
            CoverageState::Complete,
        ));
    }
}

// ---------------------------------------------------------------------------------------------
// The examples (brief §25 items 1–12, plus the loader-slice specification example).
// ---------------------------------------------------------------------------------------------

/// Example 1: Nothing found and every required check closed.
pub fn complete_pass() -> Session {
    let mut s = base(&["artifacts.discovery", "loader.identify"]);
    add_ggml(&mut s, &hex(0x11));
    pass_complete(&mut s);
    s
}

/// Example 2: A confirmed FAIL with every required check closed.
pub fn complete_fail() -> Session {
    let mut s = base(&["artifacts.discovery", "loader.identify"]);
    let g = add_ggml(&mut s, &hex(0x11));
    add_loader_code(&mut s, &g);
    add_binding(
        &mut s,
        &g,
        BindingState::Verified {
            scope: vec![g.inst.clone()],
        },
    );
    let runtime = add_runtime_user(&mut s);
    let access = add_world_writable_libdir(&mut s, &runtime);
    s.findings
        .push(replaceable_library_finding(&g, &access, &runtime));
    pass_complete(&mut s);
    s.outcome.verdict = Verdict::Fail;
    s.outcome.confirmed_failures = 1;
    s
}

/// Example 3: No violation confirmed, but a required check is not closed.
pub fn incomplete_pass() -> Session {
    let mut s = base(&[
        "artifacts.discovery",
        "loader.identify",
        "loader.search_paths",
    ]);
    add_ggml(&mut s, &hex(0x11));
    s.coverage.extend([
        complete("artifacts.discovery"),
        complete("loader.identify"),
        coverage(
            "loader.search_paths",
            Ref::Role(id(ROLE)),
            CoverageState::Partial {
                missing: vec![format!("cwd of {ROLE}")],
            },
        ),
    ]);
    s.outcome.completeness = Completeness::Incomplete {
        missing_required: ids(&["loader.search_paths"]),
        gaps: vec![],
    };
    s
}

/// Example 4: A confirmed FAIL (resting on a TargetVerified behavior) and an unrelated required check that
/// could not run: FAIL and INCOMPLETE.
pub fn fail_incomplete() -> Session {
    let mut s = complete_fail();
    s.request.required_checks.push(id("exposure.binds"));
    s.coverage.push(coverage(
        "exposure.binds",
        Ref::Audit,
        CoverageState::Skipped {
            by: SkipReason::ModeDisabled,
        },
    ));
    s.outcome.completeness = Completeness::Incomplete {
        missing_required: ids(&["exposure.binds"]),
        gaps: vec![],
    };
    s
}

/// Example 5: A requested check on an architecture SIGIL does not analyze: unsupported, so incomplete.
pub fn unsupported_check() -> Session {
    let mut s = base(&["artifacts.discovery", "loader.identify"]);
    let arm = add_binary(
        &mut s,
        &hex(0x44),
        "lib/ollama/libggml-base.so",
        Arch::Aarch64,
        1004,
    );
    s.coverage.extend([
        complete("artifacts.discovery"),
        coverage(
            "loader.identify",
            Ref::Slice(arm.slice),
            CoverageState::Unsupported {
                what: "aarch64 code analysis (M3)".to_string(),
            },
        ),
    ]);
    s.outcome.completeness = Completeness::Incomplete {
        missing_required: ids(&["loader.identify"]),
        gaps: vec![],
    };
    s
}

/// Example 6: A budget hit: the analysis is truncated, not "nothing found".
pub fn budget_exceeded() -> Session {
    let mut s = base(&["artifacts.discovery", "identity.strings"]);
    let g = add_ggml(&mut s, &hex(0x11));
    let limit = 64 * 1024 * 1024;
    s.coverage.extend([
        complete("artifacts.discovery"),
        Coverage {
            check: id("identity.strings"),
            scope: Ref::Artifact(g.artifact),
            state: CoverageState::BudgetExceeded {
                budget: "string_scan_bytes".to_string(),
                used: limit,
                limit,
            },
            budget: Some(BudgetUse {
                budget: "string_scan_bytes".to_string(),
                used: limit,
                limit,
            }),
        },
    ]);
    s.outcome.completeness = Completeness::Incomplete {
        missing_required: ids(&["identity.strings"]),
        gaps: vec![],
    };
    s
}

/// The open question of plan §5.5: loader behavior and the runtime principal are established,
/// the effective cwd is not, and the filter operands are a reference-only premise.
pub fn cwd_open_question(g: &Placed) -> OpenQuestion {
    OpenQuestion {
        id: id(&format!("oq:loader.search_path_untrusted_creator@cwd/{ROLE}")),
        rule: id("loader.search_path_untrusted_creator"),
        subject: Ref::SearchPath { role: id(ROLE), search_path: "cwd".to_string() },
        conditions: vec![
            met("rule_supported:evaluate", CondEvidence::Behavior(loader_rule(g, "evaluate"))),
            met("runtime_principal_known", runtime_user_known()),
            Condition {
                id: id("value:cwd"),
                state: CondState::Unknown {
                    reason: UnknownReason::NotModeled {
                        what: "the unit sets no WorkingDirectory=; the systemd default is assumption A-3, not accepted by the policy".to_string(),
                    },
                    evidence: None,
                },
                unresolved: vec![],
            },
            Condition {
                id: id("premise:candidate.operands"),
                state: CondState::Unknown { reason: UnknownReason::PremiseUnresolved, evidence: None },
                unresolved: ids(&["candidate.operands"]),
            },
        ],
        evidence: vec![EvidenceRef::Value { value: id("val:llama-server (per model)/user/predicted") }],
        decision: OpenQuestionDecision { treatment: OqTreatment::CountAsGap, source: id("policy:open_questions.default"), reason: None },
    }
}

/// Example 7: An open question: some conditions met, one unknown; no finding is fabricated.
pub fn open_question() -> Session {
    let mut s = base(&["artifacts.discovery", "loader.identify"]);
    let g = add_ggml(&mut s, &hex(0x11));
    add_loader_code(&mut s, &g);
    add_runtime_user(&mut s);
    s.assumptions.push(Assumption {
        id: id("A-3"),
        statement: "A unit without WorkingDirectory= runs with cwd \"/\" (systemd default)"
            .to_string(),
        acceptance: AssumptionAcceptance::NotAccepted,
    });
    let oq = cwd_open_question(&g);
    let oq_id = oq.id.clone();
    s.open_questions.push(oq);
    pass_complete(&mut s);
    s.outcome.completeness = Completeness::Incomplete {
        missing_required: vec![],
        gaps: vec![oq_id],
    };
    s
}

/// Example 8: A profile mismatch: something loader-like is there, but an obligation fails. A gap, not a pass.
pub fn profile_mismatch() -> Session {
    let mut s = base(&["artifacts.discovery", "loader.identify"]);
    add_profile_knowledge(&mut s);
    let m = add_binary(
        &mut s,
        &hex(0x66),
        "lib/ollama/libggml.so",
        Arch::X86_64,
        1006,
    );
    s.components.push(ComponentClaim {
        subject: m.slice.clone(),
        component: id("ggml"),
        assertions: vec![IdentityAssertion::SelfName {
            kind: NameKind::Filename,
            value: t("libggml.so"),
            at: EvidenceRef::Instance {
                instance: m.inst.clone(),
            },
        }],
        status: IdentityStatus::NameOnly,
        versions: vec![],
    });
    s.relations.push(Relation::ProfileMatch {
        profile: id(PROFILE),
        slice: m.slice.clone(),
        obligations: vec![
            ObligationResult {
                id: id("entry.name_sequence"),
                result: ObligationState::Pass,
                at: vec![Loc::VAddr(0xecb0)],
            },
            ObligationResult {
                id: id("filter.reach_predicate"),
                result: ObligationState::Fail,
                at: vec![Loc::VAddr(0xd4c0)],
            },
        ],
    });
    s.coverage.extend([
        complete("artifacts.discovery"),
        coverage(
            "loader.identify",
            Ref::Slice(m.slice),
            CoverageState::ProfileMismatch {
                profile: id(PROFILE),
                failed: ids(&["filter.reach_predicate"]),
            },
        ),
    ]);
    s.outcome.completeness = Completeness::Incomplete {
        missing_required: ids(&["loader.identify"]),
        gaps: vec![],
    };
    s
}

/// A backend candidate. The loader's filter and evaluate rules are verified in its code, but the
/// facts about this file and role rest on unresolved premises (the filter operands, the role's
/// binding), and the `select` rule only feature-matches.
pub fn add_feature_match_candidate(s: &mut Session, g: &Placed, zen4_hex: &str) -> Placed {
    let zen4 = add_binary(
        s,
        zen4_hex,
        "lib/ollama/libggml-cpu-zen4.so",
        Arch::X86_64,
        1002,
    );
    let profile: ProfileRef = id(PROFILE);
    let binding = format!("binding:{ROLE}");
    s.rule_support.push(RuleSupport {
        profile,
        rule: id("select"),
        slice: g.slice.clone(),
        support: Support::FeatureMatch {
            matched: vec![],
            unverified: ids(&["select"]),
        },
    });
    s.loads.push(LoadFacts {
        instance: zen4.inst.clone(),
        context: LoadContext {
            process_role: id(ROLE),
            rule: "ggml.backend-loader/load_best(cpu)".to_string(),
        },
        present: true,
        candidate: Tri::Yes {
            why: CandidateWhy {
                search_path: "exe_dir".to_string(),
                filter: "libggml-cpu-*.so".to_string(),
            },
            basis: Basis::Modeled(loader_rule(g, "filter")),
            unresolved: ids(&["candidate.operands"]),
        },
        would_evaluate: Tri::Yes {
            why: EffectWhy {
                phase: LoaderPhase::Evaluate,
            },
            basis: Basis::Modeled(loader_rule(g, "evaluate")),
            unresolved: ids(&["candidate.operands", &binding]),
        },
        selectable: Tri::Unknown {
            reason: UnknownReason::RunTimeDependent {
                what: "the score depends on run-time CPU features".to_string(),
            },
        },
        mapped: vec![],
        mapping_observability: Observability::NotObservable(NotObservable::ModeDisabled),
        used_for_inference: Tri::Unknown {
            reason: UnknownReason::RequiresActive {
                what: "tracing inference calls".to_string(),
            },
        },
    });
    zen4
}

/// Observe mode: the per-model `llama-server` has the zen4 backend mapped, and its load facts list
/// that observation. Mapped is not "used for inference".
pub fn add_observed_zen4_mapping(s: &mut Session) {
    s.request.mode = Mode::Observe;
    let process = ProcessRef {
        pid: 4242,
        start_ticks: 987_654,
        boot_id: "00000000-0000-4000-8000-000000000000".to_string(),
    };
    let zen4: InstanceId = id("inst:lib/ollama/libggml-cpu-zen4.so");
    let mapping = MappingObs {
        process: process.clone(),
        at: ts("2026-10-07T07:00:01Z"),
        dev: 2049,
        ino: 1002,
        path_text: t("/usr/local/lib/ollama/libggml-cpu-zen4.so"),
        deleted: false,
        instance: Some(zen4.clone()),
        same_mount_ns: Tri::Yes {
            why: (),
            basis: Basis::Observed {
                source: ObsSource::Proc,
            },
            unresolved: vec![],
        },
    };
    s.processes.push(ProcessObs {
        process,
        at: ts("2026-10-07T07:00:01Z"),
        roles: ids(&[ROLE]),
        exe: ProcessExe::Path {
            path: t("/usr/local/lib/ollama/llama-server"),
            deleted: false,
        },
        mappings: vec![mapping.clone()],
    });
    let load = s.loads.iter_mut().find(|l| l.instance == zen4).unwrap();
    load.mapped = vec![mapping];
    load.mapping_observability = Observability::Observed;
}

/// Example 9: A feature-match-only claim: it is recorded, and it cannot support a confirmed finding (the
/// rule yields an open question at most).
pub fn feature_match_only() -> Session {
    let mut s = base(&["artifacts.discovery", "loader.identify"]);
    let g = add_ggml(&mut s, &hex(0x11));
    add_loader_code(&mut s, &g);
    let zen4 = add_feature_match_candidate(&mut s, &g, &hex(0x22));
    add_binding(
        &mut s,
        &g,
        BindingState::Unknown {
            reason: UnknownReason::NotModeled {
                what: format!(
                    "LD_PRELOAD of {ROLE} is child-derived through an unsupported topology rule"
                ),
            },
        },
    );
    let oq = OpenQuestion {
        id: id(&format!(
            "oq:loader.search_path_untrusted_creator@exe_dir/{ROLE}"
        )),
        rule: id("loader.search_path_untrusted_creator"),
        subject: Ref::SearchPath {
            role: id(ROLE),
            search_path: "exe_dir".to_string(),
        },
        conditions: vec![
            Condition {
                id: id("candidate_evaluated"),
                state: CondState::Unknown {
                    reason: UnknownReason::InsufficientEvidence,
                    evidence: Some(CondEvidence::Load {
                        instance: zen4.inst.clone(),
                        context: LoadContext {
                            process_role: id(ROLE),
                            rule: "ggml.backend-loader/load_best(cpu)".to_string(),
                        },
                        fact: LoadFact::WouldEvaluate,
                    }),
                },
                unresolved: ids(&["candidate.operands", &format!("binding:{ROLE}")]),
            },
            Condition {
                id: id("rule_supported:select"),
                state: CondState::Unknown {
                    reason: UnknownReason::InsufficientEvidence,
                    evidence: Some(CondEvidence::Behavior(loader_rule(&g, "select"))),
                },
                unresolved: ids(&["select"]),
            },
        ],
        evidence: vec![EvidenceRef::Instance {
            instance: zen4.inst,
        }],
        decision: OpenQuestionDecision {
            treatment: OqTreatment::CountAsGap,
            source: id("policy:open_questions.default"),
            reason: None,
        },
    };
    let oq_id = oq.id.clone();
    s.open_questions.push(oq);
    pass_complete(&mut s);
    s.outcome.completeness = Completeness::Incomplete {
        missing_required: vec![],
        gaps: vec![oq_id],
    };
    s
}

/// Example 10: TargetVerified claims: every obligation decided `Pass` in the target's code, with code facts.
pub fn target_verified() -> Session {
    let mut s = base(&["artifacts.discovery", "loader.identify"]);
    let g = add_ggml(&mut s, &hex(0x11));
    add_loader_code(&mut s, &g);
    pass_complete(&mut s);
    s
}

/// Example 11: A ReferenceVerified claim: the hash equals a reference whose behavior ground truth verified.
pub fn reference_verified() -> Session {
    let mut s = base(&["artifacts.discovery", "loader.identify"]);
    add_profile_knowledge(&mut s);
    let g = add_ggml(&mut s, &hex(0x11));
    s.rule_support.push(RuleSupport {
        profile: id(PROFILE),
        rule: id("select"),
        slice: g.slice.clone(),
        support: Support::ReferenceVerified {
            reference: g.artifact.clone(),
            verification: id("groundtruth:ollama-0.30.6-loader#G-2"),
            rule: id("select"),
        },
    });
    pass_complete(&mut s);
    s
}

/// Example 12: Conflicting identity: a file name and an embedded value disagree on the version; both
/// stay, and the per-file hash still matches the official release.
pub fn conflicting_identity() -> Session {
    let mut s = base(&["artifacts.discovery", "loader.identify"]);
    let g = add_ggml(&mut s, &hex(0x11));
    let claim = &mut s.components[0];
    claim.assertions.push(IdentityAssertion::Embedded {
        field: "GGML_VERSION".to_string(),
        value: t("0.12.0"),
        at: EvidenceRef::Code {
            slice: g.slice.clone(),
            loc: Loc::Section {
                name: t(".rodata"),
                offset: 0x1f40,
            },
        },
        method: ExtractMethod::StringScan,
    });
    claim.versions.push(VersionAssertion {
        value: t("0.12.0"),
        source: VersionSource::Embedded {
            field: "GGML_VERSION".to_string(),
        },
        at: EvidenceRef::Code {
            slice: g.slice.clone(),
            loc: Loc::Section {
                name: t(".rodata"),
                offset: 0x1f40,
            },
        },
    });
    claim.status = IdentityStatus::Conflicting;
    s.releases.push(ReleaseClaim {
        product: id("ollama"),
        candidates: vec!["v0.30.6".to_string()],
        basis: ReleaseBasis::ReferenceMatches {
            reference: id("ollama-official"),
            files: vec![g.inst.clone()],
        },
    });
    pass_complete(&mut s);
    s
}

/// Example 13: The loader vertical slice of plan §5.8, corrected to the PR-2 types. Specification example
/// (the plan's values), not a SIGIL measurement.
pub fn loader_slice_spec_example() -> Session {
    let mut s = base(&[
        "artifacts.discovery",
        "loader.identify",
        "loader.search_paths",
    ]);
    let g = add_ggml(&mut s, R1_GGML_HEX);
    add_loader_code(&mut s, &g);
    add_runtime_user(&mut s);
    add_feature_match_candidate(&mut s, &g, &hex(0x22));
    add_binding(
        &mut s,
        &g,
        BindingState::Unknown {
            reason: UnknownReason::NotModeled {
                what: format!(
                    "LD_PRELOAD of {ROLE} is child-derived through an unsupported topology rule"
                ),
            },
        },
    );
    s.assumptions.push(Assumption {
        id: id("A-3"),
        statement: "A unit without WorkingDirectory= runs with cwd \"/\" (systemd default)"
            .to_string(),
        acceptance: AssumptionAcceptance::NotAccepted,
    });
    let oq = cwd_open_question(&g);
    let oq_id = oq.id.clone();
    s.open_questions.push(oq);
    pass_complete(&mut s);
    s.outcome.completeness = Completeness::Incomplete {
        missing_required: vec![],
        gaps: vec![oq_id],
    };
    s
}

/// Every golden example, by file stem.
pub fn examples() -> Vec<(&'static str, Session)> {
    vec![
        ("01-complete-pass", complete_pass()),
        ("02-complete-fail", complete_fail()),
        ("03-incomplete-pass", incomplete_pass()),
        ("04-fail-incomplete", fail_incomplete()),
        ("05-unsupported-check", unsupported_check()),
        ("06-budget-exceeded", budget_exceeded()),
        ("07-open-question", open_question()),
        ("08-profile-mismatch", profile_mismatch()),
        ("09-feature-match-only", feature_match_only()),
        ("10-target-verified", target_verified()),
        ("11-reference-verified", reference_verified()),
        ("12-conflicting-identity", conflicting_identity()),
        ("13-loader-slice-spec-example", loader_slice_spec_example()),
    ]
}
