//! Assembling sessions (plan §4.4.1). The CLI uses this from PR-3b.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use sigil_model::{
    ActiveFeature, ApiProbe, Artifact, CheckId, CodeFacts, Completeness, Coverage, CoverageState,
    Format, KnowledgeRef, Mode, ObservationMeta, Outcome, Ref, RootId, RunRequest, ScanRoot,
    SchemaVersion, Session, SkipReason, SliceId, Timestamp, ToolInfo, Unavailability,
    UntrustedText, Verdict, ARTIFACTS_CONTAINER, ARTIFACTS_DISCOVERY, ARTIFACTS_IDENTITY,
    ARTIFACTS_RELEASE, BINARY_BYTES, BINARY_CODE_BYTES, BINARY_SCAN_BYTES, INSTALL_ROOT,
};

use crate::analyze::binary::CodeCoverageError;
use crate::analyze::{
    binary, container, exposure, hints, identity, model_store, release, runtime_api,
};
use crate::code::CodeOutcome;
use crate::collect::fs::{recorded, FsBudgets, RootError, SafeFs};
use crate::collect::install::{self, InstallBudgets};
use crate::collect::named::{self, NamedBudgets};
use crate::collect::ollama_store::{self, StoreFacts, INVENTORY};
use crate::observe;
use crate::observe::proc::{ProcBudgets, ProcFacts};
use crate::policy::{evaluate, EvaluateError, Policy, ScopeInput};
use crate::reference;

/// What a static model-store inspection is asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreRequest {
    /// The model store: `manifests/` and `blobs/` below it.
    pub models_dir: PathBuf,
    /// Only the model with this display name (exact match).
    pub model_filter: Option<String>,
    pub budgets: FsBudgets,
    /// The largest manifest read, in bytes.
    pub manifest_limit: u64,
    /// The installation to inspect (`--install-dir`), if any.
    pub install: Option<InstallRequest>,
}

/// An installation to inspect: its files against the embedded reference set (PR-4a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallRequest {
    /// The install prefix: `bin/ollama` and `lib/ollama/` below it.
    pub dir: PathBuf,
    pub budgets: InstallBudgets,
}

/// The scan root of the model store.
pub const MODELS_ROOT: &str = "models";

/// Why a session could not be assembled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectError {
    /// The policy refused the session. The request is built from the same policy, so this
    /// indicates a bug.
    Evaluate(EvaluateError),
    /// A built-in identifier failed the model's rules (a bug, reported rather than panicking).
    BadId(String),
    /// The assembled session fails `Session::validate` (a bug, reported rather than returned as
    /// a result).
    Invalid(Vec<String>),
    /// The session's reference rows are not what the embedded set gives (a bug).
    Reference(Vec<String>),
    /// An input of `binary inspect` that cannot be inspected (exit 1; plan §4.9).
    Input(String),
    /// Embedded data the engine cannot use, e.g. invalid signatures (a bug, reported rather than
    /// panicking).
    Internal(String),
}

impl fmt::Display for InspectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InspectError::Evaluate(e) => write!(f, "{e}"),
            InspectError::BadId(e) => write!(f, "invalid built-in identifier: {e}"),
            InspectError::Invalid(errors) => {
                write!(f, "the assembled session is invalid: {}", errors.join("; "))
            }
            InspectError::Reference(errors) => write!(
                f,
                "the session's reference matches disagree with the embedded set: {}",
                errors.join("; ")
            ),
            InspectError::Input(e) => write!(f, "{e}"),
            InspectError::Internal(e) => write!(f, "internal error: {e}"),
        }
    }
}

impl std::error::Error for InspectError {}

/// The active features requested and what they observed (ADR-002 active mode). The CLI runs the
/// probes (`sigil-probe`) and passes their records here: the engine performs no network I/O.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActiveInput {
    pub features: Vec<ActiveFeature>,
    /// One per requested target.
    pub probes: Vec<ApiProbe>,
    /// The probe bounds in effect, by the names `request.budgets` records (`api_connect_ms`,
    /// `api_io_ms`, `api_response_bytes`).
    pub budgets: BTreeMap<String, u64>,
}

/// What an observe-mode inspection is asked to do: the model store, and the running system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserveRequest {
    pub store: StoreRequest,
    /// `/proc` outside tests.
    pub proc_root: PathBuf,
    pub proc_budgets: ProcBudgets,
}

/// Inspects a model store in static mode and evaluates `policy` on the result.
///
/// The request's audit scope and required checks come from `policy`, so evaluation cannot refuse
/// it. `active` adds the requested active features, their probes, and `runtime_api` coverage;
/// a probe that does not match its request makes the session invalid. `observation` is recorded
/// as given; `policy_time` judges rule expiry. The session is in canonical order and passes
/// `Session::validate`.
pub fn store_session(
    req: &StoreRequest,
    active: &ActiveInput,
    policy: &Policy,
    tool: ToolInfo,
    observation: ObservationMeta,
    policy_time: Timestamp,
) -> Result<Session, InspectError> {
    assemble(req, None, active, policy, tool, observation, policy_time)
}

/// Inspects the model store and the running system in observe mode (plan §4.6.8), and evaluates
/// `policy` on the result. As [`store_session`], with the runtime's processes, listeners, and
/// exposure added. SIGIL's own network namespace, as read, replaces `observation.net_ns`; the
/// processes are observed at `observation.started_at`.
pub fn observe_session(
    req: &ObserveRequest,
    active: &ActiveInput,
    policy: &Policy,
    tool: ToolInfo,
    mut observation: ObservationMeta,
    policy_time: Timestamp,
) -> Result<Session, InspectError> {
    let proc = observe::proc::observe(
        &req.proc_root,
        &observation.started_at,
        &observation.boot_id,
        req.proc_budgets,
    );
    observation.net_ns = proc.own_net_ns;
    let observed = Some((proc, req.proc_budgets));
    assemble(
        &req.store,
        observed,
        active,
        policy,
        tool,
        observation,
        policy_time,
    )
}

/// Assembles the session: observe mode when the running system was `observed`, else static.
fn assemble(
    req: &StoreRequest,
    observed: Option<(ProcFacts, ProcBudgets)>,
    active: &ActiveInput,
    policy: &Policy,
    tool: ToolInfo,
    observation: ObservationMeta,
    policy_time: Timestamp,
) -> Result<Session, InspectError> {
    let mode = if observed.is_some() {
        Mode::Observe
    } else {
        Mode::Static
    };
    let root = RootId::new(MODELS_ROOT).map_err(|e| InspectError::BadId(e.to_string()))?;
    let mut fs = SafeFs::new(req.budgets);
    let facts = match fs.add_root(root.clone(), &req.models_dir) {
        Ok(()) => {
            ollama_store::collect(&fs, &root, req.model_filter.as_deref(), req.manifest_limit)
        }
        Err(e) => unopened(&root, e),
    };
    // The canonical path SafeFs opened, or the path as given when it could not be opened.
    let path = fs.root_path(&root).unwrap_or(&req.models_dir);
    let (mut findings, analysis_coverage) = model_store::analyze(&facts, &root);
    let (audit, required_checks) = policy.scope(&ScopeInput {
        mode,
        active: !active.features.is_empty(),
        install: req.install.is_some(),
        binary: false,
        code: false,
    });
    let mut coverage = facts.coverage;
    coverage.extend(analysis_coverage);
    let mut budgets = budgets(req);
    let mut roots = vec![ScanRoot {
        id: root,
        path: recorded(path),
    }];
    let (mut artifacts, mut instances) = (facts.artifacts, facts.instances);
    let mut knowledge = Vec::<KnowledgeRef>::new();
    let (mut closed, mut reference_matches) = (None, vec![]);
    let mut install_set = None;
    let (mut relations, mut binaries, mut scans) = (vec![], vec![], vec![]);
    if let Some(r) = &req.install {
        let set = reference::official().map_err(|e| InspectError::Reference(vec![e]))?;
        let facts = install::collect(&r.dir, r.budgets).map_err(InspectError::BadId)?;
        let result = release::analyze(&facts, set).map_err(InspectError::BadId)?;
        let (container, declares) = container::analyze(&facts).map_err(InspectError::BadId)?;
        let identity_coverage = container::identity(&facts).map_err(InspectError::BadId)?;
        roots.push(ScanRoot {
            id: RootId::new(INSTALL_ROOT).map_err(|e| InspectError::BadId(e.to_string()))?,
            path: facts.root_path,
        });
        instances.extend(facts.instances);
        for a in facts.artifacts {
            match artifacts.iter_mut().find(|x| x.id == a.id) {
                Some(known) => merge(known, a).map_err(|e| InspectError::Invalid(vec![e]))?,
                None => artifacts.push(a),
            }
        }
        knowledge.push(set.knowledge());
        install_set = Some(set);
        budgets.extend(install_budgets(r.budgets));
        coverage.push(facts.discovery);
        coverage.push(result.coverage);
        coverage.push(container);
        coverage.push(identity_coverage);
        relations.extend(declares);
        binaries = facts.binaries;
        scans = facts.scans;
        reference_matches = result.rows;
        closed = result.claim;
    } else {
        // A policy that requires the install's checks without one: skipped, so incomplete.
        for check in &required_checks {
            if [
                ARTIFACTS_DISCOVERY,
                ARTIFACTS_RELEASE,
                ARTIFACTS_CONTAINER,
                ARTIFACTS_IDENTITY,
            ]
            .contains(&check.as_str())
            {
                coverage.push(Coverage {
                    check: check.clone(),
                    scope: Ref::Audit,
                    state: CoverageState::Skipped {
                        by: SkipReason::Flag {
                            flag: "--install-dir".to_string(),
                        },
                    },
                    budget: None,
                });
            }
        }
    }
    let (mut processes, mut listeners) = (vec![], vec![]);
    if let Some((proc, proc_budgets)) = observed {
        let (exposure_findings, exposure_coverage) = exposure::analyze(&proc);
        findings.extend(exposure_findings);
        coverage.extend(exposure_coverage);
        processes = proc.processes;
        listeners = proc.listeners;
        budgets.extend([
            ("processes_listed".to_string(), proc_budgets.max_processes),
            ("fds_per_process".to_string(), proc_budgets.max_fds),
            ("tcp_table_bytes".to_string(), proc_budgets.max_table_bytes),
        ]);
    }
    coverage.extend(runtime_api::analyze(&active.probes));
    budgets.extend(active.budgets.clone());
    let mut hints = hints::derive(&binaries).map_err(InspectError::Internal)?;
    hints.extend(hints::from_scans(&scans));
    // PR-4c-1: from the facts above; nothing more is read.
    let components = identity::derive(&instances, &binaries, &reference_matches)
        .map_err(InspectError::Internal)?;
    // PR-4c-2c: the closed claim, or else the open claim of the install's self-reported commits.
    let releases = match install_set {
        Some(set) => release::claims(closed, &components, set).map_err(InspectError::Internal)?,
        None => vec![],
    };
    let mut session = Session {
        schema: SchemaVersion::SessionV1,
        tool,
        knowledge,
        request: RunRequest {
            mode,
            roots,
            audit,
            required_checks,
            budgets,
            observe_env: false,
            model_filter: req.model_filter.clone(),
            active: active.features.clone(),
            code: false,
        },
        observation,
        artifacts,
        instances,
        models: facts.models,
        processes,
        listeners,
        probes: active.probes.clone(),
        values: vec![],
        components,
        releases,
        reference_matches,
        binaries,
        hints,
        code: vec![],
        relations,
        rule_support: vec![],
        bindings: vec![],
        loads: vec![],
        access: vec![],
        assumptions: vec![],
        coverage,
        findings,
        open_questions: vec![],
        policy_violations: vec![],
        // Computed by `evaluate`.
        outcome: Outcome {
            verdict: Verdict::Pass,
            completeness: Completeness::Complete,
            confirmed_failures: 0,
            confirmed_warnings: 0,
            policy_time: policy_time.clone(),
        },
    };
    evaluate(&mut session, policy, policy_time).map_err(InspectError::Evaluate)?;
    session.canonicalize();
    // A successful result always validates.
    session.validate().map_err(|errors| {
        InspectError::Invalid(errors.iter().map(ToString::to_string).collect())
    })?;
    // What `validate` cannot re-derive: the rows are exactly the embedded set's.
    if req.install.is_some() {
        let set = reference::official().map_err(|e| InspectError::Reference(vec![e]))?;
        reference::verify_reference_matches(&session, set).map_err(InspectError::Reference)?;
    }
    Ok(session)
}

/// What a binary inspection is asked to do (`sigil binary inspect`; PR-4b-2a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryRequest {
    /// The files, as given: each is resolved, and a file named twice is one input.
    pub paths: Vec<PathBuf>,
    pub budgets: NamedBudgets,
}

/// Inspects the files of `req` and evaluates `policy`'s binary scope on the result (spec §4.5).
/// With `req.budgets.binary.code`, the session has `request.code`, the code facts, and one
/// `binary.code` entry per input (PR-5a spec §5). An input that cannot be inspected is
/// [`InspectError::Input`]. The session is in canonical order and passes `Session::validate`.
pub fn binary_session(
    req: &BinaryRequest,
    policy: &Policy,
    tool: ToolInfo,
    observation: ObservationMeta,
    policy_time: Timestamp,
) -> Result<Session, InspectError> {
    let facts = named::collect(&req.paths, req.budgets).map_err(InspectError::Input)?;
    let code_request = req.budgets.binary.code;
    // With code, `binary_code_audit` is added: what `evaluate` derives from `request.code`.
    let (audit, required_checks) = policy.scope(&ScopeInput {
        mode: Mode::Static,
        active: false,
        install: false,
        binary: true,
        code: code_request.is_some(),
    });
    let relations = container::declares(&facts.binaries);
    let mut budgets = BTreeMap::from([
        (BINARY_BYTES.to_string(), req.budgets.bytes),
        (
            "binary_parse_bytes".to_string(),
            req.budgets.binary.parse_bytes,
        ),
        ("binary_imports".to_string(), req.budgets.binary.imports),
        (BINARY_SCAN_BYTES.to_string(), req.budgets.binary.scan_bytes),
    ]);
    // With code (PR-5a): its byte budget. Its aggregate limits are constants, not recorded.
    if let Some(c) = code_request {
        budgets.insert(BINARY_CODE_BYTES.to_string(), c.bytes);
    }
    let mut hints = hints::derive(&facts.binaries).map_err(InspectError::Internal)?;
    hints.extend(hints::from_scans(&facts.scans));
    // PR-4c-1: a binary inspection has no reference rows.
    let components =
        identity::derive(&facts.instances, &facts.binaries, &[]).map_err(InspectError::Internal)?;
    let mut session = Session {
        schema: SchemaVersion::SessionV1,
        tool,
        knowledge: vec![],
        request: RunRequest {
            mode: Mode::Static,
            roots: facts.roots,
            audit,
            required_checks,
            budgets,
            observe_env: false,
            model_filter: None,
            active: vec![],
            code: code_request.is_some(),
        },
        observation,
        artifacts: facts.artifacts,
        instances: facts.instances,
        models: vec![],
        processes: vec![],
        listeners: vec![],
        probes: vec![],
        values: vec![],
        components,
        releases: vec![],
        reference_matches: vec![],
        binaries: facts.binaries,
        hints,
        // Moved out of the outcomes once their coverage is computed, below.
        code: vec![],
        relations,
        rule_support: vec![],
        bindings: vec![],
        loads: vec![],
        access: vec![],
        assumptions: vec![],
        coverage: vec![],
        findings: vec![],
        open_questions: vec![],
        policy_violations: vec![],
        // Computed by `evaluate`.
        outcome: Outcome {
            verdict: Verdict::Pass,
            completeness: Completeness::Complete,
            confirmed_failures: 0,
            confirmed_warnings: 0,
            policy_time: policy_time.clone(),
        },
    };
    // The container's entries first: an input over `binary_bytes` copies its state to
    // `binary.code`.
    session.coverage = binary::analyze(&session, &facts.over).map_err(InspectError::BadId)?;
    // PR-4c-2a: after the container's entries, whose state an input over `binary_bytes` copies.
    let identity_coverage =
        binary::identity_coverage(&session, &facts.scans).map_err(InspectError::Internal)?;
    session.coverage.extend(identity_coverage);
    let code_coverage = binary::code_coverage(&session, &facts.code).map_err(|e| match e {
        CodeCoverageError::BadId(e) => InspectError::BadId(e),
        CodeCoverageError::Undecided(e) => InspectError::Internal(e),
    })?;
    session.coverage.extend(code_coverage);
    session.code = code_facts(facts.code);
    evaluate(&mut session, policy, policy_time).map_err(InspectError::Evaluate)?;
    session.canonicalize();
    session.validate().map_err(|errors| {
        InspectError::Invalid(errors.iter().map(ToString::to_string).collect())
    })?;
    Ok(session)
}

/// The code facts of each analyzed slice that has a call site, moved out of `outcomes`. One
/// content named twice is one slice, so one entry.
fn code_facts(outcomes: Vec<(SliceId, CodeOutcome)>) -> Vec<CodeFacts> {
    outcomes
        .into_iter()
        .filter_map(|(slice, outcome)| match outcome {
            CodeOutcome::Analyzed {
                functions,
                call_sites,
                ..
            } if !call_sites.is_empty() => Some(CodeFacts {
                slice,
                functions,
                call_sites,
                predicate_checks: vec![],
                close_checks: vec![],
                guard_regions: vec![],
                param_mappings: vec![],
            }),
            _ => None,
        })
        .collect()
}

/// The facts of a model store whose root could not be opened: inventory coverage only.
fn unopened(root: &RootId, e: RootError) -> StoreFacts {
    let state = match e {
        RootError::NotFound => CoverageState::Unavailable {
            why: Unavailability::NotFound,
        },
        RootError::PermissionDenied => CoverageState::Unavailable {
            why: Unavailability::PermissionDenied,
        },
        RootError::NotADirectory => CoverageState::Error {
            message: UntrustedText::new("the models directory is not a directory"),
        },
        RootError::Duplicate => CoverageState::Error {
            message: UntrustedText::new("the models root was added twice"),
        },
        RootError::Failed(message) => CoverageState::Error {
            message: UntrustedText::new(message),
        },
    };
    let coverage = CheckId::new(INVENTORY)
        .map(|check| Coverage {
            check,
            scope: Ref::Root(root.clone()),
            state,
            budget: None,
        })
        .into_iter()
        .collect();
    StoreFacts {
        coverage,
        ..StoreFacts::default()
    }
}

/// The budgets in effect, by the names `BudgetUse` reports.
fn budgets(req: &StoreRequest) -> BTreeMap<String, u64> {
    let b = req.budgets;
    BTreeMap::from([
        ("files_discovered".to_string(), b.max_files),
        ("entries_listed".to_string(), b.max_entries),
        ("directory_entries".to_string(), b.max_dir_entries),
        ("walk_depth".to_string(), u64::from(b.max_depth)),
        ("link_hops".to_string(), u64::from(b.max_link_hops)),
        ("manifest_bytes".to_string(), req.manifest_limit),
    ])
}

/// One content read under two roots: the same bytes, so the same size, and the format and slices
/// that either reading identified. The model store does not parse executables, so an ELF found
/// there too keeps the install's ELF format and slice. Two readings that identified different
/// formats are a bug.
fn merge(known: &mut Artifact, other: Artifact) -> Result<(), String> {
    let plain = |a: &Artifact| a.format == Format::Other && a.slices.is_empty();
    if known.size != other.size {
        return Err(format!("artifact {}: read with two sizes", known.id));
    }
    if plain(known) {
        *known = other;
    } else if !plain(&other) && (known.format != other.format || known.slices != other.slices) {
        return Err(format!("artifact {}: read as two formats", known.id));
    }
    Ok(())
}

/// The install scan's budgets, by the names `BudgetUse` reports with the `install_` prefix.
fn install_budgets(b: InstallBudgets) -> BTreeMap<String, u64> {
    let fs = FsBudgets::default();
    BTreeMap::from([
        ("install_files_discovered".to_string(), b.files),
        ("install_entries_listed".to_string(), b.entries),
        ("install_directory_entries".to_string(), fs.max_dir_entries),
        ("install_walk_depth".to_string(), u64::from(fs.max_depth)),
        ("install_link_hops".to_string(), u64::from(fs.max_link_hops)),
        ("install_bytes".to_string(), b.bytes),
        ("binary_parse_bytes".to_string(), b.binary.parse_bytes),
        ("binary_imports".to_string(), b.binary.imports),
        (BINARY_SCAN_BYTES.to_string(), b.binary.scan_bytes),
    ])
}

#[cfg(test)]
mod tests {
    use sigil_model::{Arch, ArtifactId, ElfType, Format, Slice, SliceId};

    use super::{merge, Artifact};

    fn artifact(format: Format, sliced: bool, size: u64) -> Artifact {
        let id = ArtifactId::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let slices = if sliced {
            vec![Slice {
                id: SliceId::from_parts(&id, Arch::X86_64, 0),
                arch: Arch::X86_64,
                offset: 0,
                size,
                sha256: sigil_model::Sha256Hex::new("a".repeat(64)).unwrap(),
            }]
        } else {
            vec![]
        };
        Artifact {
            id,
            size,
            format,
            slices,
        }
    }

    #[test]
    fn the_identified_reading_of_one_content_is_kept() {
        let elf = || artifact(Format::Elf { kind: ElfType::Dyn }, true, 64);
        let plain = || artifact(Format::Other, false, 64);
        // Whichever was read first, the ELF reading is kept.
        let mut known = plain();
        merge(&mut known, elf()).unwrap();
        assert_eq!(known, elf());
        let mut known = elf();
        merge(&mut known, plain()).unwrap();
        assert_eq!(known, elf());
        let mut known = elf();
        merge(&mut known, elf()).unwrap();
        assert_eq!(known, elf());
        // Readings that disagree are a bug, not a choice.
        assert!(merge(&mut elf(), artifact(Format::MachO, false, 64)).is_err());
        assert!(merge(&mut plain(), artifact(Format::Other, false, 65)).is_err());
    }
}
