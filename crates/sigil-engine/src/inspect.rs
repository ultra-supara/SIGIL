//! Assembling sessions (plan §4.4.1). The CLI uses this from PR-3b.

use std::collections::BTreeMap;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use sigil_model::{
    CheckId, Completeness, Coverage, CoverageState, KnowledgeRef, Mode, ObservationMeta, Outcome,
    Ref, RootId, RunRequest, ScanRoot, SchemaVersion, Session, Timestamp, ToolInfo, Unavailability,
    UntrustedText, Verdict,
};

use crate::analyze::model_store;
use crate::collect::fs::{FsBudgets, RootError, SafeFs};
use crate::collect::ollama_store::{self, StoreFacts, INVENTORY};
use crate::policy::{evaluate, EvaluateError, Policy};

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
}

impl fmt::Display for InspectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InspectError::Evaluate(e) => write!(f, "{e}"),
            InspectError::BadId(e) => write!(f, "invalid built-in identifier: {e}"),
        }
    }
}

impl std::error::Error for InspectError {}

/// Inspects a model store in static mode and evaluates `policy` on the result.
///
/// The request's audit scope and required checks come from `policy`, so evaluation cannot refuse
/// it. `observation` is recorded as given; `policy_time` judges rule expiry. The session is in
/// canonical order and passes `Session::validate`.
pub fn store_session(
    req: &StoreRequest,
    policy: &Policy,
    tool: ToolInfo,
    observation: ObservationMeta,
    policy_time: Timestamp,
) -> Result<Session, InspectError> {
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
    let (findings, analysis_coverage) = model_store::analyze(&facts, &root);
    let (audit, required_checks) = policy.scope(Mode::Static);
    let mut coverage = facts.coverage;
    coverage.extend(analysis_coverage);
    let mut session = Session {
        schema: SchemaVersion::SessionV1,
        tool,
        knowledge: Vec::<KnowledgeRef>::new(),
        request: RunRequest {
            mode: Mode::Static,
            roots: vec![ScanRoot {
                id: root,
                path: UntrustedText::from_bytes(path.as_os_str().as_bytes()),
            }],
            audit,
            required_checks,
            budgets: budgets(req),
            observe_env: false,
            model_filter: req.model_filter.clone(),
        },
        observation,
        artifacts: facts.artifacts,
        instances: facts.instances,
        models: facts.models,
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
    Ok(session)
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
