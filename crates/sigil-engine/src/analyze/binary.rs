//! `binary.container`, one entry per input (PR-4b-2a spec §4.3). Its state is the model's
//! `expected_binary_container`, which `Session::validate` (B9) checks against the same session.
//! With `request.code`, `binary.code` too, one entry per input (PR-5a spec §5.2): what it may be
//! is the model's `expected_binary_code` (C3), and an analyzed input's is its slice's outcome.

use std::collections::BTreeMap;

use sigil_model::{
    expected_binary_code, expected_binary_container, is_binary_root, BudgetUse, CheckId, Coverage,
    CoverageState, ExpectedCode, ExpectedContainer, FileInstance, InstanceContent, InstanceId, Ref,
    Session, SliceId, BINARY_CODE, BINARY_CODE_BYTES, BINARY_CONTAINER, BINARY_NOT_PARSED,
    CODE_UNSUPPORTED,
};

use crate::code::CodeOutcome;

/// The coverage of every input of `s`. `over`: the bytes hashed before each input that was over
/// `binary_bytes`.
pub fn analyze(s: &Session, over: &BTreeMap<InstanceId, u64>) -> Result<Vec<Coverage>, String> {
    let check = CheckId::new(BINARY_CONTAINER).map_err(|e| e.to_string())?;
    s.instances
        .iter()
        .filter(|i| is_binary_root(&i.root))
        .map(|i| {
            let expected = expected_binary_container(s, i)?;
            let used = match expected {
                ExpectedContainer::OverBytes { .. } => over
                    .get(&i.id)
                    .copied()
                    .ok_or_else(|| format!("{}: over binary_bytes without a count", i.id))?,
                ExpectedContainer::Exactly(_) => 0,
            };
            let state = expected.into_state(used);
            Ok(Coverage {
                check: check.clone(),
                scope: Ref::Instance(i.id.clone()),
                state,
                budget: None,
            })
        })
        .collect()
}

/// Why `binary.code` could not be computed: a bug either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeCoverageError {
    /// `binary.code` failed the model's rules for a check ID.
    BadId(String),
    /// The model cannot judge an input of the session (`expected_binary_code`'s error).
    Undecided(String),
}

/// The `binary.code` entry of every input of `s`, when `s.request.code`; none otherwise. `code`:
/// each analyzed slice's outcome, of which only the variant, the gaps, and the budget use are
/// read. It runs after the `binary.container` entries are in `s.coverage`: an input over
/// `binary_bytes` copies its container entry's state, `used` included.
pub fn code_coverage(
    s: &Session,
    code: &[(SliceId, CodeOutcome)],
) -> Result<Vec<Coverage>, CodeCoverageError> {
    if !s.request.code {
        return Ok(vec![]);
    }
    let check = CheckId::new(BINARY_CODE).map_err(|e| CodeCoverageError::BadId(e.to_string()))?;
    s.instances
        .iter()
        .filter(|i| is_binary_root(&i.root))
        .map(|i| {
            let expected = expected_binary_code(s, i).map_err(CodeCoverageError::Undecided)?;
            let (state, budget) = match expected {
                ExpectedCode::Exactly(state) => (state, None),
                ExpectedCode::Analyzable { limit, parsed } => analyzed(s, i, code, limit, parsed),
            };
            Ok(Coverage {
                check: check.clone(),
                scope: Ref::Instance(i.id.clone()),
                state,
                budget,
            })
        })
        .collect()
}

/// `binary.code` of an input the model says is analyzable (an x86-64 ELF, whose one slice is
/// the artifact's first): its slice's outcome. A slice without an outcome, or not `parsed`, is
/// `Partial`, having read nothing for code. (An ELF slice has an outcome exactly when its read
/// saw no change, and then container facts too, so it is `parsed`.)
fn analyzed(
    s: &Session,
    i: &FileInstance,
    code: &[(SliceId, CodeOutcome)],
    limit: u64,
    parsed: bool,
) -> (CoverageState, Option<BudgetUse>) {
    let not_parsed = || {
        (
            CoverageState::Partial {
                missing: vec![BINARY_NOT_PARSED.to_string()],
            },
            Some(BudgetUse {
                budget: BINARY_CODE_BYTES.to_string(),
                used: 0,
                limit,
            }),
        )
    };
    let slice = match &i.content {
        InstanceContent::Read { artifact } => s
            .artifacts
            .iter()
            .find(|a| a.id == *artifact)
            .and_then(|a| a.slices.first()),
        InstanceContent::NotRead { .. } => None,
    };
    let Some(slice) = slice.filter(|_| parsed) else {
        return not_parsed();
    };
    match code.iter().find(|(id, _)| *id == slice.id).map(|(_, o)| o) {
        Some(CodeOutcome::Analyzed { gaps, budget, .. }) => (
            if gaps.is_empty() {
                CoverageState::Complete
            } else {
                CoverageState::Partial {
                    missing: gaps.clone(),
                }
            },
            Some(budget.clone()),
        ),
        // An x32 or big-endian file: `x86_64` in the model (plan R-c).
        Some(CodeOutcome::Unsupported) => (
            CoverageState::Unsupported {
                what: CODE_UNSUPPORTED.to_string(),
            },
            None,
        ),
        None => not_parsed(),
    }
}
