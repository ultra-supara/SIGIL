//! A binary inspection's inputs (`sigil binary inspect`; PR-4b-2a spec §4.3, §5).
//!
//! Each input is its own scan root, `binary-<n>` in argument order, whose path is the file. Its
//! one instance gets exactly one `binary.container` coverage, whose state is the one
//! [`expected_binary_container`] derives from the instance, its artifact, and its facts. The
//! engine records that state, and `Session::validate` (B9) requires it. With `request.code`
//! (PR-5a), each input also gets one `binary.code` coverage, whose state
//! [`expected_binary_code`] derives the same way (C3).

use crate::artifact::{Arch, FileInstance, Format, InstanceContent, NotReadReason, Stability};
use crate::coverage::{Coverage, CoverageState};
use crate::evidence::Ref;
use crate::id::RootId;
use crate::session::{RunRequest, Session};
use crate::text::UntrustedText;

/// The check of a binary inspection: one entry per input, scope `Instance`.
pub const BINARY_CONTAINER: &str = "binary.container";
/// The code check of a binary inspection with code (PR-5a): one entry per input, scope
/// `Instance`.
pub const BINARY_CODE: &str = "binary.code";
/// Bytes read for code, per artifact (PR-5a spec §4.10).
pub const BINARY_CODE_BYTES: &str = "binary_code_bytes";
/// `binary.code`'s `Unsupported` reason: a container the code analysis does not read.
pub const CODE_UNSUPPORTED: &str = "code analysis: x86-64 ELF64 little-endian only";
/// Hashing reads, over all inputs.
pub const BINARY_BYTES: &str = "binary_bytes";
/// `binary.container`'s `Unsupported` reason.
pub const BINARY_UNSUPPORTED: &str = "not a supported ELF or Mach-O container";
/// `binary.container`'s `Error` for a read that saw a change.
pub const BINARY_CHANGED: &str = "changed during the read";
/// `binary.container`'s `Error` for a file gone after its read.
pub const BINARY_VANISHED: &str = "vanished during the read";
/// A `Partial` entry: a recognized slice without facts.
pub const BINARY_NOT_PARSED: &str = "not parsed";
/// Binary roots are `binary-<n>`.
pub const BINARY_ROOT_PREFIX: &str = "binary-";
/// Bytes the signature scan reads, per artifact (PR-4c-2a spec §4).
pub const BINARY_SCAN_BYTES: &str = "binary_scan_bytes";
/// A scan gap: a needle looks in sections, and the file has no readable section header table.
pub const SCAN_NO_SECTIONS: &str = "string scan: no section headers";
/// A scan gap: the name of a section or of an exported symbol could not be read, so a needle may
/// be there unseen.
pub const SCAN_NAME_NOT_READ: &str = "string scan: a name not read";
/// A scan gap: a read of a section failed, and the rest of that section was not read; or the
/// section passes the end of the file, and its bytes past it could not be read.
pub const SCAN_READ_FAILED: &str = "string scan: a read failed";

/// The scan gap of an artifact whose scan reached `binary_scan_bytes` (`limit`): `string scan:
/// binary_scan_bytes <limit> exceeded`. What was found before it is kept.
pub fn scan_over_gap(limit: u64) -> String {
    format!("string scan: {BINARY_SCAN_BYTES} {limit} exceeded")
}

/// The root of input `n`; `None` for 0, which `binary_root_index` refuses too.
pub fn binary_root(n: u32) -> Option<RootId> {
    if n == 0 {
        return None;
    }
    RootId::new(format!("{BINARY_ROOT_PREFIX}{n}")).ok()
}

/// The `n` of `binary-<n>`: decimal, from 1, without leading zeros.
pub fn binary_root_index(id: &RootId) -> Option<u32> {
    let digits = id.as_str().strip_prefix(BINARY_ROOT_PREFIX)?;
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Whether `id` is a binary root.
pub fn is_binary_root(id: &RootId) -> bool {
    binary_root_index(id).is_some()
}

/// Whether `request` is a binary inspection's: it has a binary root. The one test of a binary
/// session, for the policy scope, the validator, and the renderers alike; B10 makes every root of
/// such a session a binary root.
pub fn is_binary_inspection(request: &RunRequest) -> bool {
    request.roots.iter().any(|r| is_binary_root(&r.id))
}

/// The `binary.container` state an input implies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedContainer {
    /// This state, exactly.
    Exactly(CoverageState),
    /// `BudgetExceeded` over `binary_bytes` with this limit; its `used` is the engine's count.
    OverBytes { limit: u64 },
}

impl ExpectedContainer {
    /// The state to record: `used` is the bytes hashed before the input, for `OverBytes`.
    pub fn into_state(self, used: u64) -> CoverageState {
        match self {
            ExpectedContainer::Exactly(state) => state,
            ExpectedContainer::OverBytes { limit } => CoverageState::BudgetExceeded {
                budget: BINARY_BYTES.to_string(),
                used,
                limit,
            },
        }
    }

    /// Whether `state` is the one implied: exactly, or for `OverBytes` a `BudgetExceeded` over
    /// `binary_bytes` with this limit and `used` at most the limit (B9).
    pub fn admits(&self, state: &CoverageState) -> bool {
        match self {
            ExpectedContainer::Exactly(expected) => state == expected,
            ExpectedContainer::OverBytes { limit } => matches!(
                state,
                CoverageState::BudgetExceeded { budget, used, limit: l }
                    if budget == BINARY_BYTES && l == limit && used <= l
            ),
        }
    }
}

/// What `i`'s read implies for `binary.container` (spec §4.3). `Err` for an input that cannot be
/// part of a session: one the engine treats as a fatal input error, or one whose artifact or
/// budget is missing.
pub fn expected_binary_container(
    s: &Session,
    i: &FileInstance,
) -> Result<ExpectedContainer, String> {
    let artifact = match &i.content {
        InstanceContent::NotRead {
            why: NotReadReason::BudgetExceeded,
        } => {
            let limit = s
                .request
                .budgets
                .get(BINARY_BYTES)
                .copied()
                .ok_or("an input over binary_bytes, without a binary_bytes budget")?;
            return Ok(ExpectedContainer::OverBytes { limit });
        }
        InstanceContent::NotRead { why } => {
            return Err(format!(
                "an input not read ({why:?}) is a fatal input error, never part of a session"
            ))
        }
        InstanceContent::Read { artifact } => artifact,
    };
    let error = |message: &str| {
        Ok(ExpectedContainer::Exactly(CoverageState::Error {
            message: UntrustedText::new(message),
        }))
    };
    match i.stability {
        Stability::ChangedDuringRead => return error(BINARY_CHANGED),
        Stability::Vanished => return error(BINARY_VANISHED),
        Stability::NoChangeDetected => {}
    }
    let a = s
        .artifacts
        .iter()
        .find(|a| a.id == *artifact)
        .ok_or("its artifact is not in the session")?;
    if !matches!(
        a.format,
        Format::Elf { .. } | Format::MachO | Format::MachOFat
    ) {
        return Ok(ExpectedContainer::Exactly(CoverageState::Unsupported {
            what: BINARY_UNSUPPORTED.to_string(),
        }));
    }
    let mut missing = vec![];
    if a.slices.is_empty() {
        missing.push(BINARY_NOT_PARSED.to_string());
    }
    for slice in &a.slices {
        match s.binaries.iter().find(|b| b.slice == slice.id) {
            Some(b) => missing.extend(b.gaps.iter().cloned()),
            None => missing.push(BINARY_NOT_PARSED.to_string()),
        }
    }
    missing.sort();
    missing.dedup();
    Ok(ExpectedContainer::Exactly(if missing.is_empty() {
        CoverageState::Complete
    } else {
        CoverageState::Partial { missing }
    }))
}

/// The `binary.code` state an input implies (PR-5a spec §5.2, C3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedCode {
    /// Exactly this state, without a budget: the container's state for an input whose container
    /// was not read (`BudgetExceeded`, `Error`, `Unsupported`), or `Unsupported {
    /// CODE_UNSUPPORTED }` for a container the code analysis does not read (a Mach-O, a fat
    /// Mach-O, or an ELF with a slice that is not `x86_64`).
    Exactly(CoverageState),
    /// An x86-64 ELF, analyzed: `Complete` (only when `parsed`) or `Partial`, with a
    /// `binary_code_bytes` budget of `limit` whose `used` is at most the limit. `Unsupported {
    /// CODE_UNSUPPORTED }` without a budget is admitted too: the model records no ELF class or
    /// byte order, so an x32 or big-endian file is `x86_64` here (plan R-c).
    Analyzable {
        /// The request's `binary_code_bytes`.
        limit: u64,
        /// The artifact has slices, and each has facts. Otherwise some code was not parsed, and
        /// the input's code is `Partial` at best.
        parsed: bool,
    },
}

impl ExpectedCode {
    /// Whether `c`, the input's `binary.code` entry, has the implied state and budget. `Err`
    /// says how it differs, showing the recorded state as reports do.
    pub fn admits(&self, c: &Coverage) -> Result<(), String> {
        use crate::render::coverage_state;
        let shown = |state: &CoverageState| coverage_state(state).terminal();
        let is = shown(&c.state);
        let no_budget = || match c.budget {
            None => Ok(()),
            Some(_) => Err(format!(
                "binary.code is {is} and names a budget, but the input's code is not read"
            )),
        };
        match self {
            ExpectedCode::Exactly(state) if c.state != *state => Err(format!(
                "binary.code is {is}, but the input implies {}",
                shown(state)
            )),
            ExpectedCode::Exactly(_) => no_budget(),
            ExpectedCode::Analyzable { limit, parsed } => match &c.state {
                CoverageState::Unsupported { what } if what == CODE_UNSUPPORTED => no_budget(),
                CoverageState::Complete if !parsed => Err(format!(
                    "binary.code is {is}, but a slice of the input was not parsed"
                )),
                CoverageState::Complete | CoverageState::Partial { .. } => match &c.budget {
                    None => Err(format!(
                        "binary.code is {is} without a {BINARY_CODE_BYTES} budget"
                    )),
                    Some(b) if b.budget != BINARY_CODE_BYTES => Err(format!(
                        "binary.code is {is}, but its budget is {}, not {BINARY_CODE_BYTES}",
                        UntrustedText::new(b.budget.as_str()).terminal_line()
                    )),
                    Some(b) if b.limit != *limit => Err(format!(
                        "binary.code is {is}, but its {BINARY_CODE_BYTES} limit is {}, not the request's {limit}",
                        b.limit
                    )),
                    Some(b) if b.used > b.limit => Err(format!(
                        "binary.code is {is}, but it used {} of {BINARY_CODE_BYTES}, over the limit {}",
                        b.used, b.limit
                    )),
                    Some(_) => Ok(()),
                },
                _ => Err(format!(
                    "binary.code is {is}, but the input implies complete or partial with {BINARY_CODE_BYTES} ({limit}), or {}",
                    shown(&CoverageState::Unsupported {
                        what: CODE_UNSUPPORTED.to_string()
                    })
                )),
            },
        }
    }
}

/// What `i`'s read implies for `binary.code`, in a binary inspection with `request.code` (spec
/// §5.2, C3). Whether the container was read comes from [`expected_binary_container`], not from
/// its entry. `Err` for an input that cannot be judged: one B9 refuses (including an input over
/// `binary_bytes` without exactly one `binary.container` entry that B9 admits, since its state
/// needs that entry's `used`), an analyzable input without a `binary_code_bytes` budget, or a
/// session without `request.code`.
pub fn expected_binary_code(s: &Session, i: &FileInstance) -> Result<ExpectedCode, String> {
    if !s.request.code {
        return Err("no binary.code without request.code".to_string());
    }
    let state = match expected_binary_container(s, i)? {
        expected @ ExpectedContainer::OverBytes { .. } => {
            let entries: Vec<&Coverage> = s
                .coverage
                .iter()
                .filter(|c| {
                    c.check.as_str() == BINARY_CONTAINER && c.scope == Ref::Instance(i.id.clone())
                })
                .collect();
            return match entries.as_slice() {
                [c] if expected.admits(&c.state) => Ok(ExpectedCode::Exactly(c.state.clone())),
                _ => Err(format!(
                    "an input over {BINARY_BYTES} needs one {BINARY_CONTAINER} entry in the state it implies"
                )),
            };
        }
        ExpectedContainer::Exactly(state) => state,
    };
    if !matches!(
        state,
        CoverageState::Complete | CoverageState::Partial { .. }
    ) {
        return Ok(ExpectedCode::Exactly(state));
    }
    let InstanceContent::Read { artifact } = &i.content else {
        return Err("an input not read has no container to analyze".to_string());
    };
    let a = s
        .artifacts
        .iter()
        .find(|a| a.id == *artifact)
        .ok_or("its artifact is not in the session")?;
    if !matches!(a.format, Format::Elf { .. }) || a.slices.iter().any(|x| x.arch != Arch::X86_64) {
        return Ok(ExpectedCode::Exactly(CoverageState::Unsupported {
            what: CODE_UNSUPPORTED.to_string(),
        }));
    }
    let limit = s
        .request
        .budgets
        .get(BINARY_CODE_BYTES)
        .copied()
        .ok_or_else(|| format!("request.code without a {BINARY_CODE_BYTES} budget"))?;
    let parsed = !a.slices.is_empty()
        && a.slices
            .iter()
            .all(|x| s.binaries.iter().any(|b| b.slice == x.id));
    Ok(ExpectedCode::Analyzable { limit, parsed })
}
