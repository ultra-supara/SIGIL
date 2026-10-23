//! A binary inspection's inputs (`sigil binary inspect`; PR-4b-2a spec §4.3, §5).
//!
//! Each input is its own scan root, `binary-<n>` in argument order, whose path is the file. Its
//! one instance gets exactly one `binary.container` coverage, whose state is the one
//! [`expected_binary_container`] derives from the instance, its artifact, and its facts. The
//! engine records that state, and `Session::validate` (B9) requires it. With `request.code`
//! (PR-5a), each input also gets one `binary.code` coverage, whose state
//! [`expected_binary_code`] derives the same way (C3). Each input also gets one `binary.identity`
//! coverage (PR-4c-2a), whose states [`expected_binary_identity`] derives (S1).

use crate::artifact::{
    Arch, ElfType, FileInstance, Format, InstanceContent, NotReadReason, Stability,
};
use crate::binary::{BinaryFacts, ContainerFacts, DataValue, DYNSYM_UNREAD_GAPS};
use crate::coverage::{Coverage, CoverageState};
use crate::evidence::Ref;
use crate::id::{RootId, SliceId};
use crate::session::{RunRequest, Session};
use crate::text::UntrustedText;

/// The check of a binary inspection: one entry per input, scope `Instance`.
pub const BINARY_CONTAINER: &str = "binary.container";
/// The code check of a binary inspection with code (PR-5a): one entry per input, scope
/// `Instance`.
pub const BINARY_CODE: &str = "binary.code";
/// The identity check of a binary inspection (PR-4c-2a): one entry per input, scope `Instance`.
/// Every scan the signature database asks for was done within its budget.
pub const BINARY_IDENTITY: &str = "binary.identity";
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
/// A scan gap: the file has Go build info, so its Go-function needles apply, and none of its
/// sections, every name read, is `.gopclntab`: they were looked for nowhere (PR #97 review P2).
pub const SCAN_NO_GOPCLNTAB: &str = "string scan: no .gopclntab section";

/// `binary.identity`'s `Unsupported` reason for a Mach-O input, and the gap of a Mach-O artifact
/// in `artifacts.identity`: SIGIL reads no Mach-O section yet.
pub const SCAN_ELF_ONLY: &str = "string scan: ELF only";
/// `binary.identity`'s `OutOfScope` reason for an input that is not scanned (ADR-010).
pub const NAME_AND_HASH_ONLY_WHY: &str =
    "NVIDIA library: identified by name and hash only (ADR-010)";
/// The components whose files are never scanned: `scan = false` in the engine's component
/// database, which an engine test keeps equal to this list.
pub const NAME_AND_HASH_ONLY: [&str; 3] = ["cuda-runtime", "cuda/cublas", "cuda/cublasLt"];

/// The scan gap of an artifact whose scan reached `binary_scan_bytes` (`limit`): `string scan:
/// binary_scan_bytes <limit> exceeded`. What was found before it is kept.
pub fn scan_over_gap(limit: u64) -> String {
    format!("string scan: {BINARY_SCAN_BYTES} {limit} exceeded")
}

/// The identity gap of a known exported function whose returned string was not read
/// (PR-4c-2b): `returned value: <function>: <why>`, `why` being its `FunctionReturn`'s
/// `Unknown` reason.
pub fn returned_value_gap(function: &str, why: &str) -> String {
    format!("returned value: {function}: {why}")
}

/// Whether `gap` is one the scan records, with `limit` as `binary_scan_bytes`.
pub fn is_scan_gap(gap: &str, limit: u64) -> bool {
    [
        SCAN_NO_SECTIONS,
        SCAN_NO_GOPCLNTAB,
        SCAN_NAME_NOT_READ,
        SCAN_READ_FAILED,
    ]
    .contains(&gap)
        || gap == scan_over_gap(limit)
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

/// What `i`'s read implies for `binary.container`, as a state: for an input over `binary_bytes`,
/// the state of its one `binary.container` entry, which B9 must admit, since its `used` is the
/// engine's count. `Err` for an input [`expected_binary_container`] cannot judge, or one over
/// `binary_bytes` without exactly such an entry.
fn container_state(s: &Session, i: &FileInstance) -> Result<CoverageState, String> {
    match expected_binary_container(s, i)? {
        expected @ ExpectedContainer::OverBytes { .. } => {
            let entries: Vec<&Coverage> = s
                .coverage
                .iter()
                .filter(|c| {
                    c.check.as_str() == BINARY_CONTAINER && c.scope == Ref::Instance(i.id.clone())
                })
                .collect();
            match entries.as_slice() {
                [c] if expected.admits(&c.state) => Ok(c.state.clone()),
                _ => Err(format!(
                    "an input over {BINARY_BYTES} needs one {BINARY_CONTAINER} entry in the state it implies"
                )),
            }
        }
        ExpectedContainer::Exactly(state) => Ok(state),
    }
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
    let state = container_state(s, i)?;
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

/// The `binary.identity` states an input implies (PR-4c-2a spec §5, S1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedIdentity {
    /// Exactly this state: the container's for an input whose container was not read
    /// (`BudgetExceeded`, `Error`, `Unsupported`); `Unsupported {` [`SCAN_ELF_ONLY`] `}` for a
    /// Mach-O or fat Mach-O; `Partial {` [`BINARY_NOT_PARSED`] `}` for an ELF with a slice
    /// without facts.
    Exactly(CoverageState),
    /// An ELF with facts, scanned: `Complete`, or `Partial` whose gaps are scan gaps
    /// ([`is_scan_gap`]) with the request's `binary_scan_bytes`, `limit`, sorted and without
    /// repeats (the engine's form); [`SCAN_NO_SECTIONS`] among them as `no_sections` says, and
    /// [`SCAN_NAME_NOT_READ`] among them when `exports_unread`: a linked ELF whose facts carry one
    /// of [`DYNSYM_UNREAD_GAPS`]. `Complete` only when neither gap is required.
    /// [`SCAN_NO_GOPCLNTAB`] only when `no_gopclntab_admitted`: a slice is a Go ELF whose section
    /// header table was read. The model sees no section names, so it admits the gap there, and
    /// `Complete` too. Also `OutOfScope {` [`NAME_AND_HASH_ONLY_WHY`] `}` when
    /// `name_and_hash_only`: a claim on a slice of the input names one of
    /// [`NAME_AND_HASH_ONLY`].
    ///
    /// The engine excludes a file by its placement's own file name (ADR-010), and scans one whose
    /// SONAME alone is NVIDIA's. The model has no name database, so it cannot tell the two
    /// apart: a claim's `SelfName { Filename }` assertions list every placement name, mapped or
    /// not (PR-4c-1 P-d). It therefore admits `OutOfScope`, and the scanned states, for any
    /// NVIDIA claim on the slice. The engine is the source of truth here; its tests (PR-4c-2a
    /// Task 5) pin that it writes `OutOfScope` only for an NVIDIA-named file.
    ///
    /// `unread_returns` (PR-4c-2b): the [`returned_value_gap`] of each `Unknown` return in the
    /// slices' facts, sorted. Each is among the gaps of a `Partial`, and only they are admitted
    /// there besides the scan gaps; `Complete` only without one. `any_returns`: the facts have a
    /// return, so the input was scanned: never `OutOfScope`.
    Scanned {
        limit: u64,
        name_and_hash_only: bool,
        no_sections: NoSectionsGap,
        exports_unread: bool,
        no_gopclntab_admitted: bool,
        unread_returns: Vec<String>,
        any_returns: bool,
    },
}

/// Whether a scanned input's `binary.identity` lists the scan's gap [`SCAN_NO_SECTIONS`], from
/// its slices' facts (S1, S2). Ordered: the input's is its slices' greatest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NoSectionsGap {
    /// Never: the slice's section header table was read (`ElfFacts.stripped` is set; B8).
    Never,
    /// It may: the slice has no section header table. Whether a needle that applies looks in
    /// sections is the database's.
    May,
    /// It must: the slice has no section header table and has Go build info, so the embedded
    /// database's Go-function needles, which look in `.gopclntab`, apply. An engine test keeps
    /// that database with Go-function needles.
    Must,
}

/// What `b`, a slice's facts, imply for the scan's gap [`SCAN_NO_SECTIONS`].
pub(crate) fn no_sections_gap(b: &BinaryFacts) -> NoSectionsGap {
    match &b.container {
        ContainerFacts::Elf(elf) if elf.stripped.is_some() => NoSectionsGap::Never,
        _ if b.go.is_some() => NoSectionsGap::Must,
        _ => NoSectionsGap::May,
    }
}

/// Whether `b`, the facts of a slice of an ELF of kind `kind`, imply the scan's gap
/// [`SCAN_NAME_NOT_READ`]: a linked ELF whose loader has dynamic symbols the parse has no
/// `.dynsym` for (its facts carry one of [`DYNSYM_UNREAD_GAPS`]). The scan cannot look at its
/// exports, and the embedded database has an export needle, which an engine test keeps. A
/// relocatable object has no dynamic symbols: its exports are never looked at.
pub(crate) fn exports_unread(b: &BinaryFacts, kind: ElfType) -> bool {
    kind != ElfType::Rel
        && b.gaps
            .iter()
            .any(|g| DYNSYM_UNREAD_GAPS.contains(&g.as_str()))
}

/// Whether `b`, a slice's facts, admit the scan's gap [`SCAN_NO_GOPCLNTAB`]: a Go ELF (its
/// Go-function needles apply) whose section header table was read (`stripped` is set; B8), so
/// that the scan could find no section named `.gopclntab`.
pub(crate) fn no_gopclntab_admitted(b: &BinaryFacts) -> bool {
    b.go.is_some() && matches!(&b.container, ContainerFacts::Elf(elf) if elf.stripped.is_some())
}

/// The [`returned_value_gap`] of each `Unknown` return in `b`'s facts (PR-4c-2b): the identity
/// gaps they require.
pub(crate) fn unread_returns(b: &BinaryFacts) -> Vec<String> {
    match &b.container {
        ContainerFacts::Elf(elf) => elf
            .returns
            .iter()
            .filter_map(|r| match &r.value {
                DataValue::Unknown { why } => Some(returned_value_gap(&r.function, why)),
                _ => None,
            })
            .collect(),
        ContainerFacts::MachO(_) => vec![],
    }
}

/// Whether `b`'s facts have a return (PR-4c-2b): only a scan reads one.
pub(crate) fn any_returns(b: &BinaryFacts) -> bool {
    matches!(&b.container, ContainerFacts::Elf(elf) if !elf.returns.is_empty())
}

/// Whether a claim on `slice` names a component identified by name and hash only
/// ([`NAME_AND_HASH_ONLY`]; ADR-010).
pub(crate) fn name_and_hash_only(s: &Session, slice: &SliceId) -> bool {
    s.components
        .iter()
        .any(|c| c.subject == *slice && NAME_AND_HASH_ONLY.contains(&c.component.as_str()))
}

impl ExpectedIdentity {
    /// Whether `c`, the input's `binary.identity` entry, has a state implied, and no budget: the
    /// scan's limit is in its gap (P-h). `Err` says how it differs, showing the states as
    /// reports do.
    pub fn admits(&self, c: &Coverage) -> Result<(), String> {
        use crate::render::coverage_state;
        let shown = |state: &CoverageState| coverage_state(state).terminal();
        let state = &c.state;
        if c.budget.is_some() {
            return Err(format!(
                "{BINARY_IDENTITY} is {} and names a budget; the scan's limit is in its gap",
                shown(state)
            ));
        }
        match self {
            ExpectedIdentity::Exactly(expected) if state == expected => Ok(()),
            ExpectedIdentity::Exactly(expected) => Err(format!(
                "{BINARY_IDENTITY} is {}, but the input implies {}",
                shown(state),
                shown(expected)
            )),
            ExpectedIdentity::Scanned {
                limit,
                name_and_hash_only,
                no_sections,
                exports_unread,
                no_gopclntab_admitted,
                unread_returns,
                any_returns,
            } => {
                let admitted = match state {
                    CoverageState::Complete => {
                        *no_sections != NoSectionsGap::Must
                            && !*exports_unread
                            && unread_returns.is_empty()
                    }
                    CoverageState::Partial { missing } => {
                        let listed = missing.iter().any(|g| g == SCAN_NO_SECTIONS);
                        !missing.is_empty()
                            && missing.windows(2).all(|w| w[0] < w[1])
                            && missing
                                .iter()
                                .all(|g| is_scan_gap(g, *limit) || unread_returns.contains(g))
                            && unread_returns.iter().all(|g| missing.contains(g))
                            && match no_sections {
                                NoSectionsGap::Never => !listed,
                                NoSectionsGap::May => true,
                                NoSectionsGap::Must => listed,
                            }
                            && (!*exports_unread || missing.iter().any(|g| g == SCAN_NAME_NOT_READ))
                            && (*no_gopclntab_admitted
                                || !missing.iter().any(|g| g == SCAN_NO_GOPCLNTAB))
                    }
                    CoverageState::OutOfScope { why } => {
                        *name_and_hash_only && why == NAME_AND_HASH_ONLY_WHY && !*any_returns
                    }
                    _ => false,
                };
                if admitted {
                    return Ok(());
                }
                let mut required = vec![];
                if *no_sections == NoSectionsGap::Must {
                    required.push(format!("{SCAN_NO_SECTIONS:?}"));
                }
                if *exports_unread {
                    required.push(format!("{SCAN_NAME_NOT_READ:?}"));
                }
                required.extend(unread_returns.iter().map(|g| format!("{g:?}")));
                let mut gaps =
                    format!("partial with sorted, unique scan gaps ({BINARY_SCAN_BYTES} {limit})");
                if !required.is_empty() {
                    gaps.push_str(&format!(" among them {}", required.join(" and ")));
                }
                let mut refused = vec![];
                if *no_sections == NoSectionsGap::Never {
                    refused.push(format!("{SCAN_NO_SECTIONS:?}"));
                }
                if !*no_gopclntab_admitted {
                    refused.push(format!("{SCAN_NO_GOPCLNTAB:?}"));
                }
                if !refused.is_empty() {
                    gaps.push_str(&format!(" other than {}", refused.join(" and ")));
                }
                let implied = if required.is_empty() {
                    format!("complete, or {gaps}")
                } else {
                    gaps
                };
                Err(format!(
                    "{BINARY_IDENTITY} is {}, but the input implies {implied}{}",
                    shown(state),
                    if *name_and_hash_only && !*any_returns {
                        ", or out of scope (ADR-010)"
                    } else {
                        ""
                    }
                ))
            }
        }
    }
}

/// What `i`'s read implies for `binary.identity` (spec §5, S1): the shared rule the engine records
/// and `Session::validate` checks. `Err` for an input that cannot be judged: one B9 refuses
/// (including an input over `binary_bytes` without the one `binary.container` entry B9 admits),
/// or an ELF with facts in a session without a `binary_scan_bytes` budget.
///
/// A Go ELF without a section header table must list [`SCAN_NO_SECTIONS`]
/// ([`NoSectionsGap::Must`]): the embedded needle database has Go-function needles, which the
/// scan looks for in `.gopclntab`, so it cannot be `Complete`. Likewise a linked ELF whose
/// loader's dynamic symbols the parse did not read (one of [`DYNSYM_UNREAD_GAPS`] in its facts)
/// must list [`SCAN_NAME_NOT_READ`]: the database has an export needle. Engine tests pin both
/// needles.
pub fn expected_binary_identity(s: &Session, i: &FileInstance) -> Result<ExpectedIdentity, String> {
    let state = container_state(s, i)?;
    if !matches!(
        state,
        CoverageState::Complete | CoverageState::Partial { .. }
    ) {
        return Ok(ExpectedIdentity::Exactly(state));
    }
    let InstanceContent::Read { artifact } = &i.content else {
        return Err("an input not read has no container to scan".to_string());
    };
    let a = s
        .artifacts
        .iter()
        .find(|a| a.id == *artifact)
        .ok_or("its artifact is not in the session")?;
    let kind = match a.format {
        Format::MachO | Format::MachOFat => {
            return Ok(ExpectedIdentity::Exactly(CoverageState::Unsupported {
                what: SCAN_ELF_ONLY.to_string(),
            }))
        }
        Format::Elf { kind } => kind,
        _ => return Ok(ExpectedIdentity::Exactly(state)),
    };
    let parsed = !a.slices.is_empty()
        && a.slices
            .iter()
            .all(|x| s.binaries.iter().any(|b| b.slice == x.id));
    if !parsed {
        return Ok(ExpectedIdentity::Exactly(CoverageState::Partial {
            missing: vec![BINARY_NOT_PARSED.to_string()],
        }));
    }
    let limit = s
        .request
        .budgets
        .get(BINARY_SCAN_BYTES)
        .copied()
        .ok_or_else(|| format!("an ELF input without a {BINARY_SCAN_BYTES} budget"))?;
    let facts: Vec<&BinaryFacts> = a
        .slices
        .iter()
        .filter_map(|x| s.binaries.iter().find(|b| b.slice == x.id))
        .collect();
    let no_sections = facts
        .iter()
        .map(|b| no_sections_gap(b))
        .max()
        .unwrap_or(NoSectionsGap::Never);
    Ok(ExpectedIdentity::Scanned {
        limit,
        name_and_hash_only: a.slices.iter().any(|x| name_and_hash_only(s, &x.id)),
        no_sections,
        exports_unread: facts.iter().any(|b| exports_unread(b, kind)),
        no_gopclntab_admitted: facts.iter().any(|b| no_gopclntab_admitted(b)),
        unread_returns: {
            let mut gaps: Vec<String> = facts.iter().flat_map(|b| unread_returns(b)).collect();
            gaps.sort();
            gaps.dedup();
            gaps
        },
        any_returns: facts.iter().any(|b| any_returns(b)),
    })
}
