//! A binary inspection's inputs (`sigil binary inspect`; PR-4b-2a spec §4.3, §5).
//!
//! Each input is its own scan root, `binary-<n>` in argument order, whose path is the file. Its
//! one instance gets exactly one `binary.container` coverage, whose state is the one
//! [`expected_binary_container`] derives from the instance, its artifact, and its facts. The
//! engine records that state, and `Session::validate` (B9) requires it.

use crate::artifact::{FileInstance, Format, InstanceContent, NotReadReason, Stability};
use crate::coverage::CoverageState;
use crate::id::RootId;
use crate::session::Session;
use crate::text::UntrustedText;

/// The check of a binary inspection: one entry per input, scope `Instance`.
pub const BINARY_CONTAINER: &str = "binary.container";
/// Hashing reads, over all inputs.
pub const BINARY_BYTES: &str = "binary_bytes";
/// `binary.container`'s `Unsupported` reason.
pub const BINARY_UNSUPPORTED: &str = "not an ELF executable, shared object, or relocatable object";
/// `binary.container`'s `Error` for a read that saw a change.
pub const BINARY_CHANGED: &str = "changed during the read";
/// `binary.container`'s `Error` for a file gone after its read.
pub const BINARY_VANISHED: &str = "vanished during the read";
/// A `Partial` entry: an ELF slice without facts.
pub const BINARY_NOT_PARSED: &str = "not parsed";
/// Binary roots are `binary-<n>`.
pub const BINARY_ROOT_PREFIX: &str = "binary-";

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

/// The `binary.container` state an input implies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedContainer {
    /// This state, exactly.
    Exactly(CoverageState),
    /// `BudgetExceeded` over `binary_bytes` with this limit; its `used` is the engine's count.
    OverBytes { limit: u64 },
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
    if !matches!(a.format, Format::Elf { .. }) {
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
