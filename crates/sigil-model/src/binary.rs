//! Container facts of a binary slice (PR-4b-1; plan §4.6.3).
//!
//! What a binary's own bytes say: its interpreter, names, declared dependencies, search paths,
//! notes, symbol counts and imports, a few known embedded values, and Go build info. They are
//! observations, not identity: `ComponentClaim`s (4c) are built from them. Each fact is read in
//! full, confirmed absent, or listed in `gaps`.

use serde::{Deserialize, Serialize};

use crate::evidence::Loc;
use crate::id::SliceId;
use crate::text::UntrustedText;

/// The container analysis: what was read and what was not (scope `Root(install)`).
pub const ARTIFACTS_CONTAINER: &str = "artifacts.container";

/// The facts of one slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryFacts {
    pub slice: SliceId,
    pub container: ContainerFacts,
    /// `None`: no Go build info was found after a full search, or the search did not finish
    /// (then `gaps` says so).
    pub go: Option<GoBuildInfo>,
    /// What could not be read, one entry per gap (`"<what>: <why>"`). Empty: every fact is read
    /// in full or confirmed absent.
    pub gaps: Vec<String>,
}

/// The container format's facts. 4b-2 adds Mach-O.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ContainerFacts {
    Elf(ElfFacts),
}

/// ELF facts, from the program headers first (what the loader reads), then the sections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElfFacts {
    /// `PT_INTERP`, without its NUL.
    pub interp: Option<UntrustedText>,
    /// `DT_SONAME`.
    pub soname: Option<UntrustedText>,
    /// `DT_NEEDED`, in `PT_DYNAMIC` order. Never sorted: the order is evidence.
    pub needed: Vec<UntrustedText>,
    /// `DT_RPATH` values as written (not split on `:`), in order.
    pub rpath: Vec<UntrustedText>,
    /// `DT_RUNPATH` values as written, in order.
    pub runpath: Vec<UntrustedText>,
    /// `NT_GNU_BUILD_ID`, lowercase hex.
    pub build_id: Option<String>,
    /// `.comment`, split on NUL, empty entries dropped, in order.
    pub comment: Vec<UntrustedText>,
    /// Whether there is no `SHT_SYMTAB` section; `None` when the section header table could not
    /// be inspected in full (then `gaps` has a `sections: ` entry).
    pub stripped: Option<bool>,
    /// Defined dynamic symbols: `GLOBAL`/`WEAK`/`GNU_UNIQUE`, `DEFAULT`/`PROTECTED`.
    pub exports: u64,
    /// Undefined dynamic symbols, `GLOBAL` or `WEAK`. Sorted by `(name, version)`, unique.
    pub imports: Vec<ElfImport>,
    /// The known data symbols present (plan §4.4), sorted by symbol.
    pub data: Vec<DataSymbol>,
}

/// An undefined dynamic symbol.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElfImport {
    pub name: UntrustedText,
    /// The version it needs (`.gnu.version_r`), e.g. `GLIBC_2.34`.
    pub version: Option<UntrustedText>,
    pub weak: bool,
}

/// One known data symbol and its value after loading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataSymbol {
    /// A name from the engine's built-in list (e.g. `LLAMA_COMMIT`).
    pub symbol: String,
    pub value: DataValue,
    /// The symbol (`Loc::Symbol`), then, for a string, where it was read (`Loc::VAddr`).
    pub at: Vec<Loc>,
}

/// A data symbol's value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum DataValue {
    Text(UntrustedText),
    Int(i64),
    /// Present, but its value after loading is not known. `gaps` has `"<symbol>: <why>"`.
    Unknown {
        why: String,
    },
}

/// Go build info (Go's `debug/buildinfo`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoBuildInfo {
    /// Where the header was found: the `.go.buildinfo` section, or a virtual address.
    pub at: Loc,
    pub version: UntrustedText,
    pub path: Option<UntrustedText>,
    pub main: Option<GoModule>,
    /// `dep` lines in order, each with its `=>` replacement.
    pub deps: Vec<GoModule>,
    /// `build` lines in order, unquoted.
    pub settings: Vec<GoSetting>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoModule {
    pub path: UntrustedText,
    pub version: UntrustedText,
    pub sum: Option<UntrustedText>,
    pub replace: Option<Box<GoModule>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoSetting {
    pub key: UntrustedText,
    pub value: UntrustedText,
}
