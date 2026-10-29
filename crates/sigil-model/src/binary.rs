//! Container facts of a binary slice (PR-4b-1; plan §4.6.3).
//!
//! What a binary's own bytes say: its container header, names, declared dependencies, search
//! paths, notes, symbol counts and imports, a few known embedded values, and Go build info. They
//! are observations, not identity: `ComponentClaim`s (4c) are built from them. Each fact is read
//! in full, confirmed absent, or listed in `gaps`.

use serde::{Deserialize, Serialize};

use crate::evidence::Loc;
use crate::id::{FeatureKey, SliceId};
use crate::text::UntrustedText;

/// The container analysis: what was read and what was not (scope `Root(install)`).
pub const ARTIFACTS_CONTAINER: &str = "artifacts.container";

/// The signature scan of the install's binaries (PR-4c-2a; scope `Root(install)`): every scan
/// the signature database asks for was done within its budget.
pub const ARTIFACTS_IDENTITY: &str = "artifacts.identity";

/// The gap of a fat Mach-O slice whose own header names another architecture than its entry in
/// the fat table (B2).
pub const FAT_CPU_MISMATCH_GAP: &str = "fat slice: CPU type or subtype disagrees with its header";

/// The gap of every slice of a fat Mach-O whose table lists one architecture twice (B2). lipo
/// refuses to build such a file, and dyld loads only one of the two.
pub const FAT_DUPLICATE_ARCH_GAP: &str = "fat header: an architecture is listed twice";

/// The gap of a slice with more imports than `binary_imports`, before its limit
/// ([`imports_over_gap`]): only the first `binary_imports` imports, in sorted order, are kept.
pub const IMPORTS_OVER_GAP: &str = "imports: over binary_imports";

/// [`IMPORTS_OVER_GAP`] as the parser records it: `imports: over binary_imports <limit>`.
pub fn imports_over_gap(limit: u64) -> String {
    format!("{IMPORTS_OVER_GAP} {limit}")
}

/// The gap of an ELF whose loader has dynamic symbols (`DT_SYMTAB`) and whose file has no
/// section header table, so no `.dynsym` to read them by.
pub const SYMBOLS_NO_SECTIONS_GAP: &str = "symbols: no section header table";

/// The gap of an ELF whose loader has dynamic symbols (`DT_SYMTAB`) and whose section header
/// table cannot be read.
pub const SYMBOLS_UNREADABLE_SECTIONS_GAP: &str = "symbols: no readable section header table";

/// The gap of a linked ELF whose loader has dynamic symbols (`DT_SYMTAB`) and whose section
/// header table has no `SHT_DYNSYM` section with entries.
pub const SYMBOLS_NO_DYNSYM_GAP: &str = "symbols: no SHT_DYNSYM";

/// The gaps of a linked ELF whose loader's dynamic symbols the parse has no `.dynsym` for: the
/// signature scan cannot look at its exports (PR-4c-2a; `expected_binary_identity`).
pub const DYNSYM_UNREAD_GAPS: [&str; 3] = [
    SYMBOLS_NO_SECTIONS_GAP,
    SYMBOLS_UNREADABLE_SECTIONS_GAP,
    SYMBOLS_NO_DYNSYM_GAP,
];

/// The capability bits of a Mach-O CPU subtype (`CPU_SUBTYPE_MASK`).
const CPU_SUBTYPE_MASK: u32 = 0xff00_0000;

/// A Mach-O architecture as lipo compares two: the CPU type, and the subtype without its
/// capability bits.
pub fn macho_architecture(cpu_type: i32, cpu_subtype: i32) -> (i32, u32) {
    (cpu_type, cpu_subtype as u32 & !CPU_SUBTYPE_MASK)
}

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

impl BinaryFacts {
    /// Whether its import list was cut short at `binary_imports`: a gap is [`imports_over_gap`]
    /// of some limit. Then the imports past the cut, and their capability hints, are not known.
    pub fn imports_cut_short(&self) -> bool {
        self.gaps.iter().any(|gap| {
            gap.strip_prefix(IMPORTS_OVER_GAP)
                .and_then(|rest| rest.strip_prefix(' '))
                .is_some_and(|limit| !limit.is_empty() && limit.bytes().all(|b| b.is_ascii_digit()))
        })
    }
}

/// The container format's facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ContainerFacts {
    Elf(ElfFacts),
    MachO(MachOFacts),
}

/// Mach-O header and dynamic-loader facts of one slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachOFacts {
    pub is_64: bool,
    pub cpu_type: i32,
    pub cpu_subtype: i32,
    pub fat_cpu_type: Option<i32>,
    pub fat_cpu_subtype: Option<i32>,
    pub fat_alignment: Option<u32>,
    pub file_type: u32,
    pub flags: u32,
    pub uuid: Option<String>,
    pub id_dylib: Option<UntrustedText>,
    /// `LC_LOAD_*_DYLIB` names, in load-command order. A dylib-loading command whose name is not
    /// kept has no entry, and its gap starts with [`LOAD_DYLIB_GAP_PREFIX`]: without one, the
    /// list is in library-ordinal order (its n-th name is ordinal n's).
    pub load_dylibs: Vec<UntrustedText>,
    /// `LC_RPATH` values, in load-command order.
    pub rpaths: Vec<UntrustedText>,
    pub dylinker: Option<UntrustedText>,
    /// What dyld binds (PR-4c-3b): the imports of `LC_DYLD_CHAINED_FIXUPS`, or the names of the
    /// bind and lazy-bind opcodes of `LC_DYLD_INFO(_ONLY)`; for an object file (`MH_OBJECT`), the
    /// undefined external symbols of `LC_SYMTAB`, left for the linker. Sorted by
    /// `(name, library, weak)`, unique, at most `binary_imports`. Optional on read (empty when
    /// missing); written only when non-empty, so facts without one keep their bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub imports: Vec<MachOImport>,
}

/// The dylib whose names are the POSIX ones (PR-4c-3b): `libSystem`, which re-exports the C
/// library and the system calls.
pub const LIBSYSTEM: &str = "/usr/lib/libSystem.B.dylib";

/// The dylib whose names are libc++'s (#105): an import bound to it is looked up for the `cxx.*`
/// names only.
pub const LIBCXX: &str = "/usr/lib/libc++.1.dylib";

/// The start of a Mach-O slice's gap for a dylib-loading command whose name is not in
/// `load_dylibs`: not read (`load dylib: <why>`, `load dylib: command is too short`), or over the
/// limit of names (`load dylib: over 1024 names`). The command still takes its library ordinal.
pub const LOAD_DYLIB_GAP_PREFIX: &str = "load dylib: ";

/// The file type of a Mach-O object file (`MH_OBJECT`): no loader reads it.
pub const MH_OBJECT: u32 = 1;

/// A name a Mach-O slice imports (PR-4c-3b).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachOImport {
    /// As the file has it, with its leading `_` (`_connect`).
    pub name: UntrustedText,
    pub library: MachOLibrary,
    /// `weak_import` (chained fixups), `BIND_SYMBOL_FLAGS_WEAK_IMPORT` (bind opcodes), or
    /// `N_WEAK_REF` (an object file's symbol).
    pub weak: bool,
}

/// Where a Mach-O import is looked up: its library ordinal, or an object file's linker.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum MachOLibrary {
    /// Library ordinal `ordinal` (from 1): the dylib of that dylib-loading command, counted in
    /// load-command order. `name` is `None` when that command's name was not kept in
    /// `load_dylibs` (not read, or over the limit of names); its gap starts with
    /// [`LOAD_DYLIB_GAP_PREFIX`].
    Dylib {
        ordinal: u32,
        name: Option<UntrustedText>,
    },
    /// Ordinal 0: this image.
    SelfImage,
    /// Ordinal -1: the main executable.
    MainExecutable,
    /// Ordinal -2: every loaded image, in load order.
    FlatLookup,
    /// Ordinal -3: a weak definition, coalesced by name.
    WeakLookup,
    /// An object file's undefined symbol: the linker resolves it.
    Unbound,
}

/// Which capability hints a Mach-O import can support, by its library (PR-4c-3b, #105). Ordered:
/// of two imports of one name, the greater decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LookedUp {
    /// Not looked up: another dylib's import, this image's, the main executable's, a weak
    /// lookup's, or one whose dylib's name was not kept. Another dylib's `_connect` is that
    /// dylib's function, not POSIX `connect`.
    No,
    /// Bound to [`LIBCXX`]: only a name of a `cxx.*` feature.
    Cxx,
    /// Bound to [`LIBSYSTEM`], found by flat lookup, or an object file's: any name.
    All,
}

impl LookedUp {
    /// Whether an import looked up so can support a hint of `feature`.
    pub fn admits(self, feature: &FeatureKey) -> bool {
        match self {
            LookedUp::All => true,
            LookedUp::Cxx => feature.as_str().starts_with("cxx."),
            LookedUp::No => false,
        }
    }
}

impl MachOLibrary {
    /// How an import of this library is looked up in the capability table (PR-4c-3b, #105).
    pub fn looked_up(&self) -> LookedUp {
        match self {
            MachOLibrary::Dylib {
                name: Some(name), ..
            } if name.as_bytes() == LIBSYSTEM.as_bytes() => LookedUp::All,
            MachOLibrary::Dylib {
                name: Some(name), ..
            } if name.as_bytes() == LIBCXX.as_bytes() => LookedUp::Cxx,
            MachOLibrary::FlatLookup | MachOLibrary::Unbound => LookedUp::All,
            _ => LookedUp::No,
        }
    }
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
    /// Defined dynamic symbols: `GLOBAL`/`WEAK`/`GNU_UNIQUE`, `DEFAULT`/`PROTECTED`. For a
    /// relocatable object (`ET_REL`), the same, counted in its `.symtab`.
    pub exports: u64,
    /// Undefined dynamic symbols, `GLOBAL` or `WEAK`: what the loader resolves. For a relocatable
    /// object (`ET_REL`), the undefined symbols of its symbol table: what the linker resolves,
    /// not the final program's imports. Sorted by `(name, version)`, unique.
    pub imports: Vec<ElfImport>,
    /// The known data symbols present (plan §4.4), sorted by symbol. In a relocatable object
    /// (`ET_REL`) each is `Unknown`, with its gap: its data is not linked yet.
    pub data: Vec<DataSymbol>,
    /// What the known exported functions return (PR-4c-2b), sorted by function: one entry per
    /// function the signature scan found among the exports, read without running it. An
    /// `Unknown` one's gap is in the identity coverage ([`returned_value_gap`]), never in `gaps`.
    /// Optional on read (empty when missing); written only when non-empty, so facts without one
    /// keep their bytes.
    ///
    /// [`returned_value_gap`]: crate::binary_input::returned_value_gap
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub returns: Vec<FunctionReturn>,
}

/// An undefined symbol: a dynamic import, or for a relocatable object (`ET_REL`) an undefined
/// symbol of its `.symtab`, left for the linker.
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

/// What one known exported function returns (PR-4c-2b): the constant string whose address it
/// returns, read without running it, or `Unknown` with the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionReturn {
    /// A function the component database reads (`read = "function"`), e.g. `ggml_version`.
    pub function: String,
    /// `Text` or `Unknown`, never `Int`.
    pub value: DataValue,
    /// The function (`Loc::Symbol`), then, for a string, where it was read (`Loc::VAddr`).
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
