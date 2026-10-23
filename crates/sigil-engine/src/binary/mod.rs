//! Binary analysis (plan §4.6.3): ELF and Mach-O container facts, all read with `pread` through a
//! budget. Nothing is executed, loaded, or mapped.

pub mod data;
pub mod elf;
pub mod goinfo;
pub mod header;
pub mod macho;
pub mod needles;
pub mod read;
pub mod scan;
pub mod vaddr;

use std::fs::File;

use sigil_model::{Arch, ContainerFacts, Format, GoBuildInfo, Sha256Hex};

use crate::code::{CodeBudgets, CodeOutcome};
use needles::Needles;
use scan::ScanOutcome;

/// Budgets of one artifact's parse, recorded as `binary_parse_bytes`, `binary_imports`, and
/// `binary_scan_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BinaryBudgets {
    /// Bytes the parser may allocate for its input cache (spec §4.2).
    pub parse_bytes: u64,
    /// Imports kept per slice.
    pub imports: u64,
    /// Bytes the signature scan reads (PR-4c-2a spec §4).
    pub scan_bytes: u64,
    /// The code budgets when code is analyzed (PR-5a spec §4.1); `None`: no code analysis.
    pub code: Option<CodeBudgets>,
}

impl Default for BinaryBudgets {
    fn default() -> Self {
        BinaryBudgets {
            parse_bytes: 64 << 20,
            imports: 4096,
            scan_bytes: 64 << 20,
            code: None,
        }
    }
}

/// One parsed slice's container facts and gaps, and its code analysis when it was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub container: ContainerFacts,
    pub go: Option<GoBuildInfo>,
    pub gaps: Vec<String>,
    pub code: Option<CodeOutcome>,
    /// The signature scan, when needles were given (PR-4c-2a).
    pub scan: Option<ScanOutcome>,
}

/// One parsed architecture slice of an artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSlice {
    pub offset: u64,
    pub size: u64,
    pub arch: Arch,
    pub sha256: Sha256Hex,
    pub container: Option<ContainerFacts>,
    pub go: Option<GoBuildInfo>,
    /// The container's gaps. The code's are its own ([`CodeOutcome::Analyzed`]).
    pub gaps: Vec<String>,
    /// The code analysis, when `BinaryBudgets.code` asked for it.
    pub code: Option<CodeOutcome>,
    /// The signature scan (PR-4c-2a): of an ELF slice parsed with needles, or marked
    /// `NameAndHashOnly` by the read. `None` for a Mach-O slice.
    pub scan: Option<ScanOutcome>,
}

/// The format and parsed slices of one artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedArtifact {
    pub format: Format,
    pub slices: Vec<ParsedSlice>,
}

/// Parses the ELF content of `file` (of `size` bytes, from the read's `fstat`), and analyzes its
/// code on the same fd when `budgets.code` asks for it. Never fails: what cannot be read is a gap.
/// No signature scan: [`parse_artifact`] scans with the needles it is given.
pub fn parse(file: &File, size: u64, budgets: BinaryBudgets) -> Parsed {
    parse_elf(file, size, budgets, None)
}

/// [`parse`], and with `needles` the signature scan on the same fd (PR-4c-2a).
fn parse_elf(file: &File, size: u64, budgets: BinaryBudgets, needles: Option<&Needles>) -> Parsed {
    let data = read::Bounded::new(read::Budgeted::new(file, size), size, budgets.parse_bytes);
    elf::parse(&data, budgets, Some((file, size)), needles)
}

/// Parses a recognized ELF or Mach-O artifact. A recognized but malformed Mach-O is returned
/// with no slices, so callers record a partial inspection rather than treating it as unsupported.
/// With `needles`, an ELF artifact is scanned for them (PR-4c-2a); a Mach-O never is.
pub fn parse_artifact(
    file: &File,
    size: u64,
    artifact_sha256: &Sha256Hex,
    prefix: &[u8],
    budgets: BinaryBudgets,
    needles: Option<&Needles>,
) -> Option<ParsedArtifact> {
    if let Some((kind, arch)) = header::read(prefix) {
        let parsed = parse_elf(file, size, budgets, needles);
        return Some(ParsedArtifact {
            format: Format::Elf { kind },
            slices: vec![ParsedSlice {
                offset: 0,
                size,
                arch,
                sha256: artifact_sha256.clone(),
                container: Some(parsed.container),
                go: parsed.go,
                gaps: parsed.gaps,
                code: parsed.code,
                scan: parsed.scan,
            }],
        });
    }
    macho::parse_artifact(file, size, artifact_sha256, prefix, budgets)
}
