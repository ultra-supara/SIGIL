//! Binary analysis (plan §4.6.3): ELF and Mach-O container facts, all read with `pread` through a
//! budget. Nothing is executed, loaded, or mapped.

pub mod data;
pub mod elf;
pub mod goinfo;
pub mod header;
pub mod macho;
pub mod needles;
pub mod read;
pub mod vaddr;

use std::fs::File;

use sigil_model::{Arch, ContainerFacts, Format, GoBuildInfo, Sha256Hex};

use crate::code::{CodeBudgets, CodeOutcome};

/// Budgets of one artifact's parse, recorded as `binary_parse_bytes` and `binary_imports`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BinaryBudgets {
    /// Bytes the parser may allocate for its input cache (spec §4.2).
    pub parse_bytes: u64,
    /// Imports kept per slice.
    pub imports: u64,
    /// The code budgets when code is analyzed (PR-5a spec §4.1); `None`: no code analysis.
    pub code: Option<CodeBudgets>,
}

impl Default for BinaryBudgets {
    fn default() -> Self {
        BinaryBudgets {
            parse_bytes: 64 << 20,
            imports: 4096,
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
}

/// The format and parsed slices of one artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedArtifact {
    pub format: Format,
    pub slices: Vec<ParsedSlice>,
}

/// Parses the ELF content of `file` (of `size` bytes, from the read's `fstat`), and analyzes its
/// code on the same fd when `budgets.code` asks for it. Never fails: what cannot be read is a gap.
pub fn parse(file: &File, size: u64, budgets: BinaryBudgets) -> Parsed {
    let data = read::Bounded::new(read::Budgeted::new(file, size), size, budgets.parse_bytes);
    elf::parse(&data, budgets, Some((file, size)))
}

/// Parses a recognized ELF or Mach-O artifact. A recognized but malformed Mach-O is returned
/// with no slices, so callers record a partial inspection rather than treating it as unsupported.
pub fn parse_artifact(
    file: &File,
    size: u64,
    artifact_sha256: &Sha256Hex,
    prefix: &[u8],
    budgets: BinaryBudgets,
) -> Option<ParsedArtifact> {
    if let Some((kind, arch)) = header::read(prefix) {
        let parsed = parse(file, size, budgets);
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
            }],
        });
    }
    macho::parse_artifact(file, size, artifact_sha256, prefix, budgets)
}
