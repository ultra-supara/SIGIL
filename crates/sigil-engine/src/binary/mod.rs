//! Binary analysis (plan §4.6.3): ELF and Mach-O container facts, all read with `pread` through a
//! budget. Nothing is executed, loaded, or mapped.

pub mod data;
pub mod elf;
pub mod goinfo;
pub mod header;
pub mod macho;
pub mod needles;
pub mod read;
pub mod returns;
pub mod scan;
pub mod vaddr;

use std::fs::File;

use sigil_model::{Arch, ContainerFacts, Format, GoBuildInfo, Sha256Hex};

use crate::code::{ArtifactAnalysis, CodeBudgets, CodeOutcome};
use scan::{ScanOutcome, Sought};

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
    /// Descriptor enumeration, kept separate from individual container diagnostics.
    pub code_inventory: sigil_model::CodeSliceInventory,
}

/// Probe the same ELF and Mach-O recognition rules used by [`parse_artifact`], without code
/// analysis or retaining container facts. `prefix` must contain the first 64 bytes, or the whole
/// file when shorter. Mach-O recognition uses the supplied parser allocation budget.
///
/// Code collection uses [`probe_multiarch`] instead, to account for and limit discovery I/O.
pub fn recognizes_multiarch(file: &File, size: u64, prefix: &[u8], parse_bytes: u64) -> bool {
    if let Some((_, arch)) = header::read(prefix) {
        return arch == Arch::Aarch64;
    }
    macho::recognize_file(file, size, prefix, parse_bytes)
}

/// Result of a discovery probe. An absent recognition result means the I/O limit was reached
/// or an I/O error prevented a reliable decision; it must not be treated as a legacy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiarchProbe {
    pub recognized: Option<bool>,
    /// Actual bytes returned by reads made by this probe, including reads before failure.
    pub bytes_read: u64,
}

/// Probe using a strict additional I/O limit. The caller must also account for the prefix read.
/// This function does not itself establish file stability.
pub fn probe_multiarch(
    file: &File,
    size: u64,
    prefix: &[u8],
    parse_bytes: u64,
    io_limit: u64,
) -> MultiarchProbe {
    if let Some((_, arch)) = header::read(prefix) {
        return MultiarchProbe {
            recognized: Some(arch == Arch::Aarch64),
            bytes_read: 0,
        };
    }
    macho::probe_file(file, size, prefix, parse_bytes, io_limit)
}

/// Parses the ELF content of `file` (of `size` bytes, from the read's `fstat`), and analyzes its
/// code on the same fd when `budgets.code` asks for it. Never fails: what cannot be read is a gap.
/// No signature scan: [`parse_artifact`] scans with the needles it is given.
pub fn parse(file: &File, size: u64, budgets: BinaryBudgets) -> Parsed {
    parse_elf(file, size, budgets, None, false)
}

/// [`parse`], and with `sought` the signature scan on the same fd (PR-4c-2a, PR-4c-2b).
fn parse_elf(
    file: &File,
    size: u64,
    budgets: BinaryBudgets,
    sought: Option<Sought<'_>>,
    multiarch: bool,
) -> Parsed {
    let data = read::Bounded::new(read::Budgeted::new(file, size), size, budgets.parse_bytes);
    let mut analysis = budgets.code.map(|b| {
        if multiarch {
            ArtifactAnalysis::new(file, size, b)
        } else {
            ArtifactAnalysis::legacy(file, size, b)
        }
    });
    elf::parse_with_analysis(
        &data,
        budgets,
        Some((file, size)),
        sought,
        analysis.as_mut(),
    )
}

/// Parses a recognized ELF or Mach-O artifact. A recognized but malformed Mach-O is returned
/// with no slices, so callers record a partial inspection rather than treating it as unsupported.
/// With `sought`, an ELF artifact is scanned for it (PR-4c-2a, PR-4c-2b); a Mach-O never is.
pub fn parse_artifact(
    file: &File,
    size: u64,
    artifact_sha256: &Sha256Hex,
    prefix: &[u8],
    budgets: BinaryBudgets,
    sought: Option<Sought<'_>>,
) -> Option<ParsedArtifact> {
    parse_artifact_mode(file, size, artifact_sha256, prefix, budgets, sought, false)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn parse_artifact_mode(
    file: &File,
    size: u64,
    artifact_sha256: &Sha256Hex,
    prefix: &[u8],
    budgets: BinaryBudgets,
    sought: Option<Sought<'_>>,
    multiarch: bool,
) -> Option<ParsedArtifact> {
    if let Some((kind, arch)) = header::read(prefix) {
        let parsed = parse_elf(file, size, budgets, sought, multiarch);
        return Some(ParsedArtifact {
            format: Format::Elf { kind },
            code_inventory: if matches!(&parsed.container, ContainerFacts::Elf(e) if e.abi.is_none())
            {
                sigil_model::CodeSliceInventory::Partial {
                    missing: vec![sigil_model::code_coverage::CODE_INVENTORY_INCOMPLETE.into()],
                }
            } else {
                sigil_model::CodeSliceInventory::Complete
            },
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
