//! Binary analysis (plan §4.6.3): the ELF header (`header`), the bounded reader (`read`), and the
//! container facts (`elf`, `data`, `goinfo`), all read with `pread` through a budget. Nothing is
//! executed, loaded, or mapped.

pub mod data;
pub mod elf;
pub mod goinfo;
pub mod header;
pub mod read;
pub mod vaddr;

use std::fs::File;

use sigil_model::{ContainerFacts, GoBuildInfo};

/// Budgets of one artifact's parse, recorded as `binary_parse_bytes` and `binary_imports`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BinaryBudgets {
    /// Bytes the parser may allocate for its input cache (spec §4.2).
    pub parse_bytes: u64,
    /// Imports kept per slice.
    pub imports: u64,
}

impl Default for BinaryBudgets {
    fn default() -> Self {
        BinaryBudgets {
            parse_bytes: 64 << 20,
            imports: 4096,
        }
    }
}

/// One artifact's facts and gaps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub container: ContainerFacts,
    pub go: Option<GoBuildInfo>,
    pub gaps: Vec<String>,
}

/// Parses the ELF content of `file` (of `size` bytes, from the read's `fstat`). Never fails:
/// what cannot be read is a gap.
pub fn parse(file: &File, size: u64, budgets: BinaryBudgets) -> Parsed {
    let data = read::Bounded::new(read::Budgeted::new(file, size), size, budgets.parse_bytes);
    elf::parse(&data, budgets)
}
