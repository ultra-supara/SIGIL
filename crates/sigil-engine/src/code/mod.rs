//! Level C for the capability imports (PR-5a spec): where each is called directly, with the
//! argument values, in x86-64 ELF64 little-endian files. Nothing is executed or mapped: every
//! byte is read with `pread` and charged to `binary_code_bytes` first, and every collection that
//! grows with the input has a limit (spec §4.10).

use std::collections::BTreeSet;

use sigil_model::{BudgetUse, CallSite, Function, BINARY_CODE_BYTES};

pub mod data;
pub(crate) mod decode;
pub(crate) mod fde;
pub(crate) mod image;
pub(crate) mod reader;
pub(crate) mod record;
pub(crate) mod value;

use reader::{Reader, Refusal, MAX_READ};

/// Instructions decoded per function (plan §4.9).
pub const FUNCTION_INSTRUCTIONS: u64 = 200_000;
/// The longest FDE decoded.
pub const FDE_BYTES: u64 = 16 << 20;
/// Times one block is processed before its values are given up.
pub const VALUE_PASSES: u32 = 32;
/// The longest constant string read (plan §4.9).
pub const STRING_BYTES: u64 = 4096;

/// The code budgets of one artifact (spec §4.10). `bytes` is `binary_code_bytes`; the others are
/// the aggregate limits, constants outside tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeBudgets {
    pub bytes: u64,
    pub references: usize,
    /// FDEs read from `.eh_frame`.
    pub fdes: usize,
    /// GOT slots (`JUMP_SLOT`/`GLOB_DAT` addresses) collected (P1-2): past it the run stops, and
    /// the slots not collected are absent from the image.
    pub slots: usize,
    /// A relocatable object's relocations read, on code and on `.eh_frame` (review C1): past it
    /// the run stops, and the relocations not read are absent from the image.
    pub relocations: usize,
    pub instructions: u64,
    pub call_sites: usize,
    pub gaps: usize,
}

impl Default for CodeBudgets {
    fn default() -> Self {
        CodeBudgets {
            bytes: 256 << 20,
            references: 65_536,
            fdes: 1 << 20,
            slots: 1 << 20,
            relocations: 1 << 20,
            instructions: 4_000_000,
            call_sites: 65_536,
            gaps: 256,
        }
    }
}

/// What code analysis gave for one slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeOutcome {
    /// Analyzed: the recorded facts, the gaps (sorted), and the `binary_code_bytes` use.
    Analyzed {
        functions: Vec<Function>,
        call_sites: Vec<CallSite>,
        gaps: Vec<String>,
        budget: BudgetUse,
    },
    /// Not an x86-64 ELF64 little-endian slice.
    Unsupported,
}

/// The gaps and limits of one artifact's analysis.
// Used outside tests from Task 11 (`analyze`); until then only tests construct it.
#[allow(dead_code)]
pub(crate) struct Run {
    pub budgets: CodeBudgets,
    gaps: BTreeSet<String>,
    more: u64,
    stopped: bool,
    /// Instructions decoded so far, over all functions.
    pub instructions: u64,
}

// Used outside tests from Task 11 (`analyze`); until then only tests construct it.
#[allow(dead_code)]
impl Run {
    pub fn new(budgets: CodeBudgets) -> Run {
        Run {
            budgets,
            gaps: BTreeSet::new(),
            more: 0,
            stopped: false,
            instructions: 0,
        }
    }

    /// Records a gap. A gap already listed is not recorded again. Past `budgets.gaps` listed
    /// ones, it is counted in `more` instead: every such call counts, a repeat of a gap not
    /// listed included.
    pub fn gap(&mut self, gap: String) {
        if self.gaps.contains(&gap) {
            return;
        }
        if self.gaps.len() < self.budgets.gaps {
            self.gaps.insert(gap);
        } else {
            self.more = self.more.saturating_add(1);
        }
    }

    /// A gap listed whatever the count. Only for a small fixed set of strings: the limits, and
    /// `binary_code_bytes` exceeded. So the listed gaps can pass `budgets.gaps` by those, plus
    /// the line counting `more`.
    pub fn gap_always(&mut self, gap: String) {
        self.gaps.insert(gap);
    }

    /// An aggregate limit was reached: listed, and the analysis ends in order.
    pub fn limit(&mut self, what: &str, n: u64) {
        self.gap_always(format!("code: {what} limit {n} reached"));
        self.stopped = true;
    }

    /// Whether a limit or the read budget stopped the analysis.
    pub fn stopped(&self) -> bool {
        self.stopped
    }

    /// Records why `reader` refused a read of `what`. The budget stops the run; any other
    /// refusal is a gap, under the cap.
    pub fn refusal(&mut self, why: Refusal, what: &str, reader: &Reader<'_>) {
        match why {
            Refusal::Budget => {
                let limit = reader.limit();
                self.gap_always(format!("{BINARY_CODE_BYTES}: {limit} exceeded"));
                self.stopped = true;
            }
            Refusal::OutsideFile => self.gap(format!("code: {what}: outside the file")),
            Refusal::Io => self.gap(format!("code: {what}: read error")),
            Refusal::TooLarge(len) => self.gap(format!(
                "code: {what}: a read of {len} bytes over the {} MiB read limit",
                MAX_READ >> 20
            )),
        }
    }

    /// The listed gaps, sorted, with the count of the rest.
    pub fn into_gaps(self) -> Vec<String> {
        listed(self.gaps.into_iter(), self.more)
    }

    /// What [`Run::into_gaps`] would give, without ending the run (tests only).
    #[cfg(test)]
    pub fn clone_gaps(&self) -> Vec<String> {
        listed(self.gaps.iter().cloned(), self.more)
    }

    /// The outcome, with the reader's use of `binary_code_bytes`.
    pub fn finish(
        self,
        reader: &Reader<'_>,
        functions: Vec<Function>,
        call_sites: Vec<CallSite>,
    ) -> CodeOutcome {
        let budget = BudgetUse {
            budget: BINARY_CODE_BYTES.to_string(),
            used: reader.used(),
            limit: reader.limit(),
        };
        CodeOutcome::Analyzed {
            functions,
            call_sites,
            gaps: self.into_gaps(),
            budget,
        }
    }
}

/// `gaps` (sorted, from the set), with a line counting the `more` calls of [`Run::gap`] past the
/// cap (repeats of gaps not listed included), sorted in.
// Used outside tests from Task 11 (`analyze`); until then only tests construct it.
#[allow(dead_code)]
fn listed(gaps: impl Iterator<Item = String>, more: u64) -> Vec<String> {
    let mut gaps: Vec<String> = gaps.collect();
    if more > 0 {
        gaps.push(format!("code: {more} more gaps not listed"));
        gaps.sort();
    }
    gaps
}

/// The integration tests' ELF builder (`tests/common/elf.rs`), for the unit tests' synthetic files.
#[cfg(test)]
#[path = "../../tests/common/elf.rs"]
pub(crate) mod synth;

#[cfg(test)]
pub(crate) mod testing {
    use std::fs::File;
    use std::path::Path;

    use object::elf::FileHeader64;
    use object::Endianness;

    use super::image::{self, Image};
    use super::reader::Reader;
    use super::{data, CodeBudgets, Run};
    use crate::binary::read::{Bounded, Budgeted};
    use crate::binary::{elf, BinaryBudgets};

    /// Builds the image of a fixture of `tests/fixtures/code/` and passes it to `f`.
    pub fn with_image<T>(
        fixture: &str,
        budgets: CodeBudgets,
        f: impl FnOnce(&Image, &mut Run, &mut Reader<'_>) -> T,
    ) -> T {
        let path = format!(
            "{}/tests/fixtures/code/{fixture}",
            env!("CARGO_MANIFEST_DIR")
        );
        with_image_at(Path::new(&path), budgets, f)
    }

    /// [`with_image`] for the file at `path`. The fixture's kind is told by its file name: every
    /// relocatable fixture ends in `.o`.
    pub fn with_image_at<T>(
        path: &Path,
        budgets: CodeBudgets,
        f: impl FnOnce(&Image, &mut Run, &mut Reader<'_>) -> T,
    ) -> T {
        let file = File::open(path).unwrap();
        let size = file.metadata().unwrap().len();
        let data = Bounded::new(Budgeted::new(&file, size), size, 64 << 20);
        let mut p =
            elf::parts::<_, FileHeader64<Endianness>>(&data, BinaryBudgets::default()).unwrap();
        let sig = data::signatures().unwrap();
        let mut run = Run::new(budgets);
        let mut reader = Reader::new(&file, size, budgets.bytes);
        let img = if path.extension().is_some_and(|e| e == "o") {
            image::relocatable(&mut p.elf, &p.sections, sig, &mut reader, &mut run)
        } else {
            image::linked(
                &mut p.elf,
                &p.sections,
                &p.dynamic,
                sig,
                &mut reader,
                &mut run,
            )
        }
        .unwrap();
        f(&img, &mut run, &mut reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    fn small(gaps: usize) -> CodeBudgets {
        CodeBudgets {
            gaps,
            ..CodeBudgets::default()
        }
    }

    #[test]
    fn gaps_are_listed_up_to_the_limit_then_counted() {
        let mut run = Run::new(small(2));
        for k in 0..5 {
            run.gap(format!("code: g{k}"));
        }
        run.gap("code: g0".to_string()); // a repeat of a listed gap is not counted
        let gaps = run.into_gaps();
        assert_eq!(
            gaps,
            ["code: 3 more gaps not listed", "code: g0", "code: g1"]
        );
    }

    #[test]
    fn a_limit_is_always_listed_and_stops_the_run() {
        let mut run = Run::new(small(1));
        run.gap("code: first".to_string());
        assert!(!run.stopped());
        run.limit("references", 65_536);
        assert!(run.stopped());
        assert!(run
            .into_gaps()
            .contains(&"code: references limit 65536 reached".to_string()));
    }

    #[test]
    fn the_defaults_are_the_spec_values() {
        let b = CodeBudgets::default();
        assert_eq!(
            (
                b.bytes,
                b.references,
                b.fdes,
                b.instructions,
                b.call_sites,
                b.gaps,
                b.slots,
                b.relocations
            ),
            (
                256 << 20,
                65_536,
                1 << 20,
                4_000_000,
                65_536,
                256,
                1 << 20,
                1 << 20
            )
        );
    }

    fn eight_bytes() -> File {
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(&[0; 8]).unwrap();
        f
    }

    #[test]
    fn the_budget_refusal_is_listed_exactly_and_stops_the_run() {
        let f = eight_bytes();
        let mut reader = Reader::new(&f, 8, 6);
        let mut run = Run::new(small(0)); // no room for gaps: still listed
        let why = reader.read(0, 8).unwrap_err();
        assert_eq!(why, Refusal::Budget);
        run.refusal(why, ".eh_frame", &reader);
        assert!(run.stopped());
        assert_eq!(run.into_gaps(), ["binary_code_bytes: 6 exceeded"]);
    }

    #[test]
    fn other_refusals_are_capped_gaps_that_do_not_stop_the_run() {
        let f = eight_bytes();
        let reader = Reader::new(&f, 8, 6);
        let mut run = Run::new(CodeBudgets::default());
        run.refusal(Refusal::OutsideFile, "string", &reader);
        run.refusal(Refusal::Io, ".text", &reader);
        run.refusal(Refusal::TooLarge(MAX_READ + 1), ".eh_frame", &reader);
        assert!(!run.stopped());
        assert_eq!(
            run.into_gaps(),
            [
                "code: .eh_frame: a read of 67108865 bytes over the 64 MiB read limit",
                "code: .text: read error",
                "code: string: outside the file",
            ]
        );

        let mut run = Run::new(small(1));
        run.refusal(Refusal::Io, ".text", &reader);
        run.refusal(Refusal::TooLarge(MAX_READ + 1), ".eh_frame", &reader);
        assert!(!run.stopped());
        assert_eq!(
            run.into_gaps(),
            ["code: .text: read error", "code: 1 more gaps not listed"]
        );
    }

    #[test]
    fn finish_reports_the_reader_use_and_sorted_gaps() {
        let f = eight_bytes();
        let mut reader = Reader::new(&f, 8, 100);
        reader.read(0, 4).unwrap();
        let mut run = Run::new(small(2));
        for gap in ["code: z", "code: b", "code: c"] {
            run.gap(gap.to_string());
        }
        assert_eq!(
            run.finish(&reader, vec![], vec![]),
            CodeOutcome::Analyzed {
                functions: vec![],
                call_sites: vec![],
                gaps: vec![
                    "code: 1 more gaps not listed".to_string(),
                    "code: b".to_string(),
                    "code: z".to_string(),
                ],
                budget: BudgetUse {
                    budget: "binary_code_bytes".to_string(),
                    used: 4,
                    limit: 100,
                },
            }
        );
    }
}
