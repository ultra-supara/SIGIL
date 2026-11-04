//! Level C for the capability imports (PR-5a spec): where each is called directly, with the
//! argument values, in the bounded x86-64 and AArch64 ELF64 little-endian profiles. Nothing is executed or mapped: every
//! byte is read with `pread` and charged to `binary_code_bytes` first, and every collection that
//! grows with the input has a limit (spec §4.10).

use std::fs::File;

use object::elf;
use object::read::elf::FileHeader;
use object::read::ReadCacheOps;
use object::{Endian, Endianness};
use sigil_model::{BudgetUse, CallSite, Function, BINARY_CODE_BYTES};

use crate::binary::elf::{Dynamic, Elf, Sections};

pub(crate) mod aarch64;
pub mod data;
pub(crate) mod decode;
pub(crate) mod fde;
pub(crate) mod image;
pub(crate) mod macho;
pub(crate) mod reader;
pub(crate) mod record;
pub(crate) mod search;
pub(crate) mod value;

use reader::Reader;
#[cfg(test)]
use reader::{Refusal, MAX_READ};
use record::Recorder;

/// Instructions decoded per function (plan §4.9).
pub const FUNCTION_INSTRUCTIONS: u64 = 200_000;
/// The longest FDE decoded.
pub const FDE_BYTES: u64 = 16 << 20;
/// Times one block is processed before its values are given up (the function fails). Real nested
/// loops need more than 32: in Task 15's survey, 32 left 392 references in 17 files unsettled, 128
/// left 24, and 256 none, at no measurable cost.
pub const VALUE_PASSES: u32 = 256;
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
    /// Register-value steps of all functions together, in every pass of each function's fixpoint
    /// and in the pass that keeps the values its calls need, charged before the work; past it
    /// the run stops, and the function being solved fails. The work is weighted by the size of
    /// the values it touches (`value::size`: a value's members times one more than its levels of
    /// loads):
    /// - an instruction's transfer is 1, plus the size of a set a `mov`/`movzx` copies through
    ///   part of a register (`value::Machine::cost`);
    /// - each predecessor a block's input examines is `value::JOIN_COST`, and each register it
    ///   joins both sizes, or 1 beside an unknown value (`value::join_cost`);
    /// - a compare that must walk two values (their parts separate allocations), in a join or in
    ///   the check that a block's output settled, is both sizes (`value::equal_charged`).
    pub value_steps: u64,
    pub call_sites: usize,
    /// The bytes of symbol names copied into the recorded facts (review I2). A function's call
    /// targets' names count with the call-site limit: past it the run stops, and the function
    /// records nothing. Function and export names are filled only while they fit.
    pub name_bytes: u64,
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
            // 16 times the most real files needed (5,190,166, cuda_v12/libggml-cuda.so, in Task
            // 15's survey), rounded up to a power of two.
            value_steps: 1 << 27,
            call_sites: 65_536,
            name_bytes: 16 << 20,
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
    /// Not an admitted architecture/container ABI.
    Unsupported,
}

/// Owns the charged reader and work limits for one artifact, across slice callbacks.
/// Callbacks receive the same fd reader; unsupported slices never invoke them.
pub(crate) struct ArtifactAnalysis<'f> {
    reader: Reader<'f>,
    run: Run,
    slices: usize,
}

impl<'f> ArtifactAnalysis<'f> {
    /// The multiarchitecture contract: one combined reference cap, one detailed-gap cap.
    /// Create once per artifact and visit supported slices in deterministic descriptor order.
    pub fn new(file: &'f File, size: u64, budgets: CodeBudgets) -> Self {
        let mut run = Run::new(budgets);
        run.legacy_x86 = false;
        Self {
            reader: Reader::new(file, size, budgets.bytes),
            run,
            slices: 0,
        }
    }

    /// Preserve the historical independent text-relocation/search caps for x86-only ELF.
    /// New multiarchitecture dispatch uses `new` or switches before work. Session-wide
    /// mixed x86 selection remains unresolved because recognition follows collection.
    pub fn legacy(file: &'f File, size: u64, budgets: CodeBudgets) -> Self {
        let mut artifact = Self::new(file, size, budgets);
        artifact.run.legacy_x86 = true;
        artifact
    }

    pub fn multiarch(&mut self) {
        self.run.legacy_x86 = false;
    }

    pub fn size(&self) -> u64 {
        self.reader.size()
    }

    pub fn slice(
        &mut self,
        supported: bool,
        analyze: impl FnOnce(&mut Reader<'_>, &mut Run) -> (Vec<Function>, Vec<CallSite>),
    ) -> CodeOutcome {
        if !supported {
            return CodeOutcome::Unsupported;
        }
        let before = self.reader.used();
        let work_before = self.run.work_used();
        let unstarted = self.run.stopped()
            || (self.slices > 0 && self.run.detailed_gaps >= self.run.budgets.gaps);
        let (functions, call_sites) = if unstarted {
            self.run.stopped = true;
            self.run.gap_always(ARTIFACT_EXHAUSTED.to_string());
            (vec![], vec![])
        } else {
            analyze(&mut self.reader, &mut self.run)
        };
        let used = self.reader.used() - before;
        if self.slices > 0
            && self.run.stopped()
            && used == 0
            && self.run.work_used() == work_before
            && functions.is_empty()
            && call_sites.is_empty()
        {
            self.run.gap_always(ARTIFACT_EXHAUSTED.to_string());
        }
        self.slices += 1;
        let gaps = listed(
            std::mem::take(&mut self.run.gaps).into_iter(),
            std::mem::take(&mut self.run.more),
        );
        CodeOutcome::Analyzed {
            functions,
            call_sites,
            gaps,
            budget: BudgetUse {
                budget: BINARY_CODE_BYTES.to_string(),
                used,
                limit: self.reader.limit(),
            },
        }
    }
}

const ARTIFACT_EXHAUSTED: &str = "code: artifact budget exhausted before slice";

mod run;
use run::listed;
pub(crate) use run::{Run, Work};

/// Code analysis of one ELF slice (spec §4): the image, the references, their confirmation, and
/// the names of what was recorded. It runs after the container facts, on the same parse and the
/// same fd, held by the artifact's analysis owner. It never fails: what cannot be
/// analyzed is a gap. Only an x86-64 ELF64 little-endian file is analyzed (R-c).
///
/// R-h: nothing it does reaches the container's facts or gaps.
/// - A section name it cannot read (`Elf::section_named`) is a gap of the code, `code: …`, not of
///   the container, whose list is set aside while the code step runs.
/// - A `binary_parse_bytes` refusal while it runs is the gap `code: binary_parse_bytes
///   exceeded`, unless only names were refused ([`Recorder::fill_names`]): names are not
///   references, and a name left out costs no coverage.
pub(crate) fn analyze<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &mut Elf<'d, R, H>,
    sections: &Sections<'d, R, H>,
    dynamic: &Dynamic,
    analysis: &mut ArtifactAnalysis<'_>,
) -> CodeOutcome {
    let endian = e.endian;
    let supported = e.header.e_machine(endian) == elf::EM_X86_64
        && e.header.is_class_64()
        && endian.is_little_endian();
    analysis.slice(supported, |reader, run| {
        let container = std::mem::take(&mut e.gaps);
        let mut rec = Recorder::default();
        let refusals = e.data.refusals();
        let img = match data::signatures() {
            Err(why) => {
                run.gap_always(format!("code: signatures: {why}"));
                None
            }
            Ok(sig) => {
                let img = if e.header.e_type(endian) == elf::ET_REL {
                    image::relocatable(e, sections, sig, reader, run)
                } else {
                    image::linked(e, sections, dynamic, sig, reader, run)
                };
                // A limit reached while the image was built (slots, relocations, FDEs, the bytes)
                // ends the analysis there: nothing is searched.
                if let Some(img) = img.as_ref().filter(|_| !run.stopped()) {
                    let refs = search::references(img, reader, run);
                    search::confirm(img, refs, sig, reader, run, &mut rec);
                }
                img
            }
        };
        if e.data.refusals() > refusals {
            run.gap_always("code: binary_parse_bytes exceeded".to_string());
        }
        if let Some(img) = &img {
            rec.fill_names(e, sections, img, run);
        }
        for gap in std::mem::replace(&mut e.gaps, container) {
            run.gap(format!("code: {gap}"));
        }
        (rec.functions, rec.call_sites)
    })
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

    fn one_function() -> Function {
        Function {
            id: sigil_model::FnId::new("fn:0x1").unwrap(),
            entry: 1,
            end: 2,
            bounds: sigil_model::BoundsSource::EhFrameFde,
            names: vec![],
        }
    }

    fn analyzed(outcome: CodeOutcome) -> (Vec<Function>, Vec<String>, u64) {
        let CodeOutcome::Analyzed {
            functions,
            gaps,
            budget,
            ..
        } = outcome
        else {
            panic!("unsupported");
        };
        (functions, gaps, budget.used)
    }

    #[test]
    fn slice_loop_byte_budget_preserves_first_facts_and_reports_deltas() {
        let f = eight_bytes();
        let mut artifact = ArtifactAnalysis::new(
            &f,
            8,
            CodeBudgets {
                bytes: 4,
                ..CodeBudgets::default()
            },
        );
        let a = analyzed(artifact.slice(true, |reader, _| {
            reader::read_slice(reader, reader::SliceWindow { base: 0, len: 4 }, 0, 3).unwrap();
            (vec![one_function()], vec![])
        }));
        let b = analyzed(artifact.slice(true, |reader, run| {
            let why = reader::read_slice(reader, reader::SliceWindow { base: 4, len: 4 }, 0, 2)
                .unwrap_err();
            run.refusal(why, "synthetic slice", reader);
            (vec![], vec![])
        }));
        assert_eq!(a, (vec![one_function()], vec![], 3));
        assert!(b.0.is_empty());
        assert!(b
            .1
            .contains(&"code: artifact budget exhausted before slice".to_string()));
        assert_eq!(b.2, 0);
        let c = analyzed(artifact.slice(true, |_, _| {
            panic!("stopped artifact must not start a later slice")
        }));
        assert_eq!(c.2, 0);
        assert_eq!(artifact.reader.used(), 3);
        assert_eq!(
            artifact.slice(false, |_, _| panic!("unsupported")),
            CodeOutcome::Unsupported
        );
    }

    #[test]
    fn a_slice_that_did_work_is_not_reported_as_unstarted() {
        let f = eight_bytes();
        let mut artifact = ArtifactAnalysis::new(
            &f,
            8,
            CodeBudgets {
                references: 4,
                ..CodeBudgets::default()
            },
        );
        artifact.slice(true, |_, run| {
            assert!(run.charge(Work::References, 2));
            (vec![], vec![])
        });
        let second = analyzed(artifact.slice(true, |_, run| {
            assert!(run.charge(Work::References, 1));
            assert!(!run.charge(Work::References, 2));
            (vec![one_function()], vec![])
        }));
        assert_eq!(second.0, [one_function()]);
        assert_eq!(second.1, ["code: references limit 4 reached"]);
    }

    #[test]
    fn gap_limit_is_shared_but_attributed_per_slice() {
        let f = eight_bytes();
        let mut artifact = ArtifactAnalysis::new(&f, 8, small(2));
        let a = analyzed(artifact.slice(true, |_, run| {
            run.gap("code: A".into());
            (vec![], vec![])
        }));
        let b = analyzed(artifact.slice(true, |_, run| {
            run.gap("code: B".into());
            (vec![], vec![])
        }));
        assert_eq!(a.1, ["code: A"]);
        assert_eq!(b.1, ["code: B"]);
        for _ in 2..64 {
            let later =
                analyzed(artifact.slice(true, |_, _| panic!("shared detail allowance exhausted")));
            assert_eq!(later.1, ["code: artifact budget exhausted before slice"]);
            assert_eq!(later.2, 0);
        }
        assert_eq!(
            artifact.slice(false, |_, _| panic!("unsupported")),
            CodeOutcome::Unsupported
        );
    }

    #[test]
    fn later_slice_gap_details_cannot_multiply_the_cap_in_either_mode() {
        let f = eight_bytes();
        for legacy in [false, true] {
            let mut artifact = if legacy {
                ArtifactAnalysis::legacy(&f, 8, small(2))
            } else {
                ArtifactAnalysis::new(&f, 8, small(2))
            };
            artifact.slice(true, |_, run| {
                run.gap("code: A".into());
                (vec![], vec![])
            });
            let second = analyzed(artifact.slice(true, |_, run| {
                for gap in ["code: B", "code: C", "code: D"] {
                    run.gap(gap.into());
                }
                (vec![], vec![])
            }));
            assert_eq!(second.1, ["code: 2 more gaps not listed", "code: B"]);
        }
    }

    fn shared_work_limit(work: Work) {
        let f = eight_bytes();
        let budgets = CodeBudgets {
            references: 4,
            fdes: 4,
            slots: 4,
            relocations: 4,
            instructions: 4,
            value_steps: 4,
            call_sites: 4,
            name_bytes: 4,
            ..CodeBudgets::default()
        };
        let mut artifact = ArtifactAnalysis::new(&f, 8, budgets);
        let first = analyzed(artifact.slice(true, |_, run| {
            assert!(run.charge(work, 3));
            (vec![one_function()], vec![])
        }));
        let second = analyzed(artifact.slice(true, |_, run| {
            assert!(!run.charge(work, 2), "{work:?} limit reset across slices");
            assert_eq!(*run.counter(work).0, 3, "refused work is not charged");
            (vec![], vec![])
        }));
        assert_eq!(first, (vec![one_function()], vec![], 0));
        assert!(second.0.is_empty());
        assert!(second.1.contains(&ARTIFACT_EXHAUSTED.to_string()));
        let later = analyzed(artifact.slice(true, |_, _| panic!("work after artifact exhaustion")));
        assert_eq!(later.1, [ARTIFACT_EXHAUSTED]);
        assert_eq!(later.2, 0);
    }

    macro_rules! shared_limit_test {
        ($name:ident, $work:ident) => {
            #[test]
            fn $name() {
                shared_work_limit(Work::$work);
            }
        };
    }
    shared_limit_test!(slice_references_do_not_reset, References);
    shared_limit_test!(slice_fdes_do_not_reset, Fdes);
    shared_limit_test!(slice_slots_do_not_reset, Slots);
    shared_limit_test!(slice_relocations_do_not_reset, Relocations);
    shared_limit_test!(slice_instructions_do_not_reset, Instructions);
    shared_limit_test!(slice_value_steps_do_not_reset, Values);
    shared_limit_test!(slice_calls_do_not_reset, Calls);
    shared_limit_test!(slice_names_do_not_reset, Names);

    #[test]
    fn new_analysis_combines_reference_categories_legacy_selection_preserves_old_caps() {
        let f = eight_bytes();
        let budgets = CodeBudgets {
            references: 4,
            ..CodeBudgets::default()
        };
        for legacy in [false, true] {
            let mut artifact = if legacy {
                ArtifactAnalysis::legacy(&f, 8, budgets)
            } else {
                ArtifactAnalysis::new(&f, 8, budgets)
            };
            artifact.slice(true, |_, run| {
                assert!(run.charge(Work::TextReferences, 2));
                assert!(run.charge(Work::References, 1));
                (vec![], vec![])
            });
            artifact.slice(true, |_, run| {
                assert!(run.charge(Work::References, 1)); // unified cap exactly full
                assert_eq!(run.charge(Work::TextReferences, 2), legacy);
                if legacy {
                    assert!(!run.charge(Work::TextReferences, 1)); // own legacy cap full
                }
                (vec![], vec![])
            });
            assert!(artifact.run.stopped());
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
                b.value_steps,
                b.call_sites,
                b.gaps,
                b.slots,
                b.relocations,
                b.name_bytes
            ),
            (
                256 << 20,
                65_536,
                1 << 20,
                4_000_000,
                1 << 27,
                65_536,
                256,
                1 << 20,
                1 << 20,
                16 << 20
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
