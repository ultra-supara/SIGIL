//! Bounded AArch64 decoding; no architecture dispatch or evidence emission.
pub(crate) mod decode;
pub(crate) mod value;

use super::{Run, Work, FUNCTION_INSTRUCTIONS};
use decode::{A64Insn, DecodeGap, Flow};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub(crate) struct Cfg {
    pub entry: u64,
    pub end: u64,
    pub insns: BTreeMap<u64, A64Insn>,
    pub blocks: BTreeMap<u64, Block>,
}

impl Cfg {
    pub fn calls(&self) -> impl Iterator<Item = (u64, Flow)> + '_ {
        self.insns.iter().filter_map(|(pc, ins)| {
            matches!(ins.flow, Flow::CallDirect(_) | Flow::CallRegister(_))
                .then_some((*pc, ins.flow))
        })
    }

    pub fn block_insns(&self, start: u64, block: &Block) -> impl Iterator<Item = (u64, &A64Insn)> {
        (start <= block.last)
            .then(|| self.insns.range(start..=block.last))
            .into_iter()
            .flatten()
            .map(|(pc, ins)| (*pc, ins))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Block {
    pub last: u64,
    pub successors: [Option<u64>; 2],
}

/// Image proofs provided by the bounded image adapter. `executable` must prove the whole
/// half-open range has one unambiguous executable mapping; `excluded` covers data-in-code
/// and unsupported/inconsistent relocations. No callback reads uncharged target bytes.
/// `noreturn` requires a proved call target, never a guessed register or symbol name.
pub(crate) struct Proofs<'a> {
    pub executable: &'a dyn Fn(u64, u64) -> bool,
    pub excluded: &'a dyn Fn(u64, u64) -> bool,
    pub noreturn: &'a dyn Fn(u64, &A64Insn) -> bool,
    /// Already reserved against this artifact's shared `Run` with
    /// `run.charge(Work::References, ...)`, before candidate collection/proof work and before
    /// passing this list. Deduplicate candidates within each artifact slice and assign each
    /// candidate to exactly one applicable function; never submit it repeatedly to CFGs.
    /// Reservations and their aggregate cap persist across all functions and artifact slices,
    /// including failed functions. On reservation refusal, preserve the Run's gap/stop state
    /// and do not pass unreserved candidates. The CFG must not charge these reservations again.
    pub candidates: &'a [u64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    Decode(u64, DecodeGap),
    Bounds(u64),
    Truncated(u64),
    NotExecutable(u64),
    Excluded(u64),
    JumpOutside(u64),
    IndirectJump(u64),
    Fallthrough(u64),
    Unreachable(u64),
    FunctionInstructions,
    ArtifactInstructions,
    CandidateLimit,
}

impl Failure {
    fn reason(self, entry: u64) -> String {
        let detail = match self {
            Self::Decode(at, why) => format!("instruction at {at:#x}: {why:?}"),
            Self::Bounds(at) => format!("invalid instruction bounds at {at:#x}"),
            Self::Truncated(at) => format!("truncated instruction at {at:#x}"),
            Self::NotExecutable(at) => format!("no unique executable mapping at {at:#x}"),
            Self::Excluded(at) => format!("data-in-code or unsupported relocation at {at:#x}"),
            Self::JumpOutside(at) => format!("unproved jump outside function to {at:#x}"),
            Self::IndirectJump(at) => format!("unresolved indirect jump at {at:#x}"),
            Self::Fallthrough(at) => format!("fallthrough outside function at {at:#x}"),
            Self::Unreachable(at) => format!("candidate at {at:#x} unreachable from entry"),
            Self::FunctionInstructions => format!("more than {FUNCTION_INSTRUCTIONS} instructions"),
            Self::ArtifactInstructions => "artifact work limit reached".to_string(),
            Self::CandidateLimit => "candidate limit reached".to_string(),
        };
        format!("code: AArch64 function at {entry:#x}: {detail}")
    }
}

/// Decode already charged bytes beginning at the exact independently proved function entry.
/// Callers obtain these bytes through `read_slice`, after validating executable mappings and
/// the FDE/explicit object length. A result is transactional: no CFG or call list escapes on
/// failure; attempted instruction charges and the bounded gap remain. No model facts are made.
/// The caller must also discard this CFG if later relocation/value/recording proofs fail.
/// This stage uses encoded branch destinations. Object relocation resolution and proved
/// import-tail exits must be integrated before enabling a producer (Tasks 9–10).
///
/// The caller must satisfy the shared reservation, deduplication and single-function ownership
/// contract on [`Proofs::candidates`]. The list-length check below is only a defensive local
/// bound: it neither reserves references nor enforces their aggregate artifact budget.
/// Tasks 9–10 integration tests must exercise multiple functions, duplicate/repeated candidates,
/// multiple artifact slices and the exact reference-budget boundary, including refusal gaps,
/// stopped work and preservation of earlier independently proved facts.
pub(crate) fn decode_cfg(
    bytes: &[u8],
    entry: u64,
    end: u64,
    proofs: &Proofs<'_>,
    run: &mut Run,
) -> Result<Cfg, Failure> {
    let result = build_cfg(bytes, entry, end, proofs, run);
    if let Err(why) = result {
        run.gap(why.reason(entry));
    }
    result
}

fn code_at(at: u64, p: &Proofs<'_>) -> Result<u64, Failure> {
    if at & 3 != 0 {
        return Err(Failure::Bounds(at));
    }
    let next = at.checked_add(4).ok_or(Failure::Bounds(at))?;
    if !(p.executable)(at, next) {
        return Err(Failure::NotExecutable(at));
    }
    if (p.excluded)(at, next) {
        return Err(Failure::Excluded(at));
    }
    Ok(next)
}

fn successors(a: Option<u64>, b: Option<u64>) -> [Option<u64>; 2] {
    match (a, b) {
        (Some(a), Some(b)) if a != b => [Some(a.min(b)), Some(a.max(b))],
        (Some(a), _) | (_, Some(a)) => [Some(a), None],
        _ => [None, None],
    }
}

fn build_cfg(
    bytes: &[u8],
    entry: u64,
    end: u64,
    p: &Proofs<'_>,
    run: &mut Run,
) -> Result<Cfg, Failure> {
    if run.stopped() {
        return Err(Failure::ArtifactInstructions);
    }
    if entry >= end || entry & 3 != 0 || end & 3 != 0 {
        return Err(Failure::Bounds(entry));
    }
    if p.candidates.len() > run.budgets.references {
        run.limit("references", run.budgets.references as u64);
        return Err(Failure::CandidateLimit);
    }
    let inside = |pc| entry <= pc && pc < end;
    for &pc in p.candidates {
        if !inside(pc) || pc & 3 != 0 {
            return Err(Failure::Bounds(pc));
        }
        code_at(pc, p)?;
    }
    let mut insns = BTreeMap::new();
    let mut leaders = BTreeSet::from([entry]);
    let mut ends = BTreeMap::new();
    let mut pending = vec![entry];
    let mut count = 0;
    while let Some(mut pc) = pending.pop() {
        loop {
            if insns.contains_key(&pc) {
                leaders.insert(pc);
                break;
            }
            // Both caps are checked before decode or growth of instruction-indexed state.
            if count == FUNCTION_INSTRUCTIONS {
                return Err(Failure::FunctionInstructions);
            }
            if !run.charge(Work::Instructions, 1) {
                return Err(Failure::ArtifactInstructions);
            }
            count += 1;
            let next = code_at(pc, p)?;
            if !inside(pc) || next > end {
                return Err(Failure::Bounds(pc));
            }
            let pos = pc
                .checked_sub(entry)
                .and_then(|n| usize::try_from(n).ok())
                .ok_or(Failure::Bounds(pc))?;
            let raw = pos
                .checked_add(4)
                .and_then(|e| bytes.get(pos..e))
                .ok_or(Failure::Truncated(pc))?;
            let word = u32::from_le_bytes(raw.try_into().map_err(|_| Failure::Truncated(pc))?);
            let ins = decode::decode_a64(word, pc).map_err(|why| Failure::Decode(pc, why))?;
            let fall = || {
                if next < end {
                    Ok(next)
                } else {
                    Err(Failure::Fallthrough(next))
                }
            };
            let targets = match ins.flow {
                Flow::Next => {
                    insns.insert(pc, ins);
                    pc = fall()?;
                    continue;
                }
                Flow::Return => [None, None],
                Flow::JumpRegister(_) => return Err(Failure::IndirectJump(pc)),
                Flow::JumpDirect(t) | Flow::Conditional(t) => {
                    code_at(t, p)?;
                    if !inside(t) {
                        return Err(Failure::JumpOutside(t));
                    }
                    successors(
                        Some(t),
                        if matches!(ins.flow, Flow::Conditional(_)) {
                            Some(fall()?)
                        } else {
                            None
                        },
                    )
                }
                Flow::CallDirect(t) => {
                    code_at(t, p)?;
                    successors(
                        if (p.noreturn)(pc, &ins) {
                            None
                        } else {
                            Some(fall()?)
                        },
                        None,
                    )
                }
                Flow::CallRegister(_) => successors(
                    if (p.noreturn)(pc, &ins) {
                        None
                    } else {
                        Some(fall()?)
                    },
                    None,
                ),
            };
            insns.insert(pc, ins);
            for &target in targets.iter().flatten() {
                if leaders.insert(target) {
                    pending.push(target);
                }
            }
            ends.insert(pc, targets);
            break;
        }
    }
    for &pc in p.candidates {
        if !insns.contains_key(&pc) {
            return Err(Failure::Unreachable(pc));
        }
    }
    let mut blocks = BTreeMap::new();
    for start in leaders.iter().copied() {
        let mut pc = start;
        let out = loop {
            if let Some(targets) = ends.get(&pc) {
                break *targets;
            }
            // Every instruction in this contiguous fallthrough has already proved pc + 4.
            let next = pc.checked_add(4).ok_or(Failure::Bounds(pc))?;
            if leaders.contains(&next) {
                break successors(Some(next), None);
            }
            if !insns.contains_key(&next) {
                return Err(Failure::Bounds(next));
            }
            pc = next;
        };
        blocks.insert(
            start,
            Block {
                last: pc,
                successors: out,
            },
        );
    }
    Ok(Cfg {
        entry,
        end,
        insns,
        blocks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::CodeBudgets;

    fn bytes(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }
    fn proofs(candidates: &[u64]) -> Proofs<'_> {
        Proofs {
            executable: &|_, _| true,
            excluded: &|_, _| false,
            noreturn: &|_, _| false,
            candidates,
        }
    }
    fn build(words: &[u32], p: &Proofs<'_>, run: &mut Run) -> Result<Cfg, Failure> {
        decode_cfg(
            &bytes(words),
            0x1000,
            0x1000 + words.len() as u64 * 4,
            p,
            run,
        )
    }
    fn run() -> Run {
        Run::new(CodeBudgets::default())
    }

    #[test]
    fn conditional_has_both_successors() {
        // cbz x0,1010; mov w0,0; b 1014; unreachable udf; mov w0,1; bl 1000; ret
        let cfg = build(
            &[
                0xb4000080, 0x52800000, 0x14000003, 0, 0x52800020, 0x97fffffb, 0xd65f03c0,
            ],
            &proofs(&[0x1014]),
            &mut run(),
        )
        .unwrap();
        assert_eq!(cfg.blocks[&0x1000].successors, [Some(0x1004), Some(0x1010)]);
        assert_eq!(cfg.blocks[&0x1004].successors, [Some(0x1014), None]);
        assert_eq!(cfg.blocks[&0x1010].successors, [Some(0x1014), None]);
        assert_eq!(cfg.blocks[&0x1014].successors, [Some(0x1018), None]);
        assert!(!cfg.insns.contains_key(&0x100c));
        assert_eq!(
            cfg.calls().collect::<Vec<_>>(),
            [(0x1014, Flow::CallDirect(0x1000))]
        );
    }

    #[test]
    fn rollback_is_per_function() {
        let mut r = run();
        let failed = build(
            &[0x94000000, 0xd63f0200, 0xd503233f, 0xd65f03c0],
            &proofs(&[]),
            &mut r,
        );
        assert_eq!(
            failed.err(),
            Some(Failure::Decode(0x1008, DecodeGap::Unsupported))
        );
        assert_eq!(r.instructions, 3);
        assert!(!r.clone_gaps().is_empty());
        let good = build(&[0x94000000, 0xd65f03c0], &proofs(&[0x1000]), &mut r).unwrap();
        assert_eq!(
            good.calls().collect::<Vec<_>>(),
            [(0x1000, Flow::CallDirect(0x1000))]
        );
        assert_eq!(r.instructions, 5);
    }

    #[test]
    fn unreachable_candidate_is_not_a_call() {
        let mut r = run();
        assert_eq!(
            build(
                &[0x14000002, 0x94000000, 0xd65f03c0],
                &proofs(&[0x1004]),
                &mut r
            )
            .err(),
            Some(Failure::Unreachable(0x1004))
        );
        assert_eq!(r.instructions, 2);
        assert!(!r.clone_gaps().is_empty());
    }

    #[test]
    fn unresolved_jump_and_outside_branch_fail_transaction() {
        for (words, failure) in [
            (vec![0x94000000, 0xd61f0200], Failure::IndirectJump(0x1004)),
            (vec![0x94000000, 0x14000010], Failure::JumpOutside(0x1044)),
            (
                vec![0x94000000, 0x54000200, 0xd65f03c0],
                Failure::JumpOutside(0x1044),
            ),
        ] {
            let mut r = run();
            assert_eq!(build(&words, &proofs(&[]), &mut r).err(), Some(failure));
            assert!(!r.clone_gaps().is_empty());
        }
    }

    #[test]
    fn excluded_or_unmapped_instruction_cannot_supply_calls() {
        let mut p = proofs(&[]);
        p.excluded = &|s, e| s < 0x1008 && e > 0x1004;
        assert_eq!(
            build(&[0x94000000, 0xd65f03c0], &p, &mut run()).err(),
            Some(Failure::Excluded(0x1004))
        );
        p.excluded = &|_, _| false;
        p.executable = &|s, e| s >= 0x1000 && e <= 0x1008;
        assert_eq!(
            build(&[0x94000004, 0xd65f03c0], &p, &mut run()).err(),
            Some(Failure::NotExecutable(0x1010))
        );
        assert_eq!(
            build(&[0x14000002, 0, 0xd65f03c0], &p, &mut run()).err(),
            Some(Failure::NotExecutable(0x1008))
        );
    }

    #[test]
    fn calls_fall_through_unless_proven_noreturn() {
        let words = [0x94000000, 0];
        assert_eq!(
            build(&words, &proofs(&[]), &mut run()).err(),
            Some(Failure::Decode(0x1004, DecodeGap::Unsupported))
        );
        let mut p = proofs(&[]);
        p.noreturn = &|_, _| true;
        assert_eq!(build(&words, &p, &mut run()).unwrap().insns.len(), 1);
        assert_eq!(
            build(&[0xd65f03c0, 0], &proofs(&[]), &mut run())
                .unwrap()
                .insns
                .len(),
            1
        );
    }

    #[test]
    fn truncated_unaligned_and_fallthrough_fail() {
        assert_eq!(
            decode_cfg(
                &[0x1f, 0x20, 0x03],
                0x1000,
                0x1004,
                &proofs(&[]),
                &mut run()
            )
            .err(),
            Some(Failure::Truncated(0x1000))
        );
        assert_eq!(
            decode_cfg(
                &bytes(&[0xd65f03c0]),
                0x1002,
                0x1006,
                &proofs(&[]),
                &mut run()
            )
            .err(),
            Some(Failure::Bounds(0x1002))
        );
        assert_eq!(
            build(&[0xd503201f], &proofs(&[]), &mut run()).err(),
            Some(Failure::Fallthrough(0x1004))
        );
        assert_eq!(
            build(&[0xd65f03c0], &proofs(&[0x1002]), &mut run()).err(),
            Some(Failure::Bounds(0x1002))
        );
    }

    #[test]
    fn loop_terminates_and_backward_target_splits_block() {
        let mut r = run();
        let cfg = build(
            &[0xd503201f, 0xd503201f, 0x54ffffe1, 0xd65f03c0],
            &proofs(&[]),
            &mut r,
        )
        .unwrap();
        assert_eq!(cfg.blocks[&0x1000].last, 0x1000);
        assert_eq!(cfg.blocks[&0x1004].last, 0x1008);
        assert_eq!(cfg.blocks[&0x1004].successors, [Some(0x1004), Some(0x100c)]);
        assert_eq!(r.instructions, 4);
        let cfg = build(&[0x14000000], &proofs(&[]), &mut r).unwrap();
        assert_eq!(cfg.blocks[&0x1000].successors, [Some(0x1000), None]);
        assert_eq!(r.instructions, 5);
    }

    #[test]
    fn artifact_instruction_limit_counts_failed_functions() {
        let mut r = Run::new(CodeBudgets {
            instructions: 4,
            ..CodeBudgets::default()
        });
        assert_eq!(
            build(&[0x94000000, 0, 0xd65f03c0], &proofs(&[]), &mut r).err(),
            Some(Failure::Decode(0x1004, DecodeGap::Unsupported))
        );
        assert_eq!(
            build(&[0x94000000, 0xd503201f, 0xd65f03c0], &proofs(&[]), &mut r).err(),
            Some(Failure::ArtifactInstructions)
        );
        assert_eq!(r.instructions, 4);
        assert!(r.stopped());
    }

    #[test]
    fn function_instruction_cap_checked_before_decode() {
        let mut words = vec![0xd503201f; FUNCTION_INSTRUCTIONS as usize - 1];
        words.push(0xd65f03c0);
        let mut r = run();
        assert!(build(&words, &proofs(&[]), &mut r).is_ok());
        words.insert(0, 0xd503201f);
        assert_eq!(
            build(&words, &proofs(&[]), &mut r).err(),
            Some(Failure::FunctionInstructions)
        );
        assert_eq!(r.instructions, 2 * FUNCTION_INSTRUCTIONS);
        assert!(
            !r.stopped(),
            "a function cap must not prevent later independent functions"
        );
    }

    #[test]
    fn shared_artifact_slices_keep_prior_cfg_and_failed_decode_charge() {
        use crate::code::reader::{read_slice, SliceWindow};
        use crate::code::{ArtifactAnalysis, CodeOutcome};
        use std::io::Write;
        let code = bytes(&[0x94000000, 0xd65f03c0]);
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&code).unwrap();
        file.write_all(&code).unwrap();
        let mut artifact = ArtifactAnalysis::new(
            file.as_file(),
            16,
            CodeBudgets {
                instructions: 3,
                ..CodeBudgets::default()
            },
        );
        let mut retained = vec![];
        for base in [0, 8] {
            let outcome = artifact.slice(true, |reader, run| {
                let input = read_slice(reader, SliceWindow { base, len: 8 }, 0, 8).unwrap();
                if let Ok(cfg) = decode_cfg(&input, 0x1000, 0x1008, &proofs(&[0x1000]), run) {
                    retained.push(cfg.calls().collect::<Vec<_>>());
                }
                (vec![], vec![])
            });
            let CodeOutcome::Analyzed { gaps, budget, .. } = outcome else {
                panic!("supported slice");
            };
            assert_eq!(
                budget.used, 8,
                "failed function bytes remain charged only to its slice"
            );
            assert_eq!(gaps.is_empty(), base == 0);
        }
        assert_eq!(retained, [vec![(0x1000, Flow::CallDirect(0x1000))]]);
        let later = artifact.slice(true, |_, _| {
            panic!("exhausted artifact must not start a later supported slice")
        });
        let CodeOutcome::Analyzed { budget, gaps, .. } = later else {
            panic!("supported slice");
        };
        assert_eq!(budget.used, 0);
        assert!(!gaps.is_empty());
    }

    #[test]
    fn adjacent_slice_bytes_cannot_complete_a_truncated_instruction() {
        use crate::code::reader::{read_slice, Reader, Refusal, SliceWindow};
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&bytes(&[0xd65f03c0])).unwrap();
        let mut reader = Reader::new(file.as_file(), 4, 4);
        let window = SliceWindow { base: 0, len: 3 };
        assert_eq!(
            read_slice(&mut reader, window, 0, 4),
            Err(Refusal::OutsideFile)
        );
        assert_eq!(reader.used(), 0);
        let input = read_slice(&mut reader, window, 0, 3).unwrap();
        assert_eq!(
            decode_cfg(&input, 0x1000, 0x1004, &proofs(&[]), &mut run()).err(),
            Some(Failure::Truncated(0x1000))
        );
        assert_eq!(reader.used(), 3);
    }
}
