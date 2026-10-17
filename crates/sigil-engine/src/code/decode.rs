//! Decoding one function by recursive descent from its FDE start (PR-5a spec §4.5). Only bytes
//! reached along CFG edges are decoded, so data inside a function never becomes an instruction.
//! A failure fails the whole function: no value is computed from part of a CFG.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

use iced_x86::{ConstantOffsets, Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic};

use super::image::Image;
use super::{Run, FUNCTION_INSTRUCTIONS};

/// A decoded instruction and where its displacement and immediate are.
// Used outside tests from Task 11 (`analyze`); until then only tests decode.
#[allow(dead_code)]
pub(crate) struct Insn {
    pub ins: Instruction,
    pub offs: ConstantOffsets,
}

/// One function's CFG. Every block start is a decoded instruction, and each decoded instruction
/// is in exactly one block.
// Used outside tests from Task 11 (`analyze`); until then only tests decode.
#[allow(dead_code)]
pub(crate) struct Cfg {
    pub entry: u64,
    pub end: u64,
    pub insns: BTreeMap<u64, Insn>,
    /// Block start → the block.
    pub blocks: BTreeMap<u64, Block>,
}

// Used outside tests from Task 11 (`analyze`); until then only tests decode.
#[allow(dead_code)]
impl Cfg {
    /// The instructions of the block starting at `start`, in order. They are contiguous: no
    /// decoded instruction lies between two of them, as it would overlap one. A `start` past
    /// `b.last` (not this block's) gives none, where `range` would panic.
    pub fn block_insns(&self, start: u64, b: &Block) -> impl Iterator<Item = (u64, &Insn)> {
        (start <= b.last)
            .then(|| self.insns.range(start..=b.last))
            .into_iter()
            .flatten()
            .map(|(at, i)| (*at, i))
    }
}

/// One basic block: its instructions run from its start (its key in [`Cfg::blocks`]) to `last`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Block {
    /// The address of its last instruction.
    pub last: u64,
    /// At most two successors inside the function, sorted, without repeats.
    succs: Succs,
}

// Used outside tests from Task 11 (`analyze`); until then only tests decode.
#[allow(dead_code)]
impl Block {
    /// Its successors inside the function, in increasing order.
    pub fn succs(&self) -> impl Iterator<Item = u64> + '_ {
        self.succs.iter().flatten().copied()
    }
}

/// At most two successors: sorted, the `Some`s first, no repeats.
type Succs = [Option<u64>; 2];

/// `a` and `b` as [`Succs`].
fn succs(a: Option<u64>, b: Option<u64>) -> Succs {
    match (a, b) {
        (Some(x), Some(y)) if x == y => [Some(x), None],
        (Some(x), Some(y)) => [Some(x.min(y)), Some(x.max(y))],
        (Some(x), None) | (None, Some(x)) => [Some(x), None],
        (None, None) => [None, None],
    }
}

/// Why a function fails.
// Used outside tests from Task 11 (`analyze`); until then only tests decode.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Failure {
    Decode(u64),
    IntoInstruction(u64),
    Instructions,
    ArtifactInstructions,
    TextReloc(u64),
    NotModeled(u64),
}

// Used outside tests from Task 11 (`analyze`); until then only tests decode.
#[allow(dead_code)]
impl Failure {
    pub fn reason(&self, entry: u64) -> String {
        match self {
            Failure::Decode(a) => format!("function at {entry:#x}: decode failure at {a:#x}"),
            Failure::IntoInstruction(a) => {
                format!("function at {entry:#x}: branch into an instruction at {a:#x}")
            }
            Failure::Instructions => {
                format!("function at {entry:#x}: more than {FUNCTION_INSTRUCTIONS} instructions")
            }
            Failure::ArtifactInstructions => "not decoded: a limit was reached".to_string(),
            Failure::TextReloc(a) => format!("function at {entry:#x}: text relocation at {a:#x}"),
            Failure::NotModeled(a) => {
                format!("function at {entry:#x}: instruction at {a:#x} not modeled")
            }
        }
    }
}

/// How control leaves one instruction.
enum Flow {
    Next,
    Stop,
    Jump(Option<u64>),
    Branch(Option<u64>),
    Call { returns: bool },
}

fn flow(
    insn: &Insn,
    branch_target: &dyn Fn(&Insn) -> Option<u64>,
    noreturn: &dyn Fn(&Insn) -> bool,
) -> Result<Flow, Failure> {
    let ins = &insn.ins;
    Ok(match ins.flow_control() {
        FlowControl::Next if ins.mnemonic() == Mnemonic::Hlt => Flow::Stop,
        FlowControl::Next => Flow::Next,
        FlowControl::UnconditionalBranch => Flow::Jump(branch_target(insn)),
        // Through a GOT slot it is a tail call (Task 10 reads it from the instruction); any other
        // is an exit. Either way nothing in the function follows it.
        FlowControl::IndirectBranch => Flow::Jump(None),
        FlowControl::ConditionalBranch => Flow::Branch(branch_target(insn)),
        // `ret`, `iret`, …; `ud0`/`ud1`/`ud2`.
        FlowControl::Return | FlowControl::Exception => Flow::Stop,
        // Only `call` is a call. iced's `Call` also covers `syscall`, `sysenter`, `vmcall`,
        // `vmlaunch`, `tdcall`, …: those continue at the next instruction, as far as the CFG goes.
        FlowControl::Call | FlowControl::IndirectCall if ins.mnemonic() == Mnemonic::Call => {
            Flow::Call {
                returns: !noreturn(insn),
            }
        }
        FlowControl::Call | FlowControl::IndirectCall => Flow::Next,
        FlowControl::Interrupt if ins.mnemonic() == Mnemonic::Int3 => Flow::Stop,
        FlowControl::Interrupt => Flow::Next,
        FlowControl::XbeginXabortXend => return Err(Failure::NotModeled(ins.ip())),
    })
}

/// Decodes the function `[entry, end)`, whose bytes are `bytes` (from `entry`), from `entry`.
/// `branch_target`: where a direct branch goes, relocations applied (`None`: out of reach);
/// `noreturn`: whether a call never returns.
///
/// Every decode attempt is charged to `run.instructions` before it is made, whether it succeeds
/// or not; at `run.budgets.instructions` the run stops. The caller must not call it once
/// `run.stopped()`: `analyze` checks before each function.
// Used outside tests from Task 11 (`analyze`); until then only tests decode.
#[allow(dead_code)]
pub(crate) fn decode(
    bytes: &[u8],
    entry: u64,
    end: u64,
    img: &Image,
    branch_target: &dyn Fn(&Insn) -> Option<u64>,
    noreturn: &dyn Fn(&Insn) -> bool,
    run: &mut Run,
) -> Result<Cfg, Failure> {
    if entry >= end {
        // Its first instruction would be past its end.
        return Err(Failure::Decode(entry));
    }
    let mut dec = Decoder::try_with_ip(64, bytes, entry, DecoderOptions::NONE)
        .map_err(|_| Failure::Decode(entry))?;
    let mut insns: BTreeMap<u64, Insn> = BTreeMap::new();
    // Instruction ending its block → its successors inside the function. Any other instruction
    // falls through.
    let mut ends: BTreeMap<u64, Succs> = BTreeMap::new();
    let mut leaders: BTreeSet<u64> = BTreeSet::from([entry]);
    let mut work = vec![entry];
    let mut count: u64 = 0;
    let inside = |t: u64| t >= entry && t < end;
    while let Some(start) = work.pop() {
        let mut ip = start;
        while ip < end {
            if let Some((&at, prev)) = insns.range(..=ip).next_back() {
                if at == ip {
                    // Reached again. A path that falls into decoded code starts a block there
                    // (only a work item can, as an overlap would have failed; kept for safety).
                    leaders.insert(ip);
                    break;
                }
                if prev.ins.next_ip() > ip {
                    return Err(Failure::IntoInstruction(ip));
                }
            }
            // Charged before the decode, success or not (plan review P1-3): a function that fails
            // still spends the artifact's budget, so failing functions cannot decode forever.
            if run.instructions >= run.budgets.instructions {
                run.limit("decoded-instruction", run.budgets.instructions);
                return Err(Failure::ArtifactInstructions);
            }
            run.instructions += 1;
            count += 1;
            if count > FUNCTION_INSTRUCTIONS {
                return Err(Failure::Instructions);
            }
            let pos = ip
                .checked_sub(entry)
                .and_then(|o| usize::try_from(o).ok())
                .ok_or(Failure::Decode(ip))?;
            dec.set_position(pos).map_err(|_| Failure::Decode(ip))?;
            dec.set_ip(ip);
            let mut ins = Instruction::default();
            dec.decode_out(&mut ins);
            // iced's `next_ip` wraps; past `end` (or past 2^64) is a decode failure.
            let next = match ip.checked_add(ins.len() as u64) {
                Some(next) if !ins.is_invalid() && next <= end => next,
                _ => return Err(Failure::Decode(ip)),
            };
            let offs = dec.get_constant_offsets(&ins);
            if let Some((&later, _)) = insns.range((Bound::Excluded(ip), Bound::Unbounded)).next() {
                if later < next {
                    return Err(Failure::IntoInstruction(later));
                }
            }
            if img.textrel_overlaps(ip, next) {
                return Err(Failure::TextReloc(ip));
            }
            let insn = Insn { ins, offs };
            let f = flow(&insn, branch_target, noreturn)?;
            insns.insert(ip, insn);
            let fall = Some(next).filter(|n| inside(*n));
            let targets = match f {
                Flow::Next => {
                    ip = next;
                    continue;
                }
                Flow::Stop => succs(None, None),
                Flow::Jump(t) => succs(t.filter(|t| inside(*t)), None),
                Flow::Branch(t) => succs(t.filter(|t| inside(*t)), fall),
                Flow::Call { returns } => succs(fall.filter(|_| returns), None),
            };
            for t in targets.iter().flatten() {
                if leaders.insert(*t) {
                    work.push(*t);
                }
            }
            ends.insert(ip, targets);
            break;
        }
    }
    let mut blocks = BTreeMap::new();
    for &leader in &leaders {
        if !insns.contains_key(&leader) {
            continue;
        }
        let mut ip = leader;
        let out = loop {
            if let Some(out) = ends.get(&ip) {
                break *out;
            }
            // Falls through: decoded, so `ip + len <= end`.
            let Some(next) = insns.get(&ip).map(|i| i.ins.next_ip()) else {
                break succs(None, None);
            };
            if leaders.contains(&next) {
                break succs(Some(next), None);
            }
            if !insns.contains_key(&next) {
                // Ran past the FDE's end: an exit.
                break succs(None, None);
            }
            ip = next;
        };
        blocks.insert(
            leader,
            Block {
                last: ip,
                succs: out,
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
    use crate::code::image::{Image, Kind};
    use crate::code::{CodeBudgets, Run};

    fn run_decode(
        bytes: &[u8],
        img: &Image,
        noreturn: bool,
        budgets: CodeBudgets,
    ) -> (Result<Cfg, Failure>, Run) {
        let mut run = Run::new(budgets);
        let entry = 0x1000;
        let end = entry + bytes.len() as u64;
        let r = decode(
            bytes,
            entry,
            end,
            img,
            &|i: &Insn| Some(i.ins.near_branch_target()),
            &|_: &Insn| noreturn,
            &mut run,
        );
        (r, run)
    }

    /// Each block as (start, its instructions, its successors), through the helpers.
    fn shape(cfg: &Cfg) -> Vec<(u64, Vec<u64>, Vec<u64>)> {
        cfg.blocks
            .iter()
            .map(|(start, b)| {
                let insns = cfg.block_insns(*start, b).map(|(at, _)| at).collect();
                (*start, insns, b.succs().collect())
            })
            .collect()
    }

    fn shape_of(bytes: &[u8], noreturn: bool) -> Vec<(u64, Vec<u64>, Vec<u64>)> {
        let (r, _) = run_decode(
            bytes,
            &Image::empty(Kind::Shared),
            noreturn,
            CodeBudgets::default(),
        );
        shape(&r.unwrap())
    }

    #[test]
    fn blocks_end_at_calls_and_branches() {
        // 1000: xor edi,edi (31 ff); 1002: call 1007 (e8 00 00 00 00); 1007: je 100a (74 01);
        // 1009: nop (90); 100a: ret (c3)
        let bytes = [0x31, 0xff, 0xe8, 0, 0, 0, 0, 0x74, 0x01, 0x90, 0xc3];
        assert_eq!(
            shape_of(&bytes, false),
            [
                (0x1000, vec![0x1000, 0x1002], vec![0x1007]),
                (0x1007, vec![0x1007], vec![0x1009, 0x100a]),
                (0x1009, vec![0x1009], vec![0x100a]),
                (0x100a, vec![0x100a], vec![]),
            ]
        );
    }

    #[test]
    fn only_call_ends_a_block() {
        // 1000: syscall (0f 05); 1002: call 1007 (e8 00 00 00 00); 1007: nop; 1008: ret
        let bytes = [0x0f, 0x05, 0xe8, 0, 0, 0, 0, 0x90, 0xc3];
        assert_eq!(
            shape_of(&bytes, false),
            [
                (0x1000, vec![0x1000, 0x1002], vec![0x1007]),
                (0x1007, vec![0x1007, 0x1008], vec![]),
            ]
        );
        // `noreturn` is asked only of the call: were `syscall` a call, nothing would follow it.
        assert_eq!(
            shape_of(&bytes, true),
            [(0x1000, vec![0x1000, 0x1002], vec![])]
        );
        // 1000: xor edi,edi; 1002: syscall; 1004: sysenter (0f 34); 1006: vmcall (0f 01 c1);
        // 1009: ret: one block
        let bytes = [0x31, 0xff, 0x0f, 0x05, 0x0f, 0x34, 0x0f, 0x01, 0xc1, 0xc3];
        assert_eq!(
            shape_of(&bytes, true),
            [(0x1000, vec![0x1000, 0x1002, 0x1004, 0x1006, 0x1009], vec![])]
        );
    }

    #[test]
    fn a_direct_jump_inside_the_function_is_an_edge() {
        // 1000: jmp 1003 (eb 01); 1002: ff (never reached); 1003: ret
        let (r, _) = run_decode(
            &[0xeb, 0x01, 0xff, 0xc3],
            &Image::empty(Kind::Shared),
            false,
            CodeBudgets::default(),
        );
        let cfg = r.unwrap();
        assert_eq!(cfg.insns.len(), 2);
        assert_eq!(
            shape(&cfg),
            [
                (0x1000, vec![0x1000], vec![0x1003]),
                (0x1003, vec![0x1003], vec![]),
            ]
        );
        let first = cfg.blocks[&0x1000];
        assert_eq!(first.last, 0x1000);
        assert_eq!(
            cfg.block_insns(0x1003, &first).count(),
            0,
            "a start past the block's last instruction gives none, without a panic"
        );
    }

    #[test]
    fn a_backward_branch_splits_a_decoded_block() {
        // 1000: nop; 1001: nop; 1002: jne 1001 (75 fd); 1004: ret
        assert_eq!(
            shape_of(&[0x90, 0x90, 0x75, 0xfd, 0xc3], false),
            [
                (0x1000, vec![0x1000], vec![0x1001]),
                (0x1001, vec![0x1001, 0x1002], vec![0x1001, 0x1004]),
                (0x1004, vec![0x1004], vec![]),
            ]
        );
    }

    #[test]
    fn a_branch_into_an_instruction_fails_the_function() {
        // 1000: jne 1003 (75 01); 1002: mov eax,0x90909090 (b8 90 90 90 90); 1007: ret (c3)
        let bytes = [0x75, 0x01, 0xb8, 0x90, 0x90, 0x90, 0x90, 0xc3];
        let (r, _) = run_decode(
            &bytes,
            &Image::empty(Kind::Shared),
            false,
            CodeBudgets::default(),
        );
        assert!(
            matches!(r, Err(Failure::IntoInstruction(0x1003))),
            "{:?}",
            r.err()
        );
    }

    #[test]
    fn a_branch_into_an_instruction_fails_in_either_order() {
        // 1000: jmp 1006 (eb 04); 1002: ud2 (0f 0b), never reached; 1004: ud2, never reached;
        // 1006: mov eax,0x00fceb90 (b8 90 eb fc 00); 100b: jmp 1008 (eb fb), into the mov. Here
        // the target is reached after the mov is decoded; in the test above, the reverse.
        let bytes = [
            0xeb, 0x04, 0x0f, 0x0b, 0x0f, 0x0b, 0xb8, 0x90, 0xeb, 0xfc, 0x00, 0xeb, 0xfb,
        ];
        let (r, _) = run_decode(
            &bytes,
            &Image::empty(Kind::Shared),
            false,
            CodeBudgets::default(),
        );
        assert_eq!(r.err(), Some(Failure::IntoInstruction(0x1008)));
    }

    #[test]
    fn only_reached_bytes_are_decoded() {
        // 1000: ret (c3); 1001: ff ff (invalid, never reached)
        let (r, _) = run_decode(
            &[0xc3, 0xff, 0xff],
            &Image::empty(Kind::Shared),
            false,
            CodeBudgets::default(),
        );
        assert_eq!(r.unwrap().insns.len(), 1);
        // 1000: call 1005 (e8 00 00 00 00); 1005: ff ff — reached only if the call returns
        let bytes = [0xe8, 0, 0, 0, 0, 0xff, 0xff];
        let (r, _) = run_decode(
            &bytes,
            &Image::empty(Kind::Shared),
            true,
            CodeBudgets::default(),
        );
        assert!(r.is_ok(), "a noreturn call has no fall-through");
        let (r, _) = run_decode(
            &bytes,
            &Image::empty(Kind::Shared),
            false,
            CodeBudgets::default(),
        );
        assert_eq!(r.err(), Some(Failure::Decode(0x1005)));
    }

    #[test]
    fn traps_and_halts_end_paths_and_xbegin_is_not_modeled() {
        let img = Image::empty(Kind::Shared);
        // ud2 (0f 0b), hlt (f4), int3 (cc), each followed by ff ff (invalid, never reached)
        for stop in [&[0x0f, 0x0b][..], &[0xf4][..], &[0xcc][..]] {
            let mut bytes = stop.to_vec();
            bytes.extend([0xff, 0xff]);
            let (r, _) = run_decode(&bytes, &img, false, CodeBudgets::default());
            assert_eq!(r.unwrap().insns.len(), 1, "{stop:02x?}");
        }
        // 1000: int 0x80 (cd 80) falls through; 1002: ret
        let (r, _) = run_decode(&[0xcd, 0x80, 0xc3], &img, false, CodeBudgets::default());
        assert_eq!(r.unwrap().insns.len(), 2);
        // 1000: xbegin 1006 (c7 f8 00 00 00 00); 1006: ret
        let bytes = [0xc7, 0xf8, 0, 0, 0, 0, 0xc3];
        let (r, _) = run_decode(&bytes, &img, false, CodeBudgets::default());
        assert_eq!(r.err(), Some(Failure::NotModeled(0x1000)));
    }

    #[test]
    fn an_instruction_past_the_end_fails_and_running_off_the_end_is_an_exit() {
        let img = Image::empty(Kind::Shared);
        // 1000: nop; 1001: mov eax, imm32 (b8 …) with the FDE ending at 1003
        let bytes = [0x90, 0xb8, 0, 0, 0, 0];
        let mut run = Run::new(CodeBudgets::default());
        let target = |i: &Insn| Some(i.ins.near_branch_target());
        let r = decode(
            &bytes,
            0x1000,
            0x1003,
            &img,
            &target,
            &|_: &Insn| false,
            &mut run,
        );
        assert_eq!(r.err(), Some(Failure::Decode(0x1001)));
        // 1000: nop; 1001: nop, then the FDE ends: an exit
        assert_eq!(
            shape_of(&[0x90, 0x90], false),
            [(0x1000, vec![0x1000, 0x1001], vec![])]
        );
        // An empty FDE has no first instruction.
        let r = decode(
            &[],
            0x1000,
            0x1000,
            &img,
            &target,
            &|_: &Insn| false,
            &mut run,
        );
        assert_eq!(r.err(), Some(Failure::Decode(0x1000)));
    }

    #[test]
    fn exits_and_indirect_jumps_end_paths() {
        // 1000: jmp rax (ff e0); 1002: ud2 (0f 0b)
        let (r, _) = run_decode(
            &[0xff, 0xe0, 0x0f, 0x0b],
            &Image::empty(Kind::Shared),
            false,
            CodeBudgets::default(),
        );
        assert_eq!(
            r.unwrap().insns.len(),
            1,
            "nothing after an unresolved jump is reached"
        );
        // 1000: jmp 2000 (e9 fb 0f 00 00): out of the function, an exit
        assert_eq!(
            shape_of(&[0xe9, 0xfb, 0x0f, 0x00, 0x00], false),
            [(0x1000, vec![0x1000], vec![])]
        );
    }

    #[test]
    fn a_text_relocation_fails_the_instruction_over_it() {
        let mut img = Image::empty(Kind::Shared);
        img.set_textrel(vec![(0x1003, 0x100b)]);
        // 1000: nop; 1001: movabs rax, imm64 (48 b8 + 8 bytes); 100b: ret
        let mut bytes = vec![0x90, 0x48, 0xb8];
        bytes.extend([0; 8]);
        bytes.push(0xc3);
        let (r, _) = run_decode(&bytes, &img, false, CodeBudgets::default());
        assert_eq!(r.err(), Some(Failure::TextReloc(0x1001)));
    }

    #[test]
    fn instruction_limit_per_function() {
        let mut bytes = vec![0x90; FUNCTION_INSTRUCTIONS as usize];
        bytes.push(0xc3);
        let (r, _) = run_decode(
            &bytes,
            &Image::empty(Kind::Shared),
            false,
            CodeBudgets::default(),
        );
        assert_eq!(r.err(), Some(Failure::Instructions));
    }

    #[test]
    fn instruction_limit_counts_functions_that_fail() {
        // Each "function" decodes 3 nops, then fails on ff ff: 4 attempts each (plan review P1-3).
        let img = Image::empty(Kind::Shared);
        let bytes = [0x90, 0x90, 0x90, 0xff, 0xff];
        let mut run = Run::new(CodeBudgets {
            instructions: 7,
            ..CodeBudgets::default()
        });
        let decode_once = |run: &mut Run| {
            decode(
                &bytes,
                0x1000,
                0x1005,
                &img,
                &|i: &Insn| Some(i.ins.near_branch_target()),
                &|_: &Insn| false,
                run,
            )
        };
        assert_eq!(decode_once(&mut run).err(), Some(Failure::Decode(0x1003)));
        assert_eq!(run.instructions, 4, "the failed function was charged");
        assert_eq!(
            decode_once(&mut run).err(),
            Some(Failure::ArtifactInstructions)
        );
        assert!(run.stopped());
    }

    #[test]
    fn a_text_relocation_beyond_8_bytes_still_fails() {
        // A 16-byte write at 0x1002 (a TLSDESC): the ret at 0x100b lies in its second 8 bytes, and
        // nothing decoded before it is written.
        let mut img = Image::empty(Kind::Shared);
        img.set_textrel(vec![(0x1002, 0x1012)]);
        // 1000: jmp 100b (eb 09); 1002: 9 nops, never reached; 100b: ret (c3)
        let mut bytes = vec![0xeb, 0x09];
        bytes.extend([0x90; 9]);
        bytes.push(0xc3);
        let (r, _) = run_decode(&bytes, &img, false, CodeBudgets::default());
        assert_eq!(r.err(), Some(Failure::TextReloc(0x100b)));
    }

    #[test]
    fn instruction_limit_per_artifact() {
        let (r, run) = run_decode(
            &[0x90, 0x90, 0x90, 0xc3],
            &Image::empty(Kind::Shared),
            false,
            CodeBudgets {
                instructions: 2,
                ..CodeBudgets::default()
            },
        );
        assert_eq!(r.err(), Some(Failure::ArtifactInstructions));
        assert!(run.stopped());
        assert!(run
            .clone_gaps()
            .contains(&"code: decoded-instruction limit 2 reached".to_string()));
    }
}
