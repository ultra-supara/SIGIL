//! Charged candidate ownership and exact GOT provenance. Candidates are not call facts.
//! The caller still owes reachable CFG validation and a complete per-function transaction.
use super::decode::{decode_a64, A64Insn, Flow, Operation, RegisterName, Width};
use super::Cfg;
use crate::code::image::aarch64::{
    A64ElfImage, Branch, ImportWitness, ADD_LO12, ADR_GOT_PAGE, ADR_PAGE, LD64_GOT_LO12,
};
use crate::code::image::FdeAt;
use crate::code::reader::Reader;
use crate::code::{Run, Work, VALUE_PASSES};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub(crate) struct Candidates {
    seen: BTreeSet<u64>,
    scanned: Option<bool>,
    pub functions: BTreeMap<(u64, u64), Vec<u64>>,
}
impl Candidates {
    /// One owner per slice, reused across discovery routes. Reserve before insertion or proof.
    pub fn reserve(&mut self, pc: u64, image: &A64ElfImage, run: &mut Run) -> bool {
        if self.seen.contains(&pc) {
            return true;
        }
        if !run.charge(Work::References, 1) {
            return false;
        }
        self.seen.insert(pc);
        match image.function(pc) {
            FdeAt::One(range) if !image.excluded(range.0, range.1) => {
                self.functions.entry(range).or_default().push(pc);
            }
            FdeAt::Overlap => run.gap(format!(
                "code: AArch64 reference at {pc:#x} has overlapping FDEs"
            )),
            _ => run.gap(format!(
                "code: AArch64 reference at {pc:#x} has no exact function bounds"
            )),
        }
        true
    }
    pub fn scan(&mut self, image: &A64ElfImage, reader: &mut Reader<'_>, run: &mut Run) -> bool {
        if let Some(complete) = self.scanned {
            return complete && !run.stopped();
        }
        self.scanned = Some(false);
        for r in &image.code {
            if image.plt.binary_search(&(r.start, r.end)).is_ok() {
                continue;
            }
            let mut pc = r.start;
            while pc < r.end {
                let n = (r.end - pc).min(1 << 20);
                let Some(bytes) = image.read_code(pc, n, reader, run) else {
                    return false;
                };
                for raw in bytes.chunks_exact(4) {
                    if !run.charge(Work::Instructions, 1) {
                        return false;
                    }
                    let word = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
                    let candidate = if image.object && image.relocs.contains_key(&pc) {
                        // Include unsupported target-bearing forms: no silent loss of references.
                        true
                    } else {
                        match decode_a64(word, pc).map(|i| i.flow) {
                            Ok(Flow::CallDirect(t) | Flow::JumpDirect(t)) => {
                                image.stubs.contains_key(&t)
                            }
                            Ok(Flow::CallRegister(_) | Flow::JumpRegister(_)) => {
                                !image.slots.is_empty()
                            }
                            _ => false,
                        }
                    };
                    if candidate && !self.reserve(pc, image, run) {
                        return false;
                    }
                    pc += 4;
                }
            }
        }
        self.scanned = Some(true);
        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Origin {
    Address(u64),
    Page {
        identity: (usize, u32),
        addend: i64,
        got: bool,
    },
    Got(ImportWitness),
}
type State = [Option<Origin>; 31];
fn reg(r: super::decode::Register) -> Option<usize> {
    match r.name {
        RegisterName::Gpr(n) if r.width == Width::X => Some(n as usize),
        _ => None,
    }
}
fn failure(run: &mut Run, pc: u64, why: &str) -> Result<(), ()> {
    run.gap(format!("code: AArch64 target at {pc:#x}: {why}"));
    Err(())
}

/// Resolve only calls in an already reachable CFG. A failed relocation/unsupported target
/// invalidates the whole pending function. Exact equality at every incoming edge is required;
/// a clobber or disagreement cannot leave a stale GOT witness. Work is shared across slices.
pub(crate) fn resolve_cfg(
    cfg: &Cfg,
    image: &A64ElfImage,
    run: &mut Run,
) -> Result<BTreeMap<u64, Branch>, ()> {
    let mut predecessors: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    if !run.charge(Work::Values, cfg.blocks.len() as u64 + 1) {
        return Err(());
    }
    for (&at, b) in &cfg.blocks {
        for &next in b.successors.iter().flatten() {
            if !cfg.blocks.contains_key(&next) {
                return Err(());
            }
            predecessors.entry(next).or_default().push(at);
        }
    }
    let entry: State = std::array::from_fn(|_| None);
    let mut out: BTreeMap<u64, State> = BTreeMap::new();
    let mut pending = BTreeSet::from([cfg.entry]);
    let mut passes = BTreeMap::new();
    while let Some(at) = pending.pop_first() {
        let count = passes.entry(at).or_insert(0u32);
        if *count == VALUE_PASSES {
            failure(run, at, "GOT provenance did not settle")?;
        }
        *count += 1;
        let Some(mut state) = input(at, cfg.entry, &entry, &predecessors, &out, run)? else {
            continue;
        };
        let b = cfg.blocks.get(&at).ok_or(())?;
        for (pc, ins) in cfg.block_insns(at, b) {
            step(&mut state, pc, ins, image, run)?;
        }
        if !run.charge(Work::Values, 32) {
            return Err(());
        }
        if out.get(&at) != Some(&state) {
            out.insert(at, state);
            pending.extend(b.successors.iter().flatten().copied());
        }
    }
    let mut calls = BTreeMap::new();
    for (&at, b) in &cfg.blocks {
        let mut state = input(at, cfg.entry, &entry, &predecessors, &out, run)?.ok_or(())?;
        for (pc, ins) in cfg.block_insns(at, b) {
            let target = match ins.flow {
                Flow::CallDirect(_) | Flow::JumpDirect(_)
                    if image.object && image.relocs.contains_key(&pc) =>
                {
                    Some(image.branch(pc, ins.word).ok_or_else(|| {
                        run.gap(format!(
                            "code: AArch64 unresolved branch relocation at {pc:#x}"
                        ));
                    })?)
                }
                Flow::CallDirect(t) | Flow::JumpDirect(t) => {
                    image.stubs.get(&t).cloned().map(Branch::Import)
                }
                Flow::CallRegister(n) | Flow::JumpRegister(n) => match &state[n as usize] {
                    Some(Origin::Got(w)) if !w.weak => Some(Branch::Import(w.clone())),
                    _ => {
                        failure(run, pc, "unresolved indirect branch")?;
                        None
                    }
                },
                _ => None,
            };
            if let Some(t) = target {
                calls.insert(pc, t);
            }
            step(&mut state, pc, ins, image, run)?;
        }
    }
    Ok(calls)
}
fn input(
    at: u64,
    entry_pc: u64,
    entry: &State,
    preds: &BTreeMap<u64, Vec<u64>>,
    out: &BTreeMap<u64, State>,
    run: &mut Run,
) -> Result<Option<State>, ()> {
    let mut state = if at == entry_pc {
        Some(entry.clone())
    } else {
        None
    };
    for pred in preds.get(&at).into_iter().flatten() {
        if !run.charge(Work::Values, 32) {
            return Err(());
        }
        if let Some(s) = out.get(pred) {
            match &mut state {
                Some(state) => {
                    for (a, b) in state.iter_mut().zip(s) {
                        if a != b {
                            *a = None;
                        }
                    }
                }
                None => state = Some(s.clone()),
            }
        }
    }
    Ok(state)
}
fn step(
    state: &mut State,
    pc: u64,
    ins: &A64Insn,
    image: &A64ElfImage,
    run: &mut Run,
) -> Result<(), ()> {
    if !run.charge(Work::Values, 64) {
        return Err(());
    }
    let before = state.clone();
    for r in ins.effects.writes.iter().flatten() {
        if let RegisterName::Gpr(n) = r.name {
            state[n as usize] = None;
        }
    }
    if image.excluded(pc, pc + 4) {
        return failure(run, pc, "unsupported or composed relocation");
    }
    let reloc = image.relocs.get(&pc);
    if let Some(r) = reloc {
        let Some(r) = r else {
            return failure(run, pc, "ambiguous relocation");
        };
        match r.kind {
            ADR_GOT_PAGE | ADR_PAGE => {
                let Operation::Address { dst, .. } = ins.operation else {
                    return failure(run, pc, "page relocation on wrong instruction");
                };
                let Some(dst) = reg(dst) else {
                    return failure(run, pc, "invalid page destination");
                };
                if ins.word & 0xffffffe0 != 0x90000000 {
                    return failure(run, pc, "noncanonical object ADRP");
                }
                if r.symbol.is_none() {
                    return failure(run, pc, "missing page symbol");
                }
                state[dst] = Some(Origin::Page {
                    identity: r.identity,
                    addend: r.addend,
                    got: r.kind == ADR_GOT_PAGE,
                });
            }
            LD64_GOT_LO12 | ADD_LO12 => {
                let (dst, base) = match (r.kind, ins.operation) {
                    (
                        LD64_GOT_LO12,
                        Operation::Memory {
                            load: true,
                            regs: [Some(dst), None],
                            base,
                            offset: 0,
                            ..
                        },
                    ) if ins.word & 0xffc00000 == 0xf9400000 => (reg(dst), reg(base)),
                    (
                        ADD_LO12,
                        Operation::AddImmediate {
                            dst,
                            src,
                            imm: 0,
                            subtract: false,
                        },
                    ) if ins.word & 0xffc00000 == 0x91000000 => (reg(dst), reg(src)),
                    _ => return failure(run, pc, "low relocation on wrong instruction"),
                };
                let (Some(dst), Some(base)) = (dst, base) else {
                    return failure(run, pc, "invalid low registers");
                };
                let expected = Some(Origin::Page {
                    identity: r.identity,
                    addend: r.addend,
                    got: r.kind == LD64_GOT_LO12,
                });
                if before[base] != expected {
                    return failure(run, pc, "mismatched or clobbered relocation pair");
                }
                let Some(s) = &r.symbol else {
                    return failure(run, pc, "missing low symbol");
                };
                if r.kind == LD64_GOT_LO12 {
                    if r.addend != 0 || !s.undefined || !s.global || s.weak || s.name.is_empty() {
                        return failure(run, pc, "unresolved GOT pair");
                    }
                    state[dst] = Some(Origin::Got(ImportWitness {
                        name: s.name.clone(),
                        relocation: r.kind,
                        at: pc,
                        weak: s.weak,
                    }));
                } else {
                    let Some(address) = s.address.and_then(|a| a.checked_add_signed(r.addend))
                    else {
                        return failure(run, pc, "unresolved address pair");
                    };
                    // A raw relocated object address is not a linked GOT entry.
                    state[dst] = Some(Origin::Address(address));
                }
            }
            super::super::image::aarch64::CALL26 | super::super::image::aarch64::JUMP26 => {
                if image.branch(pc, ins.word).is_none() {
                    return failure(run, pc, "unresolved branch relocation");
                }
            }
            _ => return failure(run, pc, "unsupported relocation"),
        }
    } else {
        match ins.operation {
            Operation::Address { dst, address } if !image.object => {
                if let Some(n) = reg(dst) {
                    state[n] = Some(Origin::Address(address));
                }
            }
            Operation::Copy { dst, src } => {
                if let (Some(dst), Some(src)) = (reg(dst), reg(src)) {
                    state[dst] = before[src].clone();
                }
            }
            Operation::AddImmediate {
                dst,
                src,
                imm,
                subtract,
            } => {
                if let (Some(dst), Some(src)) = (reg(dst), reg(src)) {
                    if let Some(Origin::Address(a)) = before[src] {
                        state[dst] = (if subtract {
                            a.checked_sub(imm)
                        } else {
                            a.checked_add(imm)
                        })
                        .map(Origin::Address);
                    }
                }
            }
            Operation::Memory {
                load: true,
                regs: [Some(dst), None],
                base,
                offset,
                mode: super::decode::AddressMode::Offset,
            } if !image.object => {
                if let (Some(dst), Some(base)) = (reg(dst), reg(base)) {
                    if let Some(Origin::Address(a)) = before[base] {
                        state[dst] = a
                            .checked_add_signed(i64::from(offset))
                            .and_then(|slot| image.slots.get(&slot))
                            .filter(|w| !w.weak)
                            .cloned()
                            .map(Origin::Got);
                    }
                }
            }
            _ => {}
        }
    }
    if matches!(ins.flow, Flow::CallDirect(_) | Flow::CallRegister(_)) {
        for reg in state.iter_mut().take(19) {
            *reg = None;
        }
        state[30] = None;
    }
    Ok(())
}
