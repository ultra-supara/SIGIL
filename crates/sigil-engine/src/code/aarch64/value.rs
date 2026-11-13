//! Conservative AAPCS64 values. No producer or architecture dispatch uses this module yet.
//!
//! Only Task 7's validated instructions enter the transfer function. There is no stack-memory
//! model or predicate/flags state. Both conditional edges always participate, including after
//! calls. The x86 lattice and its image/relocation semantics are deliberately independent.

use super::decode::{
    A64Insn, AddressMode, Flow, Operation, Register, RegisterName, WideMove, Width,
};
use super::Cfg;
use crate::code::reader::{read_slice, Reader, SliceWindow};
use crate::code::{Run, Work, STRING_BYTES, VALUE_PASSES};
use sigil_model::code_abi::{CodeAbi, SignatureDb};
use sigil_model::{
    ArgValue, ArgumentLayout, CallId, MachOLibrary, Reg, UntrustedText, ValueUnknown,
};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

const MAX_SET: usize = 4;
const MAX_DEPTH: u8 = 3;
const ARG_REGS: [Reg; 8] = [
    Reg::X0,
    Reg::X1,
    Reg::X2,
    Reg::X3,
    Reg::X4,
    Reg::X5,
    Reg::X6,
    Reg::X7,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Why {
    ClobberedByCall,
    MergedDisagreeing,
    FromMemory,
    NotModeled,
}

/// Constants retain all 64 bits. `address` is provenance from ADR/ADRP (and checked arithmetic
/// on it), never an immediate guessed to be a pointer. Shared subexpressions make state copies
/// bounded; expression depth and distinct alternatives are independently capped.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Value {
    Const {
        bits: u64,
        address: bool,
    },
    Param(u8),
    Return(u64),
    Load {
        base: Rc<Value>,
        offset: i64,
        width: u8,
        site: u64,
    },
    Low(Rc<Value>),
    Set(Rc<[Value]>),
    Unknown(Why),
}

impl Value {
    fn weight(&self) -> u64 {
        match self {
            Self::Load { base, .. } | Self::Low(base) => 1 + base.weight(),
            Self::Set(v) => 1 + v.iter().map(Self::weight).sum::<u64>(),
            _ => 1,
        }
    }
    fn depth(&self) -> u8 {
        match self {
            Self::Load { base, .. } | Self::Low(base) => 1 + base.depth(),
            Self::Set(v) => v.iter().map(Self::depth).max().unwrap_or(0),
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct A64State {
    pub regs: [Value; 31],
    pub sp: Value,
    abi: CodeAbi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    UnsupportedAbi,
    InvalidImage,
    Budget,
    Read,
    Unsettled,
    InvalidCfg,
}

/// A mapping supplied by the later bounded image builder, in this slice's analysis address
/// domain. `file_offset` is slice-relative, including for objects whose *addresses* are absolute
/// artifact offsets. Include non-file-backed/writable/executable mappings when validating
/// overlaps. `relocated` forbids reading raw bytes as runtime constants. The builder must also
/// reject any unmodeled aliases or runtime fixups; segment permissions alone are insufficient.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Mapping {
    pub start: u64,
    pub end: u64,
    pub file_offset: Option<u64>,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub relocated: bool,
}

/// A narrow value view, not the existing x86 image. Sorted nonoverlapping mappings are checked
/// once, without copying them. Reads still require the single artifact Reader and SliceWindow.
/// A future builder must obtain metadata through its own bounded, charged parsing APIs.
pub(crate) struct Image<'a> {
    window: SliceWindow,
    mappings: &'a [Mapping],
}
impl<'a> Image<'a> {
    pub fn new(
        window: SliceWindow,
        mappings: &'a [Mapping],
        run: &mut Run,
    ) -> Result<Self, Failure> {
        charge(run, mappings.len() as u64 + 1)?;
        let mut end = None;
        let valid = window.base.checked_add(window.len).is_some()
            && mappings.iter().all(|m| {
                let valid = m.start < m.end
                    && end.is_none_or(|e| e <= m.start)
                    && m.file_offset.is_none_or(|off| {
                        off.checked_add(m.end - m.start)
                            .is_some_and(|e| e <= window.len)
                    });
                end = Some(m.end);
                valid
            });
        if !valid {
            run.gap("code: AArch64 value image has invalid or overlapping mappings".into());
            return Err(Failure::InvalidImage);
        }
        Ok(Self { window, mappings })
    }

    fn readonly(&self, at: u64) -> Option<&Mapping> {
        let index = self.mappings.partition_point(|m| m.end <= at);
        self.mappings.get(index).filter(|m| {
            m.start <= at
                && m.readable
                && !m.writable
                && !m.executable
                && !m.relocated
                && m.file_offset.is_some()
        })
    }

    fn read(
        &self,
        at: u64,
        len: u64,
        reader: &mut Reader<'_>,
        run: &mut Run,
    ) -> Result<Option<Vec<u8>>, Failure> {
        if run.stopped() {
            return Err(Failure::Budget);
        }
        let Some(m) = self.readonly(at) else {
            return Ok(None);
        };
        let Some(end) = at.checked_add(len).filter(|end| *end <= m.end) else {
            return Ok(None);
        };
        let offset = m
            .file_offset
            .and_then(|off| off.checked_add(at - m.start))
            .ok_or(Failure::InvalidImage)?;
        match read_slice(reader, self.window, offset, end - at) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(why) => {
                run.refusal(why, "AArch64 value", reader);
                Err(if run.stopped() {
                    Failure::Budget
                } else {
                    Failure::Read
                })
            }
        }
    }

    fn string(
        &self,
        at: u64,
        reader: &mut Reader<'_>,
        run: &mut Run,
    ) -> Result<Option<Vec<u8>>, Failure> {
        let Some(m) = self.readonly(at) else {
            return Ok(None);
        };
        let len = (m.end - at).min(STRING_BYTES);
        let Some(mut bytes) = self.read(at, len, reader, run)? else {
            return Ok(None);
        };
        let Some(end) = bytes.iter().position(|b| *b == 0) else {
            return Ok(None);
        };
        bytes.truncate(end);
        Ok(Some(bytes))
    }
}

fn constant(bits: u64) -> Value {
    Value::Const {
        bits,
        address: false,
    }
}
fn unknown() -> Value {
    Value::Unknown(Why::NotModeled)
}

impl A64State {
    pub fn entry(abi: CodeAbi) -> Result<Self, Failure> {
        if abi == CodeAbi::DarwinX86_64 {
            return Err(Failure::UnsupportedAbi);
        }
        Ok(Self {
            regs: std::array::from_fn(|n| {
                if n < 8 {
                    Value::Param(n as u8)
                } else {
                    unknown()
                }
            }),
            sp: unknown(),
            abi,
        })
    }
    pub fn read(&self, r: Register) -> Value {
        let value = match r.name {
            RegisterName::Gpr(18) if self.abi == CodeAbi::DarwinArm64 => unknown(),
            RegisterName::Gpr(n) => self
                .regs
                .get(usize::from(n))
                .cloned()
                .unwrap_or_else(unknown),
            RegisterName::Sp => self.sp.clone(),
            RegisterName::Zero => constant(0),
        };
        narrow(value, r.width)
    }
    fn write(&mut self, r: Register, value: Value) {
        let value = narrow(value, r.width);
        match r.name {
            RegisterName::Gpr(18) if self.abi == CodeAbi::DarwinArm64 => self.regs[18] = unknown(),
            RegisterName::Gpr(n) => {
                if let Some(slot) = self.regs.get_mut(usize::from(n)) {
                    *slot = value;
                }
            }
            RegisterName::Sp => self.sp = value,
            RegisterName::Zero => {}
        }
    }
    fn weight(&self) -> u64 {
        self.sp.weight() + self.regs.iter().map(Value::weight).sum::<u64>()
    }
    fn call(&mut self, pc: u64) {
        for reg in &mut self.regs[..18] {
            *reg = Value::Unknown(Why::ClobberedByCall);
        }
        self.regs[0] = Value::Return(pc);
        // x18 is platform-defined, not a portable callee-saved location.
        self.regs[18] = unknown();
        self.regs[30] = Value::Unknown(Why::ClobberedByCall);
    }
}

fn narrow(v: Value, width: Width) -> Value {
    if width == Width::X {
        return v;
    }
    match v {
        Value::Const { bits, .. } => constant(bits & u64::from(u32::MAX)),
        Value::Unknown(_) | Value::Low(_) => v,
        Value::Load { width: 32, .. } => v,
        Value::Set(members) => set(members.iter().cloned().map(|v| narrow(v, width)).collect()),
        _ if v.depth() < MAX_DEPTH => Value::Low(Rc::new(v)),
        _ => unknown(),
    }
}

fn set(mut values: Vec<Value>) -> Value {
    values.sort_unstable();
    values.dedup();
    if values.len() > MAX_SET || values.iter().any(|v| matches!(v, Value::Unknown(_))) {
        Value::Unknown(Why::MergedDisagreeing)
    } else if values.len() == 1 {
        values.pop().unwrap_or_else(unknown)
    } else {
        Value::Set(values.into())
    }
}

/// The caller charges both expression weights before comparison/sorting. No Set nests in a
/// Set; an unknown alternative absorbs disagreement instead of inventing an enumerable value.
pub(crate) fn join(a: &Value, b: &Value) -> Value {
    if a == b {
        return a.clone();
    }
    if matches!(a, Value::Unknown(_)) || matches!(b, Value::Unknown(_)) {
        return Value::Unknown(Why::MergedDisagreeing);
    }
    let mut members = Vec::with_capacity(MAX_SET * 2);
    for v in [a, b] {
        match v {
            Value::Set(v) => members.extend(v.iter().cloned()),
            _ => members.push(v.clone()),
        }
    }
    set(members)
}

fn charge(run: &mut Run, weight: u64) -> Result<(), Failure> {
    if !run.stopped() && run.charge(Work::Values, weight) {
        Ok(())
    } else {
        Err(Failure::Budget)
    }
}

fn add(v: Value, offset: i64, width: Width) -> Value {
    match v {
        Value::Const { bits, address } => bits
            .checked_add_signed(offset)
            .filter(|n| width == Width::X || *n <= u64::from(u32::MAX))
            .map(|bits| Value::Const {
                bits,
                address: address && width == Width::X,
            })
            .unwrap_or_else(unknown),
        Value::Set(v) => set(v.iter().cloned().map(|v| add(v, offset, width)).collect()),
        _ if offset == 0 => narrow(v, width),
        _ => unknown(),
    }
}

/// Apply one validated instruction at its actual PC. The explicit PC is necessary because
/// Task 7's A64Insn carries no PC; Reader is explicit so no hidden read/reset can occur.
/// Charge the whole state weight before any comparison, expression growth, copy, or load.
/// Refusal leaves no publishable function result; the caller must discard the current state.
pub(crate) fn step(
    state: &mut A64State,
    pc: u64,
    ins: &A64Insn,
    image: &Image<'_>,
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> Result<(), Failure> {
    charge(run, 1 + state.weight())?;
    match ins.operation {
        Operation::Control => {
            if matches!(ins.flow, Flow::CallDirect(_) | Flow::CallRegister(_)) {
                state.call(pc);
            }
        }
        Operation::Nop => {}
        Operation::Address { dst, address } => state.write(
            dst,
            Value::Const {
                bits: address,
                address: true,
            },
        ),
        Operation::Copy { dst, src } => state.write(dst, state.read(src)),
        Operation::WideMove {
            kind,
            dst,
            imm,
            shift,
        } => {
            let bits = u64::from(imm) << shift;
            let value = match kind {
                WideMove::Zero => constant(bits),
                WideMove::Not => constant(!bits),
                WideMove::Keep => match state.read(dst) {
                    Value::Const { bits: old, .. } => {
                        constant((old & !(0xffff_u64 << shift)) | bits)
                    }
                    _ => unknown(),
                },
            };
            state.write(dst, value);
        }
        Operation::AddImmediate {
            dst,
            src,
            imm,
            subtract,
        } => {
            // The audited encoding bounds imm to 4095 << 12, comfortably inside i64.
            let offset =
                i64::try_from(imm)
                    .ok()
                    .and_then(|i| if subtract { i.checked_neg() } else { Some(i) });
            let value = offset
                .map(|off| add(state.read(src), off, dst.width))
                .unwrap_or_else(unknown);
            state.write(dst, value);
        }
        Operation::Memory {
            load,
            regs,
            base,
            offset,
            mode,
        } => {
            let before = state.read(base);
            if load {
                for dst in regs.iter().flatten() {
                    let value = if regs[1].is_some()
                        || mode != AddressMode::Offset
                        || base.name == RegisterName::Sp
                    {
                        Value::Unknown(Why::FromMemory)
                    } else {
                        load_value(
                            &before,
                            i64::from(offset),
                            dst.width,
                            pc,
                            image,
                            reader,
                            run,
                        )?
                    };
                    state.write(*dst, value);
                }
            }
            if mode != AddressMode::Offset {
                state.write(base, add(before, i64::from(offset), base.width));
            }
        }
    }
    Ok(())
}

fn load_value(
    base: &Value,
    offset: i64,
    width: Width,
    site: u64,
    image: &Image<'_>,
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> Result<Value, Failure> {
    let bytes = if width == Width::X { 8 } else { 4 };
    if let Value::Const { bits, .. } = base {
        let Some(at) = bits.checked_add_signed(offset) else {
            return Ok(Value::Unknown(Why::FromMemory));
        };
        if let Some(raw) = image.read(at, bytes, reader, run)? {
            let mut le = [0; 8];
            le[..raw.len()].copy_from_slice(&raw);
            return Ok(constant(u64::from_le_bytes(le)));
        }
    }
    Ok(
        if base.depth() >= MAX_DEPTH || matches!(base, Value::Unknown(_) | Value::Set(_)) {
            Value::Unknown(Why::FromMemory)
        } else {
            Value::Load {
                base: Rc::new(base.clone()),
                offset,
                width: (bytes * 8) as u8,
                site,
            }
        },
    )
}

/// Use the archived registry for the actual target ABI/raw name/library witness. No capability
/// arity enters this API. Target proof and retention of its exact witness remain Tasks 9–10.
pub(crate) struct Target<'a> {
    pub db: &'a SignatureDb,
    pub abi: CodeAbi,
    pub symbol: &'a UntrustedText,
    pub library: Option<&'a MachOLibrary>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Arguments {
    pub values: Vec<ArgValue>,
    pub layout: ArgumentLayout,
}

/// Staged model values, not a recorder commit. Every ReturnOf ID must belong to the final
/// retained-call closure; the recorder must retain that call or conservatively downgrade the
/// reference (and any enclosing Load/Low/Set) before publication. A read failure discards the
/// entire function's pending output, including arguments already projected for earlier calls.
pub(crate) fn arguments(
    state: &A64State,
    target: Target<'_>,
    call: u64,
    image: &Image<'_>,
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> Result<Arguments, Failure> {
    charge(run, 1)?;
    if target.abi != state.abi {
        return Err(Failure::UnsupportedAbi);
    }
    let plan = target
        .db
        .argument_plan(Some(target.abi), target.symbol, target.library);
    let mut values = Vec::with_capacity(plan.registers.len());
    for reg in plan.registers {
        let n = ARG_REGS
            .iter()
            .position(|r| r == reg)
            .ok_or(Failure::UnsupportedAbi)?;
        charge(run, state.regs[n].weight())?;
        values.push(model(&state.regs[n], *reg, image, reader, run)?);
    }
    let id = call_id(call)?;
    if plan
        .coverage_gap(&id)
        .is_some_and(|gap| !run.required_gap(gap))
    {
        return Err(Failure::Budget);
    }
    Ok(Arguments {
        values,
        layout: plan.layout,
    })
}

fn call_id(pc: u64) -> Result<CallId, Failure> {
    CallId::new(format!("cs:{pc:#x}")).map_err(|_| Failure::InvalidCfg)
}

fn model(
    value: &Value,
    reg: Reg,
    image: &Image<'_>,
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> Result<ArgValue, Failure> {
    Ok(match value {
        Value::Const { bits, address } => {
            if *address {
                if let Some(bytes) = image.string(*bits, reader, run)? {
                    return Ok(ArgValue::ConstStr {
                        reg,
                        addr: *bits,
                        value: UntrustedText::from_bytes(bytes),
                    });
                }
            }
            ArgValue::ConstInt {
                reg,
                value: *bits as i64,
            }
        }
        Value::Param(index) => ArgValue::Param { reg, index: *index },
        Value::Return(pc) => ArgValue::ReturnOf {
            reg,
            call: call_id(*pc)?,
        },
        Value::Load {
            base,
            offset,
            width,
            site,
        } => ArgValue::Load {
            reg,
            base: Box::new(model(base, reg, image, reader, run)?),
            offset: *offset,
            width: *width,
            site: *site,
        },
        Value::Low(value) => ArgValue::Low {
            reg,
            value: Box::new(model(value, reg, image, reader, run)?),
            bits: 32,
        },
        Value::Set(values) => ArgValue::Set {
            reg,
            members: values
                .iter()
                .map(|v| model(v, reg, image, reader, run))
                .collect::<Result<_, _>>()?,
        },
        Value::Unknown(why) => ArgValue::Unknown {
            reg,
            reason: match why {
                Why::ClobberedByCall => ValueUnknown::ClobberedByCall,
                Why::MergedDisagreeing => ValueUnknown::MergedDisagreeing,
                Why::FromMemory => ValueUnknown::FromMemory,
                Why::NotModeled => ValueUnknown::NotModeled,
            },
        },
    })
}

/// States are staged per function and returned only after the final charged replay succeeds.
/// They prove values, not target identities or call facts. Task 10's recorder must also finish
/// relocation/target/layout proofs before committing, and charge calls/names transactionally.
#[derive(Debug)]
pub(crate) struct Values {
    pub calls: BTreeMap<u64, A64State>,
}

/// `cfg` is a successful Task 7 CFG, still subject to later relocation/target proofs. Its
/// candidate reservations remain owned by the artifact; this solver does not repeat them.
#[cfg(test)]
pub(crate) fn solve(
    cfg: &Cfg,
    abi: CodeAbi,
    image: &Image<'_>,
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> Result<Values, Failure> {
    solve_with_unapplied(cfg, abi, image, &|_| false, reader, run)
}

/// A format adapter can forbid raw relocation-written values without changing the validated
/// instruction or CFG. Preserve control flow/call clobbers and invalidate every written
/// destination (including pair destinations and writeback bases); do not read raw memory.
pub(crate) fn solve_with_unapplied(
    cfg: &Cfg,
    abi: CodeAbi,
    image: &Image<'_>,
    unapplied: &dyn Fn(u64) -> bool,
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> Result<Values, Failure> {
    let result = propagate_unapplied(cfg, abi, image, unapplied, reader, run);
    if let Err(why) = result {
        run.gap(format!(
            "code: AArch64 function at {:#x}: value analysis {why:?}",
            cfg.entry
        ));
    }
    result
}

fn merge_state(a: &mut A64State, b: &A64State, run: &mut Run) -> Result<(), Failure> {
    charge(run, a.weight() + b.weight() + 1)?;
    for (a, b) in a.regs.iter_mut().zip(&b.regs) {
        *a = join(a, b);
    }
    a.sp = join(&a.sp, &b.sp);
    Ok(())
}

fn input(
    at: u64,
    cfg: &Cfg,
    entry: &A64State,
    predecessors: &BTreeMap<u64, Vec<u64>>,
    out: &BTreeMap<u64, A64State>,
    run: &mut Run,
) -> Result<Option<A64State>, Failure> {
    let mut s = if at == cfg.entry {
        charge(run, entry.weight())?;
        Some(entry.clone())
    } else {
        None
    };
    for pred in predecessors.get(&at).into_iter().flatten() {
        charge(run, 1)?;
        if let Some(value) = out.get(pred) {
            if let Some(s) = &mut s {
                merge_state(s, value, run)?;
            } else {
                charge(run, value.weight())?;
                s = Some(value.clone());
            }
        }
    }
    Ok(s)
}

fn relocated_step(
    state: &mut A64State,
    pc: u64,
    ins: &A64Insn,
    image: &Image<'_>,
    unapplied: bool,
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> Result<(), Failure> {
    if !unapplied || matches!(ins.operation, Operation::Control) {
        return step(state, pc, ins, image, reader, run);
    }
    charge(run, 1 + state.weight())?;
    for reg in ins.effects.writes.iter().flatten() {
        state.write(*reg, unknown());
    }
    Ok(())
}

fn propagate_unapplied(
    cfg: &Cfg,
    abi: CodeAbi,
    image: &Image<'_>,
    unapplied: &dyn Fn(u64) -> bool,
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> Result<Values, Failure> {
    let entry = A64State::entry(abi)?;
    charge(run, cfg.blocks.len() as u64 + 1)?;
    if !cfg.blocks.contains_key(&cfg.entry) {
        return Err(Failure::InvalidCfg);
    }
    let mut predecessors: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for (&at, block) in &cfg.blocks {
        for next in block.successors.iter().flatten() {
            if !cfg.blocks.contains_key(next) {
                return Err(Failure::InvalidCfg);
            }
            predecessors.entry(*next).or_default().push(at);
        }
    }
    let mut pending = BTreeSet::from([cfg.entry]);
    let mut out = BTreeMap::new();
    let mut passes: BTreeMap<u64, u32> = BTreeMap::new();
    while let Some(at) = pending.pop_first() {
        let count = passes.entry(at).or_default();
        if *count == VALUE_PASSES {
            return Err(Failure::Unsettled);
        }
        *count += 1;
        let Some(mut s) = input(at, cfg, &entry, &predecessors, &out, run)? else {
            continue;
        };
        let block = cfg.blocks.get(&at).ok_or(Failure::InvalidCfg)?;
        for (pc, ins) in cfg.block_insns(at, block) {
            relocated_step(&mut s, pc, ins, image, unapplied(pc), reader, run)?;
        }
        let equal = if let Some(old) = out.get(&at) {
            charge(run, s.weight() + old.weight())?;
            *old == s
        } else {
            false
        };
        if !equal {
            out.insert(at, s);
            pending.extend(block.successors.iter().flatten().copied());
        }
    }
    let mut calls = BTreeMap::new();
    for (&at, block) in &cfg.blocks {
        let Some(mut s) = input(at, cfg, &entry, &predecessors, &out, run)? else {
            return Err(Failure::InvalidCfg);
        };
        for (pc, ins) in cfg.block_insns(at, block) {
            if matches!(ins.flow, Flow::CallDirect(_) | Flow::CallRegister(_))
                || (matches!(ins.flow, Flow::JumpDirect(_) | Flow::JumpRegister(_))
                    && block.last == pc
                    && block.successors == [None, None])
            {
                charge(run, s.weight())?;
                calls.insert(pc, s.clone());
            }
            relocated_step(&mut s, pc, ins, image, unapplied(pc), reader, run)?;
        }
    }
    Ok(Values { calls })
}

#[cfg(test)]
#[path = "value_tests.rs"]
mod tests;
