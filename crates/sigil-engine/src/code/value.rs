//! Register values (PR-5a spec §4.7): forward propagation over one function's CFG, to a
//! fixpoint, per register.
//!
//! - A value's parts are shared ([`Rc`]): a state is 16 values of 4 words, and a clone of one
//!   is 16 counts, however deep its values are. States are kept per block during the fixpoint
//!   and, after it, only before the instructions [`kept`] names.
//! - [`Val::Sym`] (spec rev. 2's `SymbolAddr`) is internal: it never leaves the engine.

// Used outside tests from Tasks 10–11 (`record`, `analyze`); until then only tests solve.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use iced_x86::{
    FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register,
};
use sigil_model::ImportVia;

use super::decode::{Block, Cfg, Failure, Insn};
use super::image::{Callee, Image, Kind, Meaning, Name, Use};
use super::VALUE_PASSES;

/// Why a value is unknown (`ValueUnknown`, with an order for sets).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Why {
    ClobberedByCall,
    MergedDisagreeing,
    FromMemory,
    NotModeled,
}

/// A register's value. Its parts are shared: a clone is a count.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Val {
    /// `address`: formed by an address-forming instruction (a `lea`, a relocation), so it may
    /// name a constant string; an immediate never does.
    Const {
        value: u64,
        address: bool,
    },
    /// Entry parameter `k` (rdi rsi rdx rcx r8 r9: 0–5).
    Param(u8),
    /// The return value of the call at this address.
    Ret(u64),
    /// `[base+offset]`, `width` bits (8, 16, 32, or 64), zero-extended, read at `site`. At most
    /// [`MAX_LOAD_DEPTH`] loads nest.
    Load {
        base: Rc<Val>,
        offset: i64,
        width: u8,
        site: u64,
    },
    /// Only the low `bits` (8, 16, or 32) are `value`'s. `value` is never a `Low`, a `Set`, or
    /// an `Unknown`.
    Low {
        value: Rc<Val>,
        bits: u8,
    },
    /// 2 to [`MAX_SET`] values, sorted, none a `Set` or an `Unknown`.
    Set(Rc<[Val]>),
    /// The address of a symbol, formed at `site`.
    Sym {
        of: Rc<SymRef>,
        site: u64,
    },
    Unknown(Why),
}

/// The symbol a [`Val::Sym`] is the address of.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SymRef {
    /// A symbol by name: undefined (`defined: None`), or defined at an address. `via`: a GOT
    /// slot's load (`Got`), a stub's address (`Plt`, `PltSec`), or in a relocatable object an
    /// undefined symbol's relocation (`Reloc`).
    Named {
        name: Name,
        defined: Option<u64>,
        via: Via,
    },
    /// A relocatable object's defined symbol, loaded from its GOT entry: its file offset (`S`).
    /// No name is read for it.
    Internal(u64),
}

/// `ImportVia`, with an order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Via {
    Plt,
    PltSec,
    Got,
    Reloc,
}

impl From<ImportVia> for Via {
    fn from(v: ImportVia) -> Via {
        match v {
            ImportVia::Plt => Via::Plt,
            ImportVia::PltSec => Via::PltSec,
            ImportVia::Got => Via::Got,
            ImportVia::Reloc => Via::Reloc,
        }
    }
}

impl From<Via> for ImportVia {
    fn from(v: Via) -> ImportVia {
        match v {
            Via::Plt => ImportVia::Plt,
            Via::PltSec => ImportVia::PltSec,
            Via::Got => ImportVia::Got,
            Via::Reloc => ImportVia::Reloc,
        }
    }
}

/// The general-purpose registers.
pub(crate) const GPRS: usize = 16;
/// The 16 GPRs, by [`gpr`] index: rax rcx rdx rbx rsp rbp rsi rdi r8 … r15.
pub(crate) type State = [Val; GPRS];

pub(crate) const MAX_SET: usize = 4;
pub(crate) const MAX_LOAD_DEPTH: usize = 3;
/// The SysV argument registers, as GPR indices: rdi rsi rdx rcx r8 r9.
pub(crate) const ARGS: [usize; 6] = [7, 6, 2, 1, 8, 9];
/// The SysV caller-saved registers: rax rcx rdx rsi rdi r8–r11.
const CALLER_SAVED: [usize; 9] = [0, 1, 2, 6, 7, 8, 9, 10, 11];
const RAX: usize = 0;
const RCX: usize = 1;
const RSP: usize = 4;
const R11: usize = 11;

/// The GPR index of `r` or of the register it is part of (`edi`, `di`, `dil` → rdi).
pub(crate) fn gpr(r: Register) -> Option<usize> {
    const FULL: [Register; GPRS] = [
        Register::RAX,
        Register::RCX,
        Register::RDX,
        Register::RBX,
        Register::RSP,
        Register::RBP,
        Register::RSI,
        Register::RDI,
        Register::R8,
        Register::R9,
        Register::R10,
        Register::R11,
        Register::R12,
        Register::R13,
        Register::R14,
        Register::R15,
    ];
    let full = r.full_register();
    FULL.iter().position(|g| *g == full)
}

fn high_byte(r: Register) -> bool {
    matches!(r, Register::AH | Register::BH | Register::CH | Register::DH)
}

fn set(s: &mut State, r: usize, v: Val) {
    if let Some(x) = s.get_mut(r) {
        *x = v;
    }
}

/// How many loads nest in `v`, through `Low`s and `Set`s.
fn depth(v: &Val) -> usize {
    match v {
        Val::Load { base, .. } => 1 + depth(base),
        Val::Low { value, .. } => depth(value),
        Val::Set(members) => members.iter().map(depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// One value standing for `members`: the member itself when one remains, else a `Set`.
/// An `Unknown` among them, or more than [`MAX_SET`], gives `Unknown(MergedDisagreeing)`.
fn set_of(mut members: Vec<Val>) -> Val {
    if members.iter().any(|m| matches!(m, Val::Unknown(_))) {
        return Val::Unknown(Why::MergedDisagreeing);
    }
    members.sort();
    members.dedup();
    if members.len() > MAX_SET {
        return Val::Unknown(Why::MergedDisagreeing);
    }
    if members.len() == 1 {
        if let Some(m) = members.pop() {
            return m;
        }
    }
    if members.is_empty() {
        return Val::Unknown(Why::MergedDisagreeing);
    }
    Val::Set(members.into())
}

/// Two values merged at a join (spec §4.7): equal values stay; others become a flat `Set`.
pub(crate) fn join(a: &Val, b: &Val) -> Val {
    if a == b {
        return a.clone();
    }
    let mut members = Vec::with_capacity(2 * MAX_SET);
    for v in [a, b] {
        match v {
            Val::Set(m) => members.extend(m.iter().cloned()),
            other => members.push(other.clone()),
        }
    }
    set_of(members)
}

fn join_states(a: &State, b: &State) -> State {
    let mut out = a.clone();
    for (x, y) in out.iter_mut().zip(b) {
        if x != y {
            *x = join(x, y);
        }
    }
    out
}

/// The low `bits` of `v`, as a sub-register read or a 32-bit write gives them. A known
/// constant is truncated (an address stays one only if unchanged); a load of at most `bits`
/// bits is already all of its value; a `Set` gives the set of its members' low bits.
pub(crate) fn low(v: Val, bits: u8) -> Val {
    if bits >= 64 {
        return v;
    }
    match v {
        Val::Const { value, address } => {
            let low = value & ((1u64 << bits) - 1);
            Val::Const {
                value: low,
                address: address && low == value,
            }
        }
        Val::Load { width, .. } if width <= bits => v,
        Val::Low { value, bits: b } => Val::Low {
            value,
            bits: b.min(bits),
        },
        Val::Set(members) => set_of(members.iter().map(|m| low(m.clone(), bits)).collect()),
        Val::Unknown(_) => v,
        other => Val::Low {
            value: Rc::new(other),
            bits,
        },
    }
}

/// The register after an 8- or 16-bit write (`size` bytes) of `v`: only the low bits are
/// known, the rest of the register is not.
pub(crate) fn write(v: Val, size: usize) -> Val {
    let bits = if size == 1 { 8 } else { 16 };
    match v {
        Val::Low { value, bits: b } => Val::Low {
            value,
            bits: b.min(bits),
        },
        Val::Set(members) => set_of(members.iter().map(|m| write(m.clone(), size)).collect()),
        Val::Unknown(_) => v,
        other => Val::Low {
            value: Rc::new(other),
            bits,
        },
    }
}

/// The register `dst` after `v` is written to it: whole, zero-extended (a 32-bit write), or in
/// part. A high-byte register is not modeled.
fn written(v: Val, dst: Register) -> Val {
    if high_byte(dst) {
        return Val::Unknown(Why::NotModeled);
    }
    match dst.size() {
        8 => v,
        4 => low(v, 32),
        n => write(v, n),
    }
}

fn callee_ref(c: Callee) -> SymRef {
    match c {
        Callee::Import(name) => SymRef::Named {
            name,
            defined: None,
            via: Via::Reloc,
        },
        Callee::Internal(at) => SymRef::Internal(at),
    }
}

fn is_immediate(k: OpKind) -> bool {
    matches!(
        k,
        OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

/// The address of the displacement field of `insn`, if it has one.
fn disp_field(insn: &Insn) -> Option<u64> {
    insn.offs.has_displacement().then(|| {
        insn.ins
            .ip()
            .saturating_add(insn.offs.displacement_offset() as u64)
    })
}

/// The address of the (first) immediate field of `insn`, if it has one.
fn imm_field(insn: &Insn) -> Option<u64> {
    insn.offs.has_immediate().then(|| {
        insn.ins
            .ip()
            .saturating_add(insn.offs.immediate_offset() as u64)
    })
}

/// Whether the instruction enters the kernel: it writes `rax`, `rcx`, `r11`, and is no call.
fn kernel_entry(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Syscall | Mnemonic::Sysenter | Mnemonic::Int | Mnemonic::Int1 | Mnemonic::Into
    )
}

/// The transfer function, with its scratch state.
pub(crate) struct Machine<'a> {
    img: &'a Image,
    info: InstructionInfoFactory,
}

impl<'a> Machine<'a> {
    pub fn new(img: &'a Image) -> Machine<'a> {
        Machine {
            img,
            info: InstructionInfoFactory::new(),
        }
    }

    /// `s` after `insn`. `rsp` is never known: every stack address is unknown.
    pub fn step(&mut self, s: &mut State, insn: &Insn) {
        let ins = &insn.ins;
        if ins.mnemonic() == Mnemonic::Call {
            for r in CALLER_SAVED {
                s[r] = Val::Unknown(Why::ClobberedByCall);
            }
            s[RAX] = Val::Ret(ins.ip());
        } else {
            match self.modeled(s, insn) {
                Some((d, v)) => set(s, d, v),
                None => self.unmodeled(s, ins),
            }
            if kernel_entry(ins.mnemonic()) {
                // What the kernel writes. Never a `Ret`: no call site is made for it.
                for r in [RAX, RCX, R11] {
                    s[r] = Val::Unknown(Why::NotModeled);
                }
            }
        }
        s[RSP] = Val::Unknown(Why::NotModeled);
    }

    /// Every GPR an instruction not modeled writes, as iced lists them, becomes unknown:
    /// `FromMemory` for a `pop`, else `NotModeled`.
    fn unmodeled(&mut self, s: &mut State, ins: &Instruction) {
        let why = if ins.mnemonic() == Mnemonic::Pop {
            Why::FromMemory
        } else {
            Why::NotModeled
        };
        for u in self.info.info(ins).used_registers() {
            let writes = matches!(
                u.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            );
            if let Some(r) = gpr(u.register()).filter(|_| writes) {
                set(s, r, Val::Unknown(why));
            }
        }
    }

    /// The modeled forms, which write only their destination: `(destination GPR, value)`.
    fn modeled(&self, s: &State, insn: &Insn) -> Option<(usize, Val)> {
        let ins = &insn.ins;
        if ins.op_count() < 1 || ins.op0_kind() != OpKind::Register {
            return None;
        }
        let dst = ins.op0_register();
        let d = gpr(dst)?;
        let size = dst.size();
        let same =
            ins.op_count() == 2 && ins.op1_kind() == OpKind::Register && ins.op1_register() == dst;
        let v = match ins.mnemonic() {
            Mnemonic::Mov | Mnemonic::Movzx => {
                let src = self.operand(s, insn, 1)?;
                // An immediate is the value itself, which a 32-bit write zero-extends.
                if size == 4 && is_immediate(ins.op1_kind()) {
                    src
                } else {
                    written(src, dst)
                }
            }
            Mnemonic::Movsx | Mnemonic::Movsxd => Val::Unknown(Why::NotModeled),
            Mnemonic::Lea if size == 8 => self.address(s, insn),
            Mnemonic::Lea => Val::Unknown(Why::NotModeled),
            Mnemonic::Xor | Mnemonic::Sub if same => written(
                Val::Const {
                    value: 0,
                    address: false,
                },
                dst,
            ),
            _ => return None,
        };
        Some((d, v))
    }

    /// Operand `i` as read. `None`: not a GPR, memory, or immediate operand.
    fn operand(&self, s: &State, insn: &Insn, i: u32) -> Option<Val> {
        let ins = &insn.ins;
        Some(match ins.op_kind(i) {
            OpKind::Register => {
                let r = ins.op_register(i);
                if high_byte(r) {
                    return Some(Val::Unknown(Why::NotModeled));
                }
                let v = s.get(gpr(r)?)?.clone();
                match r.size() {
                    8 => v,
                    4 => low(v, 32),
                    2 => low(v, 16),
                    1 => low(v, 8),
                    _ => return None,
                }
            }
            OpKind::Memory => {
                let width = u8::try_from(ins.memory_size().size().checked_mul(8)?).ok()?;
                if ![8, 16, 32, 64].contains(&width) {
                    return None;
                }
                self.load(s, insn, width)
            }
            k if is_immediate(k) => self.immediate(insn, ins.immediate(i)),
            _ => return None,
        })
    }

    /// The meaning of the relocation on `field` of `insn` used as `use_` (a relocatable object).
    fn relocated(&self, field: Option<u64>, insn: &Insn, use_: Use) -> Option<Meaning> {
        self.img.field(field?, insn.ins.next_ip(), use_)
    }

    /// The symbol whose stub is at `addr`.
    fn stub(&self, addr: u64) -> Option<SymRef> {
        self.img.stubs.get(&addr)?;
        let (sym, via) = self.img.symbol_at(addr)?;
        Some(SymRef::Named {
            name: sym.name,
            defined: sym.defined,
            via: via.into(),
        })
    }

    /// An immediate `value`: a number, except where a relocation gives its meaning (a
    /// relocatable object), or at a stub's address in an executable (the address of an import a
    /// non-PIE file takes).
    fn immediate(&self, insn: &Insn, value: u64) -> Val {
        let site = insn.ins.ip();
        let number = Val::Const {
            value,
            address: false,
        };
        match self.img.kind {
            Kind::Relocatable => match self.relocated(imm_field(insn), insn, Use::Immediate) {
                Some(Meaning::Address(a)) => Val::Const {
                    value: a,
                    address: true,
                },
                Some(Meaning::SymbolAddr(name)) => Val::Sym {
                    of: Rc::new(SymRef::Named {
                        name,
                        defined: None,
                        via: Via::Reloc,
                    }),
                    site,
                },
                Some(_) => Val::Unknown(Why::NotModeled),
                None => number,
            },
            Kind::Executable => match self.stub(value) {
                Some(of) => Val::Sym {
                    of: Rc::new(of),
                    site,
                },
                None => number,
            },
            Kind::Shared => number,
        }
    }

    /// The value a memory read of `width` bits gives (spec §4.7 Loads).
    fn load(&self, s: &State, insn: &Insn, width: u8) -> Val {
        let ins = &insn.ins;
        let site = ins.ip();
        if matches!(ins.segment_prefix(), Register::FS | Register::GS) {
            // Thread-local or segment-based: the segment's base is not tracked.
            return Val::Unknown(Why::FromMemory);
        }
        if ins.memory_index() != Register::None {
            return Val::Unknown(Why::NotModeled);
        }
        let at = |a: u64| Val::Load {
            base: Rc::new(Val::Const {
                value: a,
                address: true,
            }),
            offset: 0,
            width,
            site,
        };
        let base = ins.memory_base();
        let rip = base == Register::RIP;
        match (self.img.kind, base) {
            (Kind::Relocatable, Register::RIP | Register::None) => {
                let use_ = if rip { Use::Memory } else { Use::Absolute };
                match self.relocated(disp_field(insn), insn, use_) {
                    Some(Meaning::GotEntry(c)) if width == 64 => Val::Sym {
                        of: Rc::new(callee_ref(c)),
                        site,
                    },
                    Some(Meaning::Address(a)) => at(a),
                    Some(_) => Val::Unknown(Why::NotModeled),
                    // The same section, not relocated.
                    None if rip => at(ins.ip_rel_memory_address()),
                    None => Val::Unknown(Why::NotModeled),
                }
            }
            (kind, Register::RIP | Register::None) => {
                let a = if rip {
                    ins.ip_rel_memory_address()
                } else {
                    ins.memory_displacement64()
                };
                let slot = (rip || kind == Kind::Executable)
                    .then(|| self.img.slots.get(&a))
                    .flatten();
                match slot {
                    Some(sym) if width == 64 => Val::Sym {
                        of: Rc::new(SymRef::Named {
                            name: sym.name.clone(),
                            defined: sym.defined,
                            via: Via::Got,
                        }),
                        site,
                    },
                    _ => at(a),
                }
            }
            (kind, base) => {
                if kind == Kind::Relocatable
                    && self
                        .relocated(disp_field(insn), insn, Use::Absolute)
                        .is_some()
                {
                    // The offset is a symbol's address, not the bytes.
                    return Val::Unknown(Why::NotModeled);
                }
                let Some(b) = gpr(base).filter(|_| base.size() == 8) else {
                    return Val::Unknown(Why::NotModeled);
                };
                let bv = match s.get(b) {
                    None | Some(Val::Unknown(_)) => return Val::Unknown(Why::FromMemory),
                    Some(bv) => bv,
                };
                if depth(bv) >= MAX_LOAD_DEPTH {
                    return Val::Unknown(Why::NotModeled);
                }
                Val::Load {
                    base: Rc::new(bv.clone()),
                    offset: ins.memory_displacement64() as i64,
                    width,
                    site,
                }
            }
        }
    }

    /// The address a 64-bit `lea` forms. Only a `[rip+d]` (or a relocation, or a constant
    /// base) is known: a stack address, as any other unknown base, is `NotModeled` (R-d).
    fn address(&self, s: &State, insn: &Insn) -> Val {
        let ins = &insn.ins;
        let site = ins.ip();
        if ins.memory_index() != Register::None {
            return Val::Unknown(Why::NotModeled);
        }
        let base = ins.memory_base();
        let rip = base == Register::RIP;
        let address = |value: u64| Val::Const {
            value,
            address: true,
        };
        match (self.img.kind, base) {
            (Kind::Relocatable, Register::RIP | Register::None) => {
                let use_ = if rip { Use::Lea } else { Use::Absolute };
                match self.relocated(disp_field(insn), insn, use_) {
                    Some(Meaning::Address(a)) => address(a),
                    Some(Meaning::SymbolAddr(name)) => Val::Sym {
                        of: Rc::new(SymRef::Named {
                            name,
                            defined: None,
                            via: Via::Reloc,
                        }),
                        site,
                    },
                    Some(_) => Val::Unknown(Why::NotModeled),
                    None if rip => address(ins.ip_rel_memory_address()),
                    // An absolute number no relocation makes an address.
                    None => Val::Const {
                        value: ins.memory_displacement64(),
                        address: false,
                    },
                }
            }
            (kind, Register::RIP | Register::None) => {
                let a = if rip {
                    ins.ip_rel_memory_address()
                } else {
                    ins.memory_displacement64()
                };
                let stub = (rip || kind == Kind::Executable)
                    .then(|| self.stub(a))
                    .flatten();
                match stub {
                    Some(of) => Val::Sym {
                        of: Rc::new(of),
                        site,
                    },
                    None => address(a),
                }
            }
            (kind, base) => {
                if kind == Kind::Relocatable
                    && self
                        .relocated(disp_field(insn), insn, Use::Absolute)
                        .is_some()
                {
                    return Val::Unknown(Why::NotModeled);
                }
                match gpr(base)
                    .filter(|_| base.size() == 8)
                    .and_then(|b| s.get(b))
                {
                    Some(Val::Const { value, .. }) => Val::Const {
                        value: value.wrapping_add(ins.memory_displacement64()),
                        address: false,
                    },
                    _ => Val::Unknown(Why::NotModeled),
                }
            }
        }
    }
}

/// The states before the kept instructions of one function ([`kept`]), by address.
pub(crate) struct Values {
    pub before: BTreeMap<u64, State>,
}

/// Whether the state before the instruction at `at`, of block `b`, is kept: before a `call`,
/// and before a jump that may leave the function (a tail call). That is an indirect `jmp`, or a
/// direct `jmp`/`jcc` that ends its block without an edge to each place it may go, as decode
/// adds an edge only for a target inside the function. A `syscall`, `int n`, … is no call.
fn kept(at: u64, insn: &Insn, b: &Block) -> bool {
    let ins = &insn.ins;
    if ins.mnemonic() == Mnemonic::Call {
        return true;
    }
    if at != b.last {
        return false;
    }
    let edges = b.succs().count();
    match ins.flow_control() {
        FlowControl::IndirectBranch => true,
        FlowControl::UnconditionalBranch => edges == 0,
        FlowControl::ConditionalBranch => edges < 2,
        _ => false,
    }
}

/// The state at the function's entry.
fn entry_state() -> State {
    std::array::from_fn(|r| match ARGS.iter().position(|a| *a == r) {
        Some(k) => Val::Param(k as u8),
        None => Val::Unknown(Why::NotModeled),
    })
}

/// Propagates values to a fixpoint (each block at most [`VALUE_PASSES`] times), then records
/// the state before each kept instruction. `Err(Failure::Unsettled)`: the values did not settle,
/// and the function fails.
pub(crate) fn solve(cfg: &Cfg, img: &Image) -> Result<Values, Failure> {
    solve_within(cfg, img, VALUE_PASSES)
}

/// [`solve`], each block processed at most `passes` times.
fn solve_within(cfg: &Cfg, img: &Image, passes: u32) -> Result<Values, Failure> {
    let mut m = Machine::new(img);
    let entry = entry_state();
    let mut preds: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for (start, b) in &cfg.blocks {
        for t in b.succs() {
            preds.entry(t).or_default().push(*start);
        }
    }
    // A block's input: the join of what reaches it so far (the entry state at the entry).
    let input = |start: u64, out: &BTreeMap<u64, State>| -> Option<State> {
        let mut acc: Option<State> = (start == cfg.entry).then(|| entry.clone());
        for p in preds.get(&start).into_iter().flatten() {
            if let Some(o) = out.get(p) {
                acc = Some(match acc {
                    None => o.clone(),
                    Some(a) => join_states(&a, o),
                });
            }
        }
        acc
    };
    let mut out: BTreeMap<u64, State> = BTreeMap::new();
    let mut done: BTreeMap<u64, u32> = BTreeMap::new();
    let mut work: BTreeSet<u64> = BTreeSet::from([cfg.entry]);
    while let Some(start) = work.pop_first() {
        let (Some(b), Some(mut s)) = (cfg.blocks.get(&start), input(start, &out)) else {
            continue;
        };
        let n = done.entry(start).or_insert(0);
        *n += 1;
        if *n > passes {
            return Err(Failure::Unsettled);
        }
        for (_, insn) in cfg.block_insns(start, b) {
            m.step(&mut s, insn);
        }
        if out.get(&start) != Some(&s) {
            out.insert(start, s);
            work.extend(b.succs());
        }
    }
    let mut before = BTreeMap::new();
    for (start, b) in &cfg.blocks {
        let Some(mut s) = input(*start, &out) else {
            continue;
        };
        for (at, insn) in cfg.block_insns(*start, b) {
            if kept(at, insn, b) {
                before.insert(at, s.clone());
            }
            m.step(&mut s, insn);
        }
    }
    Ok(Values { before })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::decode::decode;
    use crate::code::image::{rtype, FieldReloc, Image, Kind, RelSym, Reloc, Sym};
    use crate::code::{CodeBudgets, Run};

    fn c(v: u64) -> Val {
        Val::Const {
            value: v,
            address: false,
        }
    }

    fn addr(v: u64) -> Val {
        Val::Const {
            value: v,
            address: true,
        }
    }

    fn set<const N: usize>(members: [Val; N]) -> Val {
        Val::Set(Rc::from(members.to_vec()))
    }

    fn lo(v: Val, bits: u8) -> Val {
        Val::Low {
            value: Rc::new(v),
            bits,
        }
    }

    fn load(base: Val, offset: i64, width: u8, site: u64) -> Val {
        Val::Load {
            base: Rc::new(base),
            offset,
            width,
            site,
        }
    }

    fn name(s: &str) -> Name {
        Name::from(s.as_bytes())
    }

    fn named(s: &str, defined: Option<u64>, via: Via, site: u64) -> Val {
        Val::Sym {
            of: Rc::new(SymRef::Named {
                name: name(s),
                defined,
                via,
            }),
            site,
        }
    }

    /// `parts`, one instruction each, laid out from 0x1000: the bytes and each one's address.
    fn code(parts: &[&[u8]]) -> (Vec<u8>, Vec<u64>) {
        let mut bytes = vec![];
        let mut at = vec![];
        for p in parts {
            at.push(0x1000 + bytes.len() as u64);
            bytes.extend_from_slice(p);
        }
        (bytes, at)
    }

    fn cfg_of(bytes: &[u8], img: &Image) -> Cfg {
        let mut run = Run::new(CodeBudgets::default());
        let end = 0x1000 + bytes.len() as u64;
        decode(
            bytes,
            0x1000,
            end,
            img,
            &|i: &Insn| Some(i.ins.near_branch_target()),
            &|_: &Insn| false,
            &mut run,
        )
        .unwrap()
    }

    fn solved(bytes: &[u8], img: &Image) -> BTreeMap<u64, State> {
        solve(&cfg_of(bytes, img), img).unwrap().before
    }

    fn states_before_calls(bytes: &[u8]) -> BTreeMap<u64, State> {
        solved(bytes, &Image::empty(Kind::Shared))
    }

    const CALL0: [u8; 5] = [0xe8, 0, 0, 0, 0];
    const RET: [u8; 1] = [0xc3];

    #[test]
    fn joins() {
        assert_eq!(join(&c(1), &c(1)), c(1));
        assert_eq!(join(&c(2), &c(1)), set([c(1), c(2)]));
        assert_eq!(
            join(&set([c(1), c(2)]), &set([c(3), c(4)])),
            set([c(1), c(2), c(3), c(4)])
        );
        assert_eq!(
            join(&set([c(1), c(2)]), &set([c(2), c(3)])),
            set([c(1), c(2), c(3)]),
            "flattened, without repeats"
        );
        assert_eq!(
            join(&set([c(1), c(2), c(3)]), &set([c(4), c(5)])),
            Val::Unknown(Why::MergedDisagreeing),
            "more than 4"
        );
        assert_eq!(
            join(&c(1), &Val::Unknown(Why::ClobberedByCall)),
            Val::Unknown(Why::MergedDisagreeing),
            "never an Unknown member"
        );
        assert_eq!(
            join(
                &Val::Unknown(Why::FromMemory),
                &Val::Unknown(Why::FromMemory)
            ),
            Val::Unknown(Why::FromMemory)
        );
        assert_eq!(
            join(
                &Val::Unknown(Why::FromMemory),
                &Val::Unknown(Why::NotModeled)
            ),
            Val::Unknown(Why::MergedDisagreeing)
        );
    }

    #[test]
    fn partial_reads_and_writes() {
        assert_eq!(
            low(c(0x1_2345_6789), 32),
            c(0x2345_6789),
            "a known constant is truncated"
        );
        assert_eq!(low(Val::Param(0), 32), lo(Val::Param(0), 32));
        assert_eq!(
            low(lo(Val::Param(0), 8), 32),
            lo(Val::Param(0), 8),
            "keeps the smaller width"
        );
        assert_eq!(low(lo(Val::Param(0), 32), 8), lo(Val::Param(0), 8));
        assert_eq!(
            low(Val::Unknown(Why::NotModeled), 16),
            Val::Unknown(Why::NotModeled)
        );
        // An 8-bit write of a constant leaves the rest unknown: not a constant.
        assert_eq!(write(c(7), 1), lo(c(7), 8));
        assert_eq!(write(lo(Val::Param(1), 8), 2), lo(Val::Param(1), 8));
        // A load of at most `bits` bits is its own low bits: zero-extended already.
        let l32 = load(Val::Param(0), 0, 32, 0x10);
        assert_eq!(low(l32.clone(), 32), l32);
        assert_eq!(low(l32.clone(), 16), lo(l32, 16));
        // An address stays one only if the truncation keeps it.
        assert_eq!(low(addr(0x1000), 32), addr(0x1000));
        assert_eq!(low(addr(0x1_0000_1000), 32), c(0x1000));
    }

    #[test]
    fn partial_values_of_a_set_are_a_set_of_partial_values() {
        // So a Low never holds a Set, and `mov eax, eax` in a loop settles.
        assert_eq!(
            low(set([Val::Param(0), lo(Val::Param(0), 32)]), 32),
            lo(Val::Param(0), 32)
        );
        assert_eq!(
            low(set([c(0x1_0000_0001), c(1), Val::Param(0)]), 32),
            set([c(1), lo(Val::Param(0), 32)])
        );
        assert_eq!(
            write(set([c(1), Val::Param(0)]), 1),
            set([lo(c(1), 8), lo(Val::Param(0), 8)])
        );
    }

    #[test]
    fn a_value_is_four_words() {
        assert!(
            std::mem::size_of::<Val>() <= 32,
            "{}",
            std::mem::size_of::<Val>()
        );
    }

    #[test]
    fn a_32_bit_copy_is_not_the_value() {
        // 1000: mov edi,edi (89 ff); 1002: call 1007 (e8 00 00 00 00); 1007: ret (c3)
        let s = states_before_calls(&[0x89, 0xff, 0xe8, 0, 0, 0, 0, 0xc3]);
        assert_eq!(s[&0x1002][7], lo(Val::Param(0), 32));
    }

    #[test]
    fn entry_values_are_the_parameters() {
        let (bytes, at) = code(&[&CALL0, &RET]);
        let s = &states_before_calls(&bytes)[&at[0]];
        for (k, r) in ARGS.iter().enumerate() {
            assert_eq!(s[*r], Val::Param(k as u8));
        }
        for r in [0, 3, 4, 5, 10, 11, 12, 13, 14, 15] {
            assert_eq!(s[r], Val::Unknown(Why::NotModeled), "{r}");
        }
    }

    #[test]
    fn constants() {
        let (bytes, at) = code(&[
            &[0xb8, 0xff, 0xff, 0xff, 0xff],             // mov eax, 0xffffffff
            &[0x48, 0xc7, 0xc1, 0xff, 0xff, 0xff, 0xff], // mov rcx, -1
            &[0x31, 0xd2],                               // xor edx, edx
            &[0x29, 0xf6],                               // sub esi, esi
            &[0x40, 0x30, 0xff],                         // xor dil, dil
            &[0x49, 0xb9, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11], // movabs r9, imm64
            &[0x4c, 0x8d, 0x05, 0x00, 0x01, 0x00, 0x00], // lea r8, [rip+0x100]
            &[0x30, 0xe4],                               // xor ah, ah
            &CALL0,
            &RET,
        ]);
        let s = &states_before_calls(&bytes)[&at[8]];
        assert_eq!(s[0], Val::Unknown(Why::NotModeled), "a high-byte write");
        assert_eq!(s[1], c(u64::MAX), "sign-extended imm32");
        assert_eq!(s[2], c(0));
        assert_eq!(s[6], c(0));
        assert_eq!(s[7], lo(c(0), 8), "an 8-bit zeroing is a partial write");
        assert_eq!(s[9], c(0x1122_3344_5566_7788));
        assert_eq!(s[8], addr(at[7] + 0x100), "a lea forms an address");
        let (bytes, at) = code(&[&[0xb8, 0xff, 0xff, 0xff, 0xff], &CALL0, &RET]);
        assert_eq!(
            states_before_calls(&bytes)[&at[1]][0],
            c(0xffff_ffff),
            "a 32-bit write zero-extends"
        );
    }

    #[test]
    fn calls_clobber_caller_saved_and_return_in_rax() {
        // 1000: mov rbx,rdi (48 89 fb); 1003: mov rsi,rdi (48 89 fe); 1006: call 100b (e8 00..);
        // 100b: mov rdi,rax (48 89 c7); 100e: call 1013 (e8 00..); 1013: ret
        let bytes = [
            0x48, 0x89, 0xfb, 0x48, 0x89, 0xfe, 0xe8, 0, 0, 0, 0, 0x48, 0x89, 0xc7, 0xe8, 0, 0, 0,
            0, 0xc3,
        ];
        let s = states_before_calls(&bytes);
        assert_eq!(s.keys().copied().collect::<Vec<_>>(), [0x1006, 0x100e]);
        let at = &s[&0x100e];
        assert_eq!(at[3], Val::Param(0), "rbx survives");
        assert_eq!(at[6], Val::Unknown(Why::ClobberedByCall), "rsi does not");
        assert_eq!(
            at[7],
            Val::Ret(0x1006),
            "rdi = rax = ReturnOf(call at 1006)"
        );
        for r in [1, 2, 8, 9, 10, 11] {
            assert_eq!(at[r], Val::Unknown(Why::ClobberedByCall), "{r}");
        }
    }

    #[test]
    fn a_syscall_is_not_a_call() {
        // syscall, sysenter, int 0x80: rax, rcx, r11 become NotModeled, never a ReturnOf, and
        // no state is kept before them.
        for entry in [&[0x0f, 0x05][..], &[0x0f, 0x34][..], &[0xcd, 0x80][..]] {
            let (bytes, at) = code(&[entry, &[0x48, 0x89, 0xc7], &CALL0, &RET]); // mov rdi, rax
            let s = states_before_calls(&bytes);
            assert_eq!(
                s.keys().copied().collect::<Vec<_>>(),
                [at[2]],
                "{entry:02x?}"
            );
            let s = &s[&at[2]];
            assert_eq!(s[7], Val::Unknown(Why::NotModeled), "{entry:02x?}");
            assert_eq!(s[1], Val::Unknown(Why::NotModeled), "{entry:02x?}");
            assert_eq!(s[11], Val::Unknown(Why::NotModeled), "{entry:02x?}");
            assert_eq!(s[6], Val::Param(1), "{entry:02x?}: others stay");
            assert_eq!(s[2], Val::Param(2), "{entry:02x?}: others stay");
        }
    }

    #[test]
    fn loads_movsx_and_high_bytes() {
        // 1000: mov rax,[rdi+8] (48 8b 47 08); 1004: movsx esi,byte [rsi] (0f be 36);
        // 1007: mov ch,1 (b5 01); 1009: mov dl,7 (b2 07); 100b: call 1010 (e8 00..); 1010: ret
        let bytes = [
            0x48, 0x8b, 0x47, 0x08, 0x0f, 0xbe, 0x36, 0xb5, 0x01, 0xb2, 0x07, 0xe8, 0, 0, 0, 0,
            0xc3,
        ];
        let s = states_before_calls(&bytes);
        let at = &s[&0x100b];
        assert_eq!(at[0], load(Val::Param(0), 8, 64, 0x1000));
        assert_eq!(
            at[6],
            Val::Unknown(Why::NotModeled),
            "sign extension is not a Load"
        );
        assert_eq!(at[1], Val::Unknown(Why::NotModeled), "a high-byte write");
        assert_eq!(at[2], lo(c(7), 8));
    }

    #[test]
    fn loads_by_base() {
        let (bytes, at) = code(&[
            &[0x48, 0x8b, 0x03],                            // mov rax, [rbx]: unknown base
            &[0x48, 0x8b, 0x4c, 0x24, 0x08],                // mov rcx, [rsp+8]: the stack
            &[0x48, 0x8b, 0x14, 0xf7],                      // mov rdx, [rdi+rsi*8]: indexed
            &[0x64, 0x4c, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0], // mov r8, fs:[0x28]
            &[0x4c, 0x8d, 0x4c, 0x24, 0x08],                // lea r9, [rsp+8]: R-d
            &[0x8b, 0x37],                                  // mov esi, [rdi]
            &[0x4c, 0x8b, 0x27],                            // mov r12, [rdi]
            &[0x4d, 0x8b, 0x24, 0x24],                      // mov r12, [r12]
            &[0x4d, 0x8b, 0x24, 0x24],                      // mov r12, [r12]: 3 deep
            &[0x4d, 0x89, 0xe5],                            // mov r13, r12
            &[0x4d, 0x8b, 0x24, 0x24],                      // mov r12, [r12]: 4 deep
            &[0x0f, 0xb7, 0x4f, 0x02],                      // movzx ecx, word [rdi+2]
            &[0x5b],                                        // pop rbx
            &[0x8b, 0x7f, 0xfc],                            // mov edi, [rdi-4]
            &CALL0,
            &RET,
        ]);
        let s = &states_before_calls(&bytes)[&at[14]];
        assert_eq!(s[0], Val::Unknown(Why::FromMemory));
        assert_eq!(s[1], load(Val::Param(0), 2, 16, at[11]), "movzx");
        assert_eq!(s[2], Val::Unknown(Why::NotModeled), "indexed");
        assert_eq!(s[8], Val::Unknown(Why::FromMemory), "fs-based");
        assert_eq!(s[9], Val::Unknown(Why::NotModeled), "a stack address");
        assert_eq!(s[6], load(Val::Param(0), 0, 32, at[5]), "zero-extending");
        let three = load(
            load(load(Val::Param(0), 0, 64, at[6]), 0, 64, at[7]),
            0,
            64,
            at[8],
        );
        assert_eq!(s[13], three);
        assert_eq!(s[12], Val::Unknown(Why::NotModeled), "past 3 deep");
        assert_eq!(s[3], Val::Unknown(Why::FromMemory), "pop");
        assert_eq!(s[7], load(Val::Param(0), -4, 32, at[13]));
        // The stack: rcx was overwritten above; read it on its own.
        let (bytes, at) = code(&[&[0x48, 0x8b, 0x4c, 0x24, 0x08], &CALL0, &RET]);
        assert_eq!(
            states_before_calls(&bytes)[&at[1]][1],
            Val::Unknown(Why::FromMemory)
        );
    }

    #[test]
    fn stubs_and_slots_in_a_linked_file() {
        let (bytes, at) = code(&[
            &[0xbe, 0x00, 0x20, 0, 0],             // mov esi, 0x2000: the stub
            &[0xba, 0x00, 0x30, 0, 0],             // mov edx, 0x3000: the slot's own address
            &[0x48, 0x8d, 0x3d, 0xef, 0x0f, 0, 0], // lea rdi, [rip -> 0x2000]
            &[0x48, 0x8b, 0x0d, 0xe8, 0x1f, 0, 0], // mov rcx, [rip -> 0x3000]
            &[0x44, 0x8b, 0x05, 0xe1, 0x1f, 0, 0], // mov r8d, [rip -> 0x3000]
            &[0x4c, 0x8d, 0x0d, 0xda, 0x1f, 0, 0], // lea r9, [rip -> 0x3000]
            &CALL0,
            &RET,
        ]);
        let linked = |kind| {
            let mut img = Image::empty(kind);
            img.stubs.insert(0x2000, (0x3000, ImportVia::Plt));
            img.slots.insert(
                0x3000,
                Sym {
                    name: name("connect"),
                    defined: None,
                },
            );
            img
        };
        let s = &solved(&bytes, &linked(Kind::Executable))[&at[6]];
        assert_eq!(
            s[6],
            named("connect", None, Via::Plt, at[0]),
            "an executable's immediate at a stub"
        );
        assert_eq!(s[2], c(0x3000), "a slot's address is not the symbol's");
        assert_eq!(s[7], named("connect", None, Via::Plt, at[2]));
        assert_eq!(s[1], named("connect", None, Via::Got, at[3]));
        assert_eq!(s[8], load(addr(0x3000), 0, 32, at[4]), "not a 64-bit read");
        assert_eq!(s[9], addr(0x3000));
        let s = &solved(&bytes, &linked(Kind::Shared))[&at[6]];
        assert_eq!(s[6], c(0x2000), "a shared object's immediate is a number");
        assert_eq!(s[7], named("connect", None, Via::Plt, at[2]));
        assert_eq!(s[1], named("connect", None, Via::Got, at[3]));
    }

    #[test]
    fn relocations_in_a_relocatable_object() {
        let (bytes, at) = code(&[
            &[0x48, 0x8b, 0x05, 0, 0, 0, 0], // mov rax, [rip+connect@GOTPCREL]
            &[0x48, 0x8b, 0x0d, 0, 0, 0, 0], // mov rcx, [rip+local@GOTPCREL]
            &[0x48, 0x8d, 0x15, 0, 0, 0, 0], // lea rdx, [rip+dlopen]
            &[0x48, 0x8d, 0x35, 0, 0, 0, 0], // lea rsi, [rip+local+0x10]
            &[0xbf, 0, 0, 0, 0],             // mov edi, local+8 (R_X86_64_32)
            &[0x49, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0], // movabs r8, connect (R_X86_64_64)
            &[0x41, 0xb9, 0x05, 0, 0, 0],    // mov r9d, 5
            &[0x4c, 0x8b, 0x97, 0, 0, 0, 0], // mov r10, [rdi+local] (R_X86_64_32S)
            &[0x48, 0x8b, 0x1d, 0, 0, 0, 0], // mov rbx, [rip+dlopen+…] (PC32, off by 4)
            &CALL0,
            &RET,
        ]);
        let mut img = Image::empty(Kind::Relocatable);
        let undefined = |n: &str| RelSym {
            name: Some(name(n)),
            at: None,
        };
        img.rel_syms.insert(1, undefined("connect"));
        img.rel_syms.insert(
            2,
            RelSym {
                name: None,
                at: Some(0x500),
            },
        );
        img.rel_syms.insert(3, undefined("dlopen"));
        let mut rel = |field: u64, r_type: u32, sym: u32, addend: i64| {
            img.relocs.insert(
                field,
                Reloc::One(FieldReloc {
                    r_type,
                    sym,
                    addend,
                }),
            );
        };
        rel(at[0] + 3, rtype::REX_GOTPCRELX, 1, -4);
        rel(at[1] + 3, rtype::REX_GOTPCRELX, 2, -4);
        rel(at[2] + 3, rtype::PC32, 3, -4);
        rel(at[3] + 3, rtype::PC32, 2, 0x10 - 4);
        rel(at[4] + 1, rtype::R32, 2, 8);
        rel(at[5] + 2, rtype::R64, 1, 0);
        rel(at[7] + 3, rtype::R32S, 2, 0);
        rel(at[8] + 3, rtype::PC32, 3, 0);
        let s = &solved(&bytes, &img)[&at[9]];
        assert_eq!(s[0], named("connect", None, Via::Reloc, at[0]));
        assert_eq!(
            s[1],
            Val::Sym {
                of: Rc::new(SymRef::Internal(0x500)),
                site: at[1]
            },
            "a defined symbol's GOT entry, by its offset"
        );
        assert_eq!(s[2], named("dlopen", None, Via::Reloc, at[2]));
        assert_eq!(s[6], addr(0x510));
        assert_eq!(s[7], addr(0x508), "an absolute relocation forms an address");
        assert_eq!(s[8], named("connect", None, Via::Reloc, at[5]));
        assert_eq!(s[9], c(5), "no relocation: a number");
        assert_eq!(
            s[10],
            Val::Unknown(Why::NotModeled),
            "a relocated displacement beside a base"
        );
        assert_eq!(
            s[3],
            Val::Unknown(Why::NotModeled),
            "PC32 data of an import"
        );
    }

    #[test]
    fn joins_at_a_merge_point() {
        let (bytes, at) = code(&[
            &[0x85, 0xff],          // test edi, edi
            &[0x74, 0x07],          // je 100b
            &[0xbe, 0x01, 0, 0, 0], // mov esi, 1
            &[0xeb, 0x08],          // jmp 1013
            &[0xbe, 0x02, 0, 0, 0], // 100b: mov esi, 2
            &[0x48, 0x89, 0xc1],    // mov rcx, rax
            &CALL0,                 // 1013
            &RET,
        ]);
        assert_eq!((at[4], at[6]), (0x100b, 0x1013));
        let s = states_before_calls(&bytes);
        assert_eq!(
            s.keys().copied().collect::<Vec<_>>(),
            [0x1013],
            "jumps inside the function keep no state"
        );
        let s = &s[&0x1013];
        assert_eq!(s[6], set([c(1), c(2)]));
        assert_eq!(s[1], Val::Unknown(Why::MergedDisagreeing));
        assert_eq!(s[7], Val::Param(0));
        assert_eq!(s[2], Val::Param(2));
    }

    #[test]
    fn states_are_kept_before_jumps_that_may_leave() {
        let (bytes, at) = code(&[
            &[0x85, 0xff],                         // test edi, edi
            &[0x0f, 0x84, 0xf8, 0x3f, 0x00, 0x00], // je 0x5000: out of the function
            &[0xff, 0xe0],                         // jmp rax
        ]);
        let s = states_before_calls(&bytes);
        assert_eq!(s.keys().copied().collect::<Vec<_>>(), [at[1], at[2]]);
        // jmp 0x5000 (e9 fb 3f 00 00)
        let s = states_before_calls(&[0xe9, 0xfb, 0x3f, 0x00, 0x00]);
        assert_eq!(s.keys().copied().collect::<Vec<_>>(), [0x1000]);
    }

    #[test]
    fn a_load_chain_in_a_loop_settles_within_the_passes() {
        let (bytes, at) = code(&[
            &[0x48, 0x8b, 0x3f], // 1000: mov rdi, [rdi]
            &[0x48, 0x85, 0xff], // test rdi, rdi
            &[0x75, 0xf8],       // jne 1000
            &CALL0,
            &RET,
        ]);
        let img = Image::empty(Kind::Shared);
        let cfg = cfg_of(&bytes, &img);
        let v = solve(&cfg, &img).unwrap();
        assert_eq!(v.before[&at[3]][7], Val::Unknown(Why::FromMemory));
        // The loop's block is processed 6 times: with 5 passes the values do not settle.
        assert!(solve_within(&cfg, &img, 6).is_ok());
        assert_eq!(solve_within(&cfg, &img, 5).err(), Some(Failure::Unsettled));
        assert_eq!(
            Failure::Unsettled.reason(0x1000),
            "function at 0x1000: values did not settle"
        );
    }

    #[test]
    fn a_32_bit_copy_in_a_loop_settles() {
        let (bytes, at) = code(&[
            &[0x89, 0xff], // 1000: mov edi, edi
            &[0x85, 0xff], // test edi, edi
            &[0x75, 0xfa], // jne 1000
            &CALL0,
            &RET,
        ]);
        let s = states_before_calls(&bytes);
        assert_eq!(s[&at[3]][7], lo(Val::Param(0), 32));
    }
}
