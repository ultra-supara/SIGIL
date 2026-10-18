//! Register values (PR-5a spec §4.7): forward propagation over one function's CFG, to a
//! fixpoint, per register.
//!
//! - A value's parts are shared ([`Rc`]): a state is 16 values of 4 words, and a clone of one
//!   is 16 counts, however deep its values are.
//! - During the fixpoint one state is kept per chain of blocks ([`Graph`]); after it, only the
//!   argument registers and a register target before each instruction [`kept`] names
//!   ([`Kept`]), review I1.
//! - [`Val::Sym`] (spec rev. 2's `SymbolAddr`) is internal: it never leaves the engine.

use std::collections::BTreeSet;
use std::rc::Rc;

use iced_x86::{
    FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register,
};
use sigil_model::ImportVia;

use super::decode::{Block, Cfg, Failure, Insn};
use super::image::{Callee, Image, Kind, Meaning, Name, Use};
use super::{Run, VALUE_PASSES};

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
/// An `Unknown` among them, or more than [`MAX_SET`], gives `Unknown(MergedDisagreeing)`. Two
/// constants of one number are one, an address only if both are (review M4).
fn set_of(mut members: Vec<Val>) -> Val {
    if members.iter().any(|m| matches!(m, Val::Unknown(_))) {
        return Val::Unknown(Why::MergedDisagreeing);
    }
    members.sort();
    members.dedup_by(|later, kept| match (&*later, &mut *kept) {
        (
            Val::Const {
                value: v,
                address: a,
            },
            Val::Const {
                value: k,
                address: b,
            },
        ) if v == k => {
            *b = *b && *a;
            true
        }
        (later, kept) => later == kept,
    });
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
    // An `Unknown` beside a different value: what `set_of` gives, without building the members.
    if matches!(a, Val::Unknown(_)) || matches!(b, Val::Unknown(_)) {
        return Val::Unknown(Why::MergedDisagreeing);
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

/// `b` joined into `acc`, in place: only the registers that differ are joined, and nothing else
/// is cloned.
fn join_into(acc: &mut State, b: &State) {
    for (x, y) in acc.iter_mut().zip(b) {
        if x != y {
            *x = join(x, y);
        }
    }
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

/// Register `r` as read: its GPR's value, or the low bits of it for a sub-register. `None`: not
/// a GPR.
fn read(s: &State, r: Register) -> Option<Val> {
    if high_byte(r) {
        return Some(Val::Unknown(Why::NotModeled));
    }
    let v = s.get(gpr(r)?)?.clone();
    Some(match r.size() {
        8 => v,
        4 => low(v, 32),
        2 => low(v, 16),
        1 => low(v, 8),
        _ => return None,
    })
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

/// Whether `ins`, not a `call`, leaves for code the values cannot follow and come back: what
/// iced classes as a call or an interrupt (`vmcall`, `int n`, …) and the enclave calls. Every
/// GPR is then unknown (review M3). `syscall`/`sysenter` are not: the kernel writes only `rax`,
/// `rcx`, and `r11` ([`Machine::step`]).
fn transition(ins: &Instruction) -> bool {
    matches!(
        ins.mnemonic(),
        Mnemonic::Encls | Mnemonic::Enclu | Mnemonic::Enclv
    ) || matches!(
        ins.flow_control(),
        FlowControl::Call | FlowControl::IndirectCall | FlowControl::Interrupt
    )
}

/// Whether a relocation's value `a` is what the CPU reads from an immediate of kind `k`,
/// extended as the instruction extends it (review M1). A 32-bit immediate a 32-bit write
/// zero-extends must be a `u32`; one sign-extended to 64 bits must sign-extend to `a`.
fn immediate_holds(a: u64, k: OpKind) -> bool {
    match k {
        OpKind::Immediate64 => true,
        OpKind::Immediate32 => a <= u64::from(u32::MAX),
        OpKind::Immediate16 => a <= u64::from(u16::MAX),
        OpKind::Immediate8 => a <= u64::from(u8::MAX),
        OpKind::Immediate32to64 => a == a as u32 as i32 as i64 as u64,
        OpKind::Immediate8to64 => a == a as u8 as i8 as i64 as u64,
        OpKind::Immediate8to32 => a == u64::from(a as u8 as i8 as i32 as u32),
        OpKind::Immediate8to16 => a == u64::from(a as u8 as i8 as i16 as u16),
        _ => false,
    }
}

/// Whether a relocation's value `a` is the address an absolute (`[disp]`, no base) operand of
/// `insn` forms (review M1): a disp32 is sign-extended with 64-bit addressing and zero-extended
/// with 32-bit addressing; a 64-bit `moffs` holds any.
fn displacement_holds(a: u64, insn: &Insn) -> bool {
    let addr64 = insn.ins.memory_displ_size() == 8;
    match insn.offs.displacement_size() {
        8 => true,
        4 if addr64 => a == a as u32 as i32 as i64 as u64,
        4 => a <= u64::from(u32::MAX),
        _ => false,
    }
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
        match ins.mnemonic() {
            Mnemonic::Call => {
                for r in CALLER_SAVED {
                    s[r] = Val::Unknown(Why::ClobberedByCall);
                }
                s[RAX] = Val::Ret(ins.ip());
            }
            Mnemonic::Syscall | Mnemonic::Sysenter => {
                self.unmodeled(s, ins);
                // What the kernel writes. Never a `Ret`: no call site is made for it.
                for r in [RAX, RCX, R11] {
                    s[r] = Val::Unknown(Why::NotModeled);
                }
            }
            _ if transition(ins) => {
                for v in s.iter_mut() {
                    *v = Val::Unknown(Why::NotModeled);
                }
            }
            _ => match self.modeled(s, insn) {
                Some((d, v)) => set(s, d, v),
                None => self.unmodeled(s, ins),
            },
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
            OpKind::Register => read(s, ins.op_register(i))?,
            OpKind::Memory => {
                let width = u8::try_from(ins.memory_size().size().checked_mul(8)?).ok()?;
                if ![8, 16, 32, 64].contains(&width) {
                    return None;
                }
                self.load(s, insn, width)
            }
            k if is_immediate(k) => self.immediate(insn, k, ins.immediate(i)),
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
    fn immediate(&self, insn: &Insn, kind: OpKind, value: u64) -> Val {
        let site = insn.ins.ip();
        let number = Val::Const {
            value,
            address: false,
        };
        match self.img.kind {
            Kind::Relocatable => match self.relocated(imm_field(insn), insn, Use::Immediate) {
                Some(Meaning::Address(a)) if immediate_holds(a, kind) => Val::Const {
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
                    Some(Meaning::Address(a)) if rip || displacement_holds(a, insn) => at(a),
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
                    // A shared object's absolute address is no image address (review M2).
                    _ if !rip && kind != Kind::Executable => Val::Load {
                        base: Rc::new(Val::Const {
                            value: a,
                            address: false,
                        }),
                        offset: 0,
                        width,
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
                    Some(Meaning::Address(a)) if rip || displacement_holds(a, insn) => address(a),
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
                    // A shared object's (or PIE's) absolute value is no image address (review
                    // M2).
                    None if !rip && kind != Kind::Executable => Val::Const {
                        value: a,
                        address: false,
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

/// What is kept before a kept instruction ([`kept`]): what its call site needs, not the
/// whole state (review I1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Kept {
    /// The argument registers, in [`ARGS`] order: rdi rsi rdx rcx r8 r9.
    pub args: [Val; 6],
    /// For a `call`/`jmp` through a register, that register's value.
    pub target: Option<Val>,
}

impl Kept {
    fn of(insn: &Insn, s: &State) -> Kept {
        let ins = &insn.ins;
        Kept {
            args: ARGS.map(|r| s.get(r).cloned().unwrap_or(Val::Unknown(Why::NotModeled))),
            target: (ins.op_count() >= 1 && ins.op0_kind() == OpKind::Register)
                .then(|| read(s, ins.op0_register()))
                .flatten(),
        }
    }
}

/// What is kept before each kept instruction of one function ([`kept`]), sorted by address.
pub(crate) struct Values {
    pub kept: Vec<(u64, Kept)>,
}

impl Values {
    /// What is kept before the instruction at `ip`, by binary search.
    pub fn at(&self, ip: u64) -> Option<&Kept> {
        let i = self.kept.binary_search_by_key(&ip, |(at, _)| *at).ok()?;
        self.kept.get(i).map(|(_, k)| k)
    }
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

/// A CFG's blocks by ordinal (address order), as the fixpoint walks them. A block whose only
/// successor has it as its only predecessor (and is not the entry) runs straight into it: the
/// two are processed as one, a chain, and only a chain's last block keeps an output state. A
/// run of calls is one chain, so it costs one state, not one per call (review I1).
struct Graph<'c> {
    cfg: &'c Cfg,
    starts: Vec<u64>,
    blocks: Vec<&'c Block>,
    entry: usize,
    /// The block each one runs straight into; `None` ends a chain.
    next: Vec<Option<usize>>,
    /// Whether a block starts a chain: the entry, and every block no other runs into.
    head: Vec<bool>,
    /// Block `b`'s predecessors: `preds[pred_at[b]..pred_at[b + 1]]`.
    pred_at: Vec<usize>,
    preds: Vec<usize>,
}

impl<'c> Graph<'c> {
    fn of(cfg: &'c Cfg) -> Option<Graph<'c>> {
        let starts: Vec<u64> = cfg.blocks.keys().copied().collect();
        let blocks: Vec<&Block> = cfg.blocks.values().collect();
        let n = starts.len();
        let ord = |a: u64| starts.binary_search(&a).ok();
        let entry = ord(cfg.entry)?;
        let succs = |b: &Block| b.succs().filter_map(ord).collect::<Vec<_>>();
        let mut pred_at = vec![0usize; n + 1];
        for b in &blocks {
            for t in succs(b) {
                if let Some(c) = pred_at.get_mut(t + 1) {
                    *c += 1;
                }
            }
        }
        for i in 1..=n {
            let before = pred_at.get(i - 1).copied().unwrap_or(0);
            if let Some(c) = pred_at.get_mut(i) {
                *c += before;
            }
        }
        let mut fill = pred_at.clone();
        let mut preds = vec![0usize; pred_at.get(n).copied().unwrap_or(0)];
        for (p, b) in blocks.iter().enumerate() {
            for t in succs(b) {
                if let Some(slot) = fill.get_mut(t).and_then(|f| {
                    let at = *f;
                    *f += 1;
                    preds.get_mut(at)
                }) {
                    *slot = p;
                }
            }
        }
        let npreds = |t: usize| match (pred_at.get(t), pred_at.get(t + 1)) {
            (Some(lo), Some(hi)) => hi - lo,
            _ => 0,
        };
        let mut next = vec![None; n];
        let mut head = vec![true; n];
        for (b, blk) in blocks.iter().enumerate() {
            if let [t] = succs(blk)[..] {
                if t != b && t != entry && npreds(t) == 1 {
                    if let (Some(x), Some(h)) = (next.get_mut(b), head.get_mut(t)) {
                        *x = Some(t);
                        *h = false;
                    }
                }
            }
        }
        Some(Graph {
            cfg,
            starts,
            blocks,
            entry,
            next,
            head,
            pred_at,
            preds,
        })
    }

    fn len(&self) -> usize {
        self.starts.len()
    }

    /// The blocks of the chain starting at `h`, in order. A chain's blocks each have one
    /// predecessor, the one before, so it never meets itself; the bound is for safety.
    fn chain(&self, h: usize) -> impl Iterator<Item = usize> + '_ {
        std::iter::successors(Some(h), |b| self.next.get(*b).copied().flatten()).take(self.len())
    }

    /// Block `b` and its instructions.
    fn insns(&self, b: usize) -> Option<(&'c Block, impl Iterator<Item = (u64, &'c Insn)>)> {
        let (start, blk) = (*self.starts.get(b)?, *self.blocks.get(b)?);
        Some((blk, self.cfg.block_insns(start, blk)))
    }

    /// Block `b`'s successors, by ordinal: each starts a chain, as `b` ends one.
    fn succs(&self, b: usize) -> impl Iterator<Item = usize> + '_ {
        self.blocks
            .get(b)
            .into_iter()
            .flat_map(|blk| blk.succs())
            .filter_map(|t| self.starts.binary_search(&t).ok())
    }

    /// Chain head `h`'s input: the join of what reaches it so far (with the entry state at the
    /// entry). Each predecessor of a head ends a chain, so its output is kept.
    fn input(&self, h: usize, entry: &State, out: &[Option<Box<State>>]) -> Option<State> {
        let mut acc = (h == self.entry).then(|| entry.clone());
        let (lo, hi) = (*self.pred_at.get(h)?, *self.pred_at.get(h + 1)?);
        for p in self.preds.get(lo..hi).into_iter().flatten() {
            if let Some(o) = out.get(*p).and_then(|o| o.as_deref()) {
                match acc.as_mut() {
                    None => acc = Some(o.clone()),
                    Some(a) => join_into(a, o),
                }
            }
        }
        acc
    }
}

/// Propagates values to a fixpoint (each block at most [`VALUE_PASSES`] times), then keeps what
/// each kept instruction needs ([`Kept`]), sorted by address. Every step is charged to `run`
/// ([`charge`]). The function fails with `Failure::Unsettled` when the values did not settle, and
/// with `Failure::ArtifactValueSteps` at the value-step limit, which stops the run.
pub(crate) fn solve(cfg: &Cfg, img: &Image, run: &mut Run) -> Result<Values, Failure> {
    let count = cfg
        .blocks
        .iter()
        .map(|(start, b)| {
            cfg.block_insns(*start, b)
                .filter(|(at, insn)| kept(*at, insn, b))
                .count()
        })
        .sum();
    let mut kept = Vec::with_capacity(count);
    propagate(cfg, img, VALUE_PASSES, run, |at, insn, s| {
        kept.push((at, Kept::of(insn, s)))
    })?;
    // A chain may run backwards (a `jmp` to an earlier block), so the visits are not in order.
    kept.sort_unstable_by_key(|(at, _)| *at);
    Ok(Values { kept })
}

/// Charges one [`Machine::step`] to the artifact's value-step budget, before it is made (review
/// of Task 15: 256 passes over up to 200,000 instructions per function need an aggregate bound,
/// as decoding has). At `budgets.value_steps` the run stops, and the function fails.
fn charge(run: &mut Run) -> Result<(), Failure> {
    if run.value_steps >= run.budgets.value_steps {
        run.limit("value-step", run.budgets.value_steps);
        return Err(Failure::ArtifactValueSteps);
    }
    run.value_steps += 1;
    Ok(())
}

/// The fixpoint, each chain processed at most `passes` times; then `visit` is called with the
/// state before each kept instruction ([`kept`]). Every step, of both, is charged to `run`.
fn propagate(
    cfg: &Cfg,
    img: &Image,
    passes: u32,
    run: &mut Run,
    mut visit: impl FnMut(u64, &Insn, &State),
) -> Result<(), Failure> {
    let Some(g) = Graph::of(cfg) else {
        return Ok(());
    };
    let mut m = Machine::new(img);
    let entry = entry_state();
    // Only a chain's last block's output is kept.
    let mut out: Vec<Option<Box<State>>> = vec![None; g.len()];
    let mut done = vec![0u32; g.len()];
    let mut work: BTreeSet<usize> = BTreeSet::from([g.entry]);
    while let Some(h) = work.pop_first() {
        let Some(mut s) = g.input(h, &entry, &out) else {
            continue;
        };
        let Some(n) = done.get_mut(h) else {
            continue;
        };
        *n += 1;
        if *n > passes {
            return Err(Failure::Unsettled);
        }
        let mut last = h;
        for b in g.chain(h) {
            last = b;
            for (_, insn) in g.insns(b).into_iter().flat_map(|(_, i)| i) {
                charge(run)?;
                m.step(&mut s, insn);
            }
        }
        if let Some(o) = out.get_mut(last) {
            if o.as_deref() != Some(&s) {
                *o = Some(Box::new(s));
                work.extend(g.succs(last));
            }
        }
    }
    for h in 0..g.len() {
        if !g.head.get(h).copied().unwrap_or(false) {
            continue;
        }
        let Some(mut s) = g.input(h, &entry, &out) else {
            continue;
        };
        for b in g.chain(h) {
            let Some((blk, insns)) = g.insns(b) else {
                break;
            };
            for (at, insn) in insns {
                if kept(at, insn, blk) {
                    visit(at, insn, &s);
                }
                charge(run)?;
                m.step(&mut s, insn);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

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

    /// A run with the default budgets.
    fn fresh() -> Run {
        Run::new(CodeBudgets::default())
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

    /// The whole state before each kept instruction (the tests look at every register).
    fn states(cfg: &Cfg, img: &Image) -> BTreeMap<u64, State> {
        let mut out = BTreeMap::new();
        propagate(cfg, img, VALUE_PASSES, &mut fresh(), |at, _, s| {
            out.insert(at, s.clone());
        })
        .unwrap();
        out
    }

    fn solved(bytes: &[u8], img: &Image) -> BTreeMap<u64, State> {
        states(&cfg_of(bytes, img), img)
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
            join(&Val::Unknown(Why::FromMemory), &set([c(1), c(2)])),
            Val::Unknown(Why::MergedDisagreeing),
            "nor a Set with one"
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
        // syscall, sysenter: rax, rcx, r11 become NotModeled (each known before),
        // never a ReturnOf, and no state is kept before them.
        for entry in [&[0x0f, 0x05][..], &[0x0f, 0x34][..]] {
            let (bytes, at) = code(&[
                &[0xb8, 0x29, 0, 0, 0],       // mov eax, 41
                &[0xb9, 0x01, 0, 0, 0],       // mov ecx, 1
                &[0x41, 0xbb, 0x02, 0, 0, 0], // mov r11d, 2
                entry,
                &[0x48, 0x89, 0xc7], // mov rdi, rax
                &CALL0,
                &RET,
            ]);
            let s = states_before_calls(&bytes);
            assert_eq!(
                s.keys().copied().collect::<Vec<_>>(),
                [at[5]],
                "{entry:02x?}"
            );
            let s = &s[&at[5]];
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
        let v = solve(&cfg, &img, &mut fresh()).unwrap();
        assert_eq!(v.at(at[3]).unwrap().args[0], Val::Unknown(Why::FromMemory));
        // The loop's block is processed 6 times: with 5 passes the values do not settle.
        assert!(propagate(&cfg, &img, 6, &mut fresh(), |_, _, _| {}).is_ok());
        assert_eq!(
            propagate(&cfg, &img, 5, &mut fresh(), |_, _, _| {}).err(),
            Some(Failure::Unsettled)
        );
        assert_eq!(
            Failure::Unsettled.reason(0x1000),
            "function at 0x1000: values did not settle"
        );
    }

    #[test]
    fn a_relocated_value_must_survive_its_field() {
        // Review M1: what the CPU reads from the field, extended, must be the relocation's value.
        let (bytes, at) = code(&[
            &[0xbf, 0, 0, 0, 0],                   // mov edi, imm32: zero-extended
            &[0x48, 0xc7, 0xc6, 0, 0, 0, 0],       // mov rsi, imm32: sign-extended
            &[0x48, 0xc7, 0xc2, 0, 0, 0, 0],       // mov rdx, imm32: sign-extended
            &[0xb9, 0, 0, 0, 0],                   // mov ecx, imm32
            &[0x4c, 0x8b, 0x04, 0x25, 0, 0, 0, 0], // mov r8, [abs32]: sign-extended
            &[0x4c, 0x8d, 0x0c, 0x25, 0, 0, 0, 0], // lea r9, [abs32]
            &CALL0,
            &RET,
        ]);
        let mut img = Image::empty(Kind::Relocatable);
        let at_ = |a: u64| RelSym {
            name: None,
            at: Some(a),
        };
        img.rel_syms.insert(1, at_(0x1_0000_0000));
        img.rel_syms.insert(2, at_(0x7000_0000));
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
        rel(at[0] + 1, rtype::R32, 1, 8); // 0x1_0000_0008: not a u32
        rel(at[1] + 3, rtype::R32, 2, 0x1000_0000); // 0x8000_0000: sign-extends to another
        rel(at[2] + 3, rtype::R32S, 2, 0x500); // 0x7000_0500: fits
        rel(at[3] + 1, rtype::R32, 2, 0x1000_0000); // 0x8000_0000: a u32
        rel(at[4] + 4, rtype::R32S, 2, 0x1000_0000); // 0x8000_0000 as a disp32
        rel(at[5] + 4, rtype::R32S, 2, 8); // 0x7000_0008
        let s = &solved(&bytes, &img)[&at[6]];
        assert_eq!(s[7], Val::Unknown(Why::NotModeled), "past a u32");
        assert_eq!(
            s[6],
            Val::Unknown(Why::NotModeled),
            "sign extension changes it"
        );
        assert_eq!(s[2], addr(0x7000_0500));
        assert_eq!(s[1], addr(0x8000_0000));
        assert_eq!(s[8], Val::Unknown(Why::NotModeled), "a disp32 sign-extends");
        assert_eq!(s[9], addr(0x7000_0008));
    }

    #[test]
    fn an_absolute_lea_is_an_address_only_in_an_executable() {
        // Review M2. lea rdi, [0x2000] (48 8d 3c 25 00 20 00 00); mov rsi, [0x2000]
        let (bytes, at) = code(&[
            &[0x48, 0x8d, 0x3c, 0x25, 0x00, 0x20, 0, 0],
            &[0x48, 0x8b, 0x34, 0x25, 0x00, 0x20, 0, 0],
            &CALL0,
            &RET,
        ]);
        let s = &solved(&bytes, &Image::empty(Kind::Executable))[&at[2]];
        assert_eq!(s[7], addr(0x2000));
        assert_eq!(s[6], load(addr(0x2000), 0, 64, at[1]));
        let s = &solved(&bytes, &Image::empty(Kind::Shared))[&at[2]];
        assert_eq!(s[7], c(0x2000), "not an image address");
        assert_eq!(s[6], load(c(0x2000), 0, 64, at[1]));
    }

    #[test]
    fn other_transitions_make_every_register_unknown() {
        // Review M3: vmcall, int 0x80, int1, into-like transfers, and enclave calls.
        for t in [
            &[0x0f, 0x01, 0xc1][..], // vmcall
            &[0xcd, 0x80][..],       // int 0x80
            &[0xf1][..],             // int1
            &[0x0f, 0x01, 0xd7][..], // enclu
        ] {
            let (bytes, at) = code(&[
                &[0xbb, 0x01, 0, 0, 0], // mov ebx, 1
                t,
                &CALL0,
                &RET,
            ]);
            let s = states_before_calls(&bytes);
            assert_eq!(s.keys().copied().collect::<Vec<_>>(), [at[2]], "{t:02x?}");
            for (r, v) in s[&at[2]].iter().enumerate() {
                assert_eq!(*v, Val::Unknown(Why::NotModeled), "{t:02x?}: register {r}");
            }
        }
    }

    #[test]
    fn the_same_number_joins_to_one_value() {
        // Review M4: an address and an immediate of the same value are one value, not an address.
        assert_eq!(join(&addr(5), &c(5)), c(5));
        assert_eq!(join(&addr(5), &addr(5)), addr(5));
        assert_eq!(join(&set([addr(5), c(6)]), &c(5)), set([c(5), c(6)]));
        assert_eq!(
            join(&set([addr(5), c(6), c(7), c(8)]), &c(5)),
            set([c(5), c(6), c(7), c(8)]),
            "not past the limit"
        );
    }

    /// One function of 199,999 `call`s (each to the next instruction) and a `ret`: 200,000
    /// instructions, the per-function limit, so 200,000 blocks and 199,999 kept values. Run under
    /// the 1 GiB cap (`limits.sh`).
    #[test]
    fn a_function_of_calls_at_the_instruction_limit() {
        let calls = crate::code::FUNCTION_INSTRUCTIONS as usize - 1;
        let mut bytes = CALL0.repeat(calls);
        bytes.push(0xc3);
        let img = Image::empty(Kind::Shared);
        let cfg = cfg_of(&bytes, &img);
        assert_eq!(cfg.blocks.len(), calls + 1);
        let v = solve(&cfg, &img, &mut fresh()).unwrap();
        assert_eq!(v.kept.len(), calls);
        assert!(v.kept.windows(2).all(|w| w[0].0 < w[1].0));
        let last = 0x1000 + 5 * (calls as u64 - 1);
        assert_eq!(
            v.at(last).unwrap().args[0],
            Val::Unknown(Why::ClobberedByCall)
        );
        assert_eq!(v.at(0x1000).unwrap().args[0], Val::Param(0));
        assert_eq!(v.at(0x1001), None);
    }

    #[test]
    fn kept_values_are_the_arguments_and_a_register_target() {
        let (bytes, at) = code(&[
            &[0xb8, 0x07, 0, 0, 0], // mov eax, 7
            &[0xff, 0xd0],          // call rax
            &CALL0,
            &[0xff, 0xe1], // jmp rcx
        ]);
        let v = solve(
            &cfg_of(&bytes, &Image::empty(Kind::Shared)),
            &Image::empty(Kind::Shared),
            &mut fresh(),
        )
        .unwrap();
        assert_eq!(
            v.kept.iter().map(|(a, _)| *a).collect::<Vec<_>>(),
            [at[1], at[2], at[3]]
        );
        let params = std::array::from_fn(|k| Val::Param(k as u8));
        assert_eq!(
            v.at(at[1]),
            Some(&Kept {
                args: params,
                target: Some(c(7)),
            })
        );
        let clobbered = std::array::from_fn(|_| Val::Unknown(Why::ClobberedByCall));
        assert_eq!(
            v.at(at[2]),
            Some(&Kept {
                args: clobbered.clone(),
                target: None,
            }),
            "a direct call has no register target"
        );
        assert_eq!(
            v.at(at[3]),
            Some(&Kept {
                args: clobbered,
                target: Some(Val::Unknown(Why::ClobberedByCall)),
            })
        );
        assert_eq!(v.at(at[0]), None);
    }

    #[test]
    fn a_loop_through_the_entry_is_joined() {
        // 1000: call 1005; 1005: jmp 1000 (eb f9). The entry, a chain's successor, starts a
        // chain of its own: its input joins the entry state.
        let (bytes, at) = code(&[&CALL0, &[0xeb, 0xf9]]);
        let s = states_before_calls(&bytes);
        assert_eq!(s.keys().copied().collect::<Vec<_>>(), [at[0]]);
        assert_eq!(s[&at[0]][7], Val::Unknown(Why::MergedDisagreeing));
        assert_eq!(s[&at[0]][3], Val::Unknown(Why::NotModeled));
    }

    #[test]
    fn a_chain_running_backwards_keeps_its_values_sorted() {
        // 1000: jmp 1008 (eb 06); 1002: call 1007; 1007: ret; 1008: call 100d;
        // 100d: jmp 1002 (eb f3). One chain 1000, 1008, 100d, 1002, 1007: 1008 is visited first.
        let (bytes, at) = code(&[&[0xeb, 0x06], &CALL0, &RET, &CALL0, &[0xeb, 0xf3]]);
        assert_eq!((at[1], at[3]), (0x1002, 0x1008));
        let img = Image::empty(Kind::Shared);
        let v = solve(&cfg_of(&bytes, &img), &img, &mut fresh()).unwrap();
        assert_eq!(
            v.kept.iter().map(|(a, _)| *a).collect::<Vec<_>>(),
            [0x1002, 0x1008]
        );
        assert_eq!(v.at(0x1008).unwrap().args[0], Val::Param(0));
        assert_eq!(
            v.at(0x1002).unwrap().args[0],
            Val::Unknown(Why::ClobberedByCall)
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

    /// `mov dst, src` (64-bit), by [`gpr`] index.
    fn mov_rr(dst: usize, src: usize) -> Vec<u8> {
        let rex = 0x48 | if src >= 8 { 4 } else { 0 } | if dst >= 8 { 1 } else { 0 };
        vec![rex, 0x89, 0xc0 | ((src as u8 & 7) << 3) | (dst as u8 & 7)]
    }

    /// `mov dst32, imm`, by [`gpr`] index.
    fn mov_ri(dst: usize, imm: u32) -> Vec<u8> {
        let mut v = if dst >= 8 { vec![0x41] } else { vec![] };
        v.push(0xb8 + (dst as u8 & 7));
        v.extend(imm.to_le_bytes());
        v
    }

    /// Loops nested in `levels` order (the first outermost), each with its level's body before
    /// the next loop, then `test eax, eax; jne` back to its start.
    fn nest(out: &mut Vec<u8>, levels: &[Vec<u8>]) {
        let Some((body, inner)) = levels.split_first() else {
            return;
        };
        let start = out.len();
        out.extend(body);
        nest(out, inner);
        out.extend([0x85, 0xc0]);
        let rel = start as i64 - (out.len() as i64 + 6);
        out.extend([0x0f, 0x85]);
        out.extend((rel as i32).to_le_bytes());
    }

    /// The 15 GPRs but rsp, by [`gpr`] index.
    const NOT_RSP: [usize; 15] = [0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    /// A function whose values settle only after 48 passes: the first 14 registers hold the
    /// constants 1 to 14, and four nested loops shift one chain r15 → r14 → … → rax (r15 is
    /// unknown), each loop a part of it, the outermost the start. Each change a loop passes on
    /// runs through every loop inside it again: real nested loops (curl's `fopen` function,
    /// CUDA libraries) needed up to 256 passes in Task 15's survey.
    fn needs_48_passes() -> Vec<u8> {
        let mut bytes: Vec<u8> = NOT_RSP[..14]
            .iter()
            .enumerate()
            .flat_map(|(i, r)| mov_ri(*r, i as u32 + 1))
            .collect();
        let shift = |regs: &[usize]| -> Vec<u8> {
            regs.windows(2).flat_map(|w| mov_rr(w[0], w[1])).collect()
        };
        let levels = [
            shift(&NOT_RSP[11..]),
            shift(&NOT_RSP[7..=11]),
            shift(&NOT_RSP[3..=7]),
            shift(&NOT_RSP[..=3]),
        ];
        nest(&mut bytes, &levels);
        bytes.extend(CALL0);
        bytes.extend(RET);
        bytes
    }

    #[test]
    fn nested_loops_settle_within_the_value_passes() {
        let img = Image::empty(Kind::Shared);
        let cfg = cfg_of(&needs_48_passes(), &img);
        assert_eq!(cfg.insns.len(), 38);
        assert_eq!(
            propagate(&cfg, &img, 47, &mut fresh(), |_, _, _| {}).err(),
            Some(Failure::Unsettled)
        );
        assert!(propagate(&cfg, &img, 48, &mut fresh(), |_, _, _| {}).is_ok());
        // More than the 32 passes PR-5a began with, within VALUE_PASSES.
        let v = solve(&cfg, &img, &mut fresh()).unwrap();
        let call = *cfg.insns.keys().next_back().unwrap() - 5;
        // rax is at the chain's end: r15's unknown value reached it.
        let at = v.at(call).unwrap();
        assert_eq!(at.args[0], Val::Unknown(Why::MergedDisagreeing), "rdi");
    }

    #[test]
    fn value_step_limit_counts_every_step_of_every_function() {
        // call; ret: one chain of two instructions, settled in one pass, then recorded: 4 steps.
        let (bytes, _) = code(&[&CALL0, &RET]);
        let img = Image::empty(Kind::Shared);
        let cfg = cfg_of(&bytes, &img);
        let at = |value_steps| {
            Run::new(CodeBudgets {
                value_steps,
                ..CodeBudgets::default()
            })
        };
        let mut run = Run::new(CodeBudgets::default());
        assert!(solve(&cfg, &img, &mut run).is_ok());
        assert_eq!(
            run.value_steps, 4,
            "the fixpoint's and the recording pass's"
        );
        let mut run = at(4);
        assert!(solve(&cfg, &img, &mut run).is_ok());
        assert!(!run.stopped());
        // Charged before each step: the 4th is refused, in the recording pass.
        let mut run = at(3);
        assert_eq!(
            solve(&cfg, &img, &mut run).err(),
            Some(Failure::ArtifactValueSteps)
        );
        assert!(run.stopped());
        assert_eq!(run.into_gaps(), ["code: value-step limit 3 reached"]);
        // Every function's steps count against the artifact's one budget.
        let mut run = at(7);
        assert!(solve(&cfg, &img, &mut run).is_ok());
        assert_eq!(
            solve(&cfg, &img, &mut run).err(),
            Some(Failure::ArtifactValueSteps)
        );
        assert_eq!(
            Failure::ArtifactValueSteps.reason(0x1000),
            "not solved: a limit was reached"
        );
        // A function that needs many passes is charged for each: 48 passes of the nested loops.
        let img = Image::empty(Kind::Shared);
        let cfg = cfg_of(&needs_48_passes(), &img);
        let mut run = Run::new(CodeBudgets::default());
        assert!(solve(&cfg, &img, &mut run).is_ok());
        assert!(run.value_steps > 48 * 6, "{}", run.value_steps);
    }

    #[test]
    fn value_step_limit_in_the_fixpoint_keeps_nothing() {
        // call; ret under a budget of 1 step: the fixpoint's second step is refused, so the
        // function fails there, before the recording pass keeps the call's values.
        let (bytes, _) = code(&[&CALL0, &RET]);
        let img = Image::empty(Kind::Shared);
        let cfg = cfg_of(&bytes, &img);
        let mut run = Run::new(CodeBudgets {
            value_steps: 1,
            ..CodeBudgets::default()
        });
        let mut visited = 0;
        let r = propagate(&cfg, &img, VALUE_PASSES, &mut run, |_, _, _| visited += 1);
        assert_eq!(r.err(), Some(Failure::ArtifactValueSteps));
        assert_eq!(visited, 0, "nothing kept");
        assert_eq!(run.value_steps, 1);
        assert_eq!(run.into_gaps(), ["code: value-step limit 1 reached"]);
    }
}
