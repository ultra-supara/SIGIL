//! Call targets, call sites, the `ReturnOf` closure, and functions (PR-5a spec §4.6, §4.8).
//!
//! - [`resolve`] says what a call or jump reaches; [`branch_target`] and [`noreturn`] are what
//!   decoding asks of it.
//! - [`Recorder::function`] records one function's calls to the capability imports, and the
//!   calls their values come from; [`Recorder::fill_names`] then names the functions and the
//!   internal callees, in one pass over the symbol tables.

use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{FlowControl, Mnemonic, OpKind, Register};
use object::elf;
use object::read::elf::{FileHeader, SectionTable, Sym as _, SymbolTable};
use object::read::ReadCacheOps;
use object::Endianness;
use sigil_model::{
    ArgValue, BoundsSource, CallId, CallKind, CallSite, CallTarget, FnId, Function, Reg,
    UntrustedText, ValueUnknown,
};

use super::data::Signatures;
use super::decode::{Cfg, Insn};
use super::image::{name_of, symbol_offset, Callee, Image, Kind, Meaning, Name, RelocWhy, Use};
use super::reader::Reader;
use super::value::{gpr, Kept, SymRef, Val, Values, Via, Why, ARGS};
use super::Run;
use crate::binary::elf::{Elf, Sections, MAX_IMPORT_NAME};
use crate::binary::read::Bounded;

/// What a call or jump reaches (spec §4.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Resolved {
    /// A symbol by name: an import (`defined: None`), or the file's own export through its PLT
    /// or GOT.
    Symbol {
        name: Name,
        defined: Option<u64>,
        via: Via,
    },
    /// A function of the file, at this address (a file offset in a relocatable object).
    Internal(u64),
    /// Through a register holding this value, not a symbol's address.
    Indirect(Val, Register),
    /// Through memory other than a known GOT slot or entry: not recorded in 5a (spec §4.6).
    Memory,
    /// A relocation that is not modeled on the field (its reason), or a target that is none of
    /// the above.
    Unresolved(Option<RelocWhy>),
}

/// The address of the branch displacement of `insn`, if it has one: iced gives a near branch's
/// displacement as its immediate.
fn branch_field(insn: &Insn) -> Option<u64> {
    insn.offs.has_immediate().then(|| {
        insn.ins
            .ip()
            .saturating_add(insn.offs.immediate_offset() as u64)
    })
}

/// The address of the displacement field of `insn`, if it has one.
fn disp_field(insn: &Insn) -> Option<u64> {
    insn.offs.has_displacement().then(|| {
        insn.ins
            .ip()
            .saturating_add(insn.offs.displacement_offset() as u64)
    })
}

/// Whether `insn`'s first operand is of kind `k`.
fn op0_is(insn: &Insn, k: OpKind) -> bool {
    insn.ins.op_count() >= 1 && insn.ins.op0_kind() == k
}

/// In a relocatable object, the meaning of the relocation on the branch displacement of `insn`.
fn branch_meaning(insn: &Insn, img: &Image) -> Option<Meaning> {
    if img.kind != Kind::Relocatable {
        return None;
    }
    img.field(branch_field(insn)?, insn.ins.next_ip(), Use::Branch)
}

/// Where a direct branch goes, relocations applied (for `decode`). `None`: not a near branch,
/// or a relocation sends it out of reach (an import, or a relocation not modeled).
pub(crate) fn branch_target(insn: &Insn, img: &Image) -> Option<u64> {
    if !op0_is(insn, OpKind::NearBranch64) {
        return None;
    }
    match branch_meaning(insn, img) {
        Some(Meaning::Branch(Callee::Internal(t))) => Some(t),
        Some(_) => None,
        None => Some(insn.ins.near_branch_target()),
    }
}

/// The symbol a value is the address of: a `Sym`, or a `Set` of `Sym`s of one symbol, with the
/// sites the values were formed at.
fn sym_of(v: &Val) -> Option<(&SymRef, Vec<u64>)> {
    match v {
        Val::Sym { of, site } => Some((of, vec![*site])),
        Val::Set(members) => {
            let mut of: Option<&SymRef> = None;
            let mut sites = Vec::with_capacity(members.len());
            for m in members.iter() {
                let Val::Sym { of: o, site } = m else {
                    return None;
                };
                if of.is_some_and(|first| first != &**o) {
                    return None;
                }
                of = Some(o);
                sites.push(*site);
            }
            of.map(|of| (of, sites))
        }
        _ => None,
    }
}

fn symbol_of(of: &SymRef) -> Resolved {
    match of {
        SymRef::Named { name, defined, via } => Resolved::Symbol {
            name: name.clone(),
            defined: *defined,
            via: *via,
        },
        SymRef::Internal(at) => Resolved::Internal(*at),
    }
}

/// What a call or jump reaches (spec §4.6). `kept`: what is kept before it, for a target in a
/// register ([`Kept::target`]); without it, a register target is unknown.
pub(crate) fn resolve(insn: &Insn, kept: Option<&Kept>, img: &Image) -> Resolved {
    if insn.ins.op_count() < 1 {
        return Resolved::Unresolved(None);
    }
    match insn.ins.op0_kind() {
        OpKind::NearBranch64 => direct(insn, img),
        OpKind::Memory => memory(insn, img),
        OpKind::Register => {
            let v = kept
                .and_then(|k| k.target.clone())
                .unwrap_or(Val::Unknown(Why::NotModeled));
            match sym_of(&v) {
                Some((of, _)) => symbol_of(of),
                None => Resolved::Indirect(v, insn.ins.op0_register()),
            }
        }
        _ => Resolved::Unresolved(None),
    }
}

/// A `call`/`jmp rel`: by its relocation in a relocatable object; else a stub's symbol, or an
/// internal function. An address in a PLT section that is no stub is neither.
fn direct(insn: &Insn, img: &Image) -> Resolved {
    if let Some(m) = branch_meaning(insn, img) {
        return match m {
            Meaning::Branch(Callee::Import(name)) => Resolved::Symbol {
                name,
                defined: None,
                via: Via::Reloc,
            },
            Meaning::Branch(Callee::Internal(t)) => Resolved::Internal(t),
            Meaning::Unknown { why, .. } => Resolved::Unresolved(Some(why)),
            _ => Resolved::Unresolved(None),
        };
    }
    let t = insn.ins.near_branch_target();
    if img.stubs.contains_key(&t) {
        return match img.symbol_at(t) {
            Some((s, via)) => Resolved::Symbol {
                name: s.name,
                defined: s.defined,
                via: via.into(),
            },
            None => Resolved::Unresolved(None),
        };
    }
    if img.plt.iter().any(|(start, end)| *start <= t && t < *end) {
        return Resolved::Unresolved(None);
    }
    Resolved::Internal(t)
}

/// A `call`/`jmp [mem]`: a known GOT slot (`[rip+slot]`, or an executable's absolute `[slot]`),
/// or in a relocatable object a GOT entry by its relocation. A far pointer, an index, or a
/// segment base is plain memory.
fn memory(insn: &Insn, img: &Image) -> Resolved {
    let ins = &insn.ins;
    if ins.memory_size().size() != 8
        || ins.memory_index() != Register::None
        || matches!(ins.segment_prefix(), Register::FS | Register::GS)
    {
        return Resolved::Memory;
    }
    let base = ins.memory_base();
    let slot = |a: u64| match img.slots.get(&a) {
        Some(s) => Resolved::Symbol {
            name: s.name.clone(),
            defined: s.defined,
            via: Via::Got,
        },
        None => Resolved::Memory,
    };
    match (img.kind, base) {
        (Kind::Relocatable, Register::RIP | Register::None) => {
            let use_ = if base == Register::RIP {
                Use::Memory
            } else {
                Use::Absolute
            };
            match disp_field(insn).and_then(|f| img.field(f, ins.next_ip(), use_)) {
                Some(Meaning::GotEntry(Callee::Import(name))) => Resolved::Symbol {
                    name,
                    defined: None,
                    via: Via::Reloc,
                },
                Some(Meaning::GotEntry(Callee::Internal(at))) => Resolved::Internal(at),
                Some(Meaning::Unknown { why, .. }) => Resolved::Unresolved(Some(why)),
                // Data (a pointer the object holds), or no relocation.
                _ => Resolved::Memory,
            }
        }
        (Kind::Relocatable, _) => Resolved::Memory,
        (_, Register::RIP) => slot(ins.ip_rel_memory_address()),
        (Kind::Executable, Register::None) => slot(ins.memory_displacement64()),
        _ => Resolved::Memory,
    }
}

/// Whether a call never returns: only a near call or a call through memory resolved to a symbol
/// that the noreturn list names (R-a).
pub(crate) fn noreturn(insn: &Insn, img: &Image, sig: &Signatures) -> bool {
    if !(op0_is(insn, OpKind::NearBranch64) || op0_is(insn, OpKind::Memory)) {
        return false;
    }
    matches!(resolve(insn, None, img), Resolved::Symbol { name, .. } if sig.is_noreturn(&name))
}

/// The model register of GPR index `i` ([`gpr`]'s order).
fn reg(i: usize) -> Option<Reg> {
    const REGS: [Reg; 16] = [
        Reg::Rax,
        Reg::Rcx,
        Reg::Rdx,
        Reg::Rbx,
        Reg::Rsp,
        Reg::Rbp,
        Reg::Rsi,
        Reg::Rdi,
        Reg::R8,
        Reg::R9,
        Reg::R10,
        Reg::R11,
        Reg::R12,
        Reg::R13,
        Reg::R14,
        Reg::R15,
    ];
    REGS.get(i).copied()
}

fn why(w: Why) -> ValueUnknown {
    match w {
        Why::ClobberedByCall => ValueUnknown::ClobberedByCall,
        Why::MergedDisagreeing => ValueUnknown::MergedDisagreeing,
        Why::FromMemory => ValueUnknown::FromMemory,
        Why::NotModeled => ValueUnknown::NotModeled,
    }
}

fn call_id(ip: u64) -> Option<CallId> {
    CallId::new(format!("cs:{ip:#x}")).ok()
}

/// The sites of the calls whose return values `v` holds: in a `Set`, a `Load` base, or a `Low`.
pub(crate) fn ret_sites(v: &Val, out: &mut Vec<u64>) {
    match v {
        Val::Ret(site) => out.push(*site),
        Val::Load { base, .. } => ret_sites(base, out),
        Val::Low { value, .. } => ret_sites(value, out),
        Val::Set(members) => members.iter().for_each(|m| ret_sites(m, out)),
        _ => {}
    }
}

/// `v` as recorded in `r` (spec §4.7, §4.8): `keep` holds the recorded calls, and `constant`
/// writes a constant `(value, address)`. The result keeps C5:
/// - a `Ret` of a call not recorded, and a `Sym`, are `Unknown(NotModeled)`;
/// - a `Load` whose base is unknown is `Unknown(FromMemory)` (nothing is known to be loaded);
/// - a `Low` of an unknown value is that `Unknown`;
/// - a `Set` with a member that is unknown is `Unknown(MergedDisagreeing)`: no `Unknown`
///   member, and no constant of the rest is read.
fn convert(
    v: &Val,
    r: Reg,
    keep: &BTreeSet<u64>,
    constant: &mut dyn FnMut(u64, bool) -> ArgValue,
) -> ArgValue {
    let unknown = |reason| ArgValue::Unknown { reg: r, reason };
    match v {
        Val::Const { value, address } => constant(*value, *address),
        Val::Param(k) => ArgValue::Param { reg: r, index: *k },
        Val::Ret(site) => match call_id(*site).filter(|_| keep.contains(site)) {
            Some(call) => ArgValue::ReturnOf { reg: r, call },
            None => unknown(ValueUnknown::NotModeled),
        },
        Val::Load {
            base,
            offset,
            width,
            site,
        } => match convert(base, r, keep, constant) {
            ArgValue::Unknown { .. } => unknown(ValueUnknown::FromMemory),
            base => ArgValue::Load {
                reg: r,
                base: Box::new(base),
                offset: *offset,
                width: *width,
                site: *site,
            },
        },
        Val::Low { value, bits } => match convert(value, r, keep, constant) {
            u @ ArgValue::Unknown { .. } => u,
            value => ArgValue::Low {
                reg: r,
                value: Box::new(value),
                bits: *bits,
            },
        },
        Val::Set(members) => {
            let mut out = Vec::with_capacity(members.len());
            for m in members.iter() {
                match convert(m, r, keep, constant) {
                    ArgValue::Unknown { .. } => return unknown(ValueUnknown::MergedDisagreeing),
                    a => out.push(a),
                }
            }
            ArgValue::Set {
                reg: r,
                members: out,
            }
        }
        Val::Sym { .. } => unknown(ValueUnknown::NotModeled),
        Val::Unknown(w) => unknown(why(*w)),
    }
}

/// `v` as recorded in `r`, without reading strings: every constant is a `ConstInt` (tests: the
/// conversions without a file).
#[cfg(test)]
pub(crate) fn to_arg_plain(v: &Val, r: Reg, keep: &BTreeSet<u64>) -> ArgValue {
    convert(v, r, keep, &mut |value, _| ArgValue::ConstInt {
        reg: r,
        value: value as i64,
    })
}

/// `v` as recorded in `r`: an address-forming constant at a NUL-terminated string of a string
/// region is a `ConstStr`, any other constant a `ConstInt` (spec §4.7).
fn to_arg(
    v: &Val,
    r: Reg,
    keep: &BTreeSet<u64>,
    img: &Image,
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> ArgValue {
    convert(v, r, keep, &mut |value, address| match address
        .then(|| img.string(value, reader, run))
        .flatten()
    {
        Some(bytes) => ArgValue::ConstStr {
            reg: r,
            addr: value,
            value: UntrustedText::from_bytes(bytes),
        },
        None => ArgValue::ConstInt {
            reg: r,
            value: value as i64,
        },
    })
}

/// How `insn`, kept before ([`Values`]), may leave for a callee: a `call`, or a jump that leaves
/// the function `[entry, end)` (an indirect `jmp`, or a direct `jmp`/`jcc` whose target is out
/// of it). `None` for anything else: `syscall`, `sysenter`, `int n` are never calls.
fn call_kind(insn: &Insn, img: &Image, entry: u64, end: u64) -> Option<CallKind> {
    let ins = &insn.ins;
    if ins.mnemonic() == Mnemonic::Call {
        return Some(CallKind::Call);
    }
    match ins.flow_control() {
        FlowControl::IndirectBranch => Some(CallKind::TailJump),
        FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
            match branch_target(insn, img) {
                Some(t) if entry <= t && t < end => None,
                _ => Some(CallKind::TailJump),
            }
        }
        _ => None,
    }
}

/// What one recorded function says of its references, for their confirmation (spec §4.4,
/// §4.7).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Consumed {
    /// The instructions whose reference became a call's target: a call or jump's own address
    /// when its operand names the callee (a branch, a GOT slot or entry), and the sites a
    /// symbol's address was formed at when it is called through a register.
    pub called: BTreeSet<u64>,
    /// The sites of the targets' addresses that a recorded value holds, anywhere in it: each is
    /// an address taken (spec §4.7), even where the same value is also called.
    pub escaped: BTreeSet<u64>,
}

/// The sites of the targets' addresses (undefined capability imports) in `v`, through `Low`s,
/// `Load` bases, and `Set`s.
fn escapes(v: &Val, img: &Image, out: &mut BTreeSet<u64>) {
    match v {
        Val::Sym { of, site } => {
            if let SymRef::Named {
                name,
                defined: None,
                ..
            } = &**of
            {
                if img.targets.contains(name) {
                    out.insert(*site);
                }
            }
        }
        Val::Load { base, .. } => escapes(base, img, out),
        Val::Low { value, .. } => escapes(value, img, out),
        Val::Set(members) => members.iter().for_each(|m| escapes(m, img, out)),
        _ => {}
    }
}

/// The recorded facts of one artifact.
#[derive(Debug, Default)]
pub(crate) struct Recorder {
    pub functions: Vec<Function>,
    pub call_sites: Vec<CallSite>,
    /// The addresses of `call_sites` and the entries of `functions`: no ID is recorded twice
    /// (review I1).
    calls: BTreeSet<u64>,
    entries: BTreeSet<u64>,
    /// The bytes of the names copied into the facts so far (`CodeBudgets.name_bytes`).
    name_bytes: u64,
}

impl Recorder {
    /// Records one function's calls to the capability imports and their `ReturnOf` closure
    /// (spec §4.8), with the function. A function records all of its calls or none:
    /// - `None`: nothing of it is recorded, and its references are not confirmed. A gap says
    ///   why: an entry or a call site already recorded (FDEs that overlap; the run goes on), or
    ///   the call-site or name-byte limit (the run stops).
    /// - `Some`: what it says of its references; nothing was recorded when it calls no target.
    pub fn function(
        &mut self,
        cfg: &Cfg,
        values: &Values,
        img: &Image,
        sig: &Signatures,
        reader: &mut Reader<'_>,
        run: &mut Run,
    ) -> Option<Consumed> {
        let mut resolved: BTreeMap<u64, (Resolved, CallKind)> = BTreeMap::new();
        let mut called = BTreeSet::new();
        for (ip, kept) in &values.kept {
            let Some(insn) = cfg.insns.get(ip) else {
                continue;
            };
            let Some(kind) = call_kind(insn, img, cfg.entry, cfg.end) else {
                continue;
            };
            let r = resolve(insn, Some(kept), img);
            if matches!(r, Resolved::Symbol { .. } | Resolved::Internal(_)) {
                if op0_is(insn, OpKind::Register) {
                    if let Some((_, sites)) = kept.target.as_ref().and_then(sym_of) {
                        called.extend(sites);
                    }
                } else {
                    called.insert(*ip);
                }
            }
            // A tail jump is recorded only to a symbol (R-b); it returns no value to the
            // function, so no closure reaches it.
            if kind == CallKind::TailJump && !matches!(r, Resolved::Symbol { .. }) {
                continue;
            }
            resolved.insert(*ip, (r, kind));
        }
        // An import's arity is its capability's; any other callee, an own export of the same
        // name included, may read all six (review M2).
        let arity = |r: &Resolved| match r {
            Resolved::Symbol {
                name,
                defined: None,
                ..
            } => sig
                .capability(name)
                .map_or(ARGS.len(), |c| usize::from(c.arity)),
            _ => ARGS.len(),
        };
        let mut keep: BTreeSet<u64> = resolved
            .iter()
            .filter(|(_, (r, _))| {
                matches!(r, Resolved::Symbol { name, defined: None, .. } if img.targets.contains(name))
            })
            .map(|(ip, _)| *ip)
            .collect();
        // The calls a recorded value's `ReturnOf` names, transitively.
        let mut todo: Vec<u64> = keep.iter().copied().collect();
        let mut sites = vec![];
        while let Some(ip) = todo.pop() {
            let (Some((r, _)), Some(kept)) = (resolved.get(&ip), values.at(ip)) else {
                continue;
            };
            for v in kept.args.iter().take(arity(r)) {
                ret_sites(v, &mut sites);
            }
            if let Resolved::Indirect(v, _) = r {
                ret_sites(v, &mut sites);
            }
            for s in sites.drain(..) {
                let recordable = resolved.get(&s).is_some_and(|(r, _)| {
                    matches!(
                        r,
                        Resolved::Symbol { .. } | Resolved::Internal(_) | Resolved::Indirect(..)
                    )
                });
                if recordable && keep.insert(s) {
                    todo.push(s);
                }
            }
        }
        if keep.is_empty() {
            return Some(Consumed {
                called,
                escaped: BTreeSet::new(),
            });
        }
        // FDEs that overlap decode the same instructions: an ID recorded twice would make the
        // facts invalid (review I1).
        if self.entries.contains(&cfg.entry) {
            run.gap(format!("code: function at {:#x} is in two FDEs", cfg.entry));
            return None;
        }
        if let Some(ip) = keep.iter().find(|ip| self.calls.contains(ip)) {
            run.gap(format!("code: call site at {ip:#x} is in two functions"));
            return None;
        }
        let limit = run.budgets.call_sites;
        if self.call_sites.len().saturating_add(keep.len()) > limit {
            run.limit("call-site", limit as u64);
            return None;
        }
        let names = keep
            .iter()
            .filter_map(|ip| match resolved.get(ip) {
                Some((Resolved::Symbol { name, .. }, _)) => Some(name.len() as u64),
                _ => None,
            })
            .fold(0, u64::saturating_add);
        let name_limit = run.budgets.name_bytes;
        if self.name_bytes.saturating_add(names) > name_limit {
            run.limit("name-byte", name_limit);
            return None;
        }
        // Every kept call forms a site: `keep` holds only resolved, recordable calls, each
        // kept by `values`. Should one not, none is recorded, so no `ReturnOf` dangles (M3).
        let mut escaped = BTreeSet::new();
        let caller = FnId::new(format!("fn:{:#x}", cfg.entry)).ok();
        let formed: Option<Vec<CallSite>> = caller.as_ref().and_then(|caller| {
            keep.iter()
                .map(|ip| {
                    let (r, kind) = resolved.get(ip)?;
                    let kept = values.at(*ip)?;
                    let target = match r {
                        Resolved::Symbol {
                            name,
                            defined: None,
                            via,
                        } => CallTarget::Import {
                            symbol: UntrustedText::from_bytes(name.to_vec()),
                            via: (*via).into(),
                        },
                        Resolved::Symbol {
                            name,
                            defined: Some(at),
                            ..
                        } => CallTarget::OwnExportViaPlt {
                            symbol: UntrustedText::from_bytes(name.to_vec()),
                            entry: *at,
                        },
                        Resolved::Internal(at) => CallTarget::Internal {
                            entry: *at,
                            export_name: None,
                        },
                        Resolved::Indirect(v, register) => {
                            let rr = gpr(*register).and_then(reg)?;
                            escapes(v, img, &mut escaped);
                            CallTarget::Indirect {
                                value: to_arg(v, rr, &keep, img, reader, run),
                            }
                        }
                        Resolved::Memory | Resolved::Unresolved(_) => return None,
                    };
                    let mut args = Vec::with_capacity(ARGS.len());
                    for (v, g) in kept.args.iter().zip(ARGS).take(arity(r)) {
                        escapes(v, img, &mut escaped);
                        args.push(to_arg(v, reg(g)?, &keep, img, reader, run));
                    }
                    Some(CallSite {
                        id: call_id(*ip)?,
                        caller: caller.clone(),
                        addr: *ip,
                        kind: *kind,
                        target,
                        args,
                    })
                })
                .collect()
        });
        debug_assert!(
            formed.is_some(),
            "function at {:#x}: a kept call forms no call site",
            cfg.entry
        );
        let (Some(caller), Some(formed)) = (caller, formed) else {
            run.gap(format!(
                "code: function at {:#x}: call sites not formed",
                cfg.entry
            ));
            return None;
        };
        self.name_bytes = self.name_bytes.saturating_add(names);
        self.calls.extend(keep.iter().copied());
        self.entries.insert(cfg.entry);
        self.call_sites.extend(formed);
        self.functions.push(Function {
            id: caller,
            entry: cfg.entry,
            end: cfg.end,
            bounds: BoundsSource::EhFrameFde,
            names: vec![],
        });
        Some(Consumed { called, escaped })
    }

    /// Fills `Internal.export_name` and `Function.names` (spec §4.6, §4.8) in one pass over the
    /// symbol tables, reading a name only for a recorded function's entry or an internal callee:
    /// - `export_name`: the smallest of the `GLOBAL`/`WEAK`, `DEFAULT`/`PROTECTED` ones at the
    ///   callee in `.dynsym` (the one the loader binds through, as the image takes it), or in a
    ///   relocatable object's `.symtab`;
    /// - names: the defined `FUNC`/`IFUNC` symbols of `.dynsym` and `.symtab` at the entry,
    ///   sorted and unique.
    ///
    /// In a relocatable object a symbol's address is its section's file offset plus its value,
    /// as for the relocations ([`symbol_offset`]). A name is read as the image reads one
    /// ([`name_of`]), up to [`MAX_IMPORT_NAME`] bytes; one that cannot be read names nothing.
    ///
    /// The names copied count against `name_bytes` with the call targets' (review I2): export
    /// names first, then each function's whole list, until one does not fit. Names are not
    /// references, so what does not fit is left out without a gap.
    pub fn fill_names<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
        &mut self,
        e: &Elf<'d, R, H>,
        sections: &Sections<'d, R, H>,
        img: &Image,
        run: &Run,
    ) {
        let limit = run.budgets.name_bytes;
        if self.name_bytes >= limit {
            return;
        }
        let mut found = Found {
            entries: self.functions.iter().map(|f| f.entry).collect(),
            internal: self
                .call_sites
                .iter()
                .filter_map(|c| match &c.target {
                    CallTarget::Internal { entry, .. } => Some(*entry),
                    _ => None,
                })
                .collect(),
            relocatable: img.kind == Kind::Relocatable,
            names: BTreeMap::new(),
            exports: BTreeMap::new(),
        };
        if found.entries.is_empty() && found.internal.is_empty() {
            return;
        }
        let Some(table) = sections.table.as_ref() else {
            return;
        };
        // A linked file's `.symtab` names, but exports nothing.
        let symtab = if found.relocatable {
            None
        } else {
            table.symbols(e.endian, e.data, elf::SHT_SYMTAB).ok()
        };
        let exporting = if found.relocatable {
            sections.symbols.as_ref()
        } else {
            sections
                .symbols
                .as_ref()
                .filter(|_| sections.dynamic_symbols_agree)
        };
        for (symbols, exports) in [(exporting, true), (symtab.as_ref(), false)] {
            if let Some(symbols) = symbols {
                found.scan(e, table, symbols, exports);
            }
        }
        let mut spend = Spend {
            used: self.name_bytes,
            limit,
            spent: false,
        };
        for c in &mut self.call_sites {
            if let CallTarget::Internal { entry, export_name } = &mut c.target {
                if let Some(name) = found.exports.get(entry) {
                    if spend.take(name.len() as u64) {
                        *export_name = Some(UntrustedText::from_bytes(name.to_vec()));
                    }
                }
            }
        }
        for f in &mut self.functions {
            if let Some(n) = found.names.remove(&f.entry) {
                let len = n
                    .iter()
                    .map(|name| name.len() as u64)
                    .fold(0, u64::saturating_add);
                if spend.take(len) {
                    f.names = n
                        .into_iter()
                        .map(|name| UntrustedText::from_bytes(name.to_vec()))
                        .collect();
                }
            }
        }
        self.name_bytes = spend.used;
    }
}

/// The name bytes [`Recorder::fill_names`] may still copy: once one name does not fit, none
/// after it is copied.
struct Spend {
    used: u64,
    limit: u64,
    spent: bool,
}

impl Spend {
    /// Whether `n` more bytes fit; if they do, they are counted.
    fn take(&mut self, n: u64) -> bool {
        match self.used.checked_add(n) {
            Some(total) if !self.spent && total <= self.limit => {
                self.used = total;
                true
            }
            _ => {
                self.spent = true;
                false
            }
        }
    }
}

/// What [`Recorder::fill_names`] looks for, and the names it finds: the parse cache's bytes,
/// not copied.
struct Found<'d> {
    /// The recorded functions' entries: their names are wanted.
    entries: BTreeSet<u64>,
    /// The internal callees: their export names are wanted.
    internal: BTreeSet<u64>,
    /// A relocatable object's symbols are at their sections' file offsets.
    relocatable: bool,
    names: BTreeMap<u64, BTreeSet<&'d [u8]>>,
    exports: BTreeMap<u64, &'d [u8]>,
}

impl<'d> Found<'d> {
    /// One table's defined `FUNC`/`IFUNC` symbols at `entries` (names) or, when the table
    /// `exports`, at `internal` (export names).
    fn scan<R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
        &mut self,
        e: &Elf<'d, R, H>,
        table: &SectionTable<'d, H, &'d Bounded<R>>,
        symbols: &SymbolTable<'d, H, &'d Bounded<R>>,
        exports: bool,
    ) {
        let endian = e.endian;
        for (index, sym) in symbols.enumerate().skip(1) {
            let ty = sym.st_type();
            if !(ty == elf::STT_FUNC || ty == elf::STT_GNU_IFUNC)
                || sym.st_shndx(endian) == elf::SHN_UNDEF
            {
                continue;
            }
            let at = if self.relocatable {
                match symbol_offset(table, symbols, endian, sym, index) {
                    Ok(Some(at)) => at,
                    _ => continue,
                }
            } else {
                sym.st_value(endian).into()
            };
            let bind = sym.st_bind();
            let vis = sym.st_visibility();
            let exported = exports
                && (bind == elf::STB_GLOBAL || bind == elf::STB_WEAK)
                && (vis == elf::STV_DEFAULT || vis == elf::STV_PROTECTED);
            let want_name = self.entries.contains(&at);
            let want_export = exported && self.internal.contains(&at);
            if !want_name && !want_export {
                continue;
            }
            let Ok(Some(name)) = name_of(e, table, symbols, sym, MAX_IMPORT_NAME) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            if want_name {
                self.names.entry(at).or_default().insert(name);
            }
            if want_export {
                self.exports
                    .entry(at)
                    .and_modify(|n| *n = (*n).min(name))
                    .or_insert(name);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::rc::Rc;

    use iced_x86::{Decoder, DecoderOptions};
    use sigil_model::ImportVia;

    use super::*;
    use crate::code::data::signatures;
    use crate::code::decode::decode;
    use crate::code::image::{rtype, FieldReloc, Region, RelSym, Reloc, Sym};
    use crate::code::value::solve;
    use crate::code::{CodeBudgets, Run};

    fn name(s: &str) -> Name {
        Name::from(s.as_bytes())
    }

    fn text(s: &[u8]) -> UntrustedText {
        UntrustedText::from_bytes(s.to_vec())
    }

    fn cs(ip: u64) -> CallId {
        CallId::new(format!("cs:{ip:#x}")).unwrap()
    }

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

    fn set<const N: usize>(members: [Val; N]) -> Val {
        Val::Set(Rc::from(members.to_vec()))
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

    fn symbol(s: &str, defined: Option<u64>, via: Via) -> Resolved {
        Resolved::Symbol {
            name: name(s),
            defined,
            via,
        }
    }

    /// C5 (the model's rule): a `Load` of 8–64 bits, a `Low` of 8–32 bits not of a `Low`, a
    /// `Set` of 2–4 members none a `Set` or `Unknown`; at every level.
    fn c5(a: &ArgValue) -> bool {
        match a {
            ArgValue::Load { base, width, .. } => [8, 16, 32, 64].contains(width) && c5(base),
            ArgValue::Low { value, bits, .. } => {
                [8, 16, 32].contains(bits) && !matches!(**value, ArgValue::Low { .. }) && c5(value)
            }
            ArgValue::Set { members, .. } => {
                (2..=4).contains(&members.len())
                    && members.iter().all(|m| {
                        !matches!(m, ArgValue::Set { .. } | ArgValue::Unknown { .. }) && c5(m)
                    })
            }
            _ => true,
        }
    }

    fn conv(v: Val, keep: &[u64]) -> ArgValue {
        let keep: BTreeSet<u64> = keep.iter().copied().collect();
        let a = to_arg_plain(&v, Reg::Rdi, &keep);
        assert!(c5(&a), "{a:?}");
        a
    }

    fn unknown(reg: Reg, reason: ValueUnknown) -> ArgValue {
        ArgValue::Unknown { reg, reason }
    }

    #[test]
    fn values_become_arg_values() {
        use ValueUnknown::*;
        let u = |reason| unknown(Reg::Rdi, reason);
        assert_eq!(
            conv(Val::Param(2), &[]),
            ArgValue::Param {
                reg: Reg::Rdi,
                index: 2
            }
        );
        assert_eq!(
            conv(Val::Ret(0x10), &[0x10]),
            ArgValue::ReturnOf {
                reg: Reg::Rdi,
                call: cs(0x10)
            }
        );
        assert_eq!(
            conv(Val::Ret(0x10), &[]),
            u(NotModeled),
            "a call not recorded"
        );
        assert_eq!(
            conv(named("connect", None, Via::Got, 1), &[]),
            u(NotModeled),
            "a symbol's address"
        );
        assert_eq!(conv(Val::Unknown(Why::FromMemory), &[]), u(FromMemory));
        assert_eq!(
            conv(Val::Unknown(Why::ClobberedByCall), &[]),
            u(ClobberedByCall)
        );
        assert_eq!(
            conv(Val::Unknown(Why::MergedDisagreeing), &[]),
            u(MergedDisagreeing)
        );
        // A set with a member that becomes Unknown is Unknown (C5: no Unknown member).
        assert_eq!(
            conv(set([Val::Param(0), Val::Ret(0x20)]), &[]),
            u(MergedDisagreeing)
        );
        assert_eq!(
            conv(set([c(1), named("connect", None, Via::Got, 1)]), &[]),
            u(MergedDisagreeing)
        );
        assert_eq!(
            conv(set([Val::Param(0), Val::Ret(0x20)]), &[0x20]),
            ArgValue::Set {
                reg: Reg::Rdi,
                members: vec![
                    ArgValue::Param {
                        reg: Reg::Rdi,
                        index: 0
                    },
                    ArgValue::ReturnOf {
                        reg: Reg::Rdi,
                        call: cs(0x20)
                    },
                ]
            }
        );
        assert_eq!(
            conv(c(u64::MAX), &[]),
            ArgValue::ConstInt {
                reg: Reg::Rdi,
                value: -1
            }
        );
        assert_eq!(
            conv(addr(0x5000), &[]),
            ArgValue::ConstInt {
                reg: Reg::Rdi,
                value: 0x5000
            },
            "no string is read"
        );
    }

    #[test]
    fn loads_and_partial_values_of_unknowns_are_unknown() {
        use ValueUnknown::*;
        let u = |reason| unknown(Reg::Rdi, reason);
        let ret = |site| ArgValue::ReturnOf {
            reg: Reg::Rdi,
            call: cs(site),
        };
        assert_eq!(
            conv(load(Val::Ret(0x10), 8, 64, 0x44), &[0x10]),
            ArgValue::Load {
                reg: Reg::Rdi,
                base: Box::new(ret(0x10)),
                offset: 8,
                width: 64,
                site: 0x44
            }
        );
        // §4.7: nothing known is loaded, whatever the base was.
        assert_eq!(conv(load(Val::Ret(0x10), 8, 64, 0x44), &[]), u(FromMemory));
        assert_eq!(
            conv(load(named("connect", None, Via::Got, 1), 0, 64, 0x44), &[]),
            u(FromMemory)
        );
        assert_eq!(
            conv(load(load(Val::Ret(0x10), 0, 64, 1), 0, 32, 2), &[]),
            u(FromMemory),
            "nested"
        );
        assert_eq!(
            conv(load(set([Val::Param(0), Val::Ret(0x10)]), 0, 8, 2), &[]),
            u(FromMemory)
        );
        assert_eq!(
            conv(lo(Val::Param(0), 32), &[]),
            ArgValue::Low {
                reg: Reg::Rdi,
                value: Box::new(ArgValue::Param {
                    reg: Reg::Rdi,
                    index: 0
                }),
                bits: 32
            }
        );
        // The Unknown itself, never a Low of it.
        assert_eq!(
            conv(lo(named("connect", None, Via::Got, 1), 32), &[]),
            u(NotModeled)
        );
        assert_eq!(conv(lo(Val::Ret(0x10), 8), &[]), u(NotModeled));
        assert_eq!(
            conv(lo(load(Val::Ret(0x10), 0, 64, 2), 16), &[]),
            u(FromMemory)
        );
        assert_eq!(
            conv(lo(load(Val::Ret(0x10), 0, 64, 2), 16), &[0x10]),
            ArgValue::Low {
                reg: Reg::Rdi,
                value: Box::new(ArgValue::Load {
                    reg: Reg::Rdi,
                    base: Box::new(ret(0x10)),
                    offset: 0,
                    width: 64,
                    site: 2
                }),
                bits: 16
            }
        );
    }

    #[test]
    fn return_sites_are_found_inside_values() {
        let v = set([
            lo(Val::Ret(0x30), 32),
            load(Val::Ret(0x40), 8, 64, 0x44),
            load(load(Val::Ret(0x50), 0, 64, 1), 0, 64, 2),
            c(0x60),
            Val::Param(1),
        ]);
        let mut out = vec![];
        ret_sites(&v, &mut out);
        assert_eq!(out, [0x30, 0x40, 0x50]);
    }

    /// `bytes` decoded as one instruction at `ip`.
    fn insn(bytes: &[u8], ip: u64) -> Insn {
        let mut dec = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
        let ins = dec.decode();
        assert!(!ins.is_invalid(), "{bytes:02x?}");
        assert_eq!(ins.len(), bytes.len(), "{bytes:02x?}");
        let offs = dec.get_constant_offsets(&ins);
        Insn { ins, offs }
    }

    fn rel32(next: u64, t: u64) -> [u8; 4] {
        (t.wrapping_sub(next) as i32).to_le_bytes()
    }

    /// `call t` at `at`.
    fn call(at: u64, t: u64) -> Vec<u8> {
        [&[0xe8][..], &rel32(at + 5, t)].concat()
    }

    /// `jmp t` at `at`.
    fn jmp(at: u64, t: u64) -> Vec<u8> {
        [&[0xe9][..], &rel32(at + 5, t)].concat()
    }

    /// `jne t` at `at`.
    fn jne(at: u64, t: u64) -> Vec<u8> {
        [&[0x0f, 0x85][..], &rel32(at + 6, t)].concat()
    }

    /// `je t` at `at`.
    fn je(at: u64, t: u64) -> Vec<u8> {
        [&[0x0f, 0x84][..], &rel32(at + 6, t)].concat()
    }

    /// `call [rip -> slot]` at `at`.
    fn call_mem(at: u64, slot: u64) -> Vec<u8> {
        [&[0xff, 0x15][..], &rel32(at + 6, slot)].concat()
    }

    /// `mov rbx, [rip -> slot]` at `at`.
    fn mov_rbx_mem(at: u64, slot: u64) -> Vec<u8> {
        [&[0x48, 0x8b, 0x1d][..], &rel32(at + 7, slot)].concat()
    }

    /// `lea rdi, [rip -> a]` at `at`.
    fn lea_rdi(at: u64, a: u64) -> Vec<u8> {
        [&[0x48, 0x8d, 0x3d][..], &rel32(at + 7, a)].concat()
    }

    const MOV_RDI_RAX: [u8; 3] = [0x48, 0x89, 0xc7];
    const CALL_RAX: [u8; 2] = [0xff, 0xd0];
    const RET: [u8; 1] = [0xc3];

    const CONNECT: u64 = 0x2000;
    const DLSYM: u64 = 0x2010;
    const GETPID: u64 = 0x2020;
    const ABORT: u64 = 0x2030;
    const HELPER: u64 = 0x2040;
    const SOCKET_OWN: u64 = 0x2050;
    const CONNECT_SLOT: u64 = 0x3000;
    const GETPID_SLOT: u64 = 0x3010;
    const ABORT_SLOT: u64 = 0x3018;
    const HELPER_SLOT: u64 = 0x3020;

    /// A linked image: the stubs of connect (`.plt`), dlsym (`.plt.sec`), getpid, abort, helper
    /// (defined at 0x1800), and socket (an own export at 0x1810), from 0x2000 every 0x10, their
    /// slots from 0x3000 every 8, in a `.plt` of [0x2000, 0x2060). Its targets: connect and
    /// dlsym.
    fn linked(kind: Kind) -> Image {
        let mut img = Image::empty(kind);
        let syms = [
            ("connect", None, ImportVia::Plt),
            ("dlsym", None, ImportVia::PltSec),
            ("getpid", None, ImportVia::Plt),
            ("abort", None, ImportVia::Plt),
            ("helper", Some(0x1800), ImportVia::Plt),
            ("socket", Some(0x1810), ImportVia::Plt),
        ];
        for (k, (n, defined, via)) in syms.into_iter().enumerate() {
            let k = k as u64;
            img.slots.insert(
                0x3000 + 8 * k,
                Sym {
                    name: name(n),
                    defined,
                },
            );
            img.stubs.insert(0x2000 + 0x10 * k, (0x3000 + 8 * k, via));
        }
        img.plt = vec![(0x2000, 0x2060)];
        img.targets = ["connect", "dlsym"].map(name).into_iter().collect();
        img
    }

    /// A relocatable object's image: symbol 1 is connect and 3 abort (undefined), 2 is defined
    /// at file offset 0x500. Its target: connect.
    fn object() -> Image {
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
        img.rel_syms.insert(3, undefined("abort"));
        img.targets.insert(name("connect"));
        img
    }

    fn reloc(img: &mut Image, field: u64, r_type: u32, sym: u32, addend: i64) {
        img.relocs.insert(
            field,
            Reloc::One(FieldReloc {
                r_type,
                sym,
                addend,
            }),
        );
    }

    #[test]
    fn calls_and_jumps_in_a_linked_file_resolve_to_stubs_slots_and_functions() {
        let at = 0x1000;
        let img = linked(Kind::Shared);
        let r = |bytes: &[u8]| resolve(&insn(bytes, at), None, &img);
        assert_eq!(r(&call(at, CONNECT)), symbol("connect", None, Via::Plt));
        assert_eq!(r(&jmp(at, CONNECT)), symbol("connect", None, Via::Plt));
        assert_eq!(r(&call(at, DLSYM)), symbol("dlsym", None, Via::PltSec));
        assert_eq!(
            r(&call(at, HELPER)),
            symbol("helper", Some(0x1800), Via::Plt),
            "an own export through its stub"
        );
        assert_eq!(r(&call(at, 0x1800)), Resolved::Internal(0x1800));
        assert_eq!(
            r(&call(at, 0x2058)),
            Resolved::Unresolved(None),
            "in .plt, at no stub"
        );
        assert_eq!(
            r(&call_mem(at, CONNECT_SLOT)),
            symbol("connect", None, Via::Got)
        );
        assert_eq!(
            r(&[0xff, 0x25, 0xfa, 0x1f, 0, 0]),
            symbol("connect", None, Via::Got),
            "jmp [rip -> 0x3000]"
        );
        assert_eq!(
            r(&call_mem(at, HELPER_SLOT)),
            symbol("helper", Some(0x1800), Via::Got)
        );
        assert_eq!(r(&call_mem(at, 0x3100)), Resolved::Memory, "no slot there");
        let absolute = [0xff, 0x14, 0x25, 0x00, 0x30, 0, 0]; // call [0x3000]
        assert_eq!(
            r(&absolute),
            Resolved::Memory,
            "a shared object's absolute address is no image address"
        );
        assert_eq!(r(&[0xff, 0x50, 0x08]), Resolved::Memory, "call [rax+8]");
        assert_eq!(
            r(&[&[0xff, 0x1d][..], &rel32(at + 6, CONNECT_SLOT)].concat()),
            Resolved::Memory,
            "call far [rip -> 0x3000]: a far pointer, not the slot's symbol"
        );

        let exe = linked(Kind::Executable);
        let r = |bytes: &[u8]| resolve(&insn(bytes, at), None, &exe);
        assert_eq!(r(&absolute), symbol("connect", None, Via::Got));
        assert_eq!(
            r(&[0xff, 0x14, 0xc5, 0x00, 0x30, 0, 0]),
            Resolved::Memory,
            "call [rax*8+0x3000]"
        );
        assert_eq!(
            r(&[0x64, 0xff, 0x14, 0x25, 0x00, 0x30, 0, 0]),
            Resolved::Memory,
            "call fs:[0x3000]"
        );
    }

    #[test]
    fn a_register_target_is_its_symbol_or_indirect() {
        let img = linked(Kind::Shared);
        let call_rax = insn(&CALL_RAX, 0x1000);
        let kept = |target: Option<Val>| Kept {
            args: std::array::from_fn(|_| Val::Unknown(Why::NotModeled)),
            target,
        };
        let r = |target: Option<Val>| resolve(&call_rax, Some(&kept(target)), &img);
        let indirect = |v: Val| Resolved::Indirect(v, Register::RAX);
        assert_eq!(
            resolve(&call_rax, None, &img),
            indirect(Val::Unknown(Why::NotModeled))
        );
        assert_eq!(r(None), indirect(Val::Unknown(Why::NotModeled)));
        assert_eq!(r(Some(Val::Param(0))), indirect(Val::Param(0)));
        assert_eq!(
            r(Some(named("connect", None, Via::Got, 0x10))),
            symbol("connect", None, Via::Got)
        );
        assert_eq!(
            r(Some(named("connect", None, Via::PltSec, 0x10))),
            symbol("connect", None, Via::PltSec)
        );
        assert_eq!(
            r(Some(set([
                named("connect", None, Via::Got, 0x10),
                named("connect", None, Via::Got, 0x20)
            ]))),
            symbol("connect", None, Via::Got),
            "one symbol, formed at two sites"
        );
        let two = set([
            named("connect", None, Via::Got, 0x10),
            named("dlsym", None, Via::Got, 0x20),
        ]);
        assert_eq!(r(Some(two.clone())), indirect(two));
        let mixed = set([named("connect", None, Via::Got, 0x10), Val::Param(0)]);
        assert_eq!(r(Some(mixed.clone())), indirect(mixed));
        let low = lo(named("connect", None, Via::Got, 0x10), 32);
        assert_eq!(r(Some(low.clone())), indirect(low));
        let internal = Val::Sym {
            of: Rc::new(SymRef::Internal(0x500)),
            site: 0x10,
        };
        assert_eq!(r(Some(internal)), Resolved::Internal(0x500));
    }

    #[test]
    fn calls_in_a_relocatable_object_resolve_by_their_relocation() {
        let call0 = [0xe8, 0, 0, 0, 0];
        let callm = [0xff, 0x15, 0, 0, 0, 0];
        let calla = [0xff, 0x14, 0x25, 0, 0, 0, 0];
        let mut img = object();
        reloc(&mut img, 0x1001, rtype::PLT32, 1, -4);
        reloc(&mut img, 0x1101, rtype::PC32, 2, -4);
        reloc(&mut img, 0x1201, rtype::PLT32, 1, 0);
        reloc(&mut img, 0x1402, rtype::GOTPCRELX, 1, -4);
        reloc(&mut img, 0x1502, rtype::GOTPCRELX, 2, -4);
        reloc(&mut img, 0x1602, rtype::GOTPCREL, 1, 0);
        reloc(&mut img, 0x1803, rtype::R32S, 1, 0);
        reloc(&mut img, 0x1902, rtype::PC32, 2, -4);
        let r = |bytes: &[u8], ip: u64| resolve(&insn(bytes, ip), None, &img);
        assert_eq!(r(&call0, 0x1000), symbol("connect", None, Via::Reloc));
        assert_eq!(r(&call0, 0x1100), Resolved::Internal(0x500));
        assert_eq!(
            r(&call0, 0x1200),
            Resolved::Unresolved(Some(RelocWhy::BranchBeside(4)))
        );
        assert_eq!(
            r(&call0, 0x1300),
            Resolved::Internal(0x1305),
            "no relocation: the same section"
        );
        assert_eq!(r(&callm, 0x1400), symbol("connect", None, Via::Reloc));
        assert_eq!(r(&callm, 0x1500), Resolved::Internal(0x500));
        assert_eq!(
            r(&callm, 0x1600),
            Resolved::Unresolved(Some(RelocWhy::Got(4)))
        );
        assert_eq!(r(&callm, 0x1700), Resolved::Memory, "no relocation");
        assert_eq!(
            r(&calla, 0x1800),
            Resolved::Memory,
            "through the bytes at connect, not a call of it"
        );
        assert_eq!(
            r(&callm, 0x1900),
            Resolved::Memory,
            "a pointer the object holds"
        );
    }

    #[test]
    fn branch_targets_apply_relocations() {
        let call0 = [0xe8, 0, 0, 0, 0];
        let mut img = object();
        reloc(&mut img, 0x1001, rtype::PLT32, 1, -4);
        reloc(&mut img, 0x1101, rtype::PC32, 2, -4);
        reloc(&mut img, 0x1201, rtype::PC32, 1, -4);
        let bt = |bytes: &[u8], ip: u64| branch_target(&insn(bytes, ip), &img);
        assert_eq!(bt(&call0, 0x1000), None, "an import is out of reach");
        assert_eq!(bt(&call0, 0x1100), Some(0x500));
        assert_eq!(bt(&call0, 0x1300), Some(0x1305), "no relocation");
        assert_eq!(bt(&[0xeb, 0x02], 0x1f00), Some(0x1f04), "jmp short");
        assert_eq!(bt(&[0xff, 0xe0], 0x1f00), None, "jmp rax");
        assert_eq!(bt(&[0xff, 0x25, 0, 0, 0, 0], 0x1f00), None, "jmp [rip]");
        let shared = linked(Kind::Shared);
        assert_eq!(
            branch_target(&insn(&call(0x1000, CONNECT), 0x1000), &shared),
            Some(CONNECT)
        );
    }

    #[test]
    fn only_a_call_to_a_noreturn_symbol_never_returns() {
        let sig = signatures().unwrap();
        let img = linked(Kind::Shared);
        let nr = |bytes: &[u8]| noreturn(&insn(bytes, 0x1000), &img, sig);
        assert!(nr(&call(0x1000, ABORT)));
        assert!(nr(&call_mem(0x1000, ABORT_SLOT)));
        assert!(!nr(&call(0x1000, CONNECT)));
        assert!(
            !nr(&call(0x1000, 0x1800)),
            "an internal function, whatever its name (R-a)"
        );
        assert!(!nr(&CALL_RAX), "call rax");
        assert!(!nr(&[0x0f, 0x05]), "syscall");
        let mut obj = object();
        reloc(&mut obj, 0x1001, rtype::PLT32, 3, -4);
        assert!(noreturn(&insn(&[0xe8, 0, 0, 0, 0], 0x1000), &obj, sig));

        // Decoding stops after it: the invalid bytes that follow are never reached.
        let bytes = [call(0x1000, ABORT), vec![0xff, 0xff]].concat();
        let mut run = Run::new(CodeBudgets::default());
        let cfg = decode(
            &bytes,
            0x1000,
            0x1007,
            &img,
            &|i: &Insn| branch_target(i, &img),
            &|i: &Insn| noreturn(i, &img, sig),
            &mut run,
        );
        assert_eq!(cfg.map(|c| c.insns.len()).ok(), Some(1));
    }

    /// `parts`, each given its address, laid out from 0x1000: the bytes and each one's address.
    fn layout(parts: &[&dyn Fn(u64) -> Vec<u8>]) -> (Vec<u8>, Vec<u64>) {
        layout_at(0x1000, parts)
    }

    /// [`layout`] from `base`.
    fn layout_at(base: u64, parts: &[&dyn Fn(u64) -> Vec<u8>]) -> (Vec<u8>, Vec<u64>) {
        let mut bytes = vec![];
        let mut at = vec![];
        for p in parts {
            let a = base + bytes.len() as u64;
            at.push(a);
            bytes.extend(p(a));
        }
        (bytes, at)
    }

    /// Decodes `bytes` as the function [entry, entry + len), solves its values, and records it
    /// into `rec`. Strings are read from a file of `file`.
    fn record_into(
        rec: &mut Recorder,
        bytes: &[u8],
        entry: u64,
        img: &Image,
        run: &mut Run,
        file: &[u8],
    ) -> Option<Consumed> {
        let sig = signatures().unwrap();
        let end = entry + bytes.len() as u64;
        let cfg = decode(
            bytes,
            entry,
            end,
            img,
            &|i: &Insn| branch_target(i, img),
            &|i: &Insn| noreturn(i, img, sig),
            run,
        )
        .unwrap();
        let values = solve(&cfg, img).unwrap();
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(file).unwrap();
        let mut reader = Reader::new(f.as_file(), file.len() as u64, 1 << 20);
        rec.function(&cfg, &values, img, sig, &mut reader, run)
    }

    /// [`record_into`] at 0x1000, into a new recorder: it records, with no gap.
    fn record(bytes: &[u8], img: &Image) -> (Recorder, Consumed) {
        let mut rec = Recorder::default();
        let mut run = Run::new(CodeBudgets::default());
        let consumed = record_into(&mut rec, bytes, 0x1000, img, &mut run, &[]).unwrap();
        assert!(run.clone_gaps().is_empty(), "{:?}", run.clone_gaps());
        for c in &rec.call_sites {
            for a in c.args.iter().chain(match &c.target {
                CallTarget::Indirect { value } => Some(value),
                _ => None,
            }) {
                assert!(c5(a), "{a:?}");
            }
        }
        (rec, consumed)
    }

    fn fn_1000() -> FnId {
        FnId::new("fn:0x1000").unwrap()
    }

    fn import(s: &str, via: ImportVia) -> CallTarget {
        CallTarget::Import {
            symbol: text(s.as_bytes()),
            via,
        }
    }

    fn params(from: usize) -> Vec<ArgValue> {
        [Reg::Rdi, Reg::Rsi, Reg::Rdx, Reg::Rcx, Reg::R8, Reg::R9]
            .into_iter()
            .enumerate()
            .skip(from)
            .map(|(k, reg)| ArgValue::Param {
                reg,
                index: k as u8,
            })
            .collect()
    }

    fn clobbered(regs: &[Reg]) -> Vec<ArgValue> {
        regs.iter()
            .map(|r| unknown(*r, ValueUnknown::ClobberedByCall))
            .collect()
    }

    #[test]
    fn a_target_call_is_recorded_with_its_arguments() {
        let mut img = linked(Kind::Shared);
        img.strings = vec![Region {
            start: 0x5000,
            end: 0x5010,
            offset: 0,
        }];
        let (bytes, at) = layout(&[
            &|a| lea_rdi(a, 0x5000),
            &|_| vec![0xbe, 0x02, 0, 0, 0], // mov esi, 2
            &|_| vec![0xba, 0x10, 0, 0, 0], // mov edx, 0x10
            &|_| vec![0x0f, 0x05],          // syscall: no call
            &|a| call(a, CONNECT),
            &|_| RET.to_vec(),
        ]);
        let mut rec = Recorder::default();
        let mut run = Run::new(CodeBudgets::default());
        let consumed = record_into(
            &mut rec,
            &bytes,
            0x1000,
            &img,
            &mut run,
            b"/tmp/sock\0junk\0\0",
        );
        assert!(run.clone_gaps().is_empty(), "{:?}", run.clone_gaps());
        assert_eq!(
            consumed,
            Some(Consumed {
                called: BTreeSet::from([at[4]]),
                escaped: BTreeSet::new()
            })
        );
        assert_eq!(
            rec.call_sites,
            [CallSite {
                id: cs(at[4]),
                caller: fn_1000(),
                addr: at[4],
                kind: CallKind::Call,
                target: import("connect", ImportVia::Plt),
                args: vec![
                    ArgValue::ConstStr {
                        reg: Reg::Rdi,
                        addr: 0x5000,
                        value: text(b"/tmp/sock")
                    },
                    ArgValue::ConstInt {
                        reg: Reg::Rsi,
                        value: 2
                    },
                    ArgValue::ConstInt {
                        reg: Reg::Rdx,
                        value: 0x10
                    },
                ],
            }]
        );
        assert_eq!(
            rec.functions,
            [Function {
                id: fn_1000(),
                entry: 0x1000,
                end: 0x1000 + bytes.len() as u64,
                bounds: BoundsSource::EhFrameFde,
                names: vec![],
            }]
        );
    }

    #[test]
    fn an_address_without_a_string_is_a_number() {
        let mut img = linked(Kind::Shared);
        img.strings = vec![Region {
            start: 0x5000,
            end: 0x5008,
            offset: 0,
        }];
        // 0x5000: no NUL within the region; 0x6000: in no string region.
        let (bytes, at) = layout(&[
            &|a| lea_rdi(a, 0x5000),
            &|a| [&[0x48, 0x8d, 0x35][..], &rel32(a + 7, 0x6000)].concat(), // lea rsi
            &|a| call(a, CONNECT),
            &|_| RET.to_vec(),
        ]);
        let mut rec = Recorder::default();
        let mut run = Run::new(CodeBudgets::default());
        record_into(&mut rec, &bytes, 0x1000, &img, &mut run, b"abcdefgh");
        assert_eq!(rec.call_sites.len(), 1);
        assert_eq!(rec.call_sites[0].addr, at[2]);
        assert_eq!(
            rec.call_sites[0].args[..2],
            [
                ArgValue::ConstInt {
                    reg: Reg::Rdi,
                    value: 0x5000
                },
                ArgValue::ConstInt {
                    reg: Reg::Rsi,
                    value: 0x6000
                },
            ]
        );
    }

    #[test]
    fn the_return_of_closure_is_transitive() {
        let img = linked(Kind::Shared);
        let (bytes, at) = layout(&[
            &|a| call(a, 0x1800), // f, internal
            &|_| MOV_RDI_RAX.to_vec(),
            &|a| call(a, GETPID), // not a capability
            &|_| MOV_RDI_RAX.to_vec(),
            &|a| call(a, CONNECT),
            &|a| call(a, 0x1900), // its value is not used: not recorded
            &|_| RET.to_vec(),
        ]);
        let (rec, consumed) = record(&bytes, &img);
        assert_eq!(
            consumed.called,
            BTreeSet::from([at[0], at[2], at[4], at[5]])
        );
        let ret = |reg, site| ArgValue::ReturnOf {
            reg,
            call: cs(site),
        };
        let site = |ip: u64, target, args| CallSite {
            id: cs(ip),
            caller: fn_1000(),
            addr: ip,
            kind: CallKind::Call,
            target,
            args,
        };
        use Reg::*;
        assert_eq!(
            rec.call_sites,
            [
                site(
                    at[0],
                    CallTarget::Internal {
                        entry: 0x1800,
                        export_name: None
                    },
                    params(0)
                ),
                site(
                    at[2],
                    import("getpid", ImportVia::Plt),
                    [vec![ret(Rdi, at[0])], clobbered(&[Rsi, Rdx, Rcx, R8, R9])].concat()
                ),
                site(
                    at[4],
                    import("connect", ImportVia::Plt),
                    [vec![ret(Rdi, at[2])], clobbered(&[Rsi, Rdx])].concat()
                ),
            ]
        );
        assert_eq!(rec.functions.len(), 1);
    }

    #[test]
    fn the_closure_follows_an_indirect_target() {
        let img = linked(Kind::Shared);
        let (bytes, at) = layout(&[
            &|a| call(a, GETPID), // stands for a call returning a function pointer
            &|_| CALL_RAX.to_vec(),
            &|_| MOV_RDI_RAX.to_vec(),
            &|a| call(a, CONNECT),
            &|_| RET.to_vec(),
        ]);
        let (rec, consumed) = record(&bytes, &img);
        assert_eq!(
            consumed.called,
            BTreeSet::from([at[0], at[3]]),
            "not the call rax"
        );
        let sites: Vec<(u64, &CallTarget)> =
            rec.call_sites.iter().map(|c| (c.addr, &c.target)).collect();
        assert_eq!(
            sites,
            [
                (at[0], &import("getpid", ImportVia::Plt)),
                (
                    at[1],
                    &CallTarget::Indirect {
                        value: ArgValue::ReturnOf {
                            reg: Reg::Rax,
                            call: cs(at[0])
                        }
                    }
                ),
                (at[3], &import("connect", ImportVia::Plt)),
            ]
        );
        assert_eq!(rec.call_sites[1].args.len(), 6, "an indirect call: all six");
        assert_eq!(
            rec.call_sites[2].args[0],
            ArgValue::ReturnOf {
                reg: Reg::Rdi,
                call: cs(at[1])
            }
        );
    }

    #[test]
    fn a_tail_jump_to_a_capability_stub_is_recorded() {
        let img = linked(Kind::Shared);
        let (bytes, at) = layout(&[
            &|_| vec![0xbf, 0x01, 0, 0, 0], // mov edi, 1
            &|a| jmp(a, CONNECT),
        ]);
        let (rec, consumed) = record(&bytes, &img);
        assert_eq!(consumed.called, BTreeSet::from([at[1]]));
        assert_eq!(
            rec.call_sites,
            [CallSite {
                id: cs(at[1]),
                caller: fn_1000(),
                addr: at[1],
                kind: CallKind::TailJump,
                target: import("connect", ImportVia::Plt),
                args: [
                    vec![ArgValue::ConstInt {
                        reg: Reg::Rdi,
                        value: 1
                    }],
                    params(1)[..2].to_vec()
                ]
                .concat(),
            }]
        );
        // A conditional one, through `.plt.sec`.
        let (bytes, at) = layout(&[
            &|_| vec![0x85, 0xff], // test edi, edi
            &|a| jne(a, DLSYM),
            &|_| RET.to_vec(),
        ]);
        let (rec, _) = record(&bytes, &img);
        let sites: Vec<_> = rec
            .call_sites
            .iter()
            .map(|c| (c.addr, c.kind, &c.target))
            .collect();
        assert_eq!(
            sites,
            [(
                at[1],
                CallKind::TailJump,
                &import("dlsym", ImportVia::PltSec)
            )]
        );
    }

    #[test]
    fn other_jumps_out_of_the_function_are_not_recorded() {
        let img = linked(Kind::Shared);
        let (bytes, at) = layout(&[
            &|_| vec![0x85, 0xff], // test edi, edi
            &|a| je(a, 0x9000),    // an internal function
            &|_| vec![0x85, 0xf6], // test esi, esi
            &|a| jne(a, GETPID),   // not a capability
            &|_| vec![0x85, 0xd2], // test edx, edx
            &|a| jne(a, HELPER),   // an own export
            &|_| vec![0xff, 0xe0], // jmp rax
        ]);
        let (rec, consumed) = record(&bytes, &img);
        assert!(rec.call_sites.is_empty(), "{:?}", rec.call_sites);
        assert!(rec.functions.is_empty(), "nothing recorded: no function");
        assert_eq!(consumed.called, BTreeSet::from([at[1], at[3], at[5]]));
    }

    #[test]
    fn a_hoisted_got_load_called_through_a_register_consumes_its_load() {
        let img = linked(Kind::Shared);
        let (bytes, at) = layout(&[
            &|a| mov_rbx_mem(a, CONNECT_SLOT),
            &|_| vec![0x31, 0xff], // xor edi, edi
            &|_| vec![0xff, 0xd3], // call rbx
            &|_| vec![0xff, 0xd3], // call rbx: rbx is callee-saved
            &|_| RET.to_vec(),
        ]);
        let (rec, consumed) = record(&bytes, &img);
        assert_eq!(
            consumed,
            Consumed {
                called: BTreeSet::from([at[0]]),
                escaped: BTreeSet::new()
            },
            "the load, not the calls"
        );
        use Reg::*;
        let sites: Vec<_> = rec
            .call_sites
            .iter()
            .map(|c| (c.addr, &c.target, &c.args))
            .collect();
        let got = import("connect", ImportVia::Got);
        let first = [
            vec![ArgValue::ConstInt { reg: Rdi, value: 0 }],
            params(1)[..2].to_vec(),
        ]
        .concat();
        let second = clobbered(&[Rdi, Rsi, Rdx]);
        assert_eq!(sites, [(at[2], &got, &first), (at[3], &got, &second)]);

        // An executable takes a stub's address as an immediate.
        let exe = linked(Kind::Executable);
        let (bytes, at) = layout(&[
            &|_| vec![0xbb, 0x00, 0x20, 0, 0], // mov ebx, 0x2000: connect's stub
            &|_| vec![0xff, 0xd3],             // call rbx
            &|_| RET.to_vec(),
        ]);
        let (rec, consumed) = record(&bytes, &exe);
        assert_eq!(consumed.called, BTreeSet::from([at[0]]));
        assert_eq!(rec.call_sites.len(), 1);
        assert_eq!(rec.call_sites[0].target, import("connect", ImportVia::Plt));
    }

    #[test]
    fn calls_in_a_relocatable_object_are_recorded() {
        let mut img = object();
        let (bytes, at) = layout(&[
            &|_| vec![0x48, 0x8b, 0x05, 0, 0, 0, 0], // mov rax, [rip + local@GOTPCREL]
            &|_| CALL_RAX.to_vec(),
            &|_| MOV_RDI_RAX.to_vec(),
            &|_| vec![0xe8, 0, 0, 0, 0], // call connect@PLT
            &|_| RET.to_vec(),
        ]);
        reloc(&mut img, at[0] + 3, rtype::REX_GOTPCRELX, 2, -4);
        reloc(&mut img, at[3] + 1, rtype::PLT32, 1, -4);
        let (rec, consumed) = record(&bytes, &img);
        assert_eq!(consumed.called, BTreeSet::from([at[0], at[3]]));
        let sites: Vec<_> = rec.call_sites.iter().map(|c| (c.addr, &c.target)).collect();
        assert_eq!(
            sites,
            [
                (
                    at[1],
                    &CallTarget::Internal {
                        entry: 0x500,
                        export_name: None
                    }
                ),
                (at[3], &import("connect", ImportVia::Reloc)),
            ]
        );
        assert_eq!(rec.call_sites[0].args, params(0));
    }

    /// Two calls of connect, as the function at `base`.
    fn two_connects(base: u64) -> Vec<u8> {
        layout_at(
            base,
            &[
                &|a| call_mem(a, CONNECT_SLOT),
                &|a| call(a, CONNECT),
                &|_| RET.to_vec(),
            ],
        )
        .0
    }

    /// The limit counts the call sites already recorded: a function that would pass it records
    /// nothing, not even part of its calls, and its references are not consumed (`None`).
    #[test]
    fn the_call_site_limit_drops_the_whole_function() {
        let img = linked(Kind::Shared);
        let mut rec = Recorder::default();
        let mut run = Run::new(CodeBudgets {
            call_sites: 4,
            ..CodeBudgets::default()
        });
        let at = |base: u64| two_connects(base);
        assert!(record_into(&mut rec, &at(0x1000), 0x1000, &img, &mut run, &[]).is_some());
        // 2 + 2 = 4: at the limit, not past it.
        assert!(record_into(&mut rec, &at(0x1100), 0x1100, &img, &mut run, &[]).is_some());
        assert_eq!((rec.call_sites.len(), rec.functions.len()), (4, 2));
        assert!(!run.stopped());
        // 4 + 2 > 4.
        assert_eq!(
            record_into(&mut rec, &at(0x1200), 0x1200, &img, &mut run, &[]),
            None
        );
        assert_eq!((rec.call_sites.len(), rec.functions.len()), (4, 2));
        assert!(run.stopped());
        assert_eq!(run.into_gaps(), ["code: call-site limit 4 reached"]);
    }

    /// I1: FDEs at 0x1000 and 0x1005 both decode the call at 0x1005. One `cs:0x1005` only: the
    /// second function is not recorded, with a gap, and the run goes on.
    #[test]
    fn a_call_site_in_two_functions_drops_the_second() {
        let img = linked(Kind::Shared);
        let (bytes, at) = layout(&[&|_| vec![0x90; 5], &|a| call(a, CONNECT), &|_| RET.to_vec()]);
        assert_eq!(at[1], 0x1005);
        let mut rec = Recorder::default();
        let mut run = Run::new(CodeBudgets::default());
        assert!(record_into(&mut rec, &bytes, 0x1000, &img, &mut run, &[]).is_some());
        assert_eq!(
            record_into(&mut rec, &bytes[5..], 0x1005, &img, &mut run, &[]),
            None
        );
        assert!(!run.stopped());
        assert_eq!(
            run.clone_gaps(),
            ["code: call site at 0x1005 is in two functions"]
        );
        let ids: Vec<_> = rec
            .call_sites
            .iter()
            .map(|c| (c.id.clone(), c.caller.clone()))
            .collect();
        assert_eq!(ids, [(cs(0x1005), fn_1000())]);
        assert_eq!(rec.functions.len(), 1);
        // The same entry twice (two FDEs from one address): one `fn:0x1000`.
        assert_eq!(
            record_into(&mut rec, &bytes[..6 + 4], 0x1000, &img, &mut run, &[]),
            None
        );
        assert_eq!(rec.functions.len(), 1);
        assert!(run
            .clone_gaps()
            .contains(&"code: function at 0x1000 is in two FDEs".to_string()));
        assert!(!run.stopped());
    }

    /// I2: the names copied into call sites are counted with the call-site limit.
    #[test]
    fn the_name_byte_limit_drops_the_whole_function() {
        let long = vec![b'l'; 100];
        let mut img = linked(Kind::Shared);
        img.slots.insert(
            0x3100,
            Sym {
                name: Name::from(long.as_slice()),
                defined: None,
            },
        );
        img.stubs.insert(0x2100, (0x3100, ImportVia::Plt));
        // Three calls of the 100-byte import, their values connect's arguments: 307 bytes.
        let function = |base: u64| {
            layout_at(
                base,
                &[
                    &|a| call(a, 0x2100),
                    &|_| vec![0x48, 0x89, 0xc3], // mov rbx, rax
                    &|a| call(a, 0x2100),
                    &|_| vec![0x48, 0x89, 0xc5], // mov rbp, rax
                    &|a| call(a, 0x2100),
                    &|_| vec![0x48, 0x89, 0xc2], // mov rdx, rax
                    &|_| vec![0x48, 0x89, 0xdf], // mov rdi, rbx
                    &|_| vec![0x48, 0x89, 0xee], // mov rsi, rbp
                    &|a| call(a, CONNECT),
                    &|_| RET.to_vec(),
                ],
            )
            .0
        };
        for (limit, second) in [(614, true), (613, false)] {
            let mut rec = Recorder::default();
            let mut run = Run::new(CodeBudgets {
                name_bytes: limit,
                ..CodeBudgets::default()
            });
            let first = record_into(&mut rec, &function(0x1000), 0x1000, &img, &mut run, &[]);
            assert!(first.is_some());
            assert_eq!(rec.call_sites.len(), 4);
            let next = record_into(&mut rec, &function(0x1100), 0x1100, &img, &mut run, &[]);
            assert_eq!(next.is_some(), second, "{limit}");
            if second {
                assert_eq!(rec.call_sites.len(), 8);
                assert!(!run.stopped());
            } else {
                assert_eq!((rec.call_sites.len(), rec.functions.len()), (4, 1));
                assert!(run.stopped());
                assert_eq!(run.into_gaps(), ["code: name-byte limit 613 reached"]);
            }
        }
    }

    /// §4.7: a target's address in a recorded value is taken, even where the same load is also
    /// called.
    #[test]
    fn a_called_symbol_also_in_an_argument_escapes() {
        let img = linked(Kind::Shared);
        let (bytes, at) = layout(&[
            &|a| mov_rbx_mem(a, CONNECT_SLOT),
            &|_| vec![0x48, 0x89, 0xdf], // mov rdi, rbx
            &|_| vec![0xff, 0xd3],       // call rbx
            &|_| RET.to_vec(),
        ]);
        let (rec, consumed) = record(&bytes, &img);
        assert_eq!(
            consumed,
            Consumed {
                called: BTreeSet::from([at[0]]),
                escaped: BTreeSet::from([at[0]])
            }
        );
        assert_eq!(
            rec.call_sites[0].args[0],
            unknown(Reg::Rdi, ValueUnknown::NotModeled)
        );
        // Inside a Low and a Load base too, each its own load; the called load does not
        // escape when no argument holds it; a symbol that is no target never escapes.
        let load = |op: [u8; 3], slot: u64| move |a: u64| [&op[..], &rel32(a + 7, slot)].concat();
        let (bytes, at) = layout(&[
            &|a| mov_rbx_mem(a, CONNECT_SLOT),
            &load([0x48, 0x8b, 0x05], CONNECT_SLOT), // mov rax, [connect]
            &|_| vec![0x89, 0xc7],                   // mov edi, eax
            &load([0x48, 0x8b, 0x15], CONNECT_SLOT), // mov rdx, [connect]
            &|_| vec![0x48, 0x8b, 0x72, 0x08],       // mov rsi, [rdx+8]
            &load([0x48, 0x8b, 0x15], GETPID_SLOT),  // mov rdx, [getpid]
            &|_| vec![0xff, 0xd3],                   // call rbx
            &|_| RET.to_vec(),
        ]);
        let (_, consumed) = record(&bytes, &img);
        assert_eq!(
            consumed,
            Consumed {
                called: BTreeSet::from([at[0]]),
                escaped: BTreeSet::from([at[1], at[3]])
            }
        );
        let mut out = BTreeSet::new();
        escapes(
            &set([
                named("connect", None, Via::Got, 1),
                named("dlsym", None, Via::Got, 2),
                named("getpid", None, Via::Got, 3),
                named("helper", Some(0x1800), Via::Got, 4),
            ]),
            &img,
            &mut out,
        );
        assert_eq!(
            out,
            BTreeSet::from([1, 2]),
            "in a Set; only undefined targets"
        );
    }

    /// M2, M4: an own export is `OwnExportViaPlt` with all six arguments, whatever its name.
    #[test]
    fn an_own_export_is_recorded_with_six_arguments() {
        let img = linked(Kind::Shared);
        let (bytes, at) = layout(&[
            &|a| call(a, SOCKET_OWN),
            &|_| MOV_RDI_RAX.to_vec(),
            &|a| call(a, CONNECT),
            &|_| RET.to_vec(),
        ]);
        let (rec, _) = record(&bytes, &img);
        assert_eq!(rec.call_sites.len(), 2);
        assert_eq!(rec.call_sites[0].addr, at[0]);
        assert_eq!(
            rec.call_sites[0].target,
            CallTarget::OwnExportViaPlt {
                symbol: text(b"socket"),
                entry: 0x1810
            }
        );
        assert_eq!(rec.call_sites[0].args, params(0), "not socket's arity 3");
    }

    /// M4: a relocatable object's tail jump to an import.
    #[test]
    fn a_tail_jump_in_a_relocatable_object_is_recorded() {
        let mut img = object();
        let (bytes, at) = layout(&[
            &|_| vec![0xbf, 0x01, 0, 0, 0], // mov edi, 1
            &|_| vec![0xe9, 0, 0, 0, 0],    // jmp connect@PLT
        ]);
        reloc(&mut img, at[1] + 1, rtype::PLT32, 1, -4);
        let (rec, consumed) = record(&bytes, &img);
        assert_eq!(consumed.called, BTreeSet::from([at[1]]));
        let sites: Vec<_> = rec
            .call_sites
            .iter()
            .map(|c| (c.addr, c.kind, &c.target))
            .collect();
        assert_eq!(
            sites,
            [(
                at[1],
                CallKind::TailJump,
                &import("connect", ImportVia::Reloc)
            )]
        );
    }

    /// M4: a tail jump's arguments feed the closure.
    #[test]
    fn a_tail_jumps_arguments_feed_the_closure() {
        let img = linked(Kind::Shared);
        let (bytes, at) = layout(&[&|a| call(a, GETPID), &|_| MOV_RDI_RAX.to_vec(), &|a| {
            jmp(a, CONNECT)
        }]);
        let (rec, _) = record(&bytes, &img);
        let sites: Vec<_> = rec.call_sites.iter().map(|c| (c.addr, c.kind)).collect();
        assert_eq!(
            sites,
            [(at[0], CallKind::Call), (at[2], CallKind::TailJump)]
        );
        assert_eq!(
            rec.call_sites[1].args[0],
            ArgValue::ReturnOf {
                reg: Reg::Rdi,
                call: cs(at[0])
            }
        );
    }

    /// M4: a memory call is not recorded, so its value is not modeled.
    #[test]
    fn a_memory_calls_value_is_not_modeled() {
        let img = linked(Kind::Shared);
        let (bytes, at) = layout(&[
            &|_| vec![0xff, 0x50, 0x08], // call [rax+8]
            &|_| MOV_RDI_RAX.to_vec(),
            &|a| call(a, CONNECT),
            &|_| RET.to_vec(),
        ]);
        let (rec, consumed) = record(&bytes, &img);
        assert_eq!(consumed.called, BTreeSet::from([at[2]]));
        assert_eq!(rec.call_sites.len(), 1);
        assert_eq!(
            rec.call_sites[0].args[0],
            unknown(Reg::Rdi, ValueUnknown::NotModeled)
        );
    }

    /// The strings of `names`, NUL-terminated after a leading NUL, and each one's offset.
    fn strtab(names: &[&[u8]]) -> (Vec<u8>, Vec<u32>) {
        let mut out = vec![0u8];
        let mut at = vec![];
        for n in names {
            at.push(out.len() as u32);
            out.extend_from_slice(n);
            out.push(0);
        }
        (out, at)
    }

    /// One `Elf64_Sym`, with `st_other` (the visibility).
    fn sym(name: u32, info: u8, other: u8, shndx: u16, value: u64) -> [u8; 24] {
        let mut s = crate::code::synth::sym64(name, info, shndx, value, 0);
        s[5] = other;
        s
    }

    const GLOBAL_FUNC: u8 = 0x12;
    const WEAK_FUNC: u8 = 0x22;
    const LOCAL_FUNC: u8 = 0x02;
    const GLOBAL_IFUNC: u8 = 0x1a;
    const GLOBAL_OBJECT: u8 = 0x11;
    const HIDDEN: u8 = 2;

    /// Parses `bytes` and fills `rec`'s names from its symbol tables, as an image of `kind`;
    /// `agree`: whether `.dynsym` is the table the loader binds through, as the parse found it
    /// (`None`) or as given.
    fn fill(bytes: &[u8], kind: Kind, agree: Option<bool>, rec: &mut Recorder) {
        fill_within(bytes, kind, agree, CodeBudgets::default().name_bytes, rec);
    }

    /// [`fill`], with `name_bytes` the name budget.
    fn fill_within(
        bytes: &[u8],
        kind: Kind,
        agree: Option<bool>,
        name_bytes: u64,
        rec: &mut Recorder,
    ) {
        use crate::binary::read::{Bounded, Budgeted};
        use crate::binary::{elf as binelf, BinaryBudgets};
        use object::elf::FileHeader64;
        let file = crate::code::synth::file(bytes);
        let size = bytes.len() as u64;
        let data = Bounded::new(Budgeted::new(&file, size), size, 64 << 20);
        let mut p =
            binelf::parts::<_, FileHeader64<Endianness>>(&data, BinaryBudgets::default()).unwrap();
        if kind != Kind::Relocatable {
            assert!(p.sections.dynamic_symbols_agree, "{:?}", p.elf.gaps);
        }
        if let Some(agree) = agree {
            p.sections.dynamic_symbols_agree = agree;
        }
        let run = Run::new(CodeBudgets {
            name_bytes,
            ..CodeBudgets::default()
        });
        rec.fill_names(&p.elf, &p.sections, &Image::empty(kind), &run);
        assert!(!data.refused());
    }

    /// The recorded function at each of `entries`, ending 0x100 later, and an internal call of
    /// each of `internal` in the first.
    fn recorded(entries: &[u64], internal: &[u64]) -> Recorder {
        let mut rec = Recorder::default();
        for e in entries {
            rec.functions.push(Function {
                id: FnId::new(format!("fn:{e:#x}")).unwrap(),
                entry: *e,
                end: e + 0x100,
                bounds: BoundsSource::EhFrameFde,
                names: vec![],
            });
        }
        for (k, t) in internal.iter().enumerate() {
            let ip = entries[0] + k as u64;
            rec.call_sites.push(CallSite {
                id: cs(ip),
                caller: rec.functions[0].id.clone(),
                addr: ip,
                kind: CallKind::Call,
                target: CallTarget::Internal {
                    entry: *t,
                    export_name: None,
                },
                args: vec![],
            });
        }
        rec
    }

    fn names_of(rec: &Recorder) -> Vec<(u64, Vec<UntrustedText>)> {
        rec.functions
            .iter()
            .map(|f| (f.entry, f.names.clone()))
            .collect()
    }

    fn exports_of(rec: &Recorder) -> Vec<(u64, Option<UntrustedText>)> {
        rec.call_sites
            .iter()
            .filter_map(|c| match &c.target {
                CallTarget::Internal { entry, export_name } => Some((*entry, export_name.clone())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn names_come_from_both_tables_and_export_names_from_dynsym() {
        use crate::code::synth::{ElfImage, SHT_DYNSYM, SHT_STRTAB, SHT_SYMTAB};
        // Past the 4096 bytes object reads: read on as the image reads names.
        let long = vec![b'n'; 5000];
        let (dynstr, d) = strtab(&[
            b"connect",
            b"helper",
            b"alias_b",
            b"a_hidden",
            b"caller",
            b"obj",
            b"ifunc",
        ]);
        let dynsym = [
            [0u8; 24],
            sym(d[0], GLOBAL_FUNC, 0, 0, 0), // undefined
            sym(d[1], GLOBAL_FUNC, 0, 1, 0x1800),
            sym(d[2], WEAK_FUNC, 0, 1, 0x1800),
            sym(d[3], GLOBAL_FUNC, HIDDEN, 1, 0x1800),
            sym(d[4], GLOBAL_FUNC, 0, 1, 0x1000),
            sym(d[5], GLOBAL_OBJECT, 0, 1, 0x1000),
            sym(d[6], GLOBAL_IFUNC, 0, 1, 0x1000),
        ]
        .concat();
        let (strs, s) = strtab(&[b"local_caller", b"aa_static", &long, b"caller", b"other"]);
        let symtab = [
            [0u8; 24],
            sym(s[0], LOCAL_FUNC, 0, 1, 0x1000),
            sym(s[1], GLOBAL_FUNC, 0, 1, 0x1800), // a linked file's .symtab exports nothing
            sym(s[2], LOCAL_FUNC, 0, 1, 0x1000),
            sym(s[3], GLOBAL_FUNC, 0, 1, 0x1000), // in .dynsym too: named once
            sym(s[4], GLOBAL_FUNC, 0, 1, 0x1900),
        ]
        .concat();
        let mut img = ElfImage::new(3);
        img.put(0x1000, &dynsym)
            .put(0x1400, &dynstr)
            .put(0x2000, &symtab)
            .put(0x2400, &strs);
        img.sec_linked(
            ".dynsym",
            SHT_DYNSYM,
            0x1000,
            0x1000,
            dynsym.len() as u64,
            2,
            24,
        )
        .sec(".dynstr", SHT_STRTAB, 0x1400, 0x1400, dynstr.len() as u64)
        .sec_linked(".symtab", SHT_SYMTAB, 0x2000, 0, symtab.len() as u64, 4, 24)
        .sec(".strtab", SHT_STRTAB, 0x2400, 0, strs.len() as u64);
        let bytes = img.build();
        let mut rec = recorded(&[0x1000], &[0x1800, 0x1900, 0x1000]);
        fill(&bytes, Kind::Shared, None, &mut rec);
        assert_eq!(
            names_of(&rec),
            [(
                0x1000,
                vec![
                    text(b"caller"),
                    text(b"ifunc"),
                    text(b"local_caller"),
                    text(&long)
                ]
            )]
        );
        assert_eq!(
            exports_of(&rec),
            [
                (0x1800, Some(text(b"alias_b"))),
                (0x1900, None),
                (0x1000, Some(text(b"caller"))),
            ]
        );
        // I2: within the name budget, export names first, then whole name lists: alias_b (7)
        // and caller (6) take 13 bytes, and the 0x1000 list (5,023) does not fit.
        for (budget, expect) in [
            (13, [Some(text(b"alias_b")), None, Some(text(b"caller"))]),
            (12, [Some(text(b"alias_b")), None, None]),
            // alias_b does not fit: caller, which would, is not copied after it.
            (6, [None, None, None]),
        ] {
            let mut rec = recorded(&[0x1000], &[0x1800, 0x1900, 0x1000]);
            fill_within(&bytes, Kind::Shared, None, budget, &mut rec);
            assert_eq!(names_of(&rec), [(0x1000, vec![])], "{budget}");
            let exports: Vec<_> = exports_of(&rec).into_iter().map(|(_, n)| n).collect();
            assert_eq!(exports, expect, "{budget}");
        }
        let mut rec = recorded(&[0x1000], &[0x1800, 0x1900, 0x1000]);
        fill_within(&bytes, Kind::Shared, None, 13 + 5023, &mut rec);
        assert_eq!(names_of(&rec)[0].1.len(), 4, "all of them, exactly");
        let mut rec = recorded(&[0x1000], &[0x1800, 0x1900, 0x1000]);
        fill_within(&bytes, Kind::Shared, None, 13 + 5022, &mut rec);
        assert_eq!(
            names_of(&rec),
            [(0x1000, vec![])],
            "one byte short: the whole list counts"
        );
        // A .dynsym the loader does not bind through is not read, as the image does not.
        let mut rec = recorded(&[0x1000], &[0x1800, 0x1900, 0x1000]);
        fill(&bytes, Kind::Shared, Some(false), &mut rec);
        assert_eq!(
            names_of(&rec),
            [(
                0x1000,
                vec![text(b"caller"), text(b"local_caller"), text(&long)]
            )]
        );
        assert_eq!(
            exports_of(&rec),
            [(0x1800, None), (0x1900, None), (0x1000, None)]
        );
    }

    #[test]
    fn a_relocatable_objects_symbols_are_at_their_sections_offsets() {
        use crate::code::synth::{ElfImage, SHT_NOBITS, SHT_PROGBITS, SHT_STRTAB, SHT_SYMTAB};
        let (strs, s) = strtab(&[
            b"f",
            b"g",
            b"g_local",
            b"_g_hidden",
            b"abs",
            b"in_bss",
            b"raw_value",
        ]);
        let symtab = [
            [0u8; 24],
            sym(s[0], GLOBAL_FUNC, 0, 1, 0x10), // .text + 0x10: 0x1010
            sym(s[1], GLOBAL_FUNC, 0, 2, 0),    // .text.b: 0x1100
            sym(s[2], LOCAL_FUNC, 0, 2, 0),
            sym(s[3], GLOBAL_FUNC, HIDDEN, 2, 0),
            sym(s[4], GLOBAL_FUNC, 0, 0xfff1, 0x1010), // SHN_ABS: no file offset
            sym(s[5], GLOBAL_FUNC, 0, 5, 0),           // .bss: no file bytes
            sym(s[6], GLOBAL_FUNC, 0, 1, 0x1100),      // 0x2100, not its value
        ]
        .concat();
        let mut img = ElfImage::new(1);
        img.put(0x1000, &[0x90; 0x200])
            .put(0x1400, &symtab)
            .put(0x1600, &strs);
        img.sec(".text", SHT_PROGBITS, 0x1000, 0, 0x100)
            .sec(".text.b", SHT_PROGBITS, 0x1100, 0, 0x100)
            .sec_linked(".symtab", SHT_SYMTAB, 0x1400, 0, symtab.len() as u64, 4, 24)
            .sec(".strtab", SHT_STRTAB, 0x1600, 0, strs.len() as u64)
            .sec(".bss", SHT_NOBITS, 0x1100, 0, 0x10);
        let mut rec = recorded(&[0x1010, 0x1100], &[0x1100, 0x2100]);
        fill(&img.build(), Kind::Relocatable, None, &mut rec);
        assert_eq!(
            names_of(&rec),
            [
                (0x1010, vec![text(b"f")]),
                (
                    0x1100,
                    vec![text(b"_g_hidden"), text(b"g"), text(b"g_local")]
                ),
            ]
        );
        assert_eq!(
            exports_of(&rec),
            [
                (0x1100, Some(text(b"g"))),
                (0x2100, Some(text(b"raw_value")))
            ]
        );
    }
}
