//! Per-function transactions on independently proved Mach-O intervals.
use super::{
    bind::{self, MachImportWitness},
    image::MachCodeView,
    reloc::{self, Relocations},
    stubs,
    unwind::{self, MachBounds},
};
use crate::code::{
    aarch64::{
        self,
        decode::{A64Insn, Flow},
        value as av,
    },
    data::Signatures,
    decode as xd,
    image::{Image, Kind, Region},
    reader::Reader,
    record as xr, value as xv, Run, Work, FDE_BYTES,
};
use iced_x86::{FlowControl, Mnemonic, OpKind, Register};
use sigil_model::{
    code_abi::{CodeAbi, V1},
    Arch, ArgValue, ArgumentLayout, CallId, CallKind, CallSite, CallTarget, FnId, Function,
    ImportVia, MachOImport, MachOLibrary, Reg, UntrustedText, LIBSYSTEM,
};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

#[derive(Clone)]
enum Target {
    Import(Rc<MachOImport>, ImportVia),
    Internal(u64),
}
impl Target {
    fn model(&self) -> CallTarget {
        match self {
            Self::Import(w, via) => CallTarget::Import {
                symbol: w.name.clone(),
                via: *via,
                macho_import: Some((**w).clone()),
            },
            Self::Internal(entry) => CallTarget::Internal {
                entry: *entry,
                export_name: None,
            },
        }
    }
}
fn exact(w: MachImportWitness) -> Rc<MachOImport> {
    Rc::new(MachOImport {
        name: w.symbol,
        library: w.library,
        weak: w.weak,
    })
}
fn queried(t: &Target, sig: &Signatures) -> bool {
    matches!(t,Target::Import(w,_) if sig.capability(w.name.as_bytes().strip_prefix(b"_").unwrap_or(w.name.as_bytes())).is_some())
}
fn no_return(t: Option<Target>, sig: &Signatures) -> bool {
    matches!(t,Some(Target::Import(w,_)) if matches!(&w.library,MachOLibrary::Dylib {name:Some(n),..} if n.as_bytes()==LIBSYSTEM.as_bytes()) && sig.is_noreturn(w.name.as_bytes().strip_prefix(b"_").unwrap_or(w.name.as_bytes())))
}
fn call_id(pc: u64) -> Result<CallId, ()> {
    CallId::new(format!("cs:{pc:#x}")).map_err(|_| ())
}
fn fn_id(pc: u64) -> Result<FnId, ()> {
    FnId::new(format!("fn:{pc:#x}")).map_err(|_| ())
}
struct Context<'a> {
    view: &'a MachCodeView,
    slots: BTreeMap<u64, Rc<MachOImport>>,
    stubs: BTreeMap<u64, Rc<MachOImport>>,
    relocs: Relocations,
    has_targets: bool,
}
impl Context<'_> {
    fn fields<'a>(&'a self, b: &MachBounds) -> impl Iterator<Item = &'a u64> {
        let start = b.start;
        self.relocs
            .fields
            .range(start.saturating_sub(7)..b.end)
            .filter(move |(pc, len)| pc.checked_add(**len).is_none_or(|end| end > start))
            .map(|(pc, _)| pc)
    }
    fn direct(&self, t: u64) -> Result<Target, ()> {
        if let Some(w) = self.stubs.get(&t) {
            return Ok(Target::Import(w.clone(), ImportVia::MachOStub));
        }
        if stubs::contains(self.view, t)
            || self
                .view
                .code_at(
                    t,
                    if self.view.arch == Arch::Aarch64 {
                        4
                    } else {
                        1
                    },
                )
                .is_err()
        {
            return Err(());
        }
        Ok(Target::Internal(t))
    }
    fn a64(&self, pc: u64, i: &A64Insn) -> Result<Option<Target>, ()> {
        match i.flow {
            Flow::CallDirect(t) | Flow::JumpDirect(t) => {
                if self.view.file_type == 1 && self.relocs.fields.contains_key(&pc) {
                    // BRANCH26 denotes the exact symbol only when the instruction addend is 0.
                    if i.word & 0x03ffffff != 0 {
                        return Err(());
                    }
                    return self
                        .relocs
                        .branches
                        .get(&pc)
                        .cloned()
                        .map(|w| Some(Target::Import(w, ImportVia::MachOReloc)))
                        .ok_or(());
                }
                self.direct(t).map(Some)
            }
            _ => Ok(None),
        }
    }
    fn x86(&self, i: &xd::Insn, kept: Option<&xv::Kept>) -> Result<Option<Target>, ()> {
        let ins = &i.ins;
        // Conditional branches only contribute CFG edges, never call targets.
        if !matches!(ins.mnemonic(), Mnemonic::Call | Mnemonic::Jmp) {
            return Ok(None);
        }
        match ins.op0_kind() {
            OpKind::NearBranch64 => {
                let field = ins
                    .ip()
                    .checked_add(i.offs.immediate_offset() as u64)
                    .ok_or(())?;
                if self.view.file_type == 1 && self.relocs.fields.contains_key(&field) {
                    if i.offs.immediate_size() != 4
                        || ins.near_branch_target() != ins.next_ip()
                        || ins.len() != 5
                    {
                        return Err(());
                    }
                    return self
                        .relocs
                        .branches
                        .get(&field)
                        .cloned()
                        .map(|w| Some(Target::Import(w, ImportVia::MachOReloc)))
                        .ok_or(());
                }
                self.direct(ins.near_branch_target()).map(Some)
            }
            OpKind::Memory
                if ins.is_ip_rel_memory_operand()
                    && ins.memory_index() == Register::None
                    && ins.segment_prefix() == Register::None
                    && ins.memory_size().size() == 8 =>
            {
                self.slot(ins.ip_rel_memory_address()).map(Some)
            }
            OpKind::Register => {
                let v = kept.and_then(|k| k.target.as_ref()).ok_or(())?;
                let xv::Val::Load {
                    base,
                    offset,
                    width: 64,
                    ..
                } = v
                else {
                    return Err(());
                };
                let xv::Val::Const {
                    value,
                    address: true,
                } = **base
                else {
                    return Err(());
                };
                self.slot(value.checked_add_signed(*offset).ok_or(())?)
                    .map(Some)
            }
            _ => Err(()),
        }
    }
    fn slot(&self, at: u64) -> Result<Target, ()> {
        self.slots
            .get(&at)
            .filter(|w| !w.weak)
            .map(|w| Target::Import(w.clone(), ImportVia::MachOGot))
            .ok_or(())
    }
}

pub(crate) fn analyze(
    view: &MachCodeView,
    sig: &Signatures,
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> (Vec<Function>, Vec<CallSite>) {
    let bounds = unwind::read_bounds(view, reader, run);
    let slots = bind::read_bindings(view, reader, run);
    let mut stub_map = BTreeMap::new();
    for s in view.sections.iter().filter(|s| s.flags & 0xff == 8) {
        let width = u64::from(s.reserved2);
        if width == 0 || width > 16 || !(s.vm.end - s.vm.start).is_multiple_of(width) {
            run.gap("code: Mach-O invalid stub section width".into());
            continue;
        }
        let mut at = s.vm.start;
        while at < s.vm.end && !run.stopped() {
            if !run.charge(Work::References, 1) {
                break;
            }
            match stubs::resolve_stub(view, at, &slots, reader, run) {
                Ok(w) => {
                    stub_map.insert(at, exact(w));
                }
                Err(why) => run.gap(format!("code: Mach-O stub at {at:#x}: {why}")),
            }
            at += width;
        }
    }
    let has_targets = slots.values().any(|w| {
        sig.capability(
            w.symbol
                .as_bytes()
                .strip_prefix(b"_")
                .unwrap_or(w.symbol.as_bytes()),
        )
        .is_some()
    });
    let ctx = Context {
        view,
        slots: slots.into_iter().map(|(at, w)| (at, exact(w))).collect(),
        stubs: stub_map,
        relocs: reloc::read_relocations(view, reader, run),
        has_targets,
    };
    let mut functions = vec![];
    let mut calls = vec![];
    if ctx.relocs.invalid {
        return (functions, calls);
    }
    if view.file_type != 1
        && view
            .sections
            .iter()
            .any(|s| s.relocations != 0 && view.executable.iter().any(|r| r.relative == s.relative))
    {
        run.gap("code: Mach-O linked code relocations unsupported".into());
        return (functions, calls);
    }
    for b in &bounds {
        if run.stopped() {
            break;
        }
        if b.end - b.start > FDE_BYTES {
            run.gap(format!(
                "code: Mach-O function at {:#x}: byte limit",
                b.start
            ));
            continue;
        }
        let result = match view.arch {
            Arch::Aarch64 => arm_function(&ctx, b, sig, reader, run),
            Arch::X86_64 => x86_function(&ctx, b, sig, reader, run),
            _ => Err(()),
        };
        match result {
            Ok(pending) if !pending.is_empty() => {
                functions.push(Function {
                    id: pending[0].caller.clone(),
                    entry: b.start,
                    end: b.end,
                    bounds: b.source,
                    names: vec![],
                });
                calls.extend(pending);
            }
            Ok(_) => {}
            Err(()) => run.gap(format!(
                "code: Mach-O function at {:#x}: recording transaction discarded",
                b.start
            )),
        }
    }
    // Target-bearing branches outside exact intervals must never disappear behind Complete.
    scan_unbounded(&ctx, &bounds, reader, run);
    (functions, calls)
}
fn bytes(
    ctx: &Context<'_>,
    b: &MachBounds,
    r: &mut Reader<'_>,
    run: &mut Run,
) -> Result<Vec<u8>, ()> {
    ctx.view
        .read_code(r, b.start, b.end - b.start)
        .map_err(|e| super::read_error(e, r, run))
}
/// Reserve target-bearing raw candidates before recursive decoding. Scanned bytes are
/// only hints; only a reachable instruction in the final CFG can become a call.
fn candidates(
    ctx: &Context<'_>,
    b: &MachBounds,
    bytes: &[u8],
    run: &mut Run,
) -> Result<BTreeSet<u64>, ()> {
    let mut out = BTreeSet::new();
    if ctx.view.file_type == 1 {
        for pc in ctx.fields(b) {
            reserve_candidate(&mut out, *pc, run)?;
        }
        return Ok(out);
    }
    if !ctx.has_targets {
        return Ok(out);
    }
    let stride = if ctx.view.arch == Arch::Aarch64 { 4 } else { 1 };
    for n in (0..bytes.len()).step_by(stride) {
        let pc = b.start + n as u64;
        if ctx.view.arch == Arch::X86_64
            && !matches!(bytes[n], 0xe8 | 0xe9 | 0xeb | 0xff | 0x0f | 0x70..=0x7f)
        {
            continue;
        }
        if !run.charge(Work::Instructions, 1) {
            return Err(());
        }
        let candidate = if ctx.view.arch == Arch::Aarch64 {
            let raw = bytes.get(n..n + 4).ok_or(())?;
            match aarch64::decode::decode_a64(
                u32::from_le_bytes(raw.try_into().map_err(|_| ())?),
                pc,
            )
            .map(|i| i.flow)
            {
                Ok(Flow::CallDirect(t) | Flow::JumpDirect(t)) => stubs::contains(ctx.view, t),
                Ok(Flow::CallRegister(_) | Flow::JumpRegister(_)) => true,
                _ => false,
            }
        } else {
            let mut d =
                iced_x86::Decoder::with_ip(64, &bytes[n..], pc, iced_x86::DecoderOptions::NONE);
            let ins = d.decode();
            if ins.is_invalid()
                || (!matches!(ins.mnemonic(), Mnemonic::Call | Mnemonic::Jmp)
                    && ins.flow_control() != FlowControl::ConditionalBranch)
            {
                false
            } else if ins.op0_kind() == OpKind::NearBranch64 {
                stubs::contains(ctx.view, ins.near_branch_target())
            } else {
                true
            }
        };
        if candidate {
            reserve_candidate(&mut out, pc, run)?;
        }
    }
    Ok(out)
}
fn reserve_candidate(out: &mut BTreeSet<u64>, pc: u64, run: &mut Run) -> Result<(), ()> {
    if !out.contains(&pc) {
        if !run.charge(Work::References, 1) {
            return Err(());
        }
        out.insert(pc);
    }
    Ok(())
}
fn arm_function(
    ctx: &Context<'_>,
    b: &MachBounds,
    sig: &Signatures,
    r: &mut Reader<'_>,
    run: &mut Run,
) -> Result<Vec<CallSite>, ()> {
    let bytes = bytes(ctx, b, r, run)?;
    let candidates = candidates(ctx, b, &bytes, run)?;
    if candidates.is_empty() {
        return Ok(vec![]);
    }
    // Every unmodeled relocation must invalidate the transaction before raw values are used.
    if ctx
        .fields(b)
        .any(|pc| !ctx.relocs.branches.contains_key(pc))
    {
        return Err(());
    }
    let executable = |s: u64, e: u64| {
        e.checked_sub(s)
            .is_some_and(|n| ctx.view.code_at(s, n).is_ok())
    };
    let excluded = |_, _| false;
    let noreturn = |pc, i: &A64Insn| no_return(ctx.a64(pc, i).ok().flatten(), sig);
    let control = |pc, i: &A64Insn| {
        if matches!(i.flow, Flow::JumpRegister(_)) {
            return Ok(aarch64::Control::ProvisionalExit);
        }
        if let Flow::CallDirect(_) | Flow::JumpDirect(_) = i.flow {
            let t = ctx.a64(pc, i).map_err(|_| aarch64::Failure::Excluded(pc))?;
            if matches!(t, Some(Target::Import(..))) {
                return Ok(aarch64::Control::Import);
            }
        }
        Ok(aarch64::Control::Encoded)
    };
    let cfg = aarch64::decode_cfg_with(
        &bytes,
        b.start,
        b.end,
        &aarch64::Proofs {
            executable: &executable,
            excluded: &excluded,
            noreturn: &noreturn,
            candidates: &candidates.iter().copied().collect::<Vec<_>>(),
        },
        &control,
        run,
    )
    .map_err(|_| ())?;
    // Runtime fixups and object memory relocations are never interpreted as constants.
    let maps: Vec<_> = ctx
        .view
        .readonly
        .iter()
        .map(|m| av::Mapping {
            start: m.address.start,
            end: m.address.end,
            file_offset: Some(m.relative.start),
            readable: true,
            writable: false,
            executable: false,
            relocated: true,
        })
        .collect();
    let image = av::Image::new(ctx.view.window, &maps, run).map_err(|_| ())?;
    for field in ctx.fields(b) {
        let ins = cfg.insns.get(field).ok_or(())?;
        if !matches!(
            ctx.a64(*field, ins),
            Ok(Some(Target::Import(_, ImportVia::MachOReloc)))
        ) {
            return Err(());
        }
    }
    let values = av::solve_with_unapplied(&cfg, CodeAbi::DarwinArm64, &image, &|_| false, r, run)
        .map_err(|_| ())?;
    let mut targets = BTreeMap::new();
    let mut tails = BTreeSet::new();
    for (&pc, state) in &values.calls {
        if !candidates.contains(&pc) && !run.charge(Work::References, 1) {
            return Err(());
        }
        let ins = cfg.insns.get(&pc).ok_or(())?;
        let t = match ins.flow {
            Flow::CallRegister(n) | Flow::JumpRegister(n) => {
                let av::Value::Load {
                    base,
                    offset,
                    width: 64,
                    ..
                } = &state.regs[n as usize]
                else {
                    return Err(());
                };
                let av::Value::Const {
                    bits,
                    address: true,
                } = **base
                else {
                    return Err(());
                };
                ctx.slot(bits.checked_add_signed(*offset).ok_or(())?)?
            }
            _ => ctx.a64(pc, ins)?.ok_or(())?,
        };
        if matches!(ins.flow, Flow::JumpDirect(_) | Flow::JumpRegister(_)) {
            tails.insert(pc);
        }
        targets.insert(pc, t);
    }
    let keep = closure(&targets, sig, |pc, out| {
        let state = values.calls.get(&pc).ok_or(())?;
        // Only proved argument positions participate in the retained return closure.
        let t = targets.get(&pc).ok_or(())?;
        let (name, lib) = target_abi(t);
        let plan = V1.argument_plan(Some(CodeAbi::DarwinArm64), name, lib);
        for reg in plan.registers {
            let n = match reg {
                Reg::X0 => 0,
                Reg::X1 => 1,
                Reg::X2 => 2,
                Reg::X3 => 3,
                _ => return Err(()),
            };
            av_returns(&state.regs[n], out);
        }
        Ok(())
    })?;
    let mut pending = vec![];
    for pc in keep {
        let t = targets.get(&pc).ok_or(())?;
        spend(t, run)?;
        let (name, lib) = target_abi(t);
        let args = av::arguments(
            values.calls.get(&pc).ok_or(())?,
            av::Target {
                db: &V1,
                abi: CodeAbi::DarwinArm64,
                symbol: name,
                library: lib,
            },
            pc,
            &image,
            r,
            run,
        )
        .map_err(|_| ())?;
        pending.push(make(
            b,
            pc,
            t,
            tails.contains(&pc),
            args.values,
            args.layout,
        )?);
    }
    Ok(pending)
}
fn target_abi(t: &Target) -> (&UntrustedText, Option<&MachOLibrary>) {
    static EMPTY: std::sync::OnceLock<UntrustedText> = std::sync::OnceLock::new();
    match t {
        Target::Import(w, _) => (&w.name, Some(&w.library)),
        Target::Internal(_) => (EMPTY.get_or_init(|| UntrustedText::new("")), None),
    }
}
fn av_returns(v: &av::Value, out: &mut BTreeSet<u64>) {
    match v {
        av::Value::Return(pc) => {
            out.insert(*pc);
        }
        av::Value::Load { base, .. } | av::Value::Low(base) => av_returns(base, out),
        av::Value::Set(m) => {
            for v in m.iter() {
                av_returns(v, out);
            }
        }
        _ => {}
    }
}
fn closure(
    targets: &BTreeMap<u64, Target>,
    sig: &Signatures,
    mut deps: impl FnMut(u64, &mut BTreeSet<u64>) -> Result<(), ()>,
) -> Result<BTreeSet<u64>, ()> {
    let mut todo: BTreeSet<_> = targets
        .iter()
        .filter_map(|(pc, t)| queried(t, sig).then_some(*pc))
        .collect();
    let mut keep = BTreeSet::new();
    while let Some(pc) = todo.pop_first() {
        if keep.insert(pc) {
            if !targets.contains_key(&pc) {
                return Err(());
            }
            deps(pc, &mut todo)?;
        }
    }
    Ok(keep)
}
fn spend(t: &Target, run: &mut Run) -> Result<(), ()> {
    let n = match t {
        Target::Import(w, _) => {
            2 * w.name.as_bytes().len() as u64
                + match &w.library {
                    MachOLibrary::Dylib { name: Some(n), .. } => n.as_bytes().len() as u64,
                    _ => 0,
                }
        }
        _ => 0,
    };
    if run.charge(Work::Calls, 1) && run.charge(Work::Names, n) {
        Ok(())
    } else {
        Err(())
    }
}
fn make(
    b: &MachBounds,
    pc: u64,
    t: &Target,
    tail: bool,
    args: Vec<ArgValue>,
    layout: ArgumentLayout,
) -> Result<CallSite, ()> {
    Ok(CallSite {
        id: call_id(pc)?,
        caller: fn_id(b.start)?,
        addr: pc,
        kind: if tail {
            CallKind::TailJump
        } else {
            CallKind::Call
        },
        target: t.model(),
        args,
        args_layout: Some(layout),
    })
}
fn x86_function(
    ctx: &Context<'_>,
    b: &MachBounds,
    sig: &Signatures,
    r: &mut Reader<'_>,
    run: &mut Run,
) -> Result<Vec<CallSite>, ()> {
    let bytes = bytes(ctx, b, r, run)?;
    let candidates = candidates(ctx, b, &bytes, run)?;
    if candidates.is_empty() {
        return Ok(vec![]);
    }
    let mut image = Image::empty(Kind::Shared);
    image.code = ctx
        .view
        .executable
        .iter()
        .map(|m| Region {
            start: m.address.start,
            end: m.address.end,
            offset: m.file.start,
        })
        .collect();
    let branch = |i: &xd::Insn| {
        if i.ins.op0_kind() != OpKind::NearBranch64 {
            return None;
        }
        match ctx.x86(i, None) {
            Ok(Some(Target::Internal(t))) => Some(t),
            Ok(Some(Target::Import(..))) | Err(()) => None,
            Ok(None) => Some(i.ins.near_branch_target()),
        }
    };
    let noreturn = |i: &xd::Insn| no_return(ctx.x86(i, None).ok().flatten(), sig);
    let cfg =
        xd::decode(&bytes, b.start, b.end, &image, &branch, &noreturn, run).map_err(|_| ())?;
    for i in cfg.insns.values() {
        if !run.charge(Work::Values, 1) {
            return Err(());
        }
        let ins = &i.ins;
        if ins.flow_control() == FlowControl::ConditionalBranch
            && (ins.op0_kind() != OpKind::NearBranch64
                || !(b.start..b.end).contains(&ins.near_branch_target()))
        {
            run.gap(format!(
                "code: Mach-O function at {:#x}: external conditional branch at {:#x} is not modeled",
                b.start, ins.ip()
            ));
            return Err(());
        }
        let target = if ins.is_ip_rel_memory_operand() {
            Some(ins.ip_rel_memory_address())
        } else if ins.op_count() > 0 && ins.op0_kind() == OpKind::NearBranch64 {
            Some(ins.near_branch_target())
        } else {
            None
        };
        if target.is_some_and(|at| {
            ins.next_ip()
                .checked_add_signed(at.wrapping_sub(ins.next_ip()) as i64)
                != Some(at)
        }) {
            return Err(());
        }
    }
    // A relocation is allowed only on the exact disp32 of a decoded, validated branch.
    for field in ctx.fields(b) {
        let Some((_, i)) = cfg.insns.range(..=*field).next_back() else {
            return Err(());
        };
        if *field != i.ins.ip() + i.offs.immediate_offset() as u64
            || !matches!(
                ctx.x86(i, None),
                Ok(Some(Target::Import(_, ImportVia::MachOReloc)))
            )
        {
            return Err(());
        }
    }
    let values = xv::solve(&cfg, &image, run).map_err(|_| ())?;
    let mut targets = BTreeMap::new();
    let mut tails = BTreeSet::new();
    for (&pc, i) in &cfg.insns {
        if !matches!(i.ins.mnemonic(), Mnemonic::Call | Mnemonic::Jmp) {
            continue;
        }
        if i.ins.mnemonic() != Mnemonic::Call
            && branch(i).is_some_and(|t| b.start <= t && t < b.end)
        {
            continue;
        }
        if !candidates.contains(&pc) && !run.charge(Work::References, 1) {
            return Err(());
        }
        if i.ins.mnemonic() != Mnemonic::Call {
            tails.insert(pc);
        }
        targets.insert(pc, ctx.x86(i, values.at(pc))?.ok_or(())?);
    }
    let keep = closure(&targets, sig, |pc, out| {
        let t = targets.get(&pc).ok_or(())?;
        let (name, lib) = target_abi(t);
        let plan = V1.argument_plan(Some(CodeAbi::DarwinX86_64), name, lib);
        let kept = values.at(pc).ok_or(())?;
        for v in kept.args.iter().take(plan.registers.len()) {
            let mut deps = vec![];
            xr::ret_sites(v, &mut deps);
            out.extend(deps);
        }
        Ok(())
    })?;
    let mut pending = vec![];
    for &pc in &keep {
        let t = targets.get(&pc).ok_or(())?;
        spend(t, run)?;
        let (name, lib) = target_abi(t);
        let plan = V1.argument_plan(Some(CodeAbi::DarwinX86_64), name, lib);
        let id = call_id(pc)?;
        if plan.coverage_gap(&id).is_some_and(|g| !run.required_gap(g)) {
            return Err(());
        }
        let kept = values.at(pc).ok_or(())?;
        let args = kept
            .args
            .iter()
            .zip(plan.registers)
            .map(|(v, reg)| xr::to_arg_plain(v, *reg, &keep))
            .collect();
        pending.push(make(b, pc, t, tails.contains(&pc), args, plan.layout)?);
    }
    Ok(pending)
}
fn scan_unbounded(
    ctx: &Context<'_>,
    bounds: &[MachBounds],
    reader: &mut Reader<'_>,
    run: &mut Run,
) {
    for region in &ctx.view.executable {
        let mut pc = region.address.start;
        while pc < region.address.end && !run.stopped() {
            let i = bounds.partition_point(|b| b.end <= pc);
            if let Some(b) = bounds.get(i).filter(|b| b.start <= pc) {
                pc = b.end;
                continue;
            }
            if stubs::contains(ctx.view, pc) {
                break;
            }
            let end = bounds
                .get(i)
                .map_or(region.address.end, |b| b.start.min(region.address.end));
            let len = (end - pc).min(1 << 20);
            let read_len = (end - pc).min(len + if ctx.view.arch == Arch::X86_64 { 14 } else { 0 });
            let bytes = match ctx.view.read_code(reader, pc, read_len) {
                Ok(bytes) => bytes,
                Err(e) => {
                    super::read_error(e, reader, run);
                    break;
                }
            };
            let stride = if ctx.view.arch == Arch::Aarch64 { 4 } else { 1 };
            for n in (0..len as usize).step_by(stride) {
                if !run.charge(Work::Instructions, 1) {
                    return;
                }
                let at = pc + n as u64;
                if ctx.relocs.fields.contains_key(&at) {
                    if !run.charge(Work::References, 1) {
                        return;
                    }
                    run.gap(format!(
                        "code: Mach-O reference at {at:#x} has no exact function bounds"
                    ));
                }
                let mut indirect_reference = false;
                let target = if ctx.view.arch == Arch::Aarch64 {
                    bytes
                        .get(n..n + 4)
                        .and_then(|b| {
                            aarch64::decode::decode_a64(u32::from_le_bytes(b.try_into().ok()?), at)
                                .ok()
                        })
                        .and_then(|i| {
                            if matches!(i.flow, Flow::CallRegister(_)) && ctx.has_targets {
                                indirect_reference = true;
                            }
                            if n >= 4 {
                                use aarch64::decode::{AddressMode, Operation};
                                if let Operation::Memory {
                                    load: true,
                                    base,
                                    offset,
                                    mode: AddressMode::Offset,
                                    ..
                                } = i.operation
                                {
                                    if !run.charge(Work::Instructions, 1) {
                                        return None;
                                    }
                                    if let Ok(previous) = aarch64::decode::decode_a64(
                                        u32::from_le_bytes(bytes[n - 4..n].try_into().ok()?),
                                        at - 4,
                                    ) {
                                        if let Operation::Address { dst, address } =
                                            previous.operation
                                        {
                                            if dst == base {
                                                indirect_reference = address
                                                    .checked_add_signed(i64::from(offset))
                                                    .is_some_and(|slot| queried_slot(ctx, slot));
                                            }
                                        }
                                    }
                                }
                            }
                            match i.flow {
                                Flow::CallDirect(t) | Flow::JumpDirect(t) => Some(t),
                                _ => None,
                            }
                        })
                } else {
                    let mut d = iced_x86::Decoder::with_ip(
                        64,
                        &bytes[n..],
                        at,
                        iced_x86::DecoderOptions::NONE,
                    );
                    let ins = d.decode();
                    if !ins.is_invalid() && matches!(ins.mnemonic(), Mnemonic::Call | Mnemonic::Jmp)
                    {
                        indirect_reference = (ins.op0_kind() == OpKind::Register
                            && ctx.has_targets)
                            || (ins.is_ip_rel_memory_operand()
                                && queried_slot(ctx, ins.ip_rel_memory_address()));
                    }
                    ((matches!(ins.mnemonic(), Mnemonic::Call | Mnemonic::Jmp)
                        || ins.flow_control() == FlowControl::ConditionalBranch)
                        && ins.op0_kind() == OpKind::NearBranch64)
                        .then(|| ins.near_branch_target())
                };
                if indirect_reference || target.is_some_and(|t| stubs::contains(ctx.view, t)) {
                    if !run.charge(Work::References, 1) {
                        return;
                    }
                    run.gap(format!(
                        "code: Mach-O reference at {at:#x} has no exact function bounds"
                    ));
                }
            }
            pc += len;
        }
    }
}

fn queried_slot(ctx: &Context<'_>, at: u64) -> bool {
    ctx.slots.get(&at).is_some_and(|w| {
        crate::code::data::signatures()
            .is_ok_and(|sig| queried(&Target::Import(w.clone(), ImportVia::MachOGot), sig))
    })
}
