//! Additive evidence contract; strict coverage lives in `code_coverage`.
use std::collections::BTreeSet;

use super::Validator;
use crate::code_abi::{self, CodeAbi};
use crate::{
    Arch, ArgValue, ArgumentLayout, BinaryParam, BoundsSource, CallTarget, ContainerFacts,
    CoverageState, Format, ImportVia, KnowledgeKind, MachOImport, Ref, Reg, SliceId, UntrustedText,
    ARTIFACTS_CODE, BINARY_CODE, INSTALL_ROOT,
};

impl Validator<'_> {
    pub(super) fn multiarch_code(&mut self) {
        let s = self.s;
        let marked = s.request.code_analysis.is_some();
        if !marked {
            // Historical installation facts may name non-x86/ELF slices. Preserve the
            // legacy validator's contract; only genuinely new evidence needs the marker.
            for binary in &s.binaries {
                if matches!(&binary.container, ContainerFacts::MachO(m) if m.little_endian.is_some())
                {
                    self.code_error(
                        &binary.slice,
                        "Mach-O byte-order observation needs multiarch-v1",
                    );
                }
            }
            for a in &s.artifacts {
                if a.code_slice_inventory.is_some() {
                    self.code_error(&a.id, "code_slice_inventory needs multiarch-v1");
                }
            }
            for c in &s.coverage {
                if matches!(c.check.as_str(), BINARY_CODE | ARTIFACTS_CODE)
                    && matches!(c.scope, Ref::Slice(_))
                {
                    self.code_error("coverage", "slice code coverage needs multiarch-v1");
                }
            }
            for f in &s.code {
                for function in &f.functions {
                    if function.bounds == BoundsSource::MachOCompactUnwind {
                        self.code_error(&f.slice, "compact unwind needs multiarch-v1");
                    }
                }
                for c in &f.call_sites {
                    if c.args_layout.is_some() {
                        self.code_error(&c.id, "argument layout needs multiarch-v1");
                    }
                    if matches!(&c.target, CallTarget::Import { via, macho_import, .. } if is_macho(*via) || macho_import.is_some())
                    {
                        self.code_error(&c.id, "Mach-O import witness needs multiarch-v1");
                    }
                }
            }
            return;
        }

        if !s.request.code {
            self.code_error("request", "marker needs request.code");
        }
        // Task 11/16 must enable slice-aware reasons and library-aware matching together
        // in the evaluator and saved-result validator. Legacy capability results stay intact.
        if s.policy_violations.iter().any(|v| {
            v.policy_rule
                .as_str()
                .starts_with(crate::CAPABILITY_DENY_PREFIX)
        }) || s
            .open_questions
            .iter()
            .any(|q| q.rule.as_str() == crate::CAPABILITY_RULE)
        {
            self.code_error(
                "policy",
                "marked capability decisions await slice-aware policy validation",
            );
        }
        if !s
            .request
            .roots
            .iter()
            .any(|r| crate::is_binary_root(&r.id) || r.id.as_str() == INSTALL_ROOT)
        {
            self.code_error("request", "marker needs a binary or installation root");
        }
        let references: Vec<_> = s
            .knowledge
            .iter()
            .filter(|k| k.id == code_abi::ID)
            .collect();
        let db = match references.as_slice() {
            [k] if k.kind == KnowledgeKind::SignatureDb => {
                code_abi::archived(&k.version, k.sha256.as_str())
            }
            _ => None,
        };
        if db.is_none() {
            self.code_error(
                "knowledge",
                "exactly one archived SignatureDb/code-abi-signatures version/hash is required",
            );
        }

        // Index exact imports once per slice, rather than scanning every import for each call.
        let imports: std::collections::HashMap<&SliceId, BTreeSet<&MachOImport>> = s
            .binaries
            .iter()
            .filter_map(|b| {
                let ContainerFacts::MachO(m) = &b.container else {
                    return None;
                };
                Some((&b.slice, m.imports.iter().collect()))
            })
            .collect();
        let elf_imports: std::collections::HashMap<&SliceId, BTreeSet<&UntrustedText>> = s
            .binaries
            .iter()
            .filter_map(|b| {
                let ContainerFacts::Elf(e) = &b.container else {
                    return None;
                };
                Some((&b.slice, e.imports.iter().map(|i| &i.name).collect()))
            })
            .collect();
        // Only the applicable check can justify a partial argument layout. A second check's
        // Partial must not lend its gaps to a complete or missing applicable child.
        let applicable = if crate::is_binary_inspection(&s.request) {
            BINARY_CODE
        } else {
            ARTIFACTS_CODE
        };
        let mut code_gaps: std::collections::HashMap<&SliceId, BTreeSet<&str>> =
            std::collections::HashMap::new();
        for coverage in &s.coverage {
            if coverage.check.as_str() != applicable {
                continue;
            }
            if let (Ref::Slice(slice), CoverageState::Partial { missing }) =
                (&coverage.scope, &coverage.state)
            {
                code_gaps
                    .entry(slice)
                    .or_default()
                    .extend(missing.iter().map(String::as_str));
            }
        }
        for facts in &s.code {
            let Some((_, artifact, slice)) = self.index.slices.get(facts.slice.as_str()) else {
                continue;
            };
            let Some(binary) = self.index.binaries.get(facts.slice.as_str()) else {
                self.code_error(&facts.slice, "multiarch code facts require a parsed slice");
                continue;
            };
            let macho = matches!(binary.container, ContainerFacts::MachO(_));
            if macho && !facts.call_sites.is_empty() {
                self.code_error(
                    &facts.slice,
                    "marked Mach-O call facts await library-aware policy validation",
                );
            }
            if !matches!(slice.arch, Arch::X86_64 | Arch::Aarch64) {
                self.code_error(&facts.slice, "unsupported code architecture");
            }
            let functions: std::collections::HashMap<_, _> =
                facts.functions.iter().map(|f| (&f.id, f)).collect();
            for f in &facts.functions {
                if f.entry >= f.end {
                    self.code_error(&f.id, "function bounds need entry < end");
                }
                if f.bounds == BoundsSource::MachOCompactUnwind
                    && !matches!(&binary.container, ContainerFacts::MachO(m) if m.file_type == crate::MH_OBJECT)
                {
                    self.code_error(
                        &f.id,
                        "compact unwind requires Mach-O object explicit-length bounds",
                    );
                }
            }
            let abi = match (&binary.container, slice.arch) {
                (ContainerFacts::Elf(e), Arch::Aarch64)
                    if matches!(
                        e.abi,
                        Some(crate::ElfAbi {
                            is_64: true,
                            little_endian: true,
                            machine: 183
                        })
                    ) =>
                {
                    Some(CodeAbi::ElfAarch64)
                }
                (ContainerFacts::MachO(m), Arch::Aarch64)
                    if m.is_64 && m.cpu_type == 0x0100_000c =>
                {
                    Some(CodeAbi::DarwinArm64)
                }
                (ContainerFacts::MachO(m), Arch::X86_64)
                    if m.is_64 && m.cpu_type == 0x0100_0007 =>
                {
                    Some(CodeAbi::DarwinX86_64)
                }
                _ => None,
            };
            let legacy =
                matches!(artifact.format, Format::Elf { .. }) && slice.arch == Arch::X86_64;
            for c in &facts.call_sites {
                if c.id.as_str() != format!("cs:{:#x}", c.addr) {
                    self.code_error(&c.id, "call ID must match its canonical address");
                    // Do not use an arbitrary legacy ID as the boundary of a per-call gap.
                    continue;
                }
                let register_limit = if slice.arch == Arch::Aarch64 { 8 } else { 6 };
                if c.args.len() > register_limit {
                    self.code_error(&c.id, "call exceeds the argument-register ABI limit");
                }
                if functions
                    .get(&c.caller)
                    .is_some_and(|f| c.addr < f.entry || c.addr >= f.end)
                {
                    self.code_error(&c.id, "call address outside caller bounds");
                }
                let unknown = UntrustedText::new("");
                let (symbol, library) = if let CallTarget::Import {
                    symbol,
                    via,
                    macho_import,
                } = &c.target
                {
                    if macho {
                        if !matches!(&binary.container, ContainerFacts::MachO(m) if macho_route_admits(*via, m.file_type))
                        {
                            self.code_error(
                                &c.id,
                                "Mach-O import route contradicts the parsed file type",
                            );
                        }
                        if !is_macho(*via)
                            || !macho_import.as_ref().is_some_and(|m| {
                                m.name == *symbol
                                    && imports.get(&facts.slice).is_some_and(|set| set.contains(m))
                            })
                        {
                            self.code_error(&c.id, "Mach-O import witness must exactly match name/library/weak in this slice and route");
                        }
                    } else {
                        if is_macho(*via) || macho_import.is_some() {
                            self.code_error(
                                &c.id,
                                "ELF cannot carry a Mach-O import witness or route",
                            );
                        }
                        if !elf_imports
                            .get(&facts.slice)
                            .is_some_and(|set| set.contains(symbol))
                        {
                            self.code_error(&c.id, "import target is absent from its parsed slice");
                        }
                    }
                    (symbol, macho_import.as_ref().map(|m| &m.library))
                } else {
                    (&unknown, None)
                };
                if legacy {
                    if c.args_layout.is_some() {
                        self.code_error(&c.id, "legacy x86 ELF argument layout must remain absent");
                    }
                    continue;
                }
                let Some(layout) = &c.args_layout else {
                    self.code_error(&c.id, "new code facts require an argument layout");
                    continue;
                };
                let Some(db) = db else { continue };
                let plan = db.argument_plan(abi, symbol, library);
                if c.args.len() != plan.registers.len()
                    || c.args
                        .iter()
                        .zip(plan.registers)
                        .any(|(arg, reg)| arg.register() != *reg)
                {
                    self.code_error(
                        &c.id,
                        "argument prefix does not match archived ABI locations",
                    );
                }
                match layout {
                    ArgumentLayout::Complete if plan.layout != ArgumentLayout::Complete => {
                        self.code_error(
                            &c.id,
                            "argument layout cannot be Complete for an unproved full prototype",
                        );
                    }
                    ArgumentLayout::Partial { reason } => {
                        if reason.as_bytes().iter().all(u8::is_ascii_whitespace) {
                            self.code_error(
                                &c.id,
                                "partial argument layout needs a nonempty reason",
                            );
                        }
                        let gap = code_abi::argument_layout_gap(&c.id, reason);
                        if !code_gaps
                            .get(&facts.slice)
                            .is_some_and(|gaps| gaps.contains(gap.as_str()))
                        {
                            self.code_error(&c.id, "partial argument layout gap is missing");
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    pub(super) fn multiarch_register(
        &mut self,
        slice: &SliceId,
        reg: Reg,
        at: &(impl std::fmt::Display + ?Sized),
    ) {
        if self.s.request.code_analysis.is_none() {
            if reg.arch() == Arch::Aarch64 {
                self.code_error(at, "AArch64 register needs multiarch-v1");
            }
        } else if self
            .index
            .slices
            .get(slice.as_str())
            .is_some_and(|(_, _, s)| s.arch != reg.arch())
        {
            self.code_error(at, "register architecture differs from owning slice");
        }
    }

    pub(super) fn multiarch_arg(
        &mut self,
        slice: &SliceId,
        value: &ArgValue,
        at: &(impl std::fmt::Display + ?Sized),
    ) {
        self.multiarch_register(slice, value.register(), at);
        if self.s.request.code_analysis.is_none() {
            return;
        }
        if let ArgValue::Param { reg, index } = value {
            if self
                .index
                .slices
                .get(slice.as_str())
                .is_some_and(|(_, _, s)| *index >= if s.arch == Arch::Aarch64 { 8 } else { 6 })
            {
                self.code_error(at, "parameter index exceeds the register ABI");
            }
            if *reg == Reg::X18
                && self
                    .index
                    .binaries
                    .get(slice.as_str())
                    .is_some_and(|b| matches!(b.container, ContainerFacts::MachO(_)))
            {
                self.code_error(at, "Darwin reserved x18 cannot hold a stable parameter");
            }
        }
    }

    pub(super) fn multiarch_param(
        &mut self,
        slice: &SliceId,
        param: &BinaryParam,
        at: &(impl std::fmt::Display + ?Sized),
    ) {
        if let BinaryParam::Reg(reg) = param {
            self.multiarch_register(slice, *reg, at);
            if self.s.request.code_analysis.is_some()
                && *reg == Reg::X18
                && self
                    .index
                    .binaries
                    .get(slice.as_str())
                    .is_some_and(|b| matches!(b.container, ContainerFacts::MachO(_)))
            {
                self.code_error(at, "Darwin reserved x18 cannot hold a stable parameter");
            }
        }
    }
}

fn is_macho(via: ImportVia) -> bool {
    matches!(
        via,
        ImportVia::MachOStub | ImportVia::MachOGot | ImportVia::MachOReloc
    )
}

/// Symbolic branch relocations are object evidence. Stub/GOT bindings belong only to
/// the linked formats admitted by the design: MH_EXECUTE=2, MH_DYLIB=6, MH_BUNDLE=8.
fn macho_route_admits(via: ImportVia, file_type: u32) -> bool {
    match via {
        ImportVia::MachOReloc => file_type == crate::MH_OBJECT,
        ImportVia::MachOStub | ImportVia::MachOGot => matches!(file_type, 2 | 6 | 8),
        _ => false,
    }
}
