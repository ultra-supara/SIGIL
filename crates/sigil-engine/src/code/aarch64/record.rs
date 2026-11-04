//! Final per-function transaction: bounds, symbolic CFG, targets, values and retained calls.
use super::{
    decode::{A64Insn, Flow},
    search::{self, Candidates},
    value, Control, Failure, Proofs,
};
use crate::code::{
    data::Signatures,
    image::aarch64::{A64ElfImage, Branch},
    reader::Reader,
    Run, Work,
};
use sigil_model::{
    code_abi::{CodeAbi, V1},
    ArgValue, BoundsSource, CallId, CallKind, CallSite, CallTarget, FnId, Function, ImportVia,
    UntrustedText,
};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn analyze(
    image: &A64ElfImage,
    imports: &[sigil_model::ElfImport],
    sig: &Signatures,
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> (Vec<Function>, Vec<CallSite>) {
    let mut functions = Vec::new();
    let mut calls = Vec::new();
    let imports: BTreeSet<&[u8]> = imports.iter().map(|i| i.name.as_bytes()).collect();
    let mut candidates = Candidates::default();
    candidates.scan_with(
        image,
        reader,
        run,
        &mut |range, candidates, reader, run| match function(
            image, &imports, sig, range, candidates, reader, run,
        ) {
            Ok(pending) if !pending.is_empty() => {
                let Some(first) = pending.first() else {
                    return;
                };
                functions.push(Function {
                    id: first.caller.clone(),
                    entry: range.0,
                    end: range.1,
                    bounds: BoundsSource::EhFrameFde,
                    names: vec![],
                });
                calls.extend(pending);
            }
            Ok(_) => {}
            Err(()) => run.gap(format!(
                "code: AArch64 function at {:#x}: recording transaction discarded",
                range.0
            )),
        },
    );
    (functions, calls)
}
fn fn_id(at: u64) -> Result<FnId, ()> {
    FnId::new(format!("fn:{at:#x}")).map_err(|_| ())
}
fn call_id(at: u64) -> Result<CallId, ()> {
    CallId::new(format!("cs:{at:#x}")).map_err(|_| ())
}

fn direct(image: &A64ElfImage, pc: u64, ins: &A64Insn) -> Result<Option<Branch>, Failure> {
    if matches!(ins.flow, Flow::CallDirect(_) | Flow::JumpDirect(_)) {
        if image.object && image.relocs.contains_key(&pc) {
            return image
                .branch(pc, ins.word)
                .map(Some)
                .ok_or(Failure::Excluded(pc));
        }
        if let Flow::CallDirect(t) | Flow::JumpDirect(t) = ins.flow {
            return Ok(image.stubs.get(&t).cloned().map(Branch::Import));
        }
    }
    Ok(None)
}
#[allow(clippy::too_many_arguments)]
fn function(
    image: &A64ElfImage,
    imports: &BTreeSet<&[u8]>,
    sig: &Signatures,
    range: (u64, u64),
    candidates: &[u64],
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> Result<Vec<CallSite>, ()> {
    let (entry, end) = range;
    let bytes = image.read_code(entry, end - entry, reader, run).ok_or(())?;
    let executable = |s, e| image.executable(s, e);
    let excluded = |s, e| image.excluded(s, e);
    let noreturn = |pc, ins: &A64Insn| matches!(direct(image, pc, ins), Ok(Some(Branch::Import(w))) if imports.contains(w.name.as_ref()) && sig.is_noreturn(&w.name));
    let control = |pc, ins: &A64Insn| {
        Ok(match direct(image, pc, ins)? {
            Some(Branch::Import(_))
                if !image.object
                    && matches!(ins.flow, Flow::JumpDirect(t) if entry <= t && t < end) =>
            {
                Control::Encoded
            }
            Some(Branch::Import(_)) => Control::Import,
            Some(Branch::Internal(t)) => Control::Internal(t),
            None if matches!(ins.flow, Flow::JumpRegister(_)) => Control::ProvisionalExit,
            None => Control::Encoded,
        })
    };
    let cfg = super::decode_cfg_with(
        &bytes,
        entry,
        end,
        &Proofs {
            executable: &executable,
            excluded: &excluded,
            noreturn: &noreturn,
            candidates,
        },
        &control,
        run,
    )
    .map_err(|_| ())?;
    let targets = search::resolve_cfg(&cfg, image, run)?;
    // The provisional BR exit is admitted only after all incoming paths prove one import.
    for (&pc, ins) in &cfg.insns {
        if matches!(ins.flow, Flow::JumpRegister(_))
            && !matches!(targets.get(&pc), Some(Branch::Import(_)))
        {
            return Err(());
        }
    }
    let mut pending = BTreeSet::new();
    for (&pc, target) in &targets {
        if let Branch::Import(w) = target {
            if !imports.contains(w.name.as_ref()) {
                run.gap(format!(
                    "code: AArch64 target at {pc:#x}: absent from bounded slice imports"
                ));
                return Err(());
            }
            if sig.capability(&w.name).is_some() {
                pending.insert(pc);
            }
        }
    }
    if pending.is_empty() {
        return Ok(vec![]);
    }
    let states = image.solve_values(&cfg, reader, run).map_err(|_| ())?;
    let values_image = image.values(run).map_err(|_| ())?;
    let mut retained = BTreeMap::new();
    while let Some(pc) = pending.pop_first() {
        if retained.contains_key(&pc) {
            continue;
        }
        if !run.charge(Work::Calls, 1) {
            return Err(());
        }
        let ins = cfg.insns.get(&pc).ok_or(())?;
        let tail = matches!(ins.flow, Flow::JumpDirect(_) | Flow::JumpRegister(_));
        let target = match targets.get(&pc) {
            Some(Branch::Import(w)) => {
                if !run.charge(Work::Names, w.name.len() as u64) {
                    return Err(());
                }
                CallTarget::Import {
                    symbol: UntrustedText::from_bytes(w.name.to_vec()),
                    via: if image.object {
                        ImportVia::Reloc
                    } else if matches!(ins.flow, Flow::CallDirect(_) | Flow::JumpDirect(_)) {
                        ImportVia::Plt
                    } else {
                        ImportVia::Got
                    },
                    macho_import: None,
                }
            }
            Some(Branch::Internal(t)) => CallTarget::Internal {
                entry: *t,
                export_name: None,
            },
            None => match ins.flow {
                Flow::CallDirect(t) => CallTarget::Internal {
                    entry: t,
                    export_name: None,
                },
                _ => return Err(()),
            },
        };
        let unknown = UntrustedText::new("");
        let symbol = match &target {
            CallTarget::Import { symbol, .. } => symbol,
            _ => &unknown,
        };
        let args = value::arguments(
            states.calls.get(&pc).ok_or(())?,
            value::Target {
                db: &V1,
                abi: CodeAbi::ElfAarch64,
                symbol,
                library: None,
            },
            pc,
            &values_image,
            reader,
            run,
        )
        .map_err(|_| ())?;
        for arg in &args.values {
            dependencies(arg, &mut pending)?;
        }
        retained.insert(
            pc,
            CallSite {
                id: call_id(pc)?,
                caller: fn_id(entry)?,
                addr: pc,
                kind: if tail {
                    CallKind::TailJump
                } else {
                    CallKind::Call
                },
                target,
                args: args.values,
                args_layout: Some(args.layout),
            },
        );
    }
    Ok(retained.into_values().collect())
}
fn dependencies(arg: &ArgValue, pending: &mut BTreeSet<u64>) -> Result<(), ()> {
    match arg {
        ArgValue::ReturnOf { call, .. } => {
            pending.insert(
                u64::from_str_radix(call.as_str().strip_prefix("cs:0x").ok_or(())?, 16)
                    .map_err(|_| ())?,
            );
        }
        ArgValue::Load { base, .. } => dependencies(base, pending)?,
        ArgValue::Low { value, .. } => dependencies(value, pending)?,
        ArgValue::Set { members, .. } => {
            for m in members {
                dependencies(m, pending)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::{reader::SliceWindow, ArtifactAnalysis, CodeBudgets, CodeOutcome};
    use std::io::Write;
    fn fixture() -> Vec<u8> {
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/code-aarch64/elf-clang-plt.so"
        ))
        .unwrap()
    }
    fn imports() -> Vec<sigil_model::ElfImport> {
        let bytes = fixture();
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&bytes).unwrap();
        let parsed = crate::binary::parse(&file, bytes.len() as u64, Default::default());
        let sigil_model::ContainerFacts::Elf(e) = parsed.container else {
            panic!("ELF")
        };
        e.imports
    }
    #[test]
    fn actual_pipeline_reference_cap_is_shared_across_functions_and_slices() {
        let bytes = fixture();
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&bytes).unwrap();
        file.write_all(&bytes).unwrap();
        let mut artifact = ArtifactAnalysis::new(
            &file,
            2 * bytes.len() as u64,
            CodeBudgets {
                references: 3,
                ..Default::default()
            },
        );
        let imports = imports();
        let sig = crate::code::data::signatures().unwrap();
        let mut outcomes = Vec::new();
        for base in [0, bytes.len() as u64] {
            outcomes.push(artifact.slice(true, |reader, run| {
                let image = crate::code::image::aarch64::build(
                    reader,
                    SliceWindow {
                        base,
                        len: bytes.len() as u64,
                    },
                    run,
                )
                .unwrap();
                analyze(&image, &imports, sig, reader, run)
            }));
        }
        let CodeOutcome::Analyzed {
            call_sites: first,
            gaps: g1,
            budget: b1,
            ..
        } = &outcomes[0]
        else {
            panic!("first")
        };
        let CodeOutcome::Analyzed {
            call_sites: second,
            gaps: g2,
            budget: b2,
            ..
        } = &outcomes[1]
        else {
            panic!("second")
        };
        assert_eq!(first.len(), 2);
        assert!(g1.is_empty());
        assert_eq!(second.len(), 1);
        assert!(g2.iter().any(|g| g.contains("references limit 3")));
        assert_eq!(artifact.run.references, 3);
        assert!(artifact.run.stopped());
        assert_eq!(artifact.reader.used(), b1.used + b2.used);
        let third = artifact.slice(true, |_, _| panic!("no later work"));
        assert!(
            matches!(third,CodeOutcome::Analyzed {budget,gaps,call_sites,..} if budget.used==0 && call_sites.is_empty() && gaps==["code: artifact budget exhausted before slice"])
        );
    }
    #[test]
    fn repeated_candidate_reservations_and_scan_commit_each_function_once() {
        let bytes = fixture();
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&bytes).unwrap();
        let mut reader = Reader::new(&file, bytes.len() as u64, 1 << 28);
        let mut run = Run::new(CodeBudgets {
            references: 2,
            ..Default::default()
        });
        let image = crate::code::image::aarch64::build(
            &mut reader,
            SliceWindow {
                base: 0,
                len: bytes.len() as u64,
            },
            &mut run,
        )
        .unwrap();
        let mut owner = Candidates::default();
        for _ in 0..8 {
            assert!(owner.reserve(0x103a0, &image, &mut run));
        }
        let imports = imports();
        let imports = imports.iter().map(|i| i.name.as_bytes()).collect();
        let mut committed = Vec::new();
        let sig = crate::code::data::signatures().unwrap();
        let mut confirm = |range, pcs: &[u64], reader: &mut Reader<'_>, run: &mut Run| {
            assert_eq!(pcs.len(), 1);
            committed.extend(function(&image, &imports, sig, range, pcs, reader, run).unwrap());
        };
        assert!(owner.scan_with(&image, &mut reader, &mut run, &mut confirm));
        let used = reader.used();
        assert!(owner.scan_with(&image, &mut reader, &mut run, &mut confirm));
        assert_eq!(reader.used(), used);
        assert_eq!(run.references, 2);
        assert_eq!(committed.len(), 2);
        assert!(!run.stopped());
        assert!(run.clone_gaps().is_empty());
    }
}
