//! Code facts of the fixtures through the parse (PR-5a spec §8.1). The expectations follow the
//! **Shape** column of `tests/fixtures/code/README.md` where the compilers differ from the spec.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use sigil_engine::binary::{parse_artifact, BinaryBudgets, ParsedSlice};
use sigil_engine::code::{CodeBudgets, CodeOutcome};
use sigil_model::{
    ArgValue, BudgetUse, CallKind, CallSite, CallTarget, Function, ImportVia, Reg, Sha256Hex,
    ValueUnknown,
};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/code")
        .join(name)
}

/// The first slice of the file at `path`, parsed with `budgets`.
fn slice_at(path: &Path, budgets: BinaryBudgets) -> ParsedSlice {
    try_slice_at(path, budgets).unwrap_or_else(|| panic!("{}: not parsed", path.display()))
}

/// The first slice of the file at `path`, if `parse_artifact` recognizes it.
fn try_slice_at(path: &Path, budgets: BinaryBudgets) -> Option<ParsedSlice> {
    try_slices_at(path, budgets).and_then(|s| s.into_iter().next())
}

/// Every slice of the file at `path`, if `parse_artifact` recognizes it.
fn try_slices_at(path: &Path, budgets: BinaryBudgets) -> Option<Vec<ParsedSlice>> {
    let file = File::open(path).unwrap();
    let size = file.metadata().unwrap().len();
    let mut prefix = vec![0u8; 64];
    let n = file.read_at(&mut prefix, 0).unwrap();
    prefix.truncate(n);
    let digest = Sha256Hex::new("0".repeat(64)).unwrap();
    parse_artifact(&file, size, &digest, &prefix, budgets).map(|p| p.slices)
}

fn with_code(code: CodeBudgets) -> BinaryBudgets {
    BinaryBudgets {
        code: Some(code),
        ..BinaryBudgets::default()
    }
}

type Outcome = (Vec<CallSite>, Vec<Function>, Vec<String>);

fn analyzed(what: &str, slice: ParsedSlice) -> Outcome {
    match slice.code.unwrap() {
        CodeOutcome::Analyzed {
            functions,
            call_sites,
            gaps,
            ..
        } => (call_sites, functions, gaps),
        CodeOutcome::Unsupported => panic!("{what}: unsupported"),
    }
}

fn outcome_at(path: &Path, code: CodeBudgets) -> Outcome {
    analyzed(&path.display().to_string(), slice_at(path, with_code(code)))
}

fn outcome_with(name: &str, code: CodeBudgets) -> Outcome {
    outcome_at(&fixture(name), code)
}

fn outcome(name: &str) -> Outcome {
    outcome_with(name, CodeBudgets::default())
}

fn import(c: &CallSite) -> Option<(&str, ImportVia)> {
    match &c.target {
        CallTarget::Import { symbol, via } => Some((symbol.as_str().unwrap(), *via)),
        _ => None,
    }
}

fn calls_of<'a>(calls: &'a [CallSite], name: &str) -> Vec<&'a CallSite> {
    calls
        .iter()
        .filter(|c| import(c).is_some_and(|(n, _)| n == name))
        .collect()
}

fn connects(calls: &[CallSite]) -> Vec<&CallSite> {
    calls_of(calls, "connect")
}

fn c0(reg: Reg) -> ArgValue {
    ArgValue::ConstInt { reg, value: 0 }
}

fn named<'a>(functions: &'a [Function], name: &str) -> &'a Function {
    functions
        .iter()
        .find(|f| f.names.iter().any(|n| n.as_str() == Some(name)))
        .unwrap_or_else(|| panic!("no function named {name}: {functions:#?}"))
}

/// The call site of `connect` in the function named `name`.
fn connect_in<'a>(calls: &'a [CallSite], functions: &[Function], name: &str) -> &'a CallSite {
    let f = named(functions, name);
    connects(calls)
        .into_iter()
        .find(|c| c.caller == f.id)
        .unwrap_or_else(|| panic!("no connect in {name}: {calls:#?}"))
}

/// `Low(ReturnOf(<the call to helper>), 32)` in `rdi`: `helper`'s result copied by `mov %eax,%edi`.
fn low_return_of_helper(calls: &[CallSite], arg: &ArgValue) -> bool {
    let ArgValue::Low {
        reg: Reg::Rdi,
        value,
        bits: 32,
    } = arg
    else {
        return false;
    };
    let ArgValue::ReturnOf { call, .. } = &**value else {
        return false;
    };
    calls.iter().any(|c| {
        &c.id == call
            && matches!(&c.target,
                CallTarget::Internal { export_name: Some(n), .. }
                | CallTarget::OwnExportViaPlt { symbol: n, .. } if n.as_str() == Some("helper"))
    })
}

#[test]
fn suspicious_kernel_calls_connect_with_zeros() {
    for f in ["suspicious_kernel-clang-O0.o", "suspicious_kernel-gcc-O2.o"] {
        let (calls, functions, gaps) = outcome(f);
        assert_eq!(gaps, Vec::<String>::new(), "{f}");
        let c = connects(&calls);
        assert_eq!(c.len(), 1, "{f}: {calls:#?}");
        assert_eq!(calls.len(), 1, "{f}: {calls:#?}");
        assert_eq!(import(c[0]), Some(("connect", ImportVia::Reloc)));
        assert_eq!(c[0].kind, CallKind::Call);
        assert_eq!(c[0].args, [c0(Reg::Rdi), c0(Reg::Rsi), c0(Reg::Rdx)], "{f}");
        let caller = functions.iter().find(|fun| fun.id == c[0].caller).unwrap();
        assert_eq!(
            caller
                .names
                .iter()
                .map(|n| n.as_str().unwrap())
                .collect::<Vec<_>>(),
            ["kernel"]
        );
    }
}

#[test]
fn clean_kernel_has_nothing_to_search() {
    for f in ["clean_kernel-clang-O0.o", "clean_kernel-gcc-O2.o"] {
        let (calls, functions, gaps) = outcome(f);
        assert!(
            calls.is_empty() && functions.is_empty() && gaps.is_empty(),
            "{f}: {calls:#?} {gaps:#?}"
        );
    }
}

#[test]
fn unlinked_got_calls_are_imports_via_reloc() {
    for f in [
        "calls-noplt-gcc-O0.o",
        "calls-noplt-clang-O0.o",
        "calls-noplt-gcc-O2.o",
        "calls-noplt-clang-O2.o",
    ] {
        let (calls, functions, gaps) = outcome(f);
        assert_eq!(gaps, Vec::<String>::new(), "{f}");
        let c = connects(&calls);
        assert_eq!(c.len(), 3, "{f}: kernel, loop, calls_helper: {calls:#?}");
        assert!(
            c.iter()
                .all(|c| import(c) == Some(("connect", ImportVia::Reloc))),
            "{f}"
        );
        for name in ["kernel", "loop", "calls_helper"] {
            let _ = connect_in(&calls, &functions, name);
        }
        // `helper`, defined in the object: through its GOT entry (gcc) or by a direct `PLT32`
        // call (clang, README): an Internal call at its offset, with its name.
        assert!(
            calls.iter().any(|c| matches!(&c.target,
                CallTarget::Internal { export_name: Some(n), .. } if n.as_str() == Some("helper"))),
            "{f}: {calls:#?}"
        );
        // README: `calls_helper`'s arg 0 is `mov %eax,%edi` after the `helper` call.
        let ch = connect_in(&calls, &functions, "calls_helper");
        assert!(
            low_return_of_helper(&calls, &ch.args[0]),
            "{f}: {:?}",
            ch.args[0]
        );
    }
    // README: at -O0, `kernel`'s arg 0 is spilled and read back from the frame.
    for f in ["calls-noplt-gcc-O0.o", "calls-noplt-clang-O0.o"] {
        let (calls, functions, _) = outcome(f);
        let k = connect_in(&calls, &functions, "kernel");
        assert_eq!(k.kind, CallKind::Call, "{f}");
        assert_eq!(
            k.args,
            [
                ArgValue::Unknown {
                    reg: Reg::Rdi,
                    reason: ValueUnknown::FromMemory
                },
                c0(Reg::Rsi),
                c0(Reg::Rdx)
            ],
            "{f}"
        );
    }
    // README: at -O2, `kernel` is `jmp *[rip]` (both compilers), and `calls_helper` tail-jumps
    // to `connect` too.
    for f in ["calls-noplt-gcc-O2.o", "calls-noplt-clang-O2.o"] {
        let (calls, functions, _) = outcome(f);
        let k = connect_in(&calls, &functions, "kernel");
        assert_eq!(k.kind, CallKind::TailJump, "{f}");
        assert_eq!(
            k.args[0],
            ArgValue::Param {
                reg: Reg::Rdi,
                index: 0
            }
        );
        assert_eq!(
            connect_in(&calls, &functions, "calls_helper").kind,
            CallKind::TailJump,
            "{f}"
        );
        assert_eq!(
            connect_in(&calls, &functions, "loop").kind,
            CallKind::Call,
            "{f}"
        );
    }
    // clang -O2's hoisted GOT load: `mov 0x0(%rip),%r15` (+ REX_GOTPCRELX) at .text+0x30, then
    // `call *%r15` at .text+0x47 (.text is at file offset 0x40): the site is the call.
    let (calls, functions, _) = outcome("calls-noplt-clang-O2.o");
    assert_eq!(connect_in(&calls, &functions, "loop").addr, 0x87);
}

#[test]
fn got_relocations_that_name_no_call_are_gaps() {
    let (calls, _, gaps) = outcome("gotrel.o");
    assert!(calls.is_empty(), "{calls:#?}");
    // `g` is at file offset 0x40: the fields are at 0x42, 0x49, 0x50, 0x57.
    assert_eq!(
        gaps,
        [
            "code: connect: GOT reference +0 at 0x49",
            "code: connect: GOT reference +4 at 0x42",
            "code: connect: PLT32 off a branch at 0x57",
            "code: connect: address taken at 0x50, not traced to a call",
        ],
        "the call off its entry, the lea of the entry, the PLT32 lea, the cmp; extern_data is no \
         target"
    );
}

#[test]
fn linked_files_resolve_plt_pltsec_and_got() {
    for (f, via) in [
        ("net-plt-gcc.so", ImportVia::Plt),
        ("net-plt-clang.so", ImportVia::Plt),
        ("net-pltsec-gcc.so", ImportVia::PltSec),
        ("net-noplt-gcc.so", ImportVia::Got),
        ("net-noplt-clang.so", ImportVia::Got),
    ] {
        let (calls, functions, gaps) = outcome(f);
        assert_eq!(gaps, Vec::<String>::new(), "{f}");
        assert_eq!(calls.len(), 2, "{f}: {calls:#?}");
        assert!(
            calls.iter().all(|c| import(c) == Some(("connect", via))),
            "{f}: {calls:#?}"
        );
        let k = connect_in(&calls, &functions, "kernel");
        assert_eq!(k.kind, CallKind::Call, "{f}");
        assert_eq!(
            k.args,
            [
                ArgValue::Param {
                    reg: Reg::Rdi,
                    index: 0
                },
                c0(Reg::Rsi),
                c0(Reg::Rdx)
            ],
            "kernel(fd): {f}"
        );
        assert_eq!(
            connect_in(&calls, &functions, "looped").kind,
            CallKind::Call,
            "{f}"
        );
    }
    // README: `main` tail-jumps, `jmp <connect@plt>`.
    for f in ["net-pie", "net-nopie"] {
        let (calls, functions, gaps) = outcome(f);
        assert_eq!(gaps, Vec::<String>::new(), "{f}");
        assert_eq!(calls.len(), 1, "{f}: {calls:#?}");
        let m = connect_in(&calls, &functions, "main");
        assert_eq!(import(m), Some(("connect", ImportVia::Plt)), "{f}");
        assert_eq!(m.kind, CallKind::TailJump, "{f}");
    }
}

#[test]
fn an_address_taken_is_partial_and_data_only_is_complete() {
    // net-addr.so: `mov slot(%rip),%rdi` at 0x1110 (its disp32 at 0x1113), passed to `keep`.
    // net-nopie-addr: `mov $<connect@plt>,%edi` at 0x401040 (its imm32 at 0x401041).
    for (f, at) in [("net-addr.so", 0x1113), ("net-nopie-addr", 0x401041)] {
        let (calls, _, gaps) = outcome(f);
        assert!(connects(&calls).is_empty(), "{f}");
        assert_eq!(
            gaps,
            [format!(
                "code: connect: address taken at {at:#x}, not traced to a call"
            )],
            "{f}"
        );
    }
    let (calls, _, gaps) = outcome("net-data.so");
    assert!(calls.is_empty() && gaps.is_empty(), "{gaps:#?}");
}

#[test]
fn code_without_fdes_is_not_analyzed() {
    let (calls, _, gaps) = outcome("net-noeh.so");
    assert!(calls.is_empty());
    assert_eq!(
        gaps,
        [
            "code: connect referenced at 0x1119 outside any FDE",
            "code: connect referenced at 0x114a outside any FDE"
        ],
        "kernel's and looped's calls"
    );
}

#[test]
fn dlsym_names_a_constant_string_or_nothing() {
    let (calls, functions, gaps) = outcome("dl.so");
    assert_eq!(gaps, Vec::<String>::new());
    let dlsym = calls_of(&calls, "dlsym");
    assert_eq!(dlsym.len(), 2, "{dlsym:#?}");
    assert_eq!(calls.len(), 2);
    let in_fn = |name: &str| {
        let f = named(&functions, name);
        *dlsym.iter().find(|c| c.caller == f.id).unwrap()
    };
    // README: `score` tail-jumps to dlsym@plt.
    let score = in_fn("score");
    assert_eq!(score.kind, CallKind::TailJump);
    assert!(
        matches!(&score.args[1], ArgValue::ConstStr { value, .. } if value.as_str() == Some("ggml_backend_score")),
        "{:?}",
        score.args[1]
    );
    // README: `byname`'s buffer is a register copy of rsp (`mov %rsp,%r10` … `mov %r10,%rsi`),
    // with no load: Unknown(NotModeled) (R-d), not spec §8.1's Unknown(FromMemory).
    let byname = in_fn("byname");
    assert_eq!(byname.kind, CallKind::Call);
    assert_eq!(
        byname.args[1],
        ArgValue::Unknown {
            reg: Reg::Rsi,
            reason: ValueUnknown::NotModeled
        }
    );
}

#[test]
fn own_exports_via_plt_and_direct() {
    let (calls, _, gaps) = outcome("ownplt.so");
    assert_eq!(gaps, Vec::<String>::new());
    let c = connects(&calls);
    assert_eq!(c.len(), 1);
    // README: a tail jump, and arg 0 is `Low(ReturnOf(helper), 32)`.
    assert_eq!(c[0].kind, CallKind::TailJump);
    let ArgValue::Low {
        value, bits: 32, ..
    } = &c[0].args[0]
    else {
        panic!("{:?}", c[0].args[0])
    };
    let ArgValue::ReturnOf { call, .. } = &**value else {
        panic!("{value:?}")
    };
    let helper = calls.iter().find(|x| &x.id == call).unwrap();
    assert!(
        matches!(&helper.target, CallTarget::OwnExportViaPlt { symbol, entry: 0x1120 } if symbol.as_str() == Some("helper")),
        "{:?}",
        helper.target
    );
    assert_eq!(helper.args.len(), 6, "an own export may read all six");

    let (calls, _, gaps) = outcome("ownplt-direct.so");
    assert_eq!(gaps, Vec::<String>::new());
    let c = connects(&calls);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].kind, CallKind::TailJump);
    assert!(
        low_return_of_helper(&calls, &c[0].args[0]),
        "{:?}",
        c[0].args[0]
    );
    assert!(calls.iter().any(|x| matches!(&x.target,
        CallTarget::Internal { entry: 0x1110, export_name: Some(n) } if n.as_str() == Some("helper"))));
    // README: gcc zeroes %esi and %edx before `call <helper>` (it knows helper keeps them); the
    // SysV rule (§4.7) clobbers them at the call all the same.
    for (k, reg) in [(1, Reg::Rsi), (2, Reg::Rdx)] {
        assert_eq!(
            c[0].args[k],
            ArgValue::Unknown {
                reg,
                reason: ValueUnknown::ClobberedByCall
            }
        );
    }
}

#[test]
fn value_forms() {
    let (calls, functions, gaps) = outcome("values.so");
    assert_eq!(gaps, Vec::<String>::new());
    assert_eq!(functions.len(), 7, "every CFI function but local_helper");
    let arg = |f: &str, k: usize| connect_in(&calls, &functions, f).args[k].clone();
    let ArgValue::ReturnOf { call, .. } = arg("getenv_shape", 0) else {
        panic!("{:?}", arg("getenv_shape", 0))
    };
    let getenv = calls.iter().find(|c| c.id == call).unwrap();
    assert_eq!(import(getenv), Some(("getenv", ImportVia::Plt)));
    assert!(
        matches!(&getenv.args[..], [ArgValue::ConstStr { value, .. }] if value.as_str() == Some("OLLAMA_HOST"))
    );
    assert!(
        matches!(arg("merge_shape", 0), ArgValue::Set { ref members, .. } if members.len() == 2)
    );
    assert_eq!(
        arg("saved_rbx", 0),
        ArgValue::Param {
            reg: Reg::Rdi,
            index: 0
        }
    );
    assert_eq!(
        arg("saved_rsi", 0),
        ArgValue::Unknown {
            reg: Reg::Rdi,
            reason: ValueUnknown::ClobberedByCall
        }
    );
    let ArgValue::Load {
        base,
        offset: 24,
        width: 64,
        ..
    } = arg("loads", 0)
    else {
        panic!("{:?}", arg("loads", 0))
    };
    assert!(matches!(*base, ArgValue::Load { offset: 16, .. }));
    assert_eq!(
        arg("loads", 2),
        ArgValue::Unknown {
            reg: Reg::Rdx,
            reason: ValueUnknown::NotModeled
        },
        "depth 4"
    );
    assert!(matches!(
        arg("loads", 1),
        ArgValue::Load {
            offset: 5,
            width: 8,
            ..
        }
    ));
    assert!(matches!(arg("partial", 0), ArgValue::Low { bits: 32, .. }));
    assert_eq!(
        arg("partial", 1),
        ArgValue::Unknown {
            reg: Reg::Rsi,
            reason: ValueUnknown::NotModeled
        }
    );
    assert!(matches!(arg("partial", 2), ArgValue::Low { bits: 8, .. }));
    assert!(
        matches!(arg("strs", 0), ArgValue::ConstStr { ref value, .. } if value.as_str() == Some("OLLAMA_HOST"))
    );
    assert_eq!(
        arg("strs", 1),
        ArgValue::ConstInt {
            reg: Reg::Rsi,
            value: 0x2000
        }
    );
    assert!(
        matches!(arg("strs", 2), ArgValue::ConstInt { .. }),
        "a writable address is not a string"
    );
}

#[test]
fn cfg_cases() {
    let (calls, functions, gaps) = outcome("cfg.so");
    assert_eq!(
        gaps,
        [
            "code: connect referenced at 0x1039: not on an instruction decoded from 0x1030",
            "code: connect referenced at 0x106d: function at 0x105d: branch into an instruction \
             at 0x1062",
            "code: connect referenced at 0x1079 outside any FDE",
        ],
        "jumptable, into_insn, noeh_code"
    );
    assert_eq!(calls.len(), 2, "{calls:#?}");
    let _ = connect_in(&calls, &functions, "after_noreturn");
    // `hot`'s `jne` leaves its FDE for `cold_part`'s: an exit (R-b); `cold_part` is analyzed
    // from its own FDE.
    let _ = connect_in(&calls, &functions, "cold_part");
}

#[test]
fn a_text_relocation_is_a_gap() {
    let (calls, _, gaps) = outcome("textrel.so");
    assert!(calls.is_empty());
    assert_eq!(gaps, ["code: connect: text relocation at 0x1002"]);
}

/// A copy of `name` in a temp dir, with the section header of section `section` patched by
/// `f(header bytes)`.
fn patched_section(
    name: &str,
    section: &str,
    f: impl FnOnce(&mut [u8]),
) -> (tempfile::TempDir, PathBuf) {
    use object::{Object, ObjectSection};
    let mut bytes = std::fs::read(fixture(name)).unwrap();
    let index = object::File::parse(&*bytes)
        .unwrap()
        .section_by_name(section)
        .unwrap()
        .index()
        .0;
    let shoff = u64::from_le_bytes(bytes[0x28..0x30].try_into().unwrap()) as usize;
    let shentsize = u16::from_le_bytes(bytes[0x3a..0x3c].try_into().unwrap()) as usize;
    let at = shoff + index * shentsize;
    f(&mut bytes[at..at + shentsize]);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    (dir, path)
}

/// [`patched_section`] of `.dynsym`. The loader never reads section headers: glibc still loads
/// such a file (plan review P1-1).
fn patched_dynsym(name: &str, f: impl FnOnce(&mut [u8])) -> (tempfile::TempDir, PathBuf) {
    patched_section(name, ".dynsym", f)
}

const NOT_LISTED: &str =
    "code: the dynamic symbols the loader binds through cannot be read; imports not listed";

#[test]
fn unreadable_dynamic_symbols_are_a_gap_not_complete() {
    // .dynsym's type changed to SHT_PROGBITS: DT_SYMTAB remains, no SHT_DYNSYM section.
    let (_dir, path) = patched_dynsym("net-plt-gcc.so", |h| {
        h[4..8].copy_from_slice(&1u32.to_le_bytes())
    });
    let (calls, _, gaps) = outcome_at(&path, CodeBudgets::default());
    assert!(calls.is_empty());
    assert_eq!(gaps, [NOT_LISTED]);
}

#[test]
fn dynamic_symbols_not_where_the_loader_reads_are_a_gap() {
    // .dynsym's sh_addr moved: loader_agrees records `symbols: .dynsym … DT_SYMTAB`.
    let (_dir, path) = patched_dynsym("net-plt-gcc.so", |h| {
        let addr = u64::from_le_bytes(h[0x10..0x18].try_into().unwrap());
        h[0x10..0x18].copy_from_slice(&(addr + 0x10).to_le_bytes());
    });
    let slice = slice_at(&path, with_code(CodeBudgets::default()));
    assert!(
        slice
            .gaps
            .iter()
            .any(|g| g.starts_with("symbols: .dynsym ") && g.ends_with(" DT_SYMTAB")),
        "{:#?}",
        slice.gaps
    );
    let (calls, _, gaps) = analyzed("patched", slice);
    assert!(calls.is_empty());
    assert_eq!(gaps, [NOT_LISTED]);
}

#[test]
fn a_section_name_the_code_step_cannot_read_is_its_gap() {
    // `.fini`'s name points past `.shstrtab`: the container records it while it looks for
    // `.comment` and `.go.buildinfo`, and the code step again while it looks for `.plt.sec`
    // and `.eh_frame`. The code's is its own gap (R-h), and the container's list is the same
    // with or without code.
    let (_dir, path) = patched_section("net-plt-gcc.so", ".fini", |h| {
        h[0..4].copy_from_slice(&u32::MAX.to_le_bytes())
    });
    const BAD: &str = "malformed: section names: a name past its string table";
    let without = slice_at(&path, BinaryBudgets::default());
    assert!(without.gaps.iter().any(|g| g == BAD), "{:#?}", without.gaps);
    let mut with = slice_at(&path, with_code(CodeBudgets::default()));
    let (calls, _, gaps) = analyzed("patched", with.clone());
    assert_eq!(connects(&calls).len(), 2);
    assert_eq!(gaps, [format!("code: {BAD}")]);
    with.code = None;
    assert_eq!(with, without);
}

#[test]
fn references_limit_with_the_defaults() {
    let (calls, _, gaps) = outcome("many.so");
    assert!(calls.is_empty());
    assert!(
        gaps.contains(&"code: references limit 65536 reached".to_string()),
        "{:?}",
        &gaps[..3]
    );
    assert!(gaps.contains(
        &"code: connect referenced at 0x1021: not confirmed: a limit was reached".to_string()
    ));
    assert!(gaps.len() <= 256 + 2, "{}", gaps.len());
    assert!(gaps.iter().any(|g| g.ends_with("more gaps not listed")));
}

#[test]
fn gap_list_limit_with_many_unexplained_references() {
    let (calls, _, gaps) = outcome_with(
        "many-noeh.so",
        CodeBudgets {
            references: 100_000,
            ..CodeBudgets::default()
        },
    );
    assert!(calls.is_empty());
    assert!(gaps.len() <= 256 + 1, "{}", gaps.len());
    // 70,000 references, each outside any FDE: 256 listed, the rest counted.
    assert!(
        gaps.contains(&"code: 69744 more gaps not listed".to_string()),
        "{:?}",
        &gaps[..3]
    );
    assert!(
        !gaps.iter().any(|g| g.contains("limit")),
        "no limit reached"
    );
}

#[test]
fn call_site_limit_drops_the_function() {
    let (calls, functions, gaps) = outcome_with(
        "many.so",
        CodeBudgets {
            references: 100_000,
            ..CodeBudgets::default()
        },
    );
    assert!(
        calls.is_empty() && functions.is_empty(),
        "70,000 calls in one function exceed 65,536"
    );
    assert!(gaps.contains(&"code: call-site limit 65536 reached".to_string()));
    assert!(gaps.contains(
        &"code: connect referenced at 0x1021: not confirmed: a limit was reached".to_string()
    ));
}

#[test]
fn byte_budget_is_a_gap() {
    let slice = slice_at(
        &fixture("values.so"),
        with_code(CodeBudgets {
            bytes: 64,
            ..CodeBudgets::default()
        }),
    );
    let Some(CodeOutcome::Analyzed {
        call_sites,
        gaps,
        budget,
        ..
    }) = slice.code
    else {
        panic!("{:?}", slice.code)
    };
    assert!(call_sites.is_empty());
    assert!(
        gaps.contains(&"binary_code_bytes: 64 exceeded".to_string()),
        "{gaps:#?}"
    );
    assert_eq!(budget.budget, "binary_code_bytes");
    assert_eq!(budget.limit, 64);
    assert!(budget.used <= 64);
}

#[test]
fn non_x86_64_is_unsupported() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/elf/libdata-aarch64.so");
    let slice = slice_at(&path, with_code(CodeBudgets::default()));
    assert_eq!(slice.code, Some(CodeOutcome::Unsupported));
}

#[test]
fn a_mach_o_slice_is_unsupported_when_code_is_asked_for() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/macho/hello-universal");
    let slices = try_slices_at(&path, with_code(CodeBudgets::default())).unwrap();
    assert_eq!(slices.len(), 2);
    for slice in slices {
        assert_eq!(
            slice.code,
            Some(CodeOutcome::Unsupported),
            "{}",
            slice.offset
        );
    }
    for slice in try_slices_at(&path, BinaryBudgets::default()).unwrap() {
        assert_eq!(slice.code, None);
    }
}

#[test]
fn a_file_without_a_target_has_nothing_to_search() {
    // Spec §4.4: Complete, with zero bytes scanned. No image is built: no `.eh_frame`, no PLT,
    // and none of their gaps.
    for path in [
        fixture("clean_kernel-clang-O0.o"),
        fixture("clean_kernel-gcc-O2.o"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/elf/exe-nopie"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/elf/libsym64.so"),
    ] {
        assert_eq!(
            slice_at(&path, with_code(CodeBudgets::default())).code,
            Some(CodeOutcome::Analyzed {
                functions: vec![],
                call_sites: vec![],
                gaps: vec![],
                budget: BudgetUse {
                    budget: "binary_code_bytes".to_string(),
                    used: 0,
                    limit: CodeBudgets::default().bytes,
                },
            }),
            "{}",
            path.display()
        );
    }
}

#[test]
fn a_relocation_type_not_modeled_against_a_target_is_named() {
    // suspicious_kernel-gcc-O2.o's one `.rela.text` entry (PLT32 connect at .text+0xe, the call's
    // rel32 at 0x4e) patched to R_X86_64_PC8 (15) at .text+0xf, inside the rel32: §4.4's gap
    // names the type, whatever the field.
    use object::{Object, ObjectSection};
    let mut bytes = std::fs::read(fixture("suspicious_kernel-gcc-O2.o")).unwrap();
    let (at, size) = object::File::parse(&*bytes)
        .unwrap()
        .section_by_name(".rela.text")
        .unwrap()
        .file_range()
        .unwrap();
    assert_eq!(size, 24, "one entry");
    let at = at as usize;
    let r_offset = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    assert_eq!(r_offset, 0xe);
    assert_eq!(bytes[at + 8..at + 12], 4u32.to_le_bytes(), "PLT32");
    bytes[at..at + 8].copy_from_slice(&(r_offset + 1).to_le_bytes());
    bytes[at + 8..at + 12].copy_from_slice(&15u32.to_le_bytes());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pc8.o");
    std::fs::write(&path, bytes).unwrap();
    let (calls, _, gaps) = outcome_at(&path, CodeBudgets::default());
    assert!(calls.is_empty(), "{calls:#?}");
    assert_eq!(gaps, ["code: connect: relocation type 15 at 0x4f"]);
}

#[test]
fn without_a_code_request_there_is_no_code_outcome() {
    assert_eq!(
        slice_at(&fixture("net-plt-gcc.so"), BinaryBudgets::default()).code,
        None
    );
}

#[test]
fn an_elf_header_the_parse_cannot_read_is_a_code_gap() {
    // A parse budget of one byte: not even the identification is read.
    let budgets = BinaryBudgets {
        parse_bytes: 1,
        ..with_code(CodeBudgets::default())
    };
    let slice = slice_at(&fixture("net-plt-gcc.so"), budgets);
    assert!(slice
        .gaps
        .contains(&"binary_parse_bytes: 1 exceeded".to_string()));
    assert_eq!(
        slice.code,
        Some(CodeOutcome::Analyzed {
            functions: vec![],
            call_sites: vec![],
            gaps: vec!["code: no readable ELF header".to_string()],
            budget: BudgetUse {
                budget: "binary_code_bytes".to_string(),
                used: 0,
                limit: CodeBudgets::default().bytes,
            },
        })
    );
}

/// The parse-budget gaps of a slice: the container's, and the code's.
fn parse_budget_gaps(slice: &ParsedSlice) -> (bool, bool) {
    let container = slice
        .gaps
        .iter()
        .any(|g| g.starts_with("binary_parse_bytes: "));
    let code = match &slice.code {
        Some(CodeOutcome::Analyzed { gaps, .. }) => gaps
            .iter()
            .any(|g| g == "code: binary_parse_bytes exceeded"),
        _ => false,
    };
    (container, code)
}

/// The smallest `binary_parse_bytes` for which `refused` is false, by bisection: `refused` holds
/// below it (a read that fits a budget fits a larger one, and the reads are the same).
fn smallest_budget(refused: impl Fn(u64) -> bool) -> u64 {
    let (mut lo, mut hi) = (0u64, 64 << 20);
    assert!(refused(lo) && !refused(hi));
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if refused(mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    hi
}

#[test]
fn a_parse_budget_refusal_in_the_code_step_is_the_codes_gap() {
    // The code step reads section names the container did not (`.plt.sec`, `.eh_frame`) through
    // the parse cache. With just the container's bytes, the code step is refused: its gap, and
    // the container's facts and gaps are those of a parse without code (R-h).
    let path = fixture("net-plt-gcc.so");
    let at = |parse_bytes: u64, code: Option<CodeBudgets>| {
        slice_at(
            &path,
            BinaryBudgets {
                parse_bytes,
                code,
                ..BinaryBudgets::default()
            },
        )
    };
    let container = smallest_budget(|b| parse_budget_gaps(&at(b, None)).0);
    let mut tight = at(container, Some(CodeBudgets::default()));
    assert_eq!(parse_budget_gaps(&tight), (false, true));
    let (calls, _, gaps) = analyzed("tight", tight.clone());
    assert!(calls.is_empty(), "{calls:#?}");
    assert_eq!(
        gaps.iter()
            .filter(|g| g.contains(" referenced at "))
            .count(),
        2,
        "both calls unexplained: {gaps:#?}"
    );
    tight.code = None;
    assert_eq!(tight, at(container, None));
    // With the code step's bytes too, its calls and gaps are the full analysis's. (Names may
    // still be left out there: they are read last, and cost no coverage.)
    let all = smallest_budget(|b| {
        let (a, b) = parse_budget_gaps(&at(b, Some(CodeBudgets::default())));
        a || b
    });
    assert!(all > container);
    let (calls, functions, gaps) = analyzed("all", at(all, Some(CodeBudgets::default())));
    let (full_calls, full_functions, full_gaps) = outcome("net-plt-gcc.so");
    assert_eq!((calls, gaps), (full_calls, full_gaps));
    let entries = |fs: &[Function]| fs.iter().map(|f| (f.entry, f.end)).collect::<Vec<_>>();
    assert_eq!(entries(&functions), entries(&full_functions));
}

#[test]
fn names_left_out_for_the_parse_budget_cost_no_coverage() {
    // With exactly the bytes the analysis needs before names, `.symtab` (read only for names) is
    // refused: `cold_part`, a local symbol, has no name, and nothing else changes.
    let path = fixture("cfg.so");
    let at = |parse_bytes: u64| {
        slice_at(
            &path,
            BinaryBudgets {
                parse_bytes,
                ..with_code(CodeBudgets::default())
            },
        )
    };
    let tight = smallest_budget(|b| {
        let (a, b) = parse_budget_gaps(&at(b));
        a || b
    });
    let (calls, functions, gaps) = analyzed("tight", at(tight));
    let (all_calls, all_functions, all_gaps) = outcome("cfg.so");
    assert_eq!((&calls, &gaps), (&all_calls, &all_gaps));
    assert_eq!(named(&all_functions, "cold_part").names.len(), 1);
    let names = |fs: &[Function]| -> Vec<Vec<String>> {
        fs.iter()
            .map(|f| {
                f.names
                    .iter()
                    .map(|n| n.as_str().unwrap().to_string())
                    .collect()
            })
            .collect()
    };
    assert_eq!(
        names(&functions),
        [vec!["after_noreturn".to_string()], vec![]],
        "after_noreturn is in .dynsym; cold_part only in .symtab"
    );
    assert_eq!(names(&all_functions)[1], ["cold_part"]);
}

/// The binary files of a fixture directory.
fn binaries(dir: &str) -> Vec<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(dir);
    let mut out: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            let name = p.file_name().unwrap().to_str().unwrap();
            !(name.contains(".objdump")
                || name.contains(".readelf")
                || name.contains(".otool")
                || name.ends_with(".c")
                || name.ends_with(".S")
                || name.ends_with(".md")
                || name.ends_with(".sh")
                || name.ends_with(".hex")
                || name.ends_with(".tbd")
                || name == "COMPILERS"
                || name == "SHA256SUMS")
        })
        .collect();
    out.sort();
    out
}

#[test]
fn a_code_request_never_changes_the_container() {
    // R-h: every slice of every fixture has the same container facts and gaps (and the rest of
    // the slice) with and without a code request.
    let mut seen = 0;
    for path in binaries("tests/fixtures/code")
        .into_iter()
        .chain(binaries("tests/fixtures/elf"))
        .chain(binaries("tests/fixtures/macho"))
    {
        let Some(without) = try_slices_at(&path, BinaryBudgets::default()) else {
            continue;
        };
        let with = try_slices_at(&path, with_code(CodeBudgets::default())).unwrap();
        assert_eq!(with.len(), without.len(), "{}", path.display());
        assert!(!with.is_empty(), "{}", path.display());
        for (mut w, wo) in with.into_iter().zip(without) {
            assert!(w.code.is_some(), "{}", path.display());
            assert!(wo.code.is_none());
            w.code = None;
            assert_eq!(w, wo, "{} at {}", path.display(), wo.offset);
            seen += 1;
        }
    }
    // 28 code fixtures, 7 ELF fixtures, and hello-universal's two slices.
    assert!(seen >= 37, "{seen} slices");
}
