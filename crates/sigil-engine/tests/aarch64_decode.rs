//! Compile the exact private adapter, without making a public decoder API or enabling dispatch.
#[allow(dead_code)]
#[path = "../src/code/aarch64/decode.rs"]
mod decode;

use decode::*;
#[path = "support/aarch64_corpus.rs"]
mod corpus;

fn reg(name: RegisterName, width: Width) -> Register {
    Register { name, width }
}

#[test]
fn bl_pc_relative_edges() {
    for (word, pc, flow) in [
        (0x94000000, 0, Flow::CallDirect(0)),
        (0x94000001, 0x1000, Flow::CallDirect(0x1004)),
        (0x95ffffff, 0, Flow::CallDirect(0x7fffffc)),
        (0x96000000, 0x8000000, Flow::CallDirect(0)),
        (0x97ffffff, 4, Flow::CallDirect(0)),
        (0x14000000, 0, Flow::JumpDirect(0)),
        (0x15ffffff, 0, Flow::JumpDirect(0x7fffffc)),
        (0x16000000, 0x8000000, Flow::JumpDirect(0)),
    ] {
        assert_eq!(decode_a64(word, pc).map(|i| i.flow), Ok(flow), "{word:08x}");
    }
}

#[test]
fn branch_register_and_conditional_forms() {
    for (word, pc, flow) in [
        (0xd61f0200, 0x1000, Flow::JumpRegister(16)),
        (0xd63f0220, 0x1000, Flow::CallRegister(17)),
        (0xd65f03c0, 0x1000, Flow::Return),
        (0x54000040, 0x1000, Flow::Conditional(0x1008)),
        (0x54ffffe1, 0x1000, Flow::Conditional(0xffc)),
        (0x547fffe0, 0x100000, Flow::Conditional(0x1ffffc)),
        (0x54800000, 0x100000, Flow::Conditional(0)),
        (0x34000040, 0x1000, Flow::Conditional(0x1008)),
        (0xb5ffffe0, 0x1000, Flow::Conditional(0xffc)),
        (0x36000040, 0x1000, Flow::Conditional(0x1008)),
        (0xb7ffffe0, 0x1000, Flow::Conditional(0xffc)),
        (0x3603ffe0, 0x8000, Flow::Conditional(0xfffc)),
        (0x36040000, 0x8000, Flow::Conditional(0)),
    ] {
        assert_eq!(decode_a64(word, pc).map(|i| i.flow), Ok(flow), "{word:08x}");
    }
}

#[test]
fn addresses_never_wrap_or_accept_unaligned_pcs() {
    for word in [
        0x94000001, 0x14000001, 0x54000020, 0x34000020, 0x36000020, 0x10000020,
    ] {
        assert_eq!(
            decode_a64(word, u64::MAX - 3),
            Err(DecodeGap::AddressOverflow)
        );
    }
    for word in [
        0x97ffffff, 0x17ffffff, 0x54ffffe0, 0x34ffffe0, 0x3607ffe0, 0x10ffffe0,
    ] {
        assert_eq!(decode_a64(word, 0), Err(DecodeGap::AddressOverflow));
    }
    assert_eq!(decode_a64(0xd503201f, 2), Err(DecodeGap::Unaligned));
    assert_eq!(
        decode_a64(0x90000000, 0x1ffc).unwrap().operation,
        Operation::Address {
            dst: reg(RegisterName::Gpr(0), Width::X),
            address: 0x1000
        }
    );
}

#[test]
fn register_31_depends_on_operand() {
    let zero = decode_a64(0xaa1f03e0, 0).unwrap();
    assert_eq!(
        zero.operation,
        Operation::Copy {
            dst: reg(RegisterName::Gpr(0), Width::X),
            src: reg(RegisterName::Zero, Width::X)
        }
    );
    let load = decode_a64(0xf94003e0, 0).unwrap();
    assert_eq!(
        load.operation,
        Operation::Memory {
            load: true,
            regs: [Some(reg(RegisterName::Gpr(0), Width::X)), None],
            base: reg(RegisterName::Sp, Width::X),
            offset: 0,
            mode: AddressMode::Offset
        }
    );
    let add = decode_a64(0x110007ff, 0).unwrap();
    assert_eq!(add.effects.writes[0], Some(reg(RegisterName::Sp, Width::W)));
    assert_eq!(decode_a64(0xd280003f, 0).unwrap().effects.writes, [None; 3]);
}

#[test]
fn adrp_uses_page_base_and_checked_signed_displacement() {
    for (word, pc, address) in [
        (0xb0000000, 0xffc, 0x1000),
        (0xb0000000, 0x1000, 0x2000),
        (0xf0ffffe0, 0x1000, 0),
        (0xf0ffffe0, 0x1ffc, 0),
        (0xf07fffe0, 0, 0xfffff000),
        (0x90800000, 0x1_0000_0000, 0),
    ] {
        assert_eq!(
            decode_a64(word, pc).unwrap().operation,
            Operation::Address {
                dst: reg(RegisterName::Gpr(0), Width::X),
                address
            }
        );
    }
    assert_eq!(
        decode_a64(0xf0ffffe0, 0xffc),
        Err(DecodeGap::AddressOverflow)
    );
    assert_eq!(
        decode_a64(0xb0000000, u64::MAX - 3),
        Err(DecodeGap::AddressOverflow)
    );
}

#[test]
fn all_load_and_writeback_destinations_are_exposed() {
    // ldp x0,x1,[sp],#16; ldp w0,w1,[sp,#-8]!; stp x0,x1,[sp,#-16]!
    for (word, load, width, offset, mode) in [
        (0xa8c107e0, true, Width::X, 16, AddressMode::PostIndex),
        (0x29ff07e0, true, Width::W, -8, AddressMode::PreIndex),
        (0xa9bf07e0, false, Width::X, -16, AddressMode::PreIndex),
    ] {
        let ins = decode_a64(word, 0).unwrap();
        let r0 = reg(RegisterName::Gpr(0), width);
        let r1 = reg(RegisterName::Gpr(1), width);
        let sp = reg(RegisterName::Sp, Width::X);
        assert_eq!(
            ins.operation,
            Operation::Memory {
                load,
                regs: [Some(r0), Some(r1)],
                base: sp,
                offset,
                mode
            }
        );
        assert_eq!(
            ins.effects.writes,
            if load {
                [Some(r0), Some(r1), Some(sp)]
            } else {
                [None, None, Some(sp)]
            }
        );
    }
}

#[test]
fn reserved_pac_and_unmodeled_forms_are_gaps() {
    for word in [
        0, 15, 0xffffffff, 0xd503233f, 0xd503245f, 0xd65f0bff, 0x18000050, 0x54ffffee, 0x54000010,
        0xd61f03e0, 0xd63f03e0, 0xd65f03e0, 0x52c00000, 0x12e00000, 0x32800000, 0x2a4103e0,
        0x2a0107e0, 0xb1000400, 0x91800000, 0x28400440, 0xa9400000, 0xa9c00400,
    ] {
        assert_eq!(
            decode_a64(word, 0x1000),
            Err(DecodeGap::Unsupported),
            "{word:08x}"
        );
    }
}

#[test]
fn million_word_production_adapter_gate() {
    let begin = std::time::Instant::now();
    let mut count = 0;
    let mut accepted = 0;
    corpus::corpus(|word| {
        count += 1;
        match decode_a64(word, 0x1_0000_0000) {
            Ok(ins) => {
                accepted += 1;
                assert_eq!(ins.word, word);
            }
            Err(DecodeGap::Unsupported) => (),
            other => panic!("adapter inconsistency for {word:08x}: {other:?}"),
        }
        for pc in [0, 4, 0xffc, 0x1000, u64::MAX - 3, u64::MAX] {
            assert_ne!(
                decode_a64(word, pc),
                Err(DecodeGap::Inconsistent),
                "{word:08x} at {pc:#x}"
            );
        }
    });
    assert_eq!(count, 1_103_289);
    assert_eq!(accepted, 179_358);
    eprintln!(
        "ADR-017 seed=0x48c0ffee visits={count} eligible={accepted} errors=0 elapsed={:?}",
        begin.elapsed()
    );
}

#[test]
fn committed_llvm_branch_destinations() {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/code-aarch64");
    let mut checked = 0;
    for path in std::fs::read_dir(directory)
        .unwrap()
        .map(|e| e.unwrap().path())
    {
        if path.extension().is_none_or(|ext| ext != "objdump") {
            continue;
        }
        for line in std::fs::read_to_string(&path).unwrap().lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 4 || !fields[0].ends_with(':') || fields[1].len() != 8 {
                continue;
            }
            let Ok(pc) = u64::from_str_radix(fields[0].trim_end_matches(':'), 16) else {
                continue;
            };
            let word = u32::from_str_radix(fields[1], 16).unwrap();
            let op = fields[2];
            if op != "bl"
                && op != "b"
                && !op.starts_with("b.")
                && !matches!(op, "cbz" | "cbnz" | "tbz" | "tbnz")
            {
                continue;
            }
            let dest = fields.iter().skip(3).find(|s| s.starts_with("0x")).unwrap();
            let dest = u64::from_str_radix(dest.trim_start_matches("0x"), 16).unwrap();
            let expected = match op {
                "bl" => Flow::CallDirect(dest),
                "b" => Flow::JumpDirect(dest),
                _ => Flow::Conditional(dest),
            };
            assert_eq!(
                decode_a64(word, pc).unwrap().flow,
                expected,
                "{} {line}",
                path.display()
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 36,
        "independent fixture branches must actually be checked"
    );
}

fn json_reg(r: Register) -> serde_json::Value {
    let (n, role) = match r.name {
        RegisterName::Gpr(n) => (n, "reg"),
        RegisterName::Sp => (31, "sp"),
        RegisterName::Zero => (31, "zr"),
    };
    serde_json::json!(["r", if r.width == Width::X { 64 } else { 32 }, n, role])
}

fn oracle_semantics(ins: A64Insn) -> serde_json::Value {
    use serde_json::json;
    let op = match ins.operation {
        Operation::Control => match ins.flow {
            Flow::CallDirect(t) => json!(["call", t]),
            Flow::JumpDirect(t) => json!(["jump", t]),
            Flow::Conditional(t) => json!(["conditional", t]),
            Flow::Return => json!(["return"]),
            Flow::CallRegister(r) => json!(["call_register", r]),
            Flow::JumpRegister(r) => json!(["jump_register", r]),
            Flow::Next => panic!("control operation cannot fall through without a flow class"),
        },
        Operation::Nop => json!(["nop"]),
        Operation::Address { dst, address } => json!(["address", json_reg(dst), address]),
        Operation::WideMove {
            kind: WideMove::Keep,
            dst,
            imm,
            shift,
        } => json!(["movk", json_reg(dst), imm, shift]),
        Operation::WideMove {
            kind,
            dst,
            imm,
            shift,
        } => {
            let value = u64::from(imm) << shift;
            let value = if kind == WideMove::Not { !value } else { value };
            json!([
                "const",
                json_reg(dst),
                if dst.width == Width::W {
                    value & 0xffff_ffff
                } else {
                    value
                }
            ])
        }
        Operation::Copy { dst, src } => json!(["copy", json_reg(dst), json_reg(src)]),
        Operation::AddImmediate {
            dst,
            src,
            imm,
            subtract,
        } => json!([
            if subtract { "sub" } else { "add" },
            json_reg(dst),
            json_reg(src),
            imm
        ]),
        Operation::Memory {
            load,
            regs,
            base,
            offset,
            mode,
        } => json!([
            "memory",
            load,
            regs.map(|r| r.map(json_reg)),
            json_reg(base),
            offset,
            match mode {
                AddressMode::Offset => "offset",
                AddressMode::PreIndex => "pre",
                AddressMode::PostIndex => "post",
            }
        ]),
    };
    json!({"op": op, "reads": ins.effects.reads.map(|r| r.map(json_reg)), "writes": ins.effects.writes.map(|r| r.map(json_reg)), "flags": ins.effects.reads_flags})
}

/// Generate disassembler input only; no expected value comes from this adapter. The separate
/// Python oracle uses pinned LLVM/GNU text to derive operation AND every register effect.
#[test]
#[ignore = "manual independent oracle input; set SIGIL_A64_ORACLE"]
fn export_independent_oracle_input() {
    use std::io::Write;
    let mut words = std::collections::BTreeSet::new();
    corpus::corpus(|w| {
        if decode_a64(w, 0x1_0000_0000).is_ok() {
            words.insert(w);
        }
    });
    // Include every independently inventoried thin AArch64 fixture, including both same-name
    // dylibs. The generator adds their words and verifies fat identity through ADR-017 inventory.
    let output = std::env::var_os("SIGIL_A64_ORACLE").unwrap();
    let mut output = std::io::BufWriter::new(std::fs::File::create(output).unwrap());
    for word in words {
        writeln!(output, "{word:08x}").unwrap();
    }
}

#[test]
#[ignore = "manual LLVM/GNU differential gate; set SIGIL_A64_ORACLE"]
fn verify_independent_oracle() {
    use std::io::BufRead;
    let path = std::env::var_os("SIGIL_A64_ORACLE").unwrap();
    let file = std::io::BufReader::new(std::fs::File::open(path).unwrap());
    let mut count = 0;
    for line in file.lines() {
        let row: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        let word = row["word"].as_u64().unwrap() as u32;
        let pc = row["pc"].as_u64().unwrap();
        let ins = decode_a64(word, pc).unwrap();
        assert_eq!(
            oracle_semantics(ins),
            row["semantics"],
            "word {word:08x}, pc {pc:#x}"
        );
        count += 1;
    }
    assert!(count >= 178_917, "full accepted corpus must be compared");
    eprintln!("independent semantic/effect oracle: {count} rows, 0 mismatches");
}
