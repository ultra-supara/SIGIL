use super::*;
use crate::code::aarch64::{decode::decode_a64, decode_cfg, Proofs};
use crate::code::{CodeBudgets, Work};
use sigil_model::{code_abi::V1, Reg};
use std::io::Write;

fn c(bits: u64) -> Value {
    Value::Const {
        bits,
        address: false,
    }
}
fn addr(bits: u64) -> Value {
    Value::Const {
        bits,
        address: true,
    }
}
fn x(n: u8) -> Register {
    Register {
        name: RegisterName::Gpr(n),
        width: Width::X,
    }
}
fn file(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(bytes).unwrap();
    f
}
fn mapping(start: u64, end: u64) -> Mapping {
    Mapping {
        start,
        end,
        file_offset: Some(0),
        readable: true,
        writable: false,
        executable: false,
        relocated: false,
    }
}
fn state(words: &[u32]) -> A64State {
    let f = file(&[]);
    let mut reader = Reader::new(f.as_file(), 0, 0);
    let mut run = Run::new(CodeBudgets::default());
    let image = Image::new(SliceWindow { base: 0, len: 0 }, &[], &mut run).unwrap();
    let mut s = A64State::entry(CodeAbi::DarwinArm64).unwrap();
    for (i, w) in words.iter().enumerate() {
        let pc = 0x1000 + i as u64 * 4;
        step(
            &mut s,
            pc,
            &decode_a64(*w, pc).unwrap(),
            &image,
            &mut reader,
            &mut run,
        )
        .unwrap();
    }
    s
}
fn cfg(words: &[u32], run: &mut Run) -> Cfg {
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let candidates: Vec<_> = words
        .iter()
        .enumerate()
        .filter(|(_, w)| **w & 0xfc000000 == 0x94000000)
        .map(|(i, _)| 0x1000 + i as u64 * 4)
        .collect();
    assert!(run.charge(Work::References, candidates.len() as u64));
    decode_cfg(
        &bytes,
        0x1000,
        0x1000 + bytes.len() as u64,
        &Proofs {
            executable: &|a, b| a >= 0x1000 && b <= 0x9000,
            excluded: &|_, _| false,
            noreturn: &|_, _| false,
            candidates: &candidates,
        },
        run,
    )
    .unwrap()
}

#[test]
fn entry_and_register_31_depends_on_operand() {
    let s = A64State::entry(CodeAbi::DarwinArm64).unwrap();
    for n in 0..8 {
        assert_eq!(s.regs[n], Value::Param(n as u8));
    }
    assert_eq!(s.regs[18], Value::Unknown(Why::NotModeled));
    assert_eq!(s.sp, Value::Unknown(Why::NotModeled));
    let s = state(&[0xaa1f03e0, 0xb94003e1, 0xd280003f]);
    assert_eq!(s.regs[0], c(0));
    assert_eq!(s.regs[1], Value::Unknown(Why::FromMemory));
    assert_eq!(
        s.read(Register {
            name: RegisterName::Zero,
            width: Width::X
        }),
        c(0)
    );
    assert_eq!(s.sp, Value::Unknown(Why::NotModeled));
}

#[test]
fn wide_moves_and_w_write_zero_extends() {
    for width in [Width::W, Width::X] {
        let sf = if width == Width::X { 0x80000000 } else { 0 };
        let mask = if width == Width::X {
            u64::MAX
        } else {
            u32::MAX as u64
        };
        for shift in (0..if width == Width::X { 64 } else { 32 }).step_by(16) {
            let fields = ((shift / 16) << 21) | (0xabcd << 5);
            assert_eq!(
                state(&[sf | 0x52800000 | fields]).regs[0],
                c(0xabcd_u64 << shift)
            );
            assert_eq!(
                state(&[sf | 0x12800000 | fields]).regs[0],
                c(!(0xabcd_u64 << shift) & mask)
            );
            assert_eq!(
                state(&[0x92800000, sf | 0x72800000 | fields]).regs[0],
                c((!(0xffff_u64 << shift) | (0xabcd_u64 << shift)) & mask)
            );
        }
    }
    assert_eq!(state(&[0x92800000, 0x52800020]).regs[0], c(1));
    assert_eq!(state(&[0x92800000, 0x2a1f03e0, 0x52800022]).regs[0], c(0));
    assert_eq!(state(&[0x52800022]).regs[2], c(1));
    assert_eq!(state(&[0xd2800020, 0xaa0003e3]).regs[3], c(1));
}

#[test]
fn arithmetic_is_checked_and_addresses_cross_pages() {
    for (words, expected) in [
        (vec![0xd2800040, 0x91000400], c(3)),
        (vec![0xd2800040, 0xd1000400], c(1)),
        (
            vec![0x92800000, 0x91000400],
            Value::Unknown(Why::NotModeled),
        ),
        (
            vec![0xd2800000, 0xd1000400],
            Value::Unknown(Why::NotModeled),
        ),
        (
            vec![0x12800000, 0x11000400],
            Value::Unknown(Why::NotModeled),
        ),
        (vec![0x90000000, 0x91400400], addr(0x2000)),
        (vec![0x10000020], addr(0x1004)),
    ] {
        assert_eq!(state(&words).regs[0], expected, "{words:x?}");
    }
    assert_eq!(
        decode_a64(0xb0000000, 0x1ffc).unwrap().operation,
        super::super::decode::Operation::Address {
            dst: x(0),
            address: 0x2000
        }
    );
    assert!(decode_a64(0xb0000000, u64::MAX - 3).is_err());
}

#[test]
fn loads_have_exact_width_and_no_fabricated_stack() {
    let f = file(&[0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80]);
    let mut reader = Reader::new(f.as_file(), 8, 32);
    let mut run = Run::new(CodeBudgets::default());
    let maps = [mapping(0x2000, 0x2008)];
    let image = Image::new(SliceWindow { base: 0, len: 8 }, &maps, &mut run).unwrap();
    let mut s = A64State::entry(CodeAbi::ElfAarch64).unwrap();
    s.regs[1] = addr(0x2000);
    for (word, expected) in [
        (0xb9400020, 0xffff_fffe),
        (0xf9400020, 0x80ff_ffff_ffff_fffe),
    ] {
        step(
            &mut s,
            0x1000,
            &decode_a64(word, 0x1000).unwrap(),
            &image,
            &mut reader,
            &mut run,
        )
        .unwrap();
        assert_eq!(s.regs[0], c(expected));
    }
    assert_eq!(reader.used(), 12);
    let s = state(&[0xd28000e0, 0xf90003e0, 0xf94003e0]);
    assert_eq!(s.regs[0], Value::Unknown(Why::FromMemory));
    let s = state(&[0xf9400020]);
    assert_eq!(
        s.regs[0],
        Value::Load {
            base: Rc::new(Value::Param(1)),
            offset: 0,
            width: 64,
            site: 0x1000
        }
    );
    assert!(
        decode_a64(0xf8616820, 0x1000).is_err(),
        "indexed load excluded by Task 7"
    );
}

#[test]
fn call_and_veneer_clobber_and_pair_writeback() {
    let s = state(&[0xd28000f0, 0xd2800111, 0xaa0003f3, 0xaa0103fd, 0x94000001]);
    assert_eq!(s.regs[0], Value::Return(0x1010));
    for n in (1..18).chain([30]) {
        assert_eq!(s.regs[n], Value::Unknown(Why::ClobberedByCall));
    }
    assert_eq!(s.regs[19], Value::Param(0));
    assert_eq!(s.regs[29], Value::Param(1));
    assert_eq!(s.regs[18], Value::Unknown(Why::NotModeled));
    let s = state(&[0xaa0003f3, 0xa9bf53f3, 0x94000001, 0xa8c153f3]);
    assert_eq!(s.regs[19], Value::Unknown(Why::FromMemory));
    assert_eq!(s.regs[20], Value::Unknown(Why::FromMemory));
    assert!(matches!(s.sp, Value::Unknown(_)));
    let s = state(&[0xd2800202, 0xa8c10440]);
    assert_eq!(s.regs[0], Value::Unknown(Why::FromMemory));
    assert_eq!(s.regs[1], Value::Unknown(Why::FromMemory));
    assert_eq!(s.regs[2], c(32));
    assert_eq!(
        state(&[0xd2800032, 0xaa1203e0]).regs[0],
        Value::Unknown(Why::NotModeled)
    );
}

#[test]
fn join_keeps_four_and_five_becomes_merged_disagreeing() {
    assert_eq!(join(&c(0), &c(0)), c(0));
    let mut v = c(0);
    for n in 1..4 {
        v = join(&v, &c(n));
    }
    assert_eq!(v, Value::Set(vec![c(0), c(1), c(2), c(3)].into()));
    assert_eq!(join(&v, &c(4)), Value::Unknown(Why::MergedDisagreeing));
    assert_eq!(
        join(&Value::Unknown(Why::FromMemory), &c(1)),
        Value::Unknown(Why::MergedDisagreeing)
    );
}

#[test]
fn conditional_has_both_successors() {
    let f = file(&[]);
    let mut reader = Reader::new(f.as_file(), 0, 0);
    for right in [0, 1] {
        let mut run = Run::new(CodeBudgets::default());
        let image = Image::new(SliceWindow { base: 0, len: 0 }, &[], &mut run).unwrap();
        let g = cfg(
            &[
                0xb4000061,
                0xd2800000,
                0x14000002,
                0xd2800000 | (right << 5),
                0x94000400,
                0xd65f03c0,
            ],
            &mut run,
        );
        let v = solve(&g, CodeAbi::DarwinArm64, &image, &mut reader, &mut run).unwrap();
        let expected = if right == 0 {
            c(0)
        } else {
            Value::Set(vec![c(0), c(1)].into())
        };
        assert_eq!(v.calls[&0x1010].regs[0], expected);
    }
}

#[test]
fn argument_prefix_is_honest_and_strings_are_read_only() {
    let bytes = b"hello\0";
    let f = file(bytes);
    let mut reader = Reader::new(f.as_file(), bytes.len() as u64, 100);
    let mut run = Run::new(CodeBudgets::default());
    let maps = [mapping(0x2000, 0x2006)];
    let image = Image::new(SliceWindow { base: 0, len: 6 }, &maps, &mut run).unwrap();
    let mut s = A64State::entry(CodeAbi::DarwinArm64).unwrap();
    s.regs[0] = addr(0x2000);
    s.regs[1] = c(u64::MAX);
    s.regs[2] = c(0o777);
    let symbol = UntrustedText::new("_open");
    let library = MachOLibrary::Dylib {
        ordinal: 1,
        name: Some(UntrustedText::new(sigil_model::LIBSYSTEM)),
    };
    let args = arguments(
        &s,
        Target {
            db: &V1,
            abi: CodeAbi::DarwinArm64,
            symbol: &symbol,
            library: Some(&library),
        },
        0x1000,
        &image,
        &mut reader,
        &mut run,
    )
    .unwrap();
    assert_eq!(
        args.values,
        vec![
            ArgValue::ConstStr {
                reg: Reg::X0,
                addr: 0x2000,
                value: UntrustedText::new("hello")
            },
            ArgValue::ConstInt {
                reg: Reg::X1,
                value: -1
            }
        ]
    );
    assert!(matches!(args.layout, ArgumentLayout::Partial { .. }));
    assert!(run.clone_gaps().iter().any(|g| g.contains("cs:0x1000")));
    assert_eq!(reader.used(), 6);
}

fn call_arguments(
    s: &A64State,
    image: &Image<'_>,
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> Result<Arguments, Failure> {
    arguments(
        s,
        Target {
            db: &V1,
            abi: CodeAbi::ElfAarch64,
            symbol: &UntrustedText::new("connect"),
            library: None,
        },
        0x1000,
        image,
        reader,
        run,
    )
}

#[test]
fn string_boundaries_permissions_and_bit_patterns() {
    for (bytes, change, want_string, want_reads) in [
        (b"ok\0".to_vec(), 0, true, 3),
        (vec![b'a'; 3], 0, false, 3),
        ([vec![b'a'; 4095], vec![0]].concat(), 0, true, 4096),
        ([vec![b'a'; 4096], vec![0]].concat(), 0, false, 4096),
        (b"ok\0".to_vec(), 1, false, 0), // writable
        (b"ok\0".to_vec(), 2, false, 0), // executable
        (b"ok\0".to_vec(), 3, false, 0), // relocation/fixup
        (b"ok\0".to_vec(), 4, false, 0), // not readable
        (b"ok\0".to_vec(), 5, false, 0), // not file backed
    ] {
        let f = file(&bytes);
        let mut reader = Reader::new(f.as_file(), bytes.len() as u64, 8192);
        let mut run = Run::new(CodeBudgets::default());
        let mut m = mapping(0x2000, 0x2000 + bytes.len() as u64);
        match change {
            1 => m.writable = true,
            2 => m.executable = true,
            3 => m.relocated = true,
            4 => m.readable = false,
            5 => m.file_offset = None,
            _ => {}
        }
        let maps = [m];
        let image = Image::new(
            SliceWindow {
                base: 0,
                len: bytes.len() as u64,
            },
            &maps,
            &mut run,
        )
        .unwrap();
        let mut s = A64State::entry(CodeAbi::ElfAarch64).unwrap();
        s.regs[0] = addr(0x2000);
        let args = call_arguments(&s, &image, &mut reader, &mut run).unwrap();
        assert_eq!(
            matches!(args.values[0], ArgValue::ConstStr { .. }),
            want_string,
            "change={change}, len={}",
            bytes.len()
        );
        if !want_string {
            assert_eq!(
                args.values[0],
                ArgValue::ConstInt {
                    reg: Reg::X0,
                    value: 0x2000
                }
            );
        }
        assert_eq!(reader.used(), want_reads);
        assert_eq!(
            args.layout,
            ArgumentLayout::Complete,
            "value uncertainty is not layout uncertainty"
        );
    }
    let f = file(&[0]);
    let mut reader = Reader::new(f.as_file(), 1, 1);
    let mut run = Run::new(CodeBudgets::default());
    let maps = [mapping(0, 1)];
    let image = Image::new(SliceWindow { base: 0, len: 1 }, &maps, &mut run).unwrap();
    for bits in [0, i64::MAX as u64, 1 << 63, u64::MAX] {
        let mut s = A64State::entry(CodeAbi::ElfAarch64).unwrap();
        s.regs[0] = c(bits);
        let args = call_arguments(&s, &image, &mut reader, &mut run).unwrap();
        assert_eq!(
            args.values[0],
            ArgValue::ConstInt {
                reg: Reg::X0,
                value: bits as i64
            }
        );
        let roundtrip: ArgValue =
            serde_json::from_slice(&serde_json::to_vec(&args.values[0]).unwrap()).unwrap();
        assert_eq!(roundtrip, args.values[0]);
    }
    assert_eq!(
        reader.used(),
        0,
        "integer immediates are never guessed to be strings"
    );
}

#[test]
fn readonly_image_rejects_aliases_and_keeps_slice_window() {
    let mut run = Run::new(CodeBudgets::default());
    for maps in [
        vec![mapping(1, 1)],
        vec![mapping(10, 9)],
        vec![mapping(0, 5)],
        vec![mapping(0, 2), mapping(1, 3)],
        vec![mapping(2, 4), mapping(0, 2)],
    ] {
        assert!(matches!(
            Image::new(SliceWindow { base: 4, len: 4 }, &maps, &mut run),
            Err(Failure::InvalidImage)
        ));
    }
    assert!(matches!(
        Image::new(
            SliceWindow {
                base: u64::MAX,
                len: 1
            },
            &[],
            &mut run
        ),
        Err(Failure::InvalidImage)
    ));
    let f = file(b"NO\0!abcd\0bad");
    let mut reader = Reader::new(f.as_file(), 12, 100);
    let maps = [mapping(0x2000, 0x2004)];
    let image = Image::new(SliceWindow { base: 4, len: 4 }, &maps, &mut run).unwrap();
    let mut s = A64State::entry(CodeAbi::ElfAarch64).unwrap();
    s.regs[0] = addr(0x2000);
    let args = call_arguments(&s, &image, &mut reader, &mut run).unwrap();
    assert_eq!(
        args.values[0],
        ArgValue::ConstInt {
            reg: Reg::X0,
            value: 0x2000
        },
        "the sibling NUL cannot terminate this slice's string"
    );
    assert_eq!(reader.used(), 4);
    let invalid_window = Image::new(SliceWindow { base: 10, len: 4 }, &maps, &mut run).unwrap();
    assert!(matches!(
        call_arguments(&s, &invalid_window, &mut reader, &mut run),
        Err(Failure::Read)
    ));
    assert_eq!(
        reader.used(),
        4,
        "out-of-file refusal does not charge bytes"
    );
}

#[test]
fn read_refusal_and_artifact_value_budget_are_not_reset() {
    let f = file(b"ok\0");
    let mut reader = Reader::new(f.as_file(), 3, 5);
    let mut run = Run::new(CodeBudgets::default());
    let maps = [mapping(0x2000, 0x2003)];
    let image = Image::new(SliceWindow { base: 0, len: 3 }, &maps, &mut run).unwrap();
    let mut s = A64State::entry(CodeAbi::ElfAarch64).unwrap();
    s.regs[0] = addr(0x2000);
    assert!(call_arguments(&s, &image, &mut reader, &mut run).is_ok());
    assert!(matches!(
        call_arguments(&s, &image, &mut reader, &mut run),
        Err(Failure::Budget)
    ));
    assert!(run.stopped());
    assert_eq!(reader.used(), 3);
    let mut reader = Reader::new(f.as_file(), 3, 20);
    let mut run = Run::new(CodeBudgets {
        value_steps: 66,
        ..CodeBudgets::default()
    });
    let image = Image::new(SliceWindow { base: 0, len: 3 }, &[], &mut run).unwrap();
    let mut s = A64State::entry(CodeAbi::ElfAarch64).unwrap();
    let mov = decode_a64(0xd2800020, 0x1000).unwrap();
    step(&mut s, 0x1000, &mov, &image, &mut reader, &mut run).unwrap();
    assert_eq!(run.value_steps, 34);
    let before = s.clone();
    assert_eq!(
        step(&mut s, 0x1004, &mov, &image, &mut reader, &mut run),
        Err(Failure::Budget)
    );
    assert_eq!(s, before, "charge occurs before writes");
    assert_eq!(run.value_steps, 34);
    let mut later = A64State::entry(CodeAbi::ElfAarch64).unwrap();
    assert_eq!(
        step(&mut later, 0x2000, &mov, &image, &mut reader, &mut run),
        Err(Failure::Budget)
    );
    assert_eq!(later.regs[0], Value::Param(0));
}

#[test]
fn expression_weight_and_depth_are_bounded() {
    let f = file(&[]);
    let mut reader = Reader::new(f.as_file(), 0, 0);
    let mut run = Run::new(CodeBudgets::default());
    let image = Image::new(SliceWindow { base: 0, len: 0 }, &[], &mut run).unwrap();
    let mut s = A64State::entry(CodeAbi::ElfAarch64).unwrap();
    s.regs[1] = Value::Set(vec![c(1), c(2), c(3), c(4)].into());
    let before = run.value_steps;
    step(
        &mut s,
        0x1000,
        &decode_a64(0x2a0103e0, 0x1000).unwrap(),
        &image,
        &mut reader,
        &mut run,
    )
    .unwrap();
    assert_eq!(
        run.value_steps - before,
        37,
        "base 33 + four extra set nodes"
    );
    assert_eq!(s.regs[0], s.regs[1]);
    s.regs[0] = Value::Param(0);
    for n in 0..3 {
        step(
            &mut s,
            0x2000 + n * 4,
            &decode_a64(0xf9400000, 0x2000 + n * 4).unwrap(),
            &image,
            &mut reader,
            &mut run,
        )
        .unwrap();
        assert!(matches!(s.regs[0], Value::Load { .. }));
    }
    step(
        &mut s,
        0x2010,
        &decode_a64(0xf9400000, 0x2010).unwrap(),
        &image,
        &mut reader,
        &mut run,
    )
    .unwrap();
    assert_eq!(s.regs[0], Value::Unknown(Why::FromMemory));
}

fn fan_in(n: usize) -> Vec<u32> {
    let mut words = vec![0; n - 1 + n * 2 + 2];
    let join = n - 1 + n * 2;
    for (i, w) in words.iter_mut().enumerate().take(n - 1) {
        let arm = n - 1 + (i + 1) * 2;
        *w = 0xb4000007 | (((arm - i) as u32) << 5);
    }
    for i in 0..n {
        let arm = n - 1 + i * 2;
        words[arm] = 0xd2800000 | ((i as u32) << 5);
        words[arm + 1] = 0x14000000 | (join - arm - 1) as u32;
    }
    words[join] = 0x94000400;
    words[join + 1] = 0xd65f03c0;
    words
}

#[test]
fn cfg_four_alternatives_and_five_incoming_paths() {
    let f = file(&[]);
    let mut reader = Reader::new(f.as_file(), 0, 0);
    let mut run = Run::new(CodeBudgets::default());
    let image = Image::new(SliceWindow { base: 0, len: 0 }, &[], &mut run).unwrap();
    for n in [4, 5] {
        let words = fan_in(n);
        let g = cfg(&words, &mut run);
        let v = solve(&g, CodeAbi::ElfAarch64, &image, &mut reader, &mut run).unwrap();
        let expected = if n == 4 {
            Value::Set((0..4).map(c).collect())
        } else {
            Value::Unknown(Why::MergedDisagreeing)
        };
        assert_eq!(v.calls.values().next().unwrap().regs[0], expected);
    }
}

// Each newly discovered predecessor schedules the low-address return block again, even
// though its value agrees. This reaches the *production* 256-pass limit without a test knob.
fn repeated_join(visits: usize) -> Vec<u32> {
    let mut words = vec![0x94000400, 0x94000400, 0x14000002, 0xd65f03c0];
    for n in 0..visits {
        let signed_words = -((n + 1) as i32);
        words.push(0xb4000007 | (((signed_words as u32) & 0x7ffff) << 5));
    }
    words.push(0xd65f03c0);
    words
}

#[test]
fn rollback_is_per_function_including_actual_256_pass_limit() {
    let f = file(&[]);
    let mut reader = Reader::new(f.as_file(), 0, 0);
    let mut run = Run::new(CodeBudgets::default());
    let image = Image::new(SliceWindow { base: 0, len: 0 }, &[], &mut run).unwrap();
    let good = cfg(&repeated_join(256), &mut run);
    let saved = solve(&good, CodeAbi::ElfAarch64, &image, &mut reader, &mut run).unwrap();
    assert_eq!(saved.calls.len(), 2);
    let bad = cfg(&repeated_join(257), &mut run);
    assert!(matches!(
        solve(&bad, CodeAbi::ElfAarch64, &image, &mut reader, &mut run),
        Err(Failure::Unsettled)
    ));
    assert!(
        !run.stopped(),
        "a function-local fixpoint cap leaves later functions available"
    );
    let next = cfg(&[0x94000400, 0xd65f03c0], &mut run);
    let later = solve(&next, CodeAbi::ElfAarch64, &image, &mut reader, &mut run).unwrap();
    assert_eq!(later.calls.len(), 1);
    assert_eq!(saved.calls.len(), 2);
    assert!(run.clone_gaps().iter().any(|g| g.contains("Unsettled")));
    let bytes: Vec<u8> = [0x94000400u32, 0x94000400, 0xd503233f]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    assert!(run.charge(Work::References, 2));
    assert!(decode_cfg(
        &bytes,
        0x1000,
        0x100c,
        &Proofs {
            executable: &|_, _| true,
            excluded: &|_, _| false,
            noreturn: &|_, _| false,
            candidates: &[0x1000, 0x1004]
        },
        &mut run
    )
    .is_err());
    assert_eq!(
        later.calls.len(),
        1,
        "failed decode exposes no call list and cannot delete independent results"
    );
}

#[test]
fn final_replay_budget_failure_discards_staged_calls() {
    let f = file(&[]);
    let mut reader = Reader::new(f.as_file(), 0, 0);
    let mut run = Run::new(CodeBudgets::default());
    let image = Image::new(SliceWindow { base: 0, len: 0 }, &[], &mut run).unwrap();
    let g = cfg(&[0x94000400, 0x94000400, 0xd65f03c0], &mut run);
    let saved = solve(&g, CodeAbi::ElfAarch64, &image, &mut reader, &mut run).unwrap();
    let used = run.value_steps;
    let mut limited = Run::new(CodeBudgets {
        value_steps: used - 2,
        ..CodeBudgets::default()
    });
    let result = solve(&g, CodeAbi::ElfAarch64, &image, &mut reader, &mut limited);
    assert!(matches!(result, Err(Failure::Budget)));
    assert!(limited.stopped());
    assert_eq!(saved.calls.len(), 2);
}

#[test]
fn variadic_and_aggregate_are_not_guessed() {
    let f = file(&[]);
    let mut reader = Reader::new(f.as_file(), 0, 0);
    let mut run = Run::new(CodeBudgets::default());
    let image = Image::new(SliceWindow { base: 0, len: 0 }, &[], &mut run).unwrap();
    let library = MachOLibrary::Dylib {
        ordinal: 1,
        name: Some(UntrustedText::new(sigil_model::LIBSYSTEM)),
    };
    for (abi, symbol, n) in [
        (CodeAbi::DarwinArm64, "_open", 2),
        (CodeAbi::DarwinArm64, "_openat", 3),
        (CodeAbi::ElfAarch64, "open", 2),
        (CodeAbi::ElfAarch64, "openat", 3),
        (CodeAbi::ElfAarch64, "printf", 0),
        (CodeAbi::DarwinArm64, "__ZN1A3runEv", 0),
    ] {
        let mut s = A64State::entry(abi).unwrap();
        for reg in &mut s.regs {
            *reg = c(7);
        }
        let args = arguments(
            &s,
            Target {
                db: &V1,
                abi,
                symbol: &UntrustedText::new(symbol),
                library: (abi == CodeAbi::DarwinArm64).then_some(&library),
            },
            0x1000,
            &image,
            &mut reader,
            &mut run,
        )
        .unwrap();
        assert_eq!(args.values.len(), n, "{symbol}");
        assert!(matches!(args.layout, ArgumentLayout::Partial { .. }));
    }
}

#[test]
fn stopped_artifact_cannot_project_even_an_unknown_signature() {
    let f = file(&[]);
    let mut reader = Reader::new(f.as_file(), 0, 0);
    let mut run = Run::new(CodeBudgets::default());
    let image = Image::new(SliceWindow { base: 0, len: 0 }, &[], &mut run).unwrap();
    let s = A64State::entry(CodeAbi::ElfAarch64).unwrap();
    run.limit("test", 0);
    let result = arguments(
        &s,
        Target {
            db: &V1,
            abi: CodeAbi::ElfAarch64,
            symbol: &UntrustedText::new("unknown"),
            library: None,
        },
        0x1000,
        &image,
        &mut reader,
        &mut run,
    );
    assert_eq!(result, Err(Failure::Budget));
}

#[test]
fn indirect_and_direct_calls_preserve_only_untouched_callee_saved_values() {
    let f = file(&[]);
    let mut reader = Reader::new(f.as_file(), 0, 0);
    let mut run = Run::new(CodeBudgets::default());
    let image = Image::new(SliceWindow { base: 0, len: 0 }, &[], &mut run).unwrap();
    for word in [0x94000400, 0xd63f0200] {
        let mut s = A64State::entry(CodeAbi::DarwinArm64).unwrap();
        for (n, reg) in s.regs.iter_mut().enumerate() {
            *reg = c(100 + n as u64);
        }
        s.sp = c(0x8000);
        step(
            &mut s,
            0x1000,
            &decode_a64(word, 0x1000).unwrap(),
            &image,
            &mut reader,
            &mut run,
        )
        .unwrap();
        assert_eq!(s.regs[0], Value::Return(0x1000));
        for n in 1..18 {
            assert_eq!(s.regs[n], Value::Unknown(Why::ClobberedByCall));
        }
        for n in 19..30 {
            assert_eq!(s.regs[n], c(100 + n as u64));
        }
        assert_eq!(s.regs[18], Value::Unknown(Why::NotModeled));
        assert_eq!(s.regs[30], Value::Unknown(Why::ClobberedByCall));
        assert_eq!(s.sp, c(0x8000));
        step(
            &mut s,
            0x1004,
            &decode_a64(0xa9bf7bfd, 0x1004).unwrap(),
            &image,
            &mut reader,
            &mut run,
        )
        .unwrap();
        assert_eq!(s.sp, c(0x7ff0));
        step(
            &mut s,
            0x1008,
            &decode_a64(0xa8c17bfd, 0x1008).unwrap(),
            &image,
            &mut reader,
            &mut run,
        )
        .unwrap();
        assert_eq!(s.sp, c(0x8000));
        assert_eq!(s.regs[29], Value::Unknown(Why::FromMemory));
        assert_eq!(s.regs[30], Value::Unknown(Why::FromMemory));
    }
    let g = cfg(
        &[
            0x94000400, 0x54000060, 0xd2800000, 0x14000002, 0xd2800020, 0x94000400, 0xd65f03c0,
        ],
        &mut run,
    );
    let values = solve(&g, CodeAbi::DarwinArm64, &image, &mut reader, &mut run).unwrap();
    assert_eq!(
        values.calls[&0x1014].regs[0],
        Value::Set(vec![c(0), c(1)].into()),
        "B.eq keeps both edges; no flags survive the call"
    );
    let g = cfg(&[0x94000400, 0x94000400, 0xd65f03c0], &mut run);
    let values = solve(&g, CodeAbi::DarwinArm64, &image, &mut reader, &mut run).unwrap();
    assert_eq!(values.calls[&0x1004].regs[0], Value::Return(0x1000));
}

#[test]
fn same_fd_failed_read_keeps_charge_and_rolls_back_function() {
    let f = file(&[1; 8]);
    let mut reader = Reader::new(f.as_file(), 8, 64);
    let mut run = Run::new(CodeBudgets::default());
    let maps = [mapping(0x2000, 0x2008)];
    let image = Image::new(SliceWindow { base: 0, len: 8 }, &maps, &mut run).unwrap();
    // First call precedes ADRP x1, +0x1000 / LDR x0,[x1]. Final metadata stability checks
    // still belong to the artifact collector; here a genuine failed pread is sufficient.
    let g = cfg(
        &[0x94000400, 0xb0000001, 0xf9400020, 0x94000400, 0xd65f03c0],
        &mut run,
    );
    f.as_file().set_len(0).unwrap();
    assert!(matches!(
        solve(&g, CodeAbi::ElfAarch64, &image, &mut reader, &mut run),
        Err(Failure::Read)
    ));
    assert_eq!(reader.used(), 8);
    assert!(!run.stopped());
    assert!(run.clone_gaps().iter().any(|g| g.contains("read error")));
}

#[test]
fn unapplied_transfer_clears_all_writes_without_reading_raw_memory() {
    let f = file(&[0; 64]);
    let mut reader = Reader::new(f.as_file(), 64, 64);
    let mut run = Run::new(CodeBudgets::default());
    let mappings = [mapping(0, 64)];
    let image = Image::new(SliceWindow { base: 0, len: 64 }, &mappings, &mut run).unwrap();
    // ADRP, ADD, scalar LDR, and pair LDP with post-index base writeback. The last case also
    // checks the separate SP destination; original control instructions preserve call clobbers.
    for (word, writes, sp_write) in [
        (0x90000000u32, vec![0], false),
        (0x91000000, vec![0], false),
        (0xf9400020, vec![0], false),
        (0xa8c10440, vec![0, 1, 2], false),
        (0xa8c107e0, vec![0, 1], true),
    ] {
        let mut s = A64State::entry(CodeAbi::ElfAarch64).unwrap();
        for r in &mut s.regs {
            *r = c(8);
        }
        s.sp = c(8);
        let ins = decode_a64(word, 0x1000).unwrap();
        relocated_step(&mut s, 0x1000, &ins, &image, true, &mut reader, &mut run).unwrap();
        for n in 0..31 {
            if writes.contains(&n) {
                assert!(matches!(s.regs[n], Value::Unknown(_)), "{word:x} x{n}");
            } else {
                assert_eq!(s.regs[n], c(8));
            }
        }
        assert_eq!(matches!(s.sp, Value::Unknown(_)), sp_write);
        assert_eq!(reader.used(), 0);
    }
    let mut s = A64State::entry(CodeAbi::ElfAarch64).unwrap();
    s.regs[16] = c(16);
    s.regs[19] = c(19);
    relocated_step(
        &mut s,
        0x1000,
        &decode_a64(0x94000000, 0x1000).unwrap(),
        &image,
        true,
        &mut reader,
        &mut run,
    )
    .unwrap();
    assert_eq!(s.regs[0], Value::Return(0x1000));
    assert_eq!(s.regs[16], Value::Unknown(Why::ClobberedByCall));
    assert_eq!(s.regs[19], c(19));
}
