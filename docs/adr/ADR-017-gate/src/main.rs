//! Research adapter, not the engine: exact raw prefilter + complete typed equality.
use disarm64::InsnOpcode;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use yaxpeax_arch::{Arch, Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::{
    ARMv8, Instruction, Opcode, Operand as O, ShiftStyle, SizeCode as S,
};

struct CountAlloc;
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for CountAlloc {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.realloc(p, l, n)
    }
}
#[global_allocator]
static ALLOCATOR: CountAlloc = CountAlloc;
fn sx(v: u32, bits: u32) -> i64 {
    ((v as i32) << (32 - bits) >> (32 - bits)) as i64
}
fn make(opcode: Opcode, operands: [O; 4]) -> Instruction {
    Instruction { opcode, operands }
}

/// This is the complete proposed supported raw input set. No other word reaches a decoder.
fn prefilter(w: u32) -> Option<Instruction> {
    let n = O::Nothing;
    let size = if w >> 31 == 0 { S::W } else { S::X };
    let d = (w & 31) as u16;
    let r = ((w >> 5) & 31) as u16;
    if w & 0x7c00_0000 == 0x1400_0000 {
        return Some(make(
            if w >> 31 == 0 { Opcode::B } else { Opcode::BL },
            [O::PCOffset(sx(w & 0x03ff_ffff, 26) * 4), n, n, n],
        ));
    }
    if w & 0xff00_0010 == 0x5400_0000 && w & 15 < 14 {
        return Some(make(
            Opcode::Bcc((w & 15) as u8),
            [O::PCOffset(sx((w >> 5) & 0x7ffff, 19) * 4), n, n, n],
        ));
    }
    if w & 0x7e00_0000 == 0x3400_0000 {
        return Some(make(
            if w & 0x0100_0000 == 0 {
                Opcode::CBZ
            } else {
                Opcode::CBNZ
            },
            [
                O::Register(size, d),
                O::PCOffset(sx((w >> 5) & 0x7ffff, 19) * 4),
                n,
                n,
            ],
        ));
    }
    if w & 0x7e00_0000 == 0x3600_0000 {
        let bit = ((w >> 19) & 31) | ((w >> 26) & 32);
        return Some(make(
            if w & 0x0100_0000 == 0 {
                Opcode::TBZ
            } else {
                Opcode::TBNZ
            },
            [
                O::Register(size, d),
                O::Imm16(bit as u16),
                O::PCOffset(sx((w >> 5) & 0x3fff, 14) * 4),
                n,
            ],
        ));
    }
    let reg_branch = match w & 0xffff_fc1f {
        0xd61f_0000 => Some(Opcode::BR),
        0xd63f_0000 => Some(Opcode::BLR),
        0xd65f_0000 => Some(Opcode::RET),
        _ => None,
    };
    if let Some(op) = reg_branch {
        return (r < 31).then(|| make(op, [O::Register(S::X, r), n, n, n]));
    }
    if w & 0x1f00_0000 == 0x1000_0000 {
        let page = w >> 31 != 0;
        let disp = sx(((w >> 5) & 0x7ffff) * 4 + ((w >> 29) & 3), 21) * if page { 4096 } else { 1 };
        return Some(make(
            if page { Opcode::ADRP } else { Opcode::ADR },
            [O::Register(S::X, d), O::PCOffset(disp), n, n],
        ));
    }
    if w & 0x1f80_0000 == 0x1280_0000 {
        let hw = (w >> 21) & 3;
        if size == S::W && hw > 1 {
            return None;
        }
        let op = match (w >> 29) & 3 {
            0 => Opcode::MOVN,
            2 => Opcode::MOVZ,
            3 => Opcode::MOVK,
            _ => return None,
        };
        return Some(make(
            op,
            [
                O::Register(size, d),
                O::ImmShift(((w >> 5) & 0xffff) as u16, (hw * 16) as u8),
                n,
                n,
            ],
        ));
    }
    // ORR Rn=ZR, no shift/invert: register-copy alias only.
    if w & 0x7fe0_ffe0 == 0x2a00_03e0 {
        return Some(make(
            Opcode::ORR,
            [
                O::Register(size, d),
                O::Register(size, 31),
                O::RegShift(ShiftStyle::LSL, 0, size, ((w >> 16) & 31) as u16),
                n,
            ],
        ));
    }
    // S=0, bit23=0; shift bit22 is 0 or 1. Reg31 is SP at both positions.
    if w & 0x3f80_0000 == 0x1100_0000 {
        let imm = (w >> 10) & 0xfff;
        return Some(make(
            if w & 0x4000_0000 == 0 {
                Opcode::ADD
            } else {
                Opcode::SUB
            },
            [
                O::RegisterOrSP(size, d),
                O::RegisterOrSP(size, r),
                if w & 0x0040_0000 == 0 {
                    O::Immediate(imm)
                } else {
                    O::ImmShift(imm as u16, 12)
                },
                n,
            ],
        ));
    }
    // Integer W/X load/store, unsigned scaled immediate, no writeback.
    if w & 0xbfc0_0000 == 0xb940_0000 || w & 0xbfc0_0000 == 0xb900_0000 {
        let x = w >> 30 == 3;
        return Some(make(
            if w & 0x0040_0000 != 0 {
                Opcode::LDR
            } else {
                Opcode::STR
            },
            [
                O::Register(if x { S::X } else { S::W }, d),
                O::RegPreIndex(
                    r,
                    (((w >> 10) & 0xfff) * if x { 8 } else { 4 }) as i32,
                    false,
                ),
                n,
                n,
            ],
        ));
    }
    // Integer W/X pairs: post-index, signed offset, or pre-index; no LDPSW/SIMD.
    if w & 0x7e00_0000 == 0x2800_0000 {
        let mode = (w >> 23) & 3;
        if mode == 0 {
            return None;
        }
        let load = w & 0x0040_0000 != 0;
        let t2 = ((w >> 10) & 31) as u16;
        if (load && d == t2) || (mode != 2 && r != 31 && (r == d || r == t2)) {
            return None;
        }
        let off = (sx((w >> 15) & 127, 7) * if size == S::X { 8 } else { 4 }) as i32;
        return Some(make(
            if load { Opcode::LDP } else { Opcode::STP },
            [
                O::Register(size, d),
                O::Register(size, t2),
                if mode == 1 {
                    O::RegPostIndex(r, off)
                } else {
                    O::RegPreIndex(r, off, mode == 3)
                },
                n,
            ],
        ));
    }
    // PAC/BTI remain explicit unsupported gaps, including hint-space aliases.
    if w == 0xd503_201f {
        return Some(make(
            Opcode::HINT,
            [O::ControlReg(0), O::Immediate(0), n, n],
        ));
    }
    None
}

fn yax(w: u32) -> Result<Option<Instruction>, &'static str> {
    let Some(expected) = prefilter(w) else {
        return Ok(None);
    };
    let bytes = w.to_le_bytes();
    let actual = <ARMv8 as Arch>::Decoder::default()
        .decode(&mut U8Reader::new(&bytes))
        .map_err(|_| "yax decode error")?;
    if actual != expected {
        return Err("yax typed operand mismatch");
    }
    Ok(Some(actual))
}

// The independent candidate checks generated instruction identity/mask and every
// static operand bitfield, then compares its extracted bits with the raw contract.
// It has no pretense that mnemonic text or acceptance is a semantic adapter.
fn dis(w: u32) -> Result<Option<Instruction>, &'static str> {
    if prefilter(w).is_none() {
        return Ok(None);
    }
    let actual = disarm64::decoder::decode(w).ok_or("disarm decode error")?;
    let def = actual.definition();
    if actual.bits() != w || w & def.mask != def.opcode {
        return Err("disarm mask mismatch");
    }
    for operand in def.operands {
        for field in operand.bit_fields {
            let lsb = u32::from(field.lsb);
            let width = u32::from(field.width);
            if width == 0 || width > 32 || lsb + width > 32 {
                return Err("disarm invalid bitfield");
            }
            let mask = u32::MAX >> (32 - width);
            let extracted = (actual.bits() >> lsb) & mask;
            if extracted != (w >> lsb) & mask {
                return Err("disarm extraction mismatch");
            }
        }
    }
    let normalized = dis_normalize(actual)?;
    if Some(normalized) != prefilter(w) {
        return Err("disarm typed operand mismatch");
    }
    Ok(Some(normalized))
}

fn dis_normalize(a: disarm64::Opcode) -> Result<Instruction, &'static str> {
    use disarm64::decoder::InsnId as I;
    let w = a.bits();
    let n = O::Nothing;
    let size = if w & (1 << 31) == 0 { S::W } else { S::X };
    let d = (w & 31) as u16;
    let r = ((w >> 5) & 31) as u16;
    let op = match a.id() {
        I::B_ADDR_PCREL26 => Opcode::B,
        I::BL_ADDR_PCREL26 => Opcode::BL,
        I::B_C_ADDR_PCREL19 => Opcode::Bcc((w & 15) as u8),
        I::CBZ_Rt_ADDR_PCREL19 => Opcode::CBZ,
        I::CBNZ_Rt_ADDR_PCREL19 => Opcode::CBNZ,
        I::TBZ_Rt_BIT_NUM_ADDR_PCREL14 => Opcode::TBZ,
        I::TBNZ_Rt_BIT_NUM_ADDR_PCREL14 => Opcode::TBNZ,
        I::BR_Rn => Opcode::BR,
        I::BLR_Rn => Opcode::BLR,
        I::RET_Rn => Opcode::RET,
        I::ADR_Rd_ADDR_PCREL21 => Opcode::ADR,
        I::ADRP_Rd_ADDR_ADRP => Opcode::ADRP,
        I::MOVN_Rd_HALF => Opcode::MOVN,
        I::MOVZ_Rd_HALF => Opcode::MOVZ,
        I::MOVK_Rd_HALF => Opcode::MOVK,
        I::ORR_Rd_Rn_Rm_SFT => Opcode::ORR,
        I::ADD_Rd_SP_Rn_SP_AIMM => Opcode::ADD,
        I::SUB_Rd_SP_Rn_SP_AIMM => Opcode::SUB,
        I::LDR_Rt_ADDR_UIMM12 => Opcode::LDR,
        I::STR_Rt_ADDR_UIMM12 => Opcode::STR,
        I::LDP_Rt_Rt2_ADDR_SIMM7 | I::LDP_Rt_W_Rt2_W_ADDR_SIMM7_S_S => Opcode::LDP,
        I::STP_Rt_Rt2_ADDR_SIMM7 | I::STP_Rt_W_Rt2_W_ADDR_SIMM7_S_S => Opcode::STP,
        I::HINT_UIMM7 if w == 0xd503201f => Opcode::HINT,
        _ => return Err("disarm unsupported instruction identity"),
    };
    // Operand kinds in disarm64 do not implement semantic extraction. This is
    // its own required extraction layer, selected by generated identity above.
    let operands = match op {
        Opcode::B | Opcode::BL => [O::PCOffset(sx(w & 0x3ffffff, 26) << 2), n, n, n],
        Opcode::Bcc(_) => [O::PCOffset(sx((w >> 5) & 0x7ffff, 19) << 2), n, n, n],
        Opcode::CBZ | Opcode::CBNZ => [
            O::Register(size, d),
            O::PCOffset(sx((w >> 5) & 0x7ffff, 19) << 2),
            n,
            n,
        ],
        Opcode::TBZ | Opcode::TBNZ => [
            O::Register(size, d),
            O::Imm16((((w >> 31) << 5) | ((w >> 19) & 31)) as u16),
            O::PCOffset(sx((w >> 5) & 0x3fff, 14) << 2),
            n,
        ],
        Opcode::BR | Opcode::BLR | Opcode::RET => [O::Register(S::X, r), n, n, n],
        Opcode::ADR | Opcode::ADRP => [
            O::Register(S::X, d),
            O::PCOffset(
                sx(((w >> 29) & 3) | (((w >> 5) & 0x7ffff) << 2), 21)
                    << if op == Opcode::ADRP { 12 } else { 0 },
            ),
            n,
            n,
        ],
        Opcode::MOVN | Opcode::MOVZ | Opcode::MOVK => [
            O::Register(size, d),
            O::ImmShift(((w >> 5) & 0xffff) as u16, (((w >> 21) & 3) * 16) as u8),
            n,
            n,
        ],
        Opcode::ORR => [
            O::Register(size, d),
            O::Register(size, r),
            O::RegShift(
                ShiftStyle::LSL,
                ((w >> 10) & 63) as u8,
                size,
                ((w >> 16) & 31) as u16,
            ),
            n,
        ],
        Opcode::ADD | Opcode::SUB => [
            O::RegisterOrSP(size, d),
            O::RegisterOrSP(size, r),
            if (w >> 22) & 3 == 0 {
                O::Immediate((w >> 10) & 0xfff)
            } else {
                O::ImmShift(((w >> 10) & 0xfff) as u16, 12)
            },
            n,
        ],
        Opcode::LDR | Opcode::STR => [
            O::Register(if (w >> 30) == 3 { S::X } else { S::W }, d),
            O::RegPreIndex(r, (((w >> 10) & 0xfff) << ((w >> 30) & 3)) as i32, false),
            n,
            n,
        ],
        Opcode::LDP | Opcode::STP => {
            let mode = (w >> 23) & 3;
            let off = (sx((w >> 15) & 127, 7) << if size == S::X { 3 } else { 2 }) as i32;
            [
                O::Register(size, d),
                O::Register(size, ((w >> 10) & 31) as u16),
                if mode == 1 {
                    O::RegPostIndex(r, off)
                } else {
                    O::RegPreIndex(r, off, mode == 3)
                },
                n,
            ]
        }
        Opcode::HINT => [O::ControlReg(0), O::Immediate(0), n, n],
        _ => return Err("disarm normalizer incomplete"),
    };
    Ok(make(op, operands))
}

/// PC is the instruction address; ADRP uses the containing page. No wrapping.
fn checked_target(pc: u64, inst: &Instruction) -> Option<u64> {
    if pc & 3 != 0 {
        return None;
    }
    let offset = inst.operands.iter().find_map(|op| match op {
        O::PCOffset(n) => Some(*n),
        _ => None,
    })?;
    let base = if inst.opcode == Opcode::ADRP {
        pc & !4095
    } else {
        pc
    };
    base.checked_add_signed(offset)
}

fn step(s: &mut u64) -> u32 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s as u32
}
const BASES: &[u32] = &[
    0x14000000, 0x94000000, 0x54000000, 0x34000000, 0xb5000000, 0x36000000, 0xb7000000, 0xd61f0000,
    0xd63f0000, 0xd65f0000, 0x10000000, 0x90000000, 0x12800000, 0x52800000, 0x72800000, 0x92800000,
    0xd2800000, 0xf2800000, 0x2a0003e0, 0xaa0003e0, 0x11000000, 0x51000000, 0x91000000, 0xd1000000,
    0xb9400000, 0xf9400000, 0xb9000000, 0xf9000000, 0x28800000, 0x28c00000, 0x29000000, 0x29400000,
    0x29800000, 0x29c00000, 0xa8800000, 0xa8c00000, 0xa9000000, 0xa9400000, 0xa9800000, 0xa9c00000,
    0xd503201f, 0xd503233f, 0xd503245f, 0xd503249f, 0xd50324df, 0xd65f0bff, 0, 0xffffffff,
];
fn corpus(mut visit: impl FnMut(u32)) {
    // Explicit masks' bit boundaries, ZR/SP, register-width, displacement and shift extremes.
    for &b in BASES {
        visit(b);
        for bit in 0..32 {
            visit(b ^ (1 << bit));
        }
        for fields in [
            0x1f, 0x3e0, 0x7c00, 0x1f0000, 0x003fffff, 0x03ffffff, 0x80000000, 0x7fffffff,
            0xffffffff,
        ] {
            visit(b | fields);
            visit(b & !fields);
        }
    }
    // Exact sign-bit boundaries and adjacent values for every immediate family.
    for b in [0x14000000, 0x94000000] {
        for imm in [0, 1, 0x1fffffe, 0x1ffffff, 0x2000000, 0x2000001, 0x3ffffff] {
            visit(b | imm);
        }
    }
    for b in [0x54000000, 0x34000000, 0xb5000000] {
        for imm in [0, 1, 0x3ffff, 0x40000, 0x7ffff] {
            visit(b | (imm << 5));
        }
    }
    for b in [0x36000000, 0xb7000000] {
        for imm in [0, 1, 0x1fff, 0x2000, 0x3fff] {
            visit(b | (imm << 5));
        }
    }
    for b in [0x10000000, 0x90000000] {
        for imm in [0, 1, 0xfffff, 0x100000, 0x1fffff] {
            visit(b | ((imm & 3) << 29) | ((imm >> 2) << 5));
        }
    }
    for b in [
        0x12800000, 0x52800000, 0x72800000, 0x92800000, 0xd2800000, 0xf2800000,
    ] {
        for hw in 0..4 {
            for imm in [0, 1, 0x7fff, 0x8000, 0xffff] {
                for rd in [0, 30, 31] {
                    visit(b | (hw << 21) | (imm << 5) | rd);
                }
            }
        }
    }
    for &b in BASES {
        for rd in [0, 30, 31] {
            for rn in [0, 30, 31] {
                visit(b | rd | (rn << 5));
            }
        }
    }
    let mut state = 0x48c0ffeeu64;
    for _ in 0..1_000_000 {
        visit(step(&mut state));
    }
    // Structured hostile mutations increase exercised eligible instructions beyond uniform noise.
    for i in 0..100_000 {
        let b = BASES[i % BASES.len()];
        visit(b ^ (step(&mut state) & 0x00ff_ffff));
    }
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("words") {
        corpus(|w| {
            if prefilter(w).is_some() {
                println!("{w:08x}");
            }
        });
        return;
    }
    if args.get(1).map(String::as_str) == Some("inspect") {
        use std::io::BufRead;
        for line in std::io::stdin().lock().lines() {
            let line = line.unwrap();
            let w = u32::from_str_radix(line.trim(), 16).unwrap();
            println!("{w:08x}\t{:?}\t{:?}", yax(w), dis(w));
        }
        return;
    }
    // Exact original eight-word smoke, preserving the PACIASP classification difference.
    for w in [
        0x94000000u32,
        0x14000000,
        0xd63f0100,
        0xd61f0100,
        0xd65f03c0,
        0x2a1f03e0,
        0xaa1f03e1,
        0xd503233f,
    ] {
        let bytes = w.to_le_bytes();
        let a = <ARMv8 as Arch>::Decoder::default()
            .decode(&mut U8Reader::new(&bytes))
            .unwrap();
        let b = disarm64::decoder::decode(w).unwrap();
        println!("smoke {w:08x}: yax={:?}, disarm={:?}", a.opcode, b.id());
    }
    assert_eq!(checked_target(0, &prefilter(0x17ffffff).unwrap()), None);
    assert_eq!(checked_target(4, &prefilter(0x17ffffff).unwrap()), Some(0));
    assert_eq!(
        checked_target(u64::MAX - 3, &prefilter(0x14000001).unwrap()),
        None
    );
    assert_eq!(
        checked_target(0x1ffc, &prefilter(0x90000000).unwrap()),
        Some(0x1000)
    );
    assert_eq!(checked_target(3, &prefilter(0x14000000).unwrap()), None);
    let run_yax = args.get(1).map(String::as_str) != Some("disarm");
    let run_dis = args.get(1).map(String::as_str) != Some("yax");
    let begin = std::time::Instant::now();
    let before = ALLOCS.load(Ordering::Relaxed);
    let mut counts = [0u64; 5];
    let mut first = None;
    corpus(|w| {
        counts[0] += 1;
        if let Some(inst) = prefilter(w) {
            counts[1] += 1;
            for pc in [0, 4, 0xffc, 0x1000, u64::MAX - 3, u64::MAX] {
                std::hint::black_box(checked_target(pc, &inst));
            }
        }
        if let Err(e) = if run_yax { yax(w) } else { Ok(None) } {
            counts[2] += 1;
            if first.is_none() {
                first = Some((w, e));
            }
        }
        if let Err(e) = if run_dis { dis(w) } else { Ok(None) } {
            counts[3] += 1;
            if first.is_none() {
                first = Some((w, e));
            }
        }
    });
    counts[4] = (ALLOCS.load(Ordering::Relaxed) - before) as u64;
    println!("seed=0x48c0ffee total={} eligible={} yax_errors={} disarm_errors={} allocations={} duration_ms={} first={first:x?}",counts[0],counts[1],counts[2],counts[3],counts[4],begin.elapsed().as_millis());
    if counts[2] + counts[3] + counts[4] != 0 {
        std::process::exit(1);
    }
}
