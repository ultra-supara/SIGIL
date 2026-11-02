//! ADR-017's audited raw whitelist and validated, allocation-free semantics.

use yaxpeax_arch::{Arch, Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::{
    ARMv8, Instruction, Opcode, Operand as O, ShiftStyle, SizeCode as S,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flow {
    Next,
    CallDirect(u64),
    CallRegister(u8),
    JumpDirect(u64),
    JumpRegister(u8),
    Conditional(u64),
    Return,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Width {
    W,
    X,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegisterName {
    Gpr(u8),
    Sp,
    Zero,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Register {
    pub name: RegisterName,
    pub width: Width,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WideMove {
    Not,
    Zero,
    Keep,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddressMode {
    Offset,
    PreIndex,
    PostIndex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operation {
    Control,
    Nop,
    Address {
        dst: Register,
        address: u64,
    },
    WideMove {
        kind: WideMove,
        dst: Register,
        imm: u16,
        shift: u8,
    },
    Copy {
        dst: Register,
        src: Register,
    },
    AddImmediate {
        dst: Register,
        src: Register,
        imm: u64,
        subtract: bool,
    },
    Memory {
        load: bool,
        regs: [Option<Register>; 2],
        base: Register,
        offset: i32,
        mode: AddressMode,
    },
}

/// Architectural register effects only. Calls also require the ABI clobbers in value transfer.
/// W destinations zero-extend. ZR is never a write; SP has its own identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Effects {
    pub reads: [Option<Register>; 3],
    pub writes: [Option<Register>; 3],
    pub reads_flags: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct A64Insn {
    pub word: u32,
    pub flow: Flow,
    pub operation: Operation,
    pub effects: Effects,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodeGap {
    Unsupported,
    Inconsistent,
    Unaligned,
    AddressOverflow,
}

fn sx(v: u32, bits: u32) -> i64 {
    ((v as i32) << (32 - bits) >> (32 - bits)) as i64
}
fn make(opcode: Opcode, operands: [O; 4]) -> Instruction {
    Instruction { opcode, operands }
}

/// The complete accepted ADR-017 raw subset. Widening it requires a new decoder gate.
/// No other word reaches the decoder.
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

/// Feed exactly four local bytes to the audited decoder, after raw classification. A success
/// requires equality of the opcode and every typed operand, including unused operand slots.
pub(crate) fn decode_a64(word: u32, pc: u64) -> Result<A64Insn, DecodeGap> {
    if pc & 3 != 0 {
        return Err(DecodeGap::Unaligned);
    }
    let expected = prefilter(word).ok_or(DecodeGap::Unsupported)?;
    let bytes = word.to_le_bytes();
    let actual = <ARMv8 as Arch>::Decoder::default()
        .decode(&mut U8Reader::new(&bytes))
        .map_err(|_| DecodeGap::Inconsistent)?;
    validated(word, pc, expected, actual)
}

fn register(size: S, n: u16, sp: bool) -> Result<Register, DecodeGap> {
    let width = match size {
        S::W => Width::W,
        S::X => Width::X,
    };
    let name = match n {
        0..=30 => RegisterName::Gpr(n as u8),
        31 if sp => RegisterName::Sp,
        31 => RegisterName::Zero,
        _ => return Err(DecodeGap::Inconsistent),
    };
    Ok(Register { name, width })
}

fn operand_register(o: O) -> Result<Register, DecodeGap> {
    match o {
        O::Register(size, n) => register(size, n, false),
        O::RegisterOrSP(size, n) => register(size, n, true),
        _ => Err(DecodeGap::Inconsistent),
    }
}

fn write(r: Register) -> Option<Register> {
    (r.name != RegisterName::Zero).then_some(r)
}

fn target(pc: u64, operand: O, page: bool) -> Result<u64, DecodeGap> {
    let O::PCOffset(offset) = operand else {
        return Err(DecodeGap::Inconsistent);
    };
    let base = if page { pc & !4095 } else { pc };
    base.checked_add_signed(offset)
        .ok_or(DecodeGap::AddressOverflow)
}

fn validated(
    word: u32,
    pc: u64,
    expected: Instruction,
    actual: Instruction,
) -> Result<A64Insn, DecodeGap> {
    if actual != expected {
        return Err(DecodeGap::Inconsistent);
    }
    let [a, b, c, _] = actual.operands;
    let mut flow = Flow::Next;
    let mut operation = Operation::Control;
    let mut effects = Effects::default();
    match actual.opcode {
        Opcode::B | Opcode::BL => {
            let destination = target(pc, a, false)?;
            flow = if actual.opcode == Opcode::BL {
                effects.writes[0] = Some(register(S::X, 30, false)?);
                Flow::CallDirect(destination)
            } else {
                Flow::JumpDirect(destination)
            };
        }
        Opcode::Bcc(_) => {
            effects.reads_flags = true;
            flow = Flow::Conditional(target(pc, a, false)?);
        }
        Opcode::CBZ | Opcode::CBNZ | Opcode::TBZ | Opcode::TBNZ => {
            effects.reads[0] = Some(operand_register(a)?);
            let offset = if matches!(actual.opcode, Opcode::TBZ | Opcode::TBNZ) {
                c
            } else {
                b
            };
            flow = Flow::Conditional(target(pc, offset, false)?);
        }
        Opcode::BR | Opcode::BLR | Opcode::RET => {
            let r = operand_register(a)?;
            let RegisterName::Gpr(n) = r.name else {
                return Err(DecodeGap::Inconsistent);
            };
            effects.reads[0] = Some(r);
            flow = match actual.opcode {
                Opcode::BR => Flow::JumpRegister(n),
                Opcode::BLR => {
                    effects.writes[0] = Some(register(S::X, 30, false)?);
                    Flow::CallRegister(n)
                }
                _ => Flow::Return,
            };
        }
        Opcode::ADR | Opcode::ADRP => {
            let dst = operand_register(a)?;
            let address = target(pc, b, actual.opcode == Opcode::ADRP)?;
            operation = Operation::Address { dst, address };
            effects.writes[0] = write(dst);
        }
        Opcode::MOVN | Opcode::MOVZ | Opcode::MOVK => {
            let dst = operand_register(a)?;
            let O::ImmShift(imm, shift) = b else {
                return Err(DecodeGap::Inconsistent);
            };
            let kind = match actual.opcode {
                Opcode::MOVN => WideMove::Not,
                Opcode::MOVZ => WideMove::Zero,
                _ => {
                    effects.reads[0] = Some(dst);
                    WideMove::Keep
                }
            };
            operation = Operation::WideMove {
                kind,
                dst,
                imm,
                shift,
            };
            effects.writes[0] = write(dst);
        }
        Opcode::ORR => {
            let dst = operand_register(a)?;
            let O::RegShift(ShiftStyle::LSL, 0, size, n) = c else {
                return Err(DecodeGap::Inconsistent);
            };
            let src = register(size, n, false)?;
            operation = Operation::Copy { dst, src };
            effects.reads = [Some(operand_register(b)?), Some(src), None];
            effects.writes[0] = write(dst);
        }
        Opcode::ADD | Opcode::SUB => {
            let dst = operand_register(a)?;
            let src = operand_register(b)?;
            let imm = match c {
                O::Immediate(n) => u64::from(n),
                O::ImmShift(n, 12) => u64::from(n) << 12,
                _ => return Err(DecodeGap::Inconsistent),
            };
            operation = Operation::AddImmediate {
                dst,
                src,
                imm,
                subtract: actual.opcode == Opcode::SUB,
            };
            effects.reads[0] = Some(src);
            effects.writes[0] = write(dst);
        }
        Opcode::LDR | Opcode::STR | Opcode::LDP | Opcode::STP => {
            let pair = matches!(actual.opcode, Opcode::LDP | Opcode::STP);
            let load = matches!(actual.opcode, Opcode::LDR | Opcode::LDP);
            let regs = [
                Some(operand_register(a)?),
                if pair {
                    Some(operand_register(b)?)
                } else {
                    None
                },
            ];
            let (base, offset, mode) = match if pair { c } else { b } {
                O::RegPreIndex(n, offset, wb) => (
                    register(S::X, n, true)?,
                    offset,
                    if wb {
                        AddressMode::PreIndex
                    } else {
                        AddressMode::Offset
                    },
                ),
                O::RegPostIndex(n, offset) => {
                    (register(S::X, n, true)?, offset, AddressMode::PostIndex)
                }
                _ => return Err(DecodeGap::Inconsistent),
            };
            effects.reads[0] = Some(base);
            if load {
                effects.writes[0] = regs[0].and_then(write);
                effects.writes[1] = regs[1].and_then(write);
            } else {
                effects.reads[1] = regs[0];
                effects.reads[2] = regs[1];
            }
            if mode != AddressMode::Offset {
                effects.writes[2] = Some(base);
            }
            operation = Operation::Memory {
                load,
                regs,
                base,
                offset,
                mode,
            };
        }
        Opcode::HINT => operation = Operation::Nop,
        _ => return Err(DecodeGap::Inconsistent),
    }
    Ok(A64Insn {
        word,
        flow,
        operation,
        effects,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_typed_opcode_operand_width_role_and_shift_are_rejected() {
        // Exercise the actual boundary immediately after the library decoder. Both unused
        // operand slots and distinctions hidden by formatted aliases must match the raw word.
        let word = 0x2a0103e0;
        let expected = prefilter(word).unwrap();
        assert!(validated(word, 0x1000, expected, expected).is_ok());
        let mut mutations = Vec::new();
        let mut wrong = expected;
        wrong.opcode = Opcode::ADD;
        mutations.push(wrong);
        for operand in [
            O::RegShift(ShiftStyle::LSR, 0, S::W, 1),
            O::RegShift(ShiftStyle::LSL, 1, S::W, 1),
            O::RegShift(ShiftStyle::LSR, 1, S::W, 1),
            O::RegShift(ShiftStyle::LSL, 0, S::X, 1),
            O::Register(S::W, 1),
        ] {
            wrong = expected;
            wrong.operands[2] = operand;
            mutations.push(wrong);
        }
        wrong = expected;
        wrong.operands[1] = O::RegisterOrSP(S::W, 31);
        mutations.push(wrong);
        wrong = expected;
        wrong.operands[3] = O::Immediate(0);
        mutations.push(wrong);
        for actual in mutations {
            assert_eq!(
                validated(word, 0x1000, expected, actual),
                Err(DecodeGap::Inconsistent)
            );
        }
        let branch = prefilter(0x94000000).unwrap();
        let mut wrong = branch;
        wrong.operands[0] = O::PCOffset(4);
        assert_eq!(
            validated(0x94000000, 0x1000, branch, wrong),
            Err(DecodeGap::Inconsistent)
        );
    }
}
