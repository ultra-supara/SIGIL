//! Decoded, entry-aligned stubs joined to the exact same-slice slot witness.
use super::{bind::MachImportWitness, image::MachCodeView};
use crate::code::{
    aarch64::decode::{decode_a64, AddressMode, Flow, Operation, RegisterName, Width},
    reader::Reader,
    Run, Work,
};
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
use sigil_model::Arch;
use std::collections::BTreeMap;

pub(crate) fn contains(v: &MachCodeView, at: u64) -> bool {
    v.sections
        .iter()
        .any(|s| s.flags & 0xff == 8 && s.vm.contains(&at))
}
pub(crate) fn resolve_stub(
    v: &MachCodeView,
    entry: u64,
    slots: &BTreeMap<u64, MachImportWitness>,
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> Result<MachImportWitness, &'static str> {
    let s = v
        .sections
        .iter()
        .find(|s| s.flags & 0xff == 8 && s.vm.contains(&entry))
        .ok_or("target outside stub section")?;
    let width = u64::from(s.reserved2);
    if v.file_type == 1
        || !s.file_backed
        || s.reserved3 != 0
        || width == 0
        || !(s.vm.end - s.vm.start).is_multiple_of(width)
        || !(entry - s.vm.start).is_multiple_of(width)
    {
        return Err("invalid stub entry or reserved fields");
    }
    let bytes = v.read_code(reader, entry, width).map_err(|e| {
        super::read_error(e, reader, run);
        "stub read refused"
    })?;
    let slot = match v.arch {
        Arch::Aarch64 if width == 12 => {
            if !run.charge(Work::Instructions, 3) {
                return Err("instruction limit");
            }
            let word = |n| u32::from_le_bytes(bytes[n..n + 4].try_into().unwrap_or_default());
            // Require ADRP, 64-bit unsigned-offset LDR, BR, and matching decoded operands.
            if word(0) & 0x9f000000 != 0x90000000 || word(4) & 0xffc00000 != 0xf9400000 {
                return Err("unrecognized arm64 stub");
            }
            let a = decode_a64(word(0), entry).map_err(|_| "ADRP decode")?;
            let l = decode_a64(word(4), entry + 4).map_err(|_| "LDR decode")?;
            let b = decode_a64(word(8), entry + 8).map_err(|_| "BR decode")?;
            match (a.operation, l.operation, b.flow) {
                (
                    Operation::Address { dst, address },
                    Operation::Memory {
                        load: true,
                        regs: [Some(out), None],
                        base,
                        offset,
                        mode: AddressMode::Offset,
                    },
                    Flow::JumpRegister(n),
                ) if dst == base
                    && dst.width == Width::X
                    && out.width == Width::X
                    && out.name == RegisterName::Gpr(n)
                    && matches!(dst.name, RegisterName::Gpr(16 | 17))
                    && matches!(out.name, RegisterName::Gpr(16 | 17)) =>
                {
                    address
                        .checked_add_signed(i64::from(offset))
                        .ok_or("slot overflow")?
                }
                _ => return Err("arm64 stub register mismatch"),
            }
        }
        Arch::X86_64 if matches!(width, 6 | 7) => {
            if !run.charge(Work::Instructions, 1) {
                return Err("instruction limit");
            }
            // Only the documented BND prefix is admitted; segment/REX/address-size variants
            // cannot silently change the slot or operand width.
            if !(bytes.starts_with(&[0xff, 0x25]) || bytes.starts_with(&[0xf2, 0xff, 0x25])) {
                return Err("unrecognized x86 stub prefix");
            }
            let mut d = Decoder::with_ip(64, &bytes, entry, DecoderOptions::NONE);
            let i = d.decode();
            if i.is_invalid()
                || i.len() as u64 != width
                || i.mnemonic() != Mnemonic::Jmp
                || i.op0_kind() != OpKind::Memory
                || !i.is_ip_rel_memory_operand()
                || i.memory_base() != Register::RIP
                || i.memory_index() != Register::None
                || i.memory_size().size() != 8
            {
                return Err("unrecognized x86 stub");
            }
            let target = i.ip_rel_memory_address();
            let next = entry.checked_add(width).ok_or("stub address overflow")?;
            let delta = target.wrapping_sub(next) as i64;
            next.checked_add_signed(delta)
                .filter(|n| *n == target)
                .ok_or("stub displacement overflow")?
        }
        _ => return Err("unsupported stub width or architecture"),
    };
    let w = slots
        .get(&slot)
        .ok_or("stub has no unique validated slot")?;
    let library = match &w.library {
        sigil_model::MachOLibrary::Dylib { name: Some(n), .. } => n.as_bytes().len() as u64,
        _ => 0,
    };
    if !run.charge(Work::Names, w.symbol.as_bytes().len() as u64 + library) {
        return Err("name limit");
    }
    Ok(w.clone())
}
