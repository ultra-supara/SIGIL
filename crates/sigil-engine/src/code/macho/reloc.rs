//! MH_OBJECT branch relocations, without dyld addresses or synthetic slots.
use super::image::MachCodeView;
use crate::code::{
    reader::{read_slice, Reader},
    Run, Work,
};
use sigil_model::{Arch, MachOImport, MachOLibrary, UntrustedText};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
const MAX: u64 = 16 << 20;
type Result<T> = std::result::Result<T, &'static str>;
fn read(v: &MachCodeView, r: &mut Reader<'_>, run: &mut Run, at: u64, n: u64) -> Result<Vec<u8>> {
    if n > MAX || run.stopped() {
        return Err("metadata limit");
    }
    read_slice(r, v.window, at, n).map_err(|e| {
        run.refusal(e, "Mach-O relocations", r);
        "read refused"
    })
}
fn u32le(b: &[u8], n: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(n..n.checked_add(4).ok_or("overflow")?)
            .ok_or("truncated word")?
            .try_into()
            .map_err(|_| "word")?,
    ))
}
#[derive(Default)]
pub(crate) struct Relocations {
    /// Relocation field address -> exact object import; opcode/addend checked by caller.
    pub branches: BTreeMap<u64, Rc<MachOImport>>,
    /// Every code relocation field, including rejected ones, poisons raw interpretation.
    pub fields: BTreeMap<u64, u64>,
    pub invalid: bool,
}
pub(crate) fn read_relocations(v: &MachCodeView, r: &mut Reader<'_>, run: &mut Run) -> Relocations {
    if v.file_type != 1 {
        return Relocations::default();
    }
    let mut out = Relocations::default();
    if let Err(why) = inner(v, r, run, &mut out) {
        out.invalid = true;
        out.branches.clear();
        run.gap(format!("code: Mach-O relocations: {why}"));
    }
    out
}
fn inner(v: &MachCodeView, r: &mut Reader<'_>, run: &mut Run, out: &mut Relocations) -> Result<()> {
    let h = read(v, r, run, 0, 32)?;
    let commands = read(v, r, run, 32, u32le(&h, 20)?.into())?;
    let mut table = None;
    let mut at = 0usize;
    for _ in 0..u32le(&h, 16)? {
        if !run.charge(Work::Relocations, 1) {
            return Err("work limit");
        }
        let len = u32le(&commands, at + 4)? as usize;
        let c = commands
            .get(at..at.checked_add(len).ok_or("overflow")?)
            .ok_or("command bounds")?;
        if u32le(c, 0)? == 2 {
            if len != 24 || table.is_some() {
                return Err("duplicate or invalid symbol table");
            }
            table = Some([u32le(c, 8)?, u32le(c, 12)?, u32le(c, 16)?, u32le(c, 20)?]);
        }
        at += len;
    }
    let Some([off, count, stroff, strsize]) = table else {
        return Err("missing symbol table");
    };
    let syms = read(v, r, run, off.into(), u64::from(count) * 16)?;
    let strings = read(v, r, run, stroff.into(), strsize.into())?;
    let inventory: BTreeSet<_> = v.imports.iter().collect();
    let mut poisoned = BTreeSet::new();
    for s in &v.sections {
        if s.relocations == 0 || !v.executable.iter().any(|e| e.relative == s.relative) {
            continue;
        }
        let raw = read(
            v,
            r,
            run,
            s.relocation_offset.into(),
            u64::from(s.relocations) * 8,
        )?;
        for rec in raw.as_chunks::<8>().0 {
            if !run.charge(Work::Relocations, 1) {
                return Err("work limit");
            }
            let a = u32le(rec, 0)?;
            let info = u32le(rec, 4)?;
            if a & 0x80000000 != 0 {
                return Err("scattered relocation");
            }
            let field = v
                .window
                .base
                .checked_add(s.relative.start)
                .and_then(|n| n.checked_add(u64::from(a)))
                .ok_or("address overflow")?;
            let len = 1u64 << ((info >> 25) & 3);
            if u64::from(a)
                .checked_add(len)
                .is_none_or(|end| end > s.relative.end - s.relative.start)
            {
                return Err("field outside section");
            }
            if let Some(previous) = out.fields.insert(field, len) {
                out.fields.insert(field, previous.max(len));
                out.branches.remove(&field);
                poisoned.insert(field);
                run.gap(format!(
                    "code: Mach-O relocation at {field:#x}: duplicate relocation field"
                ));
                continue;
            }
            let index = info & 0xffffff;
            let kind = info >> 28;
            if info & (1 << 24) == 0
                || info & (1 << 27) == 0
                || len != 4
                || kind != 2
                || index >= count
            {
                run.gap(format!("code: Mach-O relocation at {field:#x}: unsupported branch relocation type, size or symbol"));
                continue;
            }
            let sym = &syms[index as usize * 16..index as usize * 16 + 16];
            let desc = u16::from_le_bytes([sym[6], sym[7]]);
            if sym[4] & 0xe0 != 0
                || sym[4] & 0x0f != 1
                || sym[5] != 0
                || desc & 0xc0 != 0
                || sym[8..16] != [0; 8]
            {
                run.gap(format!("code: Mach-O relocation at {field:#x}: branch symbol is not strong undefined external"));
                continue;
            }
            let rest = strings
                .get(u32le(sym, 0)? as usize..)
                .ok_or("name offset")?;
            let mut end = None;
            for (i, b) in rest.iter().take(65537).enumerate() {
                if !run.charge(Work::Names, 1) {
                    return Err("name limit");
                }
                if *b == 0 {
                    end = Some(i);
                    break;
                }
            }
            let end = end.filter(|n| *n > 0).ok_or("empty or unterminated name")?;
            let import = MachOImport {
                name: UntrustedText::from_bytes(rest[..end].to_vec()),
                library: MachOLibrary::Unbound,
                weak: false,
            };
            if !inventory.contains(&import) {
                run.gap(format!("code: Mach-O relocation at {field:#x}: branch import absent from exact slice inventory"));
                continue;
            }
            if !matches!(v.arch, Arch::Aarch64 | Arch::X86_64) {
                return Err("unsupported architecture");
            }
            if !poisoned.contains(&field) {
                out.branches.insert(field, Rc::new(import));
            }
        }
    }
    Ok(())
}
