//! Bounded slot witnesses. Names alone never establish an address; every retained witness
//! also belongs to the caller's exact same-slice import inventory. No fixup is applied.
use super::image::MachCodeView;
use crate::code::reader::{read_slice, Reader};
use crate::code::{Run, Work};
use sigil_model::{MachOImport, MachOLibrary, UntrustedText};
use std::collections::{BTreeMap, BTreeSet};

const MAX_METADATA: u64 = 16 << 20;
const MAX_NAME: usize = 65_536;
type Result<T> = std::result::Result<T, &'static str>;
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MachImportWitness {
    pub symbol: UntrustedText,
    pub library: MachOLibrary,
    pub weak: bool,
    pub slot_vmaddr: u64,
}
fn gap(run: &mut Run, why: &str) {
    run.gap(format!("code: Mach-O bindings: {why}"));
}
fn read(v: &MachCodeView, r: &mut Reader<'_>, run: &mut Run, at: u64, len: u64) -> Result<Vec<u8>> {
    if run.stopped() {
        return Err("work stopped");
    }
    if len > MAX_METADATA {
        return Err("metadata byte limit");
    }
    read_slice(r, v.window, at, len).map_err(|e| {
        run.refusal(e, "Mach-O bindings", r);
        "metadata read refused"
    })
}
fn u16le(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(at..at.checked_add(2).ok_or("offset overflow")?)
            .ok_or("truncated u16")?
            .try_into()
            .map_err(|_| "integer width")?,
    ))
}
fn u32le(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..at.checked_add(4).ok_or("offset overflow")?)
            .ok_or("truncated u32")?
            .try_into()
            .map_err(|_| "integer width")?,
    ))
}
fn u64le(b: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(at..at.checked_add(8).ok_or("offset overflow")?)
            .ok_or("truncated u64")?
            .try_into()
            .map_err(|_| "integer width")?,
    ))
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or("address overflow")
}
fn charge(run: &mut Run, w: Work, n: u64) -> Result<()> {
    if run.charge(w, n) {
        Ok(())
    } else {
        Err("work limit")
    }
}
fn name(b: &[u8], at: usize, run: &mut Run) -> Result<UntrustedText> {
    let rest = b.get(at..).ok_or("name offset")?;
    for (n, &byte) in rest.iter().take(MAX_NAME + 1).enumerate() {
        charge(run, Work::Names, 1)?;
        if byte == 0 {
            if n == 0 {
                return Err("empty name");
            }
            return Ok(UntrustedText::from_bytes(rest[..n].to_vec()));
        }
    }
    Err("oversized or unterminated name")
}
#[derive(Default)]
struct Commands {
    dylibs: Vec<Option<UntrustedText>>,
    info: Vec<[(u32, u32); 2]>,
    chained: Vec<(u32, u32)>,
    symtab: Vec<[u32; 4]>,
    dysym: Vec<[u32; 2]>,
}
fn commands(v: &MachCodeView, r: &mut Reader<'_>, run: &mut Run) -> Result<Commands> {
    let h = read(v, r, run, 0, 32)?;
    let n = u32le(&h, 16)?;
    let b = read(v, r, run, 32, u32le(&h, 20)?.into())?;
    let mut out = Commands::default();
    let mut at = 0;
    for _ in 0..n {
        charge(run, Work::References, 1)?;
        let len = u32le(&b, at + 4)? as usize;
        if len < 8 || !len.is_multiple_of(8) {
            return Err("load command size");
        }
        let c = b
            .get(at..at.checked_add(len).ok_or("command overflow")?)
            .ok_or("load command bounds")?;
        match u32le(c, 0)? {
            0xc | 0x80000018 | 0x8000001f | 0x80000023 | 0x20 => {
                if len < 24 {
                    return Err("dylib command");
                }
                let off = u32le(c, 8)? as usize;
                if off < 24 {
                    return Err("dylib name offset");
                }
                out.dylibs.push(Some(name(c, off, run)?));
            }
            0x22 | 0x80000022 => {
                if len != 48 {
                    return Err("dyld info size");
                }
                if u32le(c, 28)? != 0 {
                    return Err("weak bind stream unsupported");
                }
                out.info.push([
                    (u32le(c, 16)?, u32le(c, 20)?),
                    (u32le(c, 32)?, u32le(c, 36)?),
                ]);
            }
            0x80000034 => {
                if len != 16 {
                    return Err("chained command size");
                }
                out.chained.push((u32le(c, 8)?, u32le(c, 12)?));
            }
            2 => {
                if len != 24 {
                    return Err("symtab command size");
                }
                out.symtab
                    .push([u32le(c, 8)?, u32le(c, 12)?, u32le(c, 16)?, u32le(c, 20)?]);
            }
            0xb => {
                if len != 80 {
                    return Err("dysymtab command size");
                }
                out.dysym.push([u32le(c, 56)?, u32le(c, 60)?]);
            }
            _ => {}
        }
        at += len;
    }
    if at != b.len() {
        return Err("load command count");
    }
    Ok(out)
}
fn library(ordinal: i64, dylibs: &[Option<UntrustedText>], run: &mut Run) -> Result<MachOLibrary> {
    if ordinal > 0 {
        if let Some(Some(name)) = usize::try_from(ordinal - 1)
            .ok()
            .and_then(|i| dylibs.get(i))
        {
            charge(run, Work::Names, name.as_bytes().len() as u64)?;
        }
    }
    Ok(match ordinal {
        0 => MachOLibrary::SelfImage,
        -1 => MachOLibrary::MainExecutable,
        -2 => MachOLibrary::FlatLookup,
        -3 => MachOLibrary::WeakLookup,
        n if n > 0 => MachOLibrary::Dylib {
            ordinal: u32::try_from(n).map_err(|_| "library ordinal")?,
            name: dylibs
                .get(usize::try_from(n - 1).map_err(|_| "library ordinal")?)
                .ok_or("library ordinal beyond dylibs")?
                .clone(),
        },
        _ => return Err("unknown library ordinal"),
    })
}
/// A rejected address stays poisoned even if a later claim happens to repeat its first name.
#[derive(Default)]
struct Claims {
    slots: BTreeMap<u64, MachImportWitness>,
    seen: BTreeSet<u64>,
}
impl Claims {
    fn keep(
        &mut self,
        slot: u64,
        import: &MachOImport,
        inventory: &BTreeSet<&MachOImport>,
        run: &mut Run,
    ) -> Result<()> {
        let before = self
            .seen
            .range(..slot)
            .next_back()
            .copied()
            .filter(|a| slot - *a < 8);
        let after = self
            .seen
            .range(slot..)
            .next()
            .copied()
            .filter(|a| *a - slot < 8);
        self.seen.insert(slot);
        if before.is_some() || after.is_some() {
            for address in before.into_iter().chain(after).chain([slot]) {
                self.slots.remove(&address);
            }
            gap(run, "duplicate or overlapping slot");
            return Ok(());
        }
        if !inventory.contains(import) {
            gap(run, "binding absent from same-slice import inventory");
            return Ok(());
        }
        let library_bytes = match &import.library {
            MachOLibrary::Dylib { name: Some(n), .. } => n.as_bytes().len(),
            _ => 0,
        };
        charge(
            run,
            Work::Names,
            (import.name.as_bytes().len() + library_bytes) as u64,
        )?;
        self.slots.insert(
            slot,
            MachImportWitness {
                symbol: import.name.clone(),
                library: import.library.clone(),
                weak: import.weak,
                slot_vmaddr: slot,
            },
        );
        Ok(())
    }
}
/// Unique file-backed translation, including writable/nonsection slots. The image builder
/// has already proved disjoint VM and file extents, so an ordinal's translation is unique.
fn slot(v: &MachCodeView, segment: usize, offset: u64) -> Result<(u64, u64)> {
    let s = v.segments.get(segment).ok_or("segment ordinal")?;
    if add(offset, 8)? > s.relative.end - s.relative.start
        || add(offset, 8)? > s.vm.end - s.vm.start
    {
        return Err("slot outside file-backed segment");
    }
    let vm = add(s.vm.start, offset)?;
    let file = add(s.relative.start, offset)?;
    Ok((vm, file))
}
/// Strict finite LEB decoding: at most ten bytes; the tenth must contain only valid bits.
fn uleb(b: &[u8], at: &mut usize) -> Result<u64> {
    let mut n = 0;
    for shift in (0..70).step_by(7) {
        let c = *b.get(*at).ok_or("truncated ULEB")?;
        *at += 1;
        if shift == 63 && c & 0xfe != 0 {
            return Err("overlong ULEB");
        }
        n |= u64::from(c & 0x7f) << shift;
        if c & 0x80 == 0 {
            return Ok(n);
        }
    }
    Err("overlong ULEB")
}
fn sleb(b: &[u8], at: &mut usize) -> Result<i64> {
    let mut n = 0u64;
    for shift in (0..70).step_by(7) {
        let c = *b.get(*at).ok_or("truncated SLEB")?;
        *at += 1;
        if shift == 63 && !matches!(c, 0 | 0x7f) {
            return Err("overlong SLEB");
        }
        n |= u64::from(c & 0x7f) << shift;
        if c & 0x80 == 0 {
            let bits = shift + 7;
            if bits < 64 && c & 0x40 != 0 {
                n |= u64::MAX << bits;
            }
            return Ok(n as i64);
        }
    }
    Err("overlong SLEB")
}
#[allow(clippy::too_many_arguments)]
fn classic(
    v: &MachCodeView,
    b: &[u8],
    lazy: bool,
    c: &Commands,
    inventory: &BTreeSet<&MachOImport>,
    claims: &mut Claims,
    run: &mut Run,
) -> Result<()> {
    let (mut at, mut ordinal, mut symbol, mut weak, mut segment, mut offset, mut addend, mut kind) =
        (0, 0, None, false, None, 0u64, 0i64, 1u8);
    let mut ended = false;
    while at < b.len() {
        ended = false;
        charge(run, Work::Relocations, 1)?;
        let byte = b[at];
        at += 1;
        let imm = byte & 15;
        let mut count = 0;
        let mut skip = 0;
        match byte & 0xf0 {
            0 => {
                if imm != 0 {
                    return Err("invalid DONE");
                }
                if !lazy {
                    return Ok(());
                }
                ended = true;
                segment = None;
                offset = 0;
                addend = 0;
                kind = 1;
            }
            0x10 => ordinal = i64::from(imm),
            0x20 => {
                ordinal = i64::from(
                    i32::try_from(uleb(b, &mut at)?).map_err(|_| "library ordinal overflow")?,
                );
            }
            0x30 => {
                ordinal = if imm == 0 {
                    0
                } else {
                    i64::from((0xf0 | imm) as i8)
                }
            }
            0x40 => {
                if imm & !1 != 0 {
                    return Err("unsupported symbol flags");
                }
                let n = name(b, at, run)?;
                at += n.as_bytes().len() + 1;
                symbol = Some(n);
                weak = imm & 1 != 0;
            }
            0x50 => kind = imm,
            0x60 => addend = sleb(b, &mut at)?,
            0x70 => {
                segment = Some(imm as usize);
                offset = uleb(b, &mut at)?;
            }
            0x80 => offset = add(offset, uleb(b, &mut at)?)?,
            0x90 if imm == 0 => count = 1,
            0xa0 if imm == 0 => {
                count = 1;
                skip = uleb(b, &mut at)?;
            }
            0xb0 => {
                count = 1;
                skip = u64::from(imm) * 8;
            }
            0xc0 if imm == 0 => {
                count = uleb(b, &mut at)?;
                skip = uleb(b, &mut at)?;
            }
            _ => return Err("unsupported bind opcode"),
        }
        if count > 0 {
            if kind != 1 || addend != 0 {
                return Err("unsupported bind type or nonzero addend");
            }
            let symbol = symbol.as_ref().ok_or("bind without symbol")?;
            let segment = segment.ok_or("bind without segment")?;
            let library = library(ordinal, &c.dylibs, run)?;
            for _ in 0..count {
                charge(run, Work::Slots, 1)?;
                let (vm, _) = slot(v, segment, offset)?;
                let library_bytes = match &library {
                    MachOLibrary::Dylib { name: Some(n), .. } => n.as_bytes().len(),
                    _ => 0,
                };
                charge(
                    run,
                    Work::Names,
                    (symbol.as_bytes().len() + library_bytes) as u64,
                )?;
                claims.keep(
                    vm,
                    &MachOImport {
                        name: symbol.clone(),
                        library: library.clone(),
                        weak,
                    },
                    inventory,
                    run,
                )?;
                offset = add(offset, add(8, skip)?)?;
            }
        }
    }
    if lazy && ended {
        Ok(())
    } else {
        Err("bind stream lacks DONE")
    }
}
/// Failure is transactional for the binding source: unknown metadata can contain a later
/// conflicting claim. No partial map escapes an unvalidated stream or chain.
pub(crate) fn read_bindings(
    v: &MachCodeView,
    r: &mut Reader<'_>,
    run: &mut Run,
) -> BTreeMap<u64, MachImportWitness> {
    if run.stopped() || v.file_type == 1 {
        return BTreeMap::new();
    }
    match inner(v, r, run) {
        Ok(map) => map,
        Err(why) => {
            gap(run, why);
            BTreeMap::new()
        }
    }
}
fn inner(
    v: &MachCodeView,
    r: &mut Reader<'_>,
    run: &mut Run,
) -> Result<BTreeMap<u64, MachImportWitness>> {
    charge(run, Work::References, v.imports.len() as u64)?;
    let inventory = v.imports.iter().collect();
    let c = commands(v, r, run)?;
    let mut claims = Claims::default();
    match (c.info.as_slice(), c.chained.as_slice()) {
        ([streams], []) => {
            for ((at, len), lazy) in [(streams[0], false), (streams[1], true)] {
                if len > 0 {
                    let b = read(v, r, run, at.into(), len.into())?;
                    classic(v, &b, lazy, &c, &inventory, &mut claims, run)?;
                }
            }
        }
        ([], [(at, len)]) => {
            let b = read(v, r, run, (*at).into(), (*len).into())?;
            chained(v, r, &b, &c, &inventory, &mut claims, run)?;
        }
        ([], []) => {
            if !c.dylibs.is_empty() {
                return Err("no supported binding source");
            }
        }
        _ => return Err("duplicate or competing binding sources"),
    }
    indirect(v, r, &c, &mut claims, run)?;
    Ok(claims.slots)
}
#[allow(clippy::too_many_arguments)]
fn chained(
    v: &MachCodeView,
    r: &mut Reader<'_>,
    b: &[u8],
    c: &Commands,
    inventory: &BTreeSet<&MachOImport>,
    claims: &mut Claims,
    run: &mut Run,
) -> Result<()> {
    if u32le(b, 0)? != 0 || u32le(b, 24)? != 0 {
        return Err("unsupported fixups version or compressed symbols");
    }
    let starts = u32le(b, 4)? as usize;
    let imports = u32le(b, 8)? as usize;
    let symbols = u32le(b, 12)? as usize;
    let count = u32le(b, 16)? as usize;
    let format = u32le(b, 20)?;
    let width = match format {
        1 => 4,
        2 => 8,
        3 => 16,
        _ => return Err("unsupported chained import format"),
    };
    let import_end = imports
        .checked_add(count.checked_mul(width).ok_or("import size overflow")?)
        .ok_or("import size overflow")?;
    if starts < 28
        || imports < 28
        || symbols < import_end
        || symbols > b.len()
        || import_end > b.len()
    {
        return Err("fixup table bounds");
    }
    let mut table = Vec::new();
    for i in 0..count {
        charge(run, Work::Relocations, 1)?;
        let at = imports + i * width;
        let (ordinal, weak, off, addend) = if format == 3 {
            let raw = u64le(b, at)?;
            if raw >> 17 & 0x7fff != 0 {
                return Err("chained import reserved bits");
            }
            let ord = raw as u16;
            (
                if ord > 0xfff0 {
                    i64::from(ord as i16)
                } else {
                    i64::from(ord)
                },
                raw >> 16 & 1 != 0,
                (raw >> 32) as usize,
                u64le(b, at + 8)? as i64,
            )
        } else {
            let raw = u32le(b, at)?;
            let ord = raw as u8;
            (
                if ord > 0xf0 {
                    i64::from(ord as i8)
                } else {
                    i64::from(ord)
                },
                raw >> 8 & 1 != 0,
                (raw >> 9) as usize,
                if format == 2 {
                    i64::from(u32le(b, at + 4)? as i32)
                } else {
                    0
                },
            )
        };
        let import = MachOImport {
            name: name(
                b,
                symbols.checked_add(off).ok_or("symbol offset overflow")?,
                run,
            )?,
            library: library(ordinal, &c.dylibs, run)?,
            weak,
        };
        table.push((import, addend));
    }
    let segments = u32le(b, starts)? as usize;
    if segments != v.segments.len() {
        return Err("chained segment count");
    }
    let array_end = starts
        .checked_add(4)
        .and_then(|n| n.checked_add(segments.checked_mul(4)?))
        .ok_or("starts overflow")?;
    if array_end > imports {
        return Err("starts table bounds");
    }
    let mut ranges = BTreeMap::new();
    for (index, segment) in v.segments.iter().enumerate() {
        charge(run, Work::Relocations, 1)?;
        let off = u32le(b, starts + 4 + index * 4)? as usize;
        if off == 0 {
            continue;
        }
        let at = starts.checked_add(off).ok_or("segment starts overflow")?;
        let size = u32le(b, at)? as usize;
        let end = at.checked_add(size).ok_or("segment starts overflow")?;
        if at < array_end
            || end > imports
            || size < 22
            || ranges
                .range(..=at)
                .next_back()
                .is_some_and(|(_, z)| at < *z)
            || ranges.range(at..).next().is_some_and(|(a, _)| *a < end)
        {
            return Err("overlapping or invalid segment starts");
        }
        ranges.insert(at, end);
        let page = u64::from(u16le(b, at + 4)?);
        let pointer = u16le(b, at + 6)?;
        // These formats share the specified 4-byte stride and unauthenticated 64-bit layout.
        if !matches!(pointer, 2 | 6) {
            return Err("unsupported chained pointer format (including authenticated forms)");
        }
        if !matches!(page, 0x1000 | 0x4000) || u32le(b, at + 16)? != 0 {
            return Err("chained page size or max pointer");
        }
        if add(v.image_base.ok_or("missing image base")?, u64le(b, at + 8)?)? != segment.vm.start {
            return Err("chained segment mapping");
        }
        let pages = u16le(b, at + 20)? as usize;
        if size != 22 + pages * 2
            || pages as u64 != (segment.vm.end - segment.vm.start).div_ceil(page)
        {
            return Err("chained page count or starts size");
        }
        for p in 0..pages {
            charge(run, Work::Relocations, 1)?;
            let first = u16le(b, at + 22 + p * 2)?;
            if first == 0xffff {
                continue;
            }
            if first & 0x8000 != 0 {
                return Err("multiple chained starts unsupported");
            }
            let page_offset = p as u64 * page;
            let mut within = u64::from(first);
            let mut visited = BTreeSet::new();
            loop {
                charge(run, Work::Slots, 1)?;
                if !within.is_multiple_of(4) || add(within, 8)? > page || !visited.insert(within) {
                    return Err("cyclic, unaligned or page-escaping chain");
                }
                let (vm, file) = slot(v, index, add(page_offset, within)?)?;
                let word = read(v, r, run, file, 8)?;
                let raw = u64le(&word, 0)?;
                let next = (raw >> 51) & 0xfff;
                if raw >> 63 != 0 {
                    if raw >> 32 & 0x7ffff != 0 {
                        return Err("chained pointer reserved bits");
                    }
                    let (import, addend) = table
                        .get((raw & 0xffffff) as usize)
                        .ok_or("chained ordinal beyond import table")?;
                    if addend.checked_add(((raw >> 24) & 0xff) as i64) != Some(0) {
                        return Err("nonzero chained addend");
                    }
                    claims.keep(vm, import, inventory, run)?;
                } else if raw >> 44 & 0x7f != 0 {
                    return Err("chained rebase reserved bits");
                }
                if next == 0 {
                    break;
                }
                let step = next * 4;
                if step < 8 {
                    return Err("overlapping chained pointers");
                }
                within = add(within, step)?;
            }
        }
    }
    Ok(())
}
fn indirect(
    v: &MachCodeView,
    r: &mut Reader<'_>,
    c: &Commands,
    claims: &mut Claims,
    run: &mut Run,
) -> Result<()> {
    let sections: Vec<_> = v
        .sections
        .iter()
        .filter(|s| matches!(s.flags & 0xff, 6 | 7 | 8 | 0x10))
        .collect();
    if sections.is_empty() {
        return Ok(());
    }
    let ([sym], [dysym]) = (c.symtab.as_slice(), c.dysym.as_slice()) else {
        return Err("missing or duplicate symbol/indirect table");
    };
    let [symoff, nsyms, stroff, strsize] = *sym;
    let [indoff, nind] = *dysym;
    let symbols = read(v, r, run, symoff.into(), u64::from(nsyms) * 16)?;
    let strings = read(v, r, run, stroff.into(), strsize.into())?;
    let indirect = read(v, r, run, indoff.into(), u64::from(nind) * 4)?;
    let mut occupied = BTreeSet::new();
    for s in sections {
        let stub = s.flags & 0xff == 8;
        let width = if stub { u64::from(s.reserved2) } else { 8 };
        let len = s.vm.end - s.vm.start;
        if !s.file_backed
            || width == 0
            || !len.is_multiple_of(width)
            || (!stub && s.reserved2 != 0)
            || s.reserved3 != 0
        {
            return Err("indirect section type, width or reserved fields");
        }
        let count = len / width;
        if add(u64::from(s.reserved1), count)? > u64::from(nind) {
            return Err("indirect section index bounds");
        }
        for i in 0..count {
            charge(run, Work::Relocations, 1)?;
            let index = u64::from(s.reserved1) + i;
            if !occupied.insert(index) {
                return Err("overlapping indirect table ranges");
            }
            let raw = u32le(&indirect, index as usize * 4)?;
            let vm = add(s.vm.start, i * width)?;
            if raw & 0xc0000000 != 0 {
                if raw & 0x3fffffff != 0 || raw & 0x80000000 == 0 {
                    return Err("invalid local indirect index");
                }
                if !stub && claims.slots.remove(&vm).is_some() {
                    gap(run, "binding contradicts local indirect symbol");
                }
                continue;
            }
            if raw >= nsyms {
                return Err("indirect symbol index");
            }
            let at = raw as usize * 16;
            let ty = symbols[at + 4];
            let desc = u16le(&symbols, at + 6)?;
            if ty & 0xe0 != 0
                || ty & 0x0f != 1
                || symbols[at + 5] != 0
                || u64le(&symbols, at + 8)? != 0
            {
                return Err("indirect symbol is not undefined external");
            }
            let ordinal = match desc >> 8 {
                0xff => -1,
                0xfe => -2,
                n => i64::from(n),
            };
            let import = MachOImport {
                name: name(&strings, u32le(&symbols, at)? as usize, run)?,
                library: library(ordinal, &c.dylibs, run)?,
                weak: desc & 0x40 != 0,
            };
            if !stub {
                if let Some(w) = claims.slots.get(&vm) {
                    if w.symbol != import.name
                        || w.library != import.library
                        || w.weak != import.weak
                    {
                        claims.slots.remove(&vm);
                        gap(run, "binding disagrees with indirect symbol");
                    }
                }
            }
        }
    }
    Ok(())
}
