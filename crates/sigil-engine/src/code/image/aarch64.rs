//! A private same-fd ELF64/AArch64 adapter. Every metadata and code read uses read_slice.
//! Section tables are required: sectionless/extended tables and packed relocations stay gaps.
//! No runtime binding is inferred from a slot or symbolic object relocation.
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use super::{FdeAt, Image, Kind, Region};
use crate::code::aarch64::decode::{decode_a64, Operation, RegisterName, Width};
use crate::code::aarch64::value::{self, Mapping};
use crate::code::reader::{read_slice, Reader, SliceWindow};
use crate::code::{fde, Run, Work, FDE_BYTES};

// ADRP always uses 4KiB pages. Loader alias/permission proof must conservatively cover
// arm64's 4/16/64KiB granules; an unstated runtime granule cannot justify readonly bytes.
const LOADER_PAGE: u64 = 65_536;
pub(crate) const CALL26: u32 = 283;
pub(crate) const JUMP26: u32 = 282;
pub(crate) const ADR_GOT_PAGE: u32 = 311;
pub(crate) const LD64_GOT_LO12: u32 = 312;
pub(crate) const ADR_PAGE: u32 = 275;
pub(crate) const ADD_LO12: u32 = 277;
pub(crate) const GLOB_DAT: u32 = 1025;
pub(crate) const JUMP_SLOT: u32 = 1026;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImportWitness {
    pub name: Rc<[u8]>,
    pub relocation: u32,
    /// A real linked GOT slot, or the object instruction's absolute file offset.
    pub at: u64,
    pub weak: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Symbol {
    pub name: Rc<[u8]>,
    pub undefined: bool,
    pub weak: bool,
    pub global: bool,
    pub address: Option<u64>,
    pub section: usize,
    pub section_bounds: Option<(u64, u64)>,
}
#[derive(Debug, Clone)]
pub(crate) struct Relocation {
    pub kind: u32,
    pub addend: i64,
    pub symbol: Option<Symbol>,
    /// Symbol identity includes its symbol table; equal spelling is insufficient for pairs.
    pub identity: (usize, u32),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Branch {
    Import(ImportWitness),
    Internal(u64),
}
#[derive(Debug)]
pub(crate) struct A64ElfImage {
    pub window: SliceWindow,
    pub object: bool,
    pub code: Vec<Region>,
    pub mappings: Vec<Mapping>,
    pub fdes: Vec<(u64, u64)>,
    pub slots: BTreeMap<u64, ImportWitness>,
    pub stubs: BTreeMap<u64, ImportWitness>,
    /// None permanently poisons duplicate/composed/unsupported relocations.
    pub relocs: BTreeMap<u64, Option<Relocation>>,
    pub excluded: Vec<(u64, u64)>,
    /// Exact-name section hints for PLT discovery, not permission to skip searching bytes.
    pub plt: Vec<(u64, u64)>,
    /// Only complete byte-validated ABI scaffolding; no section-name-only exclusion.
    plt_verified: Vec<(u64, u64)>,
    bounds: Image,
}
impl A64ElfImage {
    pub fn verified_plt_instruction(&self, pc: u64) -> bool {
        self.plt_verified
            .get(self.plt_verified.partition_point(|r| r.1 <= pc))
            .is_some_and(|r| r.0 <= pc && pc.checked_add(4).is_some_and(|end| end <= r.1))
    }
    pub fn executable(&self, start: u64, end: u64) -> bool {
        start < end
            && self
                .code
                .get(self.code.partition_point(|r| r.end <= start))
                .is_some_and(|r| r.holds(start, end))
    }
    pub fn excluded(&self, start: u64, end: u64) -> bool {
        self.excluded
            .get(self.excluded.partition_point(|r| r.1 <= start))
            .is_some_and(|r| r.0 < end)
    }
    pub fn function(&self, pc: u64) -> FdeAt {
        match self.bounds.fde_at(pc) {
            FdeAt::One((start, end))
                if self
                    .bounds
                    .fde_shared
                    .get(self.bounds.fde_shared.partition_point(|r| r.1 <= start))
                    .is_some_and(|r| r.0 < end) =>
            {
                FdeAt::Overlap
            }
            result => result,
        }
    }
    pub fn values<'a>(
        &'a self,
        run: &mut Run,
    ) -> std::result::Result<value::Image<'a>, value::Failure> {
        value::Image::new(self.window, &self.mappings, run)
    }
    /// Use this entry point for ELF value analysis. Object instruction relocations are not
    /// applied by the loader yet; their raw immediate bits cannot establish argument values.
    pub fn solve_values(
        &self,
        cfg: &crate::code::aarch64::Cfg,
        reader: &mut Reader<'_>,
        run: &mut Run,
    ) -> std::result::Result<value::Values, value::Failure> {
        if self.excluded(cfg.entry, cfg.end) {
            run.gap(format!(
                "code: AArch64 function at {:#x}: unsupported relocation values",
                cfg.entry
            ));
            return Err(value::Failure::InvalidImage);
        }
        let image = self.values(run)?;
        value::solve_with_unapplied(
            cfg,
            sigil_model::code_abi::CodeAbi::ElfAarch64,
            &image,
            &|pc| self.object && self.relocs.contains_key(&pc),
            reader,
            run,
        )
    }
    pub fn read_code(
        &self,
        pc: u64,
        len: u64,
        reader: &mut Reader<'_>,
        run: &mut Run,
    ) -> Option<Vec<u8>> {
        let end = pc.checked_add(len)?;
        let r = self
            .code
            .get(self.code.partition_point(|r| r.end <= pc))
            .filter(|r| r.holds(pc, end))?;
        read(
            reader,
            self.window,
            r.offset.checked_add(pc.checked_sub(r.start)?)?,
            len,
            run,
        )
        .ok()
    }
    /// An object branch is a symbolic witness, never a fabricated linked PLT destination.
    pub fn branch(&self, pc: u64, word: u32) -> Option<Branch> {
        let r = self.relocs.get(&pc)?.as_ref()?;
        let expected = match r.kind {
            CALL26 => 0x94000000,
            JUMP26 => 0x14000000,
            _ => return None,
        };
        // RELA supplies the whole immediate; require canonical zero bits in the input object.
        if word != expected || pc & 3 != 0 || !self.executable(pc, pc.checked_add(4)?) {
            return None;
        }
        let s = r.symbol.as_ref()?;
        if s.undefined {
            (r.addend == 0 && s.global && !s.weak && !s.name.is_empty()).then(|| {
                Branch::Import(ImportWitness {
                    name: s.name.clone(),
                    relocation: r.kind,
                    at: pc,
                    weak: s.weak,
                })
            })
        } else {
            let at = s.address?.checked_add_signed(r.addend)?;
            (at & 3 == 0
                && s.section_bounds.is_some_and(|(start, end)| {
                    start <= at && at.checked_add(4).is_some_and(|e| e <= end)
                })
                && self.executable(at, at.checked_add(4)?))
            .then_some(Branch::Internal(at))
        }
    }
}

#[derive(Clone, Debug)]
struct Section {
    name: Vec<u8>,
    ty: u32,
    flags: u64,
    addr: u64,
    off: u64,
    size: u64,
    link: usize,
    info: usize,
    align: u64,
    entsize: u64,
}
#[derive(Clone, Copy)]
struct Segment {
    flags: u32,
    off: u64,
    addr: u64,
    filesz: u64,
    memsz: u64,
}
type Result<T> = std::result::Result<T, &'static str>;
fn u16le(b: &[u8], n: usize) -> u16 {
    u16::from_le_bytes([b[n], b[n + 1]])
}
fn u32le(b: &[u8], n: usize) -> u32 {
    u32::from_le_bytes([b[n], b[n + 1], b[n + 2], b[n + 3]])
}
fn u64le(b: &[u8], n: usize) -> u64 {
    u64::from_le_bytes([
        b[n],
        b[n + 1],
        b[n + 2],
        b[n + 3],
        b[n + 4],
        b[n + 5],
        b[n + 6],
        b[n + 7],
    ])
}
fn end(start: u64, len: u64) -> Result<u64> {
    start.checked_add(len).ok_or("range overflow")
}
fn inside(off: u64, len: u64, size: u64) -> Result<()> {
    if end(off, len)? > size {
        Err("range outside slice")
    } else {
        Ok(())
    }
}
fn charge(run: &mut Run, work: Work, n: u64) -> Result<()> {
    if run.charge(work, n) {
        Ok(())
    } else {
        Err("artifact work limit")
    }
}
fn read(
    reader: &mut Reader<'_>,
    window: SliceWindow,
    off: u64,
    len: u64,
    run: &mut Run,
) -> Result<Vec<u8>> {
    if run.stopped() {
        return Err("artifact stopped");
    }
    read_slice(reader, window, off, len).map_err(|why| {
        run.refusal(why, "AArch64 ELF", reader);
        "read refused"
    })
}
fn text(
    reader: &mut Reader<'_>,
    window: SliceWindow,
    table: &Section,
    off: u32,
    run: &mut Run,
) -> Result<Vec<u8>> {
    if table.ty != 3 || u64::from(off) >= table.size {
        return Err("invalid string table offset");
    }
    let len = (table.size - u64::from(off)).min(crate::binary::elf::MAX_IMPORT_NAME as u64 + 1);
    let bytes = read(reader, window, end(table.off, u64::from(off))?, len, run)?;
    let n = bytes
        .iter()
        .position(|b| *b == 0)
        .ok_or("unterminated or oversized ELF name")?;
    charge(run, Work::Names, n as u64)?;
    Ok(bytes[..n].to_vec())
}

/// None means mappings/metadata could not be established, or the artifact stopped. A returned
/// image may retain independently valid ranges/witnesses alongside Run gaps; Some is never a
/// completeness claim. Preserve every gap when assembling the later slice outcome.
pub(crate) fn build(
    reader: &mut Reader<'_>,
    window: SliceWindow,
    run: &mut Run,
) -> Option<A64ElfImage> {
    match build_inner(reader, window, run) {
        Ok(image) => Some(image),
        Err(why) => {
            run.gap(format!("code: AArch64 ELF: {why}"));
            None
        }
    }
}
fn build_inner(reader: &mut Reader<'_>, window: SliceWindow, run: &mut Run) -> Result<A64ElfImage> {
    let h = read(reader, window, 0, 64, run)?;
    if &h[..4] != b"\x7fELF"
        || h[4] != 2
        || h[5] != 1
        || h[6] != 1
        || u16le(&h, 18) != 183
        || u32le(&h, 20) != 1
        || u32le(&h, 48) != 0
    {
        return Err("requires ELF64 little-endian EM_AARCH64");
    }
    let object = match u16le(&h, 16) {
        1 => true,
        2 | 3 => false,
        _ => return Err("unsupported ELF type"),
    };
    if u16le(&h, 52) != 64 || u16le(&h, 58) != 64 || u16le(&h, 60) == 0 || u16le(&h, 62) == 0xffff {
        return Err("missing or extended section headers");
    }
    let shnum = u16le(&h, 60) as usize;
    let raw = read(reader, window, u64le(&h, 40), shnum as u64 * 64, run)?;
    let mut sections = Vec::with_capacity(shnum);
    for s in raw.chunks_exact(64) {
        let row = Section {
            name: vec![],
            ty: u32le(s, 4),
            flags: u64le(s, 8),
            addr: u64le(s, 16),
            off: u64le(s, 24),
            size: u64le(s, 32),
            link: u32le(s, 40) as usize,
            info: u32le(s, 44) as usize,
            align: u64le(s, 48),
            entsize: u64le(s, 56),
        };
        if row.ty != 8 {
            inside(row.off, row.size, window.len)?;
        }
        if row.flags & 0x802 == 0x802 {
            return Err("compressed allocated section is unsupported");
        }
        if row.align > 1
            && (!row.align.is_power_of_two() || (row.ty != 8 && !row.off.is_multiple_of(row.align)))
        {
            return Err("invalid section alignment");
        }
        sections.push(row);
    }
    let strings = sections
        .get(u16le(&h, 62) as usize)
        .ok_or("invalid section names")?
        .clone();
    for (s, raw) in sections.iter_mut().zip(raw.chunks_exact(64)) {
        s.name = text(reader, window, &strings, u32le(raw, 0), run)?;
    }
    let mut segments = vec![];
    let mut dynamic = None;
    if !object {
        let count = u16le(&h, 56);
        if count == 0 || count == 0xffff || u16le(&h, 54) != 56 {
            return Err("missing or extended program headers");
        }
        let raw = read(reader, window, u64le(&h, 32), u64::from(count) * 56, run)?;
        for p in raw.chunks_exact(56) {
            let seg = Segment {
                flags: u32le(p, 4),
                off: u64le(p, 8),
                addr: u64le(p, 16),
                filesz: u64le(p, 32),
                memsz: u64le(p, 40),
            };
            if u32le(p, 0) == 2 && dynamic.replace(seg).is_some() {
                return Err("duplicate PT_DYNAMIC");
            }
            if u32le(p, 0) != 1 {
                continue;
            }
            let align = u64le(p, 48);
            if seg.memsz == 0
                || seg.filesz > seg.memsz
                || seg.off % 4096 != seg.addr % 4096
                || (align > 1 && (!align.is_power_of_two() || seg.off % align != seg.addr % align))
            {
                return Err("invalid PT_LOAD");
            }
            inside(seg.off, seg.filesz, window.len)?;
            end(seg.addr, seg.memsz)?;
            segments.push(seg);
        }
        segments.sort_by_key(|p| p.addr);
        validate_segments(&segments)?;
    }
    let mut image = A64ElfImage {
        window,
        object,
        code: vec![],
        mappings: vec![],
        fdes: vec![],
        slots: BTreeMap::new(),
        stubs: BTreeMap::new(),
        relocs: BTreeMap::new(),
        excluded: vec![],
        plt: vec![],
        plt_verified: vec![],
        bounds: Image::empty(Kind::Relocatable),
    };
    mappings(&mut image, &sections, &segments)?;
    mapping_symbols(&mut image, &sections, reader, run)?;
    let dynamic_tables = if object {
        DynamicTables::default()
    } else {
        dynamic_tables(reader, window, &sections, &segments, dynamic, run)?
    };
    let mut symbols = BTreeMap::new();
    let mut eh_relocs = BTreeMap::new();
    let mut poison_slots = BTreeSet::new();
    let mut dynamic_writes = BTreeMap::new();
    let eh: Vec<_> = sections
        .iter()
        .enumerate()
        .filter(|(_, s)| s.name == b".eh_frame")
        .collect();
    if eh.len() > 1 {
        return Err("duplicate .eh_frame sections");
    }
    let eh_index = eh.first().map(|(i, _)| *i);
    for (index, section) in sections.iter().enumerate() {
        if !matches!(section.ty, 4 | 9 | 19 | 20) {
            continue;
        }
        if object && (section.info == 0 || section.info >= sections.len()) {
            return Err("invalid object relocation target section");
        }
        let relevant = !object
            || sections.get(section.info).is_some_and(|s| s.flags & 4 != 0)
            || Some(section.info) == eh_index;
        if !relevant {
            // All relocation-bearing data is forbidden as a raw constant.
            if let Some(s) = sections.get(section.info) {
                mark_relocated(&mut image, end(window.base, s.off)?, s.size);
            }
            continue;
        }
        if section.ty != 4 || section.entsize != 24 || section.size % 24 != 0 {
            return Err("unsupported REL/packed or malformed relocation table");
        }
        if !object && !dynamic_tables.relocations.contains(&index) {
            return Err("relocation table not owned by PT_DYNAMIC");
        }
        let destination = if object {
            Some(
                sections
                    .get(section.info)
                    .ok_or("invalid relocation target section")?,
            )
        } else {
            None
        };
        for n in 0..section.size / 24 {
            charge(run, Work::Relocations, 1)?;
            let row = read(reader, window, end(section.off, n * 24)?, 24, run)?;
            let off = u64le(&row, 0);
            let info = u64le(&row, 8);
            let kind = info as u32;
            let sym = (info >> 32) as u32;
            let addend = u64le(&row, 16) as i64;
            let symbol = symbol(
                reader,
                window,
                &sections,
                section.link,
                sym,
                object,
                &mut symbols,
                run,
            );
            let relocation = Relocation {
                kind,
                addend,
                symbol: symbol.ok(),
                identity: (section.link, sym),
            };
            if let Some(s) = destination {
                inside(off, 4, s.size)?;
                if Some(section.info) == eh_index {
                    if eh_relocs.insert(off, Some(relocation)).is_some() {
                        eh_relocs.insert(off, None);
                    }
                    continue;
                }
                let pc = end(end(window.base, s.off)?, off)?;
                if off & 3 != 0 || !image.executable(pc, end(pc, 4)?) {
                    return Err("relocation outside aligned executable section");
                }
                if image.relocs.insert(pc, Some(relocation)).is_some() {
                    image.relocs.insert(pc, None);
                    run.gap(format!("code: AArch64 duplicate relocation at {pc:#x}"));
                }
            } else {
                if !matches!(kind, 257 | 1027 | GLOB_DAT | JUMP_SLOT) {
                    return Err("unmodeled dynamic relocation write extent");
                }
                let duplicate = dynamic_writes.insert(off, end(off, 8)?).is_some();
                if duplicate {
                    poison_slots.insert(off);
                    image.slots.remove(&off);
                    run.gap(format!("code: AArch64 ambiguous GOT slot {off:#x}"));
                }
                mark_relocated(&mut image, off, 8);
                // Any runtime relocation in code makes that entire mapping unavailable.
                let first = image.code.partition_point(|r| r.end <= off);
                for r in image.code[first..]
                    .iter()
                    .take_while(|r| r.start < off.saturating_add(8))
                {
                    image.excluded.push((r.start, r.end));
                }
                if matches!(kind, GLOB_DAT | JUMP_SLOT) {
                    charge(run, Work::Slots, 1)?;
                }
                if !matches!(kind, GLOB_DAT | JUMP_SLOT)
                    || addend != 0
                    || off & 7 != 0
                    || !slot_mapping(off, &segments)
                {
                    run.gap(format!(
                        "code: AArch64 unsupported dynamic relocation at {off:#x}"
                    ));
                    poison_slots.insert(off);
                    image.slots.remove(&off);
                    continue;
                }
                let Some(s) = relocation
                    .symbol
                    .filter(|s| s.undefined && s.global && !s.name.is_empty())
                else {
                    run.gap(format!("code: AArch64 invalid import symbol at {off:#x}"));
                    poison_slots.insert(off);
                    image.slots.remove(&off);
                    continue;
                };
                if poison_slots.contains(&off) || image.slots.contains_key(&off) {
                    image.slots.remove(&off);
                    poison_slots.insert(off);
                    run.gap(format!("code: AArch64 ambiguous GOT slot {off:#x}"));
                    continue;
                }
                image.slots.insert(
                    off,
                    ImportWitness {
                        name: s.name,
                        relocation: kind,
                        at: off,
                        weak: s.weak,
                    },
                );
            }
        }
    }
    // A second relocation with a different start can still overlap a slot. No ownership is
    // inferred from table ordering or from a valid record preceding an invalid one.
    for (&start, &finish) in &dynamic_writes {
        if dynamic_writes
            .range(..start)
            .next_back()
            .is_some_and(|(_, end)| *end > start)
        {
            return Err("overlapping dynamic relocation writes");
        }
        if let Some((_, eh)) = eh.first() {
            if start < end(eh.addr, eh.size)? && eh.addr < finish {
                return Err("runtime-relocated .eh_frame");
            }
        }
    }
    // All duplicate and unsupported object fields are excluded, including stale-value sources.
    for (&pc, r) in &image.relocs {
        if r.as_ref().is_none_or(|r| {
            !matches!(
                r.kind,
                CALL26 | JUMP26 | ADR_GOT_PAGE | LD64_GOT_LO12 | ADR_PAGE | ADD_LO12
            )
        }) {
            image.excluded.push((pc, end(pc, 4)?));
            run.gap(format!("code: AArch64 unsupported relocation at {pc:#x}"));
        }
    }
    normalize(&mut image.excluded);
    if let Some((_, s)) = eh.first() {
        if s.ty != 1 || s.flags & 0x800 != 0 || s.size > FDE_BYTES {
            return Err("invalid or oversized .eh_frame");
        }
        if !object && !mapped_section(s, &segments, false) {
            return Err(".eh_frame has no unique file mapping");
        }
        let base = if object {
            end(window.base, s.off)?
        } else {
            s.addr
        };
        let mut bytes = read(reader, window, s.off, s.size, run)?;
        let ranges = if object {
            let patches = eh_patches(&eh_relocs, base)?;
            fde::parse_a64_object(&mut bytes, base, &patches, run)
        } else {
            fde::parse_a64_linked(&bytes, base, run)
        };
        for (start, end) in ranges {
            if start & 3 != 0
                || end & 3 != 0
                || !image.executable(start, end)
                || image.excluded(start, end)
            {
                run.gap(format!(
                    "code: AArch64 FDE {start:#x}..{end:#x} has no exact executable mapping"
                ));
            } else {
                image.fdes.push((start, end));
            }
        }
    } else {
        run.gap("code: AArch64 missing .eh_frame exact bounds".into());
    }
    image.bounds.set_fdes(image.fdes.clone());
    if !image.bounds.fde_shared.is_empty() {
        run.gap("code: AArch64 overlapping FDE ranges".into());
    }
    if !object {
        // PLT0's BR is resolver machinery only for DT_PLTGOT's reserved third word.
        // Neither a symbol relocation nor a competing dynamic write may own those words.
        let resolver = dynamic_tables.plt_got.and_then(|got| {
            let finish = got.checked_add(24)?;
            let mapping = image
                .mappings
                .get(image.mappings.partition_point(|m| m.end <= got))?;
            (got & 7 == 0
                && mapping.start <= got
                && finish <= mapping.end
                && mapping.readable
                && !mapping.executable
                && mapping.file_offset.is_some()
                && dynamic_writes
                    .range(..finish)
                    .next_back()
                    .is_none_or(|(_, end)| *end <= got))
            .then(|| got + 16)
        });
        stubs(&mut image, resolver, reader, run)?;
    }
    if run.stopped() {
        return Err("artifact work limit");
    }
    Ok(image)
}

fn normalize(ranges: &mut Vec<(u64, u64)>) {
    ranges.sort_unstable();
    let mut write = 0;
    for read in 0..ranges.len() {
        let range = ranges[read];
        if write > 0 && range.0 <= ranges[write - 1].1 {
            ranges[write - 1].1 = ranges[write - 1].1.max(range.1);
        } else {
            ranges[write] = range;
            write += 1;
        }
    }
    ranges.truncate(write);
}

fn validate_segments(segments: &[Segment]) -> Result<()> {
    for p in segments {
        end(end(p.addr, p.memsz)?, LOADER_PAGE - 1)?;
    }
    for pair in segments.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        if end(a.addr, a.memsz)? > b.addr {
            return Err("overlapping virtual PT_LOAD mappings");
        }
        if end(end(a.addr, a.memsz)?, LOADER_PAGE - 1)? & !(LOADER_PAGE - 1)
            > b.addr & !(LOADER_PAGE - 1)
        {
            return Err("overlapping PT_LOAD pages");
        }
    }
    let mut files: Vec<_> = segments
        .iter()
        .filter(|p| p.filesz > 0)
        .map(|p| (p.off, p.filesz))
        .collect();
    files.sort_unstable();
    for pair in files.windows(2) {
        if end(pair[0].0, pair[0].1)? > pair[1].0 {
            return Err("aliased file PT_LOAD mappings");
        }
    }
    Ok(())
}
fn mapped_section(s: &Section, segments: &[Segment], exec: bool) -> bool {
    let at = segments.partition_point(|p| p.addr <= s.addr);
    at.checked_sub(1)
        .and_then(|i| segments.get(i))
        .is_some_and(|p| {
            (!exec || p.flags & 1 != 0)
                && end(s.addr, s.size).is_ok_and(|e| e <= p.addr.saturating_add(p.filesz))
                && s.off.checked_sub(p.off) == s.addr.checked_sub(p.addr)
        })
}
fn mappings(image: &mut A64ElfImage, sections: &[Section], segments: &[Segment]) -> Result<()> {
    if image.object {
        let mut file_extents = vec![];
        for s in sections
            .iter()
            .filter(|s| s.size > 0 && s.ty != 0 && s.ty != 8)
        {
            file_extents.push((s.off, end(s.off, s.size)?));
        }
        file_extents.sort_unstable();
        if file_extents.windows(2).any(|p| p[0].1 > p[1].0) {
            return Err("aliased object sections");
        }
        for s in sections
            .iter()
            .filter(|s| s.size > 0 && s.flags & 2 != 0 && s.ty != 8)
        {
            let start = end(image.window.base, s.off)?;
            image.mappings.push(Mapping {
                start,
                end: end(start, s.size)?,
                file_offset: Some(s.off),
                readable: true,
                writable: s.flags & 1 != 0,
                executable: s.flags & 4 != 0,
                relocated: false,
            });
        }
    } else {
        let mut unsafe_pages: Vec<_> = segments
            .iter()
            .filter(|p| p.filesz > 0 && p.flags & 3 != 0)
            .map(|p| {
                (
                    p.off / LOADER_PAGE,
                    (p.off + p.filesz - 1) / LOADER_PAGE + 1,
                )
            })
            .collect();
        unsafe_pages.sort_unstable();
        let mut merged: Vec<(u64, u64)> = vec![];
        for (start, end) in unsafe_pages {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        for p in segments {
            // Raw bytes also present in a writable/executable loader page are not constant proof.
            let first = p.off / LOADER_PAGE;
            let last = end(p.off, p.filesz)?.saturating_sub(1) / LOADER_PAGE;
            let at = merged.partition_point(|r| r.1 <= first);
            let page_alias = merged.get(at).is_some_and(|r| r.0 <= last);
            if p.filesz > 0 {
                image.mappings.push(Mapping {
                    start: p.addr,
                    end: end(p.addr, p.filesz)?,
                    file_offset: Some(p.off),
                    readable: p.flags & 4 != 0,
                    writable: p.flags & 2 != 0,
                    executable: p.flags & 1 != 0,
                    relocated: page_alias,
                });
            }
            if p.memsz > p.filesz {
                image.mappings.push(Mapping {
                    start: end(p.addr, p.filesz)?,
                    end: end(p.addr, p.memsz)?,
                    file_offset: None,
                    readable: p.flags & 4 != 0,
                    writable: p.flags & 2 != 0,
                    executable: p.flags & 1 != 0,
                    relocated: true,
                });
            }
        }
    }
    image.mappings.sort_by_key(|m| m.start);
    for s in sections.iter().filter(|s| s.flags & 4 != 0 && s.size > 0) {
        if s.ty != 1 || s.flags & 2 == 0 || (!image.object && !mapped_section(s, segments, true)) {
            return Err("instruction section has no unique executable file mapping");
        }
        let start = if image.object {
            end(image.window.base, s.off)?
        } else {
            s.addr
        };
        if start & 3 != 0 || s.off & 3 != 0 || s.size & 3 != 0 {
            return Err("unaligned instruction section");
        }
        let finish = end(start, s.size)?;
        image.code.push(Region {
            start,
            end: finish,
            offset: s.off,
        });
        if s.name == b".plt" {
            image.plt.push((start, finish));
        }
    }
    image.code.sort_unstable();
    image.plt.sort_unstable();
    if image.code.windows(2).any(|p| p[0].end > p[1].start) {
        return Err("overlapping executable sections");
    }
    Ok(())
}
/// AArch64 ELF mapping symbols explicitly delimit instruction/data regions. They never
/// supply function lengths. Bound the metadata walk independently, and charge every entry.
fn mapping_symbols(
    image: &mut A64ElfImage,
    sections: &[Section],
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> Result<()> {
    let mut markers: BTreeMap<(usize, u64), bool> = BTreeMap::new();
    let mut count = 0u64;
    for table in sections.iter().filter(|s| s.ty == 2) {
        if table.entsize != 24 || table.size % 24 != 0 {
            return Err("invalid mapping symbol table");
        }
        count = end(count, table.size / 24)?;
        if count > 1 << 20 {
            return Err("mapping symbol metadata limit");
        }
        let strings = sections
            .get(table.link)
            .ok_or("invalid mapping symbol string table")?;
        for n in 0..table.size / 24 {
            charge(run, Work::Values, 1)?;
            let bytes = read(reader, image.window, end(table.off, n * 24)?, 24, run)?;
            let section = u16le(&bytes, 6) as usize;
            let Some(target) = sections
                .get(section)
                .filter(|s| s.flags & 4 != 0 && s.size > 0)
            else {
                continue;
            };
            let name = text(reader, image.window, strings, u32le(&bytes, 0), run)?;
            let kind = match name.as_slice() {
                b"$x" => false,
                b"$d" => true,
                n if n.starts_with(b"$x.") => false,
                n if n.starts_with(b"$d.") => true,
                _ => continue,
            };
            if bytes[4] != 0 {
                return Err("invalid mapping symbol type/binding");
            }
            let raw = u64le(&bytes, 8);
            let (pc, start) = if image.object {
                (
                    end(end(image.window.base, target.off)?, raw)?,
                    end(image.window.base, target.off)?,
                )
            } else {
                (raw, target.addr)
            };
            if pc < start || pc >= end(start, target.size)? || pc & 3 != 0 {
                return Err("mapping symbol outside instruction section");
            }
            if markers.insert((section, pc), kind).is_some() {
                return Err("ambiguous mapping symbols");
            }
        }
    }
    for (&(section, pc), &data) in &markers {
        if !data {
            continue;
        }
        let s = &sections[section];
        let section_end = if image.object {
            end(end(image.window.base, s.off)?, s.size)?
        } else {
            end(s.addr, s.size)?
        };
        let finish = markers
            .range((section, pc + 1)..)
            .next()
            .filter(|((next, _), _)| *next == section)
            .map_or(section_end, |((_, at), _)| *at);
        image.excluded.push((pc, finish));
        run.gap(format!(
            "code: AArch64 data mapping in executable section at {pc:#x}"
        ));
    }
    Ok(())
}

fn mark_relocated(image: &mut A64ElfImage, start: u64, len: u64) {
    let first = image.mappings.partition_point(|m| m.end <= start);
    for m in image.mappings[first..]
        .iter_mut()
        .take_while(|m| m.start < start.saturating_add(len))
    {
        m.relocated = true;
    }
}
fn slot_mapping(at: u64, segments: &[Segment]) -> bool {
    segments
        .partition_point(|p| p.addr <= at)
        .checked_sub(1)
        .and_then(|i| segments.get(i))
        .is_some_and(|p| {
            p.flags & 5 == 4
                && at
                    .checked_add(8)
                    .is_some_and(|end| end <= p.addr.saturating_add(p.filesz))
        })
}

#[derive(Default)]
struct DynamicTables {
    relocations: BTreeSet<usize>,
    plt_got: Option<u64>,
}
fn dynamic_tables(
    reader: &mut Reader<'_>,
    window: SliceWindow,
    sections: &[Section],
    segments: &[Segment],
    dynamic: Option<Segment>,
    run: &mut Run,
) -> Result<DynamicTables> {
    let d = dynamic.ok_or("missing PT_DYNAMIC target table")?;
    if d.filesz / 16 > crate::binary::elf::MAX_DYNAMIC
        || d.filesz % 16 != 0
        || !segments.iter().any(|p| {
            p.addr <= d.addr
                && end(d.addr, d.filesz).is_ok_and(|e| e <= p.addr.saturating_add(p.filesz))
                && d.off.checked_sub(p.off) == d.addr.checked_sub(p.addr)
        })
    {
        return Err("invalid PT_DYNAMIC mapping");
    }
    let bytes = read(reader, window, d.off, d.filesz, run)?;
    let mut tags = BTreeMap::new();
    let mut terminated = false;
    for row in bytes.chunks_exact(16) {
        let tag = u64le(row, 0);
        if !matches!(tag,0..=33|0x6ffffef5|0x6ffffff0|0x6ffffff9|0x6ffffffb..=0x6fffffff) {
            return Err("unsupported dynamic tag/fixup extension");
        }
        if tag == 0 {
            terminated = true;
            break;
        }
        if matches!(
            tag,
            2 | 3 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 17 | 18 | 19 | 20 | 23 | 35 | 36 | 37
        ) && tags.insert(tag, u64le(row, 8)).is_some()
        {
            return Err("duplicate dynamic table tag");
        }
    }
    if !terminated
        || [17, 18, 19, 35, 36, 37]
            .iter()
            .any(|t| tags.contains_key(t))
    {
        return Err("unterminated or unsupported dynamic relocations");
    }
    let mut tables = BTreeSet::new();
    for (addr, size, entry) in [(7, 8, 9), (23, 2, 20)] {
        if !tags.contains_key(&addr) && !tags.contains_key(&size) {
            continue;
        }
        let address = *tags.get(&addr).ok_or("missing relocation address")?;
        let size = *tags.get(&size).ok_or("missing relocation size")?;
        if tags.get(&entry) != Some(&(if entry == 20 { 7 } else { 24 })) {
            return Err("invalid dynamic relocation format");
        }
        let matched: Vec<_> = sections
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                s.ty == 4
                    && s.addr == address
                    && s.size == size
                    && mapped_section(s, segments, false)
            })
            .collect();
        if matched.len() != 1 {
            return Err("dynamic relocation table has no unique section");
        }
        let (i, s) = matched[0];
        let syms = sections.get(s.link).ok_or("invalid dynsym link")?;
        let strings = sections.get(syms.link).ok_or("invalid dynstr link")?;
        if syms.ty != 11
            || tags.get(&6) != Some(&syms.addr)
            || tags.get(&11) != Some(&24)
            || tags.get(&5) != Some(&strings.addr)
            || tags.get(&10) != Some(&strings.size)
            || !mapped_section(syms, segments, false)
            || !mapped_section(strings, segments, false)
        {
            return Err("dynamic symbols disagree with sections");
        }
        if !tables.insert(i) {
            return Err("ambiguous dynamic relocation ownership");
        }
    }
    Ok(DynamicTables {
        relocations: tables,
        plt_got: tags.get(&3).copied(),
    })
}
#[allow(clippy::too_many_arguments)]
fn symbol(
    reader: &mut Reader<'_>,
    window: SliceWindow,
    sections: &[Section],
    table: usize,
    index: u32,
    object: bool,
    cache: &mut BTreeMap<(usize, u32), Symbol>,
    run: &mut Run,
) -> Result<Symbol> {
    if let Some(s) = cache.get(&(table, index)) {
        return Ok(s.clone());
    }
    let t = sections.get(table).ok_or("missing symbol table")?;
    if t.ty != if object { 2 } else { 11 }
        || t.entsize != 24
        || t.size % 24 != 0
        || u64::from(index) >= t.size / 24
    {
        return Err("invalid symbol index/table");
    }
    let b = read(reader, window, end(t.off, u64::from(index) * 24)?, 24, run)?;
    let section = u16le(&b, 6) as usize;
    let value = u64le(&b, 8);
    if !matches!(b[4] & 15, 0 | 2 | 3)
        || (section == 0 && (b[4] & 15 == 3 || b[5] != 0))
        || b[5] & !3 != 0
    {
        return Err("unsupported symbol type or variant PCS");
    }
    let name = text(
        reader,
        window,
        sections.get(t.link).ok_or("missing symbol strings")?,
        u32le(&b, 0),
        run,
    )?;
    let address = if section == 0 {
        None
    } else if object {
        sections
            .get(section)
            .filter(|s| s.ty != 8 && value < s.size)
            .and_then(|s| window.base.checked_add(s.off)?.checked_add(value))
    } else {
        Some(value)
    };
    let section_bounds = if object {
        sections.get(section).filter(|s| s.ty != 8).and_then(|s| {
            Some((
                window.base.checked_add(s.off)?,
                window.base.checked_add(s.off)?.checked_add(s.size)?,
            ))
        })
    } else {
        None
    };
    let s = Symbol {
        name: Rc::from(name),
        undefined: section == 0,
        weak: b[4] >> 4 == 2,
        global: matches!(b[4] >> 4, 1 | 2),
        address,
        section,
        section_bounds,
    };
    cache.insert((table, index), s.clone());
    Ok(s)
}
fn eh_patches(relocs: &BTreeMap<u64, Option<Relocation>>, base: u64) -> Result<BTreeMap<u64, i32>> {
    let mut patches = BTreeMap::new();
    for (&off, r) in relocs {
        let r = r.as_ref().ok_or("duplicate FDE relocation")?;
        let symbol = r
            .symbol
            .as_ref()
            .filter(|s| !s.undefined)
            .ok_or("unresolved FDE relocation")?;
        let s = symbol.address.ok_or("unresolved FDE relocation")?;
        let target = s
            .checked_add_signed(r.addend)
            .ok_or("FDE target overflow")?;
        if !symbol
            .section_bounds
            .is_some_and(|(start, end)| start <= target && target < end)
        {
            return Err("FDE target outside symbol section");
        }
        if r.kind != 261 {
            return Err("unsupported FDE relocation");
        }
        let value = i128::from(s) + i128::from(r.addend) - i128::from(end(base, off)?);
        patches.insert(
            off,
            i32::try_from(value).map_err(|_| "FDE relocation overflow")?,
        );
    }
    Ok(patches)
}
/// Decode the exact ordinary ADRP/LDR/ADD/BR slot-address sequence. This helper proves the
/// computed address only; callers still prove slot ownership or the reserved resolver role.
fn plt_slot(bytes: &[u8], pc: u64, run: &mut Run) -> Result<Option<u64>> {
    if bytes.len() != 16 {
        return Err("invalid PLT sequence length");
    }
    let mut words = [0u32; 4];
    let mut first = None;
    let mut valid = true;
    for (i, b) in bytes.chunks_exact(4).enumerate() {
        charge(run, Work::Instructions, 1)?;
        words[i] = u32le(b, 0);
        let decoded = decode_a64(words[i], end(pc, i as u64 * 4)?);
        valid &= decoded.is_ok();
        if i == 0 {
            first = decoded.ok();
        }
    }
    let target = (|| {
        let Operation::Address { dst, address } = first?.operation else {
            return None;
        };
        if !valid
            || words[0] & 0x9f00001f != 0x90000010
            || dst.name != RegisterName::Gpr(16)
            || dst.width != Width::X
            || words[1] & 0xffc003ff != 0xf9400211
            || words[2] & 0xffc003ff != 0x91000210
            || words[3] != 0xd61f0220
        {
            return None;
        }
        let load = u64::from((words[1] >> 10) & 4095) * 8;
        let add = u64::from((words[2] >> 10) & 4095);
        if load != add {
            return None;
        }
        address.checked_add(load)
    })();
    Ok(target)
}

fn stubs(
    image: &mut A64ElfImage,
    resolver: Option<u64>,
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> Result<()> {
    for &(start, finish) in &image.plt {
        // A name is only a discovery hint. Unsupported layouts remain searchable and partial.
        if finish - start < 32 || (finish - start - 32) % 16 != 0 {
            run.gap(format!("code: AArch64 unproved PLT layout at {start:#x}"));
            continue;
        }
        let header_end = end(start, 32)?;
        charge(run, Work::Slots, 1)?;
        let header_valid = if image.excluded(start, header_end) {
            false
        } else {
            let bytes = image
                .read_code(start, 32, reader, run)
                .ok_or("PLT header read failed")?;
            let mut valid = true;
            for i in [0, 5, 6, 7] {
                charge(run, Work::Instructions, 1)?;
                let word = u32le(&bytes, i * 4);
                valid &= word == if i == 0 { 0xa9bf7bf0 } else { 0xd503201f };
                valid &= decode_a64(word, end(start, i as u64 * 4)?).is_ok();
            }
            let slot = plt_slot(&bytes[4..20], end(start, 4)?, run)?;
            valid && resolver.is_some() && slot == resolver
        };
        if header_valid {
            image.plt_verified.push((start, header_end));
        } else {
            run.gap(format!(
                "code: AArch64 unproved PLT resolver header at {start:#x}"
            ));
        }

        let mut pc = header_end;
        while pc < finish {
            charge(run, Work::Slots, 1)?;
            if image.excluded(pc, end(pc, 16)?) {
                run.gap(format!(
                    "code: AArch64 relocated or excluded PLT stub at {pc:#x}"
                ));
                pc = end(pc, 16)?;
                continue;
            }
            let bytes = image
                .read_code(pc, 16, reader, run)
                .ok_or("PLT read failed")?;
            let target = plt_slot(&bytes, pc, run)?
                .and_then(|slot| image.slots.get(&slot))
                .filter(|w| !w.weak)
                .cloned();
            if let Some(witness) = target {
                image.stubs.insert(pc, witness);
                image.plt_verified.push((pc, end(pc, 16)?));
            } else {
                run.gap(format!("code: AArch64 unproved PLT stub at {pc:#x}"));
            }
            pc = end(pc, 16)?;
        }
    }
    normalize(&mut image.plt_verified);
    // A truncated/renamed/missing PLT section cannot turn an unresolved JUMP_SLOT route
    // into an empty successful search. Both collections are bounded by prior slot charges.
    let witnessed: BTreeSet<_> = image.stubs.values().map(|w| w.at).collect();
    for (&slot, witness) in &image.slots {
        if witness.relocation == JUMP_SLOT && !witnessed.contains(&slot) {
            run.gap(format!(
                "code: AArch64 JUMP_SLOT at {slot:#x} has no proved PLT stub"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "aarch64_tests.rs"]
mod tests;
