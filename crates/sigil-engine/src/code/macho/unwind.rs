//! Exact Mach-O unwind bounds. Linked compact tables describe lookup spans and can fold
//! several functions into one entry; neither the next entry nor LC_FUNCTION_STARTS is an end.
use std::collections::BTreeMap;
use std::ops::Range;

use sigil_model::{Arch, BoundsSource};

use super::image::{MachCodeView, Section};
use crate::code::fde;
use crate::code::reader::{read_slice, Reader};
use crate::code::{Run, Work};

const MAX_METADATA: u64 = 16 << 20;
const NOT_START: u32 = 0x8000_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MachBounds {
    pub start: u64,
    pub end: u64,
    pub source: BoundsSource,
}

fn named(name: &[u8; 16], expected: &[u8]) -> bool {
    name[..expected.len()] == *expected && name[expected.len()..].iter().all(|b| *b == 0)
}
fn gap(run: &mut Run, reason: &str) {
    run.gap(format!("code: Mach-O unwind: {reason}"));
}
fn read(
    view: &MachCodeView,
    reader: &mut Reader<'_>,
    run: &mut Run,
    at: u64,
    len: u64,
) -> Option<Vec<u8>> {
    if run.stopped() {
        return None;
    }
    if len > MAX_METADATA {
        gap(run, "metadata byte limit");
        return None;
    }
    match read_slice(reader, view.window, at, len) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            run.refusal(e, "Mach-O unwind", reader);
            None
        }
    }
}
fn section<'a>(
    view: &'a MachCodeView,
    segment: &[u8],
    name: &[u8],
) -> Result<Option<&'a Section>, &'static str> {
    let mut matching = view
        .sections
        .iter()
        .filter(|s| named(&s.segment_name, segment) && named(&s.name, name));
    let first = matching.next();
    if matching.next().is_some() {
        return Err("duplicate unwind sections");
    }
    if first.is_some_and(|s| !s.file_backed || s.relative.is_empty()) {
        return Err("unbacked or empty unwind section");
    }
    Ok(first)
}

/// Sorted, disjoint accepted intervals. Every rejected extent leaves a diagnostic on the
/// same artifact Run; all reads use the caller's already-open fd and checked SliceWindow.
pub(crate) fn read_bounds(
    view: &MachCodeView,
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> Vec<MachBounds> {
    if run.stopped() {
        return vec![];
    }
    let result = read_inner(view, reader, run);
    match result {
        Ok(bounds) => disjoint(bounds, run),
        Err(reason) => {
            gap(run, reason);
            vec![]
        }
    }
}
fn read_inner(
    view: &MachCodeView,
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> Result<Vec<MachBounds>, &'static str> {
    let mut records = vec![];
    if let Some(s) = section(view, b"__TEXT", b"__eh_frame")? {
        // Object FDEs without relocations already name section-VM addresses; translate
        // their complete recorded extent below. Paired/subtractor relocations remain a gap.
        if s.relocations != 0 && view.file_type == 1 {
            gap(run, "object __eh_frame relocations unsupported");
        } else if s.relocations != 0 {
            return Err("linked __eh_frame has relocations");
        } else if let Some(bytes) = read(
            view,
            reader,
            run,
            s.relative.start,
            s.relative.end - s.relative.start,
        ) {
            records = fde::parse_records(&bytes, s.vm.start, run);
        }
    }
    if view.file_type == 1 {
        let mut bounds = vec![];
        let mut sections: Vec<_> = view.sections.iter().filter(|s| s.file_backed).collect();
        sections.sort_by_key(|s| s.vm.start);
        for r in records {
            let at = sections.partition_point(|s| s.vm.end <= r.start);
            let Some(target) = sections
                .get(at)
                .filter(|s| s.vm.start <= r.start && r.end <= s.vm.end)
            else {
                gap(run, "object FDE outside one section");
                continue;
            };
            let start = view
                .window
                .base
                .checked_add(target.relative.start)
                .and_then(|n| n.checked_add(r.start - target.vm.start))
                .ok_or("object FDE address overflow")?;
            let end = start
                .checked_add(r.end - r.start)
                .ok_or("object FDE length overflow")?;
            if let Some(b) = checked(view, start, end, BoundsSource::EhFrameFde, run) {
                bounds.push(b);
            }
        }
        if let Some(s) = section(view, b"__LD", b"__compact_unwind")? {
            bounds.extend(object(view, s, reader, run)?);
        }
        if bounds.is_empty() && !run.stopped() {
            gap(run, "missing exact bounds");
        }
        return Ok(bounds);
    }
    let exact = disjoint(
        records
            .iter()
            .map(|r| MachBounds {
                start: r.start,
                end: r.end,
                source: BoundsSource::EhFrameFde,
            })
            .collect(),
        run,
    );
    let mut bounds: Vec<_> = exact
        .into_iter()
        .filter_map(|r| checked(view, r.start, r.end, r.source, run))
        .collect();
    if let Some(s) = section(view, b"__TEXT", b"__unwind_info")? {
        if s.relocations != 0 {
            return Err("linked __unwind_info has relocations");
        }
        let Some(bytes) = read(
            view,
            reader,
            run,
            s.relative.start,
            s.relative.end - s.relative.start,
        ) else {
            return Ok(vec![]);
        };
        let entries = linked(&bytes, run)?;
        if run.stopped() {
            return Ok(vec![]);
        }
        let base = view.image_base.ok_or("missing image header mapping")?;
        let dwarf_mode = match view.arch {
            Arch::Aarch64 => 0x0300_0000,
            Arch::X86_64 => 0x0400_0000,
            _ => return Err("unsupported architecture"),
        };
        // A rejected compact entry poisons its whole lookup span, including any conflicting
        // standalone FDE. A correct DWARF offset must name an actual walked FDE, not a CIE,
        // the middle of an FDE, another function's FDE or a runtime fallback hint.
        let by_offset: BTreeMap<_, _> = records.iter().map(|r| (r.offset as u32, r)).collect();
        let by_start: BTreeMap<_, _> = bounds.iter().map(|b| (b.start, b.end)).collect();
        let mut forbidden = vec![];
        for e in entries {
            let start = base
                .checked_add(u64::from(e.start))
                .ok_or("function offset overflow")?;
            let end = base
                .checked_add(u64::from(e.end))
                .ok_or("sentinel overflow")?;
            let reject = if !valid_encoding(view.arch, e.encoding) || e.encoding & NOT_START != 0 {
                Some("unknown/zero encoding or nonfunction compact entry")
            } else if e.encoding & 0x0f00_0000 == dwarf_mode {
                match by_offset.get(&(e.encoding & 0x00ff_ffff)) {
                    Some(r)
                        if r.start == start
                            && r.end <= end
                            && view.code_at(r.start, r.end - r.start).is_ok() =>
                    {
                        None
                    }
                    _ => Some("DWARF entry does not match exact FDE offset/start/extent"),
                }
            } else if by_start.get(&start).is_none_or(|fde_end| *fde_end > end) {
                Some("native linked compact entry lacks exact function bounds (possibly folded)")
            } else {
                None
            };
            if let Some(reason) = reject {
                run.gap(format!(
                    "code: Mach-O unwind: [{start:#x},{end:#x}): {reason}"
                ));
                forbidden.push(start..end);
            }
        }
        forbidden.sort_by_key(|r| r.start);
        bounds.retain(|b| {
            let i = forbidden.partition_point(|r| r.end <= b.start);
            forbidden.get(i).is_none_or(|r| r.start >= b.end)
        });
    }
    if bounds.is_empty() && !run.stopped() {
        gap(run, "missing exact bounds");
    }
    Ok(bounds)
}
fn valid_encoding(arch: Arch, encoding: u32) -> bool {
    let mode = encoding & 0x0f00_0000;
    match arch {
        Arch::Aarch64 => matches!(mode, 0x0200_0000 | 0x0300_0000 | 0x0400_0000),
        Arch::X86_64 => matches!(mode, 0x0100_0000 | 0x0200_0000 | 0x0300_0000 | 0x0400_0000),
        _ => false,
    }
}
fn checked(
    view: &MachCodeView,
    start: u64,
    end: u64,
    source: BoundsSource,
    run: &mut Run,
) -> Option<MachBounds> {
    if end <= start || view.code_at(start, end - start).is_err() {
        run.gap(format!("code: Mach-O unwind: [{start:#x},{end:#x}): extent outside one executable section, unaligned, empty or data-in-code"));
        None
    } else {
        Some(MachBounds { start, end, source })
    }
}
fn disjoint(mut bounds: Vec<MachBounds>, run: &mut Run) -> Vec<MachBounds> {
    bounds.sort_by_key(|b| (b.start, b.end));
    let mut out = vec![];
    let mut i = 0;
    while i < bounds.len() {
        let mut j = i + 1;
        let mut end = bounds[i].end;
        while j < bounds.len() && bounds[j].start < end {
            end = end.max(bounds[j].end);
            j += 1;
        }
        if j == i + 1 {
            out.push(bounds[i].clone());
        } else if j == i + 2
            && bounds[i].start == bounds[i + 1].start
            && bounds[i].end == bounds[i + 1].end
            && bounds[i].source != bounds[i + 1].source
        {
            // One FDE and one explicit object entry may corroborate exactly. Duplicates
            // within either source, and any nonidentical overlapping extent, stay ambiguous.
            let fde = if bounds[i].source == BoundsSource::EhFrameFde {
                i
            } else {
                i + 1
            };
            out.push(bounds[fde].clone());
        } else {
            run.gap(format!(
                "code: Mach-O unwind: [{:#x},{end:#x}): overlapping or duplicate exact bounds",
                bounds[i].start
            ));
        }
        i = j;
    }
    out
}
fn word(bytes: &[u8], at: usize) -> Result<u32, &'static str> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at.checked_add(4).ok_or("offset overflow")?)
            .ok_or("truncated word")?
            .try_into()
            .map_err(|_| "word")?,
    ))
}
fn pointer(bytes: &[u8], at: usize) -> Result<u64, &'static str> {
    Ok(u64::from_le_bytes(
        bytes
            .get(at..at.checked_add(8).ok_or("offset overflow")?)
            .ok_or("truncated pointer")?
            .try_into()
            .map_err(|_| "pointer")?,
    ))
}
fn object(
    view: &MachCodeView,
    s: &Section,
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> Result<Vec<MachBounds>, &'static str> {
    let len = s.relative.end - s.relative.start;
    if !s.relative.start.is_multiple_of(8)
        || !len.is_multiple_of(32)
        || !s.relocation_offset.is_multiple_of(4)
    {
        return Err("object entry width/alignment");
    }
    let count = len / 32;
    if !run.charge(Work::Fdes, count) || !run.charge(Work::Relocations, u64::from(s.relocations)) {
        return Ok(vec![]);
    }
    let Some(bytes) = read(view, reader, run, s.relative.start, len) else {
        return Ok(vec![]);
    };
    let Some(relocs) = read(
        view,
        reader,
        run,
        u64::from(s.relocation_offset),
        u64::from(s.relocations) * 8,
    ) else {
        return Ok(vec![]);
    };
    let mut targets = BTreeMap::new();
    for r in relocs.chunks_exact(8) {
        let at = word(r, 0)?;
        let flags = word(r, 4)?;
        // ARM64_RELOC_UNSIGNED and X86_64_RELOC_UNSIGNED have the same type0/layout.
        if at & 0x8000_0000 != 0
            || at % 32 != 0
            || u64::from(at) >= len
            || flags >> 24 != 0x06
            || flags & 0x00ff_ffff == 0
        {
            return Err("unsupported/misplaced compact object relocation");
        }
        let target = view
            .sections
            .get((flags & 0x00ff_ffff) as usize - 1)
            .ok_or("relocation section ordinal")?;
        if targets.insert(at, target).is_some() {
            return Err("duplicate compact object relocation");
        }
    }
    if targets.len() as u64 != count {
        return Err("unresolved compact object function pointer");
    }
    let mut out = vec![];
    for (i, e) in bytes.chunks_exact(32).enumerate() {
        let entry_gap = |run: &mut Run, reason: &str| {
            run.gap(format!(
                "code: Mach-O unwind: object entry {:#x}: {reason}",
                i * 32
            ))
        };
        let encoding = word(e, 12)?;
        if !valid_encoding(view.arch, encoding) || encoding & NOT_START != 0 {
            entry_gap(
                run,
                "unknown/zero encoding or nonfunction compact object entry",
            );
            continue;
        }
        // Personality/LSDA pointers need their own relocations; this bounded first adapter
        // accepts only entries where they are absent, rather than ignoring unresolved data.
        if encoding & 0x7000_0000 != 0 || pointer(e, 16)? != 0 || pointer(e, 24)? != 0 {
            entry_gap(run, "unsupported compact object personality/LSDA");
            continue;
        }
        let target = targets
            .get(&((i * 32) as u32))
            .ok_or("missing object relocation")?;
        let raw = pointer(e, 0)?;
        let Some(delta) = raw.checked_sub(target.vm.start) else {
            entry_gap(run, "object pointer precedes target section");
            continue;
        };
        let length = u64::from(word(e, 8)?);
        if !target.file_backed
            || delta
                .checked_add(length)
                .is_none_or(|end| end > target.relative.end - target.relative.start)
        {
            entry_gap(run, "object length outside relocation target section");
            continue;
        }
        let start = view
            .window
            .base
            .checked_add(target.relative.start)
            .and_then(|n| n.checked_add(delta))
            .ok_or("object function address overflow")?;
        let end = start
            .checked_add(length)
            .ok_or("object function length overflow")?;
        if let Some(b) = checked(view, start, end, BoundsSource::MachOCompactUnwind, run) {
            out.push(b);
        }
    }
    Ok(out)
}

#[derive(Debug)]
struct Entry {
    start: u32,
    end: u32,
    encoding: u32,
}
// All metadata subarrays are disjoint, aligned and inside the section/page before indexing.
fn array(
    bytes: &[u8],
    at: usize,
    count: usize,
    width: usize,
    min: usize,
    max: usize,
) -> Result<Range<usize>, &'static str> {
    let end = count
        .checked_mul(width)
        .and_then(|n| at.checked_add(n))
        .ok_or("array overflow")?;
    if !at.is_multiple_of(4) || at < min || end > max || end > bytes.len() {
        return Err("array extent/alignment");
    }
    Ok(at..end)
}
fn no_overlaps(mut ranges: Vec<Range<usize>>) -> Result<(), &'static str> {
    ranges.retain(|r| !r.is_empty());
    ranges.sort_by_key(|r| r.start);
    if ranges.windows(2).any(|w| w[0].end > w[1].start) {
        Err("overlapping unwind arrays/pages")
    } else {
        Ok(())
    }
}
fn linked(bytes: &[u8], run: &mut Run) -> Result<Vec<Entry>, &'static str> {
    if bytes.len() < 28 || word(bytes, 0)? != 1 {
        return Err("unwind_info header/version");
    }
    let common = array(
        bytes,
        word(bytes, 4)? as usize,
        word(bytes, 8)? as usize,
        4,
        28,
        bytes.len(),
    )?;
    let personalities = array(
        bytes,
        word(bytes, 12)? as usize,
        word(bytes, 16)? as usize,
        4,
        28,
        bytes.len(),
    )?;
    if personalities.len() / 4 > 3 {
        return Err("personality index limit");
    }
    let indices = array(
        bytes,
        word(bytes, 20)? as usize,
        word(bytes, 24)? as usize,
        12,
        28,
        bytes.len(),
    )?;
    if indices.len() < 24 {
        return Err("missing first-level sentinel");
    }
    // Count headers before allocating or walking input-controlled pages.
    if !run.fits(Work::Fdes, (indices.len() / 12 - 1) as u64) {
        return Ok(vec![]);
    }
    let mut occupied = vec![0..28, common.clone(), personalities, indices.clone()];
    let mut entries = vec![];
    let n = indices.len() / 12;
    for i in 0..n - 1 {
        let index = indices.start + i * 12;
        let start = word(bytes, index)?;
        let end = word(bytes, index + 12)?;
        let page = word(bytes, index + 4)? as usize;
        let lsda = word(bytes, index + 8)? as usize;
        let next_lsda = word(bytes, index + 20)? as usize;
        if start >= end || page < 28 || !page.is_multiple_of(4) || lsda > next_lsda {
            return Err("unsorted index/sentinel/page");
        }
        let descriptors = array(bytes, lsda, (next_lsda - lsda) / 8, 8, 28, bytes.len())?;
        if !(next_lsda - lsda).is_multiple_of(8) {
            return Err("LSDA descriptor width");
        }
        occupied.push(descriptors.clone());
        let mut previous = None;
        for p in (descriptors.start..descriptors.end).step_by(8) {
            let function = word(bytes, p)?;
            if function < start || function >= end || previous.is_some_and(|v| function <= v) {
                return Err("LSDA descriptor function order");
            }
            previous = Some(function);
        }
        let page_end = page
            .checked_add(4096)
            .ok_or("page overflow")?
            .min(bytes.len());
        let kind = word(bytes, page)?;
        let header = match kind {
            2 => 8,
            3 => 12,
            _ => return Err("unsupported second-level page kind"),
        };
        let offsets = word(bytes, page + 4)?;
        let entry_offset = (offsets & 0xffff) as usize;
        let count = (offsets >> 16) as usize;
        if count == 0 {
            return Err("empty second-level page");
        }
        if !run.charge(Work::Fdes, count as u64) {
            return Ok(vec![]);
        }
        let data = array(
            bytes,
            page.checked_add(entry_offset)
                .ok_or("page entry overflow")?,
            count,
            if kind == 2 { 8 } else { 4 },
            page + header,
            page_end,
        )?;
        let mut page_spans = vec![page..page + header, data.clone()];
        let local = if kind == 3 {
            let offsets = word(bytes, page + 8)?;
            let a = array(
                bytes,
                page.checked_add((offsets & 0xffff) as usize)
                    .ok_or("local encoding overflow")?,
                (offsets >> 16) as usize,
                4,
                page + header,
                page_end,
            )?;
            page_spans.push(a.clone());
            a
        } else {
            page + header..page + header
        };
        no_overlaps(page_spans.clone())?;
        occupied.extend(page_spans);
        let mut page_entries = vec![];
        for j in 0..count {
            let (address, encoding) = if kind == 2 {
                (
                    word(bytes, data.start + j * 8)?,
                    word(bytes, data.start + j * 8 + 4)?,
                )
            } else {
                let raw = word(bytes, data.start + j * 4)?;
                let address = start
                    .checked_add(raw & 0x00ff_ffff)
                    .ok_or("compressed address overflow")?;
                let encoding_index = (raw >> 24) as usize;
                let common_count = common.len() / 4;
                let encoding = if encoding_index < common_count {
                    word(bytes, common.start + encoding_index * 4)?
                } else {
                    let at = encoding_index - common_count;
                    if at >= local.len() / 4 {
                        return Err("compressed encoding index");
                    }
                    word(bytes, local.start + at * 4)?
                };
                (address, encoding)
            };
            if address < start
                || address >= end
                || (j == 0 && address != start)
                || page_entries
                    .last()
                    .is_some_and(|e: &Entry| address <= e.start)
            {
                return Err("unsorted/duplicate/out-of-range compact functions");
            }
            let personality = (encoding >> 28) & 3;
            if personality as usize > word(bytes, 16)? as usize {
                return Err("compact personality index");
            }
            page_entries.push(Entry {
                start: address,
                end,
                encoding,
            });
        }
        for j in 0..page_entries.len() - 1 {
            page_entries[j].end = page_entries[j + 1].start;
        }
        entries.extend(page_entries);
    }
    let last = indices.end - 12;
    if word(bytes, last + 4)? != 0 {
        return Err("nonzero sentinel page");
    }
    no_overlaps(occupied)?;
    Ok(entries)
}
