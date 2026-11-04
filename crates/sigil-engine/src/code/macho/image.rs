use std::ops::Range;

use sigil_model::{macho_architecture, Arch, MachOImport, SliceId};

use crate::code::reader::{read_slice, Reader, Refusal, SliceWindow};

const MAX_COMMANDS: u32 = 65_536;
const MAX_COMMAND_BYTES: u64 = 8 << 20;
const MH_OBJECT: u32 = 1;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Read(Refusal),
    Unsupported,
    Invalid(&'static str),
}

/// All three address domains are explicit. Object addresses are absolute file offsets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Region {
    pub address: Range<u64>,
    pub relative: Range<u64>,
    pub file: Range<u64>,
}

impl Region {
    pub fn relative_at(&self, address: u64, len: u64) -> Option<u64> {
        let end = address.checked_add(len)?;
        if address < self.address.start || end > self.address.end {
            return None;
        }
        self.relative
            .start
            .checked_add(address - self.address.start)
    }
}

#[derive(Debug)]
pub(crate) struct MachCodeView {
    pub slice: SliceId,
    pub window: SliceWindow,
    pub arch: Arch,
    pub file_type: u32,
    /// Linked image header address (base used by compact-unwind function offsets).
    pub image_base: Option<u64>,
    pub executable: Vec<Region>,
    /// Readable, nonwritable and nonexecutable file-backed regions for constant strings.
    pub readonly: Vec<Region>,
    /// Slice-relative file ranges, as recorded by LC_DATA_IN_CODE.
    pub data_in_code: Vec<Range<u64>>,
    pub sections: Vec<Section>,
    /// Exact bounded import inventory of this slice, supplied by the artifact owner.
    pub imports: Vec<MachOImport>,
    /// Load-command order is significant for dyld segment ordinals.
    pub segments: Vec<Mapping>,
}

#[derive(Debug)]
pub(crate) struct Section {
    pub segment_name: [u8; 16],
    pub name: [u8; 16],
    pub vm: Range<u64>,
    pub relative: Range<u64>,
    pub flags: u32,
    pub file_backed: bool,
    pub relocation_offset: u32,
    pub relocations: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
}

#[derive(Debug)]
pub(crate) struct Mapping {
    pub vm: Range<u64>,
    pub relative: Range<u64>,
}

#[derive(Debug)]
struct Segment {
    vm: Range<u64>,
    relative: Range<u64>,
    protection: u32,
    sections: Vec<Section>,
}

fn extent(start: u64, len: u64) -> Result<Range<u64>, Error> {
    Ok(start
        ..start
            .checked_add(len)
            .ok_or(Error::Invalid("range overflow"))?)
}
fn holds(outer: &Range<u64>, inner: &Range<u64>) -> bool {
    outer.start <= inner.start && inner.start <= inner.end && inner.end <= outer.end
}
fn overlaps(a: &Range<u64>, b: &Range<u64>) -> bool {
    a.start < b.end && b.start < a.end
}
fn u32le(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap_or_default())
}
fn u64le(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or_default())
}
fn name(bytes: &[u8], at: usize) -> [u8; 16] {
    bytes[at..at + 16].try_into().unwrap_or_default()
}
fn read(reader: &mut Reader<'_>, window: SliceWindow, at: u64, len: u64) -> Result<Vec<u8>, Error> {
    read_slice(reader, window, at, len).map_err(Error::Read)
}

/// Reads only the borrowed artifact fd. Every metadata and payload read is slice checked.
pub(crate) fn build(
    reader: &mut Reader<'_>,
    slice: SliceId,
    window: SliceWindow,
    arch: Arch,
    fat_cpu: Option<(i32, i32)>,
) -> Result<MachCodeView, Error> {
    let header = read(reader, window, 0, 32)?;
    if header[..4] != [0xcf, 0xfa, 0xed, 0xfe] {
        return Err(Error::Unsupported);
    }
    let cpu = (u32le(&header, 4) as i32, u32le(&header, 8) as i32);
    let actual = match cpu.0 as u32 {
        0x0100_0007 => Arch::X86_64,
        0x0100_000c if cpu.1 as u32 & 0x00ff_ffff == 0 => Arch::Aarch64,
        _ => return Err(Error::Unsupported),
    };
    if actual != arch
        || fat_cpu.is_some_and(|f| macho_architecture(f.0, f.1) != macho_architecture(cpu.0, cpu.1))
    {
        return Err(Error::Invalid("CPU header/table disagreement"));
    }
    let file_type = u32le(&header, 12);
    if !matches!(file_type, 1 | 2 | 6 | 8) {
        return Err(Error::Unsupported);
    }
    let count = u32le(&header, 16);
    let size = u64::from(u32le(&header, 20));
    if count > MAX_COMMANDS || size > MAX_COMMAND_BYTES {
        return Err(Error::Invalid("load-command limit"));
    }
    let commands = read(reader, window, 32, size)?;
    let mut segments = Vec::new();
    let mut data_commands = Vec::new();
    let mut at = 0usize;
    for _ in 0..count {
        let rest = commands.get(at..).ok_or(Error::Invalid("command bounds"))?;
        if rest.len() < 8 {
            return Err(Error::Invalid("truncated command"));
        }
        let len = u32le(rest, 4) as usize;
        if len < 8 || !len.is_multiple_of(8) || len > rest.len() {
            return Err(Error::Invalid("command size"));
        }
        let c = &rest[..len];
        match u32le(c, 0) {
            0x19 => segments.push(segment(c, window, file_type == MH_OBJECT)?),
            0x29 => {
                if len != 16 {
                    return Err(Error::Invalid("data-in-code command"));
                }
                data_commands.push((u64::from(u32le(c, 8)), u64::from(u32le(c, 12))));
            }
            _ => {}
        }
        at += len;
    }
    if at != commands.len() {
        return Err(Error::Invalid("command count"));
    }
    // Even an excluded writable mapping can make an executable/string translation ambiguous.
    let disjoint = |mut ranges: Vec<Range<u64>>| {
        ranges.retain(|r| !r.is_empty());
        ranges.sort_by_key(|r| r.start);
        !ranges.windows(2).any(|w| overlaps(&w[0], &w[1]))
    };
    if !disjoint(segments.iter().map(|s| s.vm.clone()).collect())
        || !disjoint(segments.iter().map(|s| s.relative.clone()).collect())
    {
        return Err(Error::Invalid("overlapping segments"));
    }
    if !disjoint(
        segments
            .iter()
            .flat_map(|s| &s.sections)
            .map(|s| s.vm.clone())
            .collect(),
    ) {
        return Err(Error::Invalid("overlapping sections"));
    }
    let mut view = MachCodeView {
        slice,
        window,
        arch,
        file_type,
        image_base: segments
            .iter()
            .find(|s| s.relative.start == 0 && s.relative.end >= 32)
            .map(|s| s.vm.start),
        executable: vec![],
        readonly: vec![],
        data_in_code: vec![],
        sections: vec![],
        imports: vec![],
        segments: segments
            .iter()
            .map(|s| Mapping {
                vm: s.vm.clone(),
                relative: s.relative.clone(),
            })
            .collect(),
    };
    for segment in segments {
        for section in segment.sections {
            let kind = section.flags & 0xff;
            // Zero-fill sections have no file bytes. Every other section must have one exact
            // segment translation, including metadata used by later readers.
            if !section.file_backed {
                view.sections.push(section);
                continue;
            }
            let region = Region {
                address: if file_type == MH_OBJECT {
                    extent(
                        window
                            .base
                            .checked_add(section.relative.start)
                            .ok_or(Error::Invalid("object address overflow"))?,
                        section.relative.end - section.relative.start,
                    )?
                } else {
                    section.vm.clone()
                },
                relative: section.relative.clone(),
                file: extent(
                    window
                        .base
                        .checked_add(section.relative.start)
                        .ok_or(Error::Invalid("file overflow"))?,
                    section.relative.end - section.relative.start,
                )?,
            };
            if region.address.is_empty() {
                view.sections.push(section);
                continue;
            }
            if segment.protection & 4 != 0
                && matches!(kind, 0 | 8)
                && section.flags & 0x8000_0400 != 0
            {
                if arch == Arch::Aarch64
                    && (!region.address.start.is_multiple_of(4)
                        || !region.relative.start.is_multiple_of(4)
                        || !region.address.end.is_multiple_of(4))
                {
                    return Err(Error::Invalid("unaligned arm64 instructions"));
                }
                view.executable.push(region.clone());
            }
            if segment.protection & 7 == 1 {
                view.readonly.push(region);
            }
            view.sections.push(section);
        }
    }
    if !disjoint(
        view.sections
            .iter()
            .filter(|s| s.file_backed)
            .map(|s| s.relative.clone())
            .collect(),
    ) {
        return Err(Error::Invalid("overlapping sections"));
    }
    let mut data_bytes = 0u64;
    for (at, len) in data_commands {
        if !len.is_multiple_of(8) {
            return Err(Error::Invalid("data-in-code size"));
        }
        // Bound allocation by the same metadata limit as load commands.
        data_bytes = data_bytes
            .checked_add(len)
            .ok_or(Error::Invalid("data-in-code limit"))?;
        if data_bytes > MAX_COMMAND_BYTES {
            return Err(Error::Invalid("data-in-code limit"));
        }
        let entries = read(reader, window, at, len)?;
        for entry in entries.as_chunks::<8>().0 {
            let len = u64::from(u16::from_le_bytes([entry[4], entry[5]]));
            let range = extent(u64::from(u32le(entry, 0)), len)?;
            if range.is_empty() || range.end > window.len {
                return Err(Error::Invalid("data-in-code range"));
            }
            view.data_in_code.push(range);
        }
    }
    view.executable.sort_by_key(|r| r.address.start);
    view.readonly.sort_by_key(|r| r.address.start);
    view.data_in_code.sort_by_key(|r| r.start);
    let mut merged: Vec<Range<u64>> = Vec::new();
    for range in view.data_in_code {
        match merged.last_mut() {
            Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
            _ => merged.push(range),
        }
    }
    view.data_in_code = merged;
    Ok(view)
}

fn segment(c: &[u8], window: SliceWindow, object: bool) -> Result<Segment, Error> {
    if c.len() < 72 {
        return Err(Error::Invalid("segment size"));
    }
    if u32le(c, 68) & 1 != 0 || u32le(c, 60) & !u32le(c, 56) != 0 {
        return Err(Error::Invalid("segment flags/protection"));
    }
    let n = u32le(c, 64) as usize;
    if n.checked_mul(80).and_then(|s| s.checked_add(72)) != Some(c.len()) {
        return Err(Error::Invalid("section table bounds"));
    }
    let vm = extent(u64le(c, 24), u64le(c, 32))?;
    let relative = extent(u64le(c, 40), u64le(c, 48))?;
    if vm.is_empty() {
        return Err(Error::Invalid("empty segment"));
    }
    if relative.end > window.len || relative.end - relative.start > vm.end - vm.start {
        return Err(Error::Invalid("segment file bounds"));
    }
    let mut sections = Vec::new();
    for s in c[72..].as_chunks::<80>().0 {
        if !object && name(s, 16) != name(c, 8) {
            return Err(Error::Invalid("section segment name"));
        }
        let section_vm = extent(u64le(s, 32), u64le(s, 40))?;
        let section_relative = extent(u64::from(u32le(s, 48)), u64le(s, 40))?;
        let kind = u32le(s, 64) & 0xff;
        let alignment = u32le(s, 52);
        let boundary = 1u64
            .checked_shl(alignment)
            .ok_or(Error::Invalid("section alignment"))?;
        if !holds(&vm, &section_vm) || !section_vm.start.is_multiple_of(boundary) {
            return Err(Error::Invalid("section VM bounds/alignment"));
        }
        if !matches!(kind, 1 | 0xc | 0x12)
            && (!holds(&relative, &section_relative)
                || section_vm.start - vm.start != section_relative.start - relative.start)
        {
            return Err(Error::Invalid("section file translation"));
        }
        sections.push(Section {
            segment_name: name(s, 16),
            name: name(s, 0),
            vm: section_vm,
            relative: section_relative,
            flags: u32le(s, 64),
            file_backed: !matches!(kind, 1 | 0xc | 0x12),
            relocation_offset: u32le(s, 56),
            relocations: u32le(s, 60),
            reserved1: u32le(s, 68),
            reserved2: u32le(s, 72),
            reserved3: u32le(s, 76),
        });
    }
    Ok(Segment {
        vm,
        relative,
        protection: u32le(c, 60),
        sections,
    })
}

impl MachCodeView {
    pub fn code_at(&self, address: u64, len: u64) -> Result<&Region, Error> {
        if len == 0 {
            return Err(Error::Invalid("empty candidate"));
        }
        if self.arch == Arch::Aarch64 && (!address.is_multiple_of(4) || !len.is_multiple_of(4)) {
            return Err(Error::Invalid("unaligned arm64 candidate"));
        }
        let i = self
            .executable
            .partition_point(|r| r.address.end <= address);
        let region = self
            .executable
            .get(i)
            .filter(|r| r.relative_at(address, len).is_some())
            .ok_or(Error::Invalid("candidate outside executable section"))?;
        let relative = region
            .relative_at(address, len)
            .ok_or(Error::Invalid("candidate address"))?;
        let range = extent(relative, len)?;
        let i = self
            .data_in_code
            .partition_point(|data| data.end <= range.start);
        if self
            .data_in_code
            .get(i)
            .is_some_and(|data| overlaps(data, &range))
        {
            return Err(Error::Invalid("candidate intersects data-in-code"));
        }
        Ok(region)
    }
    pub fn read_code(
        &self,
        reader: &mut Reader<'_>,
        address: u64,
        len: u64,
    ) -> Result<Vec<u8>, Error> {
        let region = self.code_at(address, len)?;
        read(
            reader,
            self.window,
            region
                .relative_at(address, len)
                .ok_or(Error::Invalid("candidate address"))?,
            len,
        )
    }
    pub fn string(&self, reader: &mut Reader<'_>, address: u64) -> Result<Option<Vec<u8>>, Error> {
        let i = self.readonly.partition_point(|r| r.address.end <= address);
        let Some(r) = self
            .readonly
            .get(i)
            .filter(|r| r.address.contains(&address))
        else {
            return Ok(None);
        };
        let len = (r.address.end - address).min(4096);
        let bytes = read(
            reader,
            self.window,
            r.relative_at(address, len)
                .ok_or(Error::Invalid("string address"))?,
            len,
        )?;
        Ok(bytes
            .iter()
            .position(|b| *b == 0)
            .map(|n| bytes[..n].to_vec()))
    }
}
