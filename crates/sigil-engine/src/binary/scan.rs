//! The signature scan (PR-4c-2a spec §2–§4). The needles of [`super::needles`] are looked for in
//! an ELF file's `.gopclntab` and read-only data sections (`search`), read with `pread` on the
//! parse's fd in [`CHUNK`]-byte chunks, each byte charged to `binary_scan_bytes` before it is read
//! (`code::reader`). Nothing is mapped. Export needles are matched against the names of the
//! parse's dynamic symbols instead, charged to `binary_parse_bytes`. The same walk finds the known
//! functions whose returned strings [`super::returns`] reads first (PR-4c-2b).

use std::collections::BTreeMap;
use std::fs::File;

use object::elf;
use object::read::elf::{FileHeader, ProgramHeader, SectionHeader, SectionTable, Sym};
use object::read::{ReadCacheOps, SectionIndex};
use object::Endianness;
use sigil_model::{
    returned_value_gap, scan_over_gap, DataValue, FeatureKey, FunctionReturn, Loc, Signal,
    UntrustedText, SCAN_GOPCLNTAB_HEADER, SCAN_NAME_NOT_READ, SCAN_NO_GOPCLNTAB, SCAN_NO_SECTIONS,
    SCAN_READ_FAILED,
};

use super::elf::{is_export, Dynamic, Elf, Sections, MAX_IMPORT_NAME};
use super::needles::{Needle, NeedleKind, Needles};
use super::read::Bounded;
use super::returns::{self, Definition, OVER_BUDGET};
use crate::code::reader::{Reader, Refusal};

/// The bytes of a section examined per read. Each read is one chunk and the overlap of its kind
/// ([`Needles::overlap`]), so that a match that starts in the chunk is read whole.
pub const CHUNK: u64 = 1 << 20;

/// The longest section name read. A longer one is a gap.
pub const MAX_SECTION_NAME: usize = 4096;

/// The magics of Go's `pcHeader`, the first bytes of `.gopclntab` (`runtime/symtab.go`,
/// `debug/gosym`): Go 1.16 and 1.17, Go 1.18 and 1.19, Go 1.20 and later.
const GO116_MAGIC: u32 = 0xffff_fffa;
const GO118_MAGIC: u32 = 0xffff_fff0;
const GO120_MAGIC: u32 = 0xffff_fff1;

/// The bytes of the longest `pcHeader` read: the magic, four bytes, and eight 8-byte fields.
const PCLN_HEADER_MAX: u64 = 8 + 8 * 8;

/// What the scan looks for (PR-4c-2b): the needles, and the known functions whose returned
/// strings it reads (the component database's `read = "function"` fields, sorted).
#[derive(Debug, Clone, Copy)]
pub struct Sought<'d> {
    pub needles: &'d Needles,
    pub functions: &'d [String],
}

/// One needle found: a feature hint without its slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub feature: FeatureKey,
    pub signal: Signal,
    pub value: UntrustedText,
    pub at: Loc,
}

/// The signature scan of one ELF slice (PR-4c-2a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanOutcome {
    /// Scanned: the first match of each needle found, and the gaps (sorted, without repeats).
    Scanned {
        found: Vec<Found>,
        gaps: Vec<String>,
    },
    /// Not scanned: the file's name names a component identified by name and hash only (`scan =
    /// false`; ADR-010).
    NameAndHashOnly,
}

/// A section `search` reads: the kind of needle looked for in it, its name, and its bytes in
/// the file (`sh_offset`, `sh_size`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub kind: NeedleKind,
    pub name: Vec<u8>,
    pub offset: u64,
    pub size: u64,
}

/// What `search` found, and read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Searched {
    /// The first match of each needle found, at its lowest offset in the first target that has it:
    /// in target order, then read order, then database order (the needles found in one read).
    pub found: Vec<Found>,
    /// Sorted, without repeats.
    pub gaps: Vec<String>,
    /// The bytes charged to `binary_scan_bytes`.
    pub used: u64,
}

/// Looks for the needles of each target's kind in its bytes, read through `reader` (the file's
/// fd, its `fstat` size, and `binary_scan_bytes` as its limit): the Go-function needles in their
/// targets' function-name tables, each as an exact name ([`first_entry`]; PR-4c-3a), then the
/// string needles in theirs, anywhere ([`first`]), each kind until all its needles are found. A
/// kind without a needle reads nothing. The bytes looked in are read only within the file and
/// within the target's own bytes; bytes past the end of the file (or an end that overflows), while
/// a needle of the kind is still looked for, are the gap [`SCAN_READ_FAILED`], and the bytes in the
/// file are read. A Go target's header that locates no function-name table is the gap
/// [`SCAN_GOPCLNTAB_HEADER`] ([`function_names`]). Over the limit, reading stops, and what was
/// found is kept with the gap [`scan_over_gap`]. A read that fails leaves the rest of its target
/// unread, with the gap [`SCAN_READ_FAILED`]. Each gap is given once. `used` is the reader's,
/// earlier reads included.
pub(crate) fn search(reader: &mut Reader<'_>, needles: &Needles, targets: &[Target]) -> Searched {
    let size = reader.size();
    let mut out = Searched::default();
    // The gaps: bytes of a target not read (past the end of the file, or a failed read), a Go
    // target's header not understood, and the budget.
    let (mut unread, mut not_understood, mut over) = (false, false, false);
    'kinds: for kind in [NeedleKind::GoFunction, NeedleKind::String] {
        let mut open = needles.of(kind);
        let overlap = needles.overlap(kind);
        for t in targets.iter().filter(|t| t.kind == kind) {
            if open.is_empty() {
                continue;
            }
            // The bytes looked in: the section's, or a Go function's name only in the function-name
            // table, which the section's header locates (PR-4c-3a plan review P2: the file table
            // also holds NUL-terminated names).
            let (from, len) = match kind {
                NeedleKind::GoFunction => match pcln_table(reader, t) {
                    Pcln::Table(from, len) => (from, len),
                    Pcln::NotUnderstood => {
                        not_understood = true;
                        continue;
                    }
                    Pcln::Unread => {
                        unread = true;
                        continue;
                    }
                    Pcln::OverBudget => {
                        over = true;
                        break 'kinds;
                    }
                },
                _ => (t.offset, t.size),
            };
            // Bytes the file does not have: a needle may be there unread.
            if len > 0 && from.checked_add(len).is_none_or(|e| e > size) {
                unread = true;
            }
            let end = from.saturating_add(len).min(size);
            let mut pos = from;
            // The byte before `pos`, kept from the previous read: none at the start.
            let mut before = None;
            while pos < end && !open.is_empty() {
                let stop = pos.saturating_add(CHUNK).min(end);
                let bytes = match reader.read(pos, stop.saturating_add(overlap).min(end) - pos) {
                    Ok(bytes) => bytes,
                    Err(Refusal::Budget) => {
                        over = true;
                        break 'kinds;
                    }
                    Err(_) => {
                        unread = true;
                        break;
                    }
                };
                open.retain(|n| {
                    let at = match kind {
                        NeedleKind::GoFunction => first_entry(&bytes, &n.value, before),
                        _ => first(&bytes, &n.value),
                    };
                    match at {
                        Some(i) => {
                            out.found.push(found(n, t, pos - t.offset + i as u64));
                            false
                        }
                        None => true,
                    }
                });
                before = usize::try_from(stop - pos)
                    .ok()
                    .and_then(|n| n.checked_sub(1))
                    .and_then(|i| bytes.get(i))
                    .copied();
                pos = stop;
            }
        }
    }
    if unread {
        out.gaps.push(SCAN_READ_FAILED.to_string());
    }
    if not_understood {
        out.gaps.push(SCAN_GOPCLNTAB_HEADER.to_string());
    }
    if over {
        out.gaps.push(scan_over_gap(reader.limit()));
    }
    out.gaps.sort();
    out.used = reader.used();
    out
}

/// The signature scan of the ELF `e` (PR-4c-2a), after its container and code steps: the export
/// needles against the names of its exported dynamic symbols, which also finds the known
/// functions of `sought` ([`exports`]); the strings those functions return ([`returns::read`],
/// PR-4c-2b); then [`search`] for the Go-function needles in `.gopclntab`'s function-name table
/// (when it has Go build info, `go`; PR-4c-3a) and for the string needles in `.rodata`,
/// `.rodata.*`, and `.lrodata` ([`targets`]). Names are read through the parse's cache, charged to
/// `binary_parse_bytes`; function, string, and section bytes through `file` (the fd and its
/// `fstat` size), charged to `limit` (`binary_scan_bytes`). What cannot be read is a gap of the
/// scan, never of the container: a return not read is the gap [`returned_value_gap`], and one over
/// the budget also adds the scan's budget gap. A Go ELF whose sections, every name read, have no
/// `.gopclntab` gets the gap [`SCAN_NO_GOPCLNTAB`]: its Go-function needles were looked for
/// nowhere. The returns go with the container's facts.
pub(crate) fn run<R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'_, R, H>,
    sections: &Sections<'_, R, H>,
    dynamic: &Dynamic,
    go: bool,
    (file, size): (&File, u64),
    limit: u64,
    sought: Sought<'_>,
) -> (ScanOutcome, Vec<FunctionReturn>) {
    let needles = sought.needles;
    let mut found = vec![];
    let mut gaps = vec![];
    let mut reader = Reader::new(file, size, limit);
    let defined = exports(e, sections, dynamic, sought, &mut found, &mut gaps);
    let returns = match &sections.symbols {
        Some(symbols) if !defined.is_empty() => {
            returns::read(e, symbols, dynamic, &mut reader, &defined)
        }
        _ => vec![],
    };
    for r in &returns {
        if let DataValue::Unknown { why } = &r.value {
            gaps.push(returned_value_gap(&r.function, why));
            if why == OVER_BUDGET {
                gaps.push(scan_over_gap(limit));
            }
        }
    }
    let kinds: Vec<NeedleKind> = [(NeedleKind::GoFunction, go), (NeedleKind::String, true)]
        .into_iter()
        .filter(|(kind, applies)| *applies && !needles.of(*kind).is_empty())
        .map(|(kind, _)| kind)
        .collect();
    if !kinds.is_empty() {
        match &sections.table {
            None => gaps.push(SCAN_NO_SECTIONS.to_string()),
            Some(table) => {
                // `targets` adds no gap but the one for a name not read.
                let before = gaps.len();
                let targets = targets(e, table, &kinds, &mut gaps);
                let names_read = gaps.len() == before;
                // Go build info, and no section named `.gopclntab` (PR #97 review P2). With a name
                // not read, that gap already says the section may be there unseen.
                if kinds.contains(&NeedleKind::GoFunction)
                    && names_read
                    && !targets.iter().any(|t| t.kind == NeedleKind::GoFunction)
                {
                    gaps.push(SCAN_NO_GOPCLNTAB.to_string());
                }
                let searched = search(&mut reader, needles, &targets);
                found.extend(searched.found);
                gaps.extend(searched.gaps);
            }
        }
    }
    gaps.sort();
    gaps.dedup();
    (ScanOutcome::Scanned { found, gaps }, returns)
}

/// The export needles against the exports of the `.dynsym` the loader binds through (one with
/// no `symbols:` gap, as the code step reads it), in symbol-table order: the first export whose
/// name starts with a needle is its hint. The same walk returns the definitions among the
/// exports of each known function of `sought` (PR-4c-2b), by name, two at most: while a function
/// is looked for, every export is read, so that a second definition is seen. A relocatable object
/// has no dynamic symbols. A name that cannot be read is the gap [`SCAN_NAME_NOT_READ`], given
/// once. So are, while an export needle or a function is not found, the loader's dynamic symbols
/// when the parse has no such `.dynsym` and the loader has `DT_SYMTAB` (missing, of another type,
/// or not where `DT_SYMTAB` and `DT_STRTAB` are; plan review P2), and when the loader's dynamic
/// table could not be read to check a `.dynsym` against (`PT_DYNAMIC`, or the program headers
/// that would hold it, unreadable): the hints found are kept. Without an export needle or a
/// function, nothing is read.
fn exports<R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'_, R, H>,
    sections: &Sections<'_, R, H>,
    dynamic: &Dynamic,
    sought: Sought<'_>,
    found: &mut Vec<Found>,
    gaps: &mut Vec<String>,
) -> BTreeMap<String, Vec<Definition>> {
    let endian = e.endian;
    let mut open = sought.needles.of(NeedleKind::Export);
    let functions = sought.functions;
    let mut defined: BTreeMap<String, Vec<Definition>> = BTreeMap::new();
    if open.is_empty() && functions.is_empty() {
        return defined;
    }
    if e.header.e_type(endian) == elf::ET_REL {
        return defined;
    }
    // The loader's dynamic table was not read, so `loader_agrees` checked no `.dynsym` against
    // it: its `PT_DYNAMIC` cannot be read, or the program headers that would hold one.
    let has_dynamic = e.phdrs.iter().any(|p| p.p_type(endian) == elf::PT_DYNAMIC);
    let phdrs_unread = e.header.e_phnum(endian) != 0 && e.phdrs.is_empty();
    let unchecked = !dynamic.read && (has_dynamic || phdrs_unread);
    let symbols = sections
        .symbols
        .as_ref()
        .filter(|_| sections.dynamic_symbols_agree);
    let Some(symbols) = symbols else {
        if dynamic.symtab.is_some() || unchecked {
            gaps.push(SCAN_NAME_NOT_READ.to_string());
        }
        return defined;
    };
    // The symbols' string table, for the names object cannot read (spec §3.7).
    let strings = sections
        .table
        .as_ref()
        .and_then(|t| t.section(symbols.string_section()).ok())
        .and_then(|s| s.file_range(endian));
    // A name not read, recorded once however many there are.
    let mut unread = false;
    for sym in symbols.symbols().iter().skip(1) {
        if open.is_empty() && functions.is_empty() {
            break;
        }
        if !is_export(sym, endian) {
            continue;
        }
        let name = match sym.name(endian, symbols.strings()) {
            Ok(name) => Some(name),
            Err(_) => match strings.map(|s| e.name(s, sym.st_name(endian), MAX_IMPORT_NAME)) {
                Some(Ok(Some(name))) => Some(name),
                _ => None,
            },
        };
        let Some(name) = name else {
            unread = true;
            continue;
        };
        open.retain(|n| {
            if name.starts_with(&n.value) {
                found.push(Found {
                    feature: n.feature.clone(),
                    signal: n.kind.signal(),
                    value: UntrustedText::from_bytes(name.to_vec()),
                    at: Loc::Symbol(UntrustedText::from_bytes(name.to_vec())),
                });
                false
            } else {
                true
            }
        });
        if let Some(function) = functions.iter().find(|f| f.as_bytes() == name) {
            let defs = defined.entry(function.clone()).or_default();
            if defs.len() < 2 {
                defs.push(Definition {
                    value: sym.st_value(endian).into(),
                    size: sym.st_size(endian).into(),
                    st_type: sym.st_type(),
                    shndx: sym.st_shndx(endian),
                });
            }
        }
    }
    // A `.dynsym` not checked against the loader's table: what it does not have, the loader may.
    let missing = functions.iter().any(|f| !defined.contains_key(f));
    if unread || (unchecked && (!open.is_empty() || missing)) {
        gaps.push(SCAN_NAME_NOT_READ.to_string());
    }
    defined
}

/// The sections of `kinds` in `table`, in table order: `.gopclntab` for the Go-function needles
/// (whose header [`search`] reads first); `.rodata`, `.rodata.*`, and `.lrodata` for the string
/// needles. A section without file bytes (`SHT_NOBITS`) is none of them. A section name that
/// cannot be read is the gap [`SCAN_NAME_NOT_READ`], given once: it could be one of them.
fn targets<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'d, R, H>,
    table: &SectionTable<'d, H, &'d Bounded<R>>,
    kinds: &[NeedleKind],
    gaps: &mut Vec<String>,
) -> Vec<Target> {
    let endian = e.endian;
    // The string table the section names are in (`e_shstrndx`).
    let strings = e
        .header
        .shstrndx(endian, e.data)
        .ok()
        .and_then(|i| table.section(SectionIndex(i as usize)).ok())
        .and_then(|s| s.file_range(endian));
    let mut out = vec![];
    // A name not read, recorded once however many there are.
    let mut unread = false;
    for s in table.iter().skip(1) {
        if s.sh_type(endian) == elf::SHT_NOBITS {
            continue;
        }
        let name = match strings.map(|st| e.name(st, s.sh_name(endian), MAX_SECTION_NAME)) {
            Some(Ok(Some(name))) => name,
            _ => {
                unread = true;
                continue;
            }
        };
        let kind = if name == b".gopclntab" {
            NeedleKind::GoFunction
        } else if name == b".rodata" || name == b".lrodata" || name.starts_with(b".rodata.") {
            NeedleKind::String
        } else {
            continue;
        };
        if kinds.contains(&kind) {
            out.push(Target {
                kind,
                name: name.to_vec(),
                offset: s.sh_offset(endian).into(),
                size: s.sh_size(endian).into(),
            });
        }
    }
    if unread {
        gaps.push(SCAN_NAME_NOT_READ.to_string());
    }
    out
}

/// The index of the first `needle` in `bytes`.
fn first(bytes: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    bytes.windows(needle.len()).position(|w| w == needle)
}

/// Where a Go target's function-name table is ([`pcln_table`]).
enum Pcln {
    /// Its file offset and size; for a section without bytes, an empty table at the section's
    /// offset.
    Table(u64, u64),
    /// The header is not one SIGIL reads, or locates no table within the section.
    NotUnderstood,
    /// The header's bytes are not all in the file, or a read failed.
    Unread,
    /// The header's read would pass `binary_scan_bytes`.
    OverBudget,
}

/// Reads the `pcHeader` of the Go target `t` (at most [`PCLN_HEADER_MAX`] bytes, charged to
/// `reader`), and returns where its function-name table is ([`function_names`]). When
/// `funcnameOffset` is below [`PCLN_HEADER_MAX`], the header's read overlaps the table's start, so
/// up to 36 bytes are charged twice; over-charging is safe.
fn pcln_table(reader: &mut Reader<'_>, t: &Target) -> Pcln {
    let size = reader.size();
    if t.size == 0 {
        return Pcln::Table(t.offset, 0);
    }
    let wanted = t.size.min(PCLN_HEADER_MAX);
    let n = wanted.min(size.saturating_sub(t.offset));
    if n == 0 {
        return Pcln::Unread;
    }
    let bytes = match reader.read(t.offset, n) {
        Ok(bytes) => bytes,
        Err(Refusal::Budget) => return Pcln::OverBudget,
        Err(_) => return Pcln::Unread,
    };
    match function_names(&bytes, t.size) {
        Some((from, len)) => Pcln::Table(t.offset.saturating_add(from), len),
        // A header cut by the end of the file was not read whole.
        None if n < wanted => Pcln::Unread,
        None => Pcln::NotUnderstood,
    }
}

/// The function-name table of a `.gopclntab` of `size` bytes whose first bytes are `header`
/// (PR-4c-3a plan review P2): `[funcnameOffset, cuOffset)` from the section's start, as Go's
/// `pcHeader` gives it for Go 1.16 and later (1.16's and 1.18's layouts), in either byte order (the
/// magic's), returned as `(from, len)`: the table's offset from the section's start and its length.
/// The header's other bytes are `pad1` and `pad2` (zero), `minLC` (1, 2, or 4), `ptrSize` (4 or 8),
/// then its pointer-size fields: `nfunc`, `nfiles`, from Go 1.18 `textStart`, `funcnameOffset`,
/// `cuOffset`, `filetabOffset`, `pctabOffset`, and `pclnOffset`. `None` for another magic or
/// another value, a header shorter than its fields, or a table not after the header and within the
/// section.
fn function_names(header: &[u8], size: u64) -> Option<(u64, u64)> {
    let magic: [u8; 4] = header.get(..4)?.try_into().ok()?;
    let known = [GO116_MAGIC, GO118_MAGIC, GO120_MAGIC];
    let (big, magic) = if known.contains(&u32::from_le_bytes(magic)) {
        (false, u32::from_le_bytes(magic))
    } else {
        (true, u32::from_be_bytes(magic))
    };
    // The pointer-size fields before `funcnameOffset`.
    let leading = match magic {
        GO116_MAGIC => 2,
        GO118_MAGIC | GO120_MAGIC => 3,
        _ => return None,
    };
    let [pad1, pad2, min_lc, ptr]: [u8; 4] = header.get(4..8)?.try_into().ok()?;
    if pad1 != 0 || pad2 != 0 || ![1, 2, 4].contains(&min_lc) || ![4, 8].contains(&ptr) {
        return None;
    }
    let ptr = usize::from(ptr);
    let field = |k: usize| -> Option<u64> {
        let b = header.get(8 + k * ptr..8 + (k + 1) * ptr)?;
        Some(match (b.len(), big) {
            (4, false) => u64::from(u32::from_le_bytes(b.try_into().ok()?)),
            (4, true) => u64::from(u32::from_be_bytes(b.try_into().ok()?)),
            (_, false) => u64::from_le_bytes(b.try_into().ok()?),
            (_, true) => u64::from_be_bytes(b.try_into().ok()?),
        })
    };
    // The header ends with `pclnOffset`, the fifth field from `funcnameOffset`.
    field(leading + 4)?;
    let own = (8 + (leading + 5) * ptr) as u64;
    let (from, to) = (field(leading)?, field(leading + 1)?);
    // `from <= to`, so the subtraction is safe.
    (own <= from && from <= to && to <= size).then(|| (from, to - from))
}

/// The first offset in `bytes` of the Go function name `name` as an entry of `.gopclntab`'s
/// function-name table (PR-4c-3a): the name, then a NUL, after a NUL. `before` is the byte before
/// `bytes`, none at the table's start, where a name may begin. A name whose NUL is past `bytes` is
/// not matched; the next read, which overlaps this one, has it whole.
fn first_entry(bytes: &[u8], name: &[u8], before: Option<u8>) -> Option<usize> {
    if name.is_empty() {
        return None;
    }
    bytes.windows(name.len()).enumerate().find_map(|(i, w)| {
        let prior = match i.checked_sub(1) {
            Some(p) => bytes.get(p).copied(),
            None => before,
        };
        let entry =
            w == name && bytes.get(i + name.len()) == Some(&0) && prior.is_none_or(|b| b == 0);
        entry.then_some(i)
    })
}

/// The hint of needle `n`, found at `offset` in target `t`.
fn found(n: &Needle, t: &Target, offset: u64) -> Found {
    Found {
        feature: n.feature.clone(),
        signal: n.kind.signal(),
        value: UntrustedText::from_bytes(n.value.clone()),
        at: Loc::Section {
            name: UntrustedText::from_bytes(t.name.clone()),
            offset,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::binary::needles::parse;
    use crate::binary::read::Budgeted;

    const MIB: usize = CHUNK as usize;

    fn file(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f
    }

    /// A database of `(feature, kind, value)` needles.
    fn db(needles: &[(&str, &str, &str)]) -> Needles {
        let text: String = needles
            .iter()
            .map(|(f, k, v)| {
                format!(
                    "[[needle]]\nfeature = \"{f}\"\nkind = \"{k}\"\nvalue = \"{v}\"\n\
                     source = \"t\"\n"
                )
            })
            .collect();
        parse(&text).unwrap()
    }

    fn target(kind: NeedleKind, name: &str, offset: u64, size: u64) -> Target {
        Target {
            kind,
            name: name.as_bytes().to_vec(),
            offset,
            size,
        }
    }

    fn rodata(offset: u64, size: u64) -> Target {
        target(NeedleKind::String, ".rodata", offset, size)
    }

    fn gopclntab(offset: u64, size: u64) -> Target {
        target(NeedleKind::GoFunction, ".gopclntab", offset, size)
    }

    /// `bytes` of zeros with each `(offset, text)` written in.
    fn bytes(len: usize, at: &[(usize, &str)]) -> Vec<u8> {
        let mut b = vec![0u8; len];
        for (offset, text) in at {
            b[*offset..*offset + text.len()].copy_from_slice(text.as_bytes());
        }
        b
    }

    /// The start of the function-name table in [`header`]'s headers: the header's own 72 bytes.
    const TABLE: usize = 0x48;

    /// Writes at `at` in `b` a Go 1.20 `pcHeader` (little-endian, 8-byte pointers) whose
    /// function-name table is `[TABLE, names_end)` from the header's start (PR-4c-3a plan review
    /// P2); the other tables start at `names_end`.
    fn header(b: &mut [u8], at: usize, names_end: u64) {
        let mut h = vec![0xf1, 0xff, 0xff, 0xff, 0, 0, 1, 8];
        for field in [
            1,
            1,
            0,
            TABLE as u64,
            names_end,
            names_end,
            names_end,
            names_end,
        ] {
            h.extend_from_slice(&field.to_le_bytes());
        }
        b[at..at + h.len()].copy_from_slice(&h);
    }

    /// (feature, section, offset) of each needle found.
    fn places(s: &Searched) -> Vec<(String, String, u64)> {
        s.found
            .iter()
            .map(|f| match &f.at {
                Loc::Section { name, offset } => (
                    f.feature.to_string(),
                    name.as_str().unwrap().to_string(),
                    *offset,
                ),
                other => panic!("{other:?}"),
            })
            .collect()
    }

    fn run(b: &[u8], limit: u64, needles: &Needles, targets: &[Target]) -> Searched {
        let f = file(b);
        search(
            &mut Reader::new(f.as_file(), b.len() as u64, limit),
            needles,
            targets,
        )
    }

    #[test]
    fn a_needle_across_a_chunk_boundary_is_found_once() {
        let needles = db(&[("s.needle", "string", "NEEDLE")]);
        // Across the first boundary, then again in the second chunk and the third.
        let b = bytes(
            2 * MIB + 64,
            &[
                (MIB - 3, "NEEDLE"),
                (MIB + 10, "NEEDLE"),
                (2 * MIB, "NEEDLE"),
            ],
        );
        let s = run(&b, 1 << 30, &needles, &[rodata(0, b.len() as u64)]);
        assert_eq!(
            places(&s),
            [("s.needle".to_string(), ".rodata".to_string(), CHUNK - 3)]
        );
        assert_eq!(s.found[0].signal, Signal::String);
        assert_eq!(s.found[0].value.as_str(), Some("NEEDLE"));
        assert!(s.gaps.is_empty());
        // Found in the first read (the chunk and the overlap): nothing more is read.
        assert_eq!(s.used, CHUNK + 5);
    }

    #[test]
    fn the_overlap_is_the_longest_needle_of_the_kind_minus_one() {
        let needles = db(&[
            ("s.short", "string", "wxyz"),
            ("s.long", "string", "abcdefghi"),
            ("g.other", "go-function", "0123456789abcdefghij"),
        ]);
        let len = 2 * MIB + 100;
        // Nothing to find: every chunk is read with 8 more bytes, but the last.
        let s = run(&vec![0u8; len], 1 << 30, &needles, &[rodata(0, len as u64)]);
        assert!(s.found.is_empty());
        assert_eq!(s.used, len as u64 + 2 * 8);
        // The longest needle, starting at the last byte of the first chunk, ends at the last
        // byte of the overlap.
        let b = bytes(len, &[(MIB - 1, "abcdefghi")]);
        let s = run(&b, 1 << 30, &needles, &[rodata(0, len as u64)]);
        assert_eq!(
            places(&s),
            [("s.long".to_string(), ".rodata".to_string(), CHUNK - 1)]
        );
    }

    #[test]
    fn a_section_is_read_only_within_the_file_and_its_own_bytes() {
        let needles = db(&[("s.needle", "string", "abcd")]);
        let b = bytes(1000, &[(950, "abcd")]);
        // Past the end of the file: read to the end of the file, and the rest is a gap.
        let s = run(&b, 1 << 30, &needles, &[rodata(900, 5000)]);
        assert_eq!(
            places(&s),
            [("s.needle".to_string(), ".rodata".to_string(), 50)]
        );
        assert_eq!(s.gaps, [SCAN_READ_FAILED]);
        assert_eq!(s.used, 100);
        // Wholly past the end: nothing is read, and the section is a gap.
        let s = run(&b, 1 << 30, &needles, &[rodata(2000, 100)]);
        assert!(s.found.is_empty());
        assert_eq!(s.gaps, [SCAN_READ_FAILED]);
        assert_eq!(s.used, 0);
        // Two sections that overlap: each read within its own bytes.
        let s = run(&b, 1 << 30, &needles, &[rodata(0, 600), rodata(500, 400)]);
        assert!(s.found.is_empty());
        assert!(s.gaps.is_empty());
        assert_eq!(s.used, 600 + 400);
        // Found in the first section: the second is not read.
        let s = run(&b, 1 << 30, &needles, &[rodata(900, 100), rodata(0, 1000)]);
        assert_eq!(
            places(&s),
            [("s.needle".to_string(), ".rodata".to_string(), 50)]
        );
        assert!(s.gaps.is_empty());
        assert_eq!(s.used, 100);
    }

    #[test]
    fn a_needle_at_a_chunk_start_is_found_in_the_next_read() {
        let needles = db(&[("s.needle", "string", "NEEDLE")]);
        // Chunks start at the section's offset: the needle starts the section's second chunk.
        let b = bytes(2 * MIB + 200, &[(100 + MIB, "NEEDLE")]);
        let s = run(&b, 1 << 30, &needles, &[rodata(100, 2 * CHUNK + 50)]);
        assert_eq!(
            places(&s),
            [("s.needle".to_string(), ".rodata".to_string(), CHUNK)]
        );
        assert!(s.gaps.is_empty());
        // Two reads, each the chunk and the overlap (5 bytes).
        assert_eq!(s.used, 2 * (CHUNK + 5));
    }

    #[test]
    fn a_needle_ending_at_the_last_byte_of_a_section_is_found() {
        let needles = db(&[("s.needle", "string", "abcd")]);
        // In the section's last read, the four bytes before its end.
        let b = bytes(MIB + 100, &[(MIB + 6, "abcd")]);
        let s = run(&b, 1 << 30, &needles, &[rodata(0, CHUNK + 10)]);
        assert_eq!(
            places(&s),
            [("s.needle".to_string(), ".rodata".to_string(), CHUNK + 6)]
        );
        assert!(s.gaps.is_empty());
        assert_eq!(s.used, CHUNK + 3 + 10);
        // Across the section's end, the file has it; the section does not.
        let b = bytes(MIB + 100, &[(MIB + 8, "abcd")]);
        let s = run(&b, 1 << 30, &needles, &[rodata(0, CHUNK + 10)]);
        assert!(s.found.is_empty());
        assert!(s.gaps.is_empty());
        assert_eq!(s.used, CHUNK + 3 + 10);
    }

    #[test]
    fn the_budget_stops_the_scan_and_keeps_what_was_found() {
        let needles = db(&[
            ("s.first", "string", "first-needle"),
            ("s.second", "string", "second-needle"),
        ]);
        let len = 2 * MIB + 100;
        let b = bytes(len, &[(10, "first-needle"), (MIB + 500, "second-needle")]);
        let limit = CHUNK + 20;
        let s = run(&b, limit, &needles, &[rodata(0, len as u64)]);
        assert_eq!(
            places(&s),
            [("s.first".to_string(), ".rodata".to_string(), 10)]
        );
        assert_eq!(
            s.gaps,
            [format!("string scan: binary_scan_bytes {limit} exceeded")]
        );
        // The first read (the chunk and 12 bytes of overlap); the second was refused.
        assert_eq!(s.used, CHUNK + 12);
        // Reading stops for every kind: no later target is read. The Go target's header is read,
        // and its function-name table refused.
        let go = db(&[
            ("g.f", "go-function", "main.f"),
            ("s.first", "string", "first-needle"),
        ]);
        let mut b = bytes(2000, &[(0x100, "main.f"), (1500, "first-needle")]);
        header(&mut b, 0, 1000);
        let s = run(&b, 100, &go, &[gopclntab(0, 1000), rodata(1000, 1000)]);
        assert!(s.found.is_empty());
        assert_eq!(s.gaps, ["string scan: binary_scan_bytes 100 exceeded"]);
        assert_eq!(s.used, TABLE as u64);
        // The header itself over the budget: nothing is read.
        let s = run(&b, 10, &go, &[gopclntab(0, 1000), rodata(1000, 1000)]);
        assert!(s.found.is_empty());
        assert_eq!(s.gaps, ["string scan: binary_scan_bytes 10 exceeded"]);
        assert_eq!(s.used, 0);
        // The header's read refused while a later string target would fit: reading stops for
        // every kind (`break 'kinds`).
        let mut b = bytes(2000, &[(1500, "first-needle")]);
        header(&mut b, 0, 1000);
        let s = run(&b, 50, &go, &[gopclntab(0, 1000), rodata(1500, 20)]);
        assert!(s.found.is_empty());
        assert_eq!(s.gaps, ["string scan: binary_scan_bytes 50 exceeded"]);
        assert_eq!(s.used, 0);
    }

    #[test]
    fn a_kind_without_needles_reads_nothing() {
        let needles = db(&[("g.f", "go-function", "main.f")]);
        let mut b = bytes(4096, &[(100, "main.f"), (150 + 0x100, "main.f")]);
        header(&mut b, 150, 1000);
        let s = run(&b, 1 << 30, &needles, &[rodata(0, 4096)]);
        assert_eq!(s, Searched::default());
        let s = run(&b, 1 << 30, &needles, &[]);
        assert_eq!(s, Searched::default());
        // The kind with a needle is read, in its own targets: the header, then the table.
        let s = run(
            &b,
            1 << 30,
            &needles,
            &[
                rodata(0, 4096),
                target(NeedleKind::GoFunction, ".gopclntab", 150, 1000),
            ],
        );
        assert_eq!(
            places(&s),
            [("g.f".to_string(), ".gopclntab".to_string(), 0x100)]
        );
        assert_eq!(s.found[0].signal, Signal::GoFunction);
        assert_eq!(s.used, 1000);
    }

    #[test]
    fn the_first_match_is_at_the_lowest_offset_of_the_first_target() {
        let needles = db(&[("s.needle", "string", "abcd")]);
        let b = bytes(4096, &[(300, "abcd"), (100, "abcd"), (3000, "abcd")]);
        let s = run(&b, 1 << 30, &needles, &[rodata(0, 4096)]);
        assert_eq!(
            places(&s),
            [("s.needle".to_string(), ".rodata".to_string(), 100)]
        );
        let s = run(
            &b,
            1 << 30,
            &needles,
            &[
                target(NeedleKind::String, ".rodata.str1.1", 2048, 2048),
                rodata(0, 2048),
            ],
        );
        assert_eq!(
            places(&s),
            [("s.needle".to_string(), ".rodata.str1.1".to_string(), 952)]
        );
    }

    #[test]
    fn needles_found_in_one_read_are_in_database_order() {
        let needles = db(&[("s.a", "string", "aaaa"), ("s.b", "string", "bbbb")]);
        // `s.b` is at the lower offset, in the same read as `s.a`.
        let b = bytes(4096, &[(100, "bbbb"), (200, "aaaa")]);
        let s = run(&b, 1 << 30, &needles, &[rodata(0, 4096)]);
        assert_eq!(
            places(&s),
            [
                ("s.a".to_string(), ".rodata".to_string(), 200),
                ("s.b".to_string(), ".rodata".to_string(), 100),
            ]
        );
        // In another target, or a later read, a needle comes after those found before it.
        let s = run(&b, 1 << 30, &needles, &[rodata(150, 100), rodata(0, 150)]);
        assert_eq!(
            places(&s),
            [
                ("s.a".to_string(), ".rodata".to_string(), 50),
                ("s.b".to_string(), ".rodata".to_string(), 100),
            ]
        );
    }

    #[test]
    fn a_failed_read_is_a_gap_and_the_next_target_is_read() {
        let needles = db(&[("s.needle", "string", "abcd")]);
        let b = bytes(100, &[(10, "abcd")]);
        let f = file(&b);
        // A size the file does not have: the first target's `pread` comes up short.
        let s = search(
            &mut Reader::new(f.as_file(), 4096, 1 << 30),
            &needles,
            &[rodata(0, 4096), rodata(0, 100)],
        );
        assert_eq!(s.gaps, [SCAN_READ_FAILED]);
        assert_eq!(
            places(&s),
            [("s.needle".to_string(), ".rodata".to_string(), 10)]
        );
        assert_eq!(s.used, 4096 + 100);
    }

    #[test]
    fn a_gopclntab_wholly_past_the_end_of_the_file_is_a_gap() {
        let go = db(&[("g.f", "go-function", "main.f")]);
        // The needle is in the file, but not in the section, which starts past its end.
        let mut b = bytes(0x20_0000, &[(0x1000 + 0x80, "main.f")]);
        header(&mut b, 0x1000, 0x100);
        let s = run(&b, 1 << 30, &go, &[gopclntab(0x20_1000, 0x1_0000)]);
        assert!(s.found.is_empty());
        assert_eq!(s.gaps, [SCAN_READ_FAILED]);
        assert_eq!(s.used, 0);
        // A section whose end overflows is past the end of the file too.
        let s = run(&b, 1 << 30, &go, &[gopclntab(u64::MAX - 10, 100)]);
        assert!(s.found.is_empty());
        assert_eq!(s.gaps, [SCAN_READ_FAILED]);
        assert_eq!(s.used, 0);
        // A kind without needles: its section is not looked at, so it is no gap.
        let s = run(&b, 1 << 30, &go, &[rodata(0x20_1000, 0x1_0000)]);
        assert_eq!(s, Searched::default());
        // Every needle of the kind already found: a later section is no gap.
        let s = run(
            &b,
            1 << 30,
            &go,
            &[gopclntab(0x1000, 0x100), gopclntab(0x20_1000, 0x1_0000)],
        );
        assert_eq!(
            places(&s),
            [("g.f".to_string(), ".gopclntab".to_string(), 0x80)]
        );
        assert!(s.gaps.is_empty());
        assert_eq!(s.used, 0x100);
    }

    #[test]
    fn a_gopclntab_cut_by_the_end_of_the_file_is_searched_and_a_gap() {
        let go = db(&[("g.f", "go-function", "main.f")]);
        // `sh_size` passes the end of the file, and so does the function-name table: the 0x1000
        // bytes in the file are read, the header and the table's first bytes.
        let mut b = bytes(0x20_0000, &[(0x1F_F100, "main.f")]);
        header(&mut b, 0x1F_F000, 0x1_0000);
        let s = run(&b, 1 << 30, &go, &[gopclntab(0x1F_F000, 0x1_0000)]);
        assert_eq!(
            places(&s),
            [("g.f".to_string(), ".gopclntab".to_string(), 0x100)]
        );
        assert_eq!(s.found[0].signal, Signal::GoFunction);
        assert_eq!(s.gaps, [SCAN_READ_FAILED]);
        assert_eq!(s.used, 0x1000);
        // A header cut by the end of the file: unread, not misunderstood.
        let s = run(&b, 1 << 30, &go, &[gopclntab(0x20_0000 - 40, 0x1_0000)]);
        assert!(s.found.is_empty());
        assert_eq!(s.gaps, [SCAN_READ_FAILED]);
        assert_eq!(s.used, 40);
    }

    #[test]
    fn an_empty_section_past_the_end_of_the_file_is_no_gap() {
        let go = db(&[("g.f", "go-function", "main.f")]);
        let mut b = bytes(1000, &[(0x100, "main.f")]);
        header(&mut b, 0, 1000);
        // `sh_size` 0: no byte of the section is missing.
        let s = run(&b, 1 << 30, &go, &[gopclntab(2000, 0)]);
        assert_eq!(s, Searched::default());
        let s = run(
            &b,
            1 << 30,
            &go,
            &[gopclntab(u64::MAX, 0), gopclntab(0, 1000)],
        );
        assert_eq!(
            places(&s),
            [("g.f".to_string(), ".gopclntab".to_string(), 0x100)]
        );
        assert!(s.gaps.is_empty());
        assert_eq!(s.used, 1000);
    }

    #[test]
    fn a_go_function_needle_matches_only_an_exact_name() {
        let needles = db(&[("g.open", "go-function", "os.Open")]);
        // Followed by another byte (`os.OpenFile`), after another byte (`bios.Open`), then exact.
        let mut b = bytes(
            4096,
            &[(100, "os.OpenFile"), (200, "bios.Open"), (300, "os.Open")],
        );
        header(&mut b, 0, 4096);
        let s = run(&b, 1 << 30, &needles, &[gopclntab(0, 4096)]);
        assert_eq!(
            places(&s),
            [("g.open".to_string(), ".gopclntab".to_string(), 300)]
        );
        assert_eq!(s.found[0].value.as_str(), Some("os.Open"));
        // Neither of the other two is a match.
        let mut b = bytes(4096, &[(100, "os.OpenFile"), (200, "bios.Open")]);
        header(&mut b, 0, 4096);
        let s = run(&b, 1 << 30, &needles, &[gopclntab(0, 4096)]);
        assert!(s.found.is_empty());
        // A string needle still matches anywhere.
        let strings = db(&[("s.open", "string", "os.Open")]);
        let s = run(&b, 1 << 30, &strings, &[rodata(0, 4096)]);
        assert_eq!(
            places(&s),
            [("s.open".to_string(), ".rodata".to_string(), 100)]
        );
    }

    #[test]
    fn a_go_function_name_may_start_the_table_but_must_end_with_a_nul_in_it() {
        let needles = db(&[("g.f", "go-function", "main.f")]);
        // At the table's first byte, after the header's last, which is not a NUL here.
        let mut b = bytes(1000, &[(TABLE, "main.f")]);
        header(&mut b, 0, 1000);
        b[TABLE - 1] = b'x';
        let s = run(&b, 1 << 30, &needles, &[gopclntab(0, 1000)]);
        assert_eq!(
            places(&s),
            [("g.f".to_string(), ".gopclntab".to_string(), TABLE as u64)]
        );
        // Ending at the table's last byte: the NUL after it is in the section, not in the table.
        let mut b = bytes(1000, &[(0x100, "main.f")]);
        header(&mut b, 0, 0x106);
        let s = run(&b, 1 << 30, &needles, &[gopclntab(0, 1000)]);
        assert!(s.found.is_empty());
        assert_eq!(s.used, 0x106);
        header(&mut b, 0, 0x107);
        let s = run(&b, 1 << 30, &needles, &[gopclntab(0, 1000)]);
        assert_eq!(
            places(&s),
            [("g.f".to_string(), ".gopclntab".to_string(), 0x100)]
        );
    }

    /// PR-4c-3a plan review P2: `.gopclntab`'s file table holds NUL-terminated names too (a
    /// `//line` directive can make one look like a function); only the function-name table is
    /// looked in.
    #[test]
    fn a_go_function_name_outside_the_function_name_table_is_not_found() {
        let needles = db(&[("g.start", "go-function", "os/exec.(*Cmd).Start")]);
        let name = "os/exec.(*Cmd).Start";
        // A realistic header: the table ends at cuOffset (0x800), not at filetabOffset (0x880).
        let layout = |cu: u64, filetab: u64| {
            raw_header(
                0xffff_fff1,
                false,
                8,
                &[1, 1, 0, TABLE as u64, cu, filetab, 0x900, 0x900],
            )
        };
        let build = |at: usize, cu: u64, filetab: u64| {
            let mut b = bytes(4096, &[(0x100, "main.main"), (at, name)]);
            let h = layout(cu, filetab);
            b[..h.len()].copy_from_slice(&h);
            b
        };
        // In the file table (between filetabOffset and pctabOffset), and between cuOffset and
        // filetabOffset: not found. The header and the table are read, nothing past it.
        for at in [0x8a0, 0x840] {
            let b = build(at, 0x800, 0x880);
            let s = run(&b, 1 << 30, &needles, &[gopclntab(0, 4096)]);
            assert!(s.found.is_empty(), "{at:#x}");
            assert!(s.gaps.is_empty());
            assert_eq!(s.used, 0x800);
        }
        // With cuOffset past the name, it is an entry of the table.
        let b = build(0x8a0, 0x8c0, 0x900);
        let s = run(&b, 1 << 30, &needles, &[gopclntab(0, 4096)]);
        assert_eq!(
            places(&s),
            [("g.start".to_string(), ".gopclntab".to_string(), 0x8a0)]
        );
    }

    /// The table's bound is the section's size, not the file's.
    #[test]
    fn a_table_past_the_section_but_inside_the_file_is_not_understood() {
        let needles = db(&[("g.f", "go-function", "main.f")]);
        let mut b = bytes(0x400, &[(0x100, "main.f")]);
        header(&mut b, 0, 0x300);
        let s = run(&b, 1 << 30, &needles, &[gopclntab(0, 0x200)]);
        assert!(s.found.is_empty());
        assert_eq!(s.gaps, [SCAN_GOPCLNTAB_HEADER]);
        assert_eq!(s.used, 72);
    }

    /// The read-failed gap is judged on the table's end, not the section's.
    #[test]
    fn a_section_past_the_file_with_its_table_inside_it_is_no_gap() {
        let needles = db(&[("g.f", "go-function", "main.f")]);
        let mut b = bytes(0x1000, &[(0x100, "main.f")]);
        header(&mut b, 0, 0x800);
        let s = run(&b, 1 << 30, &needles, &[gopclntab(0, 0x10_0000)]);
        assert_eq!(
            places(&s),
            [("g.f".to_string(), ".gopclntab".to_string(), 0x100)]
        );
        assert!(s.gaps.is_empty());
        assert_eq!(s.used, 0x800);
    }

    #[test]
    fn a_go_function_name_is_found_across_chunks() {
        let needles = db(&[("g.f", "go-function", "main.f")]);
        let len = 2 * MIB + 100;
        // Chunks start at the table's start. Its NUL is the first byte past the first chunk: in
        // the first read, which is the chunk and the name's 6 bytes more.
        let mut b = bytes(len, &[(TABLE + MIB - 6, "main.f")]);
        header(&mut b, 0, len as u64);
        let s = run(&b, 1 << 30, &needles, &[gopclntab(0, len as u64)]);
        assert_eq!(
            places(&s),
            [(
                "g.f".to_string(),
                ".gopclntab".to_string(),
                (TABLE + MIB - 6) as u64
            )]
        );
        assert_eq!(s.used, TABLE as u64 + CHUNK + 6);
        // It starts the second chunk: its NUL is past the first read, and the byte before it,
        // the first chunk's last, is kept from that read.
        let mut b = bytes(len, &[(TABLE + MIB, "main.f")]);
        header(&mut b, 0, len as u64);
        let s = run(&b, 1 << 30, &needles, &[gopclntab(0, len as u64)]);
        assert_eq!(
            places(&s),
            [(
                "g.f".to_string(),
                ".gopclntab".to_string(),
                (TABLE + MIB) as u64
            )]
        );
        assert_eq!(s.used, TABLE as u64 + 2 * (CHUNK + 6));
        // It starts at the first chunk's last byte, after a NUL: its NUL is the last byte of the
        // first read, which holds the whole name.
        let mut b = bytes(len, &[(TABLE + MIB - 1, "main.f")]);
        header(&mut b, 0, len as u64);
        let s = run(&b, 1 << 30, &needles, &[gopclntab(0, len as u64)]);
        assert_eq!(
            places(&s),
            [(
                "g.f".to_string(),
                ".gopclntab".to_string(),
                (TABLE + MIB - 1) as u64
            )]
        );
        assert_eq!(s.used, TABLE as u64 + CHUNK + 6);
        // The same after another byte: no name, and every byte is read.
        let mut b = bytes(len, &[(TABLE + MIB, "main.f")]);
        header(&mut b, 0, len as u64);
        b[TABLE + MIB - 1] = b'x';
        let s = run(&b, 1 << 30, &needles, &[gopclntab(0, len as u64)]);
        assert!(s.found.is_empty());
        assert_eq!(s.used, len as u64 + 2 * 6);
    }

    /// A `pcHeader` of `magic` in the given byte order, with `ptr`-byte `fields`.
    fn raw_header(magic: u32, big: bool, ptr: u8, fields: &[u64]) -> Vec<u8> {
        let mut h = if big {
            magic.to_be_bytes().to_vec()
        } else {
            magic.to_le_bytes().to_vec()
        };
        h.extend_from_slice(&[0, 0, 1, ptr]);
        for &f in fields {
            match (ptr, big) {
                (4, false) => h.extend_from_slice(&(f as u32).to_le_bytes()),
                (4, true) => h.extend_from_slice(&(f as u32).to_be_bytes()),
                (_, false) => h.extend_from_slice(&f.to_le_bytes()),
                (_, true) => h.extend_from_slice(&f.to_be_bytes()),
            }
        }
        h
    }

    #[test]
    fn the_function_name_table_is_read_from_each_layout() {
        // Go 1.20 and Go 1.18: nfunc, nfiles, textStart, then the offsets.
        let go120 = raw_header(
            0xffff_fff1,
            false,
            8,
            &[1, 1, 0, 0x48, 0x100, 0x100, 0x100, 0x100],
        );
        assert_eq!(function_names(&go120, 0x200), Some((0x48, 0xb8)));
        // Go 1.20, little-endian, 4-byte pointers (a 40-byte header).
        let ptr4 = raw_header(
            0xffff_fff1,
            false,
            4,
            &[1, 1, 0, 0x28, 0x100, 0x100, 0x100, 0x100],
        );
        assert_eq!(function_names(&ptr4, 0x200), Some((0x28, 0xd8)));
        // Go 1.20, big-endian, 8-byte pointers.
        let be8 = raw_header(
            0xffff_fff1,
            true,
            8,
            &[1, 1, 0, 0x48, 0x100, 0x100, 0x100, 0x100],
        );
        assert_eq!(function_names(&be8, 0x200), Some((0x48, 0xb8)));
        // A minLC of 2 is accepted.
        let mut min_lc2 = go120.clone();
        min_lc2[6] = 2;
        assert_eq!(function_names(&min_lc2, 0x200), Some((0x48, 0xb8)));
        let go118 = raw_header(
            0xffff_fff0,
            true,
            4,
            &[1, 1, 0, 0x28, 0x100, 0x100, 0x100, 0x100],
        );
        assert_eq!(function_names(&go118, 0x200), Some((0x28, 0xd8)));
        // Go 1.16: no textStart.
        let go116 = raw_header(0xffff_fffa, false, 8, &[1, 1, 0x40, 0x80, 0x80, 0x80, 0x80]);
        assert_eq!(function_names(&go116, 0x200), Some((0x40, 0x40)));
        let go116 = raw_header(0xffff_fffa, true, 4, &[1, 1, 0x24, 0x80, 0x80, 0x80, 0x80]);
        assert_eq!(function_names(&go116, 0x200), Some((0x24, 0x5c)));
        // An empty table is a table.
        let empty = raw_header(
            0xffff_fff1,
            false,
            8,
            &[1, 1, 0, 0x48, 0x48, 0x48, 0x48, 0x48],
        );
        assert_eq!(function_names(&empty, 0x48), Some((0x48, 0)));
    }

    #[test]
    fn a_header_not_understood_is_a_gap() {
        let ok = [1, 1, 0, 0x48, 0x100, 0x100, 0x100, 0x100];
        let mut bad = vec![
            // Go 1.2's magic, and none.
            raw_header(0xffff_fffb, false, 8, &ok),
            raw_header(0, false, 8, &ok),
            // A pointer size of 2 (below: a pad byte set, and a minLC of 3).
            raw_header(0xffff_fff1, false, 2, &ok),
            // The table inside the header, after the next table, or past the section.
            raw_header(
                0xffff_fff1,
                false,
                8,
                &[1, 1, 0, 0x40, 0x100, 0x100, 0x100, 0x100],
            ),
            raw_header(
                0xffff_fff1,
                false,
                8,
                &[1, 1, 0, 0x100, 0x80, 0x100, 0x100, 0x100],
            ),
            raw_header(
                0xffff_fff1,
                false,
                8,
                &[1, 1, 0, 0x48, 0x300, 0x300, 0x300, 0x300],
            ),
            // A header shorter than its fields.
            raw_header(0xffff_fff1, false, 8, &[1, 1, 0, 0x48, 0x100, 0x100, 0x100]),
        ];
        let mut padded = raw_header(0xffff_fff1, false, 8, &ok);
        padded[4] = 1;
        bad.push(padded);
        let mut pad2 = raw_header(0xffff_fff1, false, 8, &ok);
        pad2[5] = 1;
        bad.push(pad2);
        let mut min_lc = raw_header(0xffff_fff1, false, 8, &ok);
        min_lc[6] = 3;
        bad.push(min_lc);
        for h in &bad {
            assert_eq!(function_names(h, 0x200), None, "{h:02x?}");
        }
        // In a scan: the gap, and the Go-function needles not looked for in that section.
        let needles = db(&[("g.f", "go-function", "main.f")]);
        let mut b = bytes(0x200, &[(0x100, "main.f")]);
        b[..bad[1].len()].copy_from_slice(&bad[1]);
        let s = run(&b, 1 << 30, &needles, &[gopclntab(0, 0x200)]);
        assert!(s.found.is_empty());
        assert_eq!(s.gaps, [SCAN_GOPCLNTAB_HEADER]);
        assert_eq!(s.used, 72);
        // A section shorter than its header: its header is not understood either.
        let go120 = raw_header(0xffff_fff1, false, 8, &ok);
        b[..go120.len()].copy_from_slice(&go120);
        let s = run(&b, 1 << 30, &needles, &[gopclntab(0, 40)]);
        assert_eq!(s.gaps, [SCAN_GOPCLNTAB_HEADER]);
        assert_eq!(s.used, 40);
    }

    #[test]
    fn the_gaps_are_sorted_and_each_is_given_once() {
        let needles = db(&[("s.needle", "string", "abcd")]);
        let b = bytes(1000, &[]);
        // Two targets past the end of the file, then one over the budget.
        let s = run(
            &b,
            150,
            &needles,
            &[rodata(900, 5000), rodata(2000, 100), rodata(0, 1000)],
        );
        assert!(s.found.is_empty());
        assert_eq!(
            s.gaps,
            [
                "string scan: a read failed",
                "string scan: binary_scan_bytes 150 exceeded"
            ]
        );
        assert_eq!(s.used, 100);
    }

    type H64 = object::elf::FileHeader64<Endianness>;

    /// The parts of the ELF64 file `f`, as `elf::parse_as` has them before the scan.
    fn with_parts<T>(
        f: &tempfile::NamedTempFile,
        then: impl for<'d, 'f> FnOnce(
            &Elf<'d, Budgeted<'f>, H64>,
            &Sections<'d, Budgeted<'f>, H64>,
            &Dynamic,
        ) -> T,
    ) -> T {
        let file = f.reopen().unwrap();
        let size = file.metadata().unwrap().len();
        let data = Bounded::new(Budgeted::new(&file, size), size, 64 << 20);
        let p = super::super::elf::parts::<_, H64>(&data, crate::binary::BinaryBudgets::default())
            .unwrap();
        then(&p.elf, &p.sections, &p.dynamic)
    }

    fn libdata() -> Vec<u8> {
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/elf/libdata.so"
        ))
        .unwrap()
    }

    /// Final branch review: a gap is given once, however many section names cannot be read.
    #[test]
    fn section_names_not_read_are_one_gap() {
        let mut b = libdata();
        // Every section's `sh_name` past the section-name table (ELF64: `e_shoff` at 40,
        // `e_shentsize` at 58, `e_shnum` at 60; `sh_name` first in each header).
        let u16_at = |b: &[u8], at: usize| u16::from_le_bytes([b[at], b[at + 1]]) as usize;
        let shoff = u64::from_le_bytes(b[40..48].try_into().unwrap()) as usize;
        let (entsize, count) = (u16_at(&b, 58), u16_at(&b, 60));
        assert!(count > 2, "{count}");
        for k in 1..count {
            let at = shoff + k * entsize;
            b[at..at + 4].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        }
        let f = file(&b);
        with_parts(&f, |e, sections, _| {
            let table = sections.table.as_ref().unwrap();
            let mut gaps = vec![];
            let kinds = [NeedleKind::GoFunction, NeedleKind::String];
            assert_eq!(targets(e, table, &kinds, &mut gaps), []);
            assert_eq!(gaps, [SCAN_NAME_NOT_READ]);
        });
    }

    /// Final branch review: a gap is given once, however many export names cannot be read.
    #[test]
    fn export_names_not_read_are_one_gap() {
        let mut b = libdata();
        // Every `.dynsym` entry's `st_name` past its string table.
        let (offset, size) = {
            use object::{Object, ObjectSection};
            let elf = object::read::elf::ElfFile64::<Endianness>::parse(&b[..]).unwrap();
            elf.section_by_name(".dynsym")
                .unwrap()
                .file_range()
                .unwrap()
        };
        let mut exported = 0;
        for at in (offset..offset + size).step_by(24) {
            let at = at as usize;
            b[at..at + 4].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
            // STB_GLOBAL with a defined section: one of the exports the walk names.
            exported += usize::from(b[at + 4] >> 4 == 1 && b[at + 6..at + 8] != [0, 0]);
        }
        assert!(exported > 1, "{exported}");
        let f = file(&b);
        let needles = db(&[("rpc.code_present", "export", "ggml_backend_rpc_")]);
        with_parts(&f, |e, sections, dynamic| {
            let (mut found, mut gaps) = (vec![], vec![]);
            let sought = Sought {
                needles: &needles,
                functions: &[],
            };
            exports(e, sections, dynamic, sought, &mut found, &mut gaps);
            assert_eq!(found, []);
            assert_eq!(gaps, [SCAN_NAME_NOT_READ]);
        });
    }
}
