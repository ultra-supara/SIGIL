//! The signature scan (PR-4c-2a spec §2–§4). The needles of [`super::needles`] are looked for in
//! an ELF file's `.gopclntab` and read-only data sections ([`search`]), read with `pread` on the
//! parse's fd in [`CHUNK`]-byte chunks, each byte charged to `binary_scan_bytes` before it is read
//! (`code::reader`). Nothing is mapped. Export needles are matched against the names of the
//! parse's dynamic symbols instead, charged to `binary_parse_bytes`.

use std::fs::File;

use object::elf;
use object::read::elf::{FileHeader, ProgramHeader, SectionHeader, SectionTable, Sym};
use object::read::{ReadCacheOps, SectionIndex};
use object::Endianness;
use sigil_model::{
    scan_over_gap, FeatureKey, Loc, Signal, UntrustedText, SCAN_NAME_NOT_READ, SCAN_NO_GOPCLNTAB,
    SCAN_NO_SECTIONS, SCAN_READ_FAILED,
};

use super::elf::{is_export, Dynamic, Elf, Sections, MAX_IMPORT_NAME};
use super::needles::{Needle, NeedleKind, Needles};
use super::read::Bounded;
use crate::code::reader::{Reader, Refusal};

/// The bytes of a section examined per read. Each read is one chunk and the overlap of its kind
/// ([`Needles::overlap`]), so that a needle that starts in the chunk is read whole.
pub const CHUNK: u64 = 1 << 20;

/// The longest section name read. A longer one is a gap.
pub const MAX_SECTION_NAME: usize = 4096;

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

/// A section [`search`] reads: the kind of needle looked for in it, its name, and its bytes in
/// the file (`sh_offset`, `sh_size`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub kind: NeedleKind,
    pub name: Vec<u8>,
    pub offset: u64,
    pub size: u64,
}

/// What [`search`] found, and read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Searched {
    /// The first match of each needle found, at its lowest offset in the first target that has it:
    /// in target order, then read order, then database order (the needles found in one read).
    pub found: Vec<Found>,
    /// Sorted, without repeats.
    pub gaps: Vec<String>,
    /// The bytes charged to `binary_scan_bytes`.
    pub used: u64,
}

/// Looks for the needles of each target's kind in its bytes, read from `file` (`size` bytes, from
/// the read's `fstat`) within `limit` bytes: the Go-function needles in their targets, then the
/// string needles in theirs, each kind until all its needles are found. A kind without a needle
/// reads nothing. A target is read only within the file and within its own bytes; one with bytes
/// past the end of the file (or whose end overflows) while a needle of its kind is still looked
/// for has its bytes in the file read, and the gap [`SCAN_READ_FAILED`]. Over `limit`, reading
/// stops, and what was found is kept with the gap [`scan_over_gap`]. A read that fails leaves the
/// rest of its target unread, with the gap [`SCAN_READ_FAILED`]. Each gap is given once.
pub fn search(
    file: &File,
    size: u64,
    limit: u64,
    needles: &Needles,
    targets: &[Target],
) -> Searched {
    let mut reader = Reader::new(file, size, limit);
    let mut out = Searched::default();
    // The gaps: bytes of a target not read (past the end of the file, or a failed read), and the
    // budget.
    let (mut unread, mut over) = (false, false);
    'kinds: for kind in [NeedleKind::GoFunction, NeedleKind::String] {
        let mut open = needles.of(kind);
        let overlap = needles.overlap(kind);
        for t in targets.iter().filter(|t| t.kind == kind) {
            // Bytes of the section the file does not have: a needle may be there unread.
            if !open.is_empty()
                && t.size > 0
                && t.offset.checked_add(t.size).is_none_or(|e| e > size)
            {
                unread = true;
            }
            let end = t.offset.saturating_add(t.size).min(size);
            let mut pos = t.offset;
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
                open.retain(|n| match first(&bytes, &n.value) {
                    Some(i) => {
                        out.found.push(found(n, t, pos - t.offset + i as u64));
                        false
                    }
                    None => true,
                });
                pos = stop;
            }
        }
    }
    if unread {
        out.gaps.push(SCAN_READ_FAILED.to_string());
    }
    if over {
        out.gaps.push(scan_over_gap(limit));
    }
    out.gaps.sort();
    out.used = reader.used();
    out
}

/// The signature scan of the ELF `e` (PR-4c-2a), after its container and code steps: the export
/// needles against the names of its exported dynamic symbols ([`exports`]), then [`search`] for
/// the Go-function needles in `.gopclntab` (when it has Go build info, `go`) and for the string
/// needles in `.rodata`, `.rodata.*`, and `.lrodata` ([`targets`]). Names are read through the
/// parse's cache, charged to `binary_parse_bytes`; section bytes through `file` (the fd and its
/// `fstat` size), charged to `limit` (`binary_scan_bytes`). What cannot be read is a gap of the
/// scan, never of the container. A Go ELF whose sections, every name read, have no `.gopclntab`
/// gets the gap [`SCAN_NO_GOPCLNTAB`]: its Go-function needles were looked for nowhere.
pub(crate) fn run<R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'_, R, H>,
    sections: &Sections<'_, R, H>,
    dynamic: &Dynamic,
    go: bool,
    (file, size): (&File, u64),
    limit: u64,
    needles: &Needles,
) -> ScanOutcome {
    let mut found = vec![];
    let mut gaps = vec![];
    exports(e, sections, dynamic, needles, &mut found, &mut gaps);
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
                let searched = search(file, size, limit, needles, &targets);
                found.extend(searched.found);
                gaps.extend(searched.gaps);
            }
        }
    }
    gaps.sort();
    gaps.dedup();
    ScanOutcome::Scanned { found, gaps }
}

/// The export needles against the exports of the `.dynsym` the loader binds through (one with
/// no `symbols:` gap, as the code step reads it), in symbol-table order: the first export whose
/// name starts with a needle is its hint. A relocatable object has no dynamic symbols. A name
/// that cannot be read is the gap [`SCAN_NAME_NOT_READ`], given once. So are, while an export
/// needle is not found, the loader's dynamic symbols when the parse has no such `.dynsym` and the
/// loader has `DT_SYMTAB` (missing, of another type, or not where `DT_SYMTAB` and `DT_STRTAB`
/// are; plan review P2), and when the loader's dynamic table could not be read to check a
/// `.dynsym` against (`PT_DYNAMIC`, or the program headers that would hold it, unreadable): the
/// hints found are kept. Without an export needle, nothing is read.
fn exports<R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'_, R, H>,
    sections: &Sections<'_, R, H>,
    dynamic: &Dynamic,
    needles: &Needles,
    found: &mut Vec<Found>,
    gaps: &mut Vec<String>,
) {
    let endian = e.endian;
    let mut open = needles.of(NeedleKind::Export);
    if open.is_empty() {
        return;
    }
    if e.header.e_type(endian) == elf::ET_REL {
        return;
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
        return;
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
        if open.is_empty() {
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
    }
    // A `.dynsym` not checked against the loader's table: what it does not have, the loader may.
    if unread || (unchecked && !open.is_empty()) {
        gaps.push(SCAN_NAME_NOT_READ.to_string());
    }
}

/// The sections of `kinds` in `table`, in table order: `.gopclntab` for the Go-function needles;
/// `.rodata`, `.rodata.*`, and `.lrodata` for the string needles. A section without file bytes
/// (`SHT_NOBITS`) is none of them. A section name that cannot be read is the gap
/// [`SCAN_NAME_NOT_READ`], given once: it could be one of them.
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
                format!("[[needle]]\nfeature = \"{f}\"\nkind = \"{k}\"\nvalue = \"{v}\"\n")
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
        search(f.as_file(), b.len() as u64, limit, needles, targets)
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
        // Reading stops for every kind: no later target is read.
        let go = db(&[
            ("g.f", "go-function", "main.f"),
            ("s.first", "string", "first-needle"),
        ]);
        let s = run(
            &b,
            100,
            &go,
            &[
                target(NeedleKind::GoFunction, ".gopclntab", 0, 1000),
                rodata(0, 20),
            ],
        );
        assert!(s.found.is_empty());
        assert_eq!(s.gaps, ["string scan: binary_scan_bytes 100 exceeded"]);
        assert_eq!(s.used, 0);
    }

    #[test]
    fn a_kind_without_needles_reads_nothing() {
        let needles = db(&[("g.f", "go-function", "main.f")]);
        let b = bytes(4096, &[(100, "main.f"), (200, "main.f")]);
        let s = run(&b, 1 << 30, &needles, &[rodata(0, 4096)]);
        assert_eq!(s, Searched::default());
        let s = run(&b, 1 << 30, &needles, &[]);
        assert_eq!(s, Searched::default());
        // The kind with a needle is read, in its own targets.
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
            [("g.f".to_string(), ".gopclntab".to_string(), 50)]
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
            f.as_file(),
            4096,
            1 << 30,
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
        let b = bytes(0x20_0000, &[(0x1000, "main.f")]);
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
            &[gopclntab(0x1000 - 10, 100), gopclntab(0x20_1000, 0x1_0000)],
        );
        assert_eq!(
            places(&s),
            [("g.f".to_string(), ".gopclntab".to_string(), 10)]
        );
        assert!(s.gaps.is_empty());
        assert_eq!(s.used, 100);
    }

    #[test]
    fn a_gopclntab_cut_by_the_end_of_the_file_is_searched_and_a_gap() {
        let go = db(&[("g.f", "go-function", "main.f")]);
        // `sh_size` passes the end of the file: the 0x1000 bytes in it are searched.
        let b = bytes(0x20_0000, &[(0x1F_F100, "main.f")]);
        let s = run(&b, 1 << 30, &go, &[gopclntab(0x1F_F000, 0x1_0000)]);
        assert_eq!(
            places(&s),
            [("g.f".to_string(), ".gopclntab".to_string(), 0x100)]
        );
        assert_eq!(s.found[0].signal, Signal::GoFunction);
        assert_eq!(s.gaps, [SCAN_READ_FAILED]);
        assert_eq!(s.used, 0x1000);
    }

    #[test]
    fn an_empty_section_past_the_end_of_the_file_is_no_gap() {
        let go = db(&[("g.f", "go-function", "main.f")]);
        let b = bytes(1000, &[(10, "main.f")]);
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
            [("g.f".to_string(), ".gopclntab".to_string(), 10)]
        );
        assert!(s.gaps.is_empty());
        assert_eq!(s.used, 1000);
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
            exports(e, sections, dynamic, &needles, &mut found, &mut gaps);
            assert_eq!(found, []);
            assert_eq!(gaps, [SCAN_NAME_NOT_READ]);
        });
    }
}
