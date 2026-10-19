//! The signature scan (PR-4c-2a spec §2–§4). The needles of [`super::needles`] are looked for in
//! an ELF file's `.gopclntab` and read-only data sections ([`search`]), read with `pread` on the
//! parse's fd in [`CHUNK`]-byte chunks, each byte charged to `binary_scan_bytes` before it is read
//! (`code::reader`). Nothing is mapped. Export needles are matched against the names of the
//! parse's dynamic symbols instead, charged to `binary_parse_bytes`.

use std::fs::File;

use sigil_model::{scan_over_gap, FeatureKey, Loc, Signal, UntrustedText, SCAN_READ_FAILED};

use super::needles::{Needle, NeedleKind, Needles};
use crate::code::reader::{Reader, Refusal};

/// The bytes of a section examined per read. Each read is one chunk and the overlap of its kind
/// ([`Needles::overlap`]), so that a needle that starts in the chunk is read whole.
pub const CHUNK: u64 = 1 << 20;

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
}
