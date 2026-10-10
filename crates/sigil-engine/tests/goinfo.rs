//! Go build info (spec §4.5) against `go version -m`, plus the search and malformed cases.

mod common;

use common::elf::*;
use sigil_engine::binary::{parse, BinaryBudgets, Parsed};
use sigil_model::GoBuildInfo;

fn go_of(bytes: &[u8], budgets: BinaryBudgets) -> Parsed {
    parse(&file(bytes), bytes.len() as u64, budgets)
}

fn go_gaps(p: &Parsed) -> Vec<&String> {
    p.gaps.iter().filter(|g| g.starts_with("go.")).collect()
}

/// `go version -m` output: the version, then `(kind, fields)` per line. Go's printer leaves a
/// line with only a tab after a replacement (`formatMod` ends both lines); it is no line kind.
fn oracle(arch: &str) -> (String, Vec<(String, Vec<String>)>) {
    let text = String::from_utf8(fixture(&format!("go/go-{arch}.txt"))).unwrap();
    let mut lines = text.lines();
    let version = lines
        .next()
        .unwrap()
        .rsplit(": ")
        .next()
        .unwrap()
        .to_string();
    let rest = lines
        .map(|l| {
            let mut f: Vec<String> = l
                .trim_start_matches('\t')
                .split('\t')
                .map(str::to_string)
                .collect();
            let kind = f.remove(0);
            (kind, f)
        })
        .filter(|(kind, _)| !kind.is_empty())
        .collect();
    (version, rest)
}

/// An ELF with `piece` as its `.go.buildinfo` section, in a writable PT_LOAD at 0x4000.
fn with_section(piece: &[u8]) -> Vec<u8> {
    let mut img = ElfImage::new(2);
    img.put(0x4000, piece);
    let end = img.body.len() as u64;
    img.seg(PT_LOAD, PF_R | PF_W, 0, 0, end, end).sec(
        ".go.buildinfo",
        SHT_PROGBITS,
        0x4000,
        0x4000,
        piece.len() as u64,
    );
    img.build()
}

fn check(info: &GoBuildInfo, arch: &str) {
    let (version, lines) = oracle(arch);
    assert_eq!(info.version.as_str(), Some(version.as_str()));
    let text = |t: &sigil_model::UntrustedText| t.as_str().unwrap_or_default().to_string();
    for (kind, fields) in &lines {
        match kind.as_str() {
            "path" => assert_eq!(info.path.as_ref().map(text), Some(fields[0].clone())),
            "mod" => assert_eq!(
                info.main.as_ref().map(|m| text(&m.path)),
                Some(fields[0].clone())
            ),
            "dep" => assert!(
                info.deps
                    .iter()
                    .any(|d| text(&d.path) == fields[0] && text(&d.version) == fields[1]),
                "dep {fields:?}"
            ),
            "=>" => assert!(
                info.deps
                    .iter()
                    .any(|d| d.replace.as_ref().is_some_and(
                        |r| text(&r.path) == fields[0] && text(&r.version) == fields[1]
                    )),
                "=> {fields:?}"
            ),
            "build" => {
                let (k, v) = fields[0].split_once('=').unwrap();
                assert!(
                    info.settings
                        .iter()
                        .any(|s| text(&s.key) == k && text(&s.value) == v),
                    "{k}={v}"
                );
            }
            other => panic!("unexpected line kind {other:?}"),
        }
    }
    let settings = lines.iter().filter(|(k, _)| k == "build").count();
    assert_eq!(info.settings.len(), settings);
}

#[test]
fn real_pieces_match_go_version_m() {
    for arch in ["amd64", "arm64", "s390x"] {
        let p = go_of(
            &with_section(&fixture(&format!("go/go-{arch}.buildinfo"))),
            BinaryBudgets::default(),
        );
        let info =
            p.go.as_ref()
                .unwrap_or_else(|| panic!("{arch}: {:?}", p.gaps));
        check(info, arch);
        assert!(go_gaps(&p).is_empty(), "{arch}: {:?}", p.gaps);
    }
}

/// An ELF without sections whose first writable PT_LOAD starts at `vaddr` and holds `piece` at
/// segment offset `at`.
fn in_segment(piece: &[u8], vaddr: u64, at: u64) -> Vec<u8> {
    let mut img = ElfImage::new(2);
    let off = 0x2000;
    img.put(off + at, piece);
    let len = at + piece.len() as u64 + 0x100;
    img.put(off + len - 1, &[0]);
    img.seg(PT_LOAD, PF_R | PF_X, 0, 0, 0x1000, 0x1000).seg(
        PT_LOAD,
        PF_R | PF_W,
        off,
        vaddr,
        len,
        len + 0x1000,
    );
    img.build()
}

#[test]
fn the_whole_segment_is_searched_from_an_aligned_start() {
    let piece = fixture("go/go-amd64.buildinfo");
    // Past the first 64 KiB (the review's 0x10010).
    let p = go_of(
        &in_segment(&piece, 0x40_0000, 0x10010),
        BinaryBudgets::default(),
    );
    check(p.go.as_ref().expect("found past 64 KiB"), "amd64");
    // An unaligned segment start: the magic sits at the first 16-aligned address past a 64 KiB
    // chunk measured from the unaligned start, so it would cross that chunk's end.
    let vaddr = 0x40_0003;
    let magic_va = (vaddr + 0x10000 + 15) & !15;
    let p = go_of(
        &in_segment(&piece, vaddr, magic_va - vaddr),
        BinaryBudgets::default(),
    );
    check(
        p.go.as_ref().expect("found across an unaligned chunk"),
        "amd64",
    );
}

#[test]
fn a_budget_stopped_search_is_a_gap_not_an_absence() {
    let piece = fixture("go/go-amd64.buildinfo");
    let p = go_of(
        &in_segment(&piece, 0x40_0000, 0x30000),
        BinaryBudgets {
            parse_bytes: 96 << 10,
            ..BinaryBudgets::default()
        },
    );
    assert!(p.go.is_none());
    assert!(
        p.gaps
            .iter()
            .any(|g| g.starts_with("go.buildinfo: search stopped at")),
        "{:?}",
        p.gaps
    );
}

#[test]
fn no_build_info_after_a_full_search_is_not_a_gap() {
    let p = go_of(
        &in_segment(b"just data", 0x40_0000, 0x10),
        BinaryBudgets::default(),
    );
    assert!(p.go.is_none());
    assert!(go_gaps(&p).is_empty(), "{:?}", p.gaps);
}

/// `n` as Go's `binary.PutUvarint` writes it.
fn uvarint(mut n: u64) -> Vec<u8> {
    let mut out = vec![];
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return out;
        }
        out.push(b | 0x80);
    }
}

/// Modinfo as the linker writes it: 16 sentinel bytes, the lines, 16 sentinel bytes.
fn sentinel(lines: &str) -> Vec<u8> {
    let mut m = vec![b'x'; 16];
    m.extend_from_slice(lines.as_bytes());
    m.extend(vec![b'y'; 16]);
    m
}

/// A piece with the amd64 piece's 32-byte header (inline, little-endian) and `body` after it.
fn inline_with(body: &[u8]) -> Vec<u8> {
    let mut piece = fixture("go/go-amd64.buildinfo")[..32].to_vec();
    piece.extend_from_slice(body);
    piece.resize(piece.len().max(64), 0);
    with_section(&piece)
}

/// An inline piece with `version` and the modinfo `lines`.
fn inline_piece(version: &str, lines: &str) -> Vec<u8> {
    let modinfo = sentinel(lines);
    let mut body = uvarint(version.len() as u64);
    body.extend_from_slice(version.as_bytes());
    body.extend(uvarint(modinfo.len() as u64));
    body.extend(modinfo);
    inline_with(&body)
}

#[test]
fn a_hand_built_piece_parses_so_its_malformed_variants_fail_for_their_own_reason() {
    let p = go_of(
        &inline_piece(
            "go1.2",
            "path\tp\nmod\tm\tv1\t\n\nbuild\t\"a b\"=\"c\\td\"\n",
        ),
        BinaryBudgets::default(),
    );
    let info = p.go.as_ref().unwrap_or_else(|| panic!("{:?}", p.gaps));
    assert_eq!(info.version.as_str(), Some("go1.2"));
    assert_eq!(info.settings[0].key.as_str(), Some("a b"));
    assert_eq!(info.settings[0].value.as_str(), Some("c\td"));
    assert!(go_gaps(&p).is_empty(), "{:?}", p.gaps);
}

/// A pointer-format header (Go < 1.18) at segment offset 0 (file offset 0x2000), with Go string
/// headers and strings after it, in the given byte order. `ptr_size` must be 4 or 8: a malformed
/// size is made by patching byte 0x2000 + 14 of a valid file.
fn pointer_format(big: bool, ptr_size: u8) -> Vec<u8> {
    assert!(
        matches!(ptr_size, 4 | 8),
        "build a valid file, then patch it"
    );
    let vaddr = 0x50_0000u64;
    let word = |v: u64| -> Vec<u8> {
        match (ptr_size, big) {
            (8, false) => v.to_le_bytes().to_vec(),
            (8, true) => v.to_be_bytes().to_vec(),
            (_, false) => (v as u32).to_le_bytes().to_vec(),
            (_, true) => (v as u32).to_be_bytes().to_vec(),
        }
    };
    let version = b"go1.17.13";
    let modinfo = sentinel("path\texample.com/old\nmod\texample.com/old\t(devel)\t\n");
    let mut seg = vec![0u8; 0x200];
    seg[..14].copy_from_slice(b"\xff Go buildinf:");
    seg[14] = ptr_size;
    seg[15] = u8::from(big);
    let p = usize::from(ptr_size);
    let (vers_hdr, mod_hdr, vers_at, mod_at) = (0x40usize, 0x60usize, 0x80u64, 0x100u64);
    seg[16..16 + p].copy_from_slice(&word(vaddr + vers_hdr as u64));
    seg[16 + p..16 + 2 * p].copy_from_slice(&word(vaddr + mod_hdr as u64));
    let vers = [word(vaddr + vers_at), word(version.len() as u64)].concat();
    seg[vers_hdr..vers_hdr + vers.len()].copy_from_slice(&vers);
    let m = [word(vaddr + mod_at), word(modinfo.len() as u64)].concat();
    seg[mod_hdr..mod_hdr + m.len()].copy_from_slice(&m);
    seg[vers_at as usize..vers_at as usize + version.len()].copy_from_slice(version);
    seg[mod_at as usize..mod_at as usize + modinfo.len()].copy_from_slice(&modinfo);
    let mut img = ElfImage::new(2);
    img.put(0x2000, &seg);
    img.seg(
        PT_LOAD,
        PF_R | PF_W,
        0x2000,
        vaddr,
        seg.len() as u64,
        seg.len() as u64,
    );
    img.build()
}

#[test]
fn the_pointer_format_in_both_byte_orders_and_sizes() {
    for (big, size) in [(false, 8), (true, 8), (false, 4), (true, 4)] {
        let p = go_of(&pointer_format(big, size), BinaryBudgets::default());
        let info =
            p.go.as_ref()
                .unwrap_or_else(|| panic!("big={big} size={size}: {:?}", p.gaps));
        assert_eq!(info.version.as_str(), Some("go1.17.13"));
        assert_eq!(
            info.path.as_ref().and_then(|x| x.as_str()),
            Some("example.com/old")
        );
    }
}

#[test]
fn malformed_build_info_is_a_gap_never_a_panic() {
    let mut bad_ptr = pointer_format(false, 8);
    bad_ptr[0x2000 + 14] = 3; // only the ptrSize byte is invalid
    let mut out_ptr = pointer_format(false, 8);
    out_ptr[0x2000 + 16..0x2000 + 24].copy_from_slice(&0x7000_0000u64.to_le_bytes());
    let mut wrap_ptr = pointer_format(false, 8);
    wrap_ptr[0x2000 + 16..0x2000 + 24].copy_from_slice(&(u64::MAX - 4).to_le_bytes());
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("uvarint overflow", inline_with(&[0xff; 11])),
        ("string over 1 MiB", inline_with(&uvarint(2 << 20))),
        ("ptrSize", bad_ptr),
        ("pointer outside every PT_LOAD", out_ptr),
        ("pointer arithmetic overflow", wrap_ptr),
        ("=> without a module", inline_piece("go1.2", "=>\tx\tv\t\n")),
        ("mod columns", inline_piece("go1.2", "mod\tonly\n")),
        ("bad build quoting", inline_piece("go1.2", "build\t\"k=v\n")),
        ("unknown line kind", inline_piece("go1.2", "what\tever\n")),
    ];
    for (what, bytes) in cases {
        let p = go_of(&bytes, BinaryBudgets::default());
        assert!(p.go.is_none(), "{what}");
        assert!(
            p.gaps.iter().any(|g| g.starts_with("go.buildinfo: ")),
            "{what}: {:?}",
            p.gaps
        );
    }
}

/// An inline piece whose modinfo is exactly `modinfo` (no sentinel added).
fn inline_raw(version: &str, modinfo: &[u8]) -> Vec<u8> {
    let mut body = uvarint(version.len() as u64);
    body.extend_from_slice(version.as_bytes());
    body.extend(uvarint(modinfo.len() as u64));
    body.extend_from_slice(modinfo);
    inline_with(&body)
}

#[test]
fn a_malformed_sentinel_or_an_unterminated_line_is_a_gap_not_empty_modinfo() {
    // Go would read these as no modules; SIGIL says it could not read them.
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "no sentinel",
            inline_raw("go1.2", b"path\tp\nmod\tm\tv1\t\n"),
        ),
        // A valid sentinel ends the content with a newline, so an unterminated last line is a
        // malformed sentinel too.
        (
            "unterminated",
            inline_piece("go1.2", "path\tp\nmod\tm\tv1\t"),
        ),
    ];
    for (what, bytes) in cases {
        let p = go_of(&bytes, BinaryBudgets::default());
        assert!(p.go.is_none(), "{what}");
        assert!(
            p.gaps.iter().any(|g| g.starts_with("go.buildinfo: ")),
            "{what}: {:?}",
            p.gaps
        );
    }
    // An empty modinfo is not a gap: a Go binary without module information.
    let p = go_of(&inline_raw("go1.2", b""), BinaryBudgets::default());
    assert!(p.go.is_some(), "{:?}", p.gaps);
    assert!(go_gaps(&p).is_empty(), "{:?}", p.gaps);
}
