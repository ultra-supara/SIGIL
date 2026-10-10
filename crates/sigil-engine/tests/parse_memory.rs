//! The parser's memory, measured (review of #83, P1): files within `binary_parse_bytes` that
//! declare hundreds of thousands to millions of elements must not make the parser allocate much
//! beyond its input cache. A counting global allocator measures the peak of every allocation the
//! parse makes. One test function runs the cases in turn, so no other test thread allocates
//! meanwhile.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use common::elf::*;
use sigil_engine::binary::{parse, BinaryBudgets, Parsed};
use sigil_model::{ContainerFacts, DataValue};

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(by: usize) {
    let now = CURRENT.fetch_add(by, Ordering::SeqCst) + by;
    PEAK.fetch_max(now, Ordering::SeqCst);
}

// SAFETY: every call forwards to the system allocator with the same layout; the counters only
// observe sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
            grew(new_size);
        }
        p
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const BUDGET: u64 = 64 << 20;
/// The output's own limits (spec §4.9: at most 16 MiB of imports, small others) and slack.
const SLACK: usize = 24 << 20;

/// Parses `bytes` from a temporary file and returns the result and the peak growth of the heap
/// during the parse alone.
fn measured(bytes: Vec<u8>) -> (Parsed, usize) {
    let len = bytes.len() as u64;
    let f = file(&bytes);
    drop(bytes);
    let base = CURRENT.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let parsed = parse(&f, len, BinaryBudgets::default());
    let peak = PEAK.load(Ordering::SeqCst) - base;
    (parsed, peak)
}

fn bounded(what: &str, peak: usize) {
    assert!(
        peak <= BUDGET as usize + SLACK,
        "{what}: the parse grew the heap by {} MiB (bound {} MiB)",
        peak >> 20,
        (BUDGET as usize + SLACK) >> 20
    );
}

/// 60 MB of `a\0`: 30 million `.comment` entries (the review's case A).
fn many_comments() -> Vec<u8> {
    let mut img = ElfImage::new(3);
    let comment: Vec<u8> = b"a\0".repeat(30_000_000);
    let len = comment.len() as u64;
    img.put(0x1000, &comment);
    img.sec(".comment", SHT_PROGBITS, 0x1000, 0, len);
    img.build()
}

/// 15,000 undefined symbols with distinct 4,000-byte names (the review's case B): their cache is
/// within the budget, and only `binary_imports` of them may be kept.
fn many_imports() -> Vec<u8> {
    let n = 15_000u32;
    let mut img = ElfImage::new(3);
    let mut strtab = vec![0u8];
    let mut syms = vec![0u8; 24];
    for i in 0..n {
        let name = strtab.len() as u32;
        strtab.extend_from_slice(format!("{i:0>4000}").as_bytes());
        strtab.push(0);
        syms.extend_from_slice(&sym64(name, 0x12, 0, 0, 0)); // GLOBAL FUNC, undefined
    }
    let sym_off = 0x1000u64;
    let str_off = sym_off + syms.len() as u64;
    img.put(sym_off, &syms).put(str_off, &strtab);
    // Section 1 is .dynsym, linked to section 2, .dynstr.
    img.sec_linked(".dynsym", SHT_DYNSYM, sym_off, 0, syms.len() as u64, 2, 24)
        .sec(".dynstr", SHT_STRTAB, str_off, 0, strtab.len() as u64);
    img.build()
}

/// A known data symbol and a 40 MB RELA table of 1.6 million entries (the review's case B for
/// relocations): only the entry at the symbol is kept.
fn many_relocations() -> (Vec<u8>, u64) {
    let mut img = ElfImage::new(3);
    let (data_at, text_at) = (0x2000u64, 0x2100u64);
    img.put(text_at, b"6f3a9f3de\0");
    let mut strtab = vec![0u8];
    strtab.extend_from_slice(b"LLAMA_COMMIT\0");
    let mut syms = vec![0u8; 24];
    syms.extend_from_slice(&sym64(1, 0x11, 1, data_at, 8)); // GLOBAL OBJECT, defined
    let (sym_off, str_off) = (0x3000u64, 0x3100u64);
    img.put(sym_off, &syms).put(str_off, &strtab);
    let n = 1_600_000u64;
    let rela_off = 0x10_0000u64;
    let mut rela = Vec::with_capacity((n * 24) as usize);
    for i in 0..n {
        let at = if i == n / 2 {
            data_at
        } else {
            0x1000_0000 + i * 8
        };
        rela.extend_from_slice(&at.to_le_bytes());
        rela.extend_from_slice(&u64::from(R_X86_64_RELATIVE).to_le_bytes());
        rela.extend_from_slice(&text_at.to_le_bytes());
    }
    img.put(rela_off, &rela);
    let dynamic = dynamic(&[
        (DT_RELA, rela_off),
        (DT_RELASZ, rela.len() as u64),
        (DT_RELAENT, 24),
        (DT_SYMTAB, sym_off),
    ]);
    let dyn_off = 0x4000u64;
    img.put(dyn_off, &dynamic);
    let end = img.body.len() as u64;
    // Read-only, so no writable segment is searched for Go build info.
    img.seg(PT_LOAD, PF_R, 0, 0, end, end).seg(
        PT_DYNAMIC,
        PF_R,
        dyn_off,
        dyn_off,
        dynamic.len() as u64,
        dynamic.len() as u64,
    );
    img.sec_linked(
        ".dynsym",
        SHT_DYNSYM,
        sym_off,
        sym_off,
        syms.len() as u64,
        2,
        24,
    )
    .sec(".dynstr", SHT_STRTAB, str_off, str_off, strtab.len() as u64);
    (img.build(), rela.len() as u64)
}

#[test]
fn the_parse_stays_within_its_budget_whatever_the_file_declares() {
    let (p, peak) = measured(many_comments());
    let ContainerFacts::Elf(f) = &p.container;
    assert_eq!(f.comment.len(), 16);
    assert!(
        p.gaps.iter().any(|g| g.starts_with("comment: over")),
        "{:?}",
        p.gaps
    );
    bounded("30M comments", peak);

    let (p, peak) = measured(many_imports());
    let ContainerFacts::Elf(f) = &p.container;
    assert_eq!(f.imports.len(), 4096);
    assert!(
        p.gaps.iter().any(|g| g.starts_with("imports: over")),
        "{:?}",
        p.gaps
    );
    bounded("15k imports of 4 KB", peak);

    let (bytes, rela_len) = many_relocations();
    assert!(rela_len < BUDGET, "the table fits the budget");
    let (p, peak) = measured(bytes);
    let ContainerFacts::Elf(f) = &p.container;
    assert_eq!(
        f.data.first().map(|d| d.value.clone()),
        Some(DataValue::Text(sigil_model::UntrustedText::new(
            "6f3a9f3de"
        ))),
        "{:?}",
        p.gaps
    );
    bounded("1.6M relocations", peak);
}
