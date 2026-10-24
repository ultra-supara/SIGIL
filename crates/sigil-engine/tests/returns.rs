//! What known exported functions return (PR-4c-2b spec §2): `ggml_version` and `ggml_commit`,
//! read from the committed fixtures of `tests/fixtures/returns/` and from patched copies of them.
//! The files are written to temporary directories and never run.

mod common;

use std::path::PathBuf;

use common::elf::*;
use sigil_engine::analyze::components::components;
use sigil_engine::binary::needles::needles;
use sigil_engine::binary::returns::{MAX_FUNCTION, OVER_BUDGET};
use sigil_engine::binary::scan::{ScanOutcome, Sought};
use sigil_engine::binary::{parse_artifact, BinaryBudgets};
use sigil_engine::collect::named::NamedBudgets;
use sigil_engine::inspect::{binary_session, BinaryRequest};
use sigil_engine::policy::Policy;
use sigil_model::{
    returned_value_gap, scan_over_gap, Completeness, ContainerFacts, CoverageState, DataValue,
    FunctionReturn, Loc, Session, Sha256Hex, BINARY_IDENTITY,
};
use tempfile::TempDir;

/// `ggml_version` and `ggml_commit` of the gcc -O2 fixtures, and their strings' addresses.
const VERSION_FN: u64 = 0x1100;
const VERSION_AT: u64 = 0x2000;
const COMMIT_AT: u64 = 0x2007;
/// The file offset of the first `.rela.dyn` entry of the gcc -O2 fixtures.
const RELA_DYN: usize = 0x3b0;
/// The end of their read-only data segment (`.rodata` and the unwind tables after it).
const READ_ONLY_END: u64 = 0x20c4;

fn returns_fixture(name: &str) -> Vec<u8> {
    fixture(&format!("returns/{name}"))
}

/// Each return as `(function, Ok((string, address)) | Err(why))`.
type Shown = Vec<(String, Result<(String, u64), String>)>;

fn shown(returns: &[FunctionReturn]) -> Shown {
    returns
        .iter()
        .map(|r| {
            let value = match (&r.value, r.at.as_slice()) {
                (DataValue::Text(text), [Loc::Symbol(_), Loc::VAddr(at)]) => {
                    Ok((text.as_str().unwrap().to_string(), *at))
                }
                (DataValue::Unknown { why }, [Loc::Symbol(_)]) => Err(why.clone()),
                other => panic!("{other:?}"),
            };
            (r.function.clone(), value)
        })
        .collect()
}

fn read(function: &str, value: &str, at: u64) -> (String, Result<(String, u64), String>) {
    (function.to_string(), Ok((value.to_string(), at)))
}

fn unread(function: &str, why: &str) -> (String, Result<(String, u64), String>) {
    (function.to_string(), Err(why.to_string()))
}

/// The returns of `bytes` and its scan's gaps, with the embedded databases, through
/// `parse_artifact`.
fn scanned_with(bytes: &[u8], budgets: BinaryBudgets) -> (Shown, Vec<String>) {
    let f = file(bytes);
    let digest = Sha256Hex::new("0".repeat(64)).unwrap();
    let sought = Sought {
        needles: needles().unwrap(),
        functions: components().unwrap().functions(),
    };
    let parsed = parse_artifact(
        &f,
        bytes.len() as u64,
        &digest,
        &bytes[..64],
        budgets,
        Some(sought),
    )
    .unwrap();
    let slice = &parsed.slices[0];
    let Some(ContainerFacts::Elf(elf)) = &slice.container else {
        panic!("an ELF");
    };
    let Some(ScanOutcome::Scanned { gaps, .. }) = &slice.scan else {
        panic!("scanned");
    };
    (shown(&elf.returns), gaps.clone())
}

fn scanned(bytes: &[u8]) -> (Shown, Vec<String>) {
    scanned_with(bytes, BinaryBudgets::default())
}

/// The gaps of the `Unknown` returns of `shown`.
fn gaps_of(shown: &Shown) -> Vec<String> {
    shown
        .iter()
        .filter_map(|(function, value)| value.as_ref().err().map(|why| (function, why)))
        .map(|(function, why)| returned_value_gap(function, why))
        .collect()
}

#[test]
fn each_shape_of_a_constant_return_is_read() {
    for name in [
        "version-gcc-O2.so",
        "version-relr-gcc-O2.so",
        "version-clang-O0.so",
        "version-cet-gcc-O0.so",
    ] {
        let (returns, gaps) = scanned(&returns_fixture(name));
        let at = |s: &str| match &returns.iter().find(|r| r.0 == s).unwrap().1 {
            Ok((_, at)) => *at,
            Err(why) => panic!("{name}: {s}: {why}"),
        };
        assert_eq!(
            returns,
            [
                read("ggml_commit", "6f3a9f3de", at("ggml_commit")),
                read("ggml_version", "0.13.1", at("ggml_version")),
            ],
            "{name}"
        );
        assert_eq!(at("ggml_commit"), at("ggml_version") + 7, "{name}");
        assert_eq!(gaps, Vec::<String>::new(), "{name}");
    }
    let (returns, _) = scanned(&returns_fixture("version-gcc-O2.so"));
    assert_eq!(
        returns,
        [
            read("ggml_commit", "6f3a9f3de", COMMIT_AT),
            read("ggml_version", "0.13.1", VERSION_AT),
        ]
    );
    let (returns, _) = scanned(&returns_fixture("version-1.0.0-gcc-O2.so"));
    assert_eq!(returns[1], read("ggml_version", "1.0.0", VERSION_AT));
}

#[test]
fn a_value_that_is_not_one_constant_string_is_unknown_with_its_gap() {
    for (name, version) in [
        (
            "global-gcc-O2.so",
            "returns no constant string address".to_string(),
        ),
        (
            "branch-gcc-O0.so",
            "not one straight block ending in ret".to_string(),
        ),
        (
            "version-long-gcc-O2.so",
            "its string has no NUL within 256 bytes".to_string(),
        ),
    ] {
        let (returns, gaps) = scanned(&returns_fixture(name));
        assert_eq!(returns[1], unread("ggml_version", &version), "{name}");
        assert!(returns[0].1.is_ok(), "{name}: {returns:?}");
        assert_eq!(gaps, gaps_of(&returns), "{name}");
    }
    // The long string, cut by a NUL after its 256th byte: exactly 256 bytes are read.
    let mut bytes = returns_fixture("version-long-gcc-O2.so");
    assert_eq!(&bytes[0x2000..0x2000 + 300], [b'x'; 300]);
    bytes[0x2000 + 256] = 0;
    let (returns, _) = scanned(&bytes);
    assert_eq!(
        returns[1],
        read("ggml_version", &"x".repeat(256), VERSION_AT)
    );
    let (returns, gaps) = scanned(&returns_fixture("version-aarch64.so"));
    let why = "not decoded: x86-64 only";
    assert_eq!(
        returns,
        [unread("ggml_commit", why), unread("ggml_version", why)]
    );
    assert_eq!(gaps, gaps_of(&returns));
}

/// The `.dynsym` entry (its file offset) of the symbol named `name`, in an ELF64 little-endian
/// file.
fn dynsym_entry(bytes: &[u8], name: &[u8]) -> usize {
    let secs = sections64(bytes);
    let (_, _, _, sym_off, sym_size, link) =
        secs.iter().find(|s| s.1 == SHT_DYNSYM).unwrap().clone();
    let str_off = secs[link as usize].3 as usize;
    (sym_off as usize..(sym_off + sym_size) as usize)
        .step_by(24)
        .find(|e| {
            let at = str_off + u32::from_le_bytes(bytes[*e..*e + 4].try_into().unwrap()) as usize;
            bytes[at..].starts_with(name) && bytes[at + name.len()] == 0
        })
        .unwrap()
}

/// The gcc -O2 fixture with `ggml_version`'s `.dynsym` entry changed by `f`.
fn with_version_symbol(f: impl Fn(&mut [u8])) -> Vec<u8> {
    let mut bytes = returns_fixture("version-gcc-O2.so");
    let e = dynsym_entry(&bytes, b"ggml_version");
    f(&mut bytes[e..e + 24]);
    bytes
}

/// The file offset of the program header of the executable `PT_LOAD`.
fn executable_load(bytes: &[u8]) -> usize {
    let phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes([bytes[56], bytes[57]]) as usize;
    (0..phnum)
        .map(|i| phoff + i * 56)
        .find(|&p| {
            let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            word(p) == PT_LOAD && word(p + 4) & PF_X != 0
        })
        .unwrap()
}

/// `ggml_version`'s reason in `bytes`, with `ggml_commit` read.
fn version_why(bytes: &[u8]) -> String {
    let (returns, gaps) = scanned(bytes);
    assert_eq!(returns[0], read("ggml_commit", "6f3a9f3de", COMMIT_AT));
    assert_eq!(gaps, gaps_of(&returns));
    match &returns[1] {
        (f, Err(why)) if f == "ggml_version" => why.clone(),
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_symbol_is_one_function_of_at_most_64_bytes_in_an_executable_segment() {
    let set_size = |n: u64| move |s: &mut [u8]| s[16..24].copy_from_slice(&n.to_le_bytes());
    assert_eq!(
        version_why(&with_version_symbol(set_size(0))),
        "size not recorded"
    );
    assert_eq!(
        version_why(&with_version_symbol(set_size(MAX_FUNCTION + 1))),
        "longer than 64 bytes"
    );
    // Exactly 64 bytes is read, once the executable segment holds them (its file bytes end at
    // 0x1121); the bytes after `ret` are never decoded.
    let mut bytes = with_version_symbol(set_size(MAX_FUNCTION));
    assert_eq!(version_why(&bytes), "not in an executable segment");
    let p = executable_load(&bytes);
    bytes[p + 32..p + 40].copy_from_slice(&0x200u64.to_le_bytes());
    bytes[p + 40..p + 48].copy_from_slice(&0x200u64.to_le_bytes());
    let (returns, _) = scanned(&bytes);
    assert_eq!(returns[1], read("ggml_version", "0.13.1", VERSION_AT));
    // STB_GLOBAL with another type.
    for (info, ty) in [(0x11, "STT_OBJECT"), (0x1a, "STT_GNU_IFUNC")] {
        let bytes = with_version_symbol(|s| s[4] = info);
        assert_eq!(version_why(&bytes), format!("not a function ({ty})"));
    }
    // PR #98 review P2: a reserved section index. The loader does not add the load base to an
    // `SHN_ABS` symbol's value, so the code at that address in the file is not what it exports.
    for (shndx, shown) in [
        (0xfff1u16, "SHN_ABS"),
        (0xfff2, "SHN_COMMON"),
        (0xffff, "SHN_XINDEX"),
        (0xff00, "st_shndx 0xff00"),
    ] {
        let bytes = with_version_symbol(|s| s[6..8].copy_from_slice(&shndx.to_le_bytes()));
        assert_eq!(
            version_why(&bytes),
            format!("not defined in a section ({shown})")
        );
    }
    // In the read-only data segment.
    let bytes = with_version_symbol(|s| s[8..16].copy_from_slice(&VERSION_AT.to_le_bytes()));
    assert_eq!(version_why(&bytes), "not in an executable segment");
    let bytes = with_version_symbol(|s| s[8..16].copy_from_slice(&u64::MAX.to_le_bytes()));
    assert_eq!(version_why(&bytes), "not in an executable segment");
}

#[test]
fn a_function_defined_twice_has_no_single_value() {
    // `ggml_commit`'s entry renamed `ggml_version`: two definitions, and no `ggml_commit`.
    let mut bytes = returns_fixture("version-gcc-O2.so");
    let version = dynsym_entry(&bytes, b"ggml_version");
    let commit = dynsym_entry(&bytes, b"ggml_commit");
    let name: [u8; 4] = bytes[version..version + 4].try_into().unwrap();
    bytes[commit..commit + 4].copy_from_slice(&name);
    let (returns, gaps) = scanned(&bytes);
    assert_eq!(returns, [unread("ggml_version", "defined more than once")]);
    assert_eq!(gaps, gaps_of(&returns));
}

#[test]
fn the_code_must_decode_to_one_block_that_leaves_a_lea_address_in_rax() {
    // 0x06 is no instruction in 64-bit mode.
    let mut bytes = returns_fixture("version-gcc-O2.so");
    bytes[VERSION_FN as usize] = 0x06;
    assert_eq!(
        version_why(&bytes),
        "function at 0x1100: decode failure at 0x1100"
    );
    // `lea rax, [rip - 7]`: the function's own address, which is not read-only data.
    let mut bytes = returns_fixture("version-gcc-O2.so");
    let disp = VERSION_FN as usize + 3;
    bytes[disp..disp + 4].copy_from_slice(&(-7i32).to_le_bytes());
    assert_eq!(version_why(&bytes), "its string is not in read-only data");
    // `.data`, writable: not read-only data either.
    let mut bytes = returns_fixture("version-gcc-O2.so");
    let disp = VERSION_FN as usize + 3;
    let rel = 0x4000i32 - (VERSION_FN as i32 + 7);
    bytes[disp..disp + 4].copy_from_slice(&rel.to_le_bytes());
    assert_eq!(version_why(&bytes), "its string is not in read-only data");
    // The read-only segment cut to 6 bytes, just before the NUL of "0.13.1": the commit's string
    // lies outside it.
    let mut bytes = returns_fixture("version-gcc-O2.so");
    let p = (0..u16::from_le_bytes([bytes[56], bytes[57]]) as usize)
        .map(|i| u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize + i * 56)
        .find(|&p| {
            u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap()) == PT_LOAD
                && u64::from_le_bytes(bytes[p + 16..p + 24].try_into().unwrap()) == VERSION_AT
        })
        .unwrap();
    bytes[p + 32..p + 40].copy_from_slice(&6u64.to_le_bytes());
    let (returns, _) = scanned(&bytes);
    assert_eq!(
        returns,
        [
            unread("ggml_commit", "its string is not in read-only data"),
            unread(
                "ggml_version",
                "its string has no NUL before the end of read-only data"
            ),
        ]
    );
    // `mov eax, 0x2000; ret`: the address as an immediate, never a string.
    let mut bytes = returns_fixture("version-gcc-O2.so");
    let at = VERSION_FN as usize;
    bytes[at..at + 8].copy_from_slice(&[0xb8, 0x00, 0x20, 0x00, 0x00, 0xc3, 0x90, 0x90]);
    assert_eq!(version_why(&bytes), "returns no constant string address");
    // `lea rax, [rip + d]; jmp` back to the lea: a loop, not one block ending in ret.
    let mut bytes = returns_fixture("version-gcc-O2.so");
    bytes[at + 7] = 0xeb;
    let bytes = {
        let mut b = bytes;
        let e = dynsym_entry(&b, b"ggml_version");
        b[e + 16..e + 24].copy_from_slice(&9u64.to_le_bytes());
        b[at + 8] = (-9i8) as u8;
        b
    };
    assert_eq!(version_why(&bytes), "not one straight block ending in ret");
}

#[test]
fn a_relocation_on_the_code_or_the_string_makes_it_unknown() {
    // The first `.rela.dyn` entry (an R_X86_64_RELATIVE) moved onto the code, then the string.
    // R_X86_64_RELATIVE writes 8 bytes: from 2 before the string, its first 6.
    for (to, why) in [
        (VERSION_FN + 3, "a relocation writes its code"),
        (VERSION_AT - 2, "a relocation writes its string"),
    ] {
        let mut bytes = returns_fixture("version-gcc-O2.so");
        bytes[RELA_DYN..RELA_DYN + 8].copy_from_slice(&to.to_le_bytes());
        assert_eq!(version_why(&bytes), why, "{to:#x}");
    }
    // On the version string's NUL alone (and the start of the commit's): its NUL counts.
    let mut bytes = returns_fixture("version-gcc-O2.so");
    bytes[RELA_DYN..RELA_DYN + 8].copy_from_slice(&(VERSION_AT + 6).to_le_bytes());
    let (returns, _) = scanned(&bytes);
    assert_eq!(
        returns[1],
        unread("ggml_version", "a relocation writes its string")
    );
    // Just past the version string's NUL: nothing of it is written, but the commit's is.
    let mut bytes = returns_fixture("version-gcc-O2.so");
    bytes[RELA_DYN..RELA_DYN + 8].copy_from_slice(&(VERSION_AT + 7).to_le_bytes());
    let (returns, _) = scanned(&bytes);
    assert_eq!(returns[1], read("ggml_version", "0.13.1", VERSION_AT));
    assert!(returns[0].1.is_err(), "the commit's string starts there");
    // The first DT_RELR word moved onto the code.
    let mut bytes = returns_fixture("version-relr-gcc-O2.so");
    let relr = sections64(&bytes)
        .into_iter()
        .find(|s| s.0 == ".relr.dyn")
        .unwrap()
        .3 as usize;
    bytes[relr..relr + 8].copy_from_slice(&VERSION_FN.to_le_bytes());
    assert_eq!(version_why(&bytes), "a relocation writes its code");
    // The same word moved onto the version string: its 8 bytes reach the commit's first byte too.
    bytes[relr..relr + 8].copy_from_slice(&VERSION_AT.to_le_bytes());
    let (returns, _) = scanned(&bytes);
    let why = "a relocation writes its string";
    assert_eq!(
        returns,
        [unread("ggml_commit", why), unread("ggml_version", why)]
    );
}

#[test]
fn dt_rel_and_unreadable_relocations_make_it_unknown() {
    // DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ retagged DT_REL, DT_RELSZ, DT_RELENT.
    let mut bytes = returns_fixture("version-gcc-O2.so");
    retag(&mut bytes, 25, DT_REL);
    retag(&mut bytes, 27, 18);
    retag(&mut bytes, 28, 19);
    set_dynamic(&mut bytes, 18, 16);
    set_dynamic(&mut bytes, 19, 16);
    let (returns, gaps) = scanned(&bytes);
    let why = "DT_REL relocations are not modeled";
    assert_eq!(
        returns,
        [unread("ggml_commit", why), unread("ggml_version", why)]
    );
    assert_eq!(gaps, gaps_of(&returns));
    // A PT_DYNAMIC the parse cannot read lists no relocation: none can be ruled out.
    let mut bytes = returns_fixture("version-gcc-O2.so");
    let p = phdr64(&bytes, PT_DYNAMIC);
    bytes[p + 16..p + 24].copy_from_slice(&0x10_0000_0000u64.to_le_bytes());
    let (returns, gaps) = scanned(&bytes);
    let why = "relocations not read: PT_DYNAMIC not read";
    assert_eq!(
        returns,
        [unread("ggml_commit", why), unread("ggml_version", why)]
    );
    for gap in gaps_of(&returns) {
        assert!(gaps.contains(&gap), "{gap}: {gaps:?}");
    }
    // A DT_RELRSZ that is not a whole number of words: the RELR table is not read.
    let mut bytes = returns_fixture("version-relr-gcc-O2.so");
    set_dynamic(&mut bytes, DT_RELRSZ, 9);
    let (returns, _) = scanned(&bytes);
    assert_eq!(returns.len(), 2);
    for (function, value) in &returns {
        let why = value.as_ref().unwrap_err();
        assert!(
            why.starts_with("relocations not read: "),
            "{function}: {why}"
        );
    }
    // A DT_RELAENT the loader refuses: the RELA table is not read.
    let mut bytes = returns_fixture("version-gcc-O2.so");
    set_dynamic(&mut bytes, DT_RELAENT, 25);
    let (returns, _) = scanned(&bytes);
    for (function, value) in &returns {
        let why = value.as_ref().unwrap_err();
        assert!(
            why.starts_with("relocations not read: "),
            "{function}: {why}"
        );
    }
}

#[test]
fn the_reads_are_charged_to_binary_scan_bytes() {
    let bytes = returns_fixture("version-gcc-O2.so");
    let budgets = |scan_bytes| BinaryBudgets {
        scan_bytes,
        ..BinaryBudgets::default()
    };
    // Each function is 8 bytes and its string at most 257: nothing fits in 4.
    let (returns, gaps) = scanned_with(&bytes, budgets(4));
    assert_eq!(
        returns,
        [
            unread("ggml_commit", OVER_BUDGET),
            unread("ggml_version", OVER_BUDGET)
        ]
    );
    let mut want = gaps_of(&returns);
    want.push(scan_over_gap(4));
    want.sort();
    assert_eq!(gaps, want);
    // The commit's code, then its string: up to 257 bytes, cut at the segment's end. The
    // version's code no longer fits.
    let (returns, _) = scanned_with(&bytes, budgets(8 + (READ_ONLY_END - COMMIT_AT)));
    assert_eq!(returns[0], read("ggml_commit", "6f3a9f3de", COMMIT_AT));
    assert_eq!(returns[1], unread("ggml_version", OVER_BUDGET));
}

/// The functions are looked for whatever the needles: with no export needle, the walk of the
/// exports still runs for them, to its end.
#[test]
fn the_functions_are_read_without_an_export_needle() {
    use sigil_engine::binary::needles;
    let go = "[[needle]]\nfeature = \"g.f\"\nkind = \"go-function\"\nvalue = \"main.f\"\n\
              source = \"t\"\n";
    let needles = needles::parse(go).unwrap();
    let bytes = returns_fixture("version-gcc-O2.so");
    let f = file(&bytes);
    let digest = Sha256Hex::new("0".repeat(64)).unwrap();
    let functions = ["ggml_commit".to_string(), "ggml_version".to_string()];
    let parsed = parse_artifact(
        &f,
        bytes.len() as u64,
        &digest,
        &bytes[..64],
        BinaryBudgets::default(),
        Some(Sought {
            needles: &needles,
            functions: &functions,
        }),
    )
    .unwrap();
    let Some(ContainerFacts::Elf(elf)) = &parsed.slices[0].container else {
        panic!("an ELF");
    };
    assert_eq!(
        shown(&elf.returns),
        [
            read("ggml_commit", "6f3a9f3de", COMMIT_AT),
            read("ggml_version", "0.13.1", VERSION_AT),
        ]
    );
}

/// The returns and the needle search share `binary_scan_bytes`: the returns read 8 + 189 + 8 +
/// 196 bytes (each function's code, then its string up to the segment's end), the 17-byte
/// `.rodata` no longer fits in the 10 left, and the scan says so.
#[test]
fn the_returns_and_the_needle_search_share_one_budget() {
    use sigil_engine::binary::needles;
    let db = "[[needle]]\nfeature = \"s.f\"\nkind = \"string\"\nvalue = \"zzzz\"\nsource = \"t\"\n";
    let needles = needles::parse(db).unwrap();
    let bytes = returns_fixture("version-gcc-O2.so");
    let f = file(&bytes);
    let digest = Sha256Hex::new("0".repeat(64)).unwrap();
    let functions = ["ggml_commit".to_string(), "ggml_version".to_string()];
    let budgets = BinaryBudgets {
        scan_bytes: 401 + 10,
        ..BinaryBudgets::default()
    };
    let parsed = parse_artifact(
        &f,
        bytes.len() as u64,
        &digest,
        &bytes[..64],
        budgets,
        Some(Sought {
            needles: &needles,
            functions: &functions,
        }),
    )
    .unwrap();
    let slice = &parsed.slices[0];
    let Some(ContainerFacts::Elf(elf)) = &slice.container else {
        panic!("an ELF");
    };
    assert_eq!(
        shown(&elf.returns),
        [
            read("ggml_commit", "6f3a9f3de", COMMIT_AT),
            read("ggml_version", "0.13.1", VERSION_AT),
        ]
    );
    let Some(ScanOutcome::Scanned { gaps, .. }) = &slice.scan else {
        panic!("scanned");
    };
    assert_eq!(gaps, &[scan_over_gap(411)]);
}

#[test]
fn a_file_without_the_functions_has_no_return() {
    let (returns, gaps) = scanned(&fixture("elf/libdata.so"));
    assert_eq!(returns, Shown::new());
    assert_eq!(gaps, Vec::<String>::new());
    // A relocatable object has no dynamic symbols: nothing is looked for.
    let (returns, _) = scanned(&fixture("elf/net.o"));
    assert_eq!(returns, Shown::new());
}

/// Writes each `(name, bytes)` into a new directory.
fn files(entries: &[(&str, &[u8])]) -> (TempDir, Vec<PathBuf>) {
    let d = TempDir::new().unwrap();
    let paths = entries
        .iter()
        .map(|(name, bytes)| {
            let p = d.path().join(name);
            std::fs::write(&p, bytes).unwrap();
            p
        })
        .collect();
    (d, paths)
}

fn inspect(paths: &[PathBuf]) -> Session {
    let s = binary_session(
        &BinaryRequest {
            paths: paths.to_vec(),
            budgets: NamedBudgets::default(),
        },
        &Policy::builtin_default().unwrap(),
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap();
    s.validate().unwrap();
    s
}

fn identity(s: &Session) -> Vec<CoverageState> {
    s.coverage
        .iter()
        .filter(|c| c.check.as_str() == BINARY_IDENTITY)
        .map(|c| c.state.clone())
        .collect()
}

#[test]
fn a_binary_inspection_records_the_returns_and_their_gaps() {
    let (_d, paths) = files(&[
        (
            "libggml-base.so.0.13.1",
            &returns_fixture("version-gcc-O2.so"),
        ),
        ("libggml-base.so.0", &returns_fixture("global-gcc-O2.so")),
    ]);
    let s = inspect(&paths);
    let returns = |i: usize| {
        let ContainerFacts::Elf(elf) = &s.binaries[i].container else {
            panic!("an ELF");
        };
        shown(&elf.returns)
    };
    // Binaries are sorted by slice: find each by its returns.
    let (complete, partial): (Vec<usize>, Vec<usize>) =
        (0..2).partition(|i| returns(*i).iter().all(|r| r.1.is_ok()));
    assert_eq!((complete.len(), partial.len()), (1, 1));
    assert_eq!(
        returns(complete[0]),
        [
            read("ggml_commit", "6f3a9f3de", COMMIT_AT),
            read("ggml_version", "0.13.1", VERSION_AT),
        ]
    );
    let gap = returned_value_gap("ggml_version", "returns no constant string address");
    let mut states = identity(&s);
    states.sort_by_key(|state| format!("{state:?}"));
    assert_eq!(
        states,
        [
            CoverageState::Complete,
            CoverageState::Partial { missing: vec![gap] },
        ]
    );
    assert!(
        s.binaries.iter().all(|b| b.gaps.is_empty()),
        "never a container gap"
    );
    assert!(matches!(
        s.outcome.completeness,
        Completeness::Incomplete { .. }
    ));
}

/// PR #98 review P2: an `SHN_ABS` export of `ggml_version`, whose value the loader does not
/// relocate, is not read as the function in the file: the value is `Unknown`, and the input's
/// identity stays open.
#[test]
fn an_absolute_symbol_is_no_function_and_keeps_the_identity_open() {
    let bytes = with_version_symbol(|s| s[6..8].copy_from_slice(&0xfff1u16.to_le_bytes()));
    let (_d, paths) = files(&[("libggml-base.so.0.13.1", &bytes)]);
    let s = inspect(&paths);
    let ContainerFacts::Elf(elf) = &s.binaries[0].container else {
        panic!("an ELF");
    };
    let why = "not defined in a section (SHN_ABS)";
    assert_eq!(
        shown(&elf.returns),
        [
            read("ggml_commit", "6f3a9f3de", COMMIT_AT),
            unread("ggml_version", why),
        ]
    );
    assert_eq!(
        identity(&s),
        [CoverageState::Partial {
            missing: vec![returned_value_gap("ggml_version", why)],
        }]
    );
}
