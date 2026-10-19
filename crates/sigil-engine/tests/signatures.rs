//! The signature scan in sessions (PR-4c-2a): Go functions in `.gopclntab`, the RPC backend by its
//! exports, NVIDIA libraries never scanned, and the scan's own coverage. The synthetic files are
//! written to temporary directories and never run.

mod common;

use std::path::{Path, PathBuf};

use common::elf::*;
use sigil_engine::binary::scan::ScanOutcome;
use sigil_engine::collect::fs::FsBudgets;
use sigil_engine::collect::install::InstallBudgets;
use sigil_engine::collect::named::{collect, NamedBudgets};
use sigil_engine::collect::ollama_store::DEFAULT_MANIFEST_LIMIT;
use sigil_engine::inspect::{
    binary_session, store_session, ActiveInput, BinaryRequest, InstallRequest, StoreRequest,
};
use sigil_engine::policy::Policy;
use sigil_model::{FeatureHint, Loc, Session, Signal, SCAN_NO_SECTIONS};
use tempfile::TempDir;

const LAUNCH: &str = "github.com/ollama/ollama/llm.SetupLlamaServerCommandEnv";
const DISCOVER: &str = "github.com/ollama/ollama/discover.discoverNativeDevices";

/// A `.gopclntab` of `len` bytes with both Go-function needles, at 0x100 and 0x2000.
fn pclntab(len: usize) -> Vec<u8> {
    let mut t = vec![0u8; len];
    for (at, name) in [(0x10, "runtime.main"), (0x100, LAUNCH), (0x2000, DISCOVER)] {
        t[at..at + name.len()].copy_from_slice(name.as_bytes());
    }
    t
}

/// An executable with `pclntab` as `.gopclntab` at 0x8000, and with `buildinfo` Go's build info
/// in `.go.buildinfo` at 0x4000 (a real piece, `go/go-amd64.buildinfo`), in one writable PT_LOAD.
fn go_elf(pclntab: &[u8], buildinfo: bool) -> Vec<u8> {
    let piece = fixture("go/go-amd64.buildinfo");
    let mut img = ElfImage::new(2);
    if buildinfo {
        img.put(0x4000, &piece);
    }
    img.put(0x8000, pclntab);
    let end = img.body.len() as u64;
    img.seg(PT_LOAD, PF_R | PF_W, 0, 0, end, end);
    if buildinfo {
        img.sec(
            ".go.buildinfo",
            SHT_PROGBITS,
            0x4000,
            0x4000,
            piece.len() as u64,
        );
    }
    img.sec(
        ".gopclntab",
        SHT_PROGBITS,
        0x8000,
        0x8000,
        pclntab.len() as u64,
    );
    img.build()
}

/// `bytes` with every `from` replaced by `to`, of the same length; `from` must be there.
fn replaced(bytes: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    assert_eq!(from.len(), to.len());
    let mut out = bytes.to_vec();
    let mut found = 0;
    let mut i = 0;
    while let Some(at) = out[i..].windows(from.len()).position(|w| w == from) {
        out[i + at..i + at + to.len()].copy_from_slice(to);
        i += at + from.len();
        found += 1;
    }
    assert!(found > 0, "{}", String::from_utf8_lossy(from));
    out
}

/// `libdata.so` exporting `ggml_backend_rpc_init` (its export `sigil_fixture_connect` renamed).
fn rpc_library() -> Vec<u8> {
    replaced(
        &fixture("elf/libdata.so"),
        b"sigil_fixture_connect",
        b"ggml_backend_rpc_init",
    )
}

/// `libdata.so` with the string `ggml_backend_rpc_add_server` in `.rodata` and no such export, as
/// v0.30.6's `libllama-common.so.0.0.1` has it.
fn rpc_string_library() -> Vec<u8> {
    replaced(
        &fixture("elf/libdata.so"),
        b"x86_64-linux-gnu\0GNU 11.2.1\0",
        b"ggml_backend_rpc_add_server\0",
    )
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

fn inspect(paths: &[PathBuf], budgets: NamedBudgets) -> Session {
    let s = binary_session(
        &BinaryRequest {
            paths: paths.to_vec(),
            budgets,
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

/// The session's hints other than imports: (feature, signal, value, at).
fn signatures(s: &Session) -> Vec<(String, Signal, String, Loc)> {
    s.hints
        .iter()
        .filter(|h| h.signal != Signal::Import)
        .map(|h: &FeatureHint| {
            (
                h.feature.to_string(),
                h.signal,
                h.value.as_str().unwrap().to_string(),
                h.at.clone(),
            )
        })
        .collect()
}

fn gopclntab(offset: u64) -> Loc {
    Loc::Section {
        name: sigil_model::UntrustedText::new(".gopclntab"),
        offset,
    }
}

#[test]
fn a_go_executable_s_gopclntab_gives_both_function_hints() {
    let (_d, paths) = files(&[("ollama", &go_elf(&pclntab(0x3000), true))]);
    let s = inspect(&paths, NamedBudgets::default());
    assert!(s.binaries[0].go.is_some(), "{:?}", s.binaries[0].gaps);
    let mut got = signatures(&s);
    got.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        got,
        [
            (
                "ollama.device_discovery".to_string(),
                Signal::GoFunction,
                DISCOVER.to_string(),
                gopclntab(0x2000)
            ),
            (
                "ollama.llama_server_launch".to_string(),
                Signal::GoFunction,
                LAUNCH.to_string(),
                gopclntab(0x100)
            ),
        ]
    );
    assert!(s.hints.iter().all(|h| h.subject == s.binaries[0].slice));
}

#[test]
fn without_go_build_info_gopclntab_is_not_read() {
    let (_d, paths) = files(&[("ollama", &go_elf(&pclntab(0x3000), false))]);
    let s = inspect(&paths, NamedBudgets::default());
    assert!(s.binaries[0].go.is_none());
    assert!(signatures(&s).is_empty(), "{:?}", s.hints);
}

#[test]
fn an_rpc_export_gives_rpc_code_present() {
    let (_d, paths) = files(&[("libggml-rpc.so", &rpc_library())]);
    let s = inspect(&paths, NamedBudgets::default());
    let name = "ggml_backend_rpc_init".to_string();
    assert_eq!(
        signatures(&s),
        [(
            "rpc.code_present".to_string(),
            Signal::Export,
            name.clone(),
            Loc::Symbol(sigil_model::UntrustedText::new(name))
        )]
    );
}

#[test]
fn an_rpc_import_is_not_an_export() {
    // libdata.so's weak import `_ITM_deregisterTMCloneTable`, renamed: undefined, so not an export.
    let bytes = replaced(
        &fixture("elf/libdata.so"),
        b"_ITM_deregisterTMCloneTable",
        b"ggml_backend_rpc_deregister",
    );
    let (_d, paths) = files(&[("libggml-rpc.so", &bytes)]);
    let s = inspect(&paths, NamedBudgets::default());
    assert!(signatures(&s).is_empty(), "{:?}", s.hints);
}

#[test]
fn an_rpc_string_without_the_export_gives_no_hint() {
    let bytes = rpc_string_library();
    let (_d, paths) = files(&[("libllama-common.so.0.0.1", &bytes)]);
    let s = inspect(&paths, NamedBudgets::default());
    assert!(signatures(&s).is_empty(), "{:?}", s.hints);
}

#[test]
fn an_nvidia_named_library_is_not_scanned() {
    let bytes = rpc_library();
    let (_d, paths) = files(&[
        ("libcudart.so.12", &bytes),
        ("libcublasLt.so.12.8.5.5", &go_elf(&pclntab(0x3000), true)),
    ]);
    let f = collect(&paths, NamedBudgets::default()).unwrap();
    assert_eq!(f.scans.len(), 2);
    assert!(
        f.scans
            .iter()
            .all(|(_, outcome)| *outcome == ScanOutcome::NameAndHashOnly),
        "{:?}",
        f.scans
    );
    // The same bytes under another name are scanned, also when an NVIDIA name came first; and an
    // NVIDIA name that comes after does not relabel the scan.
    for names in [
        &["libggml-rpc.so"][..],
        &["libcudart.so.12", "libggml-rpc.so"],
        &["libggml-rpc.so", "libcudart.so.12"],
    ] {
        let entries: Vec<(&str, &[u8])> = names.iter().map(|n| (*n, bytes.as_slice())).collect();
        let (_d, paths) = files(&entries);
        let f = collect(&paths, NamedBudgets::default()).unwrap();
        assert!(
            matches!(&f.scans[..], [(_, ScanOutcome::Scanned { found, gaps })] if found.len() == 1 && gaps.is_empty()),
            "{names:?}: {:?}",
            f.scans
        );
    }
}

#[test]
fn a_binary_inspection_records_the_scan_budget() {
    let (_d, paths) = files(&[("ollama", &go_elf(&pclntab(0x3000), true))]);
    let budgets = NamedBudgets {
        binary: sigil_engine::binary::BinaryBudgets {
            scan_bytes: 12345,
            ..Default::default()
        },
        ..NamedBudgets::default()
    };
    let s = inspect(&paths, budgets);
    assert_eq!(s.request.budgets.get("binary_scan_bytes"), Some(&12345));
    let s = inspect(&paths, NamedBudgets::default());
    assert_eq!(
        s.request.budgets.get("binary_scan_bytes"),
        Some(&(64 << 20))
    );
}

/// An install with `bin/ollama` and `lib/ollama/<name>` for each `(name, bytes)` of `libs`.
fn install(ollama: &[u8], libs: &[(&str, &[u8])]) -> (TempDir, TempDir, Session) {
    let tree = TempDir::new().unwrap();
    std::fs::create_dir_all(tree.path().join("bin")).unwrap();
    std::fs::create_dir_all(tree.path().join("lib/ollama")).unwrap();
    std::fs::write(tree.path().join("bin/ollama"), ollama).unwrap();
    for (name, bytes) in libs {
        std::fs::write(tree.path().join("lib/ollama").join(name), bytes).unwrap();
    }
    let models = TempDir::new().unwrap();
    let s = install_session(tree.path(), models.path());
    (tree, models, s)
}

fn install_session(tree: &Path, models: &Path) -> Session {
    let req = StoreRequest {
        models_dir: models.to_path_buf(),
        model_filter: None,
        budgets: FsBudgets::default(),
        manifest_limit: DEFAULT_MANIFEST_LIMIT,
        install: Some(InstallRequest {
            dir: tree.to_path_buf(),
            budgets: InstallBudgets::default(),
        }),
    };
    let s = store_session(
        &req,
        &ActiveInput::default(),
        &Policy::builtin_default().unwrap(),
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap();
    s.validate().unwrap();
    s
}

#[test]
fn an_install_carries_the_signature_hints_and_the_scan_budget() {
    let rpc = rpc_library();
    let (_t, _m, s) = install(
        &go_elf(&pclntab(0x3000), true),
        &[("libggml-rpc.so", &rpc), ("libcudart.so.12", &rpc)],
    );
    let mut got: Vec<(String, Signal)> = signatures(&s)
        .into_iter()
        .map(|(feature, signal, _, _)| (feature, signal))
        .collect();
    got.sort_by(|a, b| a.0.cmp(&b.0));
    // The NVIDIA-named copy, read first, is the same content: it is scanned under its other name.
    assert_eq!(
        got,
        [
            ("ollama.device_discovery".to_string(), Signal::GoFunction),
            ("ollama.llama_server_launch".to_string(), Signal::GoFunction),
            ("rpc.code_present".to_string(), Signal::Export),
        ]
    );
    assert_eq!(
        s.request.budgets.get("binary_scan_bytes"),
        Some(&(64 << 20))
    );
}

#[test]
fn a_relocatable_object_has_no_dynamic_exports() {
    // net.o defines `sigil_connect_loopback`, renamed: a symbol left for the linker, not an export
    // of a loaded file.
    let bytes = replaced(
        &fixture("elf/net.o"),
        b"sigil_connect_loopback",
        b"ggml_backend_rpc_start",
    );
    let (_d, paths) = files(&[("net.o", &bytes)]);
    let s = inspect(&paths, NamedBudgets::default());
    assert!(signatures(&s).is_empty(), "{:?}", s.hints);
}

/// The scan of `bytes` with the needles of `db`, through `parse_artifact`.
fn scan_with(bytes: &[u8], db: &str) -> ScanOutcome {
    use sigil_engine::binary::{needles, parse_artifact, BinaryBudgets};
    let needles = needles::parse(db).unwrap();
    let f = file(bytes);
    let digest = sigil_model::Sha256Hex::new("0".repeat(64)).unwrap();
    let parsed = parse_artifact(
        &f,
        bytes.len() as u64,
        &digest,
        &bytes[..64],
        BinaryBudgets::default(),
        Some(&needles),
    )
    .unwrap();
    parsed.slices[0].scan.clone().unwrap()
}

#[test]
fn string_needles_are_looked_for_in_read_only_data_sections() {
    // One needle per section: only those in .rodata, .rodata.*, and .lrodata are found.
    let sections: [(&str, u32, &str); 6] = [
        (".rodata", SHT_PROGBITS, "in-rodata"),
        (".rodata.str1.1", SHT_PROGBITS, "in-rodata-str"),
        (".lrodata", SHT_PROGBITS, "in-lrodata"),
        (".data", SHT_PROGBITS, "in-data"),
        (".rodatax", SHT_PROGBITS, "in-rodatax"),
        (".rodata.bss", SHT_NOBITS, "in-nobits"),
    ];
    let mut img = ElfImage::new(3);
    let mut db = String::new();
    for (k, (_, _, needle)) in sections.iter().enumerate() {
        img.put(0x1000 + 0x100 * k as u64, needle.as_bytes());
        db.push_str(&format!(
            "[[needle]]\nfeature = \"s.{needle}\"\nkind = \"string\"\nvalue = \"{needle}\"\n"
        ));
    }
    let end = img.body.len() as u64;
    img.seg(PT_LOAD, PF_R, 0, 0, end, end);
    for (k, (name, sh_type, _)) in sections.iter().enumerate() {
        let at = 0x1000 + 0x100 * k as u64;
        img.sec(name, *sh_type, at, at, 0x100);
    }
    let ScanOutcome::Scanned { found, gaps } = scan_with(&img.build(), &db) else {
        panic!("not scanned");
    };
    let got: Vec<(String, Signal, Loc)> = found
        .iter()
        .map(|f| (f.feature.to_string(), f.signal, f.at.clone()))
        .collect();
    let at = |name: &str| Loc::Section {
        name: sigil_model::UntrustedText::new(name),
        offset: 0,
    };
    assert_eq!(
        got,
        [
            ("s.in-rodata".to_string(), Signal::String, at(".rodata")),
            (
                "s.in-rodata-str".to_string(),
                Signal::String,
                at(".rodata.str1.1")
            ),
            ("s.in-lrodata".to_string(), Signal::String, at(".lrodata")),
        ]
    );
    assert!(gaps.is_empty(), "{gaps:?}");
    // Without section headers, a string needle is a gap.
    let mut bare = ElfImage::new(3);
    bare.put(0x1000, b"in-rodata");
    let end = bare.body.len() as u64;
    bare.seg(PT_LOAD, PF_R, 0, 0, end, end);
    assert_eq!(
        scan_with(&bare.build(), &db),
        ScanOutcome::Scanned {
            found: vec![],
            gaps: vec![SCAN_NO_SECTIONS.to_string()]
        }
    );
}

/// The one scan of `bytes`, collected under the file name `name`.
fn scan_of(name: &str, bytes: &[u8]) -> ScanOutcome {
    let (_d, paths) = files(&[(name, bytes)]);
    let f = collect(&paths, NamedBudgets::default()).unwrap();
    assert_eq!(f.scans.len(), 1, "{:?}", f.scans);
    f.scans[0].1.clone()
}

/// A scan that found nothing, with `gaps`.
fn found_nothing(gaps: &[&str]) -> ScanOutcome {
    ScanOutcome::Scanned {
        found: vec![],
        gaps: gaps.iter().map(|g| g.to_string()).collect(),
    }
}

/// `bytes` with the `sh_type` of its section `name` set to `sh_type`.
fn retyped(bytes: &[u8], name: &str, sh_type: u32) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let header = sections64(&out)
        .into_iter()
        .find(|s| s.0 == name)
        .unwrap()
        .2;
    out[header + 4..header + 8].copy_from_slice(&sh_type.to_le_bytes());
    out
}

/// Plan review P2: the loader has dynamic symbols (`DT_SYMTAB`) the parse has no `.dynsym` for,
/// so an export needle is not known to be absent.
#[test]
fn a_dynsym_the_parse_does_not_read_is_a_gap() {
    // `.dynsym` typed SHT_PROGBITS; DT_SYMTAB and DT_STRTAB still name it.
    let bytes = retyped(&rpc_library(), ".dynsym", SHT_PROGBITS);
    let (_d, paths) = files(&[("libggml-rpc.so", &bytes)]);
    let s = inspect(&paths, NamedBudgets::default());
    assert!(signatures(&s).is_empty(), "{:?}", s.hints);
    // A gap of the scan, never of the container.
    assert!(
        s.binaries[0]
            .gaps
            .iter()
            .all(|g| !g.starts_with("string scan")),
        "{:?}",
        s.binaries[0].gaps
    );
    let gap = found_nothing(&[sigil_model::SCAN_NAME_NOT_READ]);
    assert_eq!(scan_of("libggml-rpc.so", &bytes), gap);
    // Without an export needle, nothing is missing.
    let go = "[[needle]]\nfeature = \"g.f\"\nkind = \"go-function\"\nvalue = \"main.f\"\n";
    assert_eq!(scan_with(&bytes, go), found_nothing(&[]));
}

#[test]
fn a_dynsym_that_disagrees_with_the_loader_is_a_gap() {
    let lib = rpc_library();
    let at = |name: &str| {
        sections64(&lib)
            .into_iter()
            .find(|s| s.0 == name)
            .unwrap()
            .3
    };
    // In libdata.so, `.dynsym` and `.dynstr` are at their file offsets. The loader reads its
    // symbols one entry later, or its names one byte later, than the parse: an export the parse
    // reads is not known to be one the loader has.
    for (tag, value) in [
        (DT_SYMTAB, at(".dynsym") + 24),
        (DT_STRTAB, at(".dynstr") + 1),
    ] {
        let mut bytes = lib.clone();
        set_dynamic(&mut bytes, tag, value);
        let (_d, paths) = files(&[("libggml-rpc.so", &bytes)]);
        let s = inspect(&paths, NamedBudgets::default());
        assert!(signatures(&s).is_empty(), "{tag}: {:?}", s.hints);
        let gap = found_nothing(&[sigil_model::SCAN_NAME_NOT_READ]);
        assert_eq!(scan_of("libggml-rpc.so", &bytes), gap, "{tag}");
    }
}

#[test]
fn an_elf_without_dt_symtab_has_no_export_gap() {
    // A static executable has no PT_DYNAMIC; this shared object's has no DT_SYMTAB; and one with
    // no program headers (`e_phnum` 0) is not loaded at all.
    let mut no_symtab = ElfImage::new(3);
    no_symtab.put(0x1000, &dynamic(&[(DT_DEBUG, 0)]));
    let end = no_symtab.body.len() as u64;
    no_symtab.seg(PT_LOAD, PF_R | PF_W, 0, 0, end, end);
    no_symtab.seg(PT_DYNAMIC, PF_R | PF_W, 0x1000, 0x1000, 32, 32);
    for (name, bytes) in [
        ("static", fixture("elf/static")),
        ("libnosym.so", no_symtab.build()),
        ("libnoload.so", ElfImage::new(3).build()),
    ] {
        assert_eq!(scan_of(name, &bytes), found_nothing(&[]), "{name}");
    }
}

#[test]
fn a_pt_dynamic_that_cannot_be_read_is_an_export_gap() {
    // PT_DYNAMIC at an address no PT_LOAD maps: whether the loader has DT_SYMTAB is not known.
    let mut img = ElfImage::new(3);
    img.put(0x1000, &dynamic(&[(DT_DEBUG, 0)]));
    let end = img.body.len() as u64;
    img.seg(PT_LOAD, PF_R | PF_W, 0, 0, end, end);
    img.seg(PT_DYNAMIC, PF_R | PF_W, 0x1000, 0x10_0000, 32, 32);
    let gap = found_nothing(&[sigil_model::SCAN_NAME_NOT_READ]);
    assert_eq!(scan_of("libunread.so", &img.build()), gap);
}

#[test]
fn a_relocatable_object_is_not_loaded_so_has_no_export_gap() {
    // Even with a PT_DYNAMIC naming DT_SYMTAB: no loader reads an ET_REL file.
    let mut img = ElfImage::new(1);
    img.put(0x1000, &dynamic(&[(DT_SYMTAB, 0x2000)]));
    let end = img.body.len() as u64;
    img.seg(PT_LOAD, PF_R | PF_W, 0, 0, end, end);
    img.seg(PT_DYNAMIC, PF_R | PF_W, 0x1000, 0x1000, 32, 32);
    assert_eq!(scan_of("dyn.o", &img.build()), found_nothing(&[]));
}

/// A change to an ELF file's bytes.
type Patch = fn(&[u8]) -> Vec<u8>;

/// `bytes` with its `PT_DYNAMIC` at an address no `PT_LOAD` maps.
fn dynamic_unmapped(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let p = phdr64(&out, PT_DYNAMIC);
    out[p + 16..p + 24].copy_from_slice(&0x10_0000_0000u64.to_le_bytes());
    out
}

/// `bytes` with its program headers (`e_phoff`) past the end of the file.
fn phdrs_past_eof(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let at = out.len() as u64 + 0x1000;
    out[32..40].copy_from_slice(&at.to_le_bytes());
    out
}

/// The loader's dynamic table cannot be read (an unmapped `PT_DYNAMIC`, or program headers past
/// the end of the file), so the `.dynsym` read is not checked against it: an export needle not
/// found there is not known to be absent; one found is kept.
#[test]
fn exports_not_checked_against_the_loader_s_table_are_a_gap_unless_found() {
    let patches: [(&str, Patch); 2] = [
        ("unmapped PT_DYNAMIC", dynamic_unmapped),
        ("program headers past EOF", phdrs_past_eof),
    ];
    let gap = found_nothing(&[sigil_model::SCAN_NAME_NOT_READ]);
    for (how, patch) in patches {
        // libdata.so has no RPC export.
        let bytes = patch(&fixture("elf/libdata.so"));
        assert_eq!(scan_of("libdata.so", &bytes), gap, "{how}");
        let (_d, paths) = files(&[("libggml-rpc.so", &patch(&rpc_library()))]);
        let s = inspect(&paths, NamedBudgets::default());
        let got: Vec<String> = signatures(&s).into_iter().map(|h| h.0).collect();
        assert_eq!(got, ["rpc.code_present"], "{how}");
        let ScanOutcome::Scanned { found, gaps } =
            scan_of("libggml-rpc.so", &patch(&rpc_library()))
        else {
            panic!("{how}: not scanned");
        };
        assert_eq!(found.len(), 1, "{how}");
        assert!(gaps.is_empty(), "{how}: {gaps:?}");
        // Without a `.dynsym`, nothing is read.
        let bytes = patch(&retyped(&rpc_library(), ".dynsym", SHT_PROGBITS));
        assert_eq!(scan_of("libggml-rpc.so", &bytes), gap, "{how}");
    }
}

/// The `.dynsym` entry of the symbol named `name` in an ELF64 little-endian file: its offset.
fn dynsym_entry(bytes: &[u8], name: &[u8]) -> usize {
    let secs = sections64(bytes);
    let sec = |n: &str| secs.iter().find(|s| s.0 == n).unwrap().clone();
    let (dynsym, dynstr) = (sec(".dynsym"), sec(".dynstr"));
    (dynsym.3..dynsym.3 + dynsym.4)
        .step_by(24)
        .map(|at| at as usize)
        .find(|&at| {
            let st_name = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as u64;
            let from = (dynstr.3 + st_name) as usize;
            st_name < dynstr.4 && bytes[from..].starts_with(name) && bytes[from + name.len()] == 0
        })
        .unwrap()
}

#[test]
fn an_export_name_that_cannot_be_read_is_a_gap() {
    // `ggml_backend_rpc_init`'s `st_name` past `.dynstr`: it could be the RPC export.
    let mut bytes = rpc_library();
    let at = dynsym_entry(&bytes, b"ggml_backend_rpc_init");
    bytes[at..at + 4].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
    let (_d, paths) = files(&[("libggml-rpc.so", &bytes)]);
    let s = inspect(&paths, NamedBudgets::default());
    assert!(signatures(&s).is_empty(), "{:?}", s.hints);
    let gap = found_nothing(&[sigil_model::SCAN_NAME_NOT_READ]);
    assert_eq!(scan_of("libggml-rpc.so", &bytes), gap);
}
