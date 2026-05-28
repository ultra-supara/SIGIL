use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use sigil_core::x86::{decode_x86_64, lift_instructions, load_function};
use tempfile::TempDir;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap()
        .to_path_buf()
}

fn compile_fixture(source: &str, output: &Path) -> bool {
    let Some(clang) = which("clang") else {
        return false;
    };
    let status = Command::new(clang)
        .current_dir(workspace_root())
        .args(["-O0", "-c", source, "-o"])
        .arg(output)
        .status()
        .expect("clang should run");
    status.success()
}

fn which(binary: &str) -> Option<String> {
    std::env::var_os("PATH")?
        .to_string_lossy()
        .split(':')
        .map(|dir| Path::new(dir).join(binary))
        .find(|path| path.is_file())
        .map(|path| path.display().to_string())
}

#[test]
fn decodes_and_lifts_simple_x86_bytes() {
    let decoded = decode_x86_64(&[0x89, 0xf8, 0x01, 0xf0, 0xc3], 0x1000).unwrap();
    assert_eq!(decoded[0].mnemonic, "mov");
    assert_eq!(decoded[1].mnemonic, "add");

    let ir = lift_instructions("kernel", &decoded, &BTreeMap::new(), &BTreeMap::new());
    let ops: Vec<_> = ir.blocks[0].ops.iter().map(|op| op.op.as_str()).collect();
    assert_eq!(ops, vec!["Mov", "Add", "Return"]);
}

#[test]
fn loads_compiled_function_and_resolves_call_relocation() {
    let tmp = TempDir::new().unwrap();
    let object = tmp.path().join("suspicious.o");
    if !compile_fixture("examples/src/suspicious_kernel.c", &object) {
        return;
    }

    let function = load_function(&object, "kernel").unwrap();
    assert_eq!(function.entry, "kernel");
    assert!(!function.code.is_empty());
    assert!(function
        .call_symbols
        .values()
        .any(|symbol| symbol == "connect"));
}
