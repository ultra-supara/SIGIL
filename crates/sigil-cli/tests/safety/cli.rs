//! The exercised CLI paths. Each runs the real `sigil` binary under strace and asserts that the
//! contracts hold for that run, and that the run really read its inspected input (so a broken
//! fixture cannot pass vacuously). Only these paths are checked; see ADR-002.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use crate::contracts::{assert_clean, check, report, Contract, Policy};
use crate::fixtures;
use crate::trace::{fd_path, require_tracer, run_traced, Event, TracedRun};

fn sigil() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sigil"))
}

/// `target/` is the inspected root (read only); `out/` receives the outputs a test names.
struct Fixture {
    tmp: TempDir,
    target: PathBuf,
    out: PathBuf,
}

fn fixture() -> Fixture {
    let tmp = TempDir::new().unwrap();
    let target = tmp.path().join("target");
    let out = tmp.path().join("out");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::create_dir_all(&out).unwrap();
    Fixture { tmp, target, out }
}

fn run(case: &str, fx: &Fixture, args: &[&OsStr]) -> TracedRun {
    run_traced(case, &sigil(), args, fx.tmp.path(), &[])
}

fn policy(fx: &Fixture, outputs: &[&Path], scopes: &[&'static str]) -> Policy {
    Policy {
        binary: sigil(),
        targets: vec![fx.target.clone()],
        allowed_writes: outputs.iter().map(|p| p.to_path_buf()).collect(),
        proc_scopes: scopes.to_vec(),
        cwd: fx.tmp.path().to_path_buf(),
        network: None,
    }
}

/// The run opened something under `root` (evidence that the inspection path was exercised).
fn assert_read_under(run: &TracedRun, root: &Path) {
    let root = std::fs::canonicalize(root).unwrap();
    let read = run.events.iter().any(|e| {
        matches!(e.name.as_str(), "openat" | "open" | "openat2")
            && fd_path(&e.ret)
                .map(|p| p.starts_with(&root))
                .unwrap_or(false)
    });
    assert!(read, "case `{}` never opened anything under {}; the fixture did not exercise the path.\nstdout: {}\nstderr: {}", run.case, root.display(), run.stdout, run.stderr);
}

fn os(args: &[&dyn AsRef<OsStr>]) -> Vec<std::ffi::OsString> {
    args.iter().map(|a| a.as_ref().to_os_string()).collect()
}

fn refs(v: &[std::ffi::OsString]) -> Vec<&OsStr> {
    v.iter().map(|s| s.as_os_str()).collect()
}

/// A saved session under `target/`, written by an untraced run: the input of the commands that
/// read a session.
fn saved_session(fx: &Fixture) -> PathBuf {
    let models = fixtures::ollama_store(&fx.target);
    let session = fx.target.join("session.json");
    let status = std::process::Command::new(sigil())
        .args(["inspect", "ollama", "--models-dir"])
        .arg(&models)
        .arg("--out")
        .arg(&session)
        .status()
        .unwrap();
    assert!(status.success());
    session
}

#[test]
fn static_inspection_to_stdout() {
    if !require_tracer("static_inspection_to_stdout") {
        return;
    }
    let fx = fixture();
    let models = fixtures::ollama_store(&fx.target);
    let args = os(&[&"inspect", &"ollama", &"--models-dir", &models]);
    let r = run("inspect-static", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert!(r.stdout.contains("sigil-session/1"), "{}", r.stdout);
    assert_read_under(&r, &models);
    // Static mode: no /proc entry beyond SIGIL's own runtime.
    assert_clean(&r, &policy(&fx, &[], &["runtime"]));
}

#[test]
fn static_markdown_writes_only_its_out() {
    if !require_tracer("static_markdown_writes_only_its_out") {
        return;
    }
    let fx = fixture();
    let models = fixtures::ollama_store(&fx.target);
    let md = fx.out.join("nested/report.md");
    let args = os(&[
        &"inspect",
        &"ollama",
        &"--models-dir",
        &models,
        &"--format",
        &"md",
        &"--out",
        &md,
    ]);
    let r = run("inspect-static-md-out", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert!(md.is_file());
    assert_read_under(&r, &models);
    assert_clean(&r, &policy(&fx, &[&md], &["runtime"]));
}

#[test]
fn static_inspection_of_an_install_reads_only_its_roots() {
    let case = "static_inspection_of_an_install_reads_only_its_roots";
    if !require_tracer(case) {
        return;
    }
    let fx = fixture();
    let build = fx.tmp.path().join("build");
    std::fs::create_dir_all(&build).unwrap();
    let Some(so) = fixtures::require(case, fixtures::shared_object(&build)) else {
        return;
    };
    let models = fixtures::ollama_store(&fx.target);
    let install = fixtures::ollama_install(&fx.target, &so);
    let md = fx.out.join("report.md");
    let args = os(&[
        &"inspect",
        &"ollama",
        &"--models-dir",
        &models,
        &"--install-dir",
        &install,
        &"--format",
        &"md",
        &"--out",
        &md,
    ]);
    let r = run("inspect-static-install", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert!(md.is_file());
    assert!(r.stderr.contains("release: "), "{}", r.stderr);
    assert_read_under(&r, &models);
    assert_read_under(&r, &install.join("lib/ollama"));
    // Reads only under `target/`, writes only --out, no exec, no load, no socket.
    assert_clean(&r, &policy(&fx, &[&md], &["runtime"]));
}

/// The run opened nothing under `dir`, and nothing relative to a directory under it.
fn assert_never_opened_under(run: &TracedRun, dir: &Path) {
    let dir = std::fs::canonicalize(dir).unwrap();
    for e in &run.events {
        if !matches!(e.name.as_str(), "openat" | "open" | "openat2") {
            continue;
        }
        let under = |raw: &str| fd_path(raw).is_some_and(|p| p.starts_with(&dir));
        let at = e.args.first().is_some_and(|a| under(a));
        assert!(
            !under(&e.ret) && !at,
            "case `{}` opened under {}: {}",
            run.case,
            dir.display(),
            e.raw
        );
    }
}

/// The #82 review's P1: a symlink in the install leads to `private/`, outside `bin/ollama` and
/// `lib/ollama/`. Path A: `lib/ollama` itself is the link. Path B: a link inside `lib/ollama/`
/// leads to a file there. Neither is followed: nothing under `private/` is opened.
#[test]
fn an_install_never_opens_what_its_links_lead_to() {
    let case = "an_install_never_opens_what_its_links_lead_to";
    if !require_tracer(case) {
        return;
    }
    let fx = fixture();
    let build = fx.tmp.path().join("build");
    std::fs::create_dir_all(&build).unwrap();
    let Some(so) = fixtures::require(case, fixtures::shared_object(&build)) else {
        return;
    };
    let models = fixtures::ollama_store(&fx.target);
    for (name, path_a) in [("a", true), ("b", false)] {
        let root = fx.target.join(name);
        let install = fixtures::ollama_install(&root, &so);
        let private = install.join("private");
        std::fs::create_dir_all(&private).unwrap();
        std::fs::write(private.join("credentials.txt"), b"secret").unwrap();
        let lib = install.join("lib/ollama");
        if path_a {
            std::fs::remove_dir_all(&lib).unwrap();
            std::os::unix::fs::symlink("../private", &lib).unwrap();
        } else {
            std::os::unix::fs::symlink("../../private/credentials.txt", lib.join("unexpected.so"))
                .unwrap();
        }
        let args = os(&[
            &"inspect",
            &"ollama",
            &"--models-dir",
            &models,
            &"--install-dir",
            &install,
        ]);
        let r = run(&format!("inspect-install-links-{name}"), &fx, &refs(&args));
        assert!(r.status.unwrap().success(), "{}", r.stderr);
        assert_read_under(&r, &install.join("bin"));
        assert_never_opened_under(&r, &private);
        assert_clean(&r, &policy(&fx, &[], &["runtime"]));
    }
}

#[test]
fn binary_inspection_reads_only_its_inputs() {
    let case = "binary_inspection_reads_only_its_inputs";
    if !require_tracer(case) {
        return;
    }
    let fx = fixture();
    let so = fx.target.join("libdata.so");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../sigil-engine/tests/fixtures/elf/libdata.so"),
        &so,
    )
    .unwrap();
    // Named through a symlink, which is resolved. Next to it, a file no run may open.
    let link = fx.target.join("link.so");
    std::os::unix::fs::symlink("libdata.so", &link).unwrap();
    std::fs::create_dir(fx.target.join("private")).unwrap();
    std::fs::write(fx.target.join("private/secret.txt"), b"secret").unwrap();
    let md = fx.out.join("report.md");
    let args = os(&[
        &"binary",
        &"inspect",
        &link,
        &"--format",
        &"md",
        &"--out",
        &md,
    ]);
    let r = run("binary-inspect", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert!(std::fs::read_to_string(&md)
        .unwrap()
        .contains("## Binaries"));
    assert_read_under(&r, &so);
    // Plan review P2: only the input is opened under target/; nothing under private/.
    assert_never_opened_under(&r, &fx.target.join("private"));
    assert_opened_only(&r, &fx.target, &[&so]);
    // No exec, no dlopen, no mmap of the target, no socket; writes only --out (and its
    // temporary siblings).
    assert_clean(&r, &policy(&fx, &[&md], &["runtime"]));
}

/// PR-5a-2 (#46): `binary inspect --code` on a relocatable object and on a linked shared object.
/// Code is read from the input's own fd: only the input is opened under target/, nothing under
/// private/, and there is no exec, dlopen, mmap of the input, or socket. It writes only --out.
#[test]
fn binary_code_inspection_reads_only_its_inputs() {
    let case = "binary_code_inspection_reads_only_its_inputs";
    if !require_tracer(case) {
        return;
    }
    let code = Path::new(env!("CARGO_MANIFEST_DIR")).join("../sigil-engine/tests/fixtures/code");
    for (name, file, call_site) in [
        (
            "kernel",
            "suspicious_kernel-gcc-O2.o",
            r"1\: kernel \@ 0x4d\: connect\(rdi\=0\, rsi\=0\, rdx\=0\)",
        ),
        ("plt", "net-plt-gcc.so", r"2\: kernel \@ 0x1118\: connect\("),
    ] {
        let fx = fixture();
        let input = fx.target.join(file);
        std::fs::copy(code.join(file), &input).unwrap();
        std::fs::create_dir(fx.target.join("private")).unwrap();
        std::fs::write(fx.target.join("private/secret.txt"), b"secret").unwrap();
        let md = fx.out.join("report.md");
        let args = os(&[
            &"binary",
            &"inspect",
            &"--code",
            &input,
            &"--format",
            &"md",
            &"--out",
            &md,
        ]);
        let r = run(&format!("binary-inspect-code-{name}"), &fx, &refs(&args));
        assert!(r.status.unwrap().success(), "{name}: {}", r.stderr);
        // The code path ran: the call site and the complete binary.code line are in the report.
        let report = std::fs::read_to_string(&md).unwrap();
        assert!(report.contains(call_site), "{name}: {report}");
        assert!(
            report.contains(r"binary\.code\: complete\; "),
            "{name}: {report}"
        );
        assert_read_under(&r, &input);
        assert_never_opened_under(&r, &fx.target.join("private"));
        assert_opened_only(&r, &fx.target, &[&input]);
        assert_clean(&r, &policy(&fx, &[&md], &["runtime"]));
    }
}

/// A Go executable as SIGIL reads one: Go's build info in `.go.buildinfo` (the engine's fixture
/// `go/go-amd64.buildinfo`) at 0x4000, and a 12 KiB `.gopclntab` at 0x8000: a Go 1.20 header whose
/// function-name table is the rest of the section (PR-4c-3a plan review P2), holding both
/// Go-function needles. Never run.
fn go_executable() -> Vec<u8> {
    use crate::elf::{ElfImage, PF_R, PF_W, PT_LOAD, SHT_PROGBITS};
    let piece = include_bytes!("../../../sigil-engine/tests/fixtures/go/go-amd64.buildinfo");
    let mut pclntab = vec![0u8; 0x3000];
    let mut header = vec![0xf1, 0xff, 0xff, 0xff, 0, 0, 1, 8];
    for field in [1u64, 1, 0, 0x48, 0x3000, 0x3000, 0x3000, 0x3000] {
        header.extend_from_slice(&field.to_le_bytes());
    }
    pclntab[..header.len()].copy_from_slice(&header);
    for (at, name) in [
        (
            0x100,
            "github.com/ollama/ollama/llm.SetupLlamaServerCommandEnv",
        ),
        (
            0x2000,
            "github.com/ollama/ollama/discover.discoverNativeDevices",
        ),
    ] {
        pclntab[at..at + name.len()].copy_from_slice(name.as_bytes());
    }
    let mut img = ElfImage::new(2);
    img.put(0x4000, piece).put(0x8000, &pclntab);
    let end = img.body.len() as u64;
    img.seg(PT_LOAD, PF_R | PF_W, 0, 0, end, end)
        .sec(
            ".go.buildinfo",
            SHT_PROGBITS,
            0x4000,
            0x4000,
            piece.len() as u64,
        )
        .sec(
            ".gopclntab",
            SHT_PROGBITS,
            0x8000,
            0x8000,
            pclntab.len() as u64,
        );
    img.build()
}

/// PR-4c-2a: the signature scan of a Go executable reads its `.gopclntab` with `pread` on the
/// input's own fd: no other read call on it than the hash's `read` and `pread`, no `read` after
/// the first `pread64`, no `lseek`, and no exec, dlopen, mmap of the input, or socket. It writes
/// only --out.
#[test]
fn binary_signature_scan_reads_with_pread_only() {
    let case = "binary_signature_scan_reads_with_pread_only";
    if !require_tracer(case) {
        return;
    }
    let fx = fixture();
    let input = fx.target.join("ollama");
    std::fs::write(&input, go_executable()).unwrap();
    std::fs::create_dir(fx.target.join("private")).unwrap();
    std::fs::write(fx.target.join("private/secret.txt"), b"secret").unwrap();
    let md = fx.out.join("report.md");
    let args = os(&[
        &"binary",
        &"inspect",
        &input,
        &"--format",
        &"md",
        &"--out",
        &md,
    ]);
    let r = run("binary-inspect-signatures", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    // The scan ran, in full: both hints are in the report, and binary.identity is complete.
    assert!(
        r.stderr.contains("  signature scan: complete"),
        "{}",
        r.stderr
    );
    let report = std::fs::read_to_string(&md).unwrap();
    for feature in ["ollama.llama_server_launch", "ollama.device_discovery"] {
        let shown = sigil_model::UntrustedText::new(feature).markdown_inline();
        assert!(report.contains(&shown), "{feature}: {report}");
    }
    assert_read_under(&r, &input);
    assert_never_opened_under(&r, &fx.target.join("private"));
    assert_opened_only(&r, &fx.target, &[&input]);
    let on_input = input_reads(&r, &input);
    // The section's header, 72 bytes at 0x8000 (32768), then its function-name table, the 12216
    // bytes after it (at 32840), each in one pread.
    for (len, at) in [(72, 32768), (12216, 32840)] {
        assert!(
            has_pread(&on_input, len, at),
            "case `{}`: no pread64 of {len} bytes at {at} (trace: {})",
            r.case,
            r.trace_dir.display()
        );
    }
    assert_clean(&r, &policy(&fx, &[&md], &["runtime"]));
}

/// The events on `input`'s fd, once checked: no read call but `read` and `pread64` (none of
/// `readv`, `preadv`, `preadv2`, `sendfile`, `splice`, `copy_file_range`, `lseek`), all by one
/// thread, so that the trace's order is the order of its reads: the hash's sequential `read`s,
/// then only `pread64`. The input is opened exactly once, so every `pread64` accepted is on the
/// fd that hashed it (the filter matches by path, which a second open would also satisfy); and
/// no `sendfile` has it as its source.
fn input_reads<'r>(r: &'r TracedRun, input: &Path) -> Vec<&'r Event> {
    let path = std::fs::canonicalize(input).unwrap();
    let opens = r
        .events
        .iter()
        .filter(|e| {
            matches!(e.name.as_str(), "open" | "openat" | "openat2")
                && fd_path(&e.ret).as_ref() == Some(&path)
        })
        .count();
    assert_eq!(
        opens,
        1,
        "case `{}`: the input is opened {opens} times (trace: {})",
        r.case,
        r.trace_dir.display()
    );
    assert!(
        !r.events.iter().any(|e| e.name == "sendfile"
            && e.args.get(1).and_then(|a| fd_path(a)).as_ref() == Some(&path)),
        "case `{}`: a sendfile from the input (trace: {})",
        r.case,
        r.trace_dir.display()
    );
    let on_input: Vec<&Event> = r
        .events
        .iter()
        .filter(|e| e.args.first().and_then(|a| fd_path(a)).as_ref() == Some(&path))
        .collect();
    for e in &on_input {
        assert!(
            !matches!(
                e.name.as_str(),
                "readv"
                    | "preadv"
                    | "preadv2"
                    | "sendfile"
                    | "splice"
                    | "copy_file_range"
                    | "lseek"
            ),
            "case `{}`: {}",
            r.case,
            e.raw
        );
    }
    assert!(
        on_input.iter().all(|e| e.pid == on_input[0].pid),
        "case `{}`: the input is read by more than one thread (trace: {})",
        r.case,
        r.trace_dir.display()
    );
    let first_pread = on_input
        .iter()
        .position(|e| e.name == "pread64")
        .unwrap_or_else(|| panic!("case `{}`: no pread64 of the input", r.case));
    for e in &on_input[first_pread..] {
        assert!(
            e.name != "read",
            "case `{}`: a read after the first pread64: {}",
            r.case,
            e.raw
        );
    }
    on_input
}

/// Whether one of `events` is a `pread64` of `len` bytes at `offset` that returned `len`.
fn has_pread(events: &[&Event], len: u64, offset: u64) -> bool {
    events.iter().any(|e| {
        e.name == "pread64"
            && e.args.get(2).map(|a| a.trim()) == Some(len.to_string().as_str())
            && e.args.get(3).map(|a| a.trim()) == Some(offset.to_string().as_str())
            && e.ret.trim() == len.to_string()
    })
}

/// PR-4c-2b: what `ggml_version` and `ggml_commit` return is read by `pread64` of their code and
/// their strings on the input's fd; nothing else reads the input, nothing is executed or mapped,
/// and only the input is opened under the target.
#[test]
fn binary_returned_value_reads_with_pread_only() {
    let case = "binary_returned_value_reads_with_pread_only";
    if !require_tracer(case) {
        return;
    }
    let fx = fixture();
    let input = fx.target.join("libggml-base.so.0.13.1");
    std::fs::write(
        &input,
        include_bytes!("../../../sigil-engine/tests/fixtures/returns/version-gcc-O2.so"),
    )
    .unwrap();
    std::fs::create_dir(fx.target.join("private")).unwrap();
    std::fs::write(fx.target.join("private/secret.txt"), b"secret").unwrap();
    let md = fx.out.join("report.md");
    let args = os(&[
        &"binary",
        &"inspect",
        &input,
        &"--format",
        &"md",
        &"--out",
        &md,
    ]);
    let r = run("binary-inspect-returns", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert!(
        r.stderr.contains("  signature scan: complete"),
        "{}",
        r.stderr
    );
    let report = std::fs::read_to_string(&md).unwrap();
    let shown = sigil_model::UntrustedText::new("0.13.1 (ggml_version)").markdown_inline();
    assert!(report.contains(&shown), "{report}");
    assert_read_under(&r, &input);
    assert_never_opened_under(&r, &fx.target.join("private"));
    assert_opened_only(&r, &fx.target, &[&input]);
    let on_input = input_reads(&r, &input);
    // `ggml_commit`'s 8 bytes at 0x1110 and 189 bytes of its string from 0x2007 to the end of
    // the read-only segment (0x20c4); `ggml_version`'s 8 bytes at 0x1100 and 196 from 0x2000.
    // File offsets equal addresses in the executable and read-only segments of this fixture
    // (README, facts marked †).
    for (len, offset) in [(8, 0x1110), (189, 0x2007), (8, 0x1100), (196, 0x2000)] {
        assert!(
            has_pread(&on_input, len, offset),
            "case `{}`: no pread64 of {len} bytes at {offset:#x} (trace: {})",
            r.case,
            r.trace_dir.display()
        );
    }
    assert_clean(&r, &policy(&fx, &[&md], &["runtime"]));
}

/// Every file the run opened under `root` is one of `files`; `root` itself (a directory fd) is
/// allowed. It sees successful opens only (by the fd annotation of their return): give it decoys
/// the run could open, as `private/secret.txt` is, so that an attempt would show.
fn assert_opened_only(run: &TracedRun, root: &Path, files: &[&Path]) {
    let root = std::fs::canonicalize(root).unwrap();
    let files: Vec<PathBuf> = files
        .iter()
        .map(|f| std::fs::canonicalize(f).unwrap())
        .collect();
    for e in &run.events {
        if !matches!(e.name.as_str(), "openat" | "open" | "openat2") {
            continue;
        }
        let Some(p) = fd_path(&e.ret) else { continue };
        assert!(
            !p.starts_with(&root) || p == root || files.contains(&p),
            "case `{}` opened {} under {}: {}",
            run.case,
            p.display(),
            root.display(),
            e.raw
        );
    }
}

#[test]
fn static_inspection_of_a_malformed_manifest() {
    if !require_tracer("static_inspection_of_a_malformed_manifest") {
        return;
    }
    let fx = fixture();
    let models = fixtures::malformed_store(&fx.target);
    let args = os(&[&"inspect", &"ollama", &"--models-dir", &models]);
    let r = run("inspect-malformed-manifest", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert_read_under(&r, &models);
    assert_clean(&r, &policy(&fx, &[], &["runtime"]));
}

#[test]
fn observe_mode_reads_only_allowlisted_proc() {
    if !require_tracer("observe_mode_reads_only_allowlisted_proc") {
        return;
    }
    let fx = fixture();
    let models = fixtures::ollama_store(&fx.target);
    let session = fx.out.join("session.json");
    let args = os(&[
        &"inspect",
        &"ollama",
        &"--mode",
        &"observe",
        &"--models-dir",
        &models,
        &"--out",
        &session,
    ]);
    let r = run("inspect-observe", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert!(session.is_file());
    let proc_reads = r
        .events
        .iter()
        .filter(|e| {
            e.raw.contains("/proc")
                || e.args.iter().any(|a| {
                    crate::trace::str_arg(a)
                        .map(|p| p.starts_with("/proc"))
                        .unwrap_or(false)
                })
        })
        .count();
    assert!(
        proc_reads > 0,
        "observe mode did not touch /proc; the observe allowlist was not exercised"
    );
    assert_clean(&r, &policy(&fx, &[&session], &["runtime", "observe"]));
    // The same trace under the static scope must fail C-6: the observe entries do real work.
    let v = check(&r, &policy(&fx, &[&session], &["runtime"]));
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        assert!(
            v.iter()
                .any(|x| x.contract == Contract::C6ProcScope && x.detail.contains(path)),
            "{path} was not flagged under the static scope:\n{}",
            report(&r, &v)
        );
    }
}

#[test]
fn session_render_writes_only_its_out() {
    if !require_tracer("session_render_writes_only_its_out") {
        return;
    }
    let fx = fixture();
    let session = saved_session(&fx);
    let md = fx.out.join("render/session.md");
    let args = os(&[&"session", &"render", &session, &"--out", &md]);
    let r = run("session-render", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert!(md.is_file());
    assert_read_under(&r, &session);
    assert_clean(&r, &policy(&fx, &[&md], &["runtime"]));
}

/// #51: `session verify` reads the session (and the built-in policy, embedded) and writes
/// nothing.
#[test]
fn session_verify_writes_nothing() {
    if !require_tracer("session_verify_writes_nothing") {
        return;
    }
    let fx = fixture();
    let session = saved_session(&fx);
    // The built-in policy's own text, read from a file: the same name and SHA-256.
    let policy_file = fx.target.join("policy.toml");
    std::fs::write(
        &policy_file,
        include_str!("../../../sigil-engine/policies/default.toml"),
    )
    .unwrap();
    let args = os(&[&"session", &"verify", &session, &"--policy", &policy_file]);
    let r = run("session-verify", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert!(r.stdout.starts_with("verified: "), "{}", r.stdout);
    assert_read_under(&r, &session);
    assert_read_under(&r, &policy_file);
    assert_clean(&r, &policy(&fx, &[], &["runtime"]));
}

#[test]
fn explain_the_verdict() {
    if !require_tracer("explain_the_verdict") {
        return;
    }
    let fx = fixture();
    let session = saved_session(&fx);
    let args = os(&[&"explain", &session, &"--verdict"]);
    let r = run("explain-verdict", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert_read_under(&r, &session);
    assert_clean(&r, &policy(&fx, &[], &["runtime"]));
}

#[test]
fn rules_reads_nothing() {
    if !require_tracer("rules_reads_nothing") {
        return;
    }
    let fx = fixture();
    let r = run("rules", &fx, &[OsStr::new("rules")]);
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert!(r.stdout.contains("exposure.bind_public"), "{}", r.stdout);
    assert_clean(&r, &policy(&fx, &[], &["runtime"]));
}

// --- the active API probe (ADR-002 active C-4) ------------------------------------------------

/// A server in this test process (not traced) that answers one `/api/version` request.
fn api_server() -> std::net::SocketAddr {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut request = vec![];
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(1) => request.push(byte[0]),
                _ => break,
            }
        }
        let body = "{\"version\":\"0.12.3\"}";
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
    });
    addr
}

/// Runs `inspect ollama --active api-probe --api-addr <dest>` under strace and checks it with the
/// probe's destination allowed. Without it, the same trace must break C-4: the case really
/// exercised the network.
fn probe_case(case: &str, dest: std::net::SocketAddr, expect: &str) {
    let fx = fixture();
    let models = fixtures::ollama_store(&fx.target);
    let addr = dest.to_string();
    let args = os(&[
        &"inspect",
        &"ollama",
        &"--models-dir",
        &models,
        &"--active",
        &"api-probe",
        &"--api-addr",
        &addr,
    ]);
    let r = run(case, &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert!(r.stderr.contains(expect), "{}", r.stderr);
    assert_read_under(&r, &models);
    let allowed = Policy {
        network: Some(dest),
        ..policy(&fx, &[], &["runtime"])
    };
    assert_clean(&r, &allowed);
    let v = check(&r, &policy(&fx, &[], &["runtime"]));
    assert!(
        v.iter()
            .any(|x| x.contract == Contract::C4NoNetwork && x.syscall == "connect"),
        "the probe's connect is missing from the trace:\n{}",
        report(&r, &v)
    );
}

#[test]
fn active_api_probe_connects_only_to_its_destination() {
    if !require_tracer("active_api_probe_connects_only_to_its_destination") {
        return;
    }
    probe_case(
        "inspect-active-api-probe",
        api_server(),
        "answered (HTTP 200), version 0.12.3",
    );
}

#[test]
fn active_api_probe_refused() {
    if !require_tracer("active_api_probe_refused") {
        return;
    }
    let dest = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    probe_case("inspect-active-api-probe-refused", dest, "→ refused");
}
