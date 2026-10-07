//! Negative controls: each one performs a forbidden operation on purpose, and its driver test
//! asserts that the contract checks detect it. This proves the detectors work, not only that
//! compliant programs pass. The bodies are ignored tests that do nothing unless this test binary
//! is re-executed by a driver with `SIGIL_SAFETY_NEGATIVE_CONTROL=1`. Test code only; never
//! reachable from the product.

use std::ffi::{c_char, c_int, c_long, c_void, CString};
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use crate::contracts::{check, report, Contract, Policy, Violation};
use crate::fixtures;
use crate::trace::{require_tracer, run_traced, TracedRun};

const ARMED: &str = "SIGIL_SAFETY_NEGATIVE_CONTROL";
const TARGET: &str = "SIGIL_SAFETY_CONTROL_TARGET";

fn armed() -> Option<PathBuf> {
    (std::env::var(ARMED).as_deref() == Ok("1")).then(|| PathBuf::from(std::env::var_os(TARGET).expect("control target")))
}

#[repr(C)]
struct IoVec {
    base: *mut c_void,
    len: usize,
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn mmap(addr: *mut c_void, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64) -> *mut c_void;
    fn syscall(number: c_long, ...) -> c_long;
    fn getpid() -> c_int;
    fn process_vm_readv(pid: c_int, local: *const IoVec, liovcnt: u64, remote: *const IoVec, riovcnt: u64, flags: u64) -> isize;
}

// Generic syscall numbers (identical on x86_64 and aarch64).
const SYS_IO_URING_SETUP: c_long = 425;
const SYS_OPENAT2: c_long = 437;
const AT_FDCWD: c_int = -100;
const RTLD_NOW: c_int = 2;
const PROT_READ: c_int = 1;
const PROT_EXEC: c_int = 4;
const MAP_PRIVATE: c_int = 2;
const O_WRONLY: u64 = 0o1;
const O_CREAT: u64 = 0o100;

fn cpath(p: &Path) -> CString {
    use std::os::unix::ffi::OsStrExt;
    CString::new(p.as_os_str().as_bytes()).unwrap()
}

fn openat2(path: &Path, flags: u64) {
    let how = OpenHow { flags, mode: 0o600, resolve: 0 };
    unsafe {
        syscall(SYS_OPENAT2, AT_FDCWD, cpath(path).as_ptr(), &how as *const OpenHow, std::mem::size_of::<OpenHow>());
    }
}

fn map(target: &Path, prot: c_int) {
    use std::os::fd::AsRawFd;
    let f = std::fs::File::open(target).unwrap();
    unsafe {
        mmap(std::ptr::null_mut(), 4096, prot, MAP_PRIVATE, f.as_raw_fd(), 0);
    }
}

// ---- bodies (ignored tests; act only when armed) ----

#[test]
#[ignore = "negative control body; run by its driver"]
fn exec_child() {
    if armed().is_some() {
        let _ = std::process::Command::new("/bin/sh").args(["-c", "exit 0"]).status();
    }
}

#[test]
#[ignore = "negative control body; run by its driver"]
fn dlopen_target() {
    if let Some(t) = armed() {
        unsafe {
            dlopen(cpath(&t).as_ptr(), RTLD_NOW);
        }
    }
}

#[test]
#[ignore = "negative control body; run by its driver"]
fn mmap_target() {
    if let Some(t) = armed() {
        map(&t, PROT_READ);
    }
}

#[test]
#[ignore = "negative control body; run by its driver"]
fn mmap_exec_target() {
    if let Some(t) = armed() {
        map(&t, PROT_READ | PROT_EXEC);
    }
}

#[test]
#[ignore = "negative control body; run by its driver"]
fn tcp_connect() {
    if armed().is_some() {
        let _ = std::net::TcpStream::connect(("127.0.0.1", 9));
    }
}

#[test]
#[ignore = "negative control body; run by its driver"]
fn udp_bind() {
    if armed().is_some() {
        let _ = std::net::UdpSocket::bind("127.0.0.1:0");
    }
}

#[test]
#[ignore = "negative control body; run by its driver"]
fn unix_connect() {
    if armed().is_some() {
        let _ = std::os::unix::net::UnixStream::connect("/nonexistent/sigil-safety-control.sock");
    }
}

#[test]
#[ignore = "negative control body; run by its driver"]
fn append_to_target() {
    if let Some(t) = armed() {
        let _ = std::fs::OpenOptions::new().append(true).open(t);
    }
}

#[test]
#[ignore = "negative control body; run by its driver"]
fn create_in_target_dir() {
    if let Some(t) = armed() {
        let _ = std::fs::write(t.with_file_name("created-by-control"), b"x");
    }
}

#[test]
#[ignore = "negative control body; run by its driver"]
fn rename_target() {
    if let Some(t) = armed() {
        let _ = std::fs::rename(&t, t.with_extension("moved"));
    }
}

#[test]
#[ignore = "negative control body; run by its driver"]
fn openat2_write() {
    if let Some(t) = armed() {
        openat2(&t.with_file_name("openat2-created"), O_WRONLY | O_CREAT);
    }
}

#[test]
#[ignore = "negative control body; run by its driver"]
fn read_proc_environ() {
    if armed().is_some() {
        let _ = std::fs::read("/proc/self/environ");
    }
}

#[test]
#[ignore = "negative control body; run by its driver"]
fn openat2_proc() {
    if armed().is_some() {
        openat2(Path::new("/proc/self/status"), 0);
    }
}

#[test]
#[ignore = "negative control body; run by its driver"]
fn process_vm_readv_self() {
    if armed().is_some() {
        let mut a = [0u8; 8];
        let b = [1u8; 8];
        let local = IoVec { base: a.as_mut_ptr().cast(), len: 8 };
        let remote = IoVec { base: b.as_ptr() as *mut c_void, len: 8 };
        unsafe {
            process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
        }
    }
}

#[test]
#[ignore = "negative control body; run by its driver"]
fn io_uring_setup() {
    if armed().is_some() {
        let mut params = [0u8; 120];
        unsafe {
            syscall(SYS_IO_URING_SETUP, 1u32, params.as_mut_ptr());
        }
    }
}

// ---- drivers ----

/// Re-executes this test binary under strace so that only `negative_controls::<name>` runs,
/// armed, against a target file inside a fresh inspected root.
fn run_control(name: &str, target_file: impl FnOnce(&Path) -> Option<PathBuf>) -> Option<(TracedRun, Vec<Violation>)> {
    if !require_tracer(name) {
        return None;
    }
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("target");
    std::fs::create_dir_all(&root).unwrap();
    let target = target_file(&root)?;
    let exe = std::env::current_exe().unwrap();
    let filter = format!("controls::{name}");
    let raw = ["--exact", filter.as_str(), "--ignored", "--test-threads=1"];
    let args: Vec<&std::ffi::OsStr> = raw.into_iter().map(std::ffi::OsStr::new).collect();
    let run = run_traced(
        &format!("control-{name}"),
        &exe,
        &args,
        tmp.path(),
        &[(ARMED, std::ffi::OsStr::new("1")), (TARGET, target.as_os_str())],
    );
    assert!(run.stdout.contains("1 passed"), "control body `{filter}` did not run (stdout: {})", run.stdout);
    let policy = Policy { binary: exe, targets: vec![root], allowed_writes: vec![], proc_scopes: vec!["runtime"], cwd: tmp.path().to_path_buf() };
    let v = check(&run, &policy);
    Some((run, v))
}

fn plain_target(root: &Path) -> Option<PathBuf> {
    let t = root.join("artifact.bin");
    std::fs::write(&t, vec![0x90u8; 8192]).unwrap();
    Some(t)
}

/// Asserts that every `(contract, any of syscalls)` expectation is among the violations.
fn expect(name: &str, target_file: impl FnOnce(&Path) -> Option<PathBuf>, expected: &[(Contract, &[&str])]) {
    let Some((run, v)) = run_control(name, target_file) else { return };
    for (contract, syscalls) in expected {
        assert!(
            v.iter().any(|x| x.contract == *contract && syscalls.contains(&x.syscall.as_str())),
            "negative control `{name}` was NOT detected as [{}] via {syscalls:?}; the detector is broken.\n{}",
            contract.label(),
            report(&run, &v)
        );
    }
}

#[test]
fn control_exec_child_is_detected() {
    expect("exec_child", plain_target, &[(Contract::C1NoExec, &["execve"]), (Contract::C1NoExec, &["clone", "clone3", "fork", "vfork"])]);
}

#[test]
fn control_dlopen_target_is_detected() {
    expect(
        "dlopen_target",
        |root| fixtures::require("control_dlopen_target_is_detected", fixtures::shared_object(root)),
        &[(Contract::C2NoDlopen, &["mmap"]), (Contract::C3NoMmap, &["mmap"])],
    );
}

#[test]
fn control_mmap_target_is_detected_as_c3_only() {
    let Some((run, v)) = run_control("mmap_target", plain_target) else { return };
    assert!(v.iter().any(|x| x.contract == Contract::C3NoMmap && x.syscall == "mmap"), "{}", report(&run, &v));
    assert!(!v.iter().any(|x| x.contract == Contract::C2NoDlopen), "a PROT_READ mapping is not a load:\n{}", report(&run, &v));
}

#[test]
fn control_mmap_exec_target_is_detected() {
    expect("mmap_exec_target", plain_target, &[(Contract::C2NoDlopen, &["mmap"]), (Contract::C3NoMmap, &["mmap"])]);
}

#[test]
fn control_tcp_connect_is_detected() {
    expect("tcp_connect", plain_target, &[(Contract::C4NoNetwork, &["socket"]), (Contract::C4NoNetwork, &["connect"])]);
}

#[test]
fn control_udp_bind_is_detected() {
    expect("udp_bind", plain_target, &[(Contract::C4NoNetwork, &["socket"]), (Contract::C4NoNetwork, &["bind"])]);
}

#[test]
fn control_unix_connect_is_detected() {
    expect("unix_connect", plain_target, &[(Contract::C4NoNetwork, &["socket"]), (Contract::C4NoNetwork, &["connect"])]);
}

#[test]
fn control_append_to_target_is_detected() {
    expect("append_to_target", plain_target, &[(Contract::C5ReadOnly, &["openat", "open"])]);
}

#[test]
fn control_create_in_target_dir_is_detected() {
    expect("create_in_target_dir", plain_target, &[(Contract::C5ReadOnly, &["openat", "open", "creat"])]);
}

#[test]
fn control_rename_target_is_detected() {
    expect("rename_target", plain_target, &[(Contract::C5ReadOnly, &["rename", "renameat", "renameat2"])]);
}

#[test]
fn control_openat2_write_is_detected() {
    expect("openat2_write", plain_target, &[(Contract::C5ReadOnly, &["openat2"])]);
}

#[test]
fn control_read_proc_environ_is_detected() {
    expect("read_proc_environ", plain_target, &[(Contract::C6ProcScope, &["openat", "open"])]);
}

#[test]
fn control_openat2_proc_is_detected() {
    expect("openat2_proc", plain_target, &[(Contract::C6ProcScope, &["openat2"])]);
}

#[test]
fn control_process_vm_readv_is_detected() {
    expect("process_vm_readv_self", plain_target, &[(Contract::C6ProcScope, &["process_vm_readv"])]);
}

#[test]
fn control_io_uring_is_detected() {
    expect("io_uring_setup", plain_target, &[(Contract::Harness, &["io_uring_setup"])]);
}
