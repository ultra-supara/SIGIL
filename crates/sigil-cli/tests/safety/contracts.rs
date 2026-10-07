//! The safety contracts C-1..C-6 (ADR-002) as rules over a traced run.

use std::path::{Component, Path, PathBuf};

use crate::trace::{fd_path, field, flags, str_arg, Event, TracedRun};

/// A contract and what it means, for failure messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Contract {
    /// C-1: static/observe never execute another program (no exec, no process creation).
    C1NoExec,
    /// C-2: never load an inspected artifact as code (dlopen or an equivalent executable mapping).
    C2NoDlopen,
    /// C-3: never mmap an inspected target file; read it with read/pread.
    C3NoMmap,
    /// C-4: static/observe perform no network I/O (any socket family).
    C4NoNetwork,
    /// C-5: read-only; writes only to the outputs the caller named.
    C5ReadOnly,
    /// C-6: /proc access stays within the documented allowlist; no ptrace/process_vm_*.
    C6ProcScope,
    /// The trace itself is unusable or an operation would be invisible to it.
    Harness,
}

impl Contract {
    pub fn label(&self) -> &'static str {
        match self {
            Contract::C1NoExec => "C-1 no child process execution",
            Contract::C2NoDlopen => "C-2 no dlopen of inspected artifacts",
            Contract::C3NoMmap => "C-3 no mmap of inspected targets",
            Contract::C4NoNetwork => "C-4 no network I/O",
            Contract::C5ReadOnly => "C-5 read-only inspection",
            Contract::C6ProcScope => "C-6 /proc access within the allowlist",
            Contract::Harness => "harness integrity",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Violation {
    pub contract: Contract,
    pub syscall: String,
    pub detail: String,
    pub location: String,
    pub raw: String,
}

/// What a run is allowed to do.
pub struct Policy {
    /// The program under test (its first execve is startup, and its own text mapping is allowed).
    pub binary: PathBuf,
    /// Inspected roots: files and directories that must only be read.
    pub targets: Vec<PathBuf>,
    /// Output files the caller named; the only write-capable opens allowed (and `mkdir` of their ancestors).
    pub allowed_writes: Vec<PathBuf>,
    /// `/proc` allowlist scopes for this run: always `runtime`, plus `observe` for observe-like paths.
    pub proc_scopes: Vec<&'static str>,
    /// Working directory of the traced process at start.
    pub cwd: PathBuf,
}

/// Every syscall a rule below inspects. `trace::trace_expr` traces all of them.
pub const RULE_SYSCALLS: &[&str] = &[
    // C-1
    "execve",
    "execveat",
    "fork",
    "vfork",
    "clone",
    "clone3",
    // C-2 / C-3
    "mmap",
    "mmap2",
    // C-4
    "socket",
    "socketpair",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
    "sendto",
    "sendmsg",
    "sendmmsg",
    "recvfrom",
    "recvmsg",
    "recvmmsg",
    "getsockopt",
    "setsockopt",
    "getpeername",
    "getsockname",
    "shutdown",
    // C-5 (write-capable opens and mutations) and C-6 (path-taking calls)
    "open",
    "openat",
    "openat2",
    "creat",
    "rename",
    "renameat",
    "renameat2",
    "unlink",
    "unlinkat",
    "rmdir",
    "mkdir",
    "mkdirat",
    "symlink",
    "symlinkat",
    "link",
    "linkat",
    "truncate",
    "ftruncate",
    "chmod",
    "fchmod",
    "fchmodat",
    "fchmodat2",
    "chown",
    "fchown",
    "lchown",
    "fchownat",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "removexattr",
    "lremovexattr",
    "fremovexattr",
    "utimensat",
    "utimes",
    "futimesat",
    "utime",
    "mknod",
    "mknodat",
    "readlink",
    "readlinkat",
    "stat",
    "lstat",
    "newfstatat",
    "statx",
    "access",
    "faccessat",
    "faccessat2",
    "chdir",
    "getdents64",
    "inotify_add_watch",
    // C-6 (process memory outside /proc)
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    // Harness: I/O channels invisible to syscall tracing
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
];

const NETWORK: &[&str] = &[
    "socket",
    "socketpair",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
    "sendto",
    "sendmsg",
    "sendmmsg",
    "recvfrom",
    "recvmsg",
    "recvmmsg",
    "getsockopt",
    "setsockopt",
    "getpeername",
    "getsockname",
    "shutdown",
];
const IO_URING: &[&str] = &["io_uring_setup", "io_uring_enter", "io_uring_register"];
const PROC_MEMORY: &[&str] = &["ptrace", "process_vm_readv", "process_vm_writev"];
const FD_MUTATIONS: &[&str] = &["ftruncate", "fchmod", "fchown", "fsetxattr", "fremovexattr"];
const WRITE_FLAGS: &[&str] = &[
    "O_WRONLY",
    "O_RDWR",
    "O_CREAT",
    "O_TRUNC",
    "O_APPEND",
    "O_TMPFILE",
];
/// Directories whose shared objects the dynamic loader maps for SIGIL itself (C-2 rule (b)).
const SYSTEM_LIB_DIRS: &[&str] = &[
    "/lib",
    "/lib64",
    "/lib32",
    "/usr/lib",
    "/usr/lib64",
    "/usr/lib32",
];

/// Path-taking syscalls: `(name, [(dirfd argument, path argument)], mutates the file system)`.
/// A missing or empty path means the dirfd itself (`AT_EMPTY_PATH`, `utimensat(fd, NULL, ...)`).
#[allow(clippy::type_complexity)]
const PATH_CALLS: &[(&str, &[(Option<usize>, usize)], bool)] = &[
    ("open", &[(None, 0)], false),
    ("openat", &[(Some(0), 1)], false),
    ("openat2", &[(Some(0), 1)], false),
    ("creat", &[(None, 0)], true),
    ("readlink", &[(None, 0)], false),
    ("readlinkat", &[(Some(0), 1)], false),
    ("stat", &[(None, 0)], false),
    ("lstat", &[(None, 0)], false),
    ("newfstatat", &[(Some(0), 1)], false),
    ("statx", &[(Some(0), 1)], false),
    ("access", &[(None, 0)], false),
    ("faccessat", &[(Some(0), 1)], false),
    ("faccessat2", &[(Some(0), 1)], false),
    ("chdir", &[(None, 0)], false),
    ("inotify_add_watch", &[(None, 1)], false),
    ("execve", &[(None, 0)], false),
    ("execveat", &[(Some(0), 1)], false),
    ("rename", &[(None, 0), (None, 1)], true),
    ("renameat", &[(Some(0), 1), (Some(2), 3)], true),
    ("renameat2", &[(Some(0), 1), (Some(2), 3)], true),
    ("unlink", &[(None, 0)], true),
    ("unlinkat", &[(Some(0), 1)], true),
    ("rmdir", &[(None, 0)], true),
    ("mkdir", &[(None, 0)], true),
    ("mkdirat", &[(Some(0), 1)], true),
    ("symlink", &[(None, 1)], true),
    ("symlinkat", &[(Some(1), 2)], true),
    ("link", &[(None, 1)], true),
    ("linkat", &[(Some(2), 3)], true),
    ("truncate", &[(None, 0)], true),
    ("chmod", &[(None, 0)], true),
    ("fchmodat", &[(Some(0), 1)], true),
    ("fchmodat2", &[(Some(0), 1)], true),
    ("chown", &[(None, 0)], true),
    ("lchown", &[(None, 0)], true),
    ("fchownat", &[(Some(0), 1)], true),
    ("setxattr", &[(None, 0)], true),
    ("lsetxattr", &[(None, 0)], true),
    ("removexattr", &[(None, 0)], true),
    ("lremovexattr", &[(None, 0)], true),
    ("utimensat", &[(Some(0), 1)], true),
    ("utimes", &[(None, 0)], true),
    ("futimesat", &[(Some(0), 1)], true),
    ("utime", &[(None, 0)], true),
    ("mknod", &[(None, 0)], true),
    ("mknodat", &[(Some(0), 1)], true),
];

/// Lexical normalization (`.` and `..`); symlinks are not resolved.
fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::RootDir => out.push("/"),
            Component::CurDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(n) => out.push(n),
        }
    }
    out
}

/// Both the lexical and the canonical form of a policy path (the trace shows requested paths
/// and kernel-resolved fd paths).
fn forms(p: &Path) -> Vec<PathBuf> {
    let mut v = vec![normalize(p)];
    let canonical = std::fs::canonicalize(p).ok().or_else(|| {
        let parent = std::fs::canonicalize(p.parent()?).ok()?;
        Some(parent.join(p.file_name()?))
    });
    if let Some(c) = canonical {
        if !v.contains(&c) {
            v.push(c);
        }
    }
    v
}

fn resolve(e: &Event, dirfd: Option<usize>, path: usize, cwd: &Path) -> Option<PathBuf> {
    let base = dirfd.and_then(|i| e.args.get(i)).and_then(|a| fd_path(a));
    match e.args.get(path).and_then(|a| str_arg(a)) {
        Some(p) if !p.as_os_str().is_empty() => {
            if p.is_absolute() {
                Some(normalize(&p))
            } else {
                Some(normalize(
                    &base.unwrap_or_else(|| cwd.to_path_buf()).join(p),
                ))
            }
        }
        _ => base.map(|b| normalize(&b)),
    }
}

#[derive(Clone, Debug)]
pub struct AllowEntry {
    pub scope: String,
    pub pattern: String,
    pub reason: String,
}

/// `proc_allowlist.txt`, parsed.
pub fn proc_allowlist() -> Vec<AllowEntry> {
    include_str!("proc_allowlist.txt")
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (body, reason) = line
                .split_once('#')
                .map(|(a, b)| (a.trim(), b.trim()))
                .unwrap_or((line, ""));
            let mut it = body.split_whitespace();
            Some(AllowEntry {
                scope: it.next()?.to_string(),
                pattern: it.next()?.to_string(),
                reason: reason.to_string(),
            })
        })
        .collect()
}

fn pattern_matches(pattern: &str, path: &Path) -> bool {
    let want: Vec<&str> = pattern.trim_start_matches('/').split('/').collect();
    let got: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    want.len() == got.len()
        && want.iter().zip(&got).all(|(w, g)| match *w {
            "{pid}" => {
                g == "self"
                    || g == "thread-self"
                    || (!g.is_empty() && g.bytes().all(|b| b.is_ascii_digit()))
            }
            "{n}" => !g.is_empty() && g.bytes().all(|b| b.is_ascii_digit()),
            lit => lit == g,
        })
}

fn proc_allowed(path: &Path, scopes: &[&str], list: &[AllowEntry]) -> bool {
    list.iter()
        .any(|e| scopes.contains(&e.scope.as_str()) && pattern_matches(&e.pattern, path))
}

fn short(s: &str) -> String {
    if s.len() > 240 {
        let mut end = 240;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    } else {
        s.to_string()
    }
}

pub fn check(run: &TracedRun, p: &Policy) -> Vec<Violation> {
    let binary = forms(&p.binary);
    let targets: Vec<PathBuf> = p.targets.iter().flat_map(|t| forms(t)).collect();
    let allowed: Vec<PathBuf> = p.allowed_writes.iter().flat_map(|w| forms(w)).collect();
    let allowlist = proc_allowlist();
    let is_target = |path: &Path| targets.iter().any(|t| path.starts_with(t));
    let is_binary = |path: &Path| binary.iter().any(|b| path == b);
    let is_system_lib = |path: &Path| SYSTEM_LIB_DIRS.iter().any(|d| path.starts_with(d));
    let write_allowed = |path: &Path| allowed.iter().any(|a| path == a);
    let mkdir_allowed = |path: &Path| allowed.iter().any(|a| a.starts_with(path) && a != path);

    let mut out = Vec::new();

    // Startup: the first event of the root process is the exec of the program under test.
    let mut seen = std::collections::HashSet::new();
    let mut startup: Option<String> = None;
    for e in &run.events {
        if seen.insert(e.pid) && e.name == "execve" && e.ret == "0" && startup.is_none() {
            if let Some(path) = resolve(e, None, 0, &p.cwd) {
                if is_binary(&path) {
                    startup = Some(e.location.clone());
                }
            }
        }
    }
    if startup.is_none() {
        out.push(Violation {
            contract: Contract::Harness,
            syscall: "execve".into(),
            detail: format!("the program under test ({}) was never seen starting; the trace cannot vouch for anything", p.binary.display()),
            location: run.trace_dir.display().to_string(),
            raw: String::new(),
        });
    }
    for (location, name, reason) in &run.unparsed {
        if RULE_SYSCALLS.contains(&name.as_str()) {
            out.push(Violation {
                contract: Contract::Harness,
                syscall: name.clone(),
                detail: "a line for a syscall the rules inspect did not parse".into(),
                location: location.clone(),
                raw: short(reason),
            });
        }
    }

    let mut push = |contract, e: &Event, detail: String| {
        out.push(Violation {
            contract,
            syscall: e.name.clone(),
            detail,
            location: e.location.clone(),
            raw: short(&e.raw),
        });
    };
    let mut cwd: std::collections::HashMap<u32, PathBuf> = std::collections::HashMap::new();
    for e in &run.events {
        let here = cwd.entry(e.pid).or_insert_with(|| p.cwd.clone()).clone();
        let name = e.name.as_str();
        match name {
            "execve" | "execveat" if startup.as_deref() != Some(e.location.as_str()) => {
                let (d, i) = if name == "execve" {
                    (None, 0)
                } else {
                    (Some(0), 1)
                };
                let target = resolve(e, d, i, &here)
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "?".into());
                push(Contract::C1NoExec, e, format!("executes {target}"));
            }
            "fork" | "vfork" => push(Contract::C1NoExec, e, "creates a child process".into()),
            "clone" | "clone3" => {
                let f = if name == "clone3" {
                    e.args.first().and_then(|a| field(a, "flags"))
                } else {
                    e.args.iter().find_map(|a| field(a, "flags"))
                };
                if !f
                    .map(|f| flags(f).contains(&"CLONE_THREAD"))
                    .unwrap_or(false)
                {
                    push(
                        Contract::C1NoExec,
                        e,
                        format!("creates a child process (flags={})", f.unwrap_or("?")),
                    );
                }
            }
            "mmap" | "mmap2" => {
                let exec = e
                    .args
                    .get(2)
                    .map(|a| flags(a).contains(&"PROT_EXEC"))
                    .unwrap_or(false);
                if let Some(path) = e.args.get(4).and_then(|a| fd_path(a)) {
                    if is_target(&path) {
                        push(
                            Contract::C3NoMmap,
                            e,
                            format!("maps inspected target {} ({})", path.display(), e.args[2]),
                        );
                        if exec {
                            push(
                                Contract::C2NoDlopen,
                                e,
                                format!("maps inspected target {} executable", path.display()),
                            );
                        }
                    } else if exec && !is_binary(&path) && !is_system_lib(&path) {
                        push(
                            Contract::C2NoDlopen,
                            e,
                            format!("maps non-system code {} executable", path.display()),
                        );
                    }
                }
            }
            _ if NETWORK.contains(&name) => push(
                Contract::C4NoNetwork,
                e,
                format!("socket operation {}({})", name, short(&e.args.join(", "))),
            ),
            _ if IO_URING.contains(&name) => push(
                Contract::Harness,
                e,
                "io_uring operations are invisible to syscall tracing".into(),
            ),
            _ if PROC_MEMORY.contains(&name) => push(
                Contract::C6ProcScope,
                e,
                "reads or controls another process outside /proc".into(),
            ),
            "getdents64" => {
                if let Some(path) = e.args.first().and_then(|a| fd_path(a)) {
                    if path.starts_with("/proc") && !proc_allowed(&path, &p.proc_scopes, &allowlist)
                    {
                        push(
                            Contract::C6ProcScope,
                            e,
                            format!(
                                "lists {} (not in proc_allowlist.txt for scopes {:?})",
                                path.display(),
                                p.proc_scopes
                            ),
                        );
                    }
                }
            }
            _ if FD_MUTATIONS.contains(&name) => {
                if let Some(path) = e.args.first().and_then(|a| fd_path(a)) {
                    if !write_allowed(&path) {
                        push(
                            Contract::C5ReadOnly,
                            e,
                            format!("modifies {}", path.display()),
                        );
                    }
                }
            }
            _ => {}
        }
        if let Some((_, operands, mutates)) = PATH_CALLS.iter().find(|(n, _, _)| *n == name) {
            let paths: Vec<PathBuf> = operands
                .iter()
                .filter_map(|(d, i)| resolve(e, *d, *i, &here))
                .collect();
            if name == "chdir" && e.ret == "0" {
                if let Some(p) = paths.first() {
                    cwd.insert(e.pid, p.clone());
                }
            }
            let open_flags = match name {
                "open" => e.args.get(1).map(|s| s.as_str()),
                "openat" => e.args.get(2).map(|s| s.as_str()),
                "openat2" => e.args.get(2).and_then(|a| field(a, "flags")),
                _ => None,
            };
            let writes_by_open = open_flags
                .map(|f| flags(f).iter().any(|x| WRITE_FLAGS.contains(x)))
                .unwrap_or(false);
            for path in &paths {
                if writes_by_open && !write_allowed(path) {
                    push(
                        Contract::C5ReadOnly,
                        e,
                        format!(
                            "write-capable open ({}) of {}",
                            open_flags.unwrap_or(""),
                            path.display()
                        ),
                    );
                } else if *mutates {
                    let ok = if name.starts_with("mkdir") {
                        mkdir_allowed(path) || write_allowed(path)
                    } else {
                        write_allowed(path)
                    };
                    if !ok {
                        push(
                            Contract::C5ReadOnly,
                            e,
                            format!("{} {}", name, path.display()),
                        );
                    }
                }
                if path.starts_with("/proc") && !proc_allowed(path, &p.proc_scopes, &allowlist) {
                    push(
                        Contract::C6ProcScope,
                        e,
                        format!(
                            "accesses {} (not in proc_allowlist.txt for scopes {:?})",
                            path.display(),
                            p.proc_scopes
                        ),
                    );
                }
            }
        }
    }
    out
}

/// A failure message that names each violated contract, the syscall, the path, and where the
/// raw trace is.
pub fn report(run: &TracedRun, v: &[Violation]) -> String {
    let mut s = format!(
        "{} safety contract violation(s) in case `{}`\n  command: {}\n  cwd: {}\n  exit status: {}\n  raw trace: {} (t.<pid> files and command.txt)\n",
        v.len(),
        run.case,
        run.command,
        run.cwd.display(),
        run.status.map(|s| s.to_string()).unwrap_or_else(|| "?".into()),
        run.trace_dir.display()
    );
    let mut sorted: Vec<&Violation> = v.iter().collect();
    sorted.sort_by_key(|v| v.contract);
    for x in sorted {
        s.push_str(&format!(
            "  [{}] {}: {}\n      at {}: {}\n",
            x.contract.label(),
            x.syscall,
            x.detail,
            x.location,
            x.raw
        ));
    }
    s
}

pub fn assert_clean(run: &TracedRun, p: &Policy) {
    let v = check(run, p);
    assert!(v.is_empty(), "{}", report(run, &v));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::from_lines;

    fn hex(s: &str) -> String {
        s.bytes().map(|b| format!("\\x{b:02x}")).collect()
    }

    fn policy(scopes: &[&'static str]) -> Policy {
        Policy {
            binary: PathBuf::from("/opt/sigil"),
            targets: vec![PathBuf::from("/fx/target")],
            allowed_writes: vec![PathBuf::from("/fx/out/report.md")],
            proc_scopes: scopes.to_vec(),
            cwd: PathBuf::from("/fx"),
        }
    }

    /// A compliant run: exec of the binary, ld.so mappings, Rust std's /proc/self/maps, a thread,
    /// reading the target, writing the allowed output.
    fn startup() -> Vec<(u32, String)> {
        let cwd = hex("/fx");
        vec![
            (10, format!("execve(\"{}\", [\"{}\"], 0x7ffd /* 3 vars */) = 0", hex("/opt/sigil"), hex("sigil"))),
            (10, format!("openat(AT_FDCWD<{cwd}>, \"{}\", O_RDONLY|O_CLOEXEC) = 3<{}>", hex("/etc/ld.so.cache"), hex("/etc/ld.so.cache"))),
            (10, format!("mmap(NULL, 100, PROT_READ, MAP_PRIVATE, 3<{}>, 0) = 0x7f00", hex("/etc/ld.so.cache"))),
            (10, format!("mmap(0x7f10, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3<{}>, 0x1000) = 0x7f10", hex("/usr/lib/x86_64-linux-gnu/libc.so.6"))),
            (10, format!("openat(AT_FDCWD<{cwd}>, \"{}\", O_RDONLY|O_CLOEXEC) = 3<{}>", hex("/proc/self/maps"), hex("/proc/10/maps"))),
            (10, "clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM, exit_signal=0}, 88) = 11".to_string()),
            (10, format!("openat(AT_FDCWD<{cwd}>, \"{}\", O_RDONLY|O_CLOEXEC) = 4<{}>", hex("target/a.o"), hex("/fx/target/a.o"))),
            (10, format!("read(4<{}>, \"\\x7f\\x45\"..., 8192) = 64", hex("/fx/target/a.o"))),
            (10, format!("mkdir(\"{}\", 0777) = -1 EEXIST (File exists)", hex("/fx/out"))),
            (10, format!("openat(AT_FDCWD<{cwd}>, \"{}\", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 5<{}>", hex("/fx/out/report.md"), hex("/fx/out/report.md"))),
            (11, "futex(0x7f, FUTEX_WAIT_PRIVATE, 0, NULL) = 0".to_string()),
            (10, "exit_group(0)                           = ?".to_string()),
        ]
    }

    fn with(extra: &[(u32, String)]) -> TracedRun {
        let mut lines = startup();
        let last = lines.pop().unwrap();
        lines.extend(extra.iter().cloned());
        lines.push(last);
        from_lines("unit", &lines)
    }

    fn found(v: &[Violation]) -> Vec<(Contract, String)> {
        v.iter().map(|v| (v.contract, v.syscall.clone())).collect()
    }

    #[test]
    fn compliant_startup_has_no_violations() {
        let v = check(&with(&[]), &policy(&["runtime"]));
        assert!(v.is_empty(), "{v:#?}");
    }

    #[test]
    fn c1_second_exec_and_process_creation() {
        let run = with(&[
            (
                10,
                "clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 12".into(),
            ),
            (
                12,
                format!(
                    "execve(\"{}\", [\"{}\"], 0x7ffd /* 3 vars */) = 0",
                    hex("/bin/sh"),
                    hex("sh")
                ),
            ),
            (10, "vfork() = 13".into()),
        ]);
        let f = found(&check(&run, &policy(&["runtime"])));
        assert!(f.contains(&(Contract::C1NoExec, "clone".into())), "{f:?}");
        assert!(f.contains(&(Contract::C1NoExec, "execve".into())), "{f:?}");
        assert!(f.contains(&(Contract::C1NoExec, "vfork".into())), "{f:?}");
    }

    #[test]
    fn c2_c3_mappings_of_targets_and_foreign_code() {
        let run = with(&[
            (
                10,
                format!(
                    "mmap(NULL, 64, PROT_READ, MAP_PRIVATE, 4<{}>, 0) = 0x7e00",
                    hex("/fx/target/a.o")
                ),
            ),
            (
                10,
                format!(
                    "mmap(NULL, 64, PROT_READ|PROT_EXEC, MAP_PRIVATE, 4<{}>, 0) = 0x7e10",
                    hex("/fx/target/lib.so")
                ),
            ),
            (
                10,
                format!(
                    "mmap(NULL, 64, PROT_READ|PROT_EXEC, MAP_PRIVATE, 5<{}>, 0) = 0x7e20",
                    hex("/home/u/plugin.so")
                ),
            ),
        ]);
        let v = check(&run, &policy(&["runtime"]));
        let f = found(&v);
        assert_eq!(
            f.iter().filter(|x| x.0 == Contract::C3NoMmap).count(),
            2,
            "{v:#?}"
        );
        assert_eq!(
            f.iter().filter(|x| x.0 == Contract::C2NoDlopen).count(),
            2,
            "{v:#?}"
        );
    }

    #[test]
    fn c4_any_socket_family() {
        let run = with(&[
            (10, "socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 6<UNIX-STREAM:[99]>".into()),
            (10, "connect(6<UNIX-STREAM:[99]>, {sa_family=AF_UNIX, sun_path=\"\\x2f\\x78\"}, 4) = -1 ENOENT (No such file)".into()),
            (10, "socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) = 7".into()),
        ]);
        let f = found(&check(&run, &policy(&["runtime"])));
        assert_eq!(
            f.iter().filter(|x| x.0 == Contract::C4NoNetwork).count(),
            3,
            "{f:?}"
        );
    }

    #[test]
    fn c5_writes_and_mutations_outside_outputs() {
        let cwd = hex("/fx");
        let run = with(&[
            (10, format!("openat(AT_FDCWD<{cwd}>, \"{}\", O_WRONLY|O_APPEND) = 6<{}>", hex("target/a.o"), hex("/fx/target/a.o"))),
            (10, format!("openat2(AT_FDCWD<{cwd}>, \"{}\", {{flags=O_RDWR|O_CREAT, mode=0600, resolve=0}}, 24) = 7", hex("/tmp/x"))),
            (10, format!("renameat2(AT_FDCWD<{cwd}>, \"{}\", AT_FDCWD<{cwd}>, \"{}\", 0) = 0", hex("target/a.o"), hex("target/b.o"))),
            (10, format!("unlinkat(AT_FDCWD<{cwd}>, \"{}\", 0) = 0", hex("out/other"))),
            (10, format!("mkdir(\"{}\", 0777) = 0", hex("/fx/target/new"))),
        ]);
        let f = found(&check(&run, &policy(&["runtime"])));
        for s in ["openat", "openat2", "renameat2", "unlinkat", "mkdir"] {
            assert!(
                f.contains(&(Contract::C5ReadOnly, s.into())),
                "{s} not flagged: {f:?}"
            );
        }
        // renameat2 is reported for both its source and its destination.
        assert_eq!(f.len(), 6, "{f:?}");
    }

    #[test]
    fn c6_proc_allowlist_by_scope() {
        let cwd = hex("/fx");
        let lines = [
            (10, format!("readlink(\"{}\", \"{}\", 1024) = 14", hex("/proc/123/fd/4"), hex("socket:[1]"))),
            (10, format!("getdents64(8<{}>, 0x55 /* 40 entries */, 32768) = 1200", hex("/proc"))),
            (10, format!("openat(AT_FDCWD<{cwd}>, \"{}\", O_RDONLY|O_CLOEXEC) = 9", hex("/proc/1/environ"))),
            (10, "process_vm_readv(10, [{iov_base=0x1, iov_len=8}], 1, [{iov_base=0x2, iov_len=8}], 1, 0) = 8".into()),
        ];
        let observe = found(&check(&with(&lines), &policy(&["runtime", "observe"])));
        assert_eq!(
            observe,
            vec![
                (Contract::C6ProcScope, "openat".into()),
                (Contract::C6ProcScope, "process_vm_readv".into())
            ],
        );
        let stat = found(&check(&with(&lines), &policy(&["runtime"])));
        assert_eq!(
            stat.iter().filter(|x| x.0 == Contract::C6ProcScope).count(),
            4,
            "{stat:?}"
        );
    }

    #[test]
    fn harness_requires_the_binary_to_start_and_rule_lines_to_parse() {
        let run = from_lines(
            "unit",
            &[(
                10,
                format!("openat(AT_FDCWD<{}>, \"{}\", O_RDONLY", hex("/"), hex("/x")),
            )],
        );
        let f = found(&check(&run, &policy(&["runtime"])));
        assert!(
            f.iter().filter(|x| x.0 == Contract::Harness).count() >= 2,
            "{f:?}"
        );
        let run = with(&[(10, "io_uring_setup(8, 0x7ffd) = 9".into())]);
        assert!(found(&check(&run, &policy(&["runtime"])))
            .contains(&(Contract::Harness, "io_uring_setup".into())));
    }

    #[test]
    fn allowlist_entries_are_documented() {
        let entries = proc_allowlist();
        assert!(!entries.is_empty());
        for e in &entries {
            assert!(["runtime", "observe"].contains(&e.scope.as_str()), "{e:?}");
            assert!(e.pattern.starts_with("/proc"), "{e:?}");
            assert!(e.reason.len() >= 10, "entry needs a reason: {e:?}");
        }
    }
}
