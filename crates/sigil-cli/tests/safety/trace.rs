//! Running a command under strace and parsing the per-process trace files.
//!
//! strace has no structured output format, so the invocation is chosen to make the text
//! unambiguous: `-ff` writes one file per process/thread (no interleaved `<unfinished ...>`
//! lines), `-xx` prints every string byte as `\xNN` (no quoting ambiguity), `-yy` annotates every
//! fd argument and return value with its path or socket (so mmap and getdents64 can be tied to a
//! file, and `AT_FDCWD<cwd>` resolves relative paths), `-qq` and `-e signal=none` drop
//! attach/exit/signal chatter. Lines are split with a small tokenizer, never with regexes.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::OnceLock;

use crate::contracts::RULE_SYSCALLS;

/// strace filter: the broad classes plus every syscall a contract rule inspects, each with `?` so
/// that names missing on an architecture do not abort strace. `trace_expr_covers_rule_syscalls`
/// keeps the two in sync, so a rule can never silently look at an untraced syscall.
pub fn trace_expr() -> String {
    let mut parts: Vec<String> = ["%process", "%network", "%file", "%desc"].iter().map(|s| s.to_string()).collect();
    parts.extend(RULE_SYSCALLS.iter().map(|s| format!("?{s}")));
    format!("trace={}", parts.join(","))
}

/// A finished traced run and its parsed events.
pub struct TracedRun {
    pub case: String,
    pub command: String,
    pub cwd: PathBuf,
    pub status: Option<ExitStatus>,
    pub stdout: String,
    pub stderr: String,
    pub trace_dir: PathBuf,
    /// Events in per-process order (files sorted by pid, lines in order).
    pub events: Vec<Event>,
    /// `(location, syscall name if recognizable, reason)` for lines that did not parse.
    pub unparsed: Vec<(String, String, String)>,
}

pub fn trace_root() -> PathBuf {
    std::env::var_os("SIGIL_SAFETY_TRACE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("safety-traces"))
}

fn probe_tracer() -> Result<String, String> {
    let version = Command::new("strace")
        .arg("-V")
        .output()
        .map_err(|e| format!("strace is not available ({e}); install it (e.g. `apt-get install strace`)"))?;
    let version = String::from_utf8_lossy(&version.stdout).lines().next().unwrap_or("").to_string();
    let probe = Command::new("strace")
        .args(["-f", "-qq", "-o", "/dev/null", "--", "/bin/true"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("strace failed to start: {e}"))?;
    if !probe.status.success() {
        return Err(format!(
            "strace cannot trace a child process here (ptrace restricted?): {}",
            String::from_utf8_lossy(&probe.stderr).trim()
        ));
    }
    Ok(version)
}

pub fn tracer() -> Result<&'static str, &'static str> {
    static STATUS: OnceLock<Result<String, String>> = OnceLock::new();
    match STATUS.get_or_init(probe_tracer) {
        Ok(v) => Ok(v.as_str()),
        Err(e) => Err(e.as_str()),
    }
}

/// `true` when the tracer is usable. Otherwise prints why the test is skipped and returns
/// `false`, or panics when `SIGIL_SAFETY_REQUIRED=1` (CI must never skip silently).
pub fn require_tracer(test: &str) -> bool {
    match tracer() {
        Ok(_) => true,
        Err(reason) => {
            if std::env::var("SIGIL_SAFETY_REQUIRED").as_deref() == Ok("1") {
                panic!("SIGIL_SAFETY_REQUIRED=1, but the syscall tracer is unusable: {reason}");
            }
            eprintln!("SKIPPED {test}: {reason} (set SIGIL_SAFETY_REQUIRED=1 to make this a failure)");
            false
        }
    }
}

/// Runs `program args` under strace with the contract filter. Traces and a `command.txt` with the
/// command line, working directory, exit status, stdout and stderr are kept in
/// `trace_root()/<case>/` (uploaded by CI on failure).
pub fn run_traced(case: &str, program: &Path, args: &[&OsStr], cwd: &Path, envs: &[(&str, &OsStr)]) -> TracedRun {
    let dir = trace_root().join(case);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create trace dir");
    let mut cmd = Command::new("strace");
    cmd.args(["-ff", "-yy", "-xx", "-qq", "-s", "256", "-e", "signal=none", "-e"])
        .arg(trace_expr())
        .arg("-o")
        .arg(dir.join("t"))
        .arg("--")
        .arg(program)
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let command = std::iter::once(program.as_os_str())
        .chain(args.iter().copied())
        .map(|a| a.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    let out = cmd.output().expect("strace should start");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let _ = fs::write(
        dir.join("command.txt"),
        format!("command: {command}\ncwd: {}\nstatus: {:?}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n", cwd.display(), out.status),
    );
    let mut run = load_dir(case, &dir);
    run.command = command;
    run.cwd = cwd.to_path_buf();
    run.status = Some(out.status);
    run.stdout = stdout;
    run.stderr = stderr;
    run
}

fn load_dir(case: &str, dir: &Path) -> TracedRun {
    let mut files: Vec<(u32, PathBuf)> = fs::read_dir(dir)
        .expect("read trace dir")
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.strip_prefix("t.").and_then(|p| p.parse().ok()).map(|pid| (pid, e.path()))
        })
        .collect();
    files.sort();
    let mut lines = Vec::new();
    for (pid, path) in files {
        let text = fs::read(&path).expect("read trace file");
        for line in String::from_utf8_lossy(&text).lines() {
            lines.push((pid, line.to_string()));
        }
    }
    let mut run = from_lines(case, &lines);
    run.trace_dir = dir.to_path_buf();
    run
}

/// Builds a run from `(pid, line)` pairs (used for real traces and for unit tests).
pub fn from_lines(case: &str, lines: &[(u32, String)]) -> TracedRun {
    let mut events = Vec::new();
    let mut unparsed = Vec::new();
    let mut counters: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    for (pid, line) in lines {
        let n = counters.entry(*pid).or_insert(0);
        *n += 1;
        let location = format!("t.{pid}:{n}");
        match parse_line(line) {
            Ok(Some((name, args, ret))) => events.push(Event { pid: *pid, location, name, args, ret, raw: line.clone() }),
            Ok(None) => {}
            Err(e) => {
                let name = line.split('(').next().unwrap_or("").trim().to_string();
                unparsed.push((location, name, format!("{e}: {line}")));
            }
        }
    }
    TracedRun {
        case: case.to_string(),
        command: String::new(),
        cwd: PathBuf::from("/"),
        status: None,
        stdout: String::new(),
        stderr: String::new(),
        trace_dir: PathBuf::new(),
        events,
        unparsed,
    }
}

/// One traced system call.
#[derive(Clone, Debug)]
pub struct Event {
    pub pid: u32,
    /// `t.<pid>:<line>` inside the trace directory.
    pub location: String,
    pub name: String,
    /// Top-level arguments, raw as strace printed them.
    pub args: Vec<String>,
    /// Raw return value, e.g. `3<\x2f...>`, `-1 ENOENT (No such file)`, `?`.
    pub ret: String,
    pub raw: String,
}

/// Scans `s` and splits it at top-level commas, respecting quoted strings, fd annotations
/// (`3<...>`, which may contain `->` inside `[...]`), `/* comments */` and `()`/`[]`/`{}` nesting.
/// With `stop_at_close`, scanning ends at the first unmatched `)` and its byte index is returned.
/// Byte ranges of the top-level parts, and the index of the closing `)` when requested.
type Scan = (Vec<(usize, usize)>, Option<usize>);

fn scan(s: &str, stop_at_close: bool) -> Result<Scan, String> {
    let b = s.as_bytes();
    let (mut depth, mut i, mut start) = (0usize, 0usize, 0usize);
    let mut parts = Vec::new();
    while i < b.len() {
        match b[i] {
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                if i >= b.len() {
                    return Err("unterminated string".into());
                }
            }
            b'<' if i > 0 && (b[i - 1].is_ascii_digit() || s[..i].ends_with("AT_FDCWD")) => {
                let mut brackets = 0usize;
                i += 1;
                while i < b.len() {
                    match b[i] {
                        b'[' => brackets += 1,
                        b']' => brackets = brackets.saturating_sub(1),
                        b'>' if brackets == 0 => break,
                        _ => {}
                    }
                    i += 1;
                }
                if i >= b.len() {
                    return Err("unterminated fd annotation".into());
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => match s[i + 2..].find("*/") {
                Some(k) => i += 2 + k + 1,
                None => return Err("unterminated comment".into()),
            },
            b'(' | b'[' | b'{' => depth += 1,
            b')' if depth == 0 && stop_at_close => {
                parts.push((start, i));
                return Ok((parts, Some(i)));
            }
            b')' | b']' | b'}' => {
                if depth == 0 {
                    return Err(format!("unbalanced '{}'", b[i] as char));
                }
                depth -= 1;
            }
            b',' if depth == 0 => {
                parts.push((start, i));
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if stop_at_close {
        return Err("no closing ')'".into());
    }
    parts.push((start, b.len()));
    Ok((parts, None))
}

/// Splits a strace line into syscall name, raw top-level arguments and raw return value.
/// Returns `Ok(None)` for informational lines (`+++ ...`, `--- ...`).
pub fn parse_line(line: &str) -> Result<Option<(String, Vec<String>, String)>, String> {
    let line = line.trim_end();
    if line.is_empty() || line.starts_with("+++") || line.starts_with("---") {
        return Ok(None);
    }
    let open = line.find('(').ok_or("no '('")?;
    let name = &line[..open];
    if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
        return Err(format!("bad syscall name {name:?}"));
    }
    let inner = &line[open + 1..];
    let (parts, close) = scan(inner, true)?;
    let close = close.expect("stop_at_close returns the index");
    let mut args: Vec<String> = parts.iter().map(|(a, z)| inner[*a..*z].trim().to_string()).collect();
    if args.len() == 1 && args[0].is_empty() {
        args.clear();
    }
    let rest = inner[close + 1..].trim_start();
    let ret = rest.strip_prefix('=').ok_or("no return value")?.trim().to_string();
    Ok(Some((name.to_string(), args, ret)))
}

/// Decodes a strace string body (`\xNN`, octal, and the usual C escapes).
pub fn unescape(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' || i + 1 >= b.len() {
            out.push(b[i]);
            i += 1;
            continue;
        }
        let c = b[i + 1];
        match c {
            b'x' if i + 4 <= b.len() => {
                let v = u8::from_str_radix(&s[i + 2..i + 4], 16).unwrap_or(b'?');
                out.push(v);
                i += 4;
            }
            b'0'..=b'7' => {
                let mut j = i + 1;
                let mut v: u32 = 0;
                while j < b.len() && j < i + 4 && (b'0'..=b'7').contains(&b[j]) {
                    v = v * 8 + u32::from(b[j] - b'0');
                    j += 1;
                }
                out.push(v as u8);
                i = j;
            }
            _ => {
                out.push(match c {
                    b'n' => b'\n',
                    b't' => b'\t',
                    b'r' => b'\r',
                    b'v' => 0x0b,
                    b'f' => 0x0c,
                    other => other,
                });
                i += 2;
            }
        }
    }
    out
}

fn bytes_to_path(v: Vec<u8>) -> PathBuf {
    use std::os::unix::ffi::OsStringExt;
    PathBuf::from(std::ffi::OsString::from_vec(v))
}

/// A quoted string argument (`"\x2f..."`, possibly followed by `...`).
pub fn str_arg(raw: &str) -> Option<PathBuf> {
    let raw = raw.trim();
    let body = raw.strip_prefix('"')?;
    let b = body.as_bytes();
    let mut i = 0;
    while i < b.len() && b[i] != b'"' {
        i += if b[i] == b'\\' { 2 } else { 1 };
    }
    Some(bytes_to_path(unescape(&body[..i.min(body.len())])))
}

/// The path annotation of an fd argument (`3<\x2f...>`, `AT_FDCWD<\x2f...>`), if it is a path.
pub fn fd_path(raw: &str) -> Option<PathBuf> {
    let raw = raw.trim();
    let open = raw.find('<')?;
    let inner = raw[open + 1..].strip_suffix('>')?;
    let mut bytes = unescape(inner);
    if !bytes.starts_with(b"/") {
        return None;
    }
    if bytes.ends_with(b" (deleted)") {
        bytes.truncate(bytes.len() - b" (deleted)".len());
    }
    Some(bytes_to_path(bytes))
}

/// A `name=value` field inside a struct argument (`{flags=O_WRONLY|O_CREAT, mode=0600}`) or a
/// `name=value` argument itself.
pub fn field<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
    let raw = raw.trim();
    let inner = raw.strip_prefix('{').and_then(|r| r.strip_suffix('}')).unwrap_or(raw);
    let (parts, _) = scan(inner, false).ok()?;
    parts.iter().map(|(a, z)| inner[*a..*z].trim()).find_map(|p| p.strip_prefix(name).and_then(|r| r.strip_prefix('=')))
}

pub fn flags(raw: &str) -> Vec<&str> {
    raw.split('|').map(str::trim).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> String {
        s.bytes().map(|b| format!("\\x{b:02x}")).collect()
    }

    #[test]
    fn parses_openat_with_hex_path_and_annotated_fds() {
        let line = format!(
            "openat(AT_FDCWD<{}>, \"{}\", O_RDONLY|O_CLOEXEC) = 3<{}>",
            hex("/work"),
            hex("/tmp/a b,\"c>.o"),
            hex("/tmp/a b,\"c>.o")
        );
        let (name, args, ret) = parse_line(&line).unwrap().unwrap();
        assert_eq!(name, "openat");
        assert_eq!(args.len(), 3);
        assert_eq!(fd_path(&args[0]), Some(PathBuf::from("/work")));
        assert_eq!(str_arg(&args[1]), Some(PathBuf::from("/tmp/a b,\"c>.o")));
        assert_eq!(flags(&args[2]), vec!["O_RDONLY", "O_CLOEXEC"]);
        assert_eq!(fd_path(&ret), Some(PathBuf::from("/tmp/a b,\"c>.o")));
    }

    #[test]
    fn parses_openat2_struct_flags() {
        let line = format!(
            "openat2(AT_FDCWD<{}>, \"{}\", {{flags=O_WRONLY|O_CREAT, mode=0600, resolve=0}}, 24) = -1 EACCES (Permission denied)",
            hex("/"),
            hex("x")
        );
        let (name, args, ret) = parse_line(&line).unwrap().unwrap();
        assert_eq!(name, "openat2");
        assert_eq!(field(&args[2], "flags"), Some("O_WRONLY|O_CREAT"));
        assert!(ret.starts_with("-1 EACCES"));
    }

    #[test]
    fn parses_mmap_fd_and_socket_annotations() {
        let line = format!(
            "mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE, 3<{}>, 0) = 0x7f0000000000",
            hex("/lib/x.so")
        );
        let (_, args, _) = parse_line(&line).unwrap().unwrap();
        assert_eq!(args.len(), 6);
        assert_eq!(fd_path(&args[4]), Some(PathBuf::from("/lib/x.so")));
        let line = "poll([{fd=0<UNIX-STREAM:[1->2]>, events=0}, {fd=1, events=0}], 2, 0) = 0 (Timeout)";
        let (_, args, _) = parse_line(line).unwrap().unwrap();
        assert_eq!(args.len(), 3);
        assert_eq!(fd_path("0<UNIX-STREAM:[1->2]>"), None);
    }

    #[test]
    fn parses_clone3_flags_comments_and_unknown_return() {
        let line = "clone3({flags=CLONE_VM|CLONE_THREAD|CLONE_SETTLS, exit_signal=0, stack=0x7f, stack_size=0x1000}, 88) = 1234";
        let (_, args, _) = parse_line(line).unwrap().unwrap();
        assert_eq!(field(&args[0], "flags"), Some("CLONE_VM|CLONE_THREAD|CLONE_SETTLS"));
        let line = "execve(\"\\x2f\\x62\", [\"\\x61\"...], 0x7ffe /* 12 vars */) = 0";
        let (_, args, ret) = parse_line(line).unwrap().unwrap();
        assert_eq!(args.len(), 3);
        assert_eq!(ret, "0");
        let (name, _, ret) = parse_line("exit_group(0)                           = ?").unwrap().unwrap();
        assert_eq!((name.as_str(), ret.as_str()), ("exit_group", "?"));
        assert!(parse_line("+++ exited with 0 +++").unwrap().is_none());
        assert!(parse_line("clone(child_stack=NULL, flags=CLONE_VM").is_err());
    }

    #[test]
    fn trace_expr_covers_rule_syscalls() {
        let expr = trace_expr();
        for s in RULE_SYSCALLS {
            assert!(expr.contains(&format!("?{s},")) || expr.ends_with(&format!("?{s}")), "{s} missing from {expr}");
        }
        for class in ["%process", "%network", "%file", "%desc"] {
            assert!(expr.contains(class));
        }
    }

    #[test]
    fn unescapes_hex_and_c_escapes() {
        assert_eq!(unescape("\\x2f\\x61"), b"/a".to_vec());
        assert_eq!(unescape("a\\nb\\\\c\\\"d"), b"a\nb\\c\"d".to_vec());
    }
}
