//! The systemd unit `--service-unit` names (PR-4d-1).
//!
//! The unit is read as a `binary inspect` input is (its path resolved, the file opened without
//! following and checked to be the file resolved), its one `ExecStart=` parsed ([`exec_start`]),
//! and the executable that names resolved to the installation it belongs to. Nothing else is
//! read: of the executable's path, only the metadata of its components (`canonicalize`,
//! `symlink_metadata`). The installation itself is walked by [`super::install::collect`].
//!
//! Every failure is an input error (exit 1): never a gap, never a guess. A `ServiceUnit` source
//! states what this file says at that line. Drop-ins are not read, so it is not the effective
//! command.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use sigil_model::{
    Artifact, ConfigRef, CoverageState, DiscoverySource, FileInstance, NotReadReason, RootId,
    ScanRoot, Stability, Unavailability, UntrustedText, INSTALL_ROOT, SERVICE_UNIT_ROOT,
};

use super::fs::{recorded, FsBudgets, ReadOutcome, ReadSpec, RelPath, RootError, SafeFs};
use super::install::InstallFacts;

/// `service_unit_bytes`'s default: systemd's line limit (1 MiB).
pub const DEFAULT_UNIT_BYTES: u64 = 1 << 20;
/// The unit's read limit, as `request.budgets` records it.
pub const SERVICE_UNIT_BYTES: &str = "service_unit_bytes";

/// What the unit gave. The CLI reads it before anything else and passes it to the engine
/// (`inspect::InstallSource::ServiceUnit`): `--out` is kept out of `dir` and `prefix` by the
/// `dev:ino` these reads saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitFacts {
    /// The path as given, for messages.
    pub given: PathBuf,
    /// The read limit (`service_unit_bytes`).
    pub limit: u64,
    /// The unit's canonical directory, and its `dev:ino` as the read opened it.
    pub dir: PathBuf,
    pub dir_id: (u64, u64),
    /// `service-unit`, at the unit's canonical path (as a binary input's root is).
    pub root: ScanRoot,
    /// `inst:service-unit/<name>`, discovered by `Argument`, read.
    pub instance: FileInstance,
    /// Its contents (`Format::Other`).
    pub artifact: Artifact,
    /// `ExecStart` at the line of the one assignment that remains.
    pub config: ConfigRef,
    /// The executable `ExecStart=` names, resolved: `<prefix>/bin/ollama`.
    pub exe: PathBuf,
    /// The installation's prefix, and its `dev:ino`, taken right after it was resolved.
    pub prefix: PathBuf,
    pub prefix_id: (u64, u64),
    /// The resolved executable's `dev:ino`, taken right after it was resolved.
    pub exe_id: (u64, u64),
}

/// Reads the unit at `path`, at most `limit` bytes, and resolves the executable its
/// `ExecStart=` names. `Err` is the input error of exit 1: `--service-unit <path>: <why>`.
pub fn collect(path: &Path, limit: u64) -> Result<UnitFacts, String> {
    collect_with(path, limit, &|_| {}, &|_| {}, &|_| {})
}

fn shown(path: &Path) -> String {
    UntrustedText::from_bytes(path.as_os_str().as_bytes()).terminal_line()
}

/// `--service-unit <path>: <why>`, the path escaped for a terminal line. `why` holds no
/// untrusted bytes, or holds them escaped already.
fn fatal(path: &Path, why: &str) -> String {
    format!("--service-unit {}: {why}", shown(path))
}

/// Why `canonicalize` or `symlink_metadata` failed.
fn io_why(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::NotFound => "not found".to_string(),
        std::io::ErrorKind::PermissionDenied => "permission denied".to_string(),
        _ => e.to_string(),
    }
}

/// As [`collect`], calling `after_resolve` with the unit's canonical path right after it was
/// resolved, `before_open` with it before its directory is opened, and `during_read` while the
/// file is open: the tests' ways to change it.
fn collect_with(
    path: &Path,
    limit: u64,
    after_resolve: &dyn Fn(&Path),
    before_open: &dyn Fn(&Path),
    during_read: &dyn Fn(&RelPath),
) -> Result<UnitFacts, String> {
    let fail = |why: &str| fatal(path, why);
    let canonical = std::fs::canonicalize(path).map_err(|e| fail(&io_why(&e)))?;
    after_resolve(&canonical);
    let resolved = std::fs::symlink_metadata(&canonical)
        .map(|st| (st.dev(), st.ino()))
        .map_err(|e| fail(&io_why(&e)))?;
    let (Some(parent), Some(name)) = (canonical.parent(), canonical.file_name()) else {
        return Err(fail("not a file"));
    };
    let dir_id = std::fs::symlink_metadata(parent)
        .map(|st| (st.dev(), st.ino()))
        .map_err(|e| fail(&format!("its directory: {}", io_why(&e))))?;
    let name = name
        .to_str()
        .ok_or_else(|| fail("the file name is not UTF-8"))?;
    let rel = RelPath::parse(name).map_err(|e| fail(&e.to_string()))?;
    let root = RootId::new(SERVICE_UNIT_ROOT).map_err(|e| format!("internal error: {e}"))?;
    let keep = usize::try_from(limit).map_err(|_| fail("service_unit_bytes is too large"))?;
    before_open(&canonical);
    let mut fs = SafeFs::new(FsBudgets::default());
    fs.add_unlisted_root(root.clone(), parent).map_err(|e| {
        let why = match e {
            RootError::NotFound => "not found".to_string(),
            RootError::PermissionDenied => "permission denied".to_string(),
            RootError::NotADirectory => "not a directory".to_string(),
            RootError::Duplicate => "named twice".to_string(),
            RootError::Failed(m) => m,
        };
        fail(&format!("its directory: {why}"))
    })?;
    // The directory opened must be the one resolved. The path catches a symlink swapped into an
    // ancestor after `canonicalize`: the root is opened from `/` without following links, so it
    // would be a directory the path does not name. `dev:ino` catches a directory replaced at the
    // same path, and it is the identity the CLI keeps `--out` away from.
    if fs.root_path(&root) != Some(parent) || fs.root_id(&root) != Some(dir_id) {
        return Err(fail("its directory changed after it was resolved"));
    }
    let (read, _) = fs.read_entry_with(
        &root,
        &rel,
        ReadSpec {
            keep,
            limit: Some(limit),
        },
        vec![DiscoverySource::Argument],
        |_| during_read(&rel),
    );
    // A file replaced after it was resolved is not the unit: it is said first, whatever it
    // turned out to be.
    let replaced = read
        .instance
        .as_ref()
        .is_some_and(|i| (i.stat.dev, i.stat.ino) != resolved);
    match &read.outcome {
        ReadOutcome::Complete | ReadOutcome::LimitExceeded { .. } if replaced => {
            return Err(fail("replaced by another file after it was resolved"));
        }
        ReadOutcome::Complete => {}
        ReadOutcome::LimitExceeded { limit, size } => {
            return Err(fail(&format!(
                "over {SERVICE_UNIT_BYTES} ({size} bytes; the limit is {limit})"
            )))
        }
        ReadOutcome::NotFound => return Err(fail("vanished after it was resolved")),
        ReadOutcome::NotRead(why) => {
            let mode = read.instance.as_ref().map_or(0, |i| i.stat.mode) & 0o170_000;
            let what = match why {
                NotReadReason::NotRegularFile if mode == 0o040_000 => "a directory".to_string(),
                // Swapped in after the argument was resolved: never followed.
                NotReadReason::NotRegularFile if mode == 0o120_000 => {
                    "a symlink now, not followed".to_string()
                }
                NotReadReason::NotRegularFile => "not a regular file".to_string(),
                NotReadReason::PermissionDenied => "permission denied".to_string(),
                NotReadReason::Vanished => "vanished before it was read".to_string(),
                other => format!("{other:?}"),
            };
            return Err(fail(&what));
        }
        // It may carry the raw file name.
        ReadOutcome::Failed(m) => return Err(fail(&UntrustedText::new(m).terminal_line())),
    }
    let (Some(instance), Some(artifact)) = (read.instance, read.artifact) else {
        return Err(fail("not read"));
    };
    match instance.stability {
        Stability::NoChangeDetected => {}
        Stability::ChangedDuringRead => return Err(fail("changed during the read")),
        Stability::Vanished => return Err(fail("vanished during the read")),
    }
    let (named, line) = exec_start(&read.prefix).map_err(|why| fail(&why))?;
    let at = format!("ExecStart= at line {line}");
    let named = Path::new(OsStr::from_bytes(&named));
    let exe = std::fs::canonicalize(named)
        .map_err(|e| fail(&format!("{at} names {}: {}", shown(named), io_why(&e))))?;
    let st = std::fs::symlink_metadata(&exe)
        .map_err(|e| fail(&format!("{at} names {}: {}", shown(&exe), io_why(&e))))?;
    if !st.is_file() {
        return Err(fail(&format!(
            "{at} names {}, which is not a regular file",
            shown(&exe)
        )));
    }
    let prefix = prefix_of(&exe).ok_or_else(|| {
        fail(&format!(
            "{at} names {}, which is not <prefix>/bin/ollama",
            shown(&exe)
        ))
    })?;
    let prefix_id = std::fs::symlink_metadata(&prefix)
        .map(|st| (st.dev(), st.ino()))
        .map_err(|e| {
            fail(&format!(
                "{at}: its prefix {}: {}",
                shown(&prefix),
                io_why(&e)
            ))
        })?;
    let config = ConfigRef {
        file: instance.id.clone(),
        key: UntrustedText::new("ExecStart"),
        line,
    };
    Ok(UnitFacts {
        given: path.to_path_buf(),
        limit,
        dir: parent.to_path_buf(),
        dir_id,
        root: ScanRoot {
            id: root,
            path: recorded(&canonical),
        },
        instance,
        artifact,
        config,
        exe,
        prefix,
        prefix_id,
        exe_id: (st.dev(), st.ino()),
    })
}

/// The installation prefix of a resolved executable `<prefix>/bin/ollama` (Ollama's bundle
/// search starts at `<exe>/../lib/ollama`), or `None` in any other layout. `/bin/ollama` has no
/// prefix to walk: `None`.
fn prefix_of(exe: &Path) -> Option<PathBuf> {
    let rest = exe.as_os_str().as_bytes().strip_suffix(b"/bin/ollama")?;
    (!rest.is_empty()).then(|| PathBuf::from(OsStr::from_bytes(rest)))
}

/// Adds the unit's source to the installation's `bin/ollama`, in the facts of the walk of its
/// prefix. The walk's root must be the prefix resolved, by `dev:ino` (`root_id`, the directory
/// it opened) and by path (`root_path`, where it opened it: the walk's placements are under it),
/// and its placement of the `install` root at the resolved executable's path must be the file
/// resolved (`dev:ino`). `Err` is the input error, and it names the cause the walk recorded: the
/// installation could not be opened (no `root_id`; the walk's coverage state says why), was
/// replaced or moved after it was resolved, its executable was replaced, or the walk did not
/// record the executable (`bin_gap`: a gap, an error, or the files budget). The facts are
/// untouched on every `Err`.
pub fn attach(unit: &UnitFacts, walk: &mut InstallFacts) -> Result<(), String> {
    let given = unit.given.as_path();
    let prefix = shown(&unit.prefix);
    match walk.root_id {
        Some(id) if id == unit.prefix_id => {}
        Some(_) => {
            return Err(fatal(
                given,
                &format!("the installation {prefix} was replaced after it was resolved"),
            ))
        }
        None => {
            let why = match &walk.discovery.state {
                CoverageState::Unavailable {
                    why: Unavailability::PermissionDenied,
                } => "permission denied".to_string(),
                CoverageState::Unavailable {
                    why: Unavailability::NotFound,
                } => "not found".to_string(),
                CoverageState::Error { message } => message.terminal_line(),
                _ => "it was not opened".to_string(),
            };
            return Err(fatal(
                given,
                &format!("the installation {prefix} could not be opened: {why}"),
            ));
        }
    }
    // The same directory at another path: the prefix was moved after it was resolved (a link
    // left in its place leads the walk there). Its placements are not at the executable's path.
    if walk.root_path.as_bytes() != unit.prefix.as_os_str().as_bytes() {
        return Err(fatal(
            given,
            &format!(
                "the installation {prefix} was moved after it was resolved (the walk opened {})",
                walk.root_path.terminal_line()
            ),
        ));
    }
    let path = unit.exe.as_os_str().as_bytes();
    let found = walk
        .instances
        .iter_mut()
        .find(|i| i.root.as_str() == INSTALL_ROOT && i.path.as_bytes() == path);
    match found {
        Some(i) if (i.stat.dev, i.stat.ino) == unit.exe_id => {
            i.discovered_by.push(DiscoverySource::ServiceUnit {
                config: unit.config.clone(),
            });
            Ok(())
        }
        Some(_) => Err(fatal(
            given,
            &format!("{} was replaced after it was resolved", shown(&unit.exe)),
        )),
        None => Err(fatal(
            given,
            &format!(
                "{} was not recorded by the installation's walk ({})",
                shown(&unit.exe),
                walk.bin_gap.as_deref().map_or_else(
                    || "it recorded no reason".to_string(),
                    |gap| UntrustedText::new(gap).terminal_line()
                )
            ),
        )),
    }
}

/// systemd's `WHITESPACE`: what is trimmed from a line and separates items.
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if !is_space(*first) {
            break;
        }
        s = rest;
    }
    while let [rest @ .., last] = s {
        if !is_space(*last) {
            break;
        }
        s = rest;
    }
    s
}

/// A line systemd skips: empty, or a comment (`#`, `;`).
fn skipped(line: &[u8]) -> bool {
    matches!(line.first(), None | Some(b'#' | b';'))
}

/// Settings of `[Service]` that make the service's paths lead elsewhere than the host's
/// (systemd.exec(5)): with one set, `ExecStart=`'s path may name another file than the one SIGIL
/// would resolve. Settings that only hide a path (`ProtectHome=`, `InaccessiblePaths=`,
/// `NoExecPaths=`) make the service fail to start rather than run another file, and are not
/// listed. `PrivateTmp=` (implied by `DynamicUser=`) is not listed either: it gives the service an
/// empty `/tmp` and `/var/tmp` of its own, so an executable there is not the host's file. Like a
/// file an `ExecStartPre=` may replace, this is not modeled.
pub const REDIRECTS: &[&str] = &[
    "RootDirectory",
    "RootImage",
    "RootMStack",
    "BindPaths",
    "BindReadOnlyPaths",
    "TemporaryFileSystem",
    "MountImages",
    "ExtensionImages",
    "ExtensionDirectories",
];

/// The executable of the one `ExecStart=` of `[Service]`, and the line its assignment starts on
/// (from 1). `Err` says why the unit is outside the modeled subset of systemd.syntax(7) and
/// systemd.service(5) "COMMAND LINES" (systemd 261):
/// - the unit is UTF-8 with no NUL, byte-order mark, or noncharacter;
/// - lines are split at `\n` and trimmed of systemd's whitespace (space, tab, CR, LF); a CR is
///   allowed only as the last byte of a line (systemd ends a line at a lone CR); empty and
///   comment (`#`, `;`) lines are skipped; a line ending in `\` is not modeled (systemd's
///   continuation rules are not emulated);
/// - only `[Service]` is read; a section header without `]` or with a quote, a backslash, or a
///   control byte in its name, and a line without `=` in `[Service]`, are outside the subset;
/// - `ExecStart` assignments apply in order, an empty one clearing the list; exactly one must
///   remain;
/// - its first item is unquoted (a whole `"…"` or `'…'` item, or up to whitespace; no other
///   quote), then the prefixes `@-:+!` are removed, each at most once; `+` with `!`, `@` without
///   a following item, and `|` (a shell) are outside the subset;
/// - the arguments after it have no quote, backslash, or `%`, and no word that is exactly `;` (a
///   second command);
/// - what remains of the first item is an absolute path with no `\`, `%`, `$`, or control byte,
///   not ending in `/` or `/.`;
/// - a [`REDIRECTS`] setting still set at the end is outside the subset: it changes where the
///   service's paths lead.
///
/// It is an explicitly limited subset, not a systemd-compatible parser: what it does not model
/// is refused, even where systemd accepts it.
///
/// SIGIL does not check that systemd would load the unit: another fatal setting (e.g. a relative
/// `WorkingDirectory=`) makes systemd run nothing while this returns the path.
pub fn exec_start(text: &[u8]) -> Result<(Vec<u8>, u32), String> {
    if text.contains(&0) {
        return Err("a NUL byte".to_string());
    }
    let Ok(utf8) = std::str::from_utf8(text) else {
        return Err("the unit is not UTF-8".to_string());
    };
    if utf8
        .chars()
        .any(|c| matches!(c as u32, 0xFDD0..=0xFDEF) || (c as u32) & 0xFFFE == 0xFFFE)
    {
        return Err("the unit is not UTF-8 clean (a noncharacter)".to_string());
    }
    if text.windows(3).any(|w| w == [0xEF, 0xBB, 0xBF]) {
        return Err("a byte-order mark".to_string());
    }
    let mut in_service = false;
    let mut assigned: Vec<(Vec<u8>, u32)> = vec![];
    // The line of the last assignment of each `REDIRECTS` setting still set, indexed like it.
    let mut redirects = [None::<u32>; REDIRECTS.len()];
    for (raw, number) in text.split(|&b| b == b'\n').zip(1u32..) {
        if raw[..raw.len().saturating_sub(1)].contains(&b'\r') {
            return Err(format!("line {number}: a carriage return inside a line"));
        }
        let line = trim(raw);
        if skipped(line) {
            continue;
        }
        if line.last() == Some(&b'\\') {
            return Err(format!(
                "line {number}: a continuation (`\\` at the end of a line) is not modeled"
            ));
        }
        if line[0] == b'[' {
            if line.last() != Some(&b']') {
                return Err(format!("line {number}: a section header without `]`"));
            }
            let name = &line[1..line.len() - 1];
            if name
                .iter()
                .any(|&b| matches!(b, b'"' | b'\'' | b'\\' | 0..=0x1f | 0x7f))
            {
                return Err(format!("line {number}: an invalid section name"));
            }
            in_service = name == b"Service";
            continue;
        }
        if !in_service {
            continue;
        }
        let Some(eq) = line.iter().position(|&b| b == b'=') else {
            return Err(format!("line {number}: an entry without `=` in [Service]"));
        };
        let key = trim(&line[..eq]);
        let value = trim(&line[eq + 1..]);
        if let Some(i) = REDIRECTS.iter().position(|k| k.as_bytes() == key) {
            redirects[i] = if value.is_empty() { None } else { Some(number) };
            continue;
        }
        if key != b"ExecStart" {
            continue;
        }
        if value.is_empty() {
            assigned.clear();
        } else {
            assigned.push((value.to_vec(), number));
        }
    }
    let earliest = redirects
        .iter()
        .enumerate()
        .filter_map(|(i, at)| at.map(|at| (at, REDIRECTS[i])))
        .min();
    if let Some((at, name)) = earliest {
        return Err(format!(
            "line {at}: {name}= changes where the service's paths lead (not modeled)"
        ));
    }
    let (value, line) = match assigned.len() {
        0 => return Err("no ExecStart= in [Service]".to_string()),
        1 => assigned.remove(0),
        n => {
            let at: Vec<String> = assigned.iter().map(|(_, n)| n.to_string()).collect();
            return Err(format!(
                "{n} ExecStart= commands (lines {}); one is modeled",
                at.join(", ")
            ));
        }
    };
    let at = |why: &str| format!("ExecStart= at line {line}: {why}");
    let (item, rest) = first_item(&value).map_err(at)?;
    let (exe, argv0) = strip_prefixes(item).map_err(at)?;
    if rest
        .iter()
        .any(|&b| matches!(b, b'"' | b'\'' | b'\\' | b'%'))
    {
        return Err(at(
            "a quote, backslash, or specifier in the arguments (not modeled)",
        ));
    }
    if rest.split(|&b| is_space(b)).any(|w| w == b";") {
        return Err(at("a `;` argument (a second command)"));
    }
    if argv0 && rest.is_empty() {
        return Err(at("`@` without the argv[0] it passes"));
    }
    if exe.is_empty() {
        return Err(at("no command"));
    }
    let special = exe.iter().find_map(|&b| match b {
        b'\\' => Some("an escape (`\\`)"),
        b'%' => Some("a specifier (`%`)"),
        b'$' => Some("a variable (`$`)"),
        0..=0x1f | 0x7f => Some("a control character"),
        _ => None,
    });
    if let Some(why) = special {
        return Err(at(why));
    }
    if exe[0] != b'/' {
        return Err(at(
            "a relative command (systemd's search path is not modeled)",
        ));
    }
    if exe.ends_with(b"/") || exe.ends_with(b"/.") {
        return Err(at("a directory path"));
    }
    Ok((exe.to_vec(), line))
}

/// The first item of a command line, unquoted, and the rest of the line, trimmed: a whole
/// `"…"` or `'…'` item, or the bytes up to whitespace. A quote anywhere else in the item is
/// outside the subset (systemd.syntax(7) "Quoting").
fn first_item(value: &[u8]) -> Result<(&[u8], &[u8]), &'static str> {
    let (item, rest) = match value.first() {
        Some(&quote @ (b'"' | b'\'')) => {
            let inner = &value[1..];
            let end = inner
                .iter()
                .position(|&b| b == quote)
                .ok_or("an unterminated quote")?;
            if inner.get(end + 1).is_some_and(|&b| !is_space(b)) {
                return Err("a quote inside an item");
            }
            (&inner[..end], &inner[end + 1..])
        }
        _ => {
            let end = value
                .iter()
                .position(|&b| is_space(b))
                .unwrap_or(value.len());
            (&value[..end], &value[end..])
        }
    };
    if item.iter().any(|&b| b == b'"' || b == b'\'') {
        return Err("a quote inside an item");
    }
    Ok((item, trim(rest)))
}

/// An item without systemd's executable prefixes (`@`, `-`, `:`, `+`, `!`, in any order, each at
/// most once), and whether `@` was among them. `+` with `!` is invalid (systemd.service(5)), and
/// `|` runs the command through a shell: both outside the subset.
fn strip_prefixes(mut item: &[u8]) -> Result<(&[u8], bool), &'static str> {
    let mut seen: Vec<u8> = vec![];
    while let [first, rest @ ..] = item {
        match first {
            b'@' | b'-' | b':' | b'+' | b'!' => {
                if seen.contains(first) {
                    return Err("a repeated prefix");
                }
                seen.push(*first);
                item = rest;
            }
            b'|' => return Err("a command run through a shell (`|`)"),
            _ => break,
        }
    }
    if seen.contains(&b'+') && seen.contains(&b'!') {
        return Err("`+` and `!` together");
    }
    Ok((item, seen.contains(&b'@')))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> (String, u32) {
        let (exe, line) = exec_start(text.as_bytes()).unwrap_or_else(|e| panic!("{text:?}: {e}"));
        (String::from_utf8(exe).unwrap(), line)
    }

    fn err(text: &str) -> String {
        exec_start(text.as_bytes()).expect_err(text)
    }

    /// The R-1 machine's `/etc/systemd/system/ollama.service`, its `Environment=` value replaced.
    const R1: &str = "[Unit]\nDescription=Ollama Service\nAfter=network-online.target\n\n\
                      [Service]\nExecStart=/usr/local/bin/ollama serve\nUser=ollama\n\
                      Group=ollama\nRestart=always\nRestartSec=3\n\
                      Environment=\"PATH=/usr/local/bin\"\n\n[Install]\n\
                      WantedBy=default.target\n";

    #[test]
    fn the_r1_unit() {
        assert_eq!(ok(R1), ("/usr/local/bin/ollama".to_string(), 6));
    }

    #[test]
    fn lines_comments_sections_and_reset() {
        let cases = [
            ("[Service]\nExecStart=/a/bin/ollama\n", 2),
            (
                "# c\n; c\n\n[Service]\n  ExecStart =  /a/bin/ollama serve  \n",
                5,
            ),
            (
                "[Unit]\nExecStart=/no\n[Service]\nExecStart=/a/bin/ollama\n",
                4,
            ),
            ("ExecStart=/no\n[Service]\nExecStart=/a/bin/ollama\n", 3),
            ("[Service]\r\nExecStart=/a/bin/ollama serve\r\n", 2),
            ("[Service]\n; ExecStart=/no\nExecStart=/a/bin/ollama\n", 3),
            ("[Service]\nExecStart=\t/a/bin/ollama\tserve\n", 2),
            ("[Service]\nExecStart=/a/bin/ollama\r", 2),
            (
                "[Service]\n# a comment ending in \\\nExecStart=/a/bin/ollama\n",
                3,
            ),
            (
                "[Service]\nExecStart=/no\nExecStart=\nExecStart=/a/bin/ollama\n",
                4,
            ),
            ("[Service]\nExecStartPre=/no\nExecStart=/a/bin/ollama\n", 3),
            (
                "[ Service ]\nExecStart=/no\n[Service]\nExecStart=/a/bin/ollama\n",
                4,
            ),
            // A setting that would change where paths lead, cleared before the end.
            (
                "[Service]\nRootDirectory=/srv\nRootDirectory=\nExecStart=/a/bin/ollama\n",
                4,
            ),
            (
                "[Unit]\nRootDirectory=/srv\n[Service]\nExecStart=/a/bin/ollama\n",
                4,
            ),
        ];
        for (text, line) in cases {
            assert_eq!(ok(text), ("/a/bin/ollama".to_string(), line), "{text:?}");
        }
    }

    #[test]
    fn quoting_and_prefixes() {
        let cases = [
            (
                "[Service]\nExecStart=\"/a b/bin/ollama\" serve\n",
                "/a b/bin/ollama",
            ),
            ("[Service]\nExecStart='/a/bin/ollama'\n", "/a/bin/ollama"),
            ("[Service]\nExecStart=-/a/bin/ollama\n", "/a/bin/ollama"),
            (
                "[Service]\nExecStart=@/a/bin/ollama ollama serve\n",
                "/a/bin/ollama",
            ),
            (
                "[Service]\nExecStart=+:-@/a/bin/ollama ollama\n",
                "/a/bin/ollama",
            ),
            ("[Service]\nExecStart=!-/a/bin/ollama\n", "/a/bin/ollama"),
            ("[Service]\nExecStart=\"-/a/bin/ollama\"\n", "/a/bin/ollama"),
            (
                "[Service]\nExecStart=/a/bin/ollama a;b ;x\n",
                "/a/bin/ollama",
            ),
        ];
        for (text, exe) in cases {
            assert_eq!(ok(text).0, exe, "{text:?}");
        }
    }

    #[test]
    fn not_utf8() {
        let e = exec_start(b"[Service]\nExecStart=/a/bin/ollama\xff\n").unwrap_err();
        assert_eq!(e, "the unit is not UTF-8");
        let e = exec_start(b"[Service]\nExecStart=/a/bin/ollama\xff\0\n").unwrap_err();
        assert_eq!(e, "a NUL byte");
    }

    #[test]
    fn outside_the_subset() {
        let cases = [
            ("[Service]\nUser=x\n", "no ExecStart= in [Service]"),
            (
                "[Service]\nExecStart=/a\nExecStart=/b\n",
                "2 ExecStart= commands (lines 2, 3)",
            ),
            (
                "[Service]\nExecStart=/a\nExecStart=\n",
                "no ExecStart= in [Service]",
            ),
            (
                "[Service]\nExecStart=ollama serve\n",
                "at line 2: a relative command",
            ),
            (
                "[Service]\nExecStart=|/a/bin/ollama\n",
                "a command run through a shell",
            ),
            ("[Service]\nExecStart=/a/bin/olla\\x6da\n", "an escape"),
            ("[Service]\nExecStart=/a/%i/bin/ollama\n", "a specifier"),
            ("[Service]\nExecStart=${BIN}/bin/ollama\n", "a variable"),
            (
                "[Service]\nExecStart=\"/a/bin/ollama\n",
                "an unterminated quote",
            ),
            ("[Service]\nExecStart=\"/a\"b\n", "a quote inside an item"),
            (
                "[Service]\nExecStart=-\"/a/bin/ollama\"\n",
                "a quote inside an item",
            ),
            (
                "[Service]\nExecStart=\"/a\tb/bin/ollama\"\n",
                "a control character",
            ),
            ("[Service]\nExecStart=@ ollama\n", "no command"),
            // Prefixes invalid for systemd 261 (systemd.service(5)): `+` with `!`, a repeated
            // one, `@` without the argv[0] it passes (external plan review, P2).
            (
                "[Service]\nExecStart=+!:/a/bin/ollama\n",
                "`+` and `!` together",
            ),
            (
                "[Service]\nExecStart=--/a/bin/ollama\n",
                "a repeated prefix",
            ),
            (
                "[Service]\nExecStart=@/a/bin/ollama\n",
                "`@` without the argv[0]",
            ),
            // Settings of the unit that change where its paths lead (external plan review, P2).
            (
                "[Service]\nRootDirectory=/srv/tenant\nExecStart=/a/bin/ollama\n",
                "line 2: RootDirectory= changes where the service's paths lead",
            ),
            (
                "[Service]\nExecStart=/a/bin/ollama\nRootImage=/x.raw\n",
                "line 3: RootImage=",
            ),
            (
                "[Service]\nBindPaths=/a:/b\nExecStart=/a/bin/ollama\n",
                "BindPaths=",
            ),
            (
                "[Service]\nBindReadOnlyPaths=/a\nExecStart=/a/bin/ollama\n",
                "BindReadOnlyPaths=",
            ),
            (
                "[Service]\nTemporaryFileSystem=/a\nExecStart=/a/bin/ollama\n",
                "TemporaryFileSystem=",
            ),
            (
                "[Service]\nMountImages=/x.raw:/a\nExecStart=/a/bin/ollama\n",
                "MountImages=",
            ),
            (
                "[Service]\nExtensionImages=/x.raw\nExecStart=/a/bin/ollama\n",
                "ExtensionImages=",
            ),
            (
                "[Service]\nExtensionDirectories=/x\nExecStart=/a/bin/ollama\n",
                "ExtensionDirectories=",
            ),
            // An explicitly limited subset: systemd accepts this one (external plan review, P3).
            (
                "[Service]\nExecStart=-\"/usr/local/bin/ollama\"\n",
                "a quote inside an item",
            ),
            ("[Service]\nnot an entry\n", "line 2: an entry without `=`"),
            (
                "[Service\nExecStart=/a/bin/ollama\n",
                "line 1: a section header without `]`",
            ),
            ("[Service]\nExecStart=/a/bin/ollama\0\n", "a NUL byte"),
            (
                "[Service]\nExecStart=/a/bin/ol\x7flama\n",
                "a control character",
            ),
            (
                "[Service]\nExecStart=\"/a'b/ollama\"\n",
                "a quote inside an item",
            ),
            (
                "\u{feff}[Service]\nExecStart=/a/bin/ollama\n",
                "a byte-order mark",
            ),
            (
                "[Service]\nExecStart=/a/bin/ollama\n# \u{feff}\n",
                "a byte-order mark",
            ),
            (
                "[Service]\nExecStart=/a/bin/ol\rlama\n",
                "line 2: a carriage return inside a line",
            ),
            (
                "[Service]\nExecStart=\\\n# skipped\n\n  /a/bin/ollama serve\n",
                "line 2: a continuation (`\\` at the end of a line) is not modeled",
            ),
            (
                "[Service]\nEnvironment=A=\\\\\nExecStart=/a/bin/ollama\n",
                "line 2: a continuation",
            ),
            (
                "[Service]\nEnvironment=A=\\ \nRootDirectory=/srv/x\nExecStart=/a/bin/ollama\n",
                "line 2: a continuation",
            ),
            (
                "[Ser\"vice]\nExecStart=/a/bin/ollama\n",
                "line 1: an invalid section name",
            ),
            (
                "[Ser'vice]\nExecStart=/a/bin/ollama\n",
                "line 1: an invalid section name",
            ),
            (
                "[Ser\\vice]\nExecStart=/a/bin/ollama\n",
                "line 1: an invalid section name",
            ),
            (
                "[Ser\x7fvice]\nExecStart=/a/bin/ollama\n",
                "line 1: an invalid section name",
            ),
            (
                "[Service]\nExecStart=/a/bin/ollama a\u{fffe}b\n",
                "the unit is not UTF-8 clean (a noncharacter)",
            ),
            (
                "[Unit]\nDescription=x\u{10ffff}\n[Service]\nExecStart=/a/bin/ollama\n",
                "the unit is not UTF-8 clean (a noncharacter)",
            ),
            (
                "[Service]\nExecStart=/a/bin/ollama a\u{fdd0}\n",
                "the unit is not UTF-8 clean (a noncharacter)",
            ),
            (
                "[Service]\nExecStart=/a/bin/ollama %Z\n",
                "at line 2: a quote, backslash, or specifier in the arguments",
            ),
            (
                "[Service]\nExecStart=/a/bin/ollama/\n",
                "at line 2: a directory path",
            ),
            (
                "[Service]\nExecStart=/a/bin/.\n",
                "at line 2: a directory path",
            ),
            (
                "[Ser\x01vice]\nExecStart=/a/bin/ollama\n",
                "line 1: an invalid section name",
            ),
            (
                "[Service]\nRootMStack=/x\nExecStart=/a/bin/ollama\n",
                "line 2: RootMStack= changes where",
            ),
            (
                "[Service]\nRootImage=/x.raw\nBindPaths=/a:/b\nExecStart=/a/bin/ollama\n",
                "line 2: RootImage=",
            ),
            (
                "[Service]\nBindPaths=/a:/b\nRootImage=/x.raw\nExecStart=/a/bin/ollama\n",
                "line 2: BindPaths=",
            ),
            (
                "[Service]\nExecStart=/a/bin/ollama \"serve\n",
                "at line 2: a quote, backslash, or specifier in the arguments",
            ),
            (
                "[Service]\nExecStart=/a/bin/ollama 'serve'\n",
                "a quote, backslash, or specifier in the arguments",
            ),
            (
                "[Service]\nExecStart=/a/bin/ollama a\\x20b\n",
                "a quote, backslash, or specifier in the arguments",
            ),
            (
                "[Service]\nExecStart=/a/bin/ollama serve \\;\n",
                "a quote, backslash, or specifier in the arguments",
            ),
            (
                "[Service]\nExecStart=/a/bin/ollama serve ; /b/bin/x\n",
                "at line 2: a `;` argument (a second command)",
            ),
        ];
        for (text, why) in cases {
            let e = err(text);
            assert!(e.contains(why), "{text:?}: {e}");
        }
    }

    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{symlink, MetadataExt};
    use std::path::{Path, PathBuf};

    use sigil_model::{
        ConfigRef, DiscoverySource, FileInstance, Format, InstanceContent, InstanceId,
        NotReadReason, RootId, Stability, StatInfo, UntrustedText, INSTALL_ROOT, SERVICE_UNIT_ROOT,
    };

    use sigil_model::{CheckId, Coverage, Ref, ARTIFACTS_DISCOVERY};

    use crate::collect::fs::recorded;

    /// `inst/bin/ollama` under a canonical temporary directory.
    fn tree() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::TempDir::new().unwrap();
        let p = std::fs::canonicalize(d.path()).unwrap();
        std::fs::create_dir_all(p.join("inst/bin")).unwrap();
        std::fs::write(p.join("inst/bin/ollama"), b"exe").unwrap();
        (d, p)
    }

    /// `ollama.service` in `dir`, whose `ExecStart=` (line 2) runs `exe serve`.
    fn unit(dir: &Path, exe: &Path) -> PathBuf {
        let path = dir.join("ollama.service");
        let mut text = b"[Service]\nExecStart=".to_vec();
        text.extend_from_slice(exe.as_os_str().as_bytes());
        text.extend_from_slice(b" serve\n");
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn a_unit_gives_its_executable_and_the_prefix() {
        let (_d, p) = tree();
        let u = unit(&p, &p.join("inst/bin/ollama"));
        let f = collect(&u, DEFAULT_UNIT_BYTES).unwrap();
        assert_eq!(f.root.id.as_str(), SERVICE_UNIT_ROOT);
        assert_eq!(f.root.path.as_bytes(), u.as_os_str().as_bytes());
        assert_eq!(f.instance.id.as_str(), "inst:service-unit/ollama.service");
        assert_eq!(f.instance.discovered_by, vec![DiscoverySource::Argument]);
        assert!(matches!(f.instance.content, InstanceContent::Read { .. }));
        assert_eq!(f.artifact.format, Format::Other);
        assert_eq!(
            f.config,
            ConfigRef {
                file: f.instance.id.clone(),
                key: UntrustedText::new("ExecStart"),
                line: 2,
            }
        );
        assert_eq!(f.exe, p.join("inst/bin/ollama"));
        assert_eq!(f.prefix, p.join("inst"));
        assert_eq!(
            (f.given.as_path(), f.limit),
            (u.as_path(), DEFAULT_UNIT_BYTES)
        );
        assert_eq!(f.dir, p);
        let id = |path: &Path| {
            let st = std::fs::metadata(path).unwrap();
            (st.dev(), st.ino())
        };
        assert_eq!(f.exe_id, id(&p.join("inst/bin/ollama")));
        assert_eq!(f.prefix_id, id(&p.join("inst")));
        assert_eq!(f.dir_id, id(&p));
    }

    #[test]
    fn a_directory_replaced_after_it_was_resolved_is_refused() {
        let (_d, p) = tree();
        std::fs::create_dir_all(p.join("units")).unwrap();
        let u = unit(&p.join("units"), &p.join("inst/bin/ollama"));
        // The old directory is kept under another name, so the new one cannot reuse its inode.
        let swap = |path: &Path| {
            let dir = path.parent().unwrap();
            std::fs::rename(dir, dir.with_extension("old")).unwrap();
            std::fs::create_dir(dir).unwrap();
            std::fs::copy(dir.with_extension("old").join("ollama.service"), path).unwrap();
        };
        let e = collect_with(&u, DEFAULT_UNIT_BYTES, &|_| {}, &swap, &|_| {}).unwrap_err();
        assert!(
            e.contains("its directory changed after it was resolved"),
            "{e}"
        );
    }

    #[test]
    fn symlinks_are_resolved_as_execve_and_an_argument_are() {
        let (_d, p) = tree();
        std::fs::create_dir_all(p.join("other")).unwrap();
        symlink(p.join("inst/bin"), p.join("other/bin")).unwrap();
        std::fs::create_dir_all(p.join("units")).unwrap();
        let u = unit(&p.join("units"), &p.join("other/bin/ollama"));
        symlink(&u, p.join("link.service")).unwrap();
        let f = collect(&p.join("link.service"), DEFAULT_UNIT_BYTES).unwrap();
        // The unit is the file the link leads to; the installation, the one the executable
        // resolves to, not `other`.
        assert_eq!(f.root.path.as_bytes(), u.as_os_str().as_bytes());
        assert_eq!(f.instance.id.as_str(), "inst:service-unit/ollama.service");
        assert_eq!(f.exe, p.join("inst/bin/ollama"));
        assert_eq!(f.prefix, p.join("inst"));
    }

    #[test]
    fn every_failure_is_an_input_error_with_its_reason() {
        let (_d, p) = tree();
        std::fs::write(p.join("inst/ollama"), b"exe").unwrap();
        std::fs::create_dir_all(p.join("dir/bin/ollama")).unwrap();
        let units = |name: &str, exe: &Path| {
            std::fs::create_dir_all(p.join(name)).unwrap();
            unit(&p.join(name), exe)
        };
        let relative = p.join("relative.service");
        std::fs::write(&relative, b"[Service]\nExecStart=ollama serve\n").unwrap();
        let cases: Vec<(PathBuf, u64, &str)> = vec![
            (p.join("none.service"), DEFAULT_UNIT_BYTES, ": not found"),
            (p.join("inst"), DEFAULT_UNIT_BYTES, "a directory"),
            (
                units("small", &p.join("inst/bin/ollama")),
                4,
                "over service_unit_bytes",
            ),
            (
                units("missing", &p.join("none/bin/ollama")),
                DEFAULT_UNIT_BYTES,
                "ExecStart= at line 2 names",
            ),
            (
                units("layout", &p.join("inst/ollama")),
                DEFAULT_UNIT_BYTES,
                "which is not <prefix>/bin/ollama",
            ),
            (
                units("directory", &p.join("dir/bin/ollama")),
                DEFAULT_UNIT_BYTES,
                "which is not a regular file",
            ),
            (relative, DEFAULT_UNIT_BYTES, "a relative command"),
        ];
        for (path, limit, why) in cases {
            let e = collect(&path, limit).expect_err(why);
            assert!(e.starts_with("--service-unit "), "{e}");
            assert!(e.contains(why), "{why}: {e}");
        }
    }

    #[test]
    fn a_unit_replaced_after_it_was_resolved_is_refused() {
        let (_d, p) = tree();
        let u = unit(&p, &p.join("inst/bin/ollama"));
        // The old file is kept under another name, so the new one cannot reuse its inode.
        let swap = |path: &Path| {
            std::fs::rename(path, path.with_extension("old")).unwrap();
            std::fs::write(path, b"[Service]\nExecStart=/elsewhere/bin/ollama\n").unwrap();
        };
        let e = collect_with(&u, DEFAULT_UNIT_BYTES, &|_| {}, &swap, &|_| {}).unwrap_err();
        assert!(
            e.contains("replaced by another file after it was resolved"),
            "{e}"
        );
    }

    #[test]
    fn an_ancestor_swapped_for_a_symlink_is_refused() {
        let (_d, p) = tree();
        std::fs::create_dir_all(p.join("a/b/c")).unwrap();
        std::fs::create_dir_all(p.join("x/c")).unwrap();
        std::fs::create_dir_all(p.join("inst2/bin")).unwrap();
        std::fs::write(p.join("inst2/bin/ollama"), b"exe").unwrap();
        let u = unit(&p.join("a/b/c"), &p.join("inst/bin/ollama"));
        unit(&p.join("x/c"), &p.join("inst2/bin/ollama"));
        // The old `b` is kept, so no inode is reused: only the path tells the two apart.
        let swap = |_: &Path| {
            std::fs::rename(p.join("a/b"), p.join("a/b.old")).unwrap();
            symlink(p.join("x"), p.join("a/b")).unwrap();
        };
        let e = collect_with(&u, DEFAULT_UNIT_BYTES, &swap, &|_| {}, &|_| {}).unwrap_err();
        assert!(
            e.contains("its directory changed after it was resolved"),
            "{e}"
        );
    }

    #[test]
    fn a_unit_changed_or_removed_during_the_read_is_refused() {
        use std::io::Write;
        let (_d, p) = tree();
        let u = unit(&p, &p.join("inst/bin/ollama"));
        let grow = |rel: &RelPath| {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(p.join(rel.display()))
                .unwrap();
            f.write_all(b"# more\n").unwrap();
        };
        let e = collect_with(&u, DEFAULT_UNIT_BYTES, &|_| {}, &|_| {}, &grow).unwrap_err();
        assert!(e.contains("changed during the read"), "{e}");
        let remove = |rel: &RelPath| std::fs::remove_file(p.join(rel.display())).unwrap();
        let u = unit(&p, &p.join("inst/bin/ollama"));
        let e = collect_with(&u, DEFAULT_UNIT_BYTES, &|_| {}, &|_| {}, &remove).unwrap_err();
        assert!(e.contains("vanished during the read"), "{e}");
    }

    #[test]
    fn a_unit_replaced_by_an_oversized_file_says_replaced() {
        let (_d, p) = tree();
        let u = unit(&p, &p.join("inst/bin/ollama"));
        let limit = std::fs::metadata(&u).unwrap().len();
        let swap = |path: &Path| {
            std::fs::rename(path, path.with_extension("old")).unwrap();
            std::fs::write(path, vec![b'#'; usize::try_from(limit).unwrap() + 100]).unwrap();
        };
        let e = collect_with(&u, limit, &|_| {}, &swap, &|_| {}).unwrap_err();
        assert!(
            e.contains("replaced by another file after it was resolved"),
            "{e}"
        );
    }

    #[test]
    fn a_unit_that_cannot_be_opened_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::geteuid().is_root() {
            eprintln!("skipped: root opens a mode-000 file");
            return;
        }
        let (_d, p) = tree();
        let u = unit(&p, &p.join("inst/bin/ollama"));
        std::fs::set_permissions(&u, std::fs::Permissions::from_mode(0o000)).unwrap();
        let e = collect(&u, DEFAULT_UNIT_BYTES).unwrap_err();
        assert!(e.contains("permission denied"), "{e}");
    }

    #[test]
    fn the_prefix_is_what_precedes_bin_ollama() {
        assert_eq!(
            prefix_of(Path::new("/usr/local/bin/ollama")),
            Some(PathBuf::from("/usr/local"))
        );
        assert_eq!(
            prefix_of(Path::new("/opt/x y/bin/ollama")),
            Some(PathBuf::from("/opt/x y"))
        );
        for path in [
            "/bin/ollama",
            "/usr/local/bin/ollama-serve",
            "/usr/local/ollama",
            "/usr/local/sbin/ollama",
            "/usr/local/bin/ollama/x",
        ] {
            assert_eq!(prefix_of(Path::new(path)), None, "{path}");
        }
    }

    /// A placement of the install root at `path` with `dev:ino`, as the walk records it.
    fn walked(path: &Path, (dev, ino): (u64, u64)) -> FileInstance {
        FileInstance {
            id: InstanceId::new("inst:install/bin/ollama").unwrap(),
            root: RootId::new(INSTALL_ROOT).unwrap(),
            path: recorded(path),
            link_chain: vec![],
            resolved: None,
            content: InstanceContent::NotRead {
                why: NotReadReason::BudgetExceeded,
            },
            stat: StatInfo {
                dev,
                ino,
                mode: 0o100755,
                uid: 0,
                gid: 0,
                size: 3,
                mtime_ns: 0,
                nlink: 1,
            },
            stability: Stability::NoChangeDetected,
            discovered_by: vec![DiscoverySource::Walk],
        }
    }

    /// The walk's facts as `attach` reads them: its root opened at `root_path` as `root_id`, its
    /// summary state, what it recorded for `bin/ollama`, and its placements.
    fn walk(
        root_path: &Path,
        root_id: Option<(u64, u64)>,
        state: CoverageState,
        bin_gap: Option<&str>,
        instances: Vec<FileInstance>,
    ) -> InstallFacts {
        InstallFacts {
            root_path: recorded(root_path),
            root_id,
            instances,
            artifacts: vec![],
            discovery: Coverage {
                check: CheckId::new(ARTIFACTS_DISCOVERY).unwrap(),
                scope: Ref::Root(RootId::new(INSTALL_ROOT).unwrap()),
                state,
                budget: None,
            },
            bin_gap: bin_gap.map(str::to_string),
            bytes_read: 0,
            binaries: vec![],
            scans: vec![],
        }
    }

    #[test]
    fn the_source_goes_on_the_file_resolved() {
        use CoverageState::Complete;
        let (_d, p) = tree();
        let u = unit(&p, &p.join("inst/bin/ollama"));
        let f = collect(&u, DEFAULT_UNIT_BYTES).unwrap();
        let (prefix, root) = (f.prefix.as_path(), Some(f.prefix_id));
        let lib = walked(&p.join("inst/lib/ollama"), (1, 2));
        let mut w = walk(
            prefix,
            root,
            Complete,
            None,
            vec![walked(&f.exe, f.exe_id), lib],
        );
        attach(&f, &mut w).unwrap();
        assert_eq!(
            w.instances[0].discovered_by,
            vec![
                DiscoverySource::Walk,
                DiscoverySource::ServiceUnit {
                    config: f.config.clone()
                }
            ]
        );
        assert_eq!(w.instances[1].discovered_by, vec![DiscoverySource::Walk]);
        let refused = |mut w: InstallFacts| {
            let e = attach(&f, &mut w).unwrap_err();
            assert!(
                w.instances
                    .iter()
                    .all(|i| i.discovered_by == vec![DiscoverySource::Walk]),
                "{e}"
            );
            e
        };
        let exe = || vec![walked(&f.exe, f.exe_id)];
        // The walk opened another directory than the prefix resolved.
        let other_root = Some((f.prefix_id.0, f.prefix_id.1 + 1));
        let e = refused(walk(prefix, other_root, Complete, None, exe()));
        assert!(e.contains("the installation"), "{e}");
        assert!(e.contains("was replaced after it was resolved"), "{e}");
        // The same directory, opened at another path: the prefix was moved and a link left in its
        // place (Task 5 re-review). The walk's placements are under the path it opened.
        let moved = p.join("moved");
        let at_moved = vec![walked(&moved.join("bin/ollama"), f.exe_id)];
        let e = refused(walk(&moved, root, Complete, None, at_moved));
        assert!(e.contains("was moved after it was resolved"), "{e}");
        assert!(e.contains("moved"), "{e}");
        assert!(!e.contains("not recorded"), "{e}");
        // The walk opened none: its state says why, never "replaced".
        let denied = CoverageState::Unavailable {
            why: Unavailability::PermissionDenied,
        };
        let e = refused(walk(prefix, None, denied, None, exe()));
        assert!(e.contains("could not be opened: permission denied"), "{e}");
        assert!(!e.contains("replaced"), "{e}");
        let gone = CoverageState::Unavailable {
            why: Unavailability::NotFound,
        };
        let e = refused(walk(prefix, None, gone, None, exe()));
        assert!(e.contains("could not be opened: not found"), "{e}");
        let e = refused(walk(prefix, None, Complete, None, exe()));
        assert!(e.contains("could not be opened: it was not opened"), "{e}");
        // Another file at the executable's path.
        let other = vec![walked(&f.exe, (f.exe_id.0, f.exe_id.1 + 1))];
        let e = refused(walk(prefix, root, Complete, None, other));
        assert!(e.contains("was replaced after it was resolved"), "{e}");
        // No instance at the executable's path: what the walk recorded for it says why, whatever
        // its summary state (Task 5 re-review: a budget reached under `lib/ollama` hid it).
        let none = || vec![walked(&p.join("inst/bin/other"), f.exe_id)];
        let bytes = CoverageState::BudgetExceeded {
            budget: "install_bytes".into(),
            used: 64,
            limit: 70,
        };
        let gap = Some("bin/ollama: PermissionDenied");
        let e = refused(walk(prefix, root, bytes, gap, none()));
        assert!(
            e.contains(
                "was not recorded by the installation's walk (bin/ollama: PermissionDenied)"
            ),
            "{e}"
        );
        assert!(!e.contains("install_bytes"), "{e}");
        let e = refused(walk(prefix, root, Complete, None, none()));
        assert!(
            e.contains("was not recorded by the installation's walk (it recorded no reason)"),
            "{e}"
        );
        // A placement at the executable's path, of another root.
        let elsewhere = vec![FileInstance {
            root: RootId::new("models").unwrap(),
            ..walked(&f.exe, f.exe_id)
        }];
        refused(walk(prefix, root, Complete, None, elsewhere));
    }
}
