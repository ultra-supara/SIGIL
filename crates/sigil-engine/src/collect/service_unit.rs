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
/// - the unit is UTF-8 with no NUL and no byte-order mark;
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
/// - the arguments after it have no quote and no backslash, and no word that is exactly `;` (a
///   second command);
/// - what remains of the first item is an absolute path with no `\`, `%`, `$`, or control byte;
/// - a [`REDIRECTS`] setting still set at the end is outside the subset: it changes where the
///   service's paths lead.
///
/// It is an explicitly limited subset, not a systemd-compatible parser: what it does not model
/// is refused, even where systemd accepts it.
pub fn exec_start(text: &[u8]) -> Result<(Vec<u8>, u32), String> {
    if text.contains(&0) {
        return Err("a NUL byte".to_string());
    }
    if std::str::from_utf8(text).is_err() {
        return Err("the unit is not UTF-8".to_string());
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
    let (item, rest) = first_item(&value).map_err(&at)?;
    let (exe, argv0) = strip_prefixes(item).map_err(&at)?;
    if rest.iter().any(|&b| matches!(b, b'"' | b'\'' | b'\\')) {
        return Err(at("a quote or backslash in the arguments (not modeled)"));
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
            (
                "[Service]\nExecStart=/tmpfs/bin/ollama\n",
                "/tmpfs/bin/ollama",
            ),
            (
                "[Service]\nExecStart=/var/tmpx/ollama\n",
                "/var/tmpx/ollama",
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
                "at line 2: a quote or backslash in the arguments",
            ),
            (
                "[Service]\nExecStart=/a/bin/ollama 'serve'\n",
                "a quote or backslash in the arguments",
            ),
            (
                "[Service]\nExecStart=/a/bin/ollama a\\x20b\n",
                "a quote or backslash in the arguments",
            ),
            (
                "[Service]\nExecStart=/a/bin/ollama serve \\;\n",
                "a quote or backslash in the arguments",
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
}
