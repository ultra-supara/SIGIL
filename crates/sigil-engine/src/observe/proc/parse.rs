//! Parsing what `/proc` returns (pure).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One LISTEN row of `/proc/net/tcp` or `/proc/net/tcp6`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpListen {
    pub address: IpAddr,
    pub port: u16,
    pub inode: u64,
}

/// What one line of `/proc/net/tcp{,6}` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpRow {
    /// A row in another state, the header, or a blank line.
    NotListen,
    Listen(TcpListen),
    /// A line that is neither: a LISTEN row that cannot be read, or an unknown format. It is
    /// reported, never taken as the absence of a socket.
    Malformed,
}

/// Classifies `line`.
///
/// The kernel prints an address as the `%08X` of its 32-bit words in host byte order. Reading each
/// word back as a host-order integer and taking its native bytes gives the address bytes on any
/// host (v0.1 swapped bytes, which assumed a little-endian host).
pub fn tcp_row(line: &str, v6: bool) -> TcpRow {
    let mut fields = line.split_whitespace();
    let (Some(_slot), Some(local), Some(_remote), Some(state)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return if line.trim().is_empty() {
            TcpRow::NotListen
        } else {
            TcpRow::Malformed
        };
    };
    if state != "0A" {
        return TcpRow::NotListen;
    }
    match listen_fields(local, fields, v6) {
        Some(row) => TcpRow::Listen(row),
        None => TcpRow::Malformed,
    }
}

fn listen_fields<'a>(
    local: &str,
    mut fields: impl Iterator<Item = &'a str>,
    v6: bool,
) -> Option<TcpListen> {
    // After the state: tx:rx, tr:when, retrnsmt, uid, timeout, inode.
    let inode = fields.nth(5)?.parse().ok()?;
    let (address, port) = local.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let address = if v6 {
        v6_address(address)?
    } else {
        v4_address(address)?
    };
    Some(TcpListen {
        address,
        port,
        inode,
    })
}

fn word(hex: &str) -> Option<[u8; 4]> {
    if hex.len() != 8 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(u32::from_str_radix(hex, 16).ok()?.to_ne_bytes())
}

fn v4_address(hex: &str) -> Option<IpAddr> {
    Some(IpAddr::V4(Ipv4Addr::from(word(hex)?)))
}

fn v6_address(hex: &str) -> Option<IpAddr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word(hex.get(i * 8..i * 8 + 8)?)?);
    }
    Some(IpAddr::V6(Ipv6Addr::from(bytes)))
}

/// The arguments of `/proc/<pid>/cmdline`: NUL-separated, with the final NUL not starting an
/// argument.
pub fn cmdline(bytes: &[u8]) -> Vec<Vec<u8>> {
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    if bytes.is_empty() {
        return vec![];
    }
    bytes.split(|b| *b == 0).map(<[u8]>::to_vec).collect()
}

/// `starttime` (field 22) of `/proc/<pid>/stat`, in clock ticks since boot. Fields are counted
/// after the last `)`, since the process name in field 2 may contain spaces and parentheses.
pub fn stat_start_ticks(stat: &str) -> Option<u64> {
    let (_, rest) = stat.rsplit_once(')')?;
    // `rest` starts at field 3 (state); field 22 is the 20th of it.
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// The inode of a link text `<kind>:[<inode>]`, e.g. `socket:[123]` or `net:[4026531840]`.
pub fn link_inode(link: &[u8], kind: &str) -> Option<u64> {
    let text = std::str::from_utf8(link).ok()?;
    let inode = text
        .strip_prefix(kind)?
        .strip_prefix(":[")?
        .strip_suffix(']')?;
    if inode.is_empty() || !inode.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    inode.parse().ok()
}

/// `ppid` (field 4) of `/proc/<pid>/stat`, counted after the last `)` as [`stat_start_ticks`]
/// (PR-4d-2).
pub fn stat_ppid(stat: &str) -> Option<u32> {
    let (_, rest) = stat.rsplit_once(')')?;
    // `rest` starts at field 3 (state); field 4 is the 2nd of it.
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// One file-backed line of `/proc/<pid>/maps` (PR-4d-2): the object's device as `st_dev`
/// encodes it, its inode, its path as the kernel printed it (a newline is `\012`), and whether
/// the kernel marked it deleted. The kernel appends ` (deleted)` to the path, so a live file whose
/// name ends in ` (deleted)` reads as deleted: the text cannot tell them apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapsLine {
    pub dev: u64,
    pub ino: u64,
    pub path: Vec<u8>,
    pub deleted: bool,
}

/// What one `maps` line is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapsRow {
    File(MapsLine),
    /// Anonymous, `[heap]`, `[stack]`, `[vdso]`, …: no file behind it.
    NotFile,
    Malformed,
}

/// `start-end perms offset MAJ:MIN inode [path]` (proc_pid_maps(5)). The path is what follows
/// the inode and the spaces that pad it, and may contain spaces. A mapping is file-backed when its
/// inode is not 0 and its path starts with `/`.
pub fn maps_row(line: &[u8]) -> MapsRow {
    let hex = |f: &[u8]| !f.is_empty() && f.iter().all(u8::is_ascii_hexdigit);
    let mut rest = line;
    let mut fields: [&[u8]; 5] = [&[]; 5];
    for field in &mut fields {
        rest = trim_spaces(rest);
        let end = rest.iter().position(|b| *b == b' ').unwrap_or(rest.len());
        if end == 0 {
            return MapsRow::Malformed;
        }
        *field = &rest[..end];
        rest = &rest[end..];
    }
    let [range, perms, offset, dev, inode] = fields;
    let range_ok = match range.iter().position(|b| *b == b'-') {
        Some(i) => hex(&range[..i]) && hex(&range[i + 1..]),
        None => false,
    };
    let perms_ok = matches!(perms, [b'r' | b'-', b'w' | b'-', b'x' | b'-', b's' | b'p']);
    if !range_ok || !perms_ok || !hex(offset) {
        return MapsRow::Malformed;
    }
    let Some(dev) = device(dev) else {
        return MapsRow::Malformed;
    };
    let Some(ino) = std::str::from_utf8(inode)
        .ok()
        .filter(|t| t.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|t| t.parse::<u64>().ok())
    else {
        return MapsRow::Malformed;
    };
    let path = trim_spaces(rest);
    if ino == 0 || !path.starts_with(b"/") {
        return MapsRow::NotFile;
    }
    let (path, deleted) = match path.strip_suffix(b" (deleted)") {
        Some(path) => (path, true),
        None => (path, false),
    };
    MapsRow::File(MapsLine {
        dev,
        ino,
        path: path.to_vec(),
        deleted,
    })
}

fn trim_spaces(mut s: &[u8]) -> &[u8] {
    while let [b' ', rest @ ..] = s {
        s = rest;
    }
    s
}

/// `MAJ:MIN` (hex, as `maps` prints a device) as `st_dev` encodes it: the kernel's
/// `new_encode_dev`, a 12-bit major and a 20-bit minor. `None` for anything else.
pub fn device(text: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(text).ok()?;
    let (major, minor) = text.split_once(':')?;
    let hex = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit());
    if !hex(major) || !hex(minor) {
        return None;
    }
    let major = u64::from_str_radix(major, 16).ok()?;
    let minor = u64::from_str_radix(minor, 16).ok()?;
    if major > 0xfff || minor > 0xf_ffff {
        return None;
    }
    Some((minor & 0xff) | (major << 8) | ((minor & !0xff) << 12))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn listen(line: &str, v6: bool) -> TcpListen {
        match tcp_row(line, v6) {
            TcpRow::Listen(row) => row,
            other => panic!("{other:?}: {line}"),
        }
    }

    /// The kernel's text for an address on this host: each 32-bit word's native bytes printed as
    /// a host-order integer.
    fn row_address(address: IpAddr) -> String {
        let bytes = match address {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        bytes
            .chunks(4)
            .map(|w| format!("{:08X}", u32::from_ne_bytes([w[0], w[1], w[2], w[3]])))
            .collect()
    }

    // --- ported from v0.1 (sigil-core/src/runtime/listeners.rs, removed in PR-3b-3c-1) ---------

    #[test]
    fn parses_ipv4_loopback_listen_row() {
        // On a little-endian host, 0100007F is 127.0.0.1; 94F9 is port 38137; 0A is LISTEN.
        let line = format!(
            "   1: {}:94F9 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 18568 1 00000000c7521507 100 0 0 10 0",
            row_address(ip("127.0.0.1"))
        );
        let row = listen(&line, false);
        assert_eq!(row.address, ip("127.0.0.1"));
        assert_eq!(row.port, 0x94F9);
        assert_eq!(row.inode, 18568);
    }

    #[test]
    fn parses_ipv4_wildcard_listen_row() {
        let line = "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 8917 1 0000000043890958 100 0 0 10 0";
        let row = listen(line, false);
        assert_eq!(row.address, ip("0.0.0.0"));
        assert_eq!(row.port, 22);
    }

    #[test]
    fn skips_non_listen_rows() {
        // 01 is ESTABLISHED.
        let line = "   2: 73014064:BE2C 1A72528C:01BB 01 00000000:00000000 02:00000F26 00000000  1000        0 4442946 2 000000000fbb84c8 45 4 26 10 -1";
        assert_eq!(tcp_row(line, false), TcpRow::NotListen);
    }

    #[test]
    fn parses_ipv6_loopback_listen_row() {
        let line = format!(
            "   0: {}:D431 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99999 1 0 100 0 0 10 0",
            row_address(ip("::1"))
        );
        let row = listen(&line, true);
        assert_eq!(row.address, ip("::1"));
        assert_eq!(row.port, 0xD431);
        assert_eq!(row.inode, 99999);
    }

    #[test]
    fn parses_ipv6_wildcard_listen_row() {
        let line = "   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 8919 1 0 100 0 0 10 0";
        assert_eq!(listen(line, true).address, ip("::"));
    }

    // --- new in v2 -----------------------------------------------------------------------------

    #[test]
    fn every_address_round_trips_through_the_kernel_text() {
        for (text, v6) in [
            ("192.168.1.20", false),
            ("10.0.0.5", false),
            ("::ffff:127.0.0.1", true),
            ("fe80::1", true),
            ("2001:db8::7", true),
        ] {
            let line = format!(
                "0: {}:2CAA {}:0000 0A 0:0 0:0 0 0 0 42",
                row_address(ip(text)),
                "0".repeat(if v6 { 32 } else { 8 })
            );
            assert_eq!(listen(&line, v6).address, ip(text), "{text}");
        }
    }

    #[test]
    fn headers_and_blank_lines_are_not_rows_and_the_rest_is_malformed() {
        for line in [
            "",
            "   ",
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
        ] {
            assert_eq!(tcp_row(line, false), TcpRow::NotListen, "{line:?}");
        }
        for (line, v6) in [
            ("0: 0100007F 00000000:0000 0A 0:0 0:0 0 0 0 1", false),
            ("0: 0100007G:0016 00000000:0000 0A 0:0 0:0 0 0 0 1", false),
            ("0: 0100007F:FFFFF 00000000:0000 0A 0:0 0:0 0 0 0 1", false),
            ("0: 0100007F:0016 00000000:0000 0A 0:0 0:0 0 0 0 x", false),
            ("0: 0100007F:0016 00000000:0000 0A", false),
            ("0: 0100007F:0016 00000000:0000 0A 0:0 0:0 0 0 0 1", true),
            ("garbage", false),
        ] {
            assert_eq!(tcp_row(line, v6), TcpRow::Malformed, "{line:?}");
        }
    }

    #[test]
    fn cmdline_splits_on_nul() {
        assert_eq!(
            cmdline(b"/usr/local/bin/ollama\0serve\0"),
            [b"/usr/local/bin/ollama".to_vec(), b"serve".to_vec()]
        );
        assert_eq!(
            cmdline(b"ollama\0\0x\0"),
            [b"ollama".to_vec(), vec![], b"x".to_vec()]
        );
        assert_eq!(cmdline(b""), Vec::<Vec<u8>>::new());
        assert_eq!(cmdline(b"\0"), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn start_ticks_are_field_22_after_the_name() {
        let fields: Vec<String> = (3..=30).map(|n| n.to_string()).collect();
        let stat = format!("4242 (ollama) {}", fields.join(" "));
        assert_eq!(stat_start_ticks(&stat), Some(22));
        // A name with spaces and parentheses.
        let stat = format!("4242 (a) b (c)) {}", fields.join(" "));
        assert_eq!(stat_start_ticks(&stat), Some(22));
        assert_eq!(stat_start_ticks("4242 (ollama) S 1"), None);
        assert_eq!(stat_start_ticks("no parenthesis"), None);
    }

    #[test]
    fn link_inodes_are_read_only_from_their_kind() {
        assert_eq!(link_inode(b"socket:[18568]", "socket"), Some(18568));
        assert_eq!(link_inode(b"net:[4026531840]", "net"), Some(4026531840));
        for (link, kind) in [
            (&b"pipe:[1]"[..], "socket"),
            (b"/dev/null", "socket"),
            (b"socket:[]", "socket"),
            (b"socket:[12a]", "socket"),
            (b"socket:[1", "socket"),
            (b"socket:[1]", "net"),
            (b"socket:[\xff]", "socket"),
        ] {
            assert_eq!(
                link_inode(link, kind),
                None,
                "{}",
                String::from_utf8_lossy(link)
            );
        }
    }

    #[test]
    fn maps_lines_are_read_as_the_kernel_prints_them() {
        let file = |dev, ino, path: &str, deleted| {
            MapsRow::File(MapsLine {
                dev,
                ino,
                path: path.as_bytes().to_vec(),
                deleted,
            })
        };
        let cases: Vec<(&str, MapsRow)> = vec![
            (
                "564f4427d000-564f44294000 r--p 00000000 103:04 2101920                   /usr/bin/zsh",
                file(66308, 2101920, "/usr/bin/zsh", false),
            ),
            (
                "7f00-7f10 r-xp 00001000 fd:01 42 /opt/a b/lib x.so",
                file(0xfd01, 42, "/opt/a b/lib x.so", false),
            ),
            (
                "7f00-7f10 r-xp 00000000 08:02 7 /tmp/gone.so (deleted)",
                file(0x0802, 7, "/tmp/gone.so", true),
            ),
            (
                "7f00-7f10 rw-s 00000000 00:01 9 /memfd:x (deleted)",
                file(0x0001, 9, "/memfd:x", true),
            ),
            (
                "7f00-7f10 r--p 00000000 08:02 7 /a\\012b",
                file(0x0802, 7, "/a\\012b", false),
            ),
            ("7f00-7f10 rw-p 00000000 00:00 0 ", MapsRow::NotFile),
            ("7f00-7f10 rw-p 00000000 00:00 0 [heap]", MapsRow::NotFile),
            ("7ffd-7ffe r-xp 00000000 00:00 0                          [vdso]", MapsRow::NotFile),
            ("7f00-7f10 rw-p 00000000 00:00 0", MapsRow::NotFile),
            ("7f00-7f10 r--p 00000000 08:02 7 relative/path", MapsRow::NotFile),
            ("garbage", MapsRow::Malformed),
            ("7f00-7f10 r--p 00000000 08:02 x /a", MapsRow::Malformed),
            ("7f00-7f10 r--p 00000000 0802 7 /a", MapsRow::Malformed),
            ("7f00 r--p 00000000 08:02 7 /a", MapsRow::Malformed),
            ("7f00-7f10 r--pq 00000000 08:02 7 /a", MapsRow::Malformed),
            ("7f00-7f10 zzzz 00000000 08:02 7 /a", MapsRow::Malformed),
            ("7f00-7f10 r--p 00000000 08:02 0 /a", MapsRow::NotFile),
            ("7f00-7f10 r--p 00000000 08:02 +7 /a", MapsRow::Malformed),
            ("zz-7f10 r--p 00000000 08:02 7 /a", MapsRow::Malformed),
            ("7f00- r--p 00000000 08:02 7 /a", MapsRow::Malformed),
            ("7f00-7f10 r--p 0000000g 08:02 7 /a", MapsRow::Malformed),
        ];
        for (line, want) in cases {
            assert_eq!(maps_row(line.as_bytes()), want, "{line}");
        }
    }

    #[test]
    fn devices_are_encoded_as_st_dev() {
        // R-1: `103:04` is 66308, `stat`'s dev of the same file.
        assert_eq!(device(b"103:04"), Some(66308));
        assert_eq!(device(b"00:00"), Some(0));
        // A minor over 255 moves its high bits above the major.
        assert_eq!(device(b"00:1a2"), Some(0xa2 | (0x100 << 12)));
        assert_eq!(
            device(b"fff:fffff"),
            Some(0xff | (0xfff << 8) | (0xfff00 << 12))
        );
        for bad in [
            &b"1000:00"[..],
            b"00:100000",
            b"103",
            b":04",
            b"103:",
            b"1g:04",
            b"+1:04",
        ] {
            assert_eq!(device(bad), None, "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn the_parent_is_read_after_the_last_parenthesis() {
        assert_eq!(stat_ppid("4242 (ollama) S 1 4242 4242 0"), Some(1));
        assert_eq!(stat_ppid("4300 (a) b (c)) R 4242 4300"), Some(4242));
        assert_eq!(stat_ppid("4300 (x) S"), None);
        assert_eq!(stat_ppid("4300 (x) S -1"), None);
        assert_eq!(stat_ppid("no parenthesis"), None);
    }
}
