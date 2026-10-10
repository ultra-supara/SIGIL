//! Go build info (spec §4.5), as Go's `debug/buildinfo` and `runtime/debug.ParseBuildInfo` read
//! it:
//! - the `.go.buildinfo` section, else the first writable, non-executable `PT_LOAD`, searched to
//!   its end at 16-aligned virtual addresses, in chunks from an aligned start;
//! - the inline (Go 1.18+) or pointer format, in either byte order;
//! - the sentinel, and the modinfo lines.
//!
//! `None` without a gap means the whole range was searched and holds no build info (or Go's own
//! rule says it is not a Go binary: an empty version). Anything cut short or malformed is a gap,
//! and no build info is reported then.

use object::read::elf::FileHeader;
use object::read::{ReadCacheOps, ReadRef};
use object::Endianness;
use sigil_model::{GoBuildInfo, GoModule, GoSetting, Loc, UntrustedText};

use super::elf::Elf;
use super::vaddr::Place;

pub const MAGIC: &[u8] = b"\xff Go buildinf:";
pub const ALIGN: u64 = 16;
pub const HEADER: u64 = 32;
pub const CHUNK: u64 = 64 << 10;
pub const MAX_VERSION: u64 = 1 << 10;
pub const MAX_MODINFO: u64 = 1 << 20;
pub const MAX_DEPS: usize = 4096;
pub const MAX_SETTINGS: usize = 1024;
const FLAGS_BIG_ENDIAN: u8 = 0x1;
const FLAGS_INLINE: u8 = 0x2;
/// `binary.MaxVarintLen64`.
const MAX_VARINT: u64 = 10;

/// The build info of the ELF, or `None`; a gap explains every `None` that is not an absence.
pub(crate) fn find<R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &mut Elf<'_, R, H>,
    section: Option<(u64, u64, u64)>,
) -> Option<GoBuildInfo> {
    let (vaddr, offset, size, is_section) = match section {
        Some((v, o, s)) => (v, o, s, true),
        None => {
            let l = e.loads.0.iter().find(|l| l.writable && !l.executable)?;
            (l.vaddr, l.offset, l.filesz, false)
        }
    };
    let result = search(e, vaddr, offset, size).and_then(|found| match found {
        None => Ok(None),
        Some(va) => {
            let at = if is_section {
                Loc::Section {
                    name: UntrustedText::new(".go.buildinfo"),
                    offset: va - vaddr,
                }
            } else {
                Loc::VAddr(va)
            };
            let header_off = offset
                .checked_add(va - vaddr)
                .ok_or_else(|| "address overflow".to_string())?;
            let end = vaddr
                .checked_add(size)
                .ok_or_else(|| "address overflow".to_string())?;
            if va.checked_add(HEADER).is_none_or(|h| h > end) {
                return Err("a truncated header".to_string());
            }
            let header = e
                .data
                .read_bytes_at(header_off, HEADER)
                .map_err(|()| "the header is outside the file".to_string())?;
            let header: [u8; HEADER as usize] = header
                .try_into()
                .map_err(|_| "a truncated header".to_string())?;
            match strings(e, va, &header)? {
                None => Ok(None),
                Some((version, modinfo)) => build(at, version, &modinfo).map(Some),
            }
        }
    });
    match result {
        Ok(info) => info,
        Err(gap) => {
            e.gaps.push(format!("go.buildinfo: {gap}"));
            None
        }
    }
}

/// The virtual address of the first magic at a multiple of 16 in `[vaddr, vaddr + size)`.
fn search<R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'_, R, H>,
    vaddr: u64,
    offset: u64,
    size: u64,
) -> Result<Option<u64>, String> {
    let overflow = || "address overflow".to_string();
    let end = vaddr.checked_add(size).ok_or_else(overflow)?;
    let mut pos = vaddr.checked_add(ALIGN - 1).ok_or_else(overflow)? & !(ALIGN - 1);
    while pos < end {
        let len = (end - pos).min(CHUNK);
        let file_off = offset.checked_add(pos - vaddr).ok_or_else(overflow)?;
        let Ok(bytes) = e.data.read_bytes_at(file_off, len) else {
            if e.data.refused() {
                return Err(format!("search stopped at {} of {size} bytes", pos - vaddr));
            }
            return Err("the searched range is outside the file".to_string());
        };
        let mut i = 0usize;
        while i + MAGIC.len() <= bytes.len() {
            if &bytes[i..i + MAGIC.len()] == MAGIC {
                return Ok(Some(pos + i as u64));
            }
            i += ALIGN as usize;
        }
        pos += len;
    }
    Ok(None)
}

/// `len` bytes at virtual address `va`, from the file.
fn at_va<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'d, R, H>,
    va: u64,
    len: u64,
) -> Result<&'d [u8], String> {
    match e.loads.place(va, len) {
        Place::File(off) => e
            .data
            .read_bytes_at(off, len)
            .map_err(|()| "outside the file or over the budget".to_string()),
        _ => Err("a pointer outside every PT_LOAD".to_string()),
    }
}

/// Up to `max` bytes at `va`, as many as its segment has in the file.
fn prefix_at<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'d, R, H>,
    va: u64,
    max: u64,
) -> Result<&'d [u8], String> {
    let room = e
        .loads
        .0
        .iter()
        .find_map(|l| {
            let end = l.vaddr.checked_add(l.filesz)?;
            (va >= l.vaddr && va < end).then(|| end - va)
        })
        .ok_or_else(|| "a pointer outside every PT_LOAD".to_string())?;
    at_va(e, va, room.min(max))
}

/// Go's `binary.Uvarint`: the value and the bytes it took.
fn uvarint(buf: &[u8]) -> Result<(u64, u64), String> {
    let mut x = 0u64;
    let mut s = 0u32;
    for (i, &b) in buf.iter().enumerate() {
        if i as u64 == MAX_VARINT {
            return Err("uvarint overflow".to_string());
        }
        if b < 0x80 {
            if i as u64 == MAX_VARINT - 1 && b > 1 {
                return Err("uvarint overflow".to_string());
            }
            return Ok((x | u64::from(b) << s, i as u64 + 1));
        }
        x |= u64::from(b & 0x7f) << s;
        s += 7;
    }
    Err("a truncated uvarint".to_string())
}

/// A version and the modinfo as read (sentinel not yet stripped).
type VersionAndModinfo = (Vec<u8>, Vec<u8>);

/// The version and the (unstripped) modinfo, or `None` for an empty version (not a Go binary).
fn strings<R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'_, R, H>,
    va: u64,
    header: &[u8; HEADER as usize],
) -> Result<Option<VersionAndModinfo>, String> {
    let flags = header[15];
    let (version, modinfo) = if flags & FLAGS_INLINE != 0 {
        let start = va.checked_add(HEADER).ok_or("address overflow")?;
        let (version, next) = inline_string(e, start, MAX_VERSION, "version")?;
        let (modinfo, _) = inline_string(e, next, MAX_MODINFO, "modinfo")?;
        (version, modinfo)
    } else {
        let ptr_size = u64::from(header[14]);
        if ptr_size != 4 && ptr_size != 8 {
            return Err(format!("ptrSize {ptr_size}"));
        }
        let big = flags & FLAGS_BIG_ENDIAN != 0;
        let p = ptr_size as usize;
        let vers_ptr = read_ptr(&header[16..16 + p], big);
        let mod_ptr = read_ptr(&header[16 + p..16 + 2 * p], big);
        (
            go_string(e, vers_ptr, ptr_size, big, MAX_VERSION, "version")?,
            go_string(e, mod_ptr, ptr_size, big, MAX_MODINFO, "modinfo")?,
        )
    };
    if version.is_empty() {
        return Ok(None);
    }
    Ok(Some((version, modinfo)))
}

fn read_ptr(b: &[u8], big: bool) -> u64 {
    b.iter().enumerate().fold(0u64, |acc, (i, &x)| {
        let shift = if big { (b.len() - 1 - i) * 8 } else { i * 8 };
        acc | u64::from(x) << shift
    })
}

/// An inline string at `va`: a uvarint length, then the bytes. Returns it and the address after.
fn inline_string<R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'_, R, H>,
    va: u64,
    max: u64,
    what: &str,
) -> Result<(Vec<u8>, u64), String> {
    let head = prefix_at(e, va, MAX_VARINT)?;
    let (len, used) = uvarint(head)?;
    if len > max {
        return Err(format!("{what} over {max} bytes"));
    }
    let at = va.checked_add(used).ok_or("address overflow")?;
    let bytes = at_va(e, at, len)?;
    let next = at.checked_add(len).ok_or("address overflow")?;
    Ok((bytes.to_vec(), next))
}

/// A Go string header `{data, len}` at `va`, and its bytes.
fn go_string<R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'_, R, H>,
    va: u64,
    ptr_size: u64,
    big: bool,
    max: u64,
    what: &str,
) -> Result<Vec<u8>, String> {
    let header = at_va(e, va, 2 * ptr_size)?;
    let p = ptr_size as usize;
    let data = read_ptr(&header[..p], big);
    let len = read_ptr(&header[p..2 * p], big);
    if len > max {
        return Err(format!("{what} over {max} bytes"));
    }
    Ok(at_va(e, data, len)?.to_vec())
}

/// Go's sentinel stripping (`debug/buildinfo`).
fn strip_sentinel(m: &[u8]) -> &[u8] {
    if m.len() >= 33 && m[m.len() - 17] == b'\n' {
        &m[16..m.len() - 16]
    } else {
        &[]
    }
}

fn text(b: &[u8]) -> UntrustedText {
    UntrustedText::from_bytes(b.to_vec())
}

/// The modinfo lines, as `runtime/debug.ParseBuildInfo` reads them.
fn build(at: Loc, version: Vec<u8>, modinfo: &[u8]) -> Result<GoBuildInfo, String> {
    let mut info = GoBuildInfo {
        at,
        version: UntrustedText::from_bytes(version),
        path: None,
        main: None,
        deps: vec![],
        settings: vec![],
    };
    // Which module the next `=>` replaces: the main module, or a dependency by index.
    #[derive(Clone, Copy)]
    enum Last {
        Main,
        Dep(usize),
    }
    let mut last: Option<Last> = None;
    let mut rest = strip_sentinel(modinfo);
    // Go reads a malformed sentinel as no modinfo; SIGIL says it could not read it.
    if rest.is_empty() && !modinfo.is_empty() {
        return Err("modinfo without its sentinel".to_string());
    }
    while let Some(nl) = rest.iter().position(|b| *b == b'\n') {
        let line = &rest[..nl];
        rest = &rest[nl + 1..];
        if line.is_empty() {
            continue;
        }
        if let Some(p) = line.strip_prefix(b"path\t") {
            info.path = Some(text(p));
        } else if let Some(m) = line.strip_prefix(b"mod\t") {
            info.main = Some(module(m)?);
            last = Some(Last::Main);
        } else if let Some(d) = line.strip_prefix(b"dep\t") {
            if info.deps.len() >= MAX_DEPS {
                return Err(format!("over {MAX_DEPS} deps"));
            }
            info.deps.push(module(d)?);
            last = Some(Last::Dep(info.deps.len() - 1));
        } else if let Some(r) = line.strip_prefix(b"=>\t") {
            let cols: Vec<&[u8]> = r.split(|b| *b == b'\t').collect();
            let [path, version, sum] = cols.as_slice() else {
                return Err("expected 3 columns for replacement".to_string());
            };
            let replacement = GoModule {
                path: text(path),
                version: text(version),
                sum: (!sum.is_empty()).then(|| text(sum)),
                replace: None,
            };
            let target = match last.take() {
                Some(Last::Main) => info.main.as_mut(),
                Some(Last::Dep(i)) => info.deps.get_mut(i),
                None => None,
            };
            let Some(target) = target else {
                return Err("replacement with no module on the previous line".to_string());
            };
            target.replace = Some(Box::new(replacement));
        } else if let Some(kv) = line.strip_prefix(b"build\t") {
            if info.settings.len() >= MAX_SETTINGS {
                return Err(format!("over {MAX_SETTINGS} build settings"));
            }
            info.settings.push(setting(kv).ok_or("bad build line")?);
        } else {
            return Err("unknown line kind".to_string());
        }
    }
    if !rest.is_empty() {
        return Err("an unterminated modinfo line".to_string());
    }
    Ok(info)
}

/// `path\tversion[\tsum]`.
fn module(line: &[u8]) -> Result<GoModule, String> {
    let cols: Vec<&[u8]> = line.split(|b| *b == b'\t').collect();
    let (path, version, sum) = match cols.as_slice() {
        [p, v] => (p, v, None),
        [p, v, s] => (p, v, (!s.is_empty()).then(|| text(s))),
        _ => return Err("expected 2 or 3 columns".to_string()),
    };
    Ok(GoModule {
        path: text(path),
        version: text(version),
        sum,
        replace: None,
    })
}

/// A `build` line's `key=value`, each possibly `strconv.Quote`d.
fn setting(kv: &[u8]) -> Option<GoSetting> {
    let kv = std::str::from_utf8(kv).ok()?;
    let (key, raw_value) = match kv.as_bytes().first()? {
        b'=' => return None,
        b'`' | b'"' => {
            let raw_key = quoted_prefix(kv)?;
            let key = unquote(raw_key)?;
            let rest = kv[raw_key.len()..].strip_prefix('=')?;
            (key, rest)
        }
        _ => {
            let (k, v) = kv.split_once('=')?;
            (k.to_string(), v)
        }
    };
    let value = match raw_value.as_bytes().first() {
        Some(b'`' | b'"') => unquote(raw_value)?,
        _ => raw_value.to_string(),
    };
    Some(GoSetting {
        key: UntrustedText::new(key),
        value: UntrustedText::new(value),
    })
}

/// `strconv.QuotedPrefix` for a backquoted or double-quoted string.
fn quoted_prefix(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    match bytes.first()? {
        b'`' => {
            let end = s[1..].find('`')? + 1;
            Some(&s[..=end])
        }
        b'"' => {
            let mut i = 1;
            while i < bytes.len() {
                match bytes[i] {
                    b'\\' => i += 2,
                    b'"' => return Some(&s[..=i]),
                    b'\n' => return None,
                    _ => i += 1,
                }
            }
            None
        }
        _ => None,
    }
}

/// `strconv.Unquote` for a backquoted or double-quoted string.
fn unquote(s: &str) -> Option<String> {
    if let Some(inner) = s.strip_prefix('`').and_then(|r| r.strip_suffix('`')) {
        return (!inner.contains('`')).then(|| inner.replace('\r', ""));
    }
    let inner = s.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' | '\n' => return None,
            '\\' => {
                let escaped = match chars.next()? {
                    'a' => '\x07',
                    'b' => '\x08',
                    'f' => '\x0c',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'v' => '\x0b',
                    '\\' => '\\',
                    '"' => '"',
                    'x' => hex_char(&mut chars, 2)?,
                    'u' => hex_char(&mut chars, 4)?,
                    'U' => hex_char(&mut chars, 8)?,
                    d @ '0'..='7' => {
                        let mut v = d.to_digit(8)?;
                        for _ in 0..2 {
                            v = v * 8 + chars.next()?.to_digit(8)?;
                        }
                        if v > 0xff {
                            return None;
                        }
                        char::from_u32(v)?
                    }
                    _ => return None,
                };
                out.push(escaped);
            }
            c => out.push(c),
        }
    }
    Some(out)
}

fn hex_char(chars: &mut std::str::Chars<'_>, n: usize) -> Option<char> {
    let mut v = 0u32;
    for _ in 0..n {
        v = v * 16 + chars.next()?.to_digit(16)?;
    }
    char::from_u32(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uvarints_as_go_reads_them() {
        assert_eq!(uvarint(&[0x05]), Ok((5, 1)));
        assert_eq!(uvarint(&[0x80, 0x01]), Ok((128, 2)));
        assert!(uvarint(&[0xff; 11]).is_err());
        assert!(uvarint(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02]).is_err());
        assert!(uvarint(&[0x80]).is_err(), "truncated");
    }

    #[test]
    fn the_sentinel_is_stripped_only_when_well_formed() {
        let mut m = vec![b'x'; 16];
        m.extend_from_slice(b"path\tp\n");
        m.extend(vec![b'y'; 16]);
        assert_eq!(strip_sentinel(&m), b"path\tp\n");
        assert_eq!(strip_sentinel(b"short"), b"");
    }

    #[test]
    fn quoting_as_strconv_does() {
        assert_eq!(unquote(r#""a\tb""#).as_deref(), Some("a\tb"));
        assert_eq!(unquote(r#""\x41é\101""#).as_deref(), Some("AéA"));
        assert_eq!(unquote("`raw\\t`").as_deref(), Some("raw\\t"));
        assert_eq!(unquote(r#""bad\q""#), None);
        assert_eq!(
            unquote(r#""it\'s""#),
            None,
            "\\' is not an escape in double quotes"
        );
        assert_eq!(quoted_prefix(r#""k=v"=x"#), Some(r#""k=v""#));
        assert_eq!(quoted_prefix(r#""open"#), None);
    }
}
