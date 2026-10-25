//! The imports of a Mach-O slice (PR-4c-3b spec §3): what dyld binds, never a linked image's
//! symbol table. A linked image's come from `LC_DYLD_CHAINED_FIXUPS` (its imports table) or from
//! `LC_DYLD_INFO(_ONLY)` (its bind and lazy-bind opcodes). Every read goes through the slice's
//! `Bounded` reader, under `binary_parse_bytes`, at the file offset dyld reads. What is not read
//! or not understood is an `imports: …` gap of the container.

use std::collections::BTreeSet;

use object::read::ReadCacheOps;
use sigil_model::{imports_over_gap, MachOImport, MachOLibrary, UntrustedText, MH_OBJECT};

use super::{range, ByteOrder, Header};
use crate::binary::elf::MAX_IMPORT_NAME;
use crate::binary::read::Bounded;

/// The most bytes scanned for the names of a slice's chained imports (Task 2 review): the
/// imports may all point at the same bytes, so each scan stops at its NUL or one byte past
/// [`MAX_IMPORT_NAME`], and all of them at this.
const MAX_NAME_SCAN: u64 = 64 << 20;

/// What the load-command walk keeps for the imports.
#[derive(Debug, Default)]
pub(super) struct Commands {
    /// Each dylib-loading command's name, in ordinal order: `None` when it was not read, or not
    /// kept in `load_dylibs` (over its limit).
    pub dylibs: Vec<Option<UntrustedText>>,
    /// Each `LC_DYLD_CHAINED_FIXUPS`: `(dataoff, datasize)`.
    pub chained: Vec<(u32, u32)>,
    /// Each `LC_DYLD_INFO` or `LC_DYLD_INFO_ONLY`: its bind and lazy-bind streams, each
    /// `(offset, size)`.
    pub dyld_info: Vec<[(u32, u32); 2]>,
}

/// The imports of the slice `header` (base `base`, `size` bytes) from its `commands`, at most
/// `limit` of them (the smallest, in sorted order), and their gaps, sorted. No loader reads an
/// object file (`MH_OBJECT`), so its dyld commands are not read.
pub(super) fn read<R: ReadCacheOps>(
    data: &Bounded<R>,
    base: u64,
    size: u64,
    header: &Header,
    commands: &Commands,
    limit: u64,
) -> (Vec<MachOImport>, Vec<String>) {
    let mut out = Imports::new(&commands.dylibs, limit);
    if header.file_type == MH_OBJECT {
        return out.finish();
    }
    match (commands.chained.as_slice(), commands.dyld_info.as_slice()) {
        ([_, _, ..], _) => out.gap("imports: more than one LC_DYLD_CHAINED_FIXUPS".to_string()),
        (_, [_, _, ..]) => out.gap("imports: more than one LC_DYLD_INFO".to_string()),
        // ld64 and lld never write both.
        ([_], [_]) => out.gap("imports: both LC_DYLD_INFO and LC_DYLD_CHAINED_FIXUPS".to_string()),
        ([blob], []) => chained(data, base, size, header.order, *blob, &mut out),
        ([], [streams]) => opcodes(data, base, size, *streams, &mut out),
        // The classic binding of macOS 10.5 and earlier (`LC_DYSYMTAB`) is not read.
        ([], []) if !commands.dylibs.is_empty() => {
            out.gap("imports: no LC_DYLD_INFO or LC_DYLD_CHAINED_FIXUPS".to_string())
        }
        ([], []) => {}
    }
    out.finish()
}

/// The imports found so far, within the limit, and the gaps, each once: a stream that repeats one
/// keeps one (Task 2 review).
struct Imports<'c> {
    dylibs: &'c [Option<UntrustedText>],
    limit: u64,
    kept: BTreeSet<MachOImport>,
    over: bool,
    gaps: BTreeSet<String>,
    /// The bytes [`Imports::name`] may still scan, of [`MAX_NAME_SCAN`].
    scan: u64,
}

impl<'c> Imports<'c> {
    fn new(dylibs: &'c [Option<UntrustedText>], limit: u64) -> Imports<'c> {
        Imports {
            dylibs,
            limit,
            kept: BTreeSet::new(),
            over: false,
            gaps: BTreeSet::new(),
            scan: MAX_NAME_SCAN,
        }
    }

    fn gap(&mut self, gap: String) {
        self.gaps.insert(gap);
    }

    /// The name at `at` in `bytes`, which other names may share: its bytes up to its NUL. One
    /// byte past [`MAX_IMPORT_NAME`] is scanned at most (a longer name comes back that long, and
    /// [`Imports::keep`] refuses it), and [`MAX_NAME_SCAN`] bytes in all, after which no name is
    /// read.
    fn name<'b>(&mut self, bytes: &'b [u8], at: u64, outside: &'static str) -> Name<'b> {
        let Some(rest) = usize::try_from(at)
            .ok()
            .and_then(|at| bytes.get(at..))
            .filter(|rest| !rest.is_empty())
        else {
            return Name::Missing(outside);
        };
        let window = rest.len().min(MAX_IMPORT_NAME + 1);
        let allowed = window.min(usize::try_from(self.scan).unwrap_or(usize::MAX));
        let found = rest[..allowed].iter().position(|b| *b == 0);
        self.scan -= found.map_or(allowed, |end| end + 1) as u64;
        match found {
            Some(end) => Name::Read(&rest[..end]),
            None if allowed < window => Name::Exhausted,
            None if window < rest.len() || window > MAX_IMPORT_NAME => Name::Read(&rest[..window]),
            None => Name::Missing("a name without its NUL"),
        }
    }

    /// `name`, bound through library ordinal `ordinal`: 0 this image, from 1 a dylib in ordinal
    /// order, -1 the main executable, -2 flat lookup, -3 weak lookup. An ordinal past the dylibs,
    /// or another special one, binds nowhere (dyld refuses the image): a gap, and no import.
    fn bind(&mut self, name: &[u8], ordinal: i64, weak: bool) {
        let library = match ordinal {
            0 => MachOLibrary::SelfImage,
            -1 => MachOLibrary::MainExecutable,
            -2 => MachOLibrary::FlatLookup,
            -3 => MachOLibrary::WeakLookup,
            n if n >= 1 => {
                let dylib = usize::try_from(n - 1)
                    .ok()
                    .and_then(|i| self.dylibs.get(i))
                    .zip(u32::try_from(n).ok());
                // The gaps name no ordinal, so that a stream of them stays one gap.
                let Some((dylib, ordinal)) = dylib else {
                    self.gap(format!(
                        "imports: an ordinal past the {} dylibs",
                        self.dylibs.len()
                    ));
                    return;
                };
                MachOLibrary::Dylib {
                    ordinal,
                    name: dylib.clone(),
                }
            }
            _ => {
                self.gap("imports: an unknown special ordinal".to_string());
                return;
            }
        };
        self.keep(name, library, weak);
    }

    fn keep(&mut self, name: &[u8], library: MachOLibrary, weak: bool) {
        if name.len() > MAX_IMPORT_NAME {
            self.gap(format!("imports: a name over {MAX_IMPORT_NAME} bytes"));
            return;
        }
        self.kept.insert(MachOImport {
            name: UntrustedText::from_bytes(name.to_vec()),
            library,
            weak,
        });
        if self.kept.len() as u64 > self.limit {
            self.kept.pop_last();
            self.over = true;
        }
    }

    fn finish(mut self) -> (Vec<MachOImport>, Vec<String>) {
        if self.over {
            self.gaps.insert(imports_over_gap(self.limit));
        }
        (
            self.kept.into_iter().collect(),
            self.gaps.into_iter().collect(),
        )
    }
}

/// A name looked up by [`Imports::name`].
enum Name<'b> {
    Read(&'b [u8]),
    /// Not read, and why.
    Missing(&'static str),
    /// [`MAX_NAME_SCAN`] bytes were scanned: this name, and the later ones, are not read.
    Exhausted,
}

/// The NUL-terminated bytes at `at` in `bytes`.
fn c_string<'b>(bytes: &'b [u8], at: u64, outside: &'static str) -> Result<&'b [u8], &'static str> {
    let rest = usize::try_from(at)
        .ok()
        .and_then(|at| bytes.get(at..))
        .filter(|rest| !rest.is_empty())
        .ok_or(outside)?;
    let end = rest
        .iter()
        .position(|b| *b == 0)
        .ok_or("a name without its NUL")?;
    Ok(&rest[..end])
}

/// The imports table of `LC_DYLD_CHAINED_FIXUPS` (`dataoff`, `datasize`): dyld resolves every
/// import in it, whether or not a fixup chain uses it, so the chains are not walked.
fn chained<R: ReadCacheOps>(
    data: &Bounded<R>,
    base: u64,
    size: u64,
    order: ByteOrder,
    (dataoff, datasize): (u32, u32),
    out: &mut Imports<'_>,
) {
    let gap = |why: &str| format!("imports: chained fixups: {why}");
    // Chained fixups are little-endian (arm64 and x86_64 only).
    if matches!(order, ByteOrder::Big) {
        out.gap(gap("a big-endian image"));
        return;
    }
    let blob = match range(data, base, size, dataoff.into(), datasize.into()) {
        Ok(blob) => blob,
        Err(why) => {
            out.gap(gap(&why));
            return;
        }
    };
    let word = |at: u64| -> Option<u64> {
        let at = usize::try_from(at).ok()?;
        let bytes = blob.get(at..at.checked_add(4)?)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?).into())
    };
    let long = |at: u64| -> Option<u64> {
        let at = usize::try_from(at).ok()?;
        let bytes = blob.get(at..at.checked_add(8)?)?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    };
    // dyld_chained_fixups_header: fixups_version, starts_offset, imports_offset, symbols_offset,
    // imports_count, imports_format, symbols_format.
    let header: Option<Vec<u64>> = (0..7).map(|k| word(4 * k)).collect();
    let Some([version, _, imports_offset, symbols_offset, count, format, symbols_format]) =
        header.and_then(|h| <[u64; 7]>::try_from(h).ok())
    else {
        out.gap(gap("a header past the blob"));
        return;
    };
    if version != 0 {
        out.gap(gap(&format!("fixups_version {version} not read")));
        return;
    }
    if symbols_format != 0 {
        out.gap(gap(&format!(
            "symbols_format {symbols_format} not read (compressed)"
        )));
        return;
    }
    let entry = match format {
        1 => 4,
        2 => 8,
        3 => 16,
        _ => {
            out.gap(gap(&format!("imports_format {format} not read")));
            return;
        }
    };
    if imports_offset + count * entry > blob.len() as u64 {
        out.gap(gap("the imports past the blob"));
        return;
    }
    for k in 0..count {
        let at = imports_offset + k * entry;
        let (ordinal, weak, name_offset) = if format == 3 {
            // DYLD_CHAINED_IMPORT_ADDEND64: lib_ordinal:16, weak_import:1, reserved:15,
            // name_offset:32; then a 64-bit addend.
            let Some(v) = long(at) else { break };
            let lib = v & 0xffff;
            let ordinal = if lib > 0xfff0 {
                i64::from(lib as u16 as i16)
            } else {
                lib as i64
            };
            (ordinal, (v >> 16) & 1 == 1, v >> 32)
        } else {
            // DYLD_CHAINED_IMPORT(_ADDEND): lib_ordinal:8, weak_import:1, name_offset:23; the
            // addend after it.
            let Some(v) = word(at) else { break };
            let lib = v & 0xff;
            let ordinal = if lib > 0xf0 {
                i64::from(lib as u8 as i8)
            } else {
                lib as i64
            };
            (ordinal, (v >> 8) & 1 == 1, v >> 9)
        };
        match out.name(blob, symbols_offset + name_offset, "a name out of the blob") {
            Name::Read(name) => out.bind(name, ordinal, weak),
            Name::Missing(why) => out.gap(gap(why)),
            Name::Exhausted => {
                out.gap(gap(&format!("over {MAX_NAME_SCAN} bytes of names scanned")));
                break;
            }
        }
    }
}

/// The bind and lazy-bind streams of `LC_DYLD_INFO(_ONLY)`, each `(offset, size)`. The weak-bind
/// stream coalesces weak definitions by name, with no ordinal, so no capability would be looked up
/// in it: it is not read.
fn opcodes<R: ReadCacheOps>(
    data: &Bounded<R>,
    base: u64,
    size: u64,
    streams: [(u32, u32); 2],
    out: &mut Imports<'_>,
) {
    for (k, (offset, len)) in streams.into_iter().enumerate() {
        if len == 0 {
            continue;
        }
        let why = match range(data, base, size, offset.into(), len.into()) {
            Ok(stream) => binds(stream, k == 1, out).err(),
            Err(why) => Some(why),
        };
        if let Some(why) = why {
            out.gap(format!("imports: bind opcodes: {why}"));
        }
    }
}

/// The binds of one opcode stream (`<mach-o/loader.h>`), as dyld reads them: each `DO_BIND*`
/// binds the current name through the current ordinal, `DO_BIND_ULEB_TIMES_SKIPPING_ULEB` as many
/// times as its count says (none for 0). `DONE` ends the bind stream; in the lazy-bind stream
/// (`lazy`) it ends an entry, and the ordinal, name, and flags carry over to the next, as dyld4
/// and LLVM read them (Task 2 review). A stream stops at its first error; the binds before it are
/// kept.
fn binds(stream: &[u8], lazy: bool, out: &mut Imports<'_>) -> Result<(), String> {
    let mut at = 0usize;
    let mut ordinal: i64 = 0;
    let mut name: Option<&[u8]> = None;
    let mut weak = false;
    while let Some(&byte) = stream.get(at) {
        at += 1;
        let (opcode, imm) = (byte & 0xf0, byte & 0x0f);
        let bind = match opcode {
            // DONE
            0x00 if lazy => false,
            0x00 => return Ok(()),
            // SET_DYLIB_ORDINAL_IMM, _ULEB, SET_DYLIB_SPECIAL_IMM
            0x10 => {
                ordinal = imm.into();
                false
            }
            // dyld keeps the ULEB's low 32 bits, as an `int`.
            0x20 => {
                ordinal = i64::from(uleb(stream, &mut at)? as u32 as i32);
                false
            }
            0x30 => {
                ordinal = if imm == 0 {
                    0
                } else {
                    i64::from((0xf0 | imm) as i8)
                };
                false
            }
            // SET_SYMBOL_TRAILING_FLAGS_IMM: the name follows; flag 0x1 is a weak import.
            0x40 => {
                let symbol = c_string(stream, at as u64, "a name without its NUL")?;
                at += symbol.len() + 1;
                name = Some(symbol);
                weak = imm & 0x1 != 0;
                false
            }
            // SET_TYPE_IMM
            0x50 => false,
            // SET_ADDEND_SLEB
            0x60 => {
                sleb(stream, &mut at)?;
                false
            }
            // SET_SEGMENT_AND_OFFSET_ULEB, ADD_ADDR_ULEB
            0x70 | 0x80 => {
                uleb(stream, &mut at)?;
                false
            }
            // DO_BIND, DO_BIND_ADD_ADDR_IMM_SCALED
            0x90 | 0xb0 => true,
            // DO_BIND_ADD_ADDR_ULEB
            0xa0 => {
                uleb(stream, &mut at)?;
                true
            }
            // DO_BIND_ULEB_TIMES_SKIPPING_ULEB: a count, then a skip. dyld binds `count` times; a
            // name bound once is an import, and one bound 0 times is none (PR-4c-3b plan review
            // P2).
            0xc0 => {
                let count = uleb(stream, &mut at)?;
                uleb(stream, &mut at)?;
                count > 0
            }
            // THREADED: SET_BIND_ORDINAL_TABLE_SIZE_ULEB, APPLY.
            0xd0 if imm == 0x00 => {
                uleb(stream, &mut at)?;
                false
            }
            0xd0 if imm == 0x01 => false,
            _ => return Err(format!("an unknown opcode {byte:#04x}")),
        };
        if bind {
            let Some(symbol) = name else {
                return Err("a bind before any name".to_string());
            };
            out.bind(symbol, ordinal, weak);
        }
    }
    Ok(())
}

/// The ULEB128 at `at`, which it moves past.
fn uleb(stream: &[u8], at: &mut usize) -> Result<u64, String> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let Some(&byte) = stream.get(*at) else {
            return Err("a ULEB128 past the stream".to_string());
        };
        *at += 1;
        let low = u64::from(byte & 0x7f);
        if shift >= 64 {
            if low != 0 {
                return Err("a ULEB128 over 64 bits".to_string());
            }
        } else {
            if (low << shift) >> shift != low {
                return Err("a ULEB128 over 64 bits".to_string());
            }
            value |= low << shift;
        }
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift = shift.saturating_add(7);
    }
}

/// Moves `at` past the SLEB128 there, of at most ten bytes.
fn sleb(stream: &[u8], at: &mut usize) -> Result<(), String> {
    let mut shift = 0u32;
    loop {
        let Some(&byte) = stream.get(*at) else {
            return Err("an SLEB128 past the stream".to_string());
        };
        *at += 1;
        if shift >= 64 {
            return Err("an SLEB128 over 64 bits".to_string());
        }
        if byte & 0x80 == 0 {
            return Ok(());
        }
        shift += 7;
    }
}
