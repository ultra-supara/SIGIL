//! Known data symbols (spec §4.4): their value after loading, or `Unknown` with the reason.
//! Never the stored word as a guess: a word some relocation rewrites at load is not a value.

use std::collections::BTreeSet;

use object::elf;
use object::read::elf::{FileHeader, SectionHeader, Sym, SymbolTable};
use object::read::{ReadCacheOps, ReadRef};
use object::Endianness;
use sigil_model::{DataSymbol, DataValue, Loc, UntrustedText};

use super::elf::{Dynamic, Elf, Reloc};
use super::read::Bounded;
use super::vaddr::Place;

/// How a known symbol is typed (llama.cpp `common/build-info.cpp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Int,
    Str,
}

/// The built-in list, by name.
pub const KNOWN: &[(&str, Kind)] = &[
    ("LLAMA_BUILD_NUMBER", Kind::Int),
    ("LLAMA_BUILD_TARGET", Kind::Str),
    ("LLAMA_COMMIT", Kind::Str),
    ("LLAMA_COMPILER", Kind::Str),
];

/// The longest string read (bytes before the NUL).
pub const MAX_STRING: u64 = 256;

pub(crate) fn read<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &mut Elf<'d, R, H>,
    symbols: &SymbolTable<'d, H, &'d Bounded<R>>,
    dynamic: &Dynamic,
) -> Vec<DataSymbol> {
    let endian = e.endian;
    let machine = e.header.e_machine(endian);
    // At most one entry per known name: a name defined twice has no single value.
    let mut found: Vec<(&str, Kind, u64, u64, elf::SymbolType)> = vec![];
    let mut twice: BTreeSet<&str> = BTreeSet::new();
    let mut unnamed = None;
    // The symbols' string table, read for names no longer than the longest known one.
    let strings = e
        .header
        .sections(endian, e.data)
        .ok()
        .and_then(|t| t.section(symbols.string_section()).ok())
        .and_then(|s| s.file_range(endian));
    let longest = KNOWN.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
    for sym in symbols.symbols() {
        // Every defined symbol, whatever its type: a known name defined twice has no single
        // value, even if one definition is a function (spec §3.3).
        if sym.st_shndx(endian) == elf::SHN_UNDEF {
            continue;
        }
        // A name that cannot be read could be a known one: a gap, never a silent skip.
        let read = match strings {
            Some(strings) => e.name(strings, sym.st_name(endian), longest),
            None => Err("no string table in the file".to_string()),
        };
        let name = match read {
            Ok(Some(name)) => name,
            // Longer than every known name.
            Ok(None) => continue,
            Err(why) => {
                unnamed.get_or_insert(why);
                continue;
            }
        };
        if let Some((n, kind)) = KNOWN.iter().find(|(n, _)| n.as_bytes() == name) {
            if found.iter().any(|f| f.0 == *n) {
                twice.insert(n);
                continue;
            }
            let addr: u64 = sym.st_value(endian).into();
            let size: u64 = sym.st_size(endian).into();
            found.push((n, *kind, addr, size, sym.st_type()));
        }
    }
    if let Some(why) = unnamed {
        e.gaps.push(format!(
            "malformed: symbols: a defined symbol's name: {why}"
        ));
    }
    if found.is_empty() {
        return vec![];
    }
    // A relocatable object's data is not linked yet: no value can be read (PR-4b-2a).
    let relocatable = e.header.e_type(endian) == elf::ET_REL;
    // The bytes each value is read from: an integer's, or a string pointer's word (spec §3.4).
    let word = if e.header.is_type_64() { 8 } else { 4 };
    let ranges: Vec<(u64, u64)> = found
        .iter()
        .map(|&(_, kind, addr, size, _)| {
            let len = match kind {
                Kind::Int => size,
                Kind::Str => word,
            };
            (addr, addr.saturating_add(len))
        })
        .collect();
    let relocs = if relocatable {
        Ok(vec![vec![]; found.len()])
    } else {
        e.relocations(dynamic, &ranges)
    };
    let mut out = vec![];
    // The strings read as values: (index in `out`, the string's bytes and its NUL).
    let mut texts: Vec<(usize, (u64, u64))> = vec![];
    for (i, (name, kind, addr, size, st_type)) in found.into_iter().enumerate() {
        let value = match &relocs {
            _ if twice.contains(name) => Err("defined more than once".to_string()),
            _ if st_type != elf::STT_OBJECT => {
                Err(format!("not a data object ({})", symbol_type(st_type)))
            }
            _ if relocatable => Err("not linked yet (a relocatable object)".to_string()),
            Err(why) => Err(format!("relocations not read: {why}")),
            Ok(hits) => value(e, kind, addr, size, &hits[i], dynamic),
        };
        let mut at = vec![Loc::Symbol(UntrustedText::new(name))];
        let value = match value {
            Ok((v, more)) => {
                if let (DataValue::Text(text), [Loc::VAddr(ptr)]) = (&v, more.as_slice()) {
                    let end = ptr.saturating_add(text.as_bytes().len() as u64 + 1);
                    texts.push((out.len(), (*ptr, end)));
                }
                at.extend(more);
                v
            }
            Err(why) => {
                e.gaps.push(format!("{name}: {why}"));
                DataValue::Unknown { why }
            }
        };
        out.push(DataSymbol {
            symbol: name.to_string(),
            value,
            at,
        });
    }
    // A relocation that writes into a string read as a value: the loaded string is another one.
    if !texts.is_empty() {
        let ranges: Vec<(u64, u64)> = texts.iter().map(|t| t.1).collect();
        let hits = e.relocations(dynamic, &ranges);
        for (j, (index, _)) in texts.iter().enumerate() {
            let why = match &hits {
                Ok(hits) => match hits[j].first() {
                    Some((_, t, _)) => format!(
                        "a relocation writes into the string ({})",
                        type_name(machine, *t)
                    ),
                    None => continue,
                },
                Err(why) => format!("relocations not read: {why}"),
            };
            let d = &mut out[*index];
            e.gaps.push(format!("{}: {why}", d.symbol));
            d.value = DataValue::Unknown { why };
            d.at.truncate(1);
        }
    }
    out.sort_by(|a, b| a.symbol.cmp(&b.symbol));
    out
}

/// The RELATIVE relocation type of the file's machine, if SIGIL reads its relocations.
fn relative_type(machine: elf::Machine) -> Option<u32> {
    match machine {
        elf::EM_X86_64 => Some(elf::R_X86_64_RELATIVE.0),
        elf::EM_AARCH64 => Some(elf::R_AARCH64_RELATIVE.0),
        _ => None,
    }
}

/// A relocation type's name, for the reason.
fn type_name(machine: elf::Machine, t: u32) -> String {
    let name = match (machine, t) {
        (elf::EM_X86_64, 1) => "R_X86_64_64",
        (elf::EM_X86_64, 6) => "R_X86_64_GLOB_DAT",
        (elf::EM_X86_64, 7) => "R_X86_64_JUMP_SLOT",
        (elf::EM_X86_64, 8) => "R_X86_64_RELATIVE",
        (elf::EM_AARCH64, 257) => "R_AARCH64_ABS64",
        (elf::EM_AARCH64, 1025) => "R_AARCH64_GLOB_DAT",
        (elf::EM_AARCH64, 1026) => "R_AARCH64_JUMP_SLOT",
        (elf::EM_AARCH64, 1027) => "R_AARCH64_RELATIVE",
        _ => return format!("type {t}"),
    };
    name.to_string()
}

/// A symbol type's name, for the reason.
fn symbol_type(t: elf::SymbolType) -> String {
    let name = match t {
        elf::STT_NOTYPE => "STT_NOTYPE",
        elf::STT_OBJECT => "STT_OBJECT",
        elf::STT_FUNC => "STT_FUNC",
        elf::STT_SECTION => "STT_SECTION",
        elf::STT_FILE => "STT_FILE",
        elf::STT_COMMON => "STT_COMMON",
        elf::STT_TLS => "STT_TLS",
        elf::STT_GNU_IFUNC => "STT_GNU_IFUNC",
        _ => return format!("type {}", t.0),
    };
    name.to_string()
}

/// One symbol's value after loading (spec §4.4 of PR-4b-1; §3.4): `relocs` are the relocations
/// over its bytes.
fn value<R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &mut Elf<'_, R, H>,
    kind: Kind,
    addr: u64,
    size: u64,
    relocs: &[Reloc],
    dynamic: &Dynamic,
) -> Result<(DataValue, Vec<Loc>), String> {
    let machine = e.header.e_machine(e.endian);
    // SIGIL does not apply REL or RELR, and they may write these bytes too (musl applies RELR
    // after RELA).
    if dynamic.rel_or_relr {
        return Err("REL/RELR relocations are not read".to_string());
    }
    let pointer = match (kind, relocs) {
        (_, [_, ..]) if relative_type(machine).is_none() => {
            return Err(format!("relocations of machine {} are not read", machine.0));
        }
        (Kind::Str, [(at, t, addend)]) if *at == addr && Some(*t) == relative_type(machine) => {
            u64::try_from(*addend).map_err(|_| "a negative addend".to_string())?
        }
        (_, [(at, t, _)]) if *at == addr => {
            return Err(format!("relocated by {}", type_name(machine, *t)))
        }
        (_, [(_, t, _)]) => {
            return Err(format!(
                "a relocation overlaps it ({})",
                type_name(machine, *t)
            ))
        }
        (_, [_, _, ..]) => return Err("relocated more than once".to_string()),
        (Kind::Int, []) => return int(e, addr, size).map(|v| (v, vec![])),
        (Kind::Str, []) if e.header.e_type(e.endian) == elf::ET_EXEC => stored_word(e, addr)?,
        (Kind::Str, []) => return Err("no relocation in a position-independent file".to_string()),
    };
    if pointer == 0 {
        return Err("a null pointer".to_string());
    }
    let text = string(e, pointer)?;
    Ok((DataValue::Text(text), vec![Loc::VAddr(pointer)]))
}

/// `size` bytes at `addr`, signed, in the file's byte order.
fn int<R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'_, R, H>,
    addr: u64,
    size: u64,
) -> Result<DataValue, String> {
    if size != 4 && size != 8 {
        return Err(format!("size {size}"));
    }
    let bytes = file_bytes(e, addr, size)?;
    let big = e.endian == Endianness::Big;
    let v = match (size, big) {
        (4, false) => i64::from(i32::from_le_bytes(word(bytes)?)),
        (4, true) => i64::from(i32::from_be_bytes(word(bytes)?)),
        (_, false) => i64::from_le_bytes(word(bytes)?),
        (_, true) => i64::from_be_bytes(word(bytes)?),
    };
    Ok(DataValue::Int(v))
}

fn word<const N: usize>(bytes: &[u8]) -> Result<[u8; N], String> {
    bytes.try_into().map_err(|_| "a short read".to_string())
}

/// The pointer-sized word at `addr` (a non-PIE executable's absolute pointer).
fn stored_word<R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'_, R, H>,
    addr: u64,
) -> Result<u64, String> {
    let big = e.endian == Endianness::Big;
    if e.header.is_type_64() {
        let b = word::<8>(file_bytes(e, addr, 8)?)?;
        Ok(if big {
            u64::from_be_bytes(b)
        } else {
            u64::from_le_bytes(b)
        })
    } else {
        let b = word::<4>(file_bytes(e, addr, 4)?)?;
        Ok(u64::from(if big {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        }))
    }
}

/// `len` bytes at virtual address `addr`, from the file only.
fn file_bytes<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'d, R, H>,
    addr: u64,
    len: u64,
) -> Result<&'d [u8], String> {
    match e.loads.place(addr, len) {
        Place::File(off) => e
            .data
            .read_bytes_at(off, len)
            .map_err(|()| "outside the file or over the budget".to_string()),
        Place::ZeroFill => Err("in zero-fill memory".to_string()),
        Place::Unmapped => Err("outside every PT_LOAD".to_string()),
    }
}

/// The NUL-terminated string at `ptr`, at most `MAX_STRING` bytes, UTF-8.
fn string<R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'_, R, H>,
    ptr: u64,
) -> Result<UntrustedText, String> {
    let off = match e.loads.place(ptr, 1) {
        Place::File(off) => off,
        Place::ZeroFill => return Err("in zero-fill memory".to_string()),
        Place::Unmapped => return Err("outside every PT_LOAD".to_string()),
    };
    // The string may not run past the end of its segment's file-backed range.
    let end = e
        .loads
        .0
        .iter()
        .filter_map(|l| {
            let file_end = l.vaddr.checked_add(l.filesz)?;
            (ptr >= l.vaddr && ptr < file_end).then(|| l.offset.checked_add(l.filesz))?
        })
        .next()
        .ok_or("outside every PT_LOAD")?;
    let limit = off.saturating_add(MAX_STRING + 1).min(end);
    let bytes = e
        .data
        .read_bytes_at_until(off..limit, 0)
        .map_err(|()| "a string over 256 bytes, without NUL, or outside the file".to_string())?;
    let text = std::str::from_utf8(bytes).map_err(|_| "a string that is not UTF-8".to_string())?;
    Ok(UntrustedText::new(text))
}
