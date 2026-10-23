//! What known exported functions return (PR-4c-2b spec §2): the constant string whose address a
//! straight-line function leaves in `rax`. The function is decoded with PR-5a's decoder and its
//! values followed with PR-5a's value machine; it is never run. Its bytes and the string are read
//! with `pread` through the scan's charged reader (`binary_scan_bytes`).

use std::collections::BTreeMap;
use std::ops::ControlFlow;

use iced_x86::Mnemonic;
use object::elf;
use object::read::elf::{FileHeader, SymbolTable};
use object::read::ReadCacheOps;
use object::{Endian, Endianness};
use sigil_model::{DataValue, FunctionReturn, Loc, UntrustedText};

use super::data::{symbol_type, MAX_STRING};
use super::elf::{Dynamic, Elf};
use super::read::Bounded;
use crate::code::decode::decode;
use crate::code::image::{overlapped_pages, regions, Image, Kind};
use crate::code::reader::{Reader, Refusal};
use crate::code::value::{entry_state, Machine, Val, RAX};
use crate::code::{CodeBudgets, Run};

/// The longest function read, in bytes: a constant return is a few instructions (17 bytes with
/// `endbr64` and a frame pointer).
pub const MAX_FUNCTION: u64 = 64;

/// The reason of a value not read because the scan reached `binary_scan_bytes`.
pub const OVER_BUDGET: &str = "not read: binary_scan_bytes exceeded";

/// One definition of a known function among the exports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Definition {
    pub value: u64,
    pub size: u64,
    pub st_type: elf::SymbolType,
}

/// The return of each known function in `defined` (its definitions among the exports, at most
/// two kept), in name order: the string it returns, or `Unknown` with the reason.
pub(crate) fn read<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'d, R, H>,
    symbols: &SymbolTable<'d, H, &'d Bounded<R>>,
    dynamic: &Dynamic,
    reader: &mut Reader<'_>,
    defined: &BTreeMap<String, Vec<Definition>>,
) -> Vec<FunctionReturn> {
    defined
        .iter()
        .map(|(function, defs)| {
            let symbol = Loc::Symbol(UntrustedText::new(function.as_str()));
            match string(e, symbols, dynamic, reader, defs) {
                Ok((text, at)) => FunctionReturn {
                    function: function.clone(),
                    value: DataValue::Text(UntrustedText::from_bytes(text)),
                    at: vec![symbol, Loc::VAddr(at)],
                },
                Err(why) => FunctionReturn {
                    function: function.clone(),
                    value: DataValue::Unknown { why },
                    at: vec![symbol],
                },
            }
        })
        .collect()
}

/// The string the function `defs` defines returns, and its address. In order: an x86-64 ELF64
/// little-endian file; one definition, a function of 1 to [`MAX_FUNCTION`] bytes inside an
/// executable segment's file bytes (minus pages two segments share); no `DT_REL`; one block
/// ending in `ret`, decoded; `rax` at its end an address a `lea` formed; inside a segment neither
/// writable nor executable; a NUL within [`MAX_STRING`] bytes; and no relocation writing the
/// function's bytes or the string's.
fn string<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'d, R, H>,
    symbols: &SymbolTable<'d, H, &'d Bounded<R>>,
    dynamic: &Dynamic,
    reader: &mut Reader<'_>,
    defs: &[Definition],
) -> Result<(Vec<u8>, u64), String> {
    let endian = e.endian;
    if e.header.e_machine(endian) != elf::EM_X86_64
        || !e.header.is_class_64()
        || !endian.is_little_endian()
    {
        return Err("not decoded: x86-64 only".to_string());
    }
    let [d] = defs else {
        return Err("defined more than once".to_string());
    };
    if d.st_type != elf::STT_FUNC {
        return Err(format!("not a function ({})", symbol_type(d.st_type)));
    }
    if d.size == 0 {
        return Err("size not recorded".to_string());
    }
    if d.size > MAX_FUNCTION {
        return Err(format!("longer than {MAX_FUNCTION} bytes"));
    }
    let outside = || "not in an executable segment".to_string();
    let end = d.value.checked_add(d.size).ok_or_else(outside)?;
    let shared = overlapped_pages(&e.loads);
    let code = regions(&e.loads, |l| l.executable, &shared);
    let region = code
        .iter()
        .find(|r| r.holds(d.value, end))
        .ok_or_else(outside)?;
    // musl applies DT_REL on x86-64 (glibc does not); SIGIL does not read it, as in PR-5a.
    if dynamic.rel.is_some() || dynamic.jmprel_rel.is_some() {
        return Err("DT_REL relocations are not modeled".to_string());
    }
    let bytes = charged(reader, region.offset_of(d.value), d.size)?;
    let kind = if e.header.e_type(endian) == elf::ET_EXEC {
        Kind::Executable
    } else {
        Kind::Shared
    };
    let img = Image::empty(kind);
    let mut run = Run::new(CodeBudgets::default());
    let cfg = decode(
        &bytes,
        d.value,
        end,
        &img,
        &|i| Some(i.ins.near_branch_target()),
        &|_| false,
        &mut run,
    )
    .map_err(|f| f.reason(d.value))?;
    let block = match (cfg.blocks.len(), cfg.blocks.get(&d.value)) {
        (1, Some(b))
            if cfg
                .insns
                .get(&b.last)
                .is_some_and(|i| i.ins.mnemonic() == Mnemonic::Ret) =>
        {
            b
        }
        _ => return Err("not one straight block ending in ret".to_string()),
    };
    let mut machine = Machine::new(&img);
    let mut state = entry_state();
    for (_, insn) in cfg.block_insns(d.value, block) {
        machine.step(&mut state, insn);
    }
    let Val::Const {
        value: at,
        address: true,
    } = state[RAX]
    else {
        return Err("returns no constant string address".to_string());
    };
    let strings = regions(&e.loads, |l| !l.writable && !l.executable, &shared);
    let r = strings
        .iter()
        .find(|r| r.start <= at && at < r.end)
        .ok_or("its string is not in read-only data")?;
    let bytes = charged(reader, r.offset_of(at), (r.end - at).min(MAX_STRING + 1))?;
    let nul = bytes
        .iter()
        .position(|b| *b == 0)
        .ok_or(format!("its string has no NUL within {MAX_STRING} bytes"))?;
    let text = bytes.get(..nul).unwrap_or_default().to_vec();
    let ranges = [(d.value, end), (at, at.saturating_add(nul as u64 + 1))];
    match written(e, symbols, dynamic, &ranges)? {
        [true, _] => Err("a relocation writes its code".to_string()),
        [_, true] => Err("a relocation writes its string".to_string()),
        _ => Ok((text, at)),
    }
}

/// `len` bytes at `offset`, charged to the scan's budget first.
fn charged(reader: &mut Reader<'_>, offset: u64, len: u64) -> Result<Vec<u8>, String> {
    reader.read(offset, len).map_err(|why| match why {
        Refusal::Budget => OVER_BUDGET.to_string(),
        Refusal::OutsideFile | Refusal::Io | Refusal::TooLarge(_) => "a read failed".to_string(),
    })
}

/// Whether a RELA or RELR relocation the loader applies writes a byte of each of the two
/// `ranges` (`[start, end)`).
fn written<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'d, R, H>,
    symbols: &SymbolTable<'d, H, &'d Bounded<R>>,
    dynamic: &Dynamic,
    ranges: &[(u64, u64); 2],
) -> Result<[bool; 2], String> {
    let unread = |why: String| format!("relocations not read: {why}");
    let hits = e.relocations(dynamic, symbols, ranges).map_err(unread)?;
    let mut out = [false; 2];
    for (w, hit) in out.iter_mut().zip(&hits) {
        *w = !hit.is_empty();
    }
    let word = if e.header.is_type_64() { 8 } else { 4 };
    e.for_each_relr(dynamic, |entry| {
        for (lo, hi) in entry.words(word) {
            for (w, (start, end)) in out.iter_mut().zip(ranges) {
                if lo < *end && *start < hi {
                    *w = true;
                }
            }
        }
        ControlFlow::Continue(())
    })
    .map_err(unread)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn a_refused_read_is_the_budget_or_a_failed_read() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&[1, 2, 3, 4]).unwrap();
        let mut reader = Reader::new(f.as_file(), 4, 3);
        assert_eq!(charged(&mut reader, 0, 2), Ok(vec![1, 2]));
        assert_eq!(charged(&mut reader, 2, 2), Err(OVER_BUDGET.to_string()));
        assert_eq!(charged(&mut reader, 3, 2), Err("a read failed".to_string()));
        // A size the file does not have: the `pread` comes up short.
        let mut reader = Reader::new(f.as_file(), 100, 100);
        assert_eq!(charged(&mut reader, 2, 8), Err("a read failed".to_string()));
    }
}
