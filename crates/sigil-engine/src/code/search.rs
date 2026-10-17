//! References to the capability imports, and their confirmation (PR-5a spec §4.4).
//!
//! - [`references`]: a relocatable object's relocations against a target; a linked file's
//!   candidates in the scanned bytes ([`scan_ranges`]), read in chunks.
//! - [`confirm`]: each reference's function is decoded from its FDE start, its values solved, and
//!   its calls recorded ([`Recorder::function`]); then each reference is a call, a value that is
//!   called, a coincidence (nothing), or a gap.

use std::collections::BTreeMap;

use iced_x86::{Mnemonic, OpKind, Register};

use super::data::Signatures;
use super::decode::{self, Insn};
use super::image::{FdeAt, Image, Kind, Meaning, Name, Region, Use};
use super::reader::Reader;
use super::record::{self, Consumed, Recorder};
use super::{value, Run, FDE_BYTES};

/// Bytes read per chunk of the scan (spec §4.4), each chunk read with the next 8 bytes too.
pub(crate) const CHUNK: u64 = 1 << 20;

/// The bytes a chunk is read past its end: a field that starts in the chunk is read whole.
const OVERLAP: u64 = 8;

/// A reference to a capability import, at a field's position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reference {
    pub at: u64,
    pub symbol: Name,
}

fn shown(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

/// The addresses that name a target in a linked file: its GOT slots, and the stubs on them.
fn target_addresses(img: &Image) -> BTreeMap<u64, Name> {
    let mut out = BTreeMap::new();
    for (slot, sym) in &img.slots {
        if img.is_target(sym) {
            out.insert(*slot, sym.name.clone());
        }
    }
    for (stub, (slot, _)) in &img.stubs {
        if let Some(name) = out.get(slot).cloned() {
            out.insert(*stub, name);
        }
    }
    out
}

/// `[start, end)` ranges, empty ones dropped, sorted and merged where they meet.
fn merge(mut v: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    v.retain(|r| r.0 < r.1);
    v.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(v.len());
    for (s, e) in v {
        match out.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

/// `parts` (sorted and disjoint) minus `cut`.
fn without(parts: Vec<(u64, u64)>, cut: (u64, u64)) -> Vec<(u64, u64)> {
    let (cs, ce) = cut;
    let mut out = Vec::with_capacity(parts.len() + 1);
    for (s, e) in parts {
        if ce <= s || e <= cs {
            out.push((s, e));
            continue;
        }
        if s < cs {
            out.push((s, cs));
        }
        if ce < e {
            out.push((ce, e));
        }
    }
    out
}

/// The scanned bytes (spec §4.4): (`SHF_EXECINSTR` sections ∪ FDE ranges) ∩ code, minus the PLT
/// sections, **per code region**. A range never spans two regions, even adjacent ones, because
/// each region has its own file offset (plan review P1-2). Sorted, by region.
pub(crate) fn scan_ranges(img: &Image) -> Vec<(Region, u64, u64)> {
    let wanted = merge(
        img.sections
            .iter()
            .chain(img.fdes.iter())
            .copied()
            .collect(),
    );
    let mut out = vec![];
    for r in &img.code {
        let first = wanted.partition_point(|w| w.1 <= r.start);
        let mut parts: Vec<(u64, u64)> = wanted
            .get(first..)
            .unwrap_or_default()
            .iter()
            .take_while(|w| w.0 < r.end)
            .map(|(ws, we)| ((*ws).max(r.start), (*we).min(r.end)))
            .filter(|(s, e)| s < e)
            .collect();
        for plt in &img.plt {
            parts = without(parts, *plt);
        }
        out.extend(parts.into_iter().map(|(s, e)| (*r, s, e)));
    }
    out
}

/// The references of `img`, at most `run.budgets.references` (spec §4.4, §4.10); at the limit the
/// search stops and the run with it. Sorted by position, one per position.
/// - A relocatable object: every relocation on code against a target, either one of a field's
///   two included ([`super::image::Reloc::each`]).
/// - A linked file: every candidate in the scanned bytes ([`scan_ranges`]), read in chunks of
///   [`CHUNK`] bytes plus [`OVERLAP`]: a `disp32`/`rel32` at `p` with `p + 4 + k + v` a target
///   stub or slot for `k` in {0, 1, 2, 4} (a branch is `k = 0`, R-g), and in an executable the
///   4- or 8-byte value at `p` equal to one.
pub(crate) fn references(img: &Image, reader: &mut Reader<'_>, run: &mut Run) -> Vec<Reference> {
    let limit = run.budgets.references;
    let mut found: Vec<Reference> = vec![];
    if img.kind == Kind::Relocatable {
        for (p, r) in &img.relocs {
            let target = r.each().find_map(|f| {
                img.rel_syms
                    .get(&f.sym)
                    .and_then(|s| s.name.as_ref())
                    .filter(|n| img.targets.contains(*n))
            });
            let Some(name) = target else {
                continue;
            };
            if found.len() >= limit {
                run.limit("references", limit as u64);
                break;
            }
            found.push(Reference {
                at: *p,
                symbol: name.clone(),
            });
        }
        return found;
    }
    let targets = target_addresses(img);
    let (Some(lo), Some(hi)) = (
        targets.keys().next().copied(),
        targets.keys().next_back().copied(),
    ) else {
        return found;
    };
    // Almost no position computes an address in [lo, hi]: those alone are looked up.
    let hit = |t: u64| {
        if t < lo || t > hi {
            None
        } else {
            targets.get(&t)
        }
    };
    let executable = img.kind == Kind::Executable;
    'ranges: for (region, s, e) in scan_ranges(img) {
        let mut pos = s;
        while pos < e {
            let end = pos.saturating_add(CHUNK).min(e);
            let read_end = end.saturating_add(OVERLAP).min(e);
            let bytes = match reader.read(region.offset_of(pos), read_end - pos) {
                Ok(b) => b,
                Err(why) => {
                    run.refusal(why, &format!("code at {pos:#x}"), reader);
                    if run.stopped() {
                        break 'ranges;
                    }
                    pos = end;
                    continue;
                }
            };
            for (i, p) in (pos..end).enumerate() {
                let w4 = bytes
                    .get(i..i.saturating_add(4))
                    .and_then(|w| <[u8; 4]>::try_from(w).ok());
                let mut name = None;
                if let Some(w) = w4 {
                    let v = i64::from(i32::from_le_bytes(w));
                    name = [0_i64, 1, 2, 4]
                        .into_iter()
                        .find_map(|k| hit((p as i64).wrapping_add(4 + k).wrapping_add(v) as u64));
                    if name.is_none() && executable {
                        name = hit(u64::from(u32::from_le_bytes(w)));
                    }
                }
                if name.is_none() && executable {
                    name = bytes
                        .get(i..i.saturating_add(8))
                        .and_then(|w| <[u8; 8]>::try_from(w).ok())
                        .and_then(|w| hit(u64::from_le_bytes(w)));
                }
                if let Some(name) = name {
                    if found.len() >= limit {
                        run.limit("references", limit as u64);
                        break 'ranges;
                    }
                    found.push(Reference {
                        at: p,
                        symbol: name.clone(),
                    });
                }
            }
            pos = end;
        }
    }
    found
}

/// The field of an instruction that starts at a reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    /// A near branch's `rel32`.
    Branch,
    /// A memory operand's 4- or 8-byte displacement.
    Disp,
    /// A 4- or 8-byte immediate.
    Imm,
}

/// Which field of `insn` starts at `p`, if one does.
fn field_at(insn: &Insn, p: u64) -> Option<Field> {
    let rel = p.checked_sub(insn.ins.ip())?;
    let o = &insn.offs;
    if o.has_immediate() && o.immediate_offset() as u64 == rel {
        let size = o.immediate_size();
        if size == 4 && insn.ins.op_count() >= 1 && insn.ins.op0_kind() == OpKind::NearBranch64 {
            return Some(Field::Branch);
        }
        if size == 4 || size == 8 {
            return Some(Field::Imm);
        }
    }
    if o.has_displacement()
        && o.displacement_offset() as u64 == rel
        && matches!(o.displacement_size(), 4 | 8)
    {
        return Some(Field::Disp);
    }
    None
}

/// The value of `insn`'s 4- or 8-byte immediate operand, as the instruction uses it
/// (sign-extended where it is).
fn immediate(insn: &Insn) -> Option<u64> {
    let ins = &insn.ins;
    (0..ins.op_count()).find_map(|k| match ins.try_op_kind(k).ok()? {
        OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate32to64 => {
            ins.try_immediate(k).ok()
        }
        _ => None,
    })
}

/// What one reference is, once its function is decoded.
enum Class {
    /// These bytes belong to another field or instruction: nothing is recorded.
    Coincidence,
    /// Unexplained: the gap.
    Gap(String),
    /// It names the target, in the instruction at this address: a call, or a value that may be
    /// called.
    Confirmed(u64),
}

/// What the reference `r`, on a decoded instruction of the function at `entry` (or not), is.
fn classify(r: &Reference, cfg: &decode::Cfg, img: &Image, targets: &BTreeMap<u64, Name>) -> Class {
    let name = shown(&r.symbol);
    let p = r.at;
    let Some((&ip, insn)) = cfg
        .insns
        .range(..=p)
        .next_back()
        .filter(|(_, i)| i.ins.next_ip() > p)
    else {
        return Class::Gap(format!(
            "code: {name} referenced at {p:#x}: not on an instruction decoded from {:#x}",
            cfg.entry
        ));
    };
    let field = field_at(insn, p);
    let base = insn.ins.memory_base();
    if img.kind == Kind::Relocatable {
        let use_ = match field {
            Some(Field::Branch) => Use::Branch,
            Some(Field::Disp) if base == Register::RIP && insn.ins.mnemonic() == Mnemonic::Lea => {
                Use::Lea
            }
            Some(Field::Disp) if base == Register::RIP => Use::Memory,
            Some(Field::Disp) => Use::Absolute,
            Some(Field::Imm) => Use::Immediate,
            None => {
                return Class::Gap(format!(
                    "code: {name}: relocation at {p:#x} not on an instruction field"
                ))
            }
        };
        return match img.field(p, insn.ins.next_ip(), use_) {
            Some(Meaning::Unknown { symbol, why }) => Class::Gap(format!(
                "code: {name}: {} at {p:#x}",
                why.shown(symbol.as_ref())
            )),
            _ => Class::Confirmed(ip),
        };
    }
    // An absolute value names an address only in an executable: anywhere else the load base is
    // added at run time (and a text relocation is its own gap).
    let absolute = img.kind == Kind::Executable;
    let points = match field {
        Some(Field::Branch) => Some(insn.ins.near_branch_target()),
        Some(Field::Disp) if base == Register::RIP => Some(insn.ins.ip_rel_memory_address()),
        Some(Field::Disp) if base == Register::None && absolute => {
            Some(insn.ins.memory_displacement64())
        }
        Some(Field::Imm) if absolute => immediate(insn),
        _ => None,
    };
    match points {
        Some(t) if targets.contains_key(&t) => Class::Confirmed(ip),
        _ => Class::Coincidence,
    }
}

/// Confirms each reference by decoding its function (spec §4.4) and records the calls
/// ([`Recorder::function`]). Each reference ends as a call, a value that is called, a coincidence,
/// or a gap: outside any FDE, in an overlap of FDEs, its function not decoded (and why), not on
/// a decoded instruction, a relocation not modeled, or an address taken. Once the run stops,
/// every reference not yet confirmed is a gap.
pub(crate) fn confirm(
    img: &Image,
    refs: Vec<Reference>,
    sig: &Signatures,
    reader: &mut Reader<'_>,
    run: &mut Run,
    rec: &mut Recorder,
) {
    let targets = target_addresses(img);
    let mut by_fde: BTreeMap<(u64, u64), Vec<Reference>> = BTreeMap::new();
    for r in refs {
        match img.fde_at(r.at) {
            FdeAt::None => run.gap(format!(
                "code: {} referenced at {:#x} outside any FDE",
                shown(&r.symbol),
                r.at
            )),
            FdeAt::One(f) => by_fde.entry(f).or_default().push(r),
            FdeAt::Overlap => run.gap(format!(
                "code: {} referenced at {:#x}: FDEs overlap there",
                shown(&r.symbol),
                r.at
            )),
        }
    }
    const STOPPED: &str = "not confirmed: a limit was reached";
    for ((start, end), refs) in by_fde {
        let gap_all = |run: &mut Run, why: &str| {
            for r in &refs {
                run.gap(format!(
                    "code: {} referenced at {:#x}: {why}",
                    shown(&r.symbol),
                    r.at
                ));
            }
        };
        if run.stopped() {
            gap_all(run, STOPPED);
            continue;
        }
        let Some(region) = img.code_at(start, end).copied() else {
            gap_all(
                run,
                &format!("FDE {start:#x}..{end:#x} outside executable code"),
            );
            continue;
        };
        if end - start > FDE_BYTES {
            gap_all(
                run,
                &format!("function at {start:#x}: {} bytes", end - start),
            );
            continue;
        }
        let what = format!("function at {start:#x}");
        let bytes = match reader.read(region.offset_of(start), end - start) {
            Ok(b) => b,
            Err(why) => {
                run.refusal(why, &what, reader);
                let why = if run.stopped() {
                    STOPPED.to_string()
                } else {
                    format!("{what} not read")
                };
                gap_all(run, &why);
                continue;
            }
        };
        let bt = |insn: &Insn| record::branch_target(insn, img);
        let nr = |insn: &Insn| record::noreturn(insn, img, sig);
        let solved = decode::decode(&bytes, start, end, img, &bt, &nr, run)
            .and_then(|cfg| value::solve(&cfg, img).map(|values| (cfg, values)));
        drop(bytes);
        let (cfg, values) = match solved {
            Ok(s) => s,
            Err(f) => {
                gap_all(run, &f.reason(start));
                continue;
            }
        };
        let consumed = rec.function(&cfg, &values, img, sig, reader, run);
        for r in &refs {
            let ip = match classify(r, &cfg, img, &targets) {
                Class::Coincidence => continue,
                Class::Gap(gap) => {
                    run.gap(gap);
                    continue;
                }
                Class::Confirmed(ip) => ip,
            };
            let name = shown(&r.symbol);
            match &consumed {
                // §4.7's strict reading: an address that is called and also passed on is taken.
                Some(Consumed { called, escaped })
                    if !called.contains(&ip) || escaped.contains(&ip) =>
                {
                    run.gap(format!(
                        "code: {name}: address taken at {:#x}, not traced to a call",
                        r.at
                    ))
                }
                Some(_) => {}
                None if run.stopped() => {
                    run.gap(format!("code: {name} referenced at {:#x}: {STOPPED}", r.at))
                }
                // Not recorded, with its gap (an entry or a call site already recorded).
                None => run.gap(format!(
                    "code: {name} referenced at {:#x}: function at {start:#x} not recorded",
                    r.at
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::data::signatures;
    use crate::code::image::{Image, Kind, Region, Sym};
    use crate::code::{CodeBudgets, Run};
    use sigil_model::ImportVia;
    use std::io::Write;

    fn name(s: &str) -> Name {
        Name::from(s.as_bytes())
    }

    /// A linked image of `kind` with code at 0x1000.. (file offset 0), one FDE over it, and
    /// connect's stub at 0x2000 on its slot 0x3000.
    fn image(code: &[u8], kind: Kind) -> (Image, tempfile::NamedTempFile) {
        image_at(code, kind, 0x1000)
    }

    /// [`image`] with the code at `base`.
    fn image_at(code: &[u8], kind: Kind, base: u64) -> (Image, tempfile::NamedTempFile) {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(code).unwrap();
        let mut img = Image::empty(kind);
        let end = base + code.len() as u64;
        img.code = vec![Region {
            start: base,
            end,
            offset: 0,
        }];
        img.sections = vec![(base, end)];
        img.slots.insert(
            0x3000,
            Sym {
                name: name("connect"),
                defined: None,
            },
        );
        img.stubs.insert(0x2000, (0x3000, ImportVia::Plt));
        img.plt = vec![(0x2000, 0x2010)];
        img.targets.insert(name("connect"));
        img.set_fdes(vec![(base, end)]);
        (img, f)
    }

    /// The references' positions in `code` (read under a 4 MiB budget).
    fn refs(code: &[u8], kind: Kind) -> Vec<u64> {
        let (img, f) = image(code, kind);
        let mut run = Run::new(CodeBudgets::default());
        let mut reader = Reader::new(f.as_file(), code.len() as u64, 4 << 20);
        references(&img, &mut reader, &mut run)
            .iter()
            .map(|r| r.at)
            .collect()
    }

    /// `references` then `confirm` of `code` as one function: the call sites and the gaps.
    fn confirmed(code: &[u8], kind: Kind) -> (Recorder, Vec<String>) {
        let (img, f) = image(code, kind);
        run_on(&img, &f)
    }

    /// `references` then `confirm` on `img`, whose bytes are `f`.
    fn run_on(img: &Image, f: &tempfile::NamedTempFile) -> (Recorder, Vec<String>) {
        let mut run = Run::new(CodeBudgets::default());
        let len = f.as_file().metadata().unwrap().len();
        let mut reader = Reader::new(f.as_file(), len, 1 << 20);
        let found = references(img, &mut reader, &mut run);
        let mut rec = Recorder::default();
        confirm(
            img,
            found,
            signatures().unwrap(),
            &mut reader,
            &mut run,
            &mut rec,
        );
        (rec, run.into_gaps())
    }

    fn rel32(from_next: u64, to: u64) -> [u8; 4] {
        ((to as i64 - from_next as i64) as i32).to_le_bytes()
    }

    #[test]
    fn every_encoding_is_a_candidate() {
        // call 0x2000 at 0x1000: e8 fb 0f 00 00 (0x1005 + 0xffb)
        assert_eq!(refs(&[0xe8, 0xfb, 0x0f, 0, 0], Kind::Shared), [0x1001]);
        // jmp 0x2000 at 0x1000: e9 fb 0f 00 00
        assert_eq!(refs(&[0xe9, 0xfb, 0x0f, 0, 0], Kind::Shared), [0x1001]);
        // jne 0x2000 at 0x1000: 0f 85 fa 0f 00 00 (0x1006 + 0xffa)
        assert_eq!(
            refs(&[0x0f, 0x85, 0xfa, 0x0f, 0, 0], Kind::Shared),
            [0x1002]
        );
        // call [rip+X] → 0x3000 at 0x1000: ff 15 fa 1f 00 00 (0x1006 + 0x1ffa)
        assert_eq!(
            refs(&[0xff, 0x15, 0xfa, 0x1f, 0, 0], Kind::Shared),
            [0x1002]
        );
        // cmp qword [rip+X], 1 → 0x3000: 48 83 3d f8 1f 00 00 01 (k = 1: 0x1003 + 4 + 1 + 0x1ff8)
        assert_eq!(
            refs(&[0x48, 0x83, 0x3d, 0xf8, 0x1f, 0, 0, 0x01], Kind::Shared),
            [0x1003]
        );
        // cmp dword [rip+X], imm16 → 0x3000: 66 81 3d f7 1f 00 00 34 12 (k = 2)
        assert_eq!(
            refs(
                &[0x66, 0x81, 0x3d, 0xf7, 0x1f, 0, 0, 0x34, 0x12],
                Kind::Shared
            ),
            [0x1003]
        );
        // cmp qword [rip+X], imm32 → 0x3000: 48 81 3d f5 1f 00 00 78 56 34 12 (k = 4)
        assert_eq!(
            refs(
                &[0x48, 0x81, 0x3d, 0xf5, 0x1f, 0, 0, 0x78, 0x56, 0x34, 0x12],
                Kind::Shared
            ),
            [0x1003]
        );
        // mov edi, 0x2000 (bf 00 20 00 00): an absolute immediate, only in an ET_EXEC
        assert_eq!(refs(&[0xbf, 0x00, 0x20, 0, 0], Kind::Executable), [0x1001]);
        assert_eq!(
            refs(&[0xbf, 0x00, 0x20, 0, 0], Kind::Shared),
            Vec::<u64>::new()
        );
        // movabs rdi, 0x3000 (48 bf 00 30 00 00 00 00 00 00): an 8-byte absolute value
        assert_eq!(
            refs(&[0x48, 0xbf, 0, 0x30, 0, 0, 0, 0, 0, 0], Kind::Executable),
            [0x1002]
        );
    }

    #[test]
    fn candidates_across_a_chunk_boundary() {
        let mut code = vec![0x90; CHUNK as usize - 2];
        let p = 0x1000 + code.len() as u64; // the call starts 2 bytes before the boundary
        code.push(0xe8);
        code.extend(rel32(p + 5, 0x2000));
        code.extend([0x90; 16]);
        assert_eq!(refs(&code, Kind::Shared), [p + 1]);
    }

    #[test]
    fn coincidence_bytes_inside_an_immediate_are_not_a_reference() {
        // 1000: movabs rax, 0xffa (48 b8 fa 0f 00 00 00 00 00 00); 100a: ret (c3).
        // At 0x1002, 0x1002 + 4 + 0xffa = 0x2000: a candidate, inside the movabs's imm64.
        let code = [0x48, 0xb8, 0xfa, 0x0f, 0, 0, 0, 0, 0, 0, 0xc3];
        assert_eq!(refs(&code, Kind::Shared), [0x1002]);
        let (rec, gaps) = confirmed(&code, Kind::Shared);
        assert_eq!(gaps, Vec::<String>::new(), "a coincidence records nothing");
        assert!(rec.call_sites.is_empty());
    }

    #[test]
    fn an_immediate_names_an_address_only_in_an_executable() {
        // ffb: mov edi, 0x2000 (bf 00 20 00 00); 1000: ret. At 0xffc, `k = 0` gives
        // 0xffc + 4 + 0x2000 = 0x3000, connect's slot: a candidate in either kind of file.
        let code = [0xbf, 0x00, 0x20, 0, 0, 0xc3];
        let (img, f) = image_at(&code, Kind::Shared, 0xffb);
        let (rec, gaps) = run_on(&img, &f);
        assert!(rec.call_sites.is_empty() && gaps.is_empty(), "{gaps:?}");
        // In an executable the immediate is connect's stub, and it is not called.
        let (img, f) = image_at(&code, Kind::Executable, 0xffb);
        let (rec, gaps) = run_on(&img, &f);
        assert!(rec.call_sites.is_empty());
        assert_eq!(
            gaps,
            ["code: connect: address taken at 0xffc, not traced to a call"]
        );
    }

    #[test]
    fn a_call_is_confirmed_and_recorded() {
        // 1000: call 0x2000; 1005: ret.
        let mut code = vec![0xe8];
        code.extend(rel32(0x1005, 0x2000));
        code.push(0xc3);
        let (rec, gaps) = confirmed(&code, Kind::Shared);
        assert_eq!(gaps, Vec::<String>::new());
        assert_eq!(rec.call_sites.len(), 1);
        assert_eq!(rec.call_sites[0].addr, 0x1000);
    }

    #[test]
    fn an_absolute_address_in_an_executable_that_is_not_called_is_taken() {
        // 1000: mov edi, 0x2000; 1005: ret.
        let (rec, gaps) = confirmed(&[0xbf, 0x00, 0x20, 0, 0, 0xc3], Kind::Executable);
        assert!(rec.call_sites.is_empty());
        assert_eq!(
            gaps,
            ["code: connect: address taken at 0x1001, not traced to a call"]
        );
    }

    #[test]
    fn a_reference_not_reached_from_the_fde_start_is_a_gap() {
        // 1000: ret; 1001: call 0x2000 (never reached).
        let mut code = vec![0xc3, 0xe8];
        code.extend(rel32(0x1006, 0x2000));
        let (rec, gaps) = confirmed(&code, Kind::Shared);
        assert!(rec.call_sites.is_empty());
        assert_eq!(
            gaps,
            ["code: connect referenced at 0x1002: not on an instruction decoded from 0x1000"]
        );
    }

    #[test]
    fn a_function_that_fails_explains_each_reference() {
        // 1000: call 0x2000; 1005: an invalid instruction (06 is not valid in 64-bit mode).
        let mut code = vec![0xe8];
        code.extend(rel32(0x1005, 0x2000));
        code.push(0x06);
        let (rec, gaps) = confirmed(&code, Kind::Shared);
        assert!(rec.call_sites.is_empty());
        assert_eq!(
            gaps,
            ["code: connect referenced at 0x1001: function at 0x1000: decode failure at 0x1005"]
        );
    }

    #[test]
    fn references_outside_fdes_and_in_overlaps_are_gaps() {
        let mut code = vec![0xe8];
        code.extend(rel32(0x1005, 0x2000));
        code.push(0xe8);
        code.extend(rel32(0x100a, 0x2000));
        code.push(0xc3);
        let (mut img, f) = image(&code, Kind::Shared);
        // The first call is in no FDE; the second in two.
        img.set_fdes(vec![(0x1005, 0x100b), (0x1006, 0x100b)]);
        let mut run = Run::new(CodeBudgets::default());
        let mut reader = Reader::new(f.as_file(), code.len() as u64, 1 << 20);
        let found = references(&img, &mut reader, &mut run);
        let mut rec = Recorder::default();
        confirm(
            &img,
            found,
            signatures().unwrap(),
            &mut reader,
            &mut run,
            &mut rec,
        );
        assert_eq!(
            run.into_gaps(),
            [
                "code: connect referenced at 0x1001 outside any FDE",
                "code: connect referenced at 0x1006: FDEs overlap there",
            ]
        );
    }

    #[test]
    fn adjacent_code_regions_are_both_searched() {
        // Two executable regions that touch at 0x1005 (two PT_LOADs), at unrelated file offsets,
        // each with a call to connect's stub at 0x2000 (plan review P1-2).
        let mut file = vec![0u8; 0x40];
        file[0x00] = 0xe8;
        file[0x01..0x05].copy_from_slice(&rel32(0x1005, 0x2000));
        file[0x30] = 0xe8;
        file[0x31..0x35].copy_from_slice(&rel32(0x100a, 0x2000));
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&file).unwrap();
        let mut img = Image::empty(Kind::Shared);
        img.code = vec![
            Region {
                start: 0x1000,
                end: 0x1005,
                offset: 0x00,
            },
            Region {
                start: 0x1005,
                end: 0x100a,
                offset: 0x30,
            },
        ];
        img.sections = vec![(0x1000, 0x100a)];
        img.slots.insert(
            0x3000,
            Sym {
                name: name("connect"),
                defined: None,
            },
        );
        img.stubs.insert(0x2000, (0x3000, ImportVia::Plt));
        img.targets.insert(name("connect"));
        assert_eq!(
            scan_ranges(&img)
                .iter()
                .map(|(_, s, e)| (*s, *e))
                .collect::<Vec<_>>(),
            [(0x1000, 0x1005), (0x1005, 0x100a)]
        );
        let mut run = Run::new(CodeBudgets::default());
        let mut reader = Reader::new(f.as_file(), file.len() as u64, 1 << 20);
        let found: Vec<u64> = references(&img, &mut reader, &mut run)
            .iter()
            .map(|r| r.at)
            .collect();
        assert_eq!(found, [0x1001, 0x1006]);
    }

    #[test]
    fn scanned_bytes_are_sections_and_fdes_in_code_minus_the_plt() {
        let mut img = Image::empty(Kind::Shared);
        img.code = vec![Region {
            start: 0x1000,
            end: 0x5000,
            offset: 0,
        }];
        // A section, an FDE beside it, an FDE partly outside code, and a PLT inside the section.
        img.sections = vec![(0x1000, 0x2000), (0x4800, 0x6000)];
        img.set_fdes(vec![(0x2000, 0x2100), (0x3000, 0x3100)]);
        img.plt = vec![(0x1200, 0x1300)];
        assert_eq!(
            scan_ranges(&img)
                .iter()
                .map(|(_, s, e)| (*s, *e))
                .collect::<Vec<_>>(),
            [
                (0x1000, 0x1200),
                (0x1300, 0x2100),
                (0x3000, 0x3100),
                (0x4800, 0x5000)
            ]
        );
    }

    #[test]
    fn references_limit_stops_the_search() {
        let mut code = vec![];
        for k in 0..10u64 {
            let p = 0x1000 + k * 5;
            code.push(0xe8);
            code.extend(rel32(p + 5, 0x2000));
        }
        let (img, f) = image(&code, Kind::Shared);
        let mut run = Run::new(CodeBudgets {
            references: 4,
            ..CodeBudgets::default()
        });
        let mut reader = Reader::new(f.as_file(), code.len() as u64, 1 << 20);
        assert_eq!(references(&img, &mut reader, &mut run).len(), 4);
        assert!(run.stopped());
        assert!(run
            .into_gaps()
            .contains(&"code: references limit 4 reached".to_string()));
    }

    #[test]
    fn a_stub_address_called_through_a_register_is_a_call() {
        // 1000: lea rax, [rip+stub] (48 8d 05 disp32); 1007: call rax (ff d0); 1009: ret.
        let mut code = vec![0x48, 0x8d, 0x05];
        code.extend(rel32(0x1007, 0x2000));
        code.extend([0xff, 0xd0, 0xc3]);
        let (rec, gaps) = confirmed(&code, Kind::Shared);
        assert_eq!(gaps, Vec::<String>::new());
        assert_eq!(rec.call_sites.len(), 1);
        assert_eq!(rec.call_sites[0].addr, 0x1007);
        assert_eq!(
            rec.call_sites[0].target,
            sigil_model::CallTarget::Import {
                symbol: sigil_model::UntrustedText::from_bytes(b"connect".to_vec()),
                via: ImportVia::Plt
            }
        );
    }

    #[test]
    fn a_stub_address_called_and_passed_on_is_taken() {
        // 1000: lea rdi, [rip+stub] (48 8d 3d disp32); 1007: call rdi (ff d7); 1009: ret. The
        // call is recorded, and its arg 0 holds connect's address: taken all the same (§4.7).
        let mut code = vec![0x48, 0x8d, 0x3d];
        code.extend(rel32(0x1007, 0x2000));
        code.extend([0xff, 0xd7, 0xc3]);
        let (rec, gaps) = confirmed(&code, Kind::Shared);
        assert_eq!(rec.call_sites.len(), 1);
        assert_eq!(
            gaps,
            ["code: connect: address taken at 0x1003, not traced to a call"]
        );
    }

    #[test]
    fn a_function_not_recorded_for_a_duplicate_explains_its_references() {
        // 1000: call stub; 1005: 3 nops; 1008: call stub; 100d: call stub; 1012: ret.
        // FDE A [0x1000, 0x100d) and FDE B [0x1008, 0x1013) share [0x1008, 0x100d). A records
        // the calls at 0x1000 and 0x1008; B would record 0x1008 again, so B records nothing.
        let mut code = vec![0xe8];
        code.extend(rel32(0x1005, 0x2000));
        code.extend([0x90; 3]);
        code.push(0xe8);
        code.extend(rel32(0x100d, 0x2000));
        code.push(0xe8);
        code.extend(rel32(0x1012, 0x2000));
        code.push(0xc3);
        let (mut img, f) = image(&code, Kind::Shared);
        img.set_fdes(vec![(0x1000, 0x100d), (0x1008, 0x1013)]);
        let (rec, gaps) = run_on(&img, &f);
        assert_eq!(
            rec.call_sites.iter().map(|c| c.addr).collect::<Vec<_>>(),
            [0x1000, 0x1008]
        );
        assert_eq!(
            gaps,
            [
                "code: call site at 0x1008 is in two functions",
                "code: connect referenced at 0x1009: FDEs overlap there",
                "code: connect referenced at 0x100e: function at 0x1008 not recorded",
            ]
        );
    }

    #[test]
    fn a_stopped_run_confirms_nothing_more() {
        let mut code = vec![0xe8];
        code.extend(rel32(0x1005, 0x2000));
        code.push(0xc3);
        let (img, f) = image(&code, Kind::Shared);
        let mut run = Run::new(CodeBudgets::default());
        let mut reader = Reader::new(f.as_file(), code.len() as u64, 1 << 20);
        let found = references(&img, &mut reader, &mut run);
        run.limit("FDE", 1);
        let mut rec = Recorder::default();
        confirm(
            &img,
            found,
            signatures().unwrap(),
            &mut reader,
            &mut run,
            &mut rec,
        );
        assert!(rec.call_sites.is_empty());
        assert_eq!(
            run.into_gaps(),
            [
                "code: FDE limit 1 reached",
                "code: connect referenced at 0x1001: not confirmed: a limit was reached",
            ]
        );
    }

    #[test]
    fn the_byte_budget_stops_the_scan() {
        let mut code = vec![0xe8];
        code.extend(rel32(0x1005, 0x2000));
        code.push(0xc3);
        let (img, f) = image(&code, Kind::Shared);
        let mut run = Run::new(CodeBudgets::default());
        let mut reader = Reader::new(f.as_file(), code.len() as u64, 3);
        assert!(references(&img, &mut reader, &mut run).is_empty());
        assert!(run.stopped());
        assert_eq!(run.into_gaps(), ["binary_code_bytes: 3 exceeded"]);
    }

    /// A relocatable object's image: `.text` at file offset 0x40, `[0x40, 0x40 + len)`, one FDE
    /// over it; symbol 1 is connect (undefined), a target.
    fn object(code: &[u8]) -> (Image, tempfile::NamedTempFile) {
        let mut bytes = vec![0u8; 0x40];
        bytes.extend_from_slice(code);
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&bytes).unwrap();
        let mut img = Image::empty(Kind::Relocatable);
        let end = 0x40 + code.len() as u64;
        img.code = vec![Region {
            start: 0x40,
            end,
            offset: 0x40,
        }];
        img.sections = vec![(0x40, end)];
        img.rel_syms.insert(
            1,
            crate::code::image::RelSym {
                name: Some(name("connect")),
                at: None,
            },
        );
        img.targets.insert(name("connect"));
        img.set_fdes(vec![(0x40, end)]);
        (img, f)
    }

    fn reloc(img: &mut Image, field: u64, r_type: u32, addend: i64) {
        img.relocs.insert(
            field,
            crate::code::image::Reloc::One(crate::code::image::FieldReloc {
                r_type,
                sym: 1,
                addend,
            }),
        );
    }

    #[test]
    fn relocations_are_confirmed_by_their_field() {
        use crate::code::image::rtype;
        // 40: call rel32 (PLT32 connect-4, exact); 45: ret.
        let (mut img, f) = object(&[0xe8, 0, 0, 0, 0, 0xc3]);
        reloc(&mut img, 0x41, rtype::PLT32, -4);
        let (rec, gaps) = run_on(&img, &f);
        assert_eq!(gaps, Vec::<String>::new());
        assert_eq!(rec.call_sites.len(), 1);

        // Not exact: a branch beside the symbol.
        let (mut img, f) = object(&[0xe8, 0, 0, 0, 0, 0xc3]);
        reloc(&mut img, 0x41, rtype::PLT32, 0);
        let (rec, gaps) = run_on(&img, &f);
        assert!(rec.call_sites.is_empty());
        assert_eq!(gaps, ["code: connect: branch to connect+4 at 0x41"]);

        // On an opcode byte: not on a field.
        let (mut img, f) = object(&[0xe8, 0, 0, 0, 0, 0xc3]);
        reloc(&mut img, 0x40, rtype::PLT32, -4);
        let (_, gaps) = run_on(&img, &f);
        assert_eq!(
            gaps,
            ["code: connect: relocation at 0x40 not on an instruction field"]
        );

        // 40: lea rdi, [rip+0] (PC32 connect-4, exact: SymbolAddr), 47: ret: taken.
        let (mut img, f) = object(&[0x48, 0x8d, 0x3d, 0, 0, 0, 0, 0xc3]);
        reloc(&mut img, 0x43, rtype::PC32, -4);
        let (_, gaps) = run_on(&img, &f);
        assert_eq!(
            gaps,
            ["code: connect: address taken at 0x43, not traced to a call"]
        );

        // 40: mov edi, imm32 (R_X86_64_32 connect): SymbolAddr, taken.
        let (mut img, f) = object(&[0xbf, 0, 0, 0, 0, 0xc3]);
        reloc(&mut img, 0x41, rtype::R32, 0);
        let (_, gaps) = run_on(&img, &f);
        assert_eq!(
            gaps,
            ["code: connect: address taken at 0x41, not traced to a call"]
        );

        // 40: mov rax, [rip+0] (GOTPCREL connect-4: the GOT entry), 47: call rax: called.
        let (mut img, f) = object(&[0x48, 0x8b, 0x05, 0, 0, 0, 0, 0xff, 0xd0, 0xc3]);
        reloc(&mut img, 0x43, rtype::REX_GOTPCRELX, -4);
        let (rec, gaps) = run_on(&img, &f);
        assert_eq!(gaps, Vec::<String>::new());
        assert_eq!(rec.call_sites.len(), 1);
        assert_eq!(rec.call_sites[0].addr, 0x47);
    }
}
