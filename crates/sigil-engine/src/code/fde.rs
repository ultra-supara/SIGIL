//! Function bounds from `.eh_frame` (PR-5a spec §4.5): one FDE is one function; there is no
//! fallback to symbol sizes (plan §4.6.5).

use std::collections::BTreeMap;

use gimli::{
    BaseAddresses, CieOrFde, CommonInformationEntry, EhFrame, EhFrameOffset, EndianSlice,
    LittleEndian, UnwindSection,
};

use super::Run;

type Slice<'a> = EndianSlice<'a, LittleEndian>;

/// The `[start, end)` ranges of the FDEs in `bytes`, the contents of `.eh_frame` whose first byte
/// is at `base` (a virtual address, or a relocatable object's file offset), sorted and unique.
/// An empty FDE gives no range, and one whose end passes 2^64 is a gap. An entry that cannot be
/// parsed is a gap and ends the walk; the FDEs before it are kept. Every FDE read counts against
/// `run.budgets.fdes`, empty and failing ones included.
// Used outside tests from Task 11 (`analyze`); until then only tests call it.
#[allow(dead_code)]
pub(crate) fn parse(bytes: &[u8], base: u64, run: &mut Run) -> Vec<(u64, u64)> {
    let mut frame = EhFrame::new(bytes, LittleEndian);
    // ELF64: an address is 8 bytes, whatever the host's word (gimli's default).
    frame.set_address_size(8);
    let bases = BaseAddresses::default().set_eh_frame(base);
    // Each CIE parsed, by offset, so it is parsed once, not once per FDE: the parse reads its
    // augmentation string, whose length the input sets. At most one is added per FDE.
    let mut cies = BTreeMap::new();
    let mut seen = 0;
    let mut out = vec![];
    let mut entries = frame.entries(&bases);
    loop {
        let partial = match entries.next() {
            Ok(None) => break,
            Ok(Some(CieOrFde::Cie(_))) => continue,
            Ok(Some(CieOrFde::Fde(partial))) => partial,
            Err(e) => {
                run.gap(format!("code: .eh_frame: {e}"));
                break;
            }
        };
        if seen == run.budgets.fdes {
            run.limit("FDE", seen as u64);
            break;
        }
        seen += 1;
        let fde = match partial.parse(|frame, bases, offset| cie(&mut cies, frame, bases, offset)) {
            Ok(fde) => fde,
            Err(e) => {
                run.gap(format!("code: .eh_frame: {e}"));
                break;
            }
        };
        let start = fde.initial_address();
        match start.checked_add(fde.len()) {
            Some(end) if end > start => out.push((start, end)),
            Some(_) => {}
            None => run.gap(format!("code: .eh_frame: FDE at {start:#x} wraps")),
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// The CIE at `offset`, from `cies` or parsed (and then kept in `cies`).
fn cie<'a>(
    cies: &mut BTreeMap<usize, CommonInformationEntry<Slice<'a>>>,
    frame: &EhFrame<Slice<'a>>,
    bases: &BaseAddresses,
    offset: EhFrameOffset,
) -> gimli::Result<CommonInformationEntry<Slice<'a>>> {
    if let Some(cie) = cies.get(&offset.0) {
        return Ok(cie.clone());
    }
    let cie = frame.cie_from_offset(bases, offset)?;
    cies.insert(offset.0, cie.clone());
    Ok(cie)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::{CodeBudgets, Run};
    use object::{Object, ObjectSection};

    fn eh_frame(fixture: &str) -> (Vec<u8>, u64) {
        let path = format!(
            "{}/tests/fixtures/code/{fixture}",
            env!("CARGO_MANIFEST_DIR")
        );
        let bytes = std::fs::read(path).unwrap();
        let file = object::File::parse(&*bytes).unwrap();
        let s = file.section_by_name(".eh_frame").unwrap();
        (s.data().unwrap().to_vec(), s.address())
    }

    /// `values.so`'s FDEs, sorted: ld's for `.plt` (0x1000..0x1030), then the 8 of `values.S`'s
    /// functions with CFI, in `.text` (0x1030..0x1110). `readelf --debug-dump=frames values.so`
    /// lists the `.plt` one last.
    const VALUES: [(u64, u64); 9] = [
        (0x1000, 0x1030),
        (0x1030, 0x1056),
        (0x1056, 0x1081),
        (0x1081, 0x1082),
        (0x1082, 0x1099),
        (0x1099, 0x10b6),
        (0x10b6, 0x10d8),
        (0x10d8, 0x10ef),
        (0x10ef, 0x1110),
    ];

    #[test]
    fn the_fdes_of_a_linked_file() {
        let (bytes, base) = eh_frame("values.so");
        let mut run = Run::new(CodeBudgets::default());
        // 9, not the plan's 8: the 8 CFI functions of `values.S`, and ld's FDE for `.plt`.
        assert_eq!(parse(&bytes, base, &mut run), VALUES);
        assert!(!run.stopped());
        assert!(run.into_gaps().is_empty());
    }

    #[test]
    fn the_fde_limit_stops_collection() {
        let (bytes, base) = eh_frame("values.so");
        let mut run = Run::new(CodeBudgets {
            fdes: 3,
            ..CodeBudgets::default()
        });
        // The first three in section order.
        assert_eq!(parse(&bytes, base, &mut run), VALUES[1..4]);
        assert!(run.stopped());
        assert_eq!(run.into_gaps(), ["code: FDE limit 3 reached"]);

        // Exactly at the limit: all of them, and no limit reached.
        let mut run = Run::new(CodeBudgets {
            fdes: 9,
            ..CodeBudgets::default()
        });
        assert_eq!(parse(&bytes, base, &mut run), VALUES);
        assert!(!run.stopped());
        assert!(run.into_gaps().is_empty());
    }

    #[test]
    fn truncated_frames_are_a_gap_not_a_panic() {
        let (bytes, base) = eh_frame("values.so");
        for cut in 0..=bytes.len() {
            let mut run = Run::new(CodeBudgets::default());
            let _ = parse(&bytes[..cut], base, &mut run);
            // Either the cut hit an entry (a gap) or it fell between entries (fewer FDEs).
            assert!(run
                .into_gaps()
                .iter()
                .all(|g| g.starts_with("code: .eh_frame: ")));
        }
        for cut in [1, 7, 23, bytes.len() / 2] {
            let mut run = Run::new(CodeBudgets::default());
            let fdes = parse(&bytes[..cut], base, &mut run);
            let gaps = run.into_gaps();
            assert!(
                gaps.len() == 1 && gaps[0].starts_with("code: .eh_frame: "),
                "{cut}: {gaps:?}"
            );
            // The FDEs before the cut are kept: the entries at 0x18, 0x30, 0x48 and 0x5c end
            // before half the section (0x7e), the one at 0x74 does not.
            if cut == bytes.len() / 2 {
                assert_eq!(fdes, VALUES[1..5]);
            }
        }
        // A cut between entries (the 5th FDE ends at 0x8c) is the end of the section.
        let mut run = Run::new(CodeBudgets::default());
        assert_eq!(parse(&bytes[..0x8c], base, &mut run), VALUES[1..6]);
        assert!(run.into_gaps().is_empty());

        let mut garbage = bytes.clone();
        garbage[4..8].copy_from_slice(&[0xff; 4]); // a CIE pointer to nowhere
        let mut run = Run::new(CodeBudgets::default());
        assert!(parse(&garbage, base, &mut run).is_empty());
        assert_eq!(
            run.into_gaps(),
            ["code: .eh_frame: invalid offset: 0xffffffff"]
        );

        // The same in the second FDE (at 0x30): the first one is kept.
        let mut garbage = bytes.clone();
        garbage[0x34..0x38].copy_from_slice(&[0xff; 4]);
        let mut run = Run::new(CodeBudgets::default());
        assert_eq!(parse(&garbage, base, &mut run), VALUES[1..2]);
        assert_eq!(
            run.into_gaps(),
            ["code: .eh_frame: invalid offset: 0xffffffff"]
        );
    }

    /// One entry: its 32-bit length, then `body`.
    fn entry(body: Vec<u8>) -> Vec<u8> {
        let mut e = u32::try_from(body.len()).unwrap().to_le_bytes().to_vec();
        e.extend(body);
        e
    }

    /// A CIE of augmentation `zR` and `pad` more `S`s, whose FDEs give their addresses
    /// `pcrel|sdata4`.
    fn cie(pad: usize) -> Vec<u8> {
        let mut body = vec![0, 0, 0, 0, 1]; // CIE id, version 1
        body.extend(b"zR");
        body.extend(std::iter::repeat_n(b'S', pad));
        // NUL; code alignment 1; data alignment -8; return address r16; augmentation data: 1 byte,
        // DW_EH_PE_pcrel | DW_EH_PE_sdata4.
        body.extend([0, 1, 0x78, 16, 1, 0x1b]);
        entry(body)
    }

    /// An FDE at `at` in a section at `base`, of the CIE at `cie`, for `[start, start + len)`.
    fn fde(at: usize, cie: usize, base: u64, start: u64, len: u32) -> Vec<u8> {
        let pointer = u32::try_from(at + 4 - cie).unwrap();
        // pc-relative to its own field, at `at + 8`.
        let initial = start.wrapping_sub(base.wrapping_add(at as u64 + 8)) as u32;
        let mut body = pointer.to_le_bytes().to_vec();
        body.extend(initial.to_le_bytes());
        body.extend(len.to_le_bytes());
        body.push(0); // augmentation data length
        entry(body)
    }

    /// `cies`, then FDEs `(index of their CIE, start, len)` in order.
    fn section(base: u64, cies: &[Vec<u8>], fdes: &[(usize, u64, u32)]) -> Vec<u8> {
        let mut out = vec![];
        let mut at = vec![];
        for c in cies {
            at.push(out.len());
            out.extend(c);
        }
        for &(c, start, len) in fdes {
            let f = fde(out.len(), at[c], base, start, len);
            out.extend(f);
        }
        out
    }

    #[test]
    fn a_long_cie_shared_by_many_fdes() {
        // A CIE with a 64 KiB augmentation string, and one short one. Each FDE asks for its CIE:
        // the long one is parsed once, not once per FDE.
        let base = 0x2000;
        let fdes: Vec<(usize, u64, u32)> = (0..4096u64)
            .map(|k| (usize::from(k % 3 == 0), 0x1000 + 16 * k, 16))
            .collect();
        let bytes = section(base, &[cie(64 << 10), cie(0)], &fdes);
        let mut run = Run::new(CodeBudgets::default());
        let got = parse(&bytes, base, &mut run);
        let want: Vec<(u64, u64)> = (0..4096u64)
            .map(|k| (0x1000 + 16 * k, 0x1010 + 16 * k))
            .collect();
        assert_eq!(got, want);
        assert!(run.into_gaps().is_empty());
    }

    #[test]
    fn empty_and_wrapping_fdes() {
        // In order: an empty FDE (dropped), one that wraps past the top of the address space (a
        // gap), a good one, and the same good one again (kept once). Each counts against the
        // FDE limit.
        let base = u64::MAX - 0xfff;
        let top = u64::MAX - 0x7ff;
        let bytes = section(
            base,
            &[cie(0)],
            &[
                (0, top, 0),
                (0, top, 0x1000),
                (0, top, 0x10),
                (0, top, 0x10),
            ],
        );
        let mut run = Run::new(CodeBudgets::default());
        assert_eq!(parse(&bytes, base, &mut run), [(top, top + 0x10)]);
        assert_eq!(
            run.into_gaps(),
            [format!("code: .eh_frame: FDE at {top:#x} wraps")]
        );

        let mut run = Run::new(CodeBudgets {
            fdes: 2,
            ..CodeBudgets::default()
        });
        assert!(parse(&bytes, base, &mut run).is_empty());
        assert!(run.stopped());
        assert_eq!(
            run.into_gaps(),
            [
                "code: .eh_frame: FDE at 0xfffffffffffff800 wraps".to_string(),
                "code: FDE limit 2 reached".to_string(),
            ]
        );
    }
}
