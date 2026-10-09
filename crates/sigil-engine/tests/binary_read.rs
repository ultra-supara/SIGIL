//! The checkpoint in front of `object::ReadCache` (spec §4.2): every allocation is charged before
//! it happens, duplicates are charged once, and strings follow ReadCache 0.40.0's 4 KiB rule.

use std::cell::Cell;
use std::io::Write;
use std::rc::Rc;

use object::read::{ReadCacheOps, ReadRef};
use sigil_engine::binary::read::{Bounded, ENTRY_OVERHEAD, STRING_LIMIT};

/// `ReadCacheOps` over bytes, recording the largest buffer ReadCache hands it.
struct Recording {
    data: Vec<u8>,
    pos: u64,
    largest: Rc<Cell<usize>>,
}

impl ReadCacheOps for Recording {
    fn len(&mut self) -> Result<u64, ()> {
        Ok(self.data.len() as u64)
    }
    fn seek(&mut self, pos: u64) -> Result<u64, ()> {
        self.pos = pos;
        Ok(pos)
    }
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ()> {
        self.largest.set(self.largest.get().max(buf.len()));
        let start = usize::try_from(self.pos).map_err(|_| ())?;
        let n = buf.len().min(self.data.len().saturating_sub(start));
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        self.pos += n as u64;
        Ok(n)
    }
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ()> {
        if self.read(buf)? == buf.len() {
            Ok(())
        } else {
            Err(())
        }
    }
}

fn bounded(data: Vec<u8>, budget: u64) -> (Bounded<Recording>, Rc<Cell<usize>>) {
    let largest = Rc::new(Cell::new(0));
    let len = data.len() as u64;
    let ops = Recording {
        data,
        pos: 0,
        largest: Rc::clone(&largest),
    };
    (Bounded::new(ops, len, budget), largest)
}

#[test]
fn a_request_over_the_budget_is_refused_before_any_allocation() {
    // 1 MiB of file, a 512 KiB budget, and a request for 900 KiB inside the file.
    let (b, largest) = bounded(vec![7u8; 1 << 20], 512 << 10);
    assert!((&b).read_bytes_at(0, 900 << 10).is_err());
    assert_eq!(largest.get(), 0, "nothing reached ReadCache");
    assert!(b.refused());
    // Past the end of the file: refused too.
    let (b, _) = bounded(vec![7u8; 100], 1 << 20);
    assert!((&b).read_bytes_at(50, 51).is_err());
}

#[test]
fn overlapping_requests_exhaust_the_budget_instead_of_growing_the_cache() {
    let (b, largest) = bounded(vec![1u8; 1 << 20], 64 << 10);
    let mut ok = 0;
    for i in 0..1000u64 {
        if (&b).read_bytes_at(i, 1000).is_ok() {
            ok += 1;
        }
    }
    assert!(ok < 1000, "the budget must stop them");
    assert!(b.used() <= 64 << 10);
    assert!(largest.get() <= 1000);
}

#[test]
fn identical_requests_are_charged_once() {
    let (b, _) = bounded(vec![1u8; 4096], 1 << 20);
    (&b).read_bytes_at(10, 100).unwrap();
    (&b).read_bytes_at(10, 100).unwrap();
    assert_eq!(b.used(), 100 + ENTRY_OVERHEAD);
}

#[test]
fn strings_follow_readcache_s_4_kib_rule() {
    // A 10-byte string, then a NUL; then 5000 bytes without a NUL.
    let mut data = b"0123456789\0".to_vec();
    data.extend(std::iter::repeat_n(b'x', 5000));
    data.push(0);
    let len = data.len() as u64;
    let (b, _) = bounded(data, 1 << 20);
    assert_eq!((&b).read_bytes_at_until(0..len, 0).unwrap(), b"0123456789");
    assert_eq!(b.used(), 10 + ENTRY_OVERHEAD, "charged its length");
    (&b).read_bytes_at_until(0..len, 0).unwrap();
    assert_eq!(b.used(), 10 + ENTRY_OVERHEAD, "and once");
    assert!(
        (&b).read_bytes_at_until(11..len, 0).is_err(),
        "over ReadCache's 4 KiB"
    );
    // A string needs its transient 4 KiB free before it is read.
    let (b, _) = bounded(b"ab\0".to_vec(), STRING_LIMIT);
    assert!((&b).read_bytes_at_until(0..3, 0).is_err());
}

#[test]
fn failed_string_searches_are_charged_so_repeats_stop() {
    // 8 KiB without a NUL: every search fails in ReadCache. The review's case: without a charge,
    // the same failure could be repeated forever.
    let (b, _) = bounded(vec![b'x'; 8192], 64 << 10);
    let mut tries = 0;
    while (&b).read_bytes_at_until(0..8192, 0).is_err() && !b.refused() {
        tries += 1;
        assert!(tries < 100, "failures never exhausted the budget");
    }
    assert!(b.refused());
    assert!(b.used() <= 64 << 10);
}

#[test]
fn a_cached_string_must_end_inside_a_narrower_range() {
    let (b, _) = bounded(b"0123456789\0".to_vec(), 1 << 20);
    assert_eq!((&b).read_bytes_at_until(0..11, 0).unwrap(), b"0123456789");
    // Same start and delimiter, so ReadCache would return the cached string; its NUL is past 5.
    assert!((&b).read_bytes_at_until(0..5, 0).is_err());
    assert!((&b).read_bytes_at_until(0..11, 0).is_ok());
}

#[test]
fn a_file_is_read_with_pread() {
    let mut f = tempfile::tempfile().unwrap();
    f.write_all(b"\x7fELF-and-more").unwrap();
    let b = Bounded::new(
        sigil_engine::binary::read::Budgeted::new(&f, 13),
        13,
        1 << 20,
    );
    assert_eq!((&b).read_bytes_at(0, 4).unwrap(), b"\x7fELF");
}
