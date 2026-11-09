//! Reading a binary for parsing (spec §4.2): `pread` on the anchored fd (never `mmap`), through a
//! checkpoint that charges every allocation `object::ReadCache` makes against a byte budget
//! **before** it happens.
//!
//! `ReadCache` allocates a request's buffer before its reader sees the request, so a budget in
//! the reader alone would not bound memory. The checkpoint sees every request first:
//! - `read_bytes_at`: the range must be inside the file; a request not served before is charged
//!   its size plus [`ENTRY_OVERHEAD`], or refused without reaching the cache. A failed read caches
//!   nothing and stays charged, so repeated failures exhaust the budget;
//! - `read_bytes_at_until`: ReadCache 0.40.0 searches at most [`STRING_LIMIT`] bytes in 256-byte
//!   steps and keeps exactly the string. A new request needs `STRING_LIMIT + ENTRY_OVERHEAD`
//!   left, and is charged the string's length plus `ENTRY_OVERHEAD`. A failed search is charged
//!   `STRING_LIMIT + ENTRY_OVERHEAD`, so repeated failures exhaust the budget instead of
//!   reading forever. A string served from the cache must end inside the requested range
//!   (ReadCache keys strings by start and delimiter only);
//! - a request seen before is served from the cache, uncharged.

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::fs::File;
use std::ops::Range;
use std::os::unix::fs::FileExt;

use object::read::{ReadCache, ReadCacheOps, ReadRef};

/// Bookkeeping charged per cache entry: ReadCache's map entry, the checkpoint's own key, and the
/// allocator's rounding of a small buffer.
pub const ENTRY_OVERHEAD: u64 = 128;
/// The longest string ReadCache (0.40.0) searches for its delimiter.
pub const STRING_LIMIT: u64 = 4096;

/// `object::ReadCacheOps` over `pread` on an open file.
pub struct Budgeted<'f> {
    file: &'f File,
    len: u64,
    pos: u64,
}

impl<'f> Budgeted<'f> {
    /// `len`: the file's size from the `fstat` of the read.
    pub fn new(file: &'f File, len: u64) -> Budgeted<'f> {
        Budgeted { file, len, pos: 0 }
    }
}

impl ReadCacheOps for Budgeted<'_> {
    fn len(&mut self) -> Result<u64, ()> {
        Ok(self.len)
    }

    fn seek(&mut self, pos: u64) -> Result<u64, ()> {
        if pos > self.len {
            return Err(());
        }
        self.pos = pos;
        Ok(pos)
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ()> {
        loop {
            match self.file.read_at(buf, self.pos) {
                Ok(n) => {
                    self.pos = self.pos.saturating_add(n as u64);
                    return Ok(n);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(()),
            }
        }
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ()> {
        self.file.read_exact_at(buf, self.pos).map_err(|_| ())?;
        self.pos = self.pos.saturating_add(buf.len() as u64);
        Ok(())
    }
}

/// A strict physical-read cap for discovery probes. Refuse a whole request before I/O when it
/// does not fit; `used` includes bytes returned before any later error. Allocation accounting
/// remains the responsibility of the enclosing `Bounded` checkpoint.
pub(crate) struct Metered<'a, R> {
    inner: R,
    limit: u64,
    used: &'a Cell<u64>,
    exhausted: &'a Cell<bool>,
    failed: &'a Cell<bool>,
}

impl<'a, R> Metered<'a, R> {
    pub(crate) fn new(
        inner: R,
        limit: u64,
        used: &'a Cell<u64>,
        exhausted: &'a Cell<bool>,
        failed: &'a Cell<bool>,
    ) -> Self {
        Self {
            inner,
            limit,
            used,
            exhausted,
            failed,
        }
    }
}

impl<R: ReadCacheOps> ReadCacheOps for Metered<'_, R> {
    fn len(&mut self) -> Result<u64, ()> {
        self.inner.len()
    }

    fn seek(&mut self, pos: u64) -> Result<u64, ()> {
        self.inner.seek(pos)
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ()> {
        if (buf.len() as u64) > self.limit.saturating_sub(self.used.get()) {
            self.exhausted.set(true);
            return Err(());
        }
        let n = match self.inner.read(buf) {
            Ok(n) => n,
            Err(()) => {
                self.failed.set(true);
                return Err(());
            }
        };
        self.used.set(self.used.get().saturating_add(n as u64));
        Ok(n)
    }

    fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<(), ()> {
        while !buf.is_empty() {
            match self.read(buf)? {
                0 => {
                    self.failed.set(true);
                    return Err(());
                }
                n => buf = &mut buf[n..],
            }
        }
        Ok(())
    }
}

/// A key of a request ReadCache has served: `(kind, offset, size or delimiter)`.
type Key = (u8, u64, u64);

/// The checkpoint: a [`ReadRef`] in front of [`ReadCache`].
pub struct Bounded<R: ReadCacheOps> {
    cache: ReadCache<R>,
    len: u64,
    budget: u64,
    used: Cell<u64>,
    /// Requests refused for the budget so far.
    refusals: Cell<u64>,
    seen: RefCell<HashSet<Key>>,
}

impl<R: ReadCacheOps> Bounded<R> {
    pub fn new(ops: R, len: u64, budget: u64) -> Bounded<R> {
        Bounded {
            cache: ReadCache::new(ops),
            len,
            budget,
            used: Cell::new(0),
            refusals: Cell::new(0),
            seen: RefCell::new(HashSet::new()),
        }
    }

    /// Bytes charged so far.
    pub fn used(&self) -> u64 {
        self.used.get()
    }

    pub fn budget(&self) -> u64 {
        self.budget
    }

    /// Whether a request was refused for the budget.
    pub fn refused(&self) -> bool {
        self.refusals.get() > 0
    }

    /// How many requests were refused for the budget: a later step (the code step) tells its own
    /// refusals from the earlier ones by the count.
    pub fn refusals(&self) -> u64 {
        self.refusals.get()
    }

    fn room(&self, n: u64) -> Result<(), ()> {
        match self.used.get().checked_add(n) {
            Some(total) if total <= self.budget => Ok(()),
            _ => {
                self.refusals.set(self.refusals.get().saturating_add(1));
                Err(())
            }
        }
    }

    fn charge(&self, n: u64) -> Result<(), ()> {
        self.room(n)?;
        self.used.set(self.used.get().saturating_add(n));
        Ok(())
    }
}

impl<'a, R: ReadCacheOps> ReadRef<'a> for &'a Bounded<R> {
    fn len(self) -> Result<u64, ()> {
        Ok(self.len)
    }

    fn read_bytes_at(self, offset: u64, size: u64) -> Result<&'a [u8], ()> {
        if size == 0 {
            return Ok(&[]);
        }
        let end = offset.checked_add(size).ok_or(())?;
        if end > self.len {
            return Err(());
        }
        let key = (0, offset, size);
        if self.seen.borrow().contains(&key) {
            return (&self.cache).read_bytes_at(offset, size);
        }
        // A failed read caches nothing, so a repeat reads again: it stays charged, and only a
        // read that succeeded is served uncharged afterwards.
        self.charge(size.saturating_add(ENTRY_OVERHEAD))?;
        let bytes = (&self.cache).read_bytes_at(offset, size)?;
        self.seen.borrow_mut().insert(key);
        Ok(bytes)
    }

    fn read_bytes_at_until(self, range: Range<u64>, delimiter: u8) -> Result<&'a [u8], ()> {
        if range.start > range.end || range.end > self.len {
            return Err(());
        }
        let key = (1, range.start, u64::from(delimiter));
        let found = if self.seen.borrow().contains(&key) {
            (&self.cache).read_bytes_at_until(range.clone(), delimiter)?
        } else {
            // ReadCache's transient buffer reaches STRING_LIMIT before it finds the delimiter.
            self.room(STRING_LIMIT + ENTRY_OVERHEAD)?;
            match (&self.cache).read_bytes_at_until(range.clone(), delimiter) {
                Ok(found) => {
                    self.charge(found.len() as u64 + ENTRY_OVERHEAD)?;
                    self.seen.borrow_mut().insert(key);
                    found
                }
                Err(()) => {
                    // A failed search read up to STRING_LIMIT and caches nothing, so a repeat
                    // reads again: each failure is charged in full.
                    self.charge(STRING_LIMIT + ENTRY_OVERHEAD)?;
                    return Err(());
                }
            }
        };
        // ReadCache keys strings by (start, delimiter) only, so a string cached under a wider
        // range comes back for a narrower one: it must still end inside this range.
        if found.len() as u64 >= range.end - range.start {
            return Err(());
        }
        Ok(found)
    }
}

#[cfg(test)]
mod meter_tests {
    use super::*;

    struct FailsAfterThree;
    impl ReadCacheOps for FailsAfterThree {
        fn len(&mut self) -> Result<u64, ()> {
            Ok(8)
        }
        fn seek(&mut self, pos: u64) -> Result<u64, ()> {
            Ok(pos)
        }
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, ()> {
            if buf.len() == 8 {
                buf[..3].copy_from_slice(b"abc");
                Ok(3)
            } else {
                Err(())
            }
        }
        fn read_exact(&mut self, _buf: &mut [u8]) -> Result<(), ()> {
            unreachable!()
        }
    }

    #[test]
    fn failed_exact_read_keeps_partial_io_charge() {
        let used = Cell::new(0);
        let exhausted = Cell::new(false);
        let failed = Cell::new(false);
        let mut ops = Metered::new(FailsAfterThree, 8, &used, &exhausted, &failed);
        assert!(ops.read_exact(&mut [0; 8]).is_err());
        assert_eq!(used.get(), 3);
        assert!(failed.get());
        assert!(!exhausted.get());
    }
}
