//! Code bytes (PR-5a spec §4.2): `pread` on the input's fd, never through the parse cache, each
//! byte charged to `binary_code_bytes` before it is read. Nothing is mapped. The signature scan
//! (PR-4c-2a) reads section bytes through it too, charged to `binary_scan_bytes`.

use std::fs::File;
use std::os::unix::fs::FileExt;

/// The largest single read (spec §4.10's memory bound): 64 MiB. The largest `.eh_frame` surveyed
/// is 6.7 MB, an FDE is decoded up to `FDE_BYTES` (16 MiB), and the scan reads 1 MiB chunks.
pub const MAX_READ: u64 = 64 << 20;

/// Why a read was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// It would pass the reader's limit (`binary_code_bytes`, or the scan's `binary_scan_bytes`).
    Budget,
    /// The range is not inside the file.
    OutsideFile,
    /// The read failed. Its bytes stay charged.
    Io,
    /// The request, of this many bytes, is over [`MAX_READ`].
    TooLarge(u64),
}

/// The charged reader of one artifact.
pub(crate) struct Reader<'f> {
    file: &'f File,
    size: u64,
    limit: u64,
    used: u64,
}

impl<'f> Reader<'f> {
    /// `size`: the file's size from the read's `fstat`; `limit`: the budget it charges
    /// (`binary_code_bytes`, or the scan's `binary_scan_bytes`).
    pub fn new(file: &'f File, size: u64, limit: u64) -> Reader<'f> {
        Reader {
            file,
            size,
            limit,
            used: 0,
        }
    }

    /// `len` bytes at `offset`, charged first. Refused for the budget, the range, or the size:
    /// nothing is charged (or allocated); a failed read keeps its charge.
    pub fn read(&mut self, offset: u64, len: u64) -> Result<Vec<u8>, Refusal> {
        if len > MAX_READ {
            return Err(Refusal::TooLarge(len));
        }
        let end = offset.checked_add(len).ok_or(Refusal::OutsideFile)?;
        if end > self.size {
            return Err(Refusal::OutsideFile);
        }
        let n = usize::try_from(len).map_err(|_| Refusal::TooLarge(len))?;
        match self.used.checked_add(len) {
            Some(total) if total <= self.limit => self.used = total,
            _ => return Err(Refusal::Budget),
        }
        let mut buf = vec![0; n];
        self.file
            .read_exact_at(&mut buf, offset)
            .map_err(|_| Refusal::Io)?;
        Ok(buf)
    }

    pub fn used(&self) -> u64 {
        self.used
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn file(bytes: &[u8]) -> (tempfile::NamedTempFile, u64) {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        (f, bytes.len() as u64)
    }

    #[test]
    fn reads_are_charged_before_they_happen() {
        let (f, size) = file(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let mut r = Reader::new(f.as_file(), size, 6);
        assert_eq!(r.read(2, 4).unwrap(), [3, 4, 5, 6]);
        assert_eq!(r.used(), 4);
        assert_eq!(
            r.read(0, 3),
            Err(Refusal::Budget),
            "4 + 3 > 6: refused, nothing read"
        );
        assert_eq!(r.used(), 4, "the refused read charged nothing");
        assert_eq!(r.read(0, 2).unwrap(), [1, 2], "a smaller read still fits");
    }

    #[test]
    fn reads_outside_the_file_are_refused_without_a_charge() {
        let (f, size) = file(&[0; 8]);
        let mut r = Reader::new(f.as_file(), size, 1 << 20);
        assert_eq!(r.read(6, 4), Err(Refusal::OutsideFile));
        assert_eq!(r.read(u64::MAX, 2), Err(Refusal::OutsideFile));
        assert_eq!(r.used(), 0);
    }

    #[test]
    fn a_failed_read_keeps_its_charge() {
        let (f, _) = file(&[0; 8]);
        // A size the file does not have: the range passes, the `pread` comes up short.
        let mut r = Reader::new(f.as_file(), 100, 1 << 20);
        assert_eq!(r.read(4, 8), Err(Refusal::Io));
        assert_eq!(r.used(), 8);
    }

    #[test]
    fn a_read_over_max_read_is_refused_without_a_charge() {
        let (f, size) = file(&[0; 8]);
        let mut r = Reader::new(f.as_file(), size, u64::MAX);
        assert_eq!(
            r.read(0, MAX_READ + 1),
            Err(Refusal::TooLarge(MAX_READ + 1))
        );
        assert_eq!(r.read(4, u64::MAX), Err(Refusal::TooLarge(u64::MAX)));
        assert_eq!(r.used(), 0);
        // Exactly `MAX_READ` is not too large: here the budget refuses it, before any allocation.
        let mut r = Reader::new(f.as_file(), u64::MAX, MAX_READ - 1);
        assert_eq!(r.read(0, MAX_READ), Err(Refusal::Budget));
        assert_eq!(r.used(), 0);
    }
}
