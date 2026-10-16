//! Code bytes (PR-5a spec §4.2): `pread` on the input's fd, never through the parse cache, each
//! byte charged to `binary_code_bytes` before it is read. Nothing is mapped.

use std::fs::File;
use std::os::unix::fs::FileExt;

/// Why a read was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Used outside tests from Task 11 (`analyze`); until then only tests construct it.
#[allow(dead_code)]
pub(crate) enum Refusal {
    /// It would pass `binary_code_bytes`.
    Budget,
    /// The range is not inside the file.
    OutsideFile,
    /// The read failed.
    Io,
}

/// The charged reader of one artifact.
// Used outside tests from Task 11 (`analyze`); until then only tests construct it.
#[allow(dead_code)]
pub(crate) struct Reader<'f> {
    file: &'f File,
    size: u64,
    limit: u64,
    used: u64,
    refused: bool,
}

// Used outside tests from Task 11 (`analyze`); until then only tests construct it.
#[allow(dead_code)]
impl<'f> Reader<'f> {
    /// `size`: the file's size from the read's `fstat`; `limit`: `binary_code_bytes`.
    pub fn new(file: &'f File, size: u64, limit: u64) -> Reader<'f> {
        Reader {
            file,
            size,
            limit,
            used: 0,
            refused: false,
        }
    }

    /// `len` bytes at `offset`, charged first. A refused read charges nothing.
    pub fn read(&mut self, offset: u64, len: u64) -> Result<Vec<u8>, Refusal> {
        let end = offset.checked_add(len).ok_or(Refusal::OutsideFile)?;
        if end > self.size {
            return Err(Refusal::OutsideFile);
        }
        match self.used.checked_add(len) {
            Some(total) if total <= self.limit => self.used = total,
            _ => {
                self.refused = true;
                return Err(Refusal::Budget);
            }
        }
        let n = usize::try_from(len).map_err(|_| Refusal::OutsideFile)?;
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

    /// Whether a read was refused for the budget.
    pub fn refused(&self) -> bool {
        self.refused
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
        assert!(r.refused());
        assert_eq!(r.used(), 4);
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
}
