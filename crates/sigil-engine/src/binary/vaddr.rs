//! Virtual address → file offset, only through a `PT_LOAD`'s file-backed range (spec §4.3).

/// One loadable segment: `[vaddr, vaddr + filesz)` is backed by `[offset, offset + filesz)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Load {
    pub vaddr: u64,
    pub offset: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub writable: bool,
    pub executable: bool,
}

/// Where a virtual range lies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    /// In the file, at this offset.
    File(u64),
    /// In a segment's zero-fill tail (`filesz..memsz`).
    ZeroFill,
    /// In no segment.
    Unmapped,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Loads(pub Vec<Load>);

impl Loads {
    /// Where `[vaddr, vaddr + len)` lies. All arithmetic is checked: an overflow is `Unmapped`.
    pub fn place(&self, vaddr: u64, len: u64) -> Place {
        let Some(end) = vaddr.checked_add(len) else {
            return Place::Unmapped;
        };
        for l in &self.0 {
            let (Some(file_end), Some(mem_end)) =
                (l.vaddr.checked_add(l.filesz), l.vaddr.checked_add(l.memsz))
            else {
                continue;
            };
            if vaddr >= l.vaddr && end <= file_end {
                return match l.offset.checked_add(vaddr - l.vaddr) {
                    Some(off) => Place::File(off),
                    None => Place::Unmapped,
                };
            }
            if vaddr >= file_end && end <= mem_end {
                return Place::ZeroFill;
            }
        }
        Place::Unmapped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loads() -> Loads {
        Loads(vec![Load {
            vaddr: 0x1000,
            offset: 0x200,
            filesz: 0x100,
            memsz: 0x300,
            writable: true,
            executable: false,
        }])
    }

    #[test]
    fn only_the_file_backed_part_maps_to_the_file() {
        let l = loads();
        assert_eq!(l.place(0x1000, 0x10), Place::File(0x200));
        assert_eq!(l.place(0x10f0, 0x10), Place::File(0x2f0));
        assert_eq!(
            l.place(0x10f8, 0x10),
            Place::Unmapped,
            "crosses the end of filesz"
        );
        assert_eq!(
            l.place(0x1100, 0x10),
            Place::ZeroFill,
            "within memsz, past filesz"
        );
        assert_eq!(l.place(0x2000, 1), Place::Unmapped);
        assert_eq!(l.place(u64::MAX, 2), Place::Unmapped, "overflow");
    }
}
