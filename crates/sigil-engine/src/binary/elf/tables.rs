//! The ELF section and symbol tables, read as object 0.40 read them, each string on demand (#145).
//!
//! object 0.41 reads a whole string table (`.dynstr`, `.strtab`, `.shstrtab`) when it builds
//! these tables, and loses the table when that read fails or `binary_parse_bytes` refuses it.

use std::fmt;
use std::slice;

use object::elf;
use object::endian::U32;
use object::read::elf::{FileHeader, SectionHeader, Sym, VersionTable};
use object::read::{ReadRef, SectionIndex, StringTable, SymbolIndex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Error(Source);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Object(object::read::Error),
    Ported(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Source::Object(e) => e.fmt(f),
            Source::Ported(message) => f.write_str(message),
        }
    }
}

impl From<object::read::Error> for Error {
    fn from(e: object::read::Error) -> Self {
        Error(Source::Object(e))
    }
}

trait ReadError<T> {
    fn read_error(self, message: &'static str) -> Result<T, Error>;
}

impl<T> ReadError<T> for Option<T> {
    fn read_error(self, message: &'static str) -> Result<T, Error> {
        self.ok_or(Error(Source::Ported(message)))
    }
}

impl<T> ReadError<T> for object::read::Result<T> {
    fn read_error(self, message: &'static str) -> Result<T, Error> {
        self.map_err(|_| Error(Source::Ported(message)))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SectionTable<'d, H: FileHeader, R: ReadRef<'d>> {
    sections: &'d [H::SectionHeader],
    endian: H::Endian,
    data: R,
}

impl<'d, H: FileHeader, R: ReadRef<'d>> SectionTable<'d, H, R> {
    /// object 0.40's `FileHeader::sections`.
    pub(crate) fn parse(header: &H, endian: H::Endian, data: R) -> Result<Self, Error> {
        let sections = header.section_headers(endian, data)?;
        // 0.40's `section_strings`, less the table it built. These checks failed the whole table.
        // The table made no read when built, and SIGIL reads section names itself.
        if !sections.is_empty() {
            let index = header.section_strings_index(endian, data)?;
            let shstrtab = sections.get(index.0).read_error("Invalid ELF e_shstrndx")?;
            if let Some((offset, size)) = shstrtab.file_range(endian) {
                offset
                    .checked_add(size)
                    .read_error("Invalid ELF shstrtab size")?;
            }
        }
        Ok(SectionTable {
            sections,
            endian,
            data,
        })
    }

    pub(crate) fn iter(&self) -> slice::Iter<'d, H::SectionHeader> {
        self.sections.iter()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.sections.is_empty()
    }

    /// object 0.40's `SectionTable::section`.
    pub(crate) fn section(&self, index: SectionIndex) -> Result<&'d H::SectionHeader, Error> {
        if index == SectionIndex(0) {
            return Err(Error(Source::Ported("Invalid ELF section index")));
        }
        self.sections
            .get(index.0)
            .read_error("Invalid ELF section index")
    }

    /// object 0.40's `SectionTable::symbols`.
    pub(crate) fn symbols(
        &self,
        sh_type: elf::SectionType,
    ) -> Result<SymbolTable<'d, H, R>, Error> {
        debug_assert!(sh_type == elf::SHT_DYNSYM || sh_type == elf::SHT_SYMTAB);
        let found = self
            .sections
            .iter()
            .enumerate()
            .find(|(_, s)| s.sh_type(self.endian) == sh_type);
        let Some((index, section)) = found else {
            return Ok(SymbolTable::empty());
        };
        SymbolTable::parse(self, SectionIndex(index), section)
    }

    /// object 0.40's `SectionTable::versions`.
    pub(crate) fn versions(&self) -> Result<Option<VersionTable<'d, H>>, Error> {
        let (endian, data) = (self.endian, self.data);
        let Some((versyms, link)) = self.first(|s| s.gnu_versym(endian, data))? else {
            return Ok(None);
        };
        // A whole symbol-table parse for its strings, as in 0.40. `.gnu.version` can link any
        // section, and that parse's reads and errors are part of 0.40's behaviour.
        let strings = self.symbol_table_by_index(link)?.strings();
        let verdefs = self.first(|s| s.gnu_verdef(endian, data))?.map(|x| x.0);
        let verneeds = self.first(|s| s.gnu_verneed(endian, data))?.map(|x| x.0);
        Ok(Some(VersionTable::parse(
            endian, versyms, verdefs, verneeds, strings,
        )?))
    }

    /// object 0.40's `SectionTable::symbol_table_by_index`.
    fn symbol_table_by_index(&self, index: SectionIndex) -> Result<SymbolTable<'d, H, R>, Error> {
        let section = self.section(index)?;
        match section.sh_type(self.endian) {
            elf::SHT_DYNSYM | elf::SHT_SYMTAB => {}
            _ => {
                return Err(Error(Source::Ported(
                    "Invalid ELF symbol table section type",
                )))
            }
        }
        SymbolTable::parse(self, index, section)
    }

    /// object 0.40's `SectionTable::strings`, with `SectionHeader::strings` inlined.
    fn strings(&self, index: SectionIndex) -> Result<StringTable<'d, R>, Error> {
        if index == SectionIndex(0) {
            return Ok(StringTable::default());
        }
        let section = self.section(index)?;
        if section.sh_type(self.endian) != elf::SHT_STRTAB {
            return Err(Error(Source::Ported("Invalid ELF string section type")));
        }
        let start: u64 = section.sh_offset(self.endian).into();
        let size: u64 = section.sh_size(self.endian).into();
        let end = start
            .checked_add(size)
            .read_error("Invalid ELF string section offset or size")?;
        Ok(StringTable::lazy(self.data, start, end))
    }

    /// object 0.40's `SectionTable::{gnu_versym, gnu_verdef, gnu_verneed}`.
    fn first<T>(
        &self,
        f: impl Fn(&'d H::SectionHeader) -> object::read::Result<Option<T>>,
    ) -> Result<Option<T>, Error> {
        for section in self.sections {
            if let Some(found) = f(section)? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }
}

/// object 0.40's `SymbolTable`.
#[derive(Clone, Copy)]
pub(crate) struct SymbolTable<'d, H: FileHeader, R: ReadRef<'d>> {
    section: SectionIndex,
    string_section: SectionIndex,
    symbols: &'d [H::Sym],
    strings: StringTable<'d, R>,
    shndx: &'d [U32<H::Endian>],
}

impl<'d, H: FileHeader, R: ReadRef<'d>> SymbolTable<'d, H, R> {
    /// object 0.40's `SymbolTable::default`.
    fn empty() -> Self {
        SymbolTable {
            section: SectionIndex(0),
            string_section: SectionIndex(0),
            symbols: &[],
            strings: StringTable::default(),
            shndx: &[],
        }
    }

    /// object 0.40's `SymbolTable::parse`.
    fn parse(
        table: &SectionTable<'d, H, R>,
        index: SectionIndex,
        section: &H::SectionHeader,
    ) -> Result<Self, Error> {
        let (endian, data) = (table.endian, table.data);
        let symbols = section
            .data_as_array(endian, data)
            .read_error("Invalid ELF symbol table data")?;
        let link = SectionIndex(section.sh_link(endian) as usize);
        let strings = table.strings(link)?;
        let mut shndx = &[][..];
        // Every match is read and the last one kept, as in 0.40, since each read is charged.
        for s in table.sections {
            if s.sh_type(endian) == elf::SHT_SYMTAB_SHNDX && s.link(endian) == index {
                shndx = s
                    .data_as_array(endian, data)
                    .read_error("Invalid ELF symtab_shndx data")?;
            }
        }
        Ok(SymbolTable {
            section: index,
            string_section: link,
            symbols,
            strings,
            shndx,
        })
    }

    pub(crate) fn section(&self) -> SectionIndex {
        self.section
    }

    pub(crate) fn string_section(&self) -> SectionIndex {
        self.string_section
    }

    pub(crate) fn strings(&self) -> StringTable<'d, R> {
        self.strings
    }

    pub(crate) fn symbols(&self) -> &'d [H::Sym] {
        self.symbols
    }

    pub(crate) fn enumerate(&self) -> impl Iterator<Item = (SymbolIndex, &'d H::Sym)> {
        self.symbols
            .iter()
            .enumerate()
            .map(|(i, sym)| (SymbolIndex(i), sym))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.symbols.len()
    }

    /// object 0.40's `SymbolTable::symbol`.
    pub(crate) fn symbol(&self, index: SymbolIndex) -> Result<&'d H::Sym, Error> {
        if index == SymbolIndex(0) {
            return Err(Error(Source::Ported("Invalid ELF symbol index")));
        }
        self.symbols
            .get(index.0)
            .read_error("Invalid ELF symbol index")
    }

    /// object 0.40's `SymbolTable::symbol_section`.
    pub(crate) fn symbol_section(
        &self,
        endian: H::Endian,
        symbol: &H::Sym,
        index: SymbolIndex,
    ) -> Result<Option<SectionIndex>, Error> {
        let shndx = symbol.st_shndx(endian);
        if let Some(index) = shndx.index() {
            Ok(Some(SectionIndex(index.into())))
        } else if shndx == elf::SHN_XINDEX {
            let shndx = self
                .shndx
                .get(index.0)
                .map(|x| x.get(endian))
                .read_error("Missing ELF symbol extended index")?;
            if shndx == 0 {
                Ok(None)
            } else {
                Ok(Some(SectionIndex(shndx as usize)))
            }
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use object::elf::{self, FileHeader64};
    use object::read::elf::FileHeader as _;
    use object::read::SymbolIndex;
    use object::Endianness;

    use super::SectionTable;
    use crate::code::synth::{fixture, sections64};

    fn first_error(bytes: &[u8]) -> Option<String> {
        let header = FileHeader64::<Endianness>::parse(bytes).unwrap();
        let endian = header.endian().unwrap();
        let table = match SectionTable::parse(header, endian, bytes) {
            Ok(table) => table,
            Err(e) => return Some(e.to_string()),
        };
        for sh_type in [elf::SHT_DYNSYM, elf::SHT_SYMTAB] {
            let symbols = match table.symbols(sh_type) {
                Ok(symbols) => symbols,
                Err(e) => return Some(e.to_string()),
            };
            for (index, sym) in symbols.enumerate() {
                if let Err(e) = symbols.symbol_section(endian, sym, index) {
                    return Some(e.to_string());
                }
            }
        }
        table.versions().err().map(|e| e.to_string())
    }

    #[test]
    fn each_error_reads_as_object_0_40_wrote_it() {
        let pristine = fixture("elf/libdata.so");
        let sections = sections64(&pristine);
        let index = |name: &str| sections.iter().position(|s| s.0 == name).unwrap();
        let header = |name: &str| sections[index(name)].2;
        let (shnum, past) = (sections.len() as u64, pristine.len() as u64);
        let symbol_1 = sections[index(".symtab")].3 as usize + 24;
        let le = |value: u64, width: usize| value.to_le_bytes()[..width].to_vec();
        let cases = [
            (
                "e_shstrndx 0",
                vec![(62, le(0, 2))],
                "Missing ELF e_shstrndx",
            ),
            (
                "e_shstrndx past the table",
                vec![(62, le(shnum, 2))],
                "Invalid ELF e_shstrndx",
            ),
            (
                ".shstrtab sh_offset u64::MAX",
                vec![(header(".shstrtab") + 24, le(u64::MAX, 8))],
                "Invalid ELF shstrtab size",
            ),
            (
                ".dynsym sh_offset past the file",
                vec![(header(".dynsym") + 24, le(past, 8))],
                "Invalid ELF symbol table data",
            ),
            (
                ".dynsym sh_link past the table",
                vec![(header(".dynsym") + 40, le(shnum, 4))],
                "Invalid ELF section index",
            ),
            (
                ".dynsym sh_link to itself",
                vec![(header(".dynsym") + 40, le(index(".dynsym") as u64, 4))],
                "Invalid ELF string section type",
            ),
            (
                ".dynstr sh_size u64::MAX",
                vec![(header(".dynstr") + 32, le(u64::MAX, 8))],
                "Invalid ELF string section offset or size",
            ),
            (
                ".comment as the SHT_SYMTAB_SHNDX of .symtab, past the file",
                vec![
                    (
                        header(".comment") + 4,
                        le(elf::SHT_SYMTAB_SHNDX.0.into(), 4),
                    ),
                    (header(".comment") + 24, le(past, 8)),
                    (header(".comment") + 40, le(index(".symtab") as u64, 4)),
                ],
                "Invalid ELF symtab_shndx data",
            ),
            (
                ".symtab symbol 1 in SHN_XINDEX",
                vec![(symbol_1 + 6, le(elf::SHN_XINDEX.0.into(), 2))],
                "Missing ELF symbol extended index",
            ),
            (
                ".gnu.version sh_link to .dynstr",
                vec![(header(".gnu.version") + 40, le(index(".dynstr") as u64, 4))],
                "Invalid ELF symbol table section type",
            ),
            (
                ".gnu.version sh_link 0",
                vec![(header(".gnu.version") + 40, le(0, 4))],
                "Invalid ELF section index",
            ),
        ];
        assert_eq!(first_error(&pristine), None, "the fixture reads whole");
        for (what, edits, message) in cases {
            let mut bytes = pristine.clone();
            for (at, value) in edits {
                bytes[at..at + value.len()].copy_from_slice(&value);
            }
            assert_eq!(first_error(&bytes).as_deref(), Some(message), "{what}");
        }

        let header = FileHeader64::<Endianness>::parse(&*pristine).unwrap();
        let endian = header.endian().unwrap();
        let table = SectionTable::parse(header, endian, &*pristine).unwrap();
        let dynsym = table.symbols(elf::SHT_DYNSYM).unwrap();
        for index in [0, dynsym.len()] {
            assert_eq!(
                dynsym.symbol(SymbolIndex(index)).unwrap_err().to_string(),
                "Invalid ELF symbol index",
                "symbol {index}"
            );
        }
        assert_eq!(
            table
                .section(object::read::SectionIndex(0))
                .unwrap_err()
                .to_string(),
            "Invalid ELF section index",
            "the null section"
        );
    }
}
