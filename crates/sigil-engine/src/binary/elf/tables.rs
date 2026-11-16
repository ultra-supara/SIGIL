//! The ELF section and symbol tables, read as object 0.40 read them, each string on demand (#145).
//!
//! object 0.41 reads a whole string table (`.dynstr`, `.strtab`, `.shstrtab`) when it builds
//! these tables, and loses the table when that read fails or `binary_parse_bytes` refuses it.
//! SIGIL reads a name itself when object cannot, so a string table it cannot read must cost only
//! the names in it. Each function here makes the reads its object 0.40 original made, in the same
//! order, and fails with the same message. [`Bounded`](crate::binary::read::Bounded) then charges,
//! refuses and caches as it did, and every session stays byte-identical.

use std::fmt;
use std::slice;

use object::elf;
use object::endian::U32;
use object::read::elf::{FileHeader, SectionHeader, Sym, VersionTable};
use object::read::{ReadRef, SectionIndex, StringTable, SymbolIndex};

/// Why a table cannot be read. Its `Display` is object 0.40's message, which gaps quote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Error(Source);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// From object's own parsers, which 0.41 left as they were.
    Object(object::read::Error),
    /// From the code here, with 0.40's message for the same condition.
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

/// object's private `ReadError`, so each body reads line for line as its 0.40 original.
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

/// The section headers of one ELF, with the reader and byte order they came from. The symbol and
/// version tables are built from it through the same reader.
#[derive(Clone, Copy)]
pub(crate) struct SectionTable<'d, H: FileHeader, R: ReadRef<'d>> {
    sections: &'d [H::SectionHeader],
    endian: H::Endian,
    data: R,
}

impl<'d, H: FileHeader, R: ReadRef<'d>> SectionTable<'d, H, R> {
    /// object 0.40's `FileHeader::sections`. An ELF without section headers is an empty table.
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

    /// The section headers, the null section at index 0 included.
    pub(crate) fn iter(&self) -> slice::Iter<'d, H::SectionHeader> {
        self.sections.iter()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.sections.is_empty()
    }

    /// object 0.40's `SectionTable::section`, an error for the null section at index 0.
    pub(crate) fn section(&self, index: SectionIndex) -> Result<&'d H::SectionHeader, Error> {
        if index == SectionIndex(0) {
            return Err(Error(Source::Ported("Invalid ELF section index")));
        }
        self.sections
            .get(index.0)
            .read_error("Invalid ELF section index")
    }

    /// object 0.40's `SectionTable::symbols`. The first symbol table of `sh_type`, or an empty
    /// table.
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

    /// object 0.40's `SectionTable::versions`, `None` without `SHT_GNU_VERSYM`.
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

    /// object 0.40's `SectionTable::strings`, with `SectionHeader::strings` inlined. An empty
    /// table for index 0.
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
        Ok(StringTable::new(self.data, start, end))
    }

    /// The first `Some` of `f` over the headers, stopping at the first error, as 0.40's
    /// `SectionTable::{gnu_versym, gnu_verdef, gnu_verneed}` do.
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

/// One symbol table and its string table, as object 0.40's `SymbolTable` held them.
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

    /// The section index of this symbol table.
    pub(crate) fn section(&self) -> SectionIndex {
        self.section
    }

    /// The section index of its string table.
    pub(crate) fn string_section(&self) -> SectionIndex {
        self.string_section
    }

    /// Its string table, for object's `Sym::name`, which reads each name on demand.
    pub(crate) fn strings(&self) -> StringTable<'d, R> {
        self.strings
    }

    /// The symbols, the null symbol at index 0 included.
    pub(crate) fn symbols(&self) -> &'d [H::Sym] {
        self.symbols
    }

    /// The symbols with their indices, the null symbol included.
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

    /// object 0.40's `SymbolTable::symbol`, an error for the null symbol at index 0.
    pub(crate) fn symbol(&self, index: SymbolIndex) -> Result<&'d H::Sym, Error> {
        if index == SymbolIndex(0) {
            return Err(Error(Source::Ported("Invalid ELF symbol index")));
        }
        self.symbols
            .get(index.0)
            .read_error("Invalid ELF symbol index")
    }

    /// object 0.40's `SymbolTable::symbol_section`. It reads `SHT_SYMTAB_SHNDX` for `SHN_XINDEX`,
    /// and gives `None` for a reserved index or an extended index of 0.
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

    /// The first error met reading `bytes` in the order the sections step asks: the table,
    /// `.dynsym` then `.symtab` with each symbol's section, then the versions.
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

/// Proves the port against object 0.40, whose own tables are the oracle. The bump deletes it, as
/// 0.41 is no oracle. Equal reads in equal order mean equal charges, refusals and cache hits in
/// `Bounded`, and the budget sweep checks that through `Bounded` itself.
#[cfg(test)]
mod same_as_object_0_40 {
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::mem::size_of;
    use std::ops::Range;
    use std::path::Path;

    use object::elf::{self, FileHeader32, FileHeader64};
    use object::pod::bytes_of;
    use object::read::elf::{FileHeader, SectionHeader, Sym, VersionTable};
    use object::read::{ReadCacheOps, ReadRef, SymbolIndex};
    use object::{Endian, Endianness, FileKind};

    use super::SectionTable;
    use crate::binary::read::Bounded;
    use crate::binary::BinaryBudgets;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Request {
        Len,
        Bytes(u64, u64),
        Until(Range<u64>, u8),
    }

    /// Which requests fail, as an out-of-file or refused read does.
    #[derive(Debug, Clone, Copy)]
    enum Fail {
        Never,
        Only(usize),
        From(usize),
    }

    /// A reader over `bytes` that logs each request and fails the ones `fail` names.
    struct Recorder<'a> {
        bytes: &'a [u8],
        fail: Fail,
        log: RefCell<Vec<Request>>,
    }

    impl<'a> Recorder<'a> {
        fn new(bytes: &'a [u8], fail: Fail) -> Self {
            Recorder {
                bytes,
                fail,
                log: RefCell::new(vec![]),
            }
        }

        fn record(&self, request: Request) -> Result<(), ()> {
            let mut log = self.log.borrow_mut();
            let k = log.len();
            log.push(request);
            match self.fail {
                Fail::Only(n) if k == n => Err(()),
                Fail::From(n) if k >= n => Err(()),
                _ => Ok(()),
            }
        }
    }

    impl<'a> ReadRef<'a> for &'a Recorder<'a> {
        fn len(self) -> Result<u64, ()> {
            self.record(Request::Len)?;
            ReadRef::len(self.bytes)
        }

        fn read_bytes_at(self, offset: u64, size: u64) -> Result<&'a [u8], ()> {
            self.record(Request::Bytes(offset, size))?;
            self.bytes.read_bytes_at(offset, size)
        }

        fn read_bytes_at_until(self, range: Range<u64>, delimiter: u8) -> Result<&'a [u8], ()> {
            self.record(Request::Until(range.clone(), delimiter))?;
            self.bytes.read_bytes_at_until(range, delimiter)
        }
    }

    /// A `Bounded` that logs what it has charged after each request.
    struct Charges<'a, R: ReadCacheOps> {
        bounded: &'a Bounded<R>,
        used: RefCell<Vec<u64>>,
    }

    impl<'a, R: ReadCacheOps> ReadRef<'a> for &'a Charges<'a, R> {
        fn len(self) -> Result<u64, ()> {
            ReadRef::len(self.bounded)
        }

        fn read_bytes_at(self, offset: u64, size: u64) -> Result<&'a [u8], ()> {
            let read = self.bounded.read_bytes_at(offset, size);
            self.used.borrow_mut().push(self.bounded.used());
            read
        }

        fn read_bytes_at_until(self, range: Range<u64>, delimiter: u8) -> Result<&'a [u8], ()> {
            let read = self.bounded.read_bytes_at_until(range, delimiter);
            self.used.borrow_mut().push(self.bounded.used());
            read
        }
    }

    /// What a caller can observe, in one order for both: the section table, `.dynsym` then
    /// `.symtab` (each `symbol(i)` for `0..=len`, then each symbol's name and section), then the
    /// version of each `.dynsym` symbol. An error is its text.
    #[derive(Debug, PartialEq)]
    enum Seen<'d> {
        Sections(Result<usize, String>),
        Symbols(Result<(usize, usize, usize, bool), String>),
        Symbol(Result<&'d [u8], String>),
        Name(Result<&'d [u8], String>, Result<Option<usize>, String>),
        Versions(Result<bool, String>),
        Version(u16, Result<Option<&'d [u8]>, String>),
    }

    /// Pushes one symbol table's observations, ours or object's (their methods share names), and
    /// gives its length.
    macro_rules! symbols_seen {
        ($seen:ident, $endian:ident, $symbols:expr) => {
            match $symbols {
                Err(e) => {
                    $seen.push(Seen::Symbols(Err(e.to_string())));
                    0
                }
                Ok(t) => {
                    $seen.push(Seen::Symbols(Ok((
                        t.section().0,
                        t.string_section().0,
                        t.len(),
                        t.is_empty(),
                    ))));
                    for i in 0..=t.len() {
                        let symbol = t.symbol(SymbolIndex(i));
                        $seen.push(Seen::Symbol(
                            symbol.map(bytes_of).map_err(|e| e.to_string()),
                        ));
                    }
                    for (i, sym) in t.enumerate() {
                        $seen.push(Seen::Name(
                            sym.name($endian, t.strings()).map_err(|e| e.to_string()),
                            t.symbol_section($endian, sym, i)
                                .map(|s| s.map(|s| s.0))
                                .map_err(|e| e.to_string()),
                        ));
                    }
                    t.len()
                }
            }
        };
    }

    fn versions_seen<'d, H: FileHeader<Endian = Endianness>>(
        seen: &mut Vec<Seen<'d>>,
        endian: Endianness,
        versions: Result<Option<VersionTable<'d, H>>, String>,
        dynsym: usize,
    ) {
        let v = match versions {
            Ok(Some(v)) => v,
            other => return seen.push(Seen::Versions(other.map(|_| false))),
        };
        seen.push(Seen::Versions(Ok(true)));
        for i in 0..dynsym {
            let index = v.version_index(endian, SymbolIndex(i)).index();
            let version = v.version(index).map(|v| v.map(|v| v.name()));
            seen.push(Seen::Version(index.0, version.map_err(|e| e.to_string())));
        }
    }

    fn ours<'d, H: FileHeader<Endian = Endianness>, R: ReadRef<'d>>(
        header: &H,
        endian: Endianness,
        data: R,
    ) -> Vec<Seen<'d>> {
        let mut seen = vec![];
        let table = match SectionTable::parse(header, endian, data) {
            Ok(table) => table,
            Err(e) => {
                seen.push(Seen::Sections(Err(e.to_string())));
                return seen;
            }
        };
        seen.push(Seen::Sections(Ok(table.sections.len())));
        let dynsym = symbols_seen!(seen, endian, table.symbols(elf::SHT_DYNSYM));
        symbols_seen!(seen, endian, table.symbols(elf::SHT_SYMTAB));
        let versions = table.versions().map_err(|e| e.to_string());
        versions_seen(&mut seen, endian, versions, dynsym);
        seen
    }

    fn theirs<'d, H: FileHeader<Endian = Endianness>, R: ReadRef<'d>>(
        header: &H,
        endian: Endianness,
        data: R,
    ) -> Vec<Seen<'d>> {
        let mut seen = vec![];
        let table = match header.sections(endian, data) {
            Ok(table) => table,
            Err(e) => {
                seen.push(Seen::Sections(Err(e.to_string())));
                return seen;
            }
        };
        seen.push(Seen::Sections(Ok(table.len())));
        let dynsym = symbols_seen!(seen, endian, table.symbols(endian, data, elf::SHT_DYNSYM));
        symbols_seen!(seen, endian, table.symbols(endian, data, elf::SHT_SYMTAB));
        let versions = table.versions(endian, data).map_err(|e| e.to_string());
        versions_seen(&mut seen, endian, versions, dynsym);
        seen
    }

    /// The file as is, then one copy per damage, each named.
    fn inputs<H: FileHeader<Endian = Endianness>>(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        let header = H::parse(bytes).unwrap();
        let endian = header.endian().unwrap();
        let sections = header.section_headers(endian, bytes).unwrap();
        let (word, sh_offset, sh_size, sh_link, e_shstrndx, st_shndx) = if header.is_class_64() {
            (8, 24, 32, 40, 62, 6)
        } else {
            (4, 16, 20, 24, 50, 14)
        };
        let shoff: u64 = header.e_shoff(endian).into();
        let at = |index: usize, field: usize| {
            shoff as usize + index * size_of::<H::SectionHeader>() + field
        };
        let first = |sh_type| sections.iter().position(|s| s.sh_type(endian) == sh_type);
        let linked = |index: Option<usize>| {
            index
                .map(|i| sections[i].sh_link(endian) as usize)
                .filter(|&link| link != 0 && link < sections.len())
        };
        let dynsym = first(elf::SHT_DYNSYM);
        let symtab = first(elf::SHT_SYMTAB);
        let versym = first(elf::SHT_GNU_VERSYM);
        let shstrtab = header.shstrndx(endian, bytes).ok().map(|i| i as usize);
        let (dynstr, strtab) = (linked(dynsym), linked(symtab));
        let (len, max) = (bytes.len() as u64, u64::MAX >> (64 - 8 * word));

        let mut out = vec![("as is".to_string(), bytes.to_vec())];
        let mut add = |name: String, edits: &[(usize, usize, u64)]| {
            let mut copy = bytes.to_vec();
            for &(at, width, value) in edits {
                let field = &mut copy[at..at + width];
                match width {
                    2 => field.copy_from_slice(&endian.write_u16(value as u16)),
                    4 => field.copy_from_slice(&endian.write_u32(value as u32)),
                    _ => field.copy_from_slice(&endian.write_u64(value)),
                }
            }
            out.push((name, copy));
        };
        for (name, index) in [
            (".shstrtab", shstrtab),
            (".dynstr", dynstr),
            (".strtab", strtab),
        ] {
            let Some(i) = index else { continue };
            for (field, offset) in [("sh_offset", sh_offset), ("sh_size", sh_size)] {
                add(
                    format!("{name} {field} past the file"),
                    &[(at(i, offset), word, len)],
                );
                add(
                    format!("{name} {field} {max:#x}"),
                    &[(at(i, offset), word, max)],
                );
            }
            let progbits = (at(i, 4), 4, elf::SHT_PROGBITS.0.into());
            add(format!("{name} as SHT_PROGBITS"), &[progbits]);
            let both = [progbits, (at(i, sh_size), word, max)];
            add(format!("{name} as SHT_PROGBITS, sh_size {max:#x}"), &both);
        }
        for (name, index) in [
            (".dynsym", dynsym),
            (".symtab", symtab),
            (".gnu.version", versym),
        ] {
            let Some(i) = index else { continue };
            for (to, link) in [("0", 0), ("itself", i), ("past the table", sections.len())] {
                add(
                    format!("{name} sh_link {to}"),
                    &[(at(i, sh_link), 4, link as u64)],
                );
            }
        }
        let xindex: u64 = elf::SHN_XINDEX.0.into();
        let past = sections.len() as u64;
        for (to, index) in [("0", 0), ("past the table", past), ("SHN_XINDEX", xindex)] {
            add(format!("e_shstrndx {to}"), &[(e_shstrndx, 2, index)]);
        }
        let symtab_with_two = symtab.filter(|&i| {
            let size: u64 = sections[i].sh_size(endian).into();
            size >= 2 * size_of::<H::Sym>() as u64
        });
        if let Some(i) = symtab_with_two {
            let symtab_at: u64 = sections[i].sh_offset(endian).into();
            let in_xindex = (
                symtab_at as usize + size_of::<H::Sym>() + st_shndx,
                2,
                xindex,
            );
            add(".symtab symbol 1 in SHN_XINDEX".into(), &[in_xindex]);
            // Two tables link `.symtab`, and 0.40 read both and kept the last.
            let untouched = [Some(i), dynsym, dynstr, strtab, versym, shstrtab];
            let shndx: u64 = elf::SHT_SYMTAB_SHNDX.0.into();
            let mut edits = vec![in_xindex];
            for s in (1..sections.len())
                .filter(|s| !untouched.contains(&Some(*s)))
                .take(2)
            {
                edits.extend([(at(s, 4), 4, shndx), (at(s, sh_link), 4, i as u64)]);
            }
            add(
                ".symtab symbol 1 in SHN_XINDEX, two SHT_SYMTAB_SHNDX".into(),
                &edits,
            );
        }
        out
    }

    #[derive(Debug, Default)]
    struct Tally {
        inputs: usize,
        fails: usize,
        budgets: usize,
        seen: usize,
    }

    fn same_reads<H: FileHeader<Endian = Endianness>>(
        name: &str,
        header: &H,
        bytes: &[u8],
        fail: Fail,
        tally: &mut Tally,
    ) -> usize {
        let endian = header.endian().unwrap();
        let (a, b) = (Recorder::new(bytes, fail), Recorder::new(bytes, fail));
        let ours = ours(header, endian, &a);
        let theirs = theirs(header, endian, &b);
        assert_eq!(ours, theirs, "{name}, {fail:?}: what the tables say");
        assert_eq!(a.log, b.log, "{name}, {fail:?}: the reads");
        tally.fails += 1;
        tally.seen += ours.len();
        let requests = a.log.borrow().len();
        requests
    }

    fn same_under_budget<H: FileHeader<Endian = Endianness>>(
        name: &str,
        header: &H,
        bytes: &[u8],
        budget: u64,
        tally: &mut Tally,
    ) {
        let endian = header.endian().unwrap();
        let len = bytes.len() as u64;
        let a = Bounded::new(Cursor::new(bytes), len, budget);
        let b = Bounded::new(Cursor::new(bytes), len, budget);
        let ours = ours(header, endian, &a);
        let theirs = theirs(header, endian, &b);
        assert_eq!(ours, theirs, "{name}, budget {budget}: what the tables say");
        assert_eq!(
            (a.used(), a.refusals()),
            (b.used(), b.refusals()),
            "{name}, budget {budget}: the charges and refusals"
        );
        tally.budgets += 1;
        tally.seen += ours.len();
    }

    fn same_as_0_40<H: FileHeader<Endian = Endianness>>(
        path: &Path,
        bytes: &[u8],
        tally: &mut Tally,
    ) {
        for (damage, input) in inputs::<H>(bytes) {
            let name = format!("{} ({damage})", path.display());
            let header = H::parse(&*input).unwrap();
            tally.inputs += 1;
            let requests = same_reads(&name, header, &input, Fail::Never, tally);
            for k in 0..requests {
                for fail in [Fail::Only(k), Fail::From(k)] {
                    same_reads(&name, header, &input, fail, tally);
                }
            }

            let default = BinaryBudgets::default().parse_bytes;
            let unbounded = Bounded::new(Cursor::new(&*input), input.len() as u64, default);
            let charges = Charges {
                bounded: &unbounded,
                used: RefCell::new(vec![]),
            };
            let _ = ours(header, header.endian().unwrap(), &charges);
            let mut budgets = vec![0, default];
            for used in charges.used.into_inner() {
                budgets.extend([used, used.saturating_sub(1)]);
            }
            budgets.sort_unstable();
            budgets.dedup();
            for budget in budgets {
                same_under_budget(&name, header, &input, budget, tally);
            }
        }
    }

    fn files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files(&path, out);
            } else {
                out.push(path);
            }
        }
    }

    #[test]
    fn every_elf_fixture_damage_and_failed_read_reads_as_object_0_40() {
        let mut paths = vec![];
        files(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"),
            &mut paths,
        );
        paths.sort();
        let (mut tally, mut elves) = (Tally::default(), 0);
        for path in paths {
            let bytes = std::fs::read(&path).unwrap();
            match FileKind::parse(&*bytes) {
                Ok(FileKind::Elf32) => {
                    same_as_0_40::<FileHeader32<Endianness>>(&path, &bytes, &mut tally)
                }
                Ok(FileKind::Elf64) => {
                    same_as_0_40::<FileHeader64<Endianness>>(&path, &bytes, &mut tally)
                }
                _ => continue,
            }
            elves += 1;
        }
        eprintln!("{elves} ELF fixtures: {tally:?}");
        assert!(elves >= 60, "the fixtures were found: {elves}");
    }
}
