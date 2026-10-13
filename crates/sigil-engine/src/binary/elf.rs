//! ELF facts (spec §4.3, §4.9). The program headers come first (what the loader reads), then the
//! sections. Each fact is read in full, confirmed absent, or a gap (§4.8). Everything is read
//! through the budgeted checkpoint ([`Bounded`]).

use std::collections::BTreeSet;
use std::mem::size_of;

use object::elf;
use object::read::elf::{
    Dyn, FileHeader, ProgramHeader, Rel, Rela, SectionHeader, SectionTable, Sym, SymbolTable,
};
use object::read::{ReadCacheOps, ReadRef, SectionIndex, SymbolIndex};
use object::{Endian, Endianness, FileKind, Pod};
use sigil_model::{ContainerFacts, ElfFacts, ElfImport, UntrustedText};

use super::read::Bounded;
use super::vaddr::{Load, Loads, Place};
use super::{data, goinfo, BinaryBudgets, Parsed};

/// Output limits (spec §4.9).
pub const MAX_DYNAMIC: u64 = 65_536;
pub const MAX_NEEDED: usize = 1_024;
pub const MAX_PATHS: usize = 64;
pub const MAX_NOTES: usize = 1_024;
pub const MAX_BUILD_ID: usize = 64;
pub const MAX_COMMENTS: usize = 16;
pub const MAX_COMMENT: usize = 256;
pub const MAX_INTERP: u64 = 4_096;
/// The longest import name kept (spec §3.7).
pub const MAX_IMPORT_NAME: usize = 65_536;
/// The first read of a name: enough for the names SIGIL looks for, and for most others.
const NAME_CHUNK: u64 = 256;

/// What `PT_DYNAMIC` says, for the other steps.
#[derive(Debug, Default)]
pub(crate) struct Dynamic {
    /// The `PT_DYNAMIC` table was read: the loader links the file through it, and a section it
    /// has no tag for is not what the loader reads.
    pub read: bool,
    /// `DT_SYMTAB`: where the loader reads the dynamic symbols.
    pub symtab: Option<u64>,
    /// `DT_STRTAB`: where the loader reads their names, and the versions' names.
    pub strtab: Option<u64>,
    /// `DT_HASH` and `DT_GNU_HASH`: the hash tables a lookup goes through.
    pub hash: Option<u64>,
    pub gnu_hash: Option<u64>,
    /// `DT_VERSYM`: where the loader reads the symbols' versions; `DT_VERNEED` and `DT_VERDEF`:
    /// the versions they name.
    pub versym: Option<u64>,
    pub verneed: Option<u64>,
    pub verdef: Option<u64>,
    /// `DT_RELA`/`DT_RELASZ`: `(vaddr, size)`.
    pub rela: Option<(u64, u64)>,
    /// `DT_JMPREL`/`DT_PLTRELSZ` when `DT_PLTREL` is `DT_RELA`: `(vaddr, size)`.
    pub jmprel_rela: Option<(u64, u64)>,
    /// `DT_REL`/`DT_RELSZ`, and `DT_JMPREL`/`DT_PLTRELSZ` when `DT_PLTREL` is not `DT_RELA`:
    /// `(vaddr, size)`. Read only for their symbol indices (spec §3.2).
    pub rel: Option<(u64, u64)>,
    pub jmprel_rel: Option<(u64, u64)>,
    /// `DT_REL`, `DT_RELR`, or a REL `DT_JMPREL` exists: SIGIL does not apply them, so no
    /// data value is read (spec §3.4).
    pub rel_or_relr: bool,
    /// Why the RELA tables cannot be read as the loader reads them: a size that is not a whole
    /// number of entries, or a `DT_RELAENT` other than the entry size. Also a gap.
    pub rela_malformed: Option<String>,
}

/// A relocation the loader applies: `(r_offset, type, addend)`.
pub(crate) type Reloc = (u64, u32, i64);

/// The sections' results the other steps need.
pub(crate) struct Sections<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>> {
    /// The symbols the data step reads: `.dynsym`, or a relocatable object's `.symtab`.
    pub symbols: Option<SymbolTable<'d, H, &'d Bounded<R>>>,
    /// `.go.buildinfo`: `(sh_addr, sh_size)`, read where Go reads it (spec §3.6).
    pub go_section: Option<(u64, u64)>,
}

/// The parse of one ELF, generic over class and byte order.
pub(crate) struct Elf<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>> {
    pub data: &'d Bounded<R>,
    pub header: &'d H,
    pub endian: Endianness,
    pub phdrs: &'d [H::ProgramHeader],
    pub loads: Loads,
    pub gaps: Vec<String>,
}

fn empty() -> ElfFacts {
    ElfFacts {
        interp: None,
        soname: None,
        needed: vec![],
        rpath: vec![],
        runpath: vec![],
        build_id: None,
        comment: vec![],
        stripped: None,
        exports: 0,
        imports: vec![],
        data: vec![],
    }
}

/// The facts of the ELF in `data`. Never fails: what cannot be read is a gap.
pub fn parse<R: ReadCacheOps>(data: &Bounded<R>, budgets: BinaryBudgets) -> Parsed {
    let parsed = match FileKind::parse(data) {
        Ok(FileKind::Elf32) => parse_as::<R, elf::FileHeader32<Endianness>>(data, budgets),
        Ok(FileKind::Elf64) => parse_as::<R, elf::FileHeader64<Endianness>>(data, budgets),
        _ => None,
    };
    let mut parsed = parsed.unwrap_or_else(|| Parsed {
        container: ContainerFacts::Elf(empty()),
        go: None,
        gaps: vec![
            "malformed: header: not a complete ELF header".to_string(),
            "sections: no readable ELF header".to_string(),
        ],
    });
    if data.refused() {
        parsed
            .gaps
            .push(format!("binary_parse_bytes: {} exceeded", data.budget()));
    }
    parsed.gaps.sort();
    parsed.gaps.dedup();
    parsed
}

fn parse_as<R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    data: &Bounded<R>,
    budgets: BinaryBudgets,
) -> Option<Parsed> {
    let header = H::parse(data).ok()?;
    let endian = header.endian().ok()?;
    let mut gaps = vec![];
    let phdrs: &[H::ProgramHeader] = match header.program_headers(endian, data) {
        Ok(p) => p,
        Err(e) => {
            gaps.push(format!("malformed: program headers: {e}"));
            &[]
        }
    };
    let loads = Loads(
        phdrs
            .iter()
            .filter(|p| p.p_type(endian) == elf::PT_LOAD)
            .map(|p| {
                let flags = p.p_flags(endian).0;
                Load {
                    vaddr: p.p_vaddr(endian).into(),
                    offset: p.p_offset(endian).into(),
                    filesz: p.p_filesz(endian).into(),
                    memsz: p.p_memsz(endian).into(),
                    writable: flags & elf::PF_W.0 != 0,
                    executable: flags & elf::PF_X.0 != 0,
                }
            })
            .collect(),
    );
    let mut e = Elf {
        data,
        header,
        endian,
        phdrs,
        loads,
        gaps,
    };
    let mut facts = empty();
    facts.interp = e.interp();
    let dynamic = e.dynamic(&mut facts);
    facts.build_id = e.build_id();
    let sections = e.sections(&mut facts, &dynamic, budgets);
    if let Some(symbols) = &sections.symbols {
        facts.data = data::read(&mut e, symbols, &dynamic);
    }
    let go = goinfo::find(&mut e, sections.go_section);
    Some(Parsed {
        container: ContainerFacts::Elf(facts),
        go,
        gaps: e.gaps,
    })
}

impl<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>> Elf<'d, R, H> {
    /// Records a gap once: a malformed table can repeat the same failure for every entry, and
    /// the gaps must stay bounded too.
    fn gap(&mut self, gap: impl Into<String>) {
        let gap = gap.into();
        if !self.gaps.contains(&gap) {
            self.gaps.push(gap);
        }
    }

    /// `PT_INTERP`, up to its NUL.
    fn interp(&mut self) -> Option<UntrustedText> {
        let endian = self.endian;
        let p = self
            .phdrs
            .iter()
            .find(|p| p.p_type(endian) == elf::PT_INTERP)?;
        let offset: u64 = p.p_offset(endian).into();
        let size = Into::<u64>::into(p.p_filesz(endian)).min(MAX_INTERP);
        let Ok(bytes) = self.data.read_bytes_at(offset, size) else {
            self.gap("interp: outside the file");
            return None;
        };
        match bytes.iter().position(|b| *b == 0) {
            Some(end) => Some(UntrustedText::from_bytes(bytes[..end].to_vec())),
            None => {
                self.gap("interp: no NUL within 4 KiB");
                None
            }
        }
    }

    /// `PT_DYNAMIC`: SONAME, NEEDED, RPATH, RUNPATH, and what the other steps need. The last
    /// `PT_DYNAMIC`, read where its `p_vaddr` is in the file: glibc and musl keep the last one
    /// (their program-header loop overwrites it) and read it in memory (spec §3.5).
    fn dynamic(&mut self, facts: &mut ElfFacts) -> Dynamic {
        let endian = self.endian;
        let mut out = Dynamic::default();
        let phdrs = self.phdrs;
        let mut dynamics = phdrs.iter().filter(|p| p.p_type(endian) == elf::PT_DYNAMIC);
        let Some(p) = dynamics.next_back() else {
            return out;
        };
        if dynamics.next().is_some() {
            self.gap("dynamic: more than one PT_DYNAMIC");
        }
        let vaddr: u64 = p.p_vaddr(endian).into();
        let filesz: u64 = p.p_filesz(endian).into();
        let entry = size_of::<H::Dyn>() as u64;
        if !filesz.is_multiple_of(entry) {
            self.gap("dynamic: malformed: p_filesz is not a whole number of entries");
        }
        let mut count = filesz / entry;
        if count > MAX_DYNAMIC {
            self.gap(format!("dynamic: over {MAX_DYNAMIC} entries"));
            count = MAX_DYNAMIC;
        }
        let Place::File(offset) = self.loads.place(vaddr, count * entry) else {
            self.gap("dynamic: not file-backed at p_vaddr");
            return out;
        };
        let Ok(entries) = self.data.read_slice_at::<H::Dyn>(offset, count as usize) else {
            self.gap("dynamic: outside the file");
            return out;
        };
        out.read = true;
        let (mut strtab, mut strsz, mut syment) = (None, None, None);
        let (mut rela, mut relasz, mut relaent, mut jmprel, mut pltrelsz, mut pltrel) =
            (None, None, None, None, None, None);
        let (mut rel, mut relsz, mut relent) = (None, None, None);
        // The string tags, in order: (tag, offset into the string table).
        let mut strings: Vec<(elf::DynamicTag, u64)> = vec![];
        let mut terminated = false;
        for d in entries {
            let tag = d.tag(endian);
            let val = d.val(endian);
            match tag {
                elf::DT_NULL => {
                    terminated = true;
                    break;
                }
                elf::DT_STRTAB => strtab = Some(val),
                elf::DT_STRSZ => strsz = Some(val),
                elf::DT_NEEDED | elf::DT_SONAME | elf::DT_RPATH | elf::DT_RUNPATH => {
                    strings.push((tag, val))
                }
                elf::DT_SYMTAB => out.symtab = Some(val),
                elf::DT_SYMENT => syment = Some(val),
                elf::DT_HASH => out.hash = Some(val),
                elf::DT_GNU_HASH => out.gnu_hash = Some(val),
                elf::DT_VERSYM => out.versym = Some(val),
                elf::DT_VERNEED => out.verneed = Some(val),
                elf::DT_VERDEF => out.verdef = Some(val),
                elf::DT_RELA => rela = Some(val),
                elf::DT_RELASZ => relasz = Some(val),
                elf::DT_RELAENT => relaent = Some(val),
                elf::DT_REL => {
                    rel = Some(val);
                    out.rel_or_relr = true;
                }
                elf::DT_RELSZ => relsz = Some(val),
                elf::DT_RELENT => relent = Some(val),
                elf::DT_JMPREL => jmprel = Some(val),
                elf::DT_PLTRELSZ => pltrelsz = Some(val),
                elf::DT_PLTREL => pltrel = Some(val),
                elf::DT_RELR => out.rel_or_relr = true,
                _ => {}
            }
        }
        out.strtab = strtab;
        // Without its DT_NULL the table may go on past what was read: NEEDED could be missing.
        if !terminated {
            self.gap("dynamic: missing DT_NULL");
        }
        if let (Some(a), Some(n)) = (rela, relasz) {
            out.rela = Some((a, n));
        }
        if let (Some(a), Some(n)) = (rel, relsz) {
            out.rel = Some((a, n));
        }
        if let (Some(a), Some(n)) = (jmprel, pltrelsz) {
            if pltrel == Some(elf::DT_RELA.0 as u64) {
                out.jmprel_rela = Some((a, n));
            } else {
                out.rel_or_relr = true;
                out.jmprel_rel = Some((a, n));
            }
        }
        // glibc refuses a DT_SYMENT other than its symbol size (spec §3.2).
        let sym_size = size_of::<H::Sym>() as u64;
        if syment.is_some_and(|n| n != sym_size) {
            self.gap(format!("dynamic: malformed: DT_SYMENT is not {sym_size}"));
        }
        // The loader walks a table up to its size, so a partial last entry is applied too, and it
        // refuses an entry size other than its own: checked here, whether or not a value needs
        // the tables later.
        let rela_size = size_of::<H::Rela>() as u64;
        let mut malformed = vec![];
        if relaent.is_some_and(|n| n != rela_size) {
            malformed.push(format!("DT_RELAENT is not {rela_size}"));
        }
        if out.rela.is_some_and(|(_, n)| !n.is_multiple_of(rela_size)) {
            malformed.push("DT_RELASZ is not a whole number of entries".to_string());
        }
        if out
            .jmprel_rela
            .is_some_and(|(_, n)| !n.is_multiple_of(rela_size))
        {
            malformed.push("DT_PLTRELSZ is not a whole number of entries".to_string());
        }
        for why in &malformed {
            self.gap(format!("dynamic: malformed: {why}"));
        }
        out.rela_malformed = malformed.into_iter().next();
        // REL tables are read only for their symbol indices (spec §3.2): the same checks.
        let rel_size = size_of::<H::Rel>() as u64;
        if relent.is_some_and(|n| n != rel_size) {
            self.gap(format!("dynamic: malformed: DT_RELENT is not {rel_size}"));
        }
        if out.rel.is_some_and(|(_, n)| !n.is_multiple_of(rel_size)) {
            self.gap("dynamic: malformed: DT_RELSZ is not a whole number of entries");
        }
        if out
            .jmprel_rel
            .is_some_and(|(_, n)| !n.is_multiple_of(rel_size))
        {
            self.gap("dynamic: malformed: DT_PLTRELSZ is not a whole number of entries");
        }
        if strings.is_empty() {
            return out;
        }
        let (Some(strtab), Some(strsz)) = (strtab, strsz) else {
            self.gap("dynamic: strings without DT_STRTAB/DT_STRSZ");
            return out;
        };
        let Place::File(base) = self.loads.place(strtab, strsz) else {
            self.gap("dynamic: DT_STRTAB not file-backed");
            return out;
        };
        let Some(end) = base.checked_add(strsz) else {
            self.gap("dynamic: DT_STRTAB not file-backed");
            return out;
        };
        let mut sonames = 0;
        for (tag, at) in strings {
            if at >= strsz {
                self.gap("dynamic: string offset past DT_STRSZ");
                continue;
            }
            let Ok(text) = self.data.read_bytes_at_until(base + at..end, 0) else {
                self.gap("dynamic: a string over 4 KiB or outside the file");
                continue;
            };
            let text = UntrustedText::from_bytes(text.to_vec());
            match tag {
                elf::DT_SONAME => {
                    sonames += 1;
                    facts.soname = Some(text);
                }
                elf::DT_NEEDED => {
                    if facts.needed.len() < MAX_NEEDED {
                        facts.needed.push(text);
                    } else {
                        self.gap(format!("needed: over {MAX_NEEDED}"));
                    }
                }
                _ => {
                    if facts.rpath.len() + facts.runpath.len() >= MAX_PATHS {
                        self.gap(format!("paths: over {MAX_PATHS}"));
                    } else if tag == elf::DT_RPATH {
                        facts.rpath.push(text);
                    } else {
                        facts.runpath.push(text);
                    }
                }
            }
        }
        if sonames > 1 {
            self.gap("dynamic: two DT_SONAME");
        }
        out
    }

    /// `NT_GNU_BUILD_ID` from every `PT_NOTE`, then, if none had one, every `SHT_NOTE`.
    fn build_id(&mut self) -> Option<String> {
        let endian = self.endian;
        let data = self.data;
        let phdrs = self.phdrs;
        for p in phdrs.iter().filter(|p| p.p_type(endian) == elf::PT_NOTE) {
            match p.notes(endian, data) {
                Ok(Some(notes)) => {
                    if let Some(id) = self.build_id_in(notes) {
                        return Some(id);
                    }
                }
                Ok(None) => {}
                Err(e) => self.gap(format!("build-id: malformed note: {e}")),
            }
        }
        let Ok(sections) = self.header.sections(endian, data) else {
            return None;
        };
        for s in sections.iter() {
            if s.sh_type(endian) != elf::SHT_NOTE {
                continue;
            }
            match s.notes(endian, data) {
                Ok(Some(notes)) => {
                    if let Some(id) = self.build_id_in(notes) {
                        return Some(id);
                    }
                }
                Ok(None) => {}
                Err(e) => self.gap(format!("build-id: malformed note: {e}")),
            }
        }
        None
    }

    fn build_id_in(&mut self, mut notes: object::read::elf::NoteIterator<'d, H>) -> Option<String> {
        let endian = self.endian;
        for n in 0.. {
            if n == MAX_NOTES {
                self.gap(format!("notes: over {MAX_NOTES}"));
                return None;
            }
            match notes.next() {
                Ok(Some(note)) => {
                    if note.name() == elf::ELF_NOTE_GNU
                        && note.n_type(endian) == elf::NT_GNU_BUILD_ID
                    {
                        let desc = note.desc();
                        if desc.len() > MAX_BUILD_ID {
                            self.gap(format!("build-id: over {MAX_BUILD_ID} bytes"));
                            return None;
                        }
                        return Some(desc.iter().map(|b| format!("{b:02x}")).collect());
                    }
                }
                Ok(None) => return None,
                Err(e) => {
                    self.gap(format!("build-id: malformed note: {e}"));
                    return None;
                }
            }
        }
        None
    }

    /// The first section named `name`, after the null section. A section whose name cannot be
    /// read could be it: a gap, never "absent" (review of #89). The gap does not start with
    /// `sections: `, which B8 keeps for a table that cannot be read.
    fn section_named(
        &mut self,
        table: &SectionTable<'d, H, &'d Bounded<R>>,
        name: &[u8],
    ) -> Option<&'d H::SectionHeader> {
        let endian = self.endian;
        // The string table `sections()` names them from (`e_shstrndx`).
        let strings = self
            .header
            .shstrndx(endian, self.data)
            .ok()
            .and_then(|i| table.section(SectionIndex(i as usize)).ok())
            .and_then(|s| s.file_range(endian));
        for s in table.iter().skip(1) {
            let read = match strings {
                Some(strings) => self.name(strings, s.sh_name(endian), name.len()),
                None => Err("no section-name table in the file".to_string()),
            };
            match read {
                Ok(Some(n)) if n == name => return Some(s),
                Ok(_) => {}
                Err(e) => self.gap(format!("malformed: section names: {e}")),
            }
        }
        None
    }

    /// The name at `offset` in the string table at `strings` (its file range), when it is at most
    /// `max` bytes. It reads in growing chunks (256 bytes, then ×4, never past the table or
    /// `max + 1` bytes): object's `StringTable::get` stops looking for the NUL after 4096 bytes,
    /// so a valid longer name (a C++ section, symbol, or import) would read as malformed (review
    /// of #89; spec §3.7). `Ok(None)`: no NUL in the first `max + 1` bytes, with more of the
    /// table after them. `Err`: the offset is past the table; the table ends before a NUL, even
    /// exactly `max + 1` bytes on; or the bytes are outside the file or over the parse budget.
    pub(crate) fn name(
        &self,
        strings: (u64, u64),
        offset: u32,
        max: usize,
    ) -> Result<Option<&'d [u8]>, String> {
        let (start, size) = strings;
        let offset = u64::from(offset);
        if offset >= size {
            return Err("a name past its string table".to_string());
        }
        let unreadable = || "a name outside the file or over the parse budget".to_string();
        let at = start.checked_add(offset).ok_or_else(unreadable)?;
        let want = (max as u64).saturating_add(1);
        let room = size - offset;
        let mut len = want.min(NAME_CHUNK).min(room);
        loop {
            let bytes = self
                .data
                .read_bytes_at(at, len)
                .map_err(|()| unreadable())?;
            if let Some(end) = bytes.iter().position(|b| *b == 0) {
                return Ok(Some(&bytes[..end]));
            }
            // The end of the table first: a name it cuts is malformed, whatever its length
            // (review of rev. 2).
            if len == room {
                return Err("a name not terminated in its string table".to_string());
            }
            if len == want {
                return Ok(None);
            }
            len = len.saturating_mul(4).min(want).min(room);
        }
    }

    /// The section facts: `.comment`, stripped, the symbols (`.dynsym`, or a relocatable object's
    /// `.symtab`), and `.go.buildinfo`.
    fn sections(
        &mut self,
        facts: &mut ElfFacts,
        dynamic: &Dynamic,
        budgets: BinaryBudgets,
    ) -> Sections<'d, R, H> {
        let endian = self.endian;
        let data = self.data;
        let none = Sections {
            symbols: None,
            go_section: None,
        };
        let table = match self.header.sections(endian, data) {
            Ok(t) if t.is_empty() => {
                self.gap("sections: no section header table");
                if dynamic.symtab.is_some() {
                    self.gap("symbols: no section header table");
                }
                return none;
            }
            Ok(t) => t,
            Err(e) => {
                self.gap(format!("sections: malformed: {e}"));
                if dynamic.symtab.is_some() {
                    self.gap("symbols: no readable section header table");
                }
                return none;
            }
        };
        facts.stripped = Some(!table.iter().any(|s| s.sh_type(endian) == elf::SHT_SYMTAB));
        if let Some(s) = self.section_named(&table, b".comment") {
            match s.data(endian, data) {
                Ok(bytes) => {
                    // Built within the limits: nothing beyond the 16 kept entries is collected.
                    let mut over = false;
                    for piece in bytes.split(|b| *b == 0).filter(|p| !p.is_empty()) {
                        if facts.comment.len() == MAX_COMMENTS {
                            over = true;
                            break;
                        }
                        if piece.len() > MAX_COMMENT {
                            over = true;
                            continue;
                        }
                        facts
                            .comment
                            .push(UntrustedText::from_bytes(piece.to_vec()));
                    }
                    if over {
                        self.gap(format!(
                            "comment: over {MAX_COMMENTS} entries of {MAX_COMMENT} bytes"
                        ));
                    }
                }
                Err(e) => self.gap(format!("malformed: comment: {e}")),
            }
        }
        // Go takes the section's address and size whatever its type, and reads it through the
        // program headers (spec §3.6).
        let go_section: Option<(u64, u64)> = self
            .section_named(&table, b".go.buildinfo")
            .map(|s| (s.sh_addr(endian).into(), s.sh_size(endian).into()));
        // A relocatable object has no `.dynsym`: its link-time symbol table holds what it leaves
        // for the linker (PR-4b-2a spec §4.4). It has no versions, and its data is not linked
        // yet: a known data symbol in it is `Unknown`, with its gap.
        let relocatable = self.header.e_type(endian) == elf::ET_REL;
        let kind = if relocatable {
            elf::SHT_SYMTAB
        } else {
            elf::SHT_DYNSYM
        };
        let symbols = match table.symbols(endian, data, kind) {
            Ok(s) => s,
            Err(e) => {
                self.gap(format!("malformed: symbols: {e}"));
                return Sections {
                    symbols: None,
                    go_section,
                };
            }
        };
        if symbols.is_empty() {
            if relocatable {
                self.gap("symbols: no SHT_SYMTAB in a relocatable object");
            } else if dynamic.symtab.is_some() {
                self.gap("symbols: no SHT_DYNSYM");
            }
            return Sections {
                symbols: None,
                go_section,
            };
        }
        let versions = if relocatable {
            None
        } else {
            match table.versions(endian, data) {
                Ok(v) => v,
                Err(e) => {
                    self.gap(format!("malformed: versions: {e}"));
                    None
                }
            }
        };
        // object treats a symbol past the end of `.gnu.version` as unversioned: say it instead.
        let versym_entries = table
            .iter()
            .find(|s| s.sh_type(endian) == elf::SHT_GNU_VERSYM)
            .map(|s| Into::<u64>::into(s.sh_size(endian)) / 2);
        if versym_entries.is_some_and(|n| n < symbols.len() as u64) {
            self.gap("versions: .gnu.version is shorter than .dynsym");
        }
        if !relocatable {
            self.loader_agrees(&table, &symbols, dynamic);
        }
        // The symbols' string table, for the names object cannot read (spec §3.7).
        let strings = table
            .section(symbols.string_section())
            .ok()
            .and_then(|s| s.file_range(endian));
        // At most `binary_imports` imports are ever held: the smallest, in sorted order.
        let limit = usize::try_from(budgets.imports).unwrap_or(usize::MAX);
        let mut imports: BTreeSet<ElfImport> = BTreeSet::new();
        let mut over = false;
        for (i, sym) in symbols.symbols().iter().enumerate().skip(1) {
            let bind = sym.st_bind();
            let global = bind == elf::STB_GLOBAL || bind == elf::STB_WEAK;
            if sym.st_shndx(endian) == elf::SHN_UNDEF {
                if !global {
                    continue;
                }
                let name = match sym.name(endian, symbols.strings()) {
                    Ok(n) => n,
                    // object stops looking for the NUL after 4096 bytes: read on (spec §3.7).
                    Err(e) => {
                        match strings.map(|s| self.name(s, sym.st_name(endian), MAX_IMPORT_NAME)) {
                            Some(Ok(Some(n))) => n,
                            Some(Ok(None)) => {
                                self.gap(format!("imports: a name over {MAX_IMPORT_NAME} bytes"));
                                continue;
                            }
                            Some(Err(why)) => {
                                self.gap(format!("malformed: symbols: {why}"));
                                continue;
                            }
                            None => {
                                self.gap(format!("malformed: symbols: {e}"));
                                continue;
                            }
                        }
                    }
                };
                if name.is_empty() {
                    continue;
                }
                let mut version = None;
                if let Some(v) = &versions {
                    let index = v.version_index(endian, SymbolIndex(i)).index();
                    match v.version(index) {
                        Ok(Some(found)) => {
                            version = Some(UntrustedText::from_bytes(found.name().to_vec()))
                        }
                        Ok(None) => {}
                        // An index that resolves to nothing is not "unversioned".
                        Err(e) => self.gap(format!("versions: {e}")),
                    }
                }
                imports.insert(ElfImport {
                    name: UntrustedText::from_bytes(name.to_vec()),
                    version,
                    weak: bind == elf::STB_WEAK,
                });
                if imports.len() > limit {
                    imports.pop_last();
                    over = true;
                }
            } else {
                let visibility = sym.st_visibility();
                if (global || bind == elf::STB_GNU_UNIQUE)
                    && (visibility == elf::STV_DEFAULT || visibility == elf::STV_PROTECTED)
                {
                    facts.exports += 1;
                }
            }
        }
        if over {
            self.gap(format!("imports: over binary_imports {}", budgets.imports));
        }
        facts.imports = imports.into_iter().collect();
        Sections {
            symbols: Some(symbols),
            go_section,
        }
    }

    /// What the loader uses agrees with the sections SIGIL reads (spec §3.1, §3.2): each
    /// disagreement is a gap. Not for a relocatable object, which no loader reads.
    fn loader_agrees(
        &mut self,
        table: &SectionTable<'d, H, &'d Bounded<R>>,
        symbols: &SymbolTable<'d, H, &'d Bounded<R>>,
        dynamic: &Dynamic,
    ) {
        let endian = self.endian;
        let count = symbols.len() as u64;
        // Where the loader reads the symbols and their names: nowhere without DT_SYMTAB.
        if dynamic.read && dynamic.symtab.is_none() {
            self.gap("symbols: .dynsym without DT_SYMTAB");
        }
        if let Some(symtab) = dynamic.symtab {
            // Without a hash table, a lookup finds none of the symbols.
            if dynamic.hash.is_none() && dynamic.gnu_hash.is_none() {
                self.gap("symbols: DT_SYMTAB without DT_HASH or DT_GNU_HASH");
            }
            if let Err(why) = self.loader_reads(table.section(symbols.section()).ok(), symtab) {
                self.gap(format!("symbols: .dynsym {why} DT_SYMTAB"));
            }
            match dynamic.strtab {
                Some(strtab) => {
                    let strings = table.section(symbols.string_section()).ok();
                    if let Err(why) = self.loader_reads(strings, strtab) {
                        self.gap(format!("symbols: .dynsym's string table {why} DT_STRTAB"));
                    }
                }
                None => self.gap("symbols: DT_SYMTAB without DT_STRTAB"),
            }
        }
        // How many symbols a lookup reaches.
        if let Some(hash) = dynamic.hash {
            match self.sysv_hash_count(hash) {
                Ok(n) if n != count => {
                    self.gap(format!("symbols: .dynsym has {count} entries, DT_HASH {n}"))
                }
                Ok(_) => {}
                Err(()) => self.gap("symbols: DT_HASH cannot be read"),
            }
        }
        if let Some(gnu_hash) = dynamic.gnu_hash {
            match self.gnu_hash_count(gnu_hash) {
                // The unhashed symbols are in the table too, whether or not one is hashed.
                Ok((symoffset, _)) if symoffset > count => self.gap(format!(
                    "symbols: .dynsym has {count} entries, DT_GNU_HASH's symoffset {symoffset}"
                )),
                Ok((_, Some(n))) if n != count => self.gap(format!(
                    "symbols: .dynsym has {count} entries, DT_GNU_HASH {n}"
                )),
                // Empty (no count, symoffset within the table), or in agreement.
                Ok(_) => {}
                Err(()) => self.gap("symbols: DT_GNU_HASH cannot be read"),
            }
        }
        // Which symbols a relocation binds: the imports.
        match self.largest_symbol_index(dynamic) {
            Ok(Some(i)) if u64::from(i) >= count => self.gap(format!(
                "symbols: a relocation names symbol {i} past .dynsym's {count} entries"
            )),
            Ok(_) => {}
            Err(why) => self.gap(format!("symbols: relocations not read: {why}")),
        }
        // ld.so checks versions through DT_VERSYM, DT_VERNEED, and DT_VERDEF, whatever the
        // sections say; object reads the first section of each type.
        for (tag, at, sh_type, name) in [
            (
                "DT_VERSYM",
                dynamic.versym,
                elf::SHT_GNU_VERSYM,
                ".gnu.version",
            ),
            (
                "DT_VERNEED",
                dynamic.verneed,
                elf::SHT_GNU_VERNEED,
                ".gnu.version_r",
            ),
            (
                "DT_VERDEF",
                dynamic.verdef,
                elf::SHT_GNU_VERDEF,
                ".gnu.version_d",
            ),
        ] {
            match (at, table.iter().find(|s| s.sh_type(endian) == sh_type)) {
                (None, None) => {}
                // The loader does not read it: its versions are not the ones the loader uses.
                (None, Some(_)) => {
                    if dynamic.read {
                        self.gap(format!("versions: {name} without {tag}"));
                    }
                }
                (Some(_), None) => self.gap(format!("versions: {tag} without a {name} section")),
                (Some(at), Some(s)) => {
                    if let Err(why) = self.loader_reads(Some(s), at) {
                        self.gap(format!("versions: {name} {why} {tag}"));
                    }
                }
            }
        }
        // object names the versions from the strings of the symbol table `.gnu.version` links,
        // ld.so from DT_STRTAB: checked above for `.dynsym`'s.
        if let Some(s) = table
            .iter()
            .find(|s| s.sh_type(endian) == elf::SHT_GNU_VERSYM)
        {
            if s.sh_link(endian) as usize != symbols.section().0 {
                self.gap("versions: .gnu.version does not link .dynsym");
            }
        }
    }

    /// Whether section `s` is the table the loader reads at `vaddr` (review of #91): object reads
    /// a section at its `sh_offset`, the loader reads the address through the `PT_LOAD`s, so both
    /// the address and the bytes must agree. `Err` says how it does not.
    fn loader_reads(&self, s: Option<&H::SectionHeader>, vaddr: u64) -> Result<(), &'static str> {
        let endian = self.endian;
        let Some(s) = s.filter(|s| Into::<u64>::into(s.sh_addr(endian)) == vaddr) else {
            return Err("is not at");
        };
        match self.loads.place(vaddr, s.sh_size(endian).into()) {
            Place::File(offset) if offset == s.sh_offset(endian).into() => Ok(()),
            _ => Err("is not the bytes mapped at"),
        }
    }

    /// The whole entries of a relocation table at `vaddr`, `size` bytes, where the loader reads
    /// it. A partial last entry is the `dynamic: malformed:` gap of `dynamic()`.
    fn relocation_table<T: Pod>(&self, vaddr: u64, size: u64) -> Result<&'d [T], String> {
        let Place::File(offset) = self.loads.place(vaddr, size) else {
            return Err("a relocation table is not file-backed".to_string());
        };
        let count = size / size_of::<T>() as u64;
        self.data
            .read_slice_at::<T>(offset, count as usize)
            .map_err(|()| "a relocation table outside the file or over the budget".to_string())
    }

    /// The largest symbol index the loader's relocation tables name (`DT_RELA`, `DT_REL`, and
    /// `DT_JMPREL` of either kind); `None` without a table.
    fn largest_symbol_index(&self, dynamic: &Dynamic) -> Result<Option<u32>, String> {
        let endian = self.endian;
        let mut largest = None;
        for (vaddr, size) in [dynamic.rela, dynamic.jmprel_rela].into_iter().flatten() {
            for r in self.relocation_table::<H::Rela>(vaddr, size)? {
                largest = largest.max(Some(r.r_sym(endian, false)));
            }
        }
        for (vaddr, size) in [dynamic.rel, dynamic.jmprel_rel].into_iter().flatten() {
            for r in self.relocation_table::<H::Rel>(vaddr, size)? {
                largest = largest.max(Some(r.r_sym(endian)));
            }
        }
        Ok(largest)
    }

    /// `len` bytes at virtual address `vaddr`, from a PT_LOAD's file-backed range only.
    fn mapped(&self, vaddr: u64, len: u64) -> Result<&'d [u8], ()> {
        match self.loads.place(vaddr, len) {
            Place::File(offset) => self.data.read_bytes_at(offset, len),
            Place::ZeroFill | Place::Unmapped => Err(()),
        }
    }

    /// The 32-bit word at the start of `bytes`, in the file's byte order.
    fn u32_of(&self, bytes: &[u8]) -> Result<u32, ()> {
        let word: [u8; 4] = bytes.get(..4).ok_or(())?.try_into().map_err(|_| ())?;
        Ok(self.endian.read_u32(word))
    }

    /// `DT_HASH`'s `nchain`: the number of symbols it covers. The loader reads the buckets and
    /// the chains after the header too, so all of it must be file-backed (review of #91, P2-1).
    /// It walks each bucket's chain, reading `symtab[i]` and then `chain[i]` until 0, with no
    /// bound: every index reached must be below `nchain`, and reached once, or the walk reads
    /// past the symbols, loops, or joins another chain (second review of #91).
    fn sysv_hash_count(&self, vaddr: u64) -> Result<u64, ()> {
        let header = self.mapped(vaddr, 8)?;
        let nbucket = u64::from(self.u32_of(&header[0..])?);
        let nchain = u64::from(self.u32_of(&header[4..])?);
        let len = nbucket
            .checked_add(nchain)
            .and_then(|n| n.checked_mul(4))
            .and_then(|n| n.checked_add(8))
            .ok_or(())?;
        let table = self.mapped(vaddr, len)?;
        let words = table[8..].as_chunks::<4>().0;
        let (buckets, chains) = words.split_at(usize::try_from(nbucket).map_err(|_| ())?);
        // One bit per symbol: at most `nchain` bits, and the table is in the file.
        let mut reached = vec![0u64; chains.len().div_ceil(64)];
        for bucket in buckets {
            let mut i = usize::try_from(self.u32_of(bucket)?).map_err(|_| ())?;
            while i != 0 {
                let chain = chains.get(i).ok_or(())?;
                let (word, bit) = (i / 64, 1u64 << (i % 64));
                if reached[word] & bit != 0 {
                    return Err(());
                }
                reached[word] |= bit;
                i = usize::try_from(self.u32_of(chain)?).map_err(|_| ())?;
            }
        }
        Ok(nchain)
    }

    /// What `DT_GNU_HASH` says about the symbols, read through the checkpoint (spec §3.2): its
    /// `symoffset` (the symbols below it are in the table, unhashed), and the number a lookup
    /// reaches, one past the end of the chain of its highest bucket, as object's
    /// `GnuHashTable::symbol_table_length` counts it. No count when every bucket is empty: no
    /// symbol is hashed. `Err`: the table cannot be read where the loader reads it (its bloom
    /// words included: review of #91, P2-1), a non-empty bucket is below `symoffset` (the loader
    /// would read before the chains), or the chain runs out of its `PT_LOAD`'s file-backed range.
    fn gnu_hash_count(&self, vaddr: u64) -> Result<(u64, Option<u64>), ()> {
        let header = self.mapped(vaddr, 16)?;
        let buckets = u64::from(self.u32_of(&header[0..])?);
        let symoffset = u64::from(self.u32_of(&header[4..])?);
        let bloom_words = u64::from(self.u32_of(&header[8..])?);
        let word_size = if self.header.is_type_64() { 8 } else { 4 };
        let bloom_end = bloom_words
            .checked_mul(word_size)
            .and_then(|bloom| bloom.checked_add(16))
            .ok_or(())?;
        self.mapped(vaddr, bloom_end)?;
        let buckets_at = vaddr.checked_add(bloom_end).ok_or(())?;
        let buckets_len = buckets.checked_mul(4).ok_or(())?;
        let mut highest = 0;
        for bucket in self.mapped(buckets_at, buckets_len)?.as_chunks::<4>().0 {
            let bucket = u64::from(self.u32_of(bucket)?);
            // 0 is an empty bucket; any other is the first hashed symbol of its chain.
            if bucket != 0 && bucket < symoffset {
                return Err(());
            }
            highest = highest.max(bucket);
        }
        if highest == 0 {
            return Ok((symoffset, None));
        }
        let chains_at = buckets_at.checked_add(buckets_len).ok_or(())?;
        // The chain ends at the first value with bit 0 set; a chain that runs out of its
        // PT_LOAD's file-backed range is a read that fails.
        let mut index = highest;
        loop {
            let at = index
                .checked_sub(symoffset)
                .and_then(|n| n.checked_mul(4))
                .and_then(|n| chains_at.checked_add(n))
                .ok_or(())?;
            let value = self.u32_of(self.mapped(at, 4)?)?;
            index = index.checked_add(1).ok_or(())?;
            if value & 1 != 0 {
                return Ok((symoffset, Some(index)));
            }
        }
    }

    /// The RELA relocations the loader applies (`DT_RELA`, and `DT_JMPREL` when RELA) whose
    /// written bytes overlap each of `ranges` (`[start, end)`), in `ranges`' order (spec §3.4).
    /// Each writes from its offset as many bytes as its type does ([`Self::write_extent`]). At
    /// most two are kept per range: two are already "more than once". Only those are kept, so a
    /// large table costs no more than its read.
    pub(crate) fn relocations(
        &self,
        dynamic: &Dynamic,
        symbols: &SymbolTable<'d, H, &'d Bounded<R>>,
        ranges: &[(u64, u64)],
    ) -> Result<Vec<Vec<Reloc>>, String> {
        let endian = self.endian;
        if let Some(why) = &dynamic.rela_malformed {
            return Err(why.clone());
        }
        let mut out: Vec<Vec<Reloc>> = vec![vec![]; ranges.len()];
        for (vaddr, size) in [dynamic.rela, dynamic.jmprel_rela].into_iter().flatten() {
            for r in self.relocation_table::<H::Rela>(vaddr, size)? {
                let at: u64 = r.r_offset(endian).into();
                let extent =
                    self.write_extent(r.r_type(endian, false), r.r_sym(endian, false), symbols);
                let end = extent.map_or(u64::MAX, |n| at.saturating_add(n));
                for (hits, (start, stop)) in out.iter_mut().zip(ranges) {
                    if at < *stop && *start < end && hits.len() < 2 {
                        hits.push((at, r.r_type(endian, false).0, r.r_addend(endian).into()));
                    }
                }
            }
        }
        Ok(out)
    }

    /// How many bytes a RELA relocation of type `t` writes from its offset (review of #91,
    /// P1-2), or `None` when SIGIL cannot bound it:
    /// - `R_*_NONE` writes none;
    /// - `R_*_COPY` copies at most its symbol's `st_size` (glibc the smaller of this symbol and
    ///   its definition, musl this one); a symbol past `.dynsym` has no size: unbounded;
    /// - `R_*_TLSDESC` writes two words;
    /// - any other x86-64 or AArch64 type at most 8 bytes: no wider field exists, and
    ///   `R_X86_64_64` writes 8 even in x32, so the bound is not the class's word.
    ///
    /// Another machine's types are not known: unbounded.
    fn write_extent(
        &self,
        t: elf::RelocationType,
        sym: u32,
        symbols: &SymbolTable<'d, H, &'d Bounded<R>>,
    ) -> Option<u64> {
        let (none, copy, tlsdesc) = match self.header.e_machine(self.endian) {
            elf::EM_X86_64 => (
                elf::R_X86_64_NONE,
                elf::R_X86_64_COPY,
                elf::R_X86_64_TLSDESC,
            ),
            elf::EM_AARCH64 if self.header.is_type_64() => (
                elf::R_AARCH64_NONE,
                elf::R_AARCH64_COPY,
                elf::R_AARCH64_TLSDESC,
            ),
            _ => return None,
        };
        if t == none {
            Some(0)
        } else if t == copy {
            let sym = symbols.symbols().get(usize::try_from(sym).ok()?)?;
            Some(sym.st_size(self.endian).into())
        } else if t == tlsdesc {
            Some(16)
        } else {
            Some(8)
        }
    }
}
