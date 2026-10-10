//! ELF facts (spec §4.3, §4.9). The program headers come first (what the loader reads), then the
//! sections. Each fact is read in full, confirmed absent, or a gap (§4.8). Everything is read
//! through the budgeted checkpoint ([`Bounded`]).

use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;

use object::elf;
use object::read::elf::{Dyn, FileHeader, ProgramHeader, Rela, SectionHeader, Sym, SymbolTable};
use object::read::{ReadCacheOps, ReadRef, SymbolIndex};
use object::{Endianness, FileKind};
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

/// What `PT_DYNAMIC` says, for the other steps.
#[derive(Debug, Default)]
pub(crate) struct Dynamic {
    /// `DT_SYMTAB` is present: the file has dynamic symbols.
    pub symtab: bool,
    /// `DT_RELA`/`DT_RELASZ`: `(vaddr, size)`.
    pub rela: Option<(u64, u64)>,
    /// `DT_JMPREL`/`DT_PLTRELSZ` when `DT_PLTREL` is `DT_RELA`: `(vaddr, size)`.
    pub jmprel_rela: Option<(u64, u64)>,
    /// `DT_REL`, `DT_RELR`, or a REL `DT_JMPREL` exists (not read in 4b-1).
    pub rel_or_relr: bool,
}

/// The sections' results the other steps need.
pub(crate) struct Sections<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>> {
    pub dynsym: Option<SymbolTable<'d, H, &'d Bounded<R>>>,
    /// `.go.buildinfo`: `(vaddr, file offset, size)`.
    pub go_section: Option<(u64, u64, u64)>,
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
    if let Some(symbols) = &sections.dynsym {
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

    /// `PT_DYNAMIC`: SONAME, NEEDED, RPATH, RUNPATH, and what the other steps need.
    fn dynamic(&mut self, facts: &mut ElfFacts) -> Dynamic {
        let endian = self.endian;
        let mut out = Dynamic::default();
        let Some(p) = self
            .phdrs
            .iter()
            .find(|p| p.p_type(endian) == elf::PT_DYNAMIC)
        else {
            return out;
        };
        let offset: u64 = p.p_offset(endian).into();
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
        let Ok(entries) = self.data.read_slice_at::<H::Dyn>(offset, count as usize) else {
            self.gap("dynamic: outside the file");
            return out;
        };
        let (mut strtab, mut strsz) = (None, None);
        let (mut rela, mut relasz, mut jmprel, mut pltrelsz, mut pltrel) =
            (None, None, None, None, None);
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
                elf::DT_SYMTAB => out.symtab = true,
                elf::DT_RELA => rela = Some(val),
                elf::DT_RELASZ => relasz = Some(val),
                elf::DT_JMPREL => jmprel = Some(val),
                elf::DT_PLTRELSZ => pltrelsz = Some(val),
                elf::DT_PLTREL => pltrel = Some(val),
                elf::DT_REL | elf::DT_RELR => out.rel_or_relr = true,
                _ => {}
            }
        }
        // Without its DT_NULL the table may go on past what was read: NEEDED could be missing.
        if !terminated {
            self.gap("dynamic: missing DT_NULL");
        }
        if let (Some(a), Some(n)) = (rela, relasz) {
            out.rela = Some((a, n));
        }
        if let (Some(a), Some(n)) = (jmprel, pltrelsz) {
            if pltrel == Some(elf::DT_RELA.0 as u64) {
                out.jmprel_rela = Some((a, n));
            } else {
                out.rel_or_relr = true;
            }
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

    /// The section facts: `.comment`, stripped, the dynamic symbols, and `.go.buildinfo`.
    fn sections(
        &mut self,
        facts: &mut ElfFacts,
        dynamic: &Dynamic,
        budgets: BinaryBudgets,
    ) -> Sections<'d, R, H> {
        let endian = self.endian;
        let data = self.data;
        let none = Sections {
            dynsym: None,
            go_section: None,
        };
        let table = match self.header.sections(endian, data) {
            Ok(t) if t.is_empty() => {
                self.gap("sections: no section header table");
                if dynamic.symtab {
                    self.gap("symbols: no section header table");
                }
                return none;
            }
            Ok(t) => t,
            Err(e) => {
                self.gap(format!("sections: malformed: {e}"));
                if dynamic.symtab {
                    self.gap("symbols: no readable section header table");
                }
                return none;
            }
        };
        facts.stripped = Some(!table.iter().any(|s| s.sh_type(endian) == elf::SHT_SYMTAB));
        if let Some((_, s)) = table.section_by_name(endian, b".comment") {
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
        let go_section = table
            .section_by_name(endian, b".go.buildinfo")
            .filter(|(_, s)| s.sh_type(endian) == elf::SHT_PROGBITS)
            .and_then(|(_, s)| {
                let (offset, size) = s.file_range(endian)?;
                Some((s.sh_addr(endian).into(), offset, size))
            });
        let symbols = match table.symbols(endian, data, elf::SHT_DYNSYM) {
            Ok(s) => s,
            Err(e) => {
                self.gap(format!("malformed: symbols: {e}"));
                return Sections {
                    dynsym: None,
                    go_section,
                };
            }
        };
        if symbols.is_empty() {
            if dynamic.symtab {
                self.gap("symbols: no SHT_DYNSYM");
            }
            return Sections {
                dynsym: None,
                go_section,
            };
        }
        let versions = match table.versions(endian, data) {
            Ok(v) => v,
            Err(e) => {
                self.gap(format!("malformed: versions: {e}"));
                None
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
                    Ok(n) if !n.is_empty() => n,
                    Ok(_) => continue,
                    Err(e) => {
                        self.gap(format!("malformed: symbols: {e}"));
                        continue;
                    }
                };
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
            dynsym: Some(symbols),
            go_section,
        }
    }

    /// The RELA relocations the loader applies (`DT_RELA`, and `DT_JMPREL` when RELA) that write
    /// one of the `wanted` addresses: `(type, addend)` by address. Only those are kept, so a large
    /// table costs no more than its read.
    pub(crate) fn relocations(
        &mut self,
        dynamic: &Dynamic,
        wanted: &BTreeSet<u64>,
    ) -> Result<BTreeMap<u64, Vec<(u32, i64)>>, String> {
        let endian = self.endian;
        let mut out: BTreeMap<u64, Vec<(u32, i64)>> = BTreeMap::new();
        for (vaddr, size) in [dynamic.rela, dynamic.jmprel_rela].into_iter().flatten() {
            let Place::File(offset) = self.loads.place(vaddr, size) else {
                return Err("a relocation table is not file-backed".to_string());
            };
            let count = size / size_of::<H::Rela>() as u64;
            let entries = self
                .data
                .read_slice_at::<H::Rela>(offset, count as usize)
                .map_err(|()| {
                    "a relocation table outside the file or over the budget".to_string()
                })?;
            for r in entries {
                let at: u64 = r.r_offset(endian).into();
                if !wanted.contains(&at) {
                    continue;
                }
                let at_addr = out.entry(at).or_default();
                // Two are already "more than once"; more add nothing.
                if at_addr.len() < 2 {
                    at_addr.push((r.r_type(endian, false).0, r.r_addend(endian).into()));
                }
            }
        }
        Ok(out)
    }
}
