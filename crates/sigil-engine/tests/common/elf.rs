//! A minimal ELF64 little-endian image for tests: chosen program headers, optional sections, and
//! payload bytes at chosen offsets. Nothing about it is validated: tests build malformed files on
//! purpose.
#![allow(dead_code)]

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_NOTE: u32 = 7;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;
pub const DT_RELA: i64 = 7;
pub const DT_RELASZ: i64 = 8;
pub const DT_RELAENT: i64 = 9;
pub const DT_PLTRELSZ: i64 = 2;
pub const R_X86_64_RELATIVE: u32 = 8;
pub const DT_NULL: i64 = 0;
pub const DT_NEEDED: i64 = 1;
pub const DT_STRTAB: i64 = 5;
pub const DT_SYMTAB: i64 = 6;
pub const DT_STRSZ: i64 = 10;
pub const DT_SONAME: i64 = 14;
pub const DT_RELR: i64 = 36;

#[derive(Debug, Clone, Copy)]
pub struct Seg {
    pub p_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
}

#[derive(Debug, Clone)]
pub struct Sec {
    pub name: String,
    pub sh_type: u32,
    pub offset: u64,
    pub addr: u64,
    pub size: u64,
    /// `sh_link`: a section index (the null section is 0, the first added is 1).
    pub link: u32,
    pub entsize: u64,
}

/// An image: `e_type` 2 (EXEC) or 3 (DYN), machine 62 (x86_64) by default.
pub struct ElfImage {
    pub e_type: u16,
    pub machine: u16,
    pub segs: Vec<Seg>,
    /// `None`: no section header table (`e_shoff = 0`).
    pub secs: Option<Vec<Sec>>,
    pub body: Vec<u8>,
}

impl ElfImage {
    /// The first 0x1000 bytes are reserved for the ELF header and program headers.
    pub fn new(e_type: u16) -> ElfImage {
        ElfImage {
            e_type,
            machine: 62,
            segs: vec![],
            secs: None,
            body: vec![0; 0x1000],
        }
    }

    /// Writes `data` at file offset `offset`, growing the body.
    pub fn put(&mut self, offset: u64, data: &[u8]) -> &mut Self {
        let at = offset as usize;
        if self.body.len() < at + data.len() {
            self.body.resize(at + data.len(), 0);
        }
        self.body[at..at + data.len()].copy_from_slice(data);
        self
    }

    pub fn seg(
        &mut self,
        p_type: u32,
        flags: u32,
        offset: u64,
        vaddr: u64,
        filesz: u64,
        memsz: u64,
    ) -> &mut Self {
        self.segs.push(Seg {
            p_type,
            flags,
            offset,
            vaddr,
            filesz,
            memsz,
        });
        self
    }

    pub fn sec(
        &mut self,
        name: &str,
        sh_type: u32,
        offset: u64,
        addr: u64,
        size: u64,
    ) -> &mut Self {
        self.sec_linked(name, sh_type, offset, addr, size, 0, 0)
    }

    /// A section with `sh_link` and `sh_entsize`, e.g. `.dynsym` linked to its string table.
    #[allow(clippy::too_many_arguments)]
    pub fn sec_linked(
        &mut self,
        name: &str,
        sh_type: u32,
        offset: u64,
        addr: u64,
        size: u64,
        link: u32,
        entsize: u64,
    ) -> &mut Self {
        self.secs.get_or_insert_with(Vec::new).push(Sec {
            name: name.to_string(),
            sh_type,
            offset,
            addr,
            size,
            link,
            entsize,
        });
        self
    }

    /// The file: header, program headers at 64, the body, then (with sections) `.shstrtab` and
    /// the section header table (a null section first).
    pub fn build(&self) -> Vec<u8> {
        let mut out = self.body.clone();
        let (shoff, shnum, shstrndx) = match &self.secs {
            None => (0u64, 0u16, 0u16),
            Some(secs) => {
                let mut names = vec![0u8];
                let mut name_at = vec![];
                for s in secs.iter() {
                    name_at.push(names.len() as u32);
                    names.extend_from_slice(s.name.as_bytes());
                    names.push(0);
                }
                let shstr_name = names.len() as u32;
                names.extend_from_slice(b".shstrtab\0");
                let shstr_off = out.len() as u64;
                out.extend_from_slice(&names);
                while !out.len().is_multiple_of(8) {
                    out.push(0);
                }
                let shoff = out.len() as u64;
                out.extend_from_slice(&[0u8; 64]); // the null section
                for (s, name) in secs.iter().zip(&name_at) {
                    out.extend_from_slice(&shdr(
                        *name, s.sh_type, s.addr, s.offset, s.size, s.link, s.entsize,
                    ));
                }
                out.extend_from_slice(&shdr(
                    shstr_name,
                    SHT_STRTAB,
                    0,
                    shstr_off,
                    names.len() as u64,
                    0,
                    0,
                ));
                (shoff, (secs.len() + 2) as u16, (secs.len() + 1) as u16)
            }
        };
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(b"\x7fELF");
        h[4] = 2;
        h[5] = 1;
        h[6] = 1;
        h[16..18].copy_from_slice(&self.e_type.to_le_bytes());
        h[18..20].copy_from_slice(&self.machine.to_le_bytes());
        h[20..24].copy_from_slice(&1u32.to_le_bytes());
        h[32..40].copy_from_slice(&(if self.segs.is_empty() { 0u64 } else { 64 }).to_le_bytes());
        h[40..48].copy_from_slice(&shoff.to_le_bytes());
        h[52..54].copy_from_slice(&64u16.to_le_bytes());
        h[54..56].copy_from_slice(&56u16.to_le_bytes());
        h[56..58].copy_from_slice(&(self.segs.len() as u16).to_le_bytes());
        h[58..60].copy_from_slice(&64u16.to_le_bytes());
        h[60..62].copy_from_slice(&shnum.to_le_bytes());
        h[62..64].copy_from_slice(&shstrndx.to_le_bytes());
        out[..64].copy_from_slice(&h);
        for (i, s) in self.segs.iter().enumerate() {
            let mut p = vec![0u8; 56];
            p[0..4].copy_from_slice(&s.p_type.to_le_bytes());
            p[4..8].copy_from_slice(&s.flags.to_le_bytes());
            p[8..16].copy_from_slice(&s.offset.to_le_bytes());
            p[16..24].copy_from_slice(&s.vaddr.to_le_bytes());
            p[24..32].copy_from_slice(&s.vaddr.to_le_bytes());
            p[32..40].copy_from_slice(&s.filesz.to_le_bytes());
            p[40..48].copy_from_slice(&s.memsz.to_le_bytes());
            p[48..56].copy_from_slice(&8u64.to_le_bytes());
            let at = 64 + i * 56;
            out[at..at + 56].copy_from_slice(&p);
        }
        out
    }
}

fn shdr(
    name: u32,
    sh_type: u32,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    entsize: u64,
) -> [u8; 64] {
    let mut s = [0u8; 64];
    s[0..4].copy_from_slice(&name.to_le_bytes());
    s[4..8].copy_from_slice(&sh_type.to_le_bytes());
    s[16..24].copy_from_slice(&addr.to_le_bytes());
    s[24..32].copy_from_slice(&offset.to_le_bytes());
    s[32..40].copy_from_slice(&size.to_le_bytes());
    s[40..44].copy_from_slice(&link.to_le_bytes());
    s[48..56].copy_from_slice(&1u64.to_le_bytes());
    s[56..64].copy_from_slice(&entsize.to_le_bytes());
    s
}

/// One `Elf64_Sym`: `info` is `(bind << 4) | type`, `shndx` 0 for undefined.
pub fn sym64(name: u32, info: u8, shndx: u16, value: u64, size: u64) -> [u8; 24] {
    let mut s = [0u8; 24];
    s[0..4].copy_from_slice(&name.to_le_bytes());
    s[4] = info;
    s[6..8].copy_from_slice(&shndx.to_le_bytes());
    s[8..16].copy_from_slice(&value.to_le_bytes());
    s[16..24].copy_from_slice(&size.to_le_bytes());
    s
}

/// The section headers of an ELF64 little-endian file: `(name, sh_type, header offset, sh_offset,
/// sh_size, sh_link)`.
pub fn sections64(bytes: &[u8]) -> Vec<(String, u32, usize, u64, u64, u32)> {
    let u16le = |a: usize| u16::from_le_bytes([bytes[a], bytes[a + 1]]) as usize;
    let u32le = |a: usize| u32::from_le_bytes(bytes[a..a + 4].try_into().unwrap());
    let u64le = |a: usize| u64::from_le_bytes(bytes[a..a + 8].try_into().unwrap());
    let (shoff, shnum, shstrndx) = (u64le(40) as usize, u16le(60), u16le(62));
    let at = |i: usize| shoff + i * 64;
    let strtab = u64le(at(shstrndx) + 24) as usize;
    (0..shnum)
        .map(|i| {
            let h = at(i);
            let name_at = strtab + u32le(h) as usize;
            let end = bytes[name_at..].iter().position(|b| *b == 0).unwrap();
            let name = String::from_utf8_lossy(&bytes[name_at..name_at + end]).to_string();
            (
                name,
                u32le(h + 4),
                h,
                u64le(h + 24),
                u64le(h + 32),
                u32le(h + 40),
            )
        })
        .collect()
}

/// `Elf64_Dyn` entries, little-endian, ending with `DT_NULL`.
pub fn dynamic(entries: &[(i64, u64)]) -> Vec<u8> {
    let mut out = vec![];
    for (tag, val) in entries.iter().chain(&[(DT_NULL, 0)]) {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&val.to_le_bytes());
    }
    out
}

/// Sets the value of the first `tag` entry of the `PT_DYNAMIC` of an ELF64 little-endian file.
pub fn set_dynamic(bytes: &mut [u8], tag: i64, value: u64) {
    let u64le = |b: &[u8], a: usize| u64::from_le_bytes(b[a..a + 8].try_into().unwrap());
    let phoff = u64le(bytes, 32) as usize;
    let phnum = u16::from_le_bytes([bytes[56], bytes[57]]) as usize;
    let (off, size) = (0..phnum)
        .map(|i| phoff + i * 56)
        .find(|&p| u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap()) == PT_DYNAMIC)
        .map(|p| (u64le(bytes, p + 8) as usize, u64le(bytes, p + 32) as usize))
        .expect("a PT_DYNAMIC");
    let at = (off..off + size)
        .step_by(16)
        .find(|&e| i64::from_le_bytes(bytes[e..e + 8].try_into().unwrap()) == tag)
        .unwrap_or_else(|| panic!("no dynamic tag {tag}"));
    bytes[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
}

/// `bytes` with every `LLAMA_` renamed `XLAMA_`: no known data symbol is left.
pub fn without_known_symbols(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let mut i = 0;
    while let Some(at) = out[i..].windows(6).position(|w| w == b"LLAMA_") {
        out[i + at] = b'X';
        i += at + 6;
    }
    out
}

/// One ELF note (4-byte aligned name and descriptor).
pub fn note(name: &[u8], n_type: u32, desc: &[u8]) -> Vec<u8> {
    let pad = |n: usize| (4 - n % 4) % 4;
    let mut out = vec![];
    out.extend_from_slice(&((name.len() + 1) as u32).to_le_bytes());
    out.extend_from_slice(&(desc.len() as u32).to_le_bytes());
    out.extend_from_slice(&n_type.to_le_bytes());
    out.extend_from_slice(name);
    out.push(0);
    out.extend(std::iter::repeat_n(0, pad(name.len() + 1)));
    out.extend_from_slice(desc);
    out.extend(std::iter::repeat_n(0, pad(desc.len())));
    out
}

/// A file with `bytes`, as the parser reads it.
pub fn file(bytes: &[u8]) -> std::fs::File {
    use std::io::{Seek, Write};
    let mut f = tempfile::tempfile().unwrap();
    f.write_all(bytes).unwrap();
    f.rewind().unwrap();
    f
}

/// A committed fixture's bytes.
pub fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}
