//! The ELF header, read from the first bytes of a file (PR-4a): enough for an artifact's format
//! and its one slice. The full container analysis is `binary::elf` (PR-4b-1).

use sigil_model::{Arch, ElfType};

/// The size of a complete ELF header of class `class` (1: ELF32, 2: ELF64).
pub fn header_size(class: u8) -> Option<usize> {
    match class {
        1 => Some(52),
        2 => Some(64),
        _ => None,
    }
}

/// The ELF type and machine of a 32- or 64-bit ELF of either byte order, or `None` when `head` is
/// not one: shorter than its class's whole header (52 or 64 bytes), another format, an unknown
/// byte order, `EI_VERSION` other than 1, or an ELF type that is not exec, dyn, or rel. The
/// parser uses the same check, so the format and the parse agree.
pub fn read(head: &[u8]) -> Option<(ElfType, Arch)> {
    if head.len() < 16 || &head[..4] != b"\x7fELF" || head[6] != 1 {
        return None;
    }
    if head.len() < header_size(head[4])? {
        return None;
    }
    let half = |at: usize| match head[5] {
        1 => Some(u16::from_le_bytes([head[at], head[at + 1]])),
        2 => Some(u16::from_be_bytes([head[at], head[at + 1]])),
        _ => None,
    };
    let kind = match half(16)? {
        1 => ElfType::Rel,
        2 => ElfType::Exec,
        3 => ElfType::Dyn,
        _ => return None,
    };
    let arch = match half(18)? {
        62 => Arch::X86_64,
        183 => Arch::Aarch64,
        _ => Arch::Other,
    };
    Some((kind, arch))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf(class: u8, data: u8, e_type: u16, machine: u16) -> Vec<u8> {
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(b"\x7fELF");
        h[4] = class;
        h[5] = data;
        h[6] = 1;
        let (t, m) = if data == 1 {
            (e_type.to_le_bytes(), machine.to_le_bytes())
        } else {
            (e_type.to_be_bytes(), machine.to_be_bytes())
        };
        h[16..18].copy_from_slice(&t);
        h[18..20].copy_from_slice(&m);
        h
    }

    #[test]
    fn elf_types_and_machines() {
        assert_eq!(read(&elf(2, 1, 3, 62)), Some((ElfType::Dyn, Arch::X86_64)));
        assert_eq!(
            read(&elf(2, 1, 2, 183)),
            Some((ElfType::Exec, Arch::Aarch64))
        );
        assert_eq!(read(&elf(1, 2, 1, 8)), Some((ElfType::Rel, Arch::Other)));
        assert_eq!(
            read(&elf(2, 1, 4, 62)),
            None,
            "ET_CORE is not an executable container"
        );
    }

    #[test]
    fn short_or_foreign_input_is_not_elf() {
        assert_eq!(read(b"\x7fEL"), None);
        assert_eq!(read(&elf(2, 1, 3, 62)[..17]), None);
        assert_eq!(
            read(b"\xcf\xfa\xed\xfe0000000000000000"),
            None,
            "Mach-O is PR-4b"
        );
        assert_eq!(read(&elf(3, 1, 3, 62)), None, "bad class");
        assert_eq!(read(&elf(2, 3, 3, 62)), None, "bad encoding");
    }

    #[test]
    fn a_header_must_be_complete_for_its_class() {
        let full64 = elf(2, 1, 3, 62);
        assert!(read(&full64).is_some());
        assert_eq!(read(&full64[..63]), None, "63 bytes of an ELF64 header");
        assert_eq!(read(&full64[..20]), None, "20 bytes");
        let mut full32 = elf(1, 1, 3, 3);
        full32.truncate(52);
        assert!(read(&full32).is_some());
        assert_eq!(read(&full32[..51]), None, "51 bytes of an ELF32 header");
        let mut bad_version = elf(2, 1, 3, 62);
        bad_version[6] = 0;
        assert_eq!(read(&bad_version), None, "EI_VERSION must be 1");
    }
}
