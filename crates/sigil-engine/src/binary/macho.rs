use std::collections::BTreeSet;
use std::fs::File;
use std::os::unix::fs::FileExt;

use object::read::{ReadCacheOps, ReadRef};
use sha2::{Digest, Sha256};
use sigil_model::{
    macho_architecture, Arch, ContainerFacts, Format, MachOFacts, Sha256Hex, UntrustedText,
    FAT_CPU_MISMATCH_GAP, FAT_DUPLICATE_ARCH_GAP,
};

use super::read::{Bounded, Budgeted};
use super::{BinaryBudgets, Parsed, ParsedArtifact, ParsedSlice};
use crate::code::CodeOutcome;

mod imports;

const MAX_SLICES: usize = 64;
const MAX_LOAD_COMMANDS: u32 = 65_536;
const MAX_LOAD_COMMAND_BYTES: u64 = 8 << 20;
const MAX_NAMES: usize = 1_024;
const MAX_NAME_BYTES: usize = 4_096;
const LC_REQ_DYLD: u32 = 0x8000_0000;
const LC_SYMTAB: u32 = 0x2;
const LC_LOAD_WEAK_DYLIB: u32 = LC_REQ_DYLD | 0x18;
const LC_RPATH: u32 = LC_REQ_DYLD | 0x1c;
const LC_REEXPORT_DYLIB: u32 = LC_REQ_DYLD | 0x1f;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = LC_REQ_DYLD | 0x22;
const LC_LOAD_UPWARD_DYLIB: u32 = LC_REQ_DYLD | 0x23;
const LC_DYLD_CHAINED_FIXUPS: u32 = LC_REQ_DYLD | 0x34;

/// The other load commands dyld requires (`LC_REQ_DYLD`), with the size of each one's structure
/// (`<mach-o/loader.h>`). Their contents are not facts, so each is skipped once its size is
/// checked. Any other required command is unknown: the walk stops there.
const SKIPPED_REQUIRED: [(u32, &str, usize); 3] = [
    (LC_REQ_DYLD | 0x28, "LC_MAIN", 24),
    (LC_REQ_DYLD | 0x33, "LC_DYLD_EXPORTS_TRIE", 16),
    (LC_REQ_DYLD | 0x35, "LC_FILESET_ENTRY", 32),
];

#[derive(Clone, Copy)]
enum ByteOrder {
    Little,
    Big,
}

#[derive(Clone, Copy)]
struct ThinMagic {
    is_64: bool,
    order: ByteOrder,
}

#[derive(Clone, Copy)]
struct FatMagic {
    is_64: bool,
    order: ByteOrder,
}

struct Header {
    is_64: bool,
    order: ByteOrder,
    cpu_type: i32,
    cpu_subtype: i32,
    file_type: u32,
    flags: u32,
    ncmds: u32,
    sizeofcmds: u32,
    size: u64,
}

struct FatSlice {
    cpu_type: i32,
    cpu_subtype: i32,
    offset: u64,
    size: u64,
    alignment: u32,
}

fn thin_magic(bytes: &[u8]) -> Option<ThinMagic> {
    match bytes.get(..4)? {
        [0xfe, 0xed, 0xfa, 0xce] => Some(ThinMagic {
            is_64: false,
            order: ByteOrder::Big,
        }),
        [0xce, 0xfa, 0xed, 0xfe] => Some(ThinMagic {
            is_64: false,
            order: ByteOrder::Little,
        }),
        [0xfe, 0xed, 0xfa, 0xcf] => Some(ThinMagic {
            is_64: true,
            order: ByteOrder::Big,
        }),
        [0xcf, 0xfa, 0xed, 0xfe] => Some(ThinMagic {
            is_64: true,
            order: ByteOrder::Little,
        }),
        _ => None,
    }
}

fn fat_magic(bytes: &[u8]) -> Option<FatMagic> {
    match bytes.get(..4)? {
        [0xca, 0xfe, 0xba, 0xbe] => Some(FatMagic {
            is_64: false,
            order: ByteOrder::Big,
        }),
        [0xbe, 0xba, 0xfe, 0xca] => Some(FatMagic {
            is_64: false,
            order: ByteOrder::Little,
        }),
        [0xca, 0xfe, 0xba, 0xbf] => Some(FatMagic {
            is_64: true,
            order: ByteOrder::Big,
        }),
        [0xbf, 0xba, 0xfe, 0xca] => Some(FatMagic {
            is_64: true,
            order: ByteOrder::Little,
        }),
        _ => None,
    }
}

fn recognized(prefix: &[u8]) -> Option<Format> {
    if fat_magic(prefix).is_some() {
        Some(Format::MachOFat)
    } else if thin_magic(prefix).is_some() {
        Some(Format::MachO)
    } else {
        None
    }
}

fn java_class<R: ReadCacheOps>(data: &Bounded<R>, size: u64) -> bool {
    let Ok(header) = range(data, 0, size, 0, 10) else {
        return false;
    };
    if header[..4] != [0xca, 0xfe, 0xba, 0xbe] {
        return false;
    }
    let minor = u16::from_be_bytes([header[4], header[5]]);
    let major = u16::from_be_bytes([header[6], header[7]]);
    if major < 45 || (major >= 56 && minor != 0 && minor != u16::MAX) {
        return false;
    }
    let constant_pool_count = usize::from(u16::from_be_bytes([header[8], header[9]]));
    if constant_pool_count == 0 {
        return false;
    }

    let mut offset = 10u64;
    let mut index = 1usize;
    while index < constant_pool_count {
        let Ok(tag_bytes) = range(data, 0, size, offset, 1) else {
            return false;
        };
        let tag = tag_bytes[0];
        let payload_size = match tag {
            1 => {
                let Ok(length_bytes) = range(data, 0, size, offset + 1, 2) else {
                    return false;
                };
                let length = u64::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
                if range(data, 0, size, offset + 3, length).is_err() {
                    return false;
                }
                3 + length
            }
            3 | 4 => 5,
            5 | 6 => {
                if index + 1 >= constant_pool_count {
                    return false;
                }
                index += 1;
                9
            }
            7 | 8 | 16 | 19 | 20 => 3,
            9 | 10 | 11 | 12 | 17 | 18 => 5,
            15 => 4,
            _ => return false,
        };
        if range(data, 0, size, offset, payload_size).is_err() {
            return false;
        }
        offset += payload_size;
        index += 1;
    }
    range(data, 0, size, offset, 6).is_ok()
}

fn u32_at<R: object::read::ReadCacheOps>(
    data: &Bounded<R>,
    base: u64,
    size: u64,
    offset: u64,
    order: ByteOrder,
) -> Result<u32, String> {
    let bytes = range(data, base, size, offset, 4)?;
    let word: [u8; 4] = bytes.try_into().map_err(|_| "short integer".to_string())?;
    Ok(match order {
        ByteOrder::Little => u32::from_le_bytes(word),
        ByteOrder::Big => u32::from_be_bytes(word),
    })
}

fn range<R: object::read::ReadCacheOps>(
    data: &Bounded<R>,
    base: u64,
    size: u64,
    offset: u64,
    len: u64,
) -> Result<&[u8], String> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| "range overflow".to_string())?;
    if end > size {
        return Err("range outside slice".to_string());
    }
    let absolute = base
        .checked_add(offset)
        .ok_or_else(|| "file offset overflow".to_string())?;
    data.read_bytes_at(absolute, len)
        .map_err(|_| "range could not be read".to_string())
}

fn parse_header<R: object::read::ReadCacheOps>(
    data: &Bounded<R>,
    base: u64,
    size: u64,
) -> Result<Header, String> {
    let magic_bytes = range(data, base, size, 0, 4)?;
    let magic = thin_magic(magic_bytes).ok_or_else(|| "not a thin Mach-O header".to_string())?;
    let header_size = if magic.is_64 { 32 } else { 28 };
    let bytes = range(data, base, size, 0, header_size)?;
    let word = |offset: usize| -> Result<u32, String> {
        let value: [u8; 4] = bytes[offset..offset + 4]
            .try_into()
            .map_err(|_| "short Mach-O header".to_string())?;
        Ok(match magic.order {
            ByteOrder::Little => u32::from_le_bytes(value),
            ByteOrder::Big => u32::from_be_bytes(value),
        })
    };
    let cpu_type = word(4)? as i32;
    let cpu_subtype = word(8)? as i32;
    let file_type = word(12)?;
    let ncmds = word(16)?;
    let sizeofcmds = word(20)?;
    let flags = word(24)?;
    let commands_end = header_size
        .checked_add(u64::from(sizeofcmds))
        .ok_or_else(|| "load-command range overflow".to_string())?;
    if commands_end > size {
        return Err("load commands extend beyond the slice".to_string());
    }
    Ok(Header {
        is_64: magic.is_64,
        order: magic.order,
        cpu_type,
        cpu_subtype,
        file_type,
        flags,
        ncmds,
        sizeofcmds,
        size: header_size,
    })
}

fn empty_facts() -> MachOFacts {
    MachOFacts {
        is_64: false,
        cpu_type: 0,
        cpu_subtype: 0,
        fat_cpu_type: None,
        fat_cpu_subtype: None,
        fat_alignment: None,
        file_type: 0,
        flags: 0,
        uuid: None,
        id_dylib: None,
        load_dylibs: vec![],
        rpaths: vec![],
        dylinker: None,
        imports: vec![],
    }
}

fn arch(cpu_type: i32) -> Arch {
    match cpu_type as u32 {
        0x0100_0007 => Arch::X86_64,
        0x0100_000c => Arch::Aarch64,
        _ => Arch::Other,
    }
}

fn name_in_command(
    command: &[u8],
    offset_at: usize,
    min_string_offset: usize,
    order: ByteOrder,
) -> Result<UntrustedText, String> {
    if command.len() < offset_at + 4 {
        return Err("load command is too short for its string offset".to_string());
    }
    let offset_bytes: [u8; 4] = command[offset_at..offset_at + 4]
        .try_into()
        .map_err(|_| "short string offset".to_string())?;
    let offset = usize::try_from(match order {
        ByteOrder::Little => u32::from_le_bytes(offset_bytes),
        ByteOrder::Big => u32::from_be_bytes(offset_bytes),
    })
    .map_err(|_| "string offset overflow".to_string())?;
    if offset < min_string_offset || offset >= command.len() {
        return Err("string offset outside load command".to_string());
    }
    let value = &command[offset..];
    let end = value
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| "load-command string is not NUL terminated".to_string())?;
    if end == 0 {
        return Err("load-command string is empty".to_string());
    }
    if end > MAX_NAME_BYTES {
        return Err(format!(
            "load-command string exceeds {MAX_NAME_BYTES} bytes"
        ));
    }
    Ok(UntrustedText::from_bytes(value[..end].to_vec()))
}

/// Records the name of `command` in `target`, and returns it; `None`, with its gap, when it is not
/// read or not kept.
fn record_name(
    target: &mut Vec<UntrustedText>,
    command: &[u8],
    offset: usize,
    min_string_offset: usize,
    order: ByteOrder,
    label: &str,
    gaps: &mut Vec<String>,
) -> Option<UntrustedText> {
    match name_in_command(command, offset, min_string_offset, order) {
        Ok(name) if target.len() < MAX_NAMES => {
            target.push(name.clone());
            Some(name)
        }
        Ok(_) => {
            gaps.push(format!("{label}: over {MAX_NAMES} names"));
            None
        }
        Err(why) => {
            gaps.push(format!("{label}: {why}"));
            None
        }
    }
}

/// The 32-bit word at `at` of a load command at least `at + 4` bytes long.
/// The slice is four bytes long, so the conversion never fails: the default is never taken.
fn word_at(command: &[u8], at: usize, order: ByteOrder) -> u32 {
    let bytes: [u8; 4] = command[at..at + 4].try_into().unwrap_or_default();
    match order {
        ByteOrder::Little => u32::from_le_bytes(bytes),
        ByteOrder::Big => u32::from_be_bytes(bytes),
    }
}

/// The facts of the load commands, their gaps, and what the imports are read from.
fn parse_commands<R: object::read::ReadCacheOps>(
    data: &Bounded<R>,
    base: u64,
    slice_size: u64,
    header: &Header,
) -> (MachOFacts, Vec<String>, imports::Commands) {
    let mut facts = MachOFacts {
        is_64: header.is_64,
        cpu_type: header.cpu_type,
        cpu_subtype: header.cpu_subtype,
        fat_cpu_type: None,
        fat_cpu_subtype: None,
        fat_alignment: None,
        file_type: header.file_type,
        flags: header.flags,
        ..empty_facts()
    };
    let mut gaps = vec![];
    let mut found = imports::Commands::default();
    if header.ncmds > MAX_LOAD_COMMANDS {
        gaps.push(format!("load commands: over {MAX_LOAD_COMMANDS} commands"));
        return (facts, gaps, found);
    }
    if u64::from(header.sizeofcmds) > MAX_LOAD_COMMAND_BYTES {
        gaps.push(format!(
            "load commands: over {MAX_LOAD_COMMAND_BYTES} bytes"
        ));
        return (facts, gaps, found);
    }
    let commands = match range(
        data,
        base,
        slice_size,
        header.size,
        u64::from(header.sizeofcmds),
    ) {
        Ok(commands) => commands,
        Err(why) => {
            gaps.push(format!("load commands: {why}"));
            return (facts, gaps, found);
        }
    };
    let mut offset = 0usize;
    let mut whole = true;
    for _ in 0..header.ncmds {
        if commands.len().saturating_sub(offset) < 8 {
            gaps.push("load commands: truncated command header".to_string());
            whole = false;
            break;
        }
        let cmd = match header.order {
            ByteOrder::Little => u32::from_le_bytes([
                commands[offset],
                commands[offset + 1],
                commands[offset + 2],
                commands[offset + 3],
            ]),
            ByteOrder::Big => u32::from_be_bytes([
                commands[offset],
                commands[offset + 1],
                commands[offset + 2],
                commands[offset + 3],
            ]),
        };
        let cmdsize = match header.order {
            ByteOrder::Little => u32::from_le_bytes([
                commands[offset + 4],
                commands[offset + 5],
                commands[offset + 6],
                commands[offset + 7],
            ]),
            ByteOrder::Big => u32::from_be_bytes([
                commands[offset + 4],
                commands[offset + 5],
                commands[offset + 6],
                commands[offset + 7],
            ]),
        } as usize;
        let alignment = if header.is_64 { 8 } else { 4 };
        if cmdsize < 8
            || !cmdsize.is_multiple_of(alignment)
            || cmdsize > commands.len().saturating_sub(offset)
        {
            gaps.push("load commands: invalid command size".to_string());
            whole = false;
            break;
        }
        let bytes = &commands[offset..offset + cmdsize];
        let mut stop_after_command = false;
        match cmd {
            // Each takes the next library ordinal, whether or not its name is read.
            0x0c | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | 0x20 | LC_LOAD_UPWARD_DYLIB => {
                let name = if cmdsize < 24 {
                    gaps.push("load dylib: command is too short".to_string());
                    None
                } else {
                    record_name(
                        &mut facts.load_dylibs,
                        bytes,
                        8,
                        24,
                        header.order,
                        "load dylib",
                        &mut gaps,
                    )
                };
                found.dylibs.push(name);
            }
            // dyld_info_command: bind_off and bind_size at 16, lazy_bind_off and lazy_bind_size
            // at 32.
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                if cmdsize < 48 {
                    let name = if cmd == LC_DYLD_INFO {
                        "LC_DYLD_INFO"
                    } else {
                        "LC_DYLD_INFO_ONLY"
                    };
                    gaps.push(format!("{name}: command is too short"));
                    whole = false;
                } else {
                    let word = |at| word_at(bytes, at, header.order);
                    found
                        .dyld_info
                        .push([(word(16), word(20)), (word(32), word(36))]);
                }
            }
            // symtab_command: symoff, nsyms, stroff, strsize. Only an object file's is read, so a
            // short one is that read's gap (`imports::read`), not the walk's.
            LC_SYMTAB => {
                let word = |at| word_at(bytes, at, header.order);
                found
                    .symtab
                    .push((cmdsize >= 24).then(|| [word(8), word(12), word(16), word(20)]));
            }
            // linkedit_data_command: dataoff, datasize.
            LC_DYLD_CHAINED_FIXUPS => {
                if cmdsize < 16 {
                    gaps.push("LC_DYLD_CHAINED_FIXUPS: command is too short".to_string());
                    whole = false;
                } else {
                    found.chained.push((
                        word_at(bytes, 8, header.order),
                        word_at(bytes, 12, header.order),
                    ));
                }
            }
            0x0d => {
                if cmdsize < 24 {
                    gaps.push("dylib id: command is too short".to_string());
                } else if facts.id_dylib.is_some() {
                    gaps.push("dylib id: more than one LC_ID_DYLIB".to_string());
                } else {
                    match name_in_command(bytes, 8, 24, header.order) {
                        Ok(name) => facts.id_dylib = Some(name),
                        Err(why) => gaps.push(format!("dylib id: {why}")),
                    }
                }
            }
            0x0e => {
                if cmdsize < 12 {
                    gaps.push("dylinker: command is too short".to_string());
                } else if facts.dylinker.is_some() {
                    gaps.push("dylinker: more than one LC_LOAD_DYLINKER".to_string());
                } else {
                    match name_in_command(bytes, 8, 12, header.order) {
                        Ok(name) => facts.dylinker = Some(name),
                        Err(why) => gaps.push(format!("dylinker: {why}")),
                    }
                }
            }
            LC_RPATH => {
                if cmdsize < 12 {
                    gaps.push("rpath: command is too short".to_string());
                } else {
                    record_name(
                        &mut facts.rpaths,
                        bytes,
                        8,
                        12,
                        header.order,
                        "rpath",
                        &mut gaps,
                    );
                }
            }
            0x1b => {
                if cmdsize < 24 {
                    gaps.push("UUID: command is too short".to_string());
                } else if facts.uuid.is_some() {
                    gaps.push("UUID: more than one LC_UUID".to_string());
                } else {
                    let digits = b"0123456789abcdef";
                    let mut uuid = String::with_capacity(32);
                    for byte in &bytes[8..24] {
                        uuid.push(digits[usize::from(byte >> 4)] as char);
                        uuid.push(digits[usize::from(byte & 0x0f)] as char);
                    }
                    facts.uuid = Some(uuid);
                }
            }
            _ if cmd & LC_REQ_DYLD != 0 => {
                match SKIPPED_REQUIRED.iter().find(|(id, ..)| *id == cmd) {
                    Some((_, name, min_size)) => {
                        if cmdsize < *min_size {
                            gaps.push(format!("{name}: command is too short"));
                        }
                    }
                    None => {
                        gaps.push(format!("load commands: unknown required command {cmd:#x}"));
                        stop_after_command = true;
                        whole = false;
                    }
                }
            }
            _ => {}
        }
        offset = offset.saturating_add(cmdsize);
        if stop_after_command {
            break;
        }
    }
    if offset != commands.len() {
        gaps.push("load commands: command count does not cover sizeofcmds".to_string());
    }
    found.all_read = whole && offset == commands.len();
    gaps.sort();
    gaps.dedup();
    (facts, gaps, found)
}

/// The slice at `base`, `size` bytes, with at most `import_limit` imports (`binary_imports`).
fn parse_thin<R: object::read::ReadCacheOps>(
    data: &Bounded<R>,
    base: u64,
    size: u64,
    import_limit: u64,
) -> Result<(Arch, Parsed), String> {
    let header = parse_header(data, base, size)?;
    let (mut facts, mut gaps, found) = parse_commands(data, base, size, &header);
    let (kept, import_gaps) = imports::read(data, base, size, &header, &found, import_limit);
    facts.imports = kept;
    gaps.extend(import_gaps);
    gaps.sort();
    gaps.dedup();
    Ok((
        arch(header.cpu_type),
        Parsed {
            container: ContainerFacts::MachO(facts),
            go: None,
            gaps,
            code: None,
            scan: None,
        },
    ))
}

fn parse_fat<R: object::read::ReadCacheOps>(
    data: &Bounded<R>,
    size: u64,
    magic: FatMagic,
) -> (Vec<FatSlice>, Vec<String>) {
    let mut gaps = vec![];
    let count = match u32_at(data, 0, size, 4, magic.order) {
        Ok(count) => count as usize,
        Err(why) => return (vec![], vec![format!("fat header: {why}")]),
    };
    if count == 0 {
        return (
            vec![],
            vec!["fat header: no architecture slices".to_string()],
        );
    }
    if count > MAX_SLICES {
        return (
            vec![],
            vec![format!("fat header: over {MAX_SLICES} slices")],
        );
    }
    let entry_size = if magic.is_64 { 32u64 } else { 20u64 };
    let table_size = match (count as u64)
        .checked_mul(entry_size)
        .and_then(|table| table.checked_add(8))
    {
        Some(table) if table <= size => table,
        _ => {
            return (
                vec![],
                vec!["fat header: architecture table is truncated".to_string()],
            )
        }
    };
    if range(data, 0, size, 0, table_size).is_err() {
        return (
            vec![],
            vec!["fat header: architecture table could not be read".to_string()],
        );
    }
    let mut slices = vec![];
    for index in 0..count {
        let at = 8 + index as u64 * entry_size;
        let get = |off| u32_at(data, 0, size, at + off, magic.order);
        let cpu_type = match get(0) {
            Ok(value) => value as i32,
            Err(why) => {
                gaps.push(format!("fat slice {index}: {why}"));
                continue;
            }
        };
        let cpu_subtype = match get(4) {
            Ok(value) => value as i32,
            Err(why) => {
                gaps.push(format!("fat slice {index}: {why}"));
                continue;
            }
        };
        let (offset, slice_size, alignment) = if magic.is_64 {
            let offset = match read_u64(data, size, at + 8, magic.order) {
                Ok(value) => value,
                Err(why) => {
                    gaps.push(format!("fat slice {index}: {why}"));
                    continue;
                }
            };
            let slice_size = match read_u64(data, size, at + 16, magic.order) {
                Ok(value) => value,
                Err(why) => {
                    gaps.push(format!("fat slice {index}: {why}"));
                    continue;
                }
            };
            let alignment = match get(24) {
                Ok(value) => value,
                Err(why) => {
                    gaps.push(format!("fat slice {index}: {why}"));
                    continue;
                }
            };
            let reserved = match get(28) {
                Ok(value) => value,
                Err(why) => {
                    gaps.push(format!("fat slice {index}: {why}"));
                    continue;
                }
            };
            if reserved != 0 {
                gaps.push(format!("fat slice {index}: reserved field is nonzero"));
                continue;
            }
            (offset, slice_size, alignment)
        } else {
            let offset = u64::from(match get(8) {
                Ok(value) => value,
                Err(why) => {
                    gaps.push(format!("fat slice {index}: {why}"));
                    continue;
                }
            });
            let slice_size = u64::from(match get(12) {
                Ok(value) => value,
                Err(why) => {
                    gaps.push(format!("fat slice {index}: {why}"));
                    continue;
                }
            });
            let alignment = match get(16) {
                Ok(value) => value,
                Err(why) => {
                    gaps.push(format!("fat slice {index}: {why}"));
                    continue;
                }
            };
            (offset, slice_size, alignment)
        };
        let end = offset.checked_add(slice_size);
        let aligned = alignment < 64
            && (alignment == 0
                || 1u64
                    .checked_shl(alignment)
                    .is_some_and(|boundary| offset % boundary == 0));
        if offset < table_size || slice_size == 0 || end.is_none_or(|end| end > size) || !aligned {
            gaps.push(format!(
                "fat slice {index}: invalid offset, size, or alignment"
            ));
            continue;
        }
        slices.push(FatSlice {
            cpu_type,
            cpu_subtype,
            offset,
            size: slice_size,
            alignment,
        });
    }
    // Each architecture once, as lipo requires: the loader would take only one of two.
    let mut architectures = BTreeSet::new();
    if !slices
        .iter()
        .all(|slice| architectures.insert(macho_architecture(slice.cpu_type, slice.cpu_subtype)))
    {
        gaps.push(FAT_DUPLICATE_ARCH_GAP.to_string());
    }
    let mut overlapping = vec![false; slices.len()];
    for left in 0..slices.len() {
        let left_end = slices[left].offset + slices[left].size;
        for right in left + 1..slices.len() {
            let right_end = slices[right].offset + slices[right].size;
            if slices[left].offset < right_end && slices[right].offset < left_end {
                overlapping[left] = true;
                overlapping[right] = true;
            }
        }
    }
    if overlapping.iter().any(|overlap| *overlap) {
        gaps.push("fat header: architecture slices overlap".to_string());
        slices = slices
            .into_iter()
            .zip(overlapping)
            .filter_map(|(slice, overlap)| (!overlap).then_some(slice))
            .collect();
    }
    (slices, gaps)
}

fn read_u64<R: object::read::ReadCacheOps>(
    data: &Bounded<R>,
    size: u64,
    offset: u64,
    order: ByteOrder,
) -> Result<u64, String> {
    let bytes = range(data, 0, size, offset, 8)?;
    let word: [u8; 8] = bytes.try_into().map_err(|_| "short integer".to_string())?;
    Ok(match order {
        ByteOrder::Little => u64::from_le_bytes(word),
        ByteOrder::Big => u64::from_be_bytes(word),
    })
}

fn hash_range(file: &File, offset: u64, size: u64) -> Result<Sha256Hex, String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65_536];
    let mut read = 0u64;
    while read < size {
        let want = usize::try_from((size - read).min(buffer.len() as u64))
            .map_err(|_| "slice hash length overflow".to_string())?;
        let at = offset
            .checked_add(read)
            .ok_or_else(|| "slice hash offset overflow".to_string())?;
        let count = loop {
            match file.read_at(&mut buffer[..want], at) {
                Ok(0) => return Err("slice ended before its declared size".to_string()),
                Ok(count) => break count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.to_string()),
            }
        };
        hasher.update(&buffer[..count]);
        read = read.saturating_add(count as u64);
    }
    Sha256Hex::new(format!("{:x}", hasher.finalize())).map_err(|error| error.to_string())
}

fn parsed_slice(
    offset: u64,
    size: u64,
    arch: Arch,
    sha256: Sha256Hex,
    parsed: Parsed,
    extra_gaps: &[String],
) -> ParsedSlice {
    let mut gaps = parsed.gaps;
    gaps.extend(extra_gaps.iter().cloned());
    gaps.sort();
    gaps.dedup();
    ParsedSlice {
        offset,
        size,
        arch,
        sha256,
        container: Some(parsed.container),
        go: parsed.go,
        gaps,
        code: None,
        scan: None,
    }
}

fn fat_slice_facts<R: ReadCacheOps>(
    data: &Bounded<R>,
    descriptor: &FatSlice,
    import_limit: u64,
) -> Result<Parsed, String> {
    let (_, mut parsed) = parse_thin(data, descriptor.offset, descriptor.size, import_limit)?;
    if let ContainerFacts::MachO(facts) = &mut parsed.container {
        facts.fat_cpu_type = Some(descriptor.cpu_type);
        facts.fat_cpu_subtype = Some(descriptor.cpu_subtype);
        facts.fat_alignment = Some(descriptor.alignment);
        if macho_architecture(facts.cpu_type, facts.cpu_subtype)
            != macho_architecture(descriptor.cpu_type, descriptor.cpu_subtype)
        {
            parsed.gaps.push(FAT_CPU_MISMATCH_GAP.to_string());
        }
    }
    Ok(parsed)
}

fn unparsed_slice(offset: u64, size: u64, arch: Arch, sha256: Sha256Hex) -> ParsedSlice {
    ParsedSlice {
        offset,
        size,
        arch,
        sha256,
        container: None,
        go: None,
        gaps: vec![],
        code: None,
        scan: None,
    }
}

pub(super) fn parse_artifact(
    file: &File,
    size: u64,
    artifact_sha256: &Sha256Hex,
    prefix: &[u8],
    budgets: BinaryBudgets,
) -> Option<ParsedArtifact> {
    let magic: [u8; 4] = prefix.get(..4)?.try_into().ok()?;
    let format = recognized(&magic)?;
    let data = Bounded::new(Budgeted::new(file, size), size, budgets.parse_bytes);
    let mut slices = vec![];
    let fat_parsed = fat_magic(&magic).map(|fat| parse_fat(&data, size, fat));
    if let Some((descriptors, gaps)) = &fat_parsed {
        if (!gaps.is_empty() || descriptors.is_empty()) && java_class(&data, size) {
            return None;
        }
    }
    match format {
        Format::MachO => {
            if let Ok((slice_arch, parsed)) = parse_thin(&data, 0, size, budgets.imports) {
                slices.push(parsed_slice(
                    0,
                    size,
                    slice_arch,
                    artifact_sha256.clone(),
                    parsed,
                    &[],
                ));
            }
        }
        Format::MachOFat => {
            let (descriptors, mut gaps) = fat_parsed?;
            for descriptor in descriptors {
                let expected_arch = arch(descriptor.cpu_type);
                let digest = match hash_range(file, descriptor.offset, descriptor.size) {
                    Ok(digest) => digest,
                    Err(why) => {
                        gaps.push(format!("fat slice at {}: hash: {why}", descriptor.offset));
                        continue;
                    }
                };
                match fat_slice_facts(&data, &descriptor, budgets.imports) {
                    Ok(parsed) => slices.push(parsed_slice(
                        descriptor.offset,
                        descriptor.size,
                        expected_arch,
                        digest,
                        parsed,
                        &[],
                    )),
                    Err(why) => {
                        gaps.push(format!("fat slice at {}: {why}", descriptor.offset));
                        slices.push(unparsed_slice(
                            descriptor.offset,
                            descriptor.size,
                            expected_arch,
                            digest,
                        ));
                    }
                }
            }
            gaps.sort();
            gaps.dedup();
            for slice in &mut slices {
                if slice.container.is_some() {
                    slice.gaps.extend(gaps.iter().cloned());
                    slice.gaps.sort();
                    slice.gaps.dedup();
                }
            }
        }
        _ => return None,
    }
    if data.refused() {
        for slice in &mut slices {
            if slice.container.is_some() {
                slice
                    .gaps
                    .push(format!("binary_parse_bytes: {} exceeded", data.budget()));
                slice.gaps.sort();
                slice.gaps.dedup();
            }
        }
    }
    // Code is analyzed only in x86-64 ELF (PR-5a spec §4.1).
    for slice in &mut slices {
        slice.code = budgets.code.map(|_| CodeOutcome::Unsupported);
    }
    Some(ParsedArtifact { format, slices })
}
