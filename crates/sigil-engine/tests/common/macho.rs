#![allow(dead_code)]

pub const X86_64: i32 = 0x0100_0007;
pub const AARCH64: i32 = 0x0100_000c;

pub fn decode_hex(input: &str) -> Vec<u8> {
    let digits: Vec<u8> = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    assert!(digits.len().is_multiple_of(2));
    let (pairs, remainder) = digits.as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).unwrap();
            let low = (pair[1] as char).to_digit(16).unwrap();
            ((high << 4) | low) as u8
        })
        .collect()
}

fn encoded_word(value: u32, big_endian: bool) -> [u8; 4] {
    if big_endian {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    }
}

fn word(value: u32, big_endian: bool, output: &mut Vec<u8>) {
    output.extend_from_slice(&encoded_word(value, big_endian));
}

pub fn thin(
    is_64: bool,
    big_endian: bool,
    cpu_type: i32,
    cpu_subtype: i32,
    commands: &[Vec<u8>],
) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(match (is_64, big_endian) {
        (false, false) => &[0xce, 0xfa, 0xed, 0xfe],
        (false, true) => &[0xfe, 0xed, 0xfa, 0xce],
        (true, false) => &[0xcf, 0xfa, 0xed, 0xfe],
        (true, true) => &[0xfe, 0xed, 0xfa, 0xcf],
    });
    word(cpu_type as u32, big_endian, &mut output);
    word(cpu_subtype as u32, big_endian, &mut output);
    word(1, big_endian, &mut output);
    word(commands.len() as u32, big_endian, &mut output);
    word(
        commands.iter().map(|command| command.len() as u32).sum(),
        big_endian,
        &mut output,
    );
    word(0, big_endian, &mut output);
    if is_64 {
        word(0, big_endian, &mut output);
    }
    for command in commands {
        output.extend_from_slice(command);
    }
    output
}

pub fn command(id: u32, size: usize, big_endian: bool) -> Vec<u8> {
    let mut output = Vec::with_capacity(size);
    word(id, big_endian, &mut output);
    word(size as u32, big_endian, &mut output);
    output.resize(size, 0);
    output
}

pub fn uuid_command(big_endian: bool) -> Vec<u8> {
    let mut output = command(0x1b, 24, big_endian);
    for (index, byte) in output[8..24].iter_mut().enumerate() {
        *byte = index as u8;
    }
    output
}

pub fn dylib_command(id: u32, name: &str, big_endian: bool, alignment: usize) -> Vec<u8> {
    let mut output = command(id, 24, big_endian);
    output[8..12].copy_from_slice(&encoded_word(24, big_endian));
    output.extend_from_slice(name.as_bytes());
    output.push(0);
    output.resize(output.len().div_ceil(alignment) * alignment, 0);
    let size = output.len() as u32;
    output[4..8].copy_from_slice(&encoded_word(size, big_endian));
    output
}

pub fn rpath_command(id: u32, path: &str, big_endian: bool, alignment: usize) -> Vec<u8> {
    let mut output = command(id, 12, big_endian);
    output[8..12].copy_from_slice(&encoded_word(12, big_endian));
    output.extend_from_slice(path.as_bytes());
    output.push(0);
    output.resize(output.len().div_ceil(alignment) * alignment, 0);
    let size = output.len() as u32;
    output[4..8].copy_from_slice(&encoded_word(size, big_endian));
    output
}

pub fn fat32(slices: &[(Vec<u8>, i32, i32)]) -> Vec<u8> {
    let table_size = 8 + slices.len() * 20;
    let mut output = vec![0; table_size];
    output[..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    output[4..8].copy_from_slice(&(slices.len() as u32).to_be_bytes());
    for (index, (slice, cpu_type, cpu_subtype)) in slices.iter().enumerate() {
        let offset = output.len().div_ceil(4) * 4;
        output.resize(offset, 0);
        output.extend_from_slice(slice);
        let descriptor = 8 + index * 20;
        output[descriptor..descriptor + 4].copy_from_slice(&(*cpu_type as u32).to_be_bytes());
        output[descriptor + 4..descriptor + 8]
            .copy_from_slice(&(*cpu_subtype as u32).to_be_bytes());
        output[descriptor + 8..descriptor + 12].copy_from_slice(&(offset as u32).to_be_bytes());
        output[descriptor + 12..descriptor + 16]
            .copy_from_slice(&(slice.len() as u32).to_be_bytes());
        output[descriptor + 16..descriptor + 20].copy_from_slice(&2u32.to_be_bytes());
    }
    output
}

pub const MH_EXECUTE: u32 = 2;
pub const LC_DYLD_INFO: u32 = 0x22;
pub const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
pub const LIBSYSTEM: &str = "/usr/lib/libSystem.B.dylib";

/// A thin Mach-O of `file_type` whose load commands are `commands(base)`, followed by `tail` at
/// offset `base`, the first byte after them. The commands' sizes must not depend on `base`.
pub fn with_tail(
    is_64: bool,
    big_endian: bool,
    cpu_type: i32,
    file_type: u32,
    commands: impl Fn(u32) -> Vec<Vec<u8>>,
    tail: &[u8],
) -> Vec<u8> {
    let header = if is_64 { 32 } else { 28 };
    let base = header + commands(0).iter().map(Vec::len).sum::<usize>();
    let mut output = thin(is_64, big_endian, cpu_type, 0, &commands(base as u32));
    assert_eq!(output.len(), base, "the commands' sizes depend on base");
    output[12..16].copy_from_slice(&encoded_word(file_type, big_endian));
    output.extend_from_slice(tail);
    output
}

/// `LC_DYLD_INFO` or `LC_DYLD_INFO_ONLY` (`id`) with its bind and lazy-bind streams, each
/// `(offset, size)`.
pub fn dyld_info_command(id: u32, bind: (u32, u32), lazy: (u32, u32), big_endian: bool) -> Vec<u8> {
    let mut output = command(id, 48, big_endian);
    for (at, value) in [(16, bind.0), (20, bind.1), (32, lazy.0), (36, lazy.1)] {
        output[at..at + 4].copy_from_slice(&encoded_word(value, big_endian));
    }
    output
}

/// A `linkedit_data_command` (`id`, e.g. `LC_DYLD_CHAINED_FIXUPS`): `dataoff`, `datasize`.
pub fn linkedit_command(id: u32, dataoff: u32, datasize: u32, big_endian: bool) -> Vec<u8> {
    let mut output = command(id, 16, big_endian);
    output[8..12].copy_from_slice(&encoded_word(dataoff, big_endian));
    output[12..16].copy_from_slice(&encoded_word(datasize, big_endian));
    output
}

/// An `LC_DYLD_CHAINED_FIXUPS` blob whose imports, in `format` (1, 2, or 3), are each
/// `(lib_ordinal field, weak_import, name)`; no fixup chains. The names follow the imports.
pub fn chained_fixups(format: u32, imports: &[(u64, bool, &str)]) -> Vec<u8> {
    let entry = match format {
        2 => 8,
        3 => 16,
        _ => 4,
    };
    let imports_offset = 32u32;
    let symbols_offset = imports_offset + (imports.len() * entry) as u32;
    let mut entries = vec![];
    let mut names = vec![];
    for (ordinal, weak, name) in imports {
        let offset = names.len() as u64;
        names.extend_from_slice(name.as_bytes());
        names.push(0);
        if format == 3 {
            let value = (ordinal & 0xffff) | (u64::from(*weak) << 16) | (offset << 32);
            entries.extend_from_slice(&value.to_le_bytes());
            entries.extend_from_slice(&0u64.to_le_bytes());
        } else {
            let value = (ordinal & 0xff) as u32 | (u32::from(*weak) << 8) | ((offset as u32) << 9);
            entries.extend_from_slice(&value.to_le_bytes());
            if format == 2 {
                entries.extend_from_slice(&0i32.to_le_bytes());
            }
        }
    }
    let mut output = vec![];
    for value in [
        0,
        28,
        imports_offset,
        symbols_offset,
        imports.len() as u32,
        format,
        0,
    ] {
        output.extend_from_slice(&value.to_le_bytes());
    }
    output.resize(imports_offset as usize, 0);
    output.extend_from_slice(&entries);
    output.extend_from_slice(&names);
    output
}

/// A 64-bit little-endian x86_64 executable that loads `dylibs`, then has `linkedit(base)`
/// (commands that point at `tail`, which starts at `base`).
pub fn executable(dylibs: &[&str], linkedit: impl Fn(u32) -> Vec<Vec<u8>>, tail: &[u8]) -> Vec<u8> {
    with_tail(
        true,
        false,
        X86_64,
        MH_EXECUTE,
        |base| {
            let mut commands: Vec<Vec<u8>> = dylibs
                .iter()
                .map(|dylib| dylib_command(0x0c, dylib, false, 8))
                .collect();
            commands.extend(linkedit(base));
            commands
        },
        tail,
    )
}

pub const MH_OBJECT: u32 = 1;
pub const LC_SYMTAB: u32 = 0x2;

/// `LC_SYMTAB`: `symoff`, `nsyms`, `stroff`, `strsize`.
pub fn symtab_command(
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
    big_endian: bool,
) -> Vec<u8> {
    let mut output = command(LC_SYMTAB, 24, big_endian);
    for (at, value) in [(8, symoff), (12, nsyms), (16, stroff), (20, strsize)] {
        output[at..at + 4].copy_from_slice(&encoded_word(value, big_endian));
    }
    output
}

/// The `nlist` (or `nlist_64`) entries of `symbols`, each `(name, n_type, n_desc, n_value)`, and
/// their strings, which start with a NUL.
pub fn nlists(
    is_64: bool,
    big_endian: bool,
    symbols: &[(&str, u8, u16, u64)],
) -> (Vec<u8>, Vec<u8>) {
    let mut table = vec![];
    let mut strings = vec![0];
    for (name, n_type, n_desc, n_value) in symbols {
        word(strings.len() as u32, big_endian, &mut table);
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        table.extend_from_slice(&[*n_type, 0]);
        table.extend_from_slice(&if big_endian {
            n_desc.to_be_bytes()
        } else {
            n_desc.to_le_bytes()
        });
        if is_64 {
            table.extend_from_slice(&if big_endian {
                n_value.to_be_bytes()
            } else {
                n_value.to_le_bytes()
            });
        } else {
            word(*n_value as u32, big_endian, &mut table);
        }
    }
    (table, strings)
}

/// An object file (`MH_OBJECT`) whose `LC_SYMTAB` holds `table` and `strings`.
pub fn object(is_64: bool, big_endian: bool, table: &[u8], strings: &[u8]) -> Vec<u8> {
    let entry = if is_64 { 16 } else { 12 };
    with_tail(
        is_64,
        big_endian,
        X86_64,
        MH_OBJECT,
        |base| {
            vec![symtab_command(
                base,
                (table.len() / entry) as u32,
                base + table.len() as u32,
                strings.len() as u32,
                big_endian,
            )]
        },
        &[table, strings].concat(),
    )
}
