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
