use std::collections::BTreeMap;
use std::fs;
use std::ops::Range;
use std::path::Path;

use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
use object::{
    Architecture, BinaryFormat, Object, ObjectSection, ObjectSymbol, RelocationTarget, SectionIndex,
};

use crate::ir::{BasicBlock, Function, IROp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInstruction {
    pub address: u64,
    pub mnemonic: String,
    pub op_str: String,
    pub raw_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedFunction {
    pub entry: String,
    pub address: u64,
    pub size: usize,
    pub code: Vec<u8>,
    pub call_symbols: BTreeMap<u64, String>,
    pub target_symbols: BTreeMap<u64, String>,
}

#[derive(Debug, thiserror::Error)]
pub enum X86Error {
    #[error("failed to read object {path}: {source}")]
    ReadObject {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse object {path}: {source}")]
    ParseObject {
        path: String,
        #[source]
        source: object::Error,
    },
    #[error("unsupported object architecture for x86_64 analysis: {0}")]
    UnsupportedArchitecture(String),
    #[error("entry symbol not found in object: {0}")]
    MissingSymbol(String),
    #[error("entry symbol section is unavailable: {0}")]
    MissingSection(String),
    #[error("entry symbol is outside its section: {0}")]
    SymbolOutOfRange(String),
    #[error("failed to read section data for {section}: {source}")]
    SectionData {
        section: String,
        #[source]
        source: object::Error,
    },
}

pub fn decode_x86_64(code: &[u8], base_address: u64) -> Result<Vec<DecodedInstruction>, X86Error> {
    let mut decoder = Decoder::with_ip(64, code, base_address, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut out = Vec::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        let mut rendered = String::new();
        formatter.format(&instruction, &mut rendered);
        let (mnemonic, op_str) = rendered
            .split_once(' ')
            .map(|(mnemonic, operands)| (mnemonic.to_string(), operands.trim().to_string()))
            .unwrap_or_else(|| (rendered, String::new()));
        let start = (instruction.ip() - base_address) as usize;
        let end = start.saturating_add(instruction.len());
        out.push(DecodedInstruction {
            address: instruction.ip(),
            mnemonic,
            op_str,
            raw_bytes: code.get(start..end).unwrap_or_default().to_vec(),
        });
    }
    Ok(out)
}

pub fn load_function(path: impl AsRef<Path>, entry: &str) -> Result<LoadedFunction, X86Error> {
    load_function_with_max_bytes(path, entry, 512)
}

pub fn load_function_with_max_bytes(
    path: impl AsRef<Path>,
    entry: &str,
    max_bytes: usize,
) -> Result<LoadedFunction, X86Error> {
    let path_ref = path.as_ref();
    let path_display = path_ref.display().to_string();
    let bytes = fs::read(path_ref).map_err(|source| X86Error::ReadObject {
        path: path_display.clone(),
        source,
    })?;
    let file = object::File::parse(bytes.as_slice()).map_err(|source| X86Error::ParseObject {
        path: path_display,
        source,
    })?;
    if file.architecture() != Architecture::X86_64 {
        return Err(X86Error::UnsupportedArchitecture(format!(
            "{:?}",
            file.architecture()
        )));
    }
    let symbol = file
        .symbols()
        .chain(file.dynamic_symbols())
        .find(|symbol| symbol_matches_entry(&file, symbol.name().ok(), entry))
        .ok_or_else(|| X86Error::MissingSymbol(entry.to_string()))?;
    let section_index = symbol
        .section_index()
        .ok_or_else(|| X86Error::MissingSection(entry.to_string()))?;
    let section = file
        .section_by_index(section_index)
        .map_err(|_| X86Error::MissingSection(entry.to_string()))?;
    let section_name = section.name().unwrap_or("<unknown>").to_string();
    let section_data = section.data().map_err(|source| X86Error::SectionData {
        section: section_name,
        source,
    })?;

    let function_address = symbol.address();
    let section_address = section.address();
    let start = function_address
        .checked_sub(section_address)
        .ok_or_else(|| X86Error::SymbolOutOfRange(entry.to_string()))? as usize;
    if start >= section_data.len() {
        return Err(X86Error::SymbolOutOfRange(entry.to_string()));
    }
    let requested_size = symbol.size() as usize;
    let end = if requested_size > 0 {
        start.saturating_add(requested_size).min(section_data.len())
    } else {
        start.saturating_add(max_bytes).min(section_data.len())
    };
    let mut code = section_data[start..end].to_vec();
    if requested_size == 0 {
        code = truncate_until_ret_instruction(&code, function_address);
    }

    let decoded = decode_x86_64(&code, function_address)?;
    let call_symbols = extract_call_relocations(
        &file,
        section_index,
        section_address,
        function_address,
        &decoded,
    );
    let target_symbols = extract_target_symbols(&file);
    Ok(LoadedFunction {
        entry: entry.to_string(),
        address: function_address,
        size: code.len(),
        code,
        call_symbols,
        target_symbols,
    })
}

fn truncate_until_ret_instruction(code: &[u8], base_address: u64) -> Vec<u8> {
    let decoded = decode_x86_64(code, base_address).unwrap_or_default();
    for instruction in decoded {
        if instruction.mnemonic == "ret" {
            let end = (instruction.address - base_address) as usize + instruction.raw_bytes.len();
            return code[..end.min(code.len())].to_vec();
        }
    }
    code.to_vec()
}

fn extract_target_symbols(file: &object::File<'_>) -> BTreeMap<u64, String> {
    file.symbols()
        .chain(file.dynamic_symbols())
        .filter_map(|symbol| {
            let name = normalize_symbol_name(file, symbol.name().ok()?);
            let address = symbol.address();
            if name.is_empty() || address == 0 {
                None
            } else {
                Some((address, name))
            }
        })
        .collect()
}

fn extract_call_relocations(
    file: &object::File<'_>,
    section_index: SectionIndex,
    section_address: u64,
    function_address: u64,
    instructions: &[DecodedInstruction],
) -> BTreeMap<u64, String> {
    let Some(section) = file.section_by_index(section_index).ok() else {
        return BTreeMap::new();
    };
    let relocations: Vec<_> = section
        .relocations()
        .filter_map(|(offset, relocation)| {
            let RelocationTarget::Symbol(symbol_index) = relocation.target() else {
                return None;
            };
            let symbol = file.symbol_by_index(symbol_index).ok()?;
            let name = normalize_symbol_name(file, symbol.name().ok()?);
            Some((offset, name))
        })
        .collect();

    let mut call_symbols = BTreeMap::new();
    for instruction in instructions {
        if !instruction.mnemonic.starts_with("call") {
            continue;
        }
        let instruction_section_offset = instruction.address.saturating_sub(section_address);
        let range = instruction_section_offset
            ..instruction_section_offset + instruction.raw_bytes.len() as u64;
        if !function_contains(function_address, instruction.address) {
            continue;
        }
        if let Some((_, name)) = relocations
            .iter()
            .find(|(offset, _)| range_contains(&range, *offset))
        {
            call_symbols.insert(instruction.address, name.clone());
        }
    }
    call_symbols
}

fn function_contains(function_address: u64, instruction_address: u64) -> bool {
    instruction_address >= function_address
}

fn range_contains(range: &Range<u64>, value: u64) -> bool {
    range.start <= value && value < range.end
}

fn symbol_matches_entry(file: &object::File<'_>, symbol_name: Option<&str>, entry: &str) -> bool {
    let Some(symbol_name) = symbol_name else {
        return false;
    };
    symbol_name == entry || normalize_symbol_name(file, symbol_name) == entry
}

fn normalize_symbol_name(file: &object::File<'_>, symbol_name: &str) -> String {
    let name = symbol_name.split('@').next().unwrap_or(symbol_name);
    if file.format() == BinaryFormat::MachO {
        name.strip_prefix('_').unwrap_or(name).to_string()
    } else {
        name.to_string()
    }
}

pub fn lift_instructions(
    name: &str,
    instructions: &[DecodedInstruction],
    call_symbols: &BTreeMap<u64, String>,
    target_symbols: &BTreeMap<u64, String>,
) -> Function {
    let mut block = BasicBlock {
        name: "entry".to_string(),
        ops: Vec::new(),
    };
    for instruction in instructions {
        let operands = split_operands(&instruction.op_str);
        let text = format_instruction(instruction);
        match instruction.mnemonic.as_str() {
            "mov" if operands.len() == 2 => {
                block.ops.push(IROp::mov(
                    &operands[0],
                    &operands[1],
                    instruction.address,
                    &text,
                ));
            }
            "add" | "sub" | "and" | "or" | "xor" if operands.len() == 2 => {
                let op = match instruction.mnemonic.as_str() {
                    "add" => "Add",
                    "sub" => "Sub",
                    "and" => "And",
                    "or" => "Or",
                    "xor" => "Xor",
                    _ => unreachable!(),
                };
                block.ops.push(IROp::binary(
                    op,
                    &operands[0],
                    &operands[0],
                    &operands[1],
                    instruction.address,
                    &text,
                ));
            }
            "imul" if operands.len() >= 2 => {
                let (src, src2) = if operands.len() >= 3 {
                    (&operands[1], &operands[2])
                } else {
                    (&operands[0], &operands[1])
                };
                block.ops.push(IROp::binary(
                    "Mul",
                    &operands[0],
                    src,
                    src2,
                    instruction.address,
                    &text,
                ));
            }
            "call" => {
                let raw = operands.first().map(String::as_str).unwrap_or("unknown");
                let symbol = call_symbols
                    .get(&instruction.address)
                    .cloned()
                    .unwrap_or_else(|| resolve_call_symbol(raw, target_symbols));
                block
                    .ops
                    .push(IROp::external_call(&symbol, instruction.address, &text));
            }
            "ret" => block.ops.push(IROp::ret(instruction.address, &text)),
            "push" | "pop" | "nop" | "leave" | "endbr64" => {}
            _ => block
                .ops
                .push(IROp::unsupported(instruction.address, &text)),
        }
    }

    Function {
        name: name.to_string(),
        blocks: vec![block],
    }
}

fn split_operands(op_str: &str) -> Vec<String> {
    op_str
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn format_instruction(instruction: &DecodedInstruction) -> String {
    if instruction.op_str.is_empty() {
        instruction.mnemonic.clone()
    } else {
        format!("{} {}", instruction.mnemonic, instruction.op_str)
    }
}

fn resolve_call_symbol(raw: &str, target_symbols: &BTreeMap<u64, String>) -> String {
    let token = raw.trim();
    let hex = token.strip_prefix("0x").or_else(|| token.strip_suffix('h'));
    if let Some(hex) = hex {
        if let Ok(address) = u64::from_str_radix(hex, 16) {
            if let Some(symbol) = target_symbols.get(&address) {
                return symbol.clone();
            }
        }
    }
    token.to_string()
}
