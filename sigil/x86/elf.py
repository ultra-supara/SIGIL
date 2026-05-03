from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LoadedFunction:
    entry: str
    address: int
    size: int
    code: bytes
    call_symbols: dict[int, str] = field(default_factory=dict)


def _extract_call_relocations(elf, section_index: int, func_addr: int, func_size: int) -> dict[int, str]:
    call_symbols: dict[int, str] = {}
    for sec in elf.iter_sections():
        if sec["sh_type"] not in ("SHT_RELA", "SHT_REL"):
            continue
        if sec["sh_info"] != section_index:
            continue
        rel_symtab = elf.get_section(sec["sh_link"])
        for rel in sec.iter_relocations():
            offset = int(rel["r_offset"])
            if offset < func_addr or offset >= func_addr + func_size:
                continue
            symbol = rel_symtab.get_symbol(rel["r_info_sym"])
            if symbol and symbol.name:
                call_symbols[offset - 1] = symbol.name
    return call_symbols


def _find_symbol(elf, entry: str):
    for symtab_name in (".symtab", ".dynsym"):
        symtab = elf.get_section_by_name(symtab_name)
        if symtab is None:
            continue
        symbol = next((s for s in symtab.iter_symbols() if s.name == entry), None)
        if symbol is not None:
            return symbol
    return None


def _truncate_until_ret_instruction(code: bytes, base_addr: int) -> bytes:
    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    except ModuleNotFoundError:
        return code

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    end = None
    for ins in md.disasm(code, base_addr):
        if ins.mnemonic == "ret":
            end = (ins.address - base_addr) + ins.size
            break
    return code[:end] if end is not None else code


def load_function(path: str, entry: str, max_bytes: int = 512) -> LoadedFunction:
    try:
        from elftools.elf.elffile import ELFFile
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise RuntimeError("pyelftools is required for ELF parsing") from exc

    with open(path, "rb") as f:
        elf = ELFFile(f)
        symbol = _find_symbol(elf, entry)
        if symbol is None:
            raise ValueError(f"entry symbol not found in .symtab/.dynsym: {entry}")

        sec_idx = int(symbol["st_shndx"])
        if sec_idx <= 0:
            raise ValueError(f"entry symbol is not in a loadable section: {entry}")
        sec = elf.get_section(sec_idx)
        if sec is None or sec["sh_type"] == "SHT_NOBITS":
            raise ValueError(f"entry symbol section is unavailable: {entry}")
        sec_data = sec.data()
        offset = int(symbol["st_value"] - sec["sh_addr"])
        size = int(symbol["st_size"])

        code = sec_data[offset : offset + size] if size > 0 else sec_data[offset : min(offset + max_bytes, len(sec_data))]
        if size == 0:
            code = _truncate_until_ret_instruction(code, int(symbol["st_value"]))

        func_addr = int(symbol["st_value"])
        call_symbols = _extract_call_relocations(elf, sec_idx, func_addr, len(code))
        return LoadedFunction(entry=entry, address=func_addr, size=len(code), code=code, call_symbols=call_symbols)
