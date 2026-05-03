from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LoadedFunction:
    entry: str
    address: int
    size: int
    code: bytes
    call_symbols: dict[int, str] = field(default_factory=dict)
    target_symbols: dict[int, str] = field(default_factory=dict)


def _extract_target_symbols(elf) -> dict[int, str]:
    out: dict[int, str] = {}
    for symtab_name in (".symtab", ".dynsym"):
        symtab = elf.get_section_by_name(symtab_name)
        if symtab is None:
            continue
        for sym in symtab.iter_symbols():
            name = sym.name
            val = int(sym["st_value"])
            if not name or val == 0:
                continue
            out[val] = name.split("@", 1)[0]
    return out


def _extract_call_relocations(elf, section_index: int, func_addr: int, code: bytes) -> dict[int, str]:
    call_symbols: dict[int, str] = {}
    reloc_entries: list[tuple[int, str]] = []

    for sec in elf.iter_sections():
        if sec["sh_type"] not in ("SHT_RELA", "SHT_REL"):
            continue
        rel_symtab = elf.get_section(sec["sh_link"])
        if rel_symtab is None:
            continue
        for rel in sec.iter_relocations():
            sym = rel_symtab.get_symbol(rel["r_info_sym"])
            if sym and sym.name:
                reloc_entries.append((int(rel["r_offset"]), sym.name.split("@", 1)[0]))

    if not reloc_entries:
        return call_symbols

    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    except ModuleNotFoundError:
        return call_symbols

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    section = elf.get_section(section_index)
    section_addr = int(section["sh_addr"])

    for ins in md.disasm(code, func_addr):
        if not ins.mnemonic.startswith("call"):
            continue
        ins_sec_start = (ins.address - func_addr) + (func_addr - section_addr)
        ins_sec_end = ins_sec_start + ins.size
        for rel_off, rel_name in reloc_entries:
            if ins_sec_start <= rel_off < ins_sec_end:
                call_symbols[ins.address] = rel_name
                break
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
        call_symbols = _extract_call_relocations(elf, sec_idx, func_addr, code)
        target_symbols = _extract_target_symbols(elf)
        return LoadedFunction(
            entry=entry,
            address=func_addr,
            size=len(code),
            code=code,
            call_symbols=call_symbols,
            target_symbols=target_symbols,
        )
