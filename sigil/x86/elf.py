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
        symtab = elf.get_section(sec["sh_link"])
        for rel in sec.iter_relocations():
            offset = int(rel["r_offset"])
            if offset < func_addr or offset >= func_addr + func_size:
                continue
            symbol = symtab.get_symbol(rel["r_info_sym"])
            if symbol and symbol.name:
                # Relocations for x86 call generally reference immediate at +1.
                call_site = offset - 1
                call_symbols[call_site] = symbol.name
    return call_symbols


def load_function(path: str, entry: str, max_bytes: int = 512) -> LoadedFunction:
    try:
        from elftools.elf.elffile import ELFFile
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise RuntimeError("pyelftools is required for ELF parsing") from exc

    with open(path, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            raise ValueError("ELF missing .symtab")

        symbol = next((s for s in symtab.iter_symbols() if s.name == entry), None)
        if symbol is None:
            raise ValueError(f"entry symbol not found: {entry}")

        sec_idx = int(symbol["st_shndx"])
        sec = elf.get_section(sec_idx)
        sec_data = sec.data()
        offset = int(symbol["st_value"] - sec["sh_addr"])
        size = int(symbol["st_size"])

        code = sec_data[offset : offset + size] if size > 0 else sec_data[offset : min(offset + max_bytes, len(sec_data))]
        if size == 0:
            ret_idx = code.find(b"\xc3")
            if ret_idx != -1:
                code = code[: ret_idx + 1]

        func_addr = int(symbol["st_value"])
        call_symbols = _extract_call_relocations(elf, sec_idx, func_addr, len(code))
        return LoadedFunction(entry=entry, address=func_addr, size=len(code), code=code, call_symbols=call_symbols)
