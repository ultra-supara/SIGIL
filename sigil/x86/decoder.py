from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DecodedInstruction:
    address: int
    mnemonic: str
    op_str: str
    raw_bytes: bytes


def decode_x86_64(code: bytes, base_address: int) -> list[DecodedInstruction]:
    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise RuntimeError("capstone is required for x86 decoding") from exc

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    out: list[DecodedInstruction] = []
    for ins in md.disasm(code, base_address):
        out.append(DecodedInstruction(address=ins.address, mnemonic=ins.mnemonic, op_str=ins.op_str, raw_bytes=bytes(ins.bytes)))
    return out
