from __future__ import annotations

from sigil.ir.model import BasicBlock, Function, IROp
from sigil.x86.decoder import DecodedInstruction

ARITH = {"add": "Add", "sub": "Sub", "and": "And", "or": "Or", "xor": "Xor"}
IGNORED = {"push", "pop", "nop", "leave"}


def _split_ops(op_str: str) -> list[str]:
    return [p.strip() for p in op_str.split(",") if p.strip()]


def _resolve_call_symbol(raw: str, target_symbols: dict[int, str]) -> str:
    token = raw.strip()
    if token.startswith("0x"):
        try:
            addr = int(token, 16)
            if addr in target_symbols:
                return target_symbols[addr]
        except ValueError:
            return token
    return token


def lift_instructions(
    name: str,
    instructions: list[DecodedInstruction],
    call_symbols: dict[int, str] | None = None,
    target_symbols: dict[int, str] | None = None,
) -> Function:
    call_symbols = call_symbols or {}
    target_symbols = target_symbols or {}
    block = BasicBlock(name="entry")
    for ins in instructions:
        ops = _split_ops(ins.op_str)
        text = f"{ins.mnemonic} {ins.op_str}".strip()
        if ins.mnemonic == "mov" and len(ops) == 2:
            block.ops.append(IROp(op="Mov", dst=ops[0], src=ops[1], source_address=ins.address, text=text))
        elif ins.mnemonic in ARITH and len(ops) == 2:
            block.ops.append(IROp(op=ARITH[ins.mnemonic], dst=ops[0], src=ops[0], src2=ops[1], source_address=ins.address, text=text))
        elif ins.mnemonic == "imul" and len(ops) >= 2:
            if len(ops) >= 3:
                block.ops.append(IROp(op="Mul", dst=ops[0], src=ops[1], src2=ops[2], source_address=ins.address, text=text))
            else:
                block.ops.append(IROp(op="Mul", dst=ops[0], src=ops[0], src2=ops[1], source_address=ins.address, text=text))
        elif ins.mnemonic == "call":
            raw = ops[0] if ops else "unknown"
            sym = call_symbols.get(ins.address) or _resolve_call_symbol(raw, target_symbols)
            block.ops.append(IROp(op="ExternalCall", symbol=sym, source_address=ins.address, text=text))
        elif ins.mnemonic == "ret":
            block.ops.append(IROp(op="Return", source_address=ins.address, text=text))
        elif ins.mnemonic in IGNORED:
            continue
        else:
            block.ops.append(IROp(op="Unsupported", source_address=ins.address, text=text))
    return Function(name=name, blocks=[block])
