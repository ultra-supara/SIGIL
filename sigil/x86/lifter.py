from __future__ import annotations

from sigil.ir.model import BasicBlock, Function, IROp
from sigil.x86.decoder import DecodedInstruction

ARITH = {"add": "Add", "sub": "Sub", "and": "And", "or": "Or", "xor": "Xor"}


def _split_ops(op_str: str) -> list[str]:
    return [p.strip() for p in op_str.split(",") if p.strip()]


def lift_instructions(name: str, instructions: list[DecodedInstruction], call_symbols: dict[int, str] | None = None) -> Function:
    call_symbols = call_symbols or {}
    block = BasicBlock(name="entry")
    for ins in instructions:
        ops = _split_ops(ins.op_str)
        text = f"{ins.mnemonic} {ins.op_str}".strip()
        if ins.mnemonic == "mov" and len(ops) == 2:
            block.ops.append(IROp(op="Mov", dst=ops[0], src=ops[1], source_address=ins.address, text=text))
        elif ins.mnemonic in ARITH and len(ops) == 2:
            block.ops.append(IROp(op=ARITH[ins.mnemonic], dst=ops[0], src=ops[0], src2=ops[1], source_address=ins.address, text=text))
        elif ins.mnemonic == "imul" and len(ops) >= 2:
            block.ops.append(IROp(op="Mul", dst=ops[0], src=ops[0], src2=ops[1], source_address=ins.address, text=text))
        elif ins.mnemonic == "call":
            sym = call_symbols.get(ins.address) or (ops[0] if ops else "unknown")
            block.ops.append(IROp(op="ExternalCall", symbol=sym, source_address=ins.address, text=text))
        elif ins.mnemonic == "ret":
            block.ops.append(IROp(op="Return", source_address=ins.address, text=text))
        else:
            block.ops.append(IROp(op="Unsupported", source_address=ins.address, text=text))
    return Function(name=name, blocks=[block])
