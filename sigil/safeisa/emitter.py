from __future__ import annotations

from sigil.ir.model import Function
from sigil.safeisa.model import Instruction, Program


MAP = {"Mov": "MOV", "Add": "ADD", "Sub": "SUB", "Mul": "MUL", "And": "AND", "Or": "OR", "Xor": "XOR"}


def emit_safeisa(function: Function) -> Program:
    instructions: list[Instruction] = []
    for block in function.blocks:
        for op in block.ops:
            if op.op in MAP:
                instructions.append(Instruction(op=MAP[op.op], a=op.dst, b=op.src, c=op.src2))
            elif op.op == "ExternalCall":
                instructions.append(Instruction(op="CALL_STUB", a=op.symbol))
            elif op.op == "Return":
                instructions.append(Instruction(op="RET"))
            elif op.op == "Unsupported":
                instructions.append(Instruction(op="TRAP", a=f"unsupported@{hex(op.source_address or 0)}"))
    return Program(instructions=instructions)


def render_safeisa(program: Program, func_name: str) -> str:
    lines = [f"FUNC {func_name}"]
    for ins in program.instructions:
        parts = [ins.op] + [str(x) for x in (ins.a, ins.b, ins.c) if x is not None]
        lines.append("  " + " ".join(parts))
    lines.append("END")
    return "\n".join(lines) + "\n"
