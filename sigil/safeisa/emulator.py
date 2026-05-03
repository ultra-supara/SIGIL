from __future__ import annotations

from sigil.assess.capabilities import capability_for_symbol
from sigil.safeisa.model import Program


class SafeISAEmulator:
    def __init__(self) -> None:
        self.regs = {f"r{i}": 0 for i in range(16)}
        self.trace: list[dict] = []

    def _val(self, x):
        if isinstance(x, int):
            return x
        if isinstance(x, str) and x.startswith("r"):
            return self.regs[x]
        return 0

    def run(self, program: Program) -> list[dict]:
        pc = 0
        while pc < len(program.instructions):
            ins = program.instructions[pc]
            if ins.op == "LI":
                self.regs[ins.a] = int(ins.b)
            elif ins.op == "MOV":
                self.regs[ins.a] = self._val(ins.b)
            elif ins.op == "ADD":
                self.regs[ins.a] = self._val(ins.b) + self._val(ins.c)
            elif ins.op == "SUB":
                self.regs[ins.a] = self._val(ins.b) - self._val(ins.c)
            elif ins.op == "MUL":
                self.regs[ins.a] = self._val(ins.b) * self._val(ins.c)
            elif ins.op == "AND":
                self.regs[ins.a] = self._val(ins.b) & self._val(ins.c)
            elif ins.op == "OR":
                self.regs[ins.a] = self._val(ins.b) | self._val(ins.c)
            elif ins.op == "XOR":
                self.regs[ins.a] = self._val(ins.b) ^ self._val(ins.c)
            elif ins.op == "CALL_STUB":
                symbol = str(ins.a)
                self.trace.append({"event": "CALL_STUB", "symbol": symbol, "blocked": True, "capability": capability_for_symbol(symbol), "pc": pc})
            elif ins.op == "SYSCALL_STUB":
                self.trace.append({"event": "SYSCALL_STUB", "number": int(ins.a), "blocked": True, "pc": pc})
            elif ins.op in {"RET", "TRAP"}:
                break
            else:
                self.trace.append({"event": "UNSUPPORTED", "op": ins.op, "blocked": True, "pc": pc})
            pc += 1
        return self.trace
