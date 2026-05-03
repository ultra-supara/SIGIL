from sigil.safeisa.emulator import SafeISAEmulator
from sigil.safeisa.model import Instruction, Program


def test_arithmetic():
    prog = Program([Instruction("LI", "r1", 2), Instruction("LI", "r2", 3), Instruction("MUL", "r0", "r1", "r2"), Instruction("RET")])
    emu = SafeISAEmulator()
    emu.run(prog)
    assert emu.regs["r0"] == 6


def test_call_stub_blocked():
    prog = Program([Instruction("CALL_STUB", "connect"), Instruction("RET")])
    emu = SafeISAEmulator()
    trace = emu.run(prog)
    assert trace and trace[0]["event"] == "CALL_STUB" and trace[0]["blocked"] is True
