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


def test_run_resets_trace_between_programs():
    emu = SafeISAEmulator()
    first = Program([Instruction("CALL_STUB", "connect"), Instruction("RET")])
    second = Program([Instruction("RET")])

    first_trace = emu.run(first)
    assert len(first_trace) == 1

    second_trace = emu.run(second)
    assert second_trace == []


def test_run_resets_registers_between_programs():
    emu = SafeISAEmulator()
    first = Program([Instruction("LI", "r1", 99), Instruction("RET")])
    second = Program([Instruction("RET")])

    emu.run(first)
    assert emu.regs["r1"] == 99

    emu.run(second)
    assert emu.regs["r1"] == 0


def test_accepts_lifted_string_immediates_and_register_tokens():
    prog = Program([
        Instruction("MOV", "r1", "5"),
        Instruction("MOV", "eax", "r1"),
        Instruction("ADD", "r0", "eax", "3"),
        Instruction("RET"),
    ])
    emu = SafeISAEmulator()
    emu.run(prog)
    assert emu.regs["r0"] == 8
