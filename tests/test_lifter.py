from sigil.x86.decoder import DecodedInstruction
from sigil.x86.lifter import lift_instructions


def test_lifter_uses_resolved_call_symbol():
    ins = [DecodedInstruction(address=0x1000, mnemonic="call", op_str="0x0", raw_bytes=b"\xe8\x00\x00\x00\x00")]
    fn = lift_instructions("kernel", ins, call_symbols={0x1000: "connect"})
    assert fn.blocks[0].ops[0].symbol == "connect"


def test_lifter_resolves_numeric_call_target_symbol():
    ins = [DecodedInstruction(address=0x1000, mnemonic="call", op_str="0x401050", raw_bytes=b"")]
    fn = lift_instructions("kernel", ins, target_symbols={0x401050: "connect"})
    assert fn.blocks[0].ops[0].symbol == "connect"


def test_lifter_imul_three_operand_uses_rhs_operands():
    ins = [DecodedInstruction(address=0x1000, mnemonic="imul", op_str="eax, ecx, 4", raw_bytes=b"")]
    fn = lift_instructions("kernel", ins)
    op = fn.blocks[0].ops[0]
    assert op.dst == "eax"
    assert op.src == "ecx"
    assert op.src2 == "4"


def test_lifter_ignores_common_prologue_ops():
    ins = [
        DecodedInstruction(address=0x1000, mnemonic="push", op_str="rbp", raw_bytes=b""),
        DecodedInstruction(address=0x1001, mnemonic="pop", op_str="rbp", raw_bytes=b""),
        DecodedInstruction(address=0x1002, mnemonic="ret", op_str="", raw_bytes=b""),
    ]
    fn = lift_instructions("kernel", ins)
    assert [op.op for op in fn.blocks[0].ops] == ["Return"]
