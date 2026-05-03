from sigil.x86.decoder import DecodedInstruction
from sigil.x86.lifter import lift_instructions


def test_lifter_uses_resolved_call_symbol():
    ins = [DecodedInstruction(address=0x1000, mnemonic="call", op_str="0x0", raw_bytes=b"\xe8\x00\x00\x00\x00")]
    fn = lift_instructions("kernel", ins, call_symbols={0x1000: "connect"})
    assert fn.blocks[0].ops[0].symbol == "connect"
