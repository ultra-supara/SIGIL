from sigil.ir.model import BasicBlock, Function, IROp


def collect_caps(ir: Function) -> list[str]:
    caps = []
    for block in ir.blocks:
        for op in block.ops:
            if op.op in {"Add", "Sub", "Mul", "And", "Or", "Xor"}:
                caps.append("arithmetic")
    return caps


def test_arithmetic_not_added_when_absent():
    ir = Function(name="kernel", blocks=[BasicBlock(name="entry", ops=[IROp(op="Mov"), IROp(op="Return")])])
    assert collect_caps(ir) == []
