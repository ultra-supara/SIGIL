from sigil.ir.model import BasicBlock, Function, IROp


def test_ir_model_create():
    op = IROp(op="Add", dst="eax", src="eax", src2="ecx", source_address=0x1000)
    fn = Function(name="kernel", blocks=[BasicBlock(name="entry", ops=[op])])
    assert fn.blocks[0].ops[0].op == "Add"
