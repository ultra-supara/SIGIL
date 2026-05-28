use sigil_core::ir::{BasicBlock, Function, IROp};
use sigil_core::safeisa::{emit_safeisa, Instruction, Program, SafeIsaEmulator, TraceEvent};

#[test]
fn ir_model_holds_function_blocks_and_ops() {
    let function = Function {
        name: "kernel".to_string(),
        blocks: vec![BasicBlock {
            name: "entry".to_string(),
            ops: vec![IROp {
                op: "Add".to_string(),
                dst: Some("r0".to_string()),
                src: Some("r1".to_string()),
                src2: Some("2".to_string()),
                symbol: None,
                source_address: Some(0x1000),
                text: "add r0, 2".to_string(),
            }],
        }],
    };

    assert_eq!(function.name, "kernel");
    assert_eq!(function.blocks[0].ops[0].source_address, Some(0x1000));
}

#[test]
fn emits_safeisa_from_ir() {
    let function = Function {
        name: "kernel".to_string(),
        blocks: vec![BasicBlock {
            name: "entry".to_string(),
            ops: vec![
                IROp::binary("Mul", "r0", "r1", "3", 0x1000, "imul r0, r1, 3"),
                IROp::external_call("connect", 0x1004, "call connect"),
                IROp::ret(0x1008, "ret"),
            ],
        }],
    };

    let program = emit_safeisa(&function);
    assert_eq!(
        program.instructions,
        vec![
            Instruction::new("MUL", Some("r0"), Some("r1"), Some("3")),
            Instruction::new("CALL_STUB", Some("connect"), None, None),
            Instruction::new("RET", None, None, None),
        ]
    );
}

#[test]
fn emulator_runs_arithmetic() {
    let program = Program::new(vec![
        Instruction::new("LI", Some("r1"), Some("2"), None),
        Instruction::new("LI", Some("r2"), Some("3"), None),
        Instruction::new("MUL", Some("r0"), Some("r1"), Some("r2")),
        Instruction::new("RET", None, None, None),
    ]);
    let mut emulator = SafeIsaEmulator::new();
    emulator.run(&program);
    assert_eq!(emulator.register("r0"), 6);
}

#[test]
fn emulator_blocks_call_stub_with_capability() {
    let program = Program::new(vec![
        Instruction::new("CALL_STUB", Some("connect"), None, None),
        Instruction::new("RET", None, None, None),
    ]);
    let mut emulator = SafeIsaEmulator::new();
    let trace = emulator.run(&program);
    assert_eq!(
        trace,
        vec![TraceEvent::CallStub {
            symbol: "connect".to_string(),
            blocked: true,
            capability: Some("network".to_string()),
            pc: 0,
        }]
    );
}

#[test]
fn emulator_resets_trace_and_registers_between_runs() {
    let mut emulator = SafeIsaEmulator::new();
    let first = Program::new(vec![
        Instruction::new("LI", Some("r1"), Some("99"), None),
        Instruction::new("CALL_STUB", Some("connect"), None, None),
        Instruction::new("RET", None, None, None),
    ]);
    let second = Program::new(vec![Instruction::new("RET", None, None, None)]);

    assert_eq!(emulator.run(&first).len(), 1);
    assert_eq!(emulator.register("r1"), 99);
    assert_eq!(emulator.run(&second).len(), 0);
    assert_eq!(emulator.register("r1"), 0);
}

#[test]
fn emulator_accepts_string_immediates_and_register_tokens() {
    let program = Program::new(vec![
        Instruction::new("MOV", Some("r1"), Some("5"), None),
        Instruction::new("MOV", Some("eax"), Some("r1"), None),
        Instruction::new("ADD", Some("r0"), Some("eax"), Some("3")),
        Instruction::new("RET", None, None, None),
    ]);
    let mut emulator = SafeIsaEmulator::new();
    emulator.run(&program);
    assert_eq!(emulator.register("r0"), 8);
}
