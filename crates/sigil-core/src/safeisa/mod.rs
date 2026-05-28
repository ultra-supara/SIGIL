use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::assess::capability_for_symbol;
use crate::ir::Function;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    pub op: String,
    pub a: Option<String>,
    pub b: Option<String>,
    pub c: Option<String>,
}

impl Instruction {
    pub fn new(op: &str, a: Option<&str>, b: Option<&str>, c: Option<&str>) -> Self {
        Self {
            op: op.to_string(),
            a: a.map(str::to_string),
            b: b.map(str::to_string),
            c: c.map(str::to_string),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Program {
    pub instructions: Vec<Instruction>,
}

impl Program {
    pub fn new(instructions: Vec<Instruction>) -> Self {
        Self { instructions }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event")]
pub enum TraceEvent {
    #[serde(rename = "CALL_STUB")]
    CallStub {
        symbol: String,
        blocked: bool,
        capability: Option<String>,
        pc: usize,
    },
    #[serde(rename = "SYSCALL_STUB")]
    SyscallStub {
        number: i64,
        blocked: bool,
        pc: usize,
    },
    #[serde(rename = "UNSUPPORTED")]
    Unsupported {
        op: String,
        blocked: bool,
        pc: usize,
    },
}

#[derive(Debug, Clone)]
pub struct SafeIsaEmulator {
    regs: BTreeMap<String, i64>,
    trace: Vec<TraceEvent>,
}

impl SafeIsaEmulator {
    pub fn new() -> Self {
        let mut emulator = Self {
            regs: BTreeMap::new(),
            trace: Vec::new(),
        };
        emulator.reset_state();
        emulator
    }

    pub fn register(&self, name: &str) -> i64 {
        self.regs.get(name).copied().unwrap_or(0)
    }

    pub fn run(&mut self, program: &Program) -> Vec<TraceEvent> {
        self.reset_state();
        let mut pc = 0;
        while pc < program.instructions.len() {
            let instruction = &program.instructions[pc];
            match instruction.op.as_str() {
                "LI" => {
                    let dst = required_operand(&instruction.a);
                    let value = self.value(instruction.b.as_deref());
                    self.regs.insert(dst.to_string(), value);
                }
                "MOV" => {
                    let dst = required_operand(&instruction.a);
                    let value = self.value(instruction.b.as_deref());
                    self.regs.insert(dst.to_string(), value);
                }
                "ADD" => self.binary_op(instruction, |left, right| left + right),
                "SUB" => self.binary_op(instruction, |left, right| left - right),
                "MUL" => self.binary_op(instruction, |left, right| left * right),
                "AND" => self.binary_op(instruction, |left, right| left & right),
                "OR" => self.binary_op(instruction, |left, right| left | right),
                "XOR" => self.binary_op(instruction, |left, right| left ^ right),
                "CALL_STUB" => {
                    let symbol = required_operand(&instruction.a).to_string();
                    self.trace.push(TraceEvent::CallStub {
                        capability: capability_for_symbol(&symbol).map(str::to_string),
                        symbol,
                        blocked: true,
                        pc,
                    });
                }
                "SYSCALL_STUB" => {
                    let number = self.value(instruction.a.as_deref());
                    self.trace.push(TraceEvent::SyscallStub {
                        number,
                        blocked: true,
                        pc,
                    });
                }
                "RET" | "TRAP" => break,
                other => self.trace.push(TraceEvent::Unsupported {
                    op: other.to_string(),
                    blocked: true,
                    pc,
                }),
            }
            pc += 1;
        }
        self.trace.clone()
    }

    fn reset_state(&mut self) {
        self.regs = (0..16).map(|index| (format!("r{index}"), 0)).collect();
        self.trace.clear();
    }

    fn value(&self, token: Option<&str>) -> i64 {
        let Some(token) = token else {
            return 0;
        };
        let trimmed = token.trim();
        if let Ok(value) = trimmed.parse::<i64>() {
            return value;
        }
        self.register(trimmed)
    }

    fn binary_op(&mut self, instruction: &Instruction, op: impl FnOnce(i64, i64) -> i64) {
        let dst = required_operand(&instruction.a);
        let left = self.value(instruction.b.as_deref());
        let right = self.value(instruction.c.as_deref());
        self.regs.insert(dst.to_string(), op(left, right));
    }
}

impl Default for SafeIsaEmulator {
    fn default() -> Self {
        Self::new()
    }
}

fn required_operand(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("")
}

pub fn emit_safeisa(function: &Function) -> Program {
    let mut instructions = Vec::new();
    for block in &function.blocks {
        for op in &block.ops {
            match op.op.as_str() {
                "Mov" => instructions.push(Instruction {
                    op: "MOV".to_string(),
                    a: op.dst.clone(),
                    b: op.src.clone(),
                    c: None,
                }),
                "Add" | "Sub" | "Mul" | "And" | "Or" | "Xor" => {
                    instructions.push(Instruction {
                        op: op.op.to_uppercase(),
                        a: op.dst.clone(),
                        b: op.src.clone(),
                        c: op.src2.clone(),
                    });
                }
                "ExternalCall" => instructions.push(Instruction {
                    op: "CALL_STUB".to_string(),
                    a: op.symbol.clone(),
                    b: None,
                    c: None,
                }),
                "Return" => instructions.push(Instruction::new("RET", None, None, None)),
                "Unsupported" => instructions.push(Instruction {
                    op: "TRAP".to_string(),
                    a: Some(format!(
                        "unsupported@{:#x}",
                        op.source_address.unwrap_or_default()
                    )),
                    b: None,
                    c: None,
                }),
                _ => {}
            }
        }
    }
    Program::new(instructions)
}

pub fn render_safeisa(program: &Program, function_name: &str) -> String {
    let mut lines = vec![format!("FUNC {function_name}")];
    for instruction in &program.instructions {
        let mut parts = vec![instruction.op.clone()];
        for operand in [&instruction.a, &instruction.b, &instruction.c]
            .into_iter()
            .flatten()
        {
            parts.push(operand.clone());
        }
        lines.push(format!("  {}", parts.join(" ")));
    }
    lines.push("END".to_string());
    lines.join("\n") + "\n"
}
