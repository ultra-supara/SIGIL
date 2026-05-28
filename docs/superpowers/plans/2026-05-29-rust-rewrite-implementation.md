# SIGIL Rust Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace SIGIL's Python MVP with a Rust workspace containing `sigil-core` and `sigil-cli`, preserving current `assess` and `lift` behavior.

**Architecture:** `sigil-core` owns deterministic analysis, policy evaluation, evidence, IR, SafeISA, and x86 lifting. `sigil-cli` is a thin Clap-based binary that calls `sigil-core`. The Python implementation is kept only as a migration oracle under `legacy/python` until parity tests prove Rust behavior.

**Tech Stack:** Rust 2021, Cargo workspace, `clap`, `serde`, `serde_json`, `serde_yaml`, `thiserror`, `anyhow`, `object`, `iced-x86`, `assert_cmd`, Python legacy tests for parity.

---

### Task 1: Workspace and Assessment Core

**Files:**
- Create: `Cargo.toml`
- Create: `crates/sigil-core/Cargo.toml`
- Create: `crates/sigil-core/src/lib.rs`
- Create: `crates/sigil-core/src/assess/mod.rs`
- Create: `crates/sigil-core/src/evidence.rs`
- Create: `crates/sigil-core/src/report.rs`
- Create: `crates/sigil-cli/Cargo.toml`
- Create: `crates/sigil-cli/src/main.rs`

- [ ] **Step 1: Write failing policy and CLI tests**

Create Rust tests that require `Verdict`, policy loading/evaluation, capability mapping, evidence serialization, and `sigil assess --external-call connect`.

- [ ] **Step 2: Verify RED**

Run: `cargo test`

Expected: failure because the workspace and Rust modules are not implemented yet.

- [ ] **Step 3: Implement assessment core and minimal CLI**

Implement typed policy loading from YAML, capability mapping, evidence JSON, markdown report rendering, and `assess --external-call`.

- [ ] **Step 4: Verify GREEN**

Run: `cargo test`

Expected: all Rust assessment tests pass.

### Task 2: IR and SafeISA

**Files:**
- Create: `crates/sigil-core/src/ir.rs`
- Create: `crates/sigil-core/src/safeisa/mod.rs`

- [ ] **Step 1: Write failing IR and SafeISA tests**

Test IR object construction, SafeISA arithmetic, blocked `CALL_STUB`, reset behavior, and string immediates/register tokens.

- [ ] **Step 2: Verify RED**

Run: `cargo test -p sigil-core`

Expected: failure because IR and SafeISA modules are missing or incomplete.

- [ ] **Step 3: Implement IR, SafeISA model, emitter, and emulator**

Port the Python behavior into Rust with deterministic trace events and reset-on-run emulator state.

- [ ] **Step 4: Verify GREEN**

Run: `cargo test -p sigil-core`

Expected: all core tests pass.

### Task 3: x86 Object Pipeline and Full CLI

**Files:**
- Create: `crates/sigil-core/src/x86/mod.rs`
- Modify: `crates/sigil-cli/src/main.rs`

- [ ] **Step 1: Write failing x86 and CLI tests**

Test ELF function loading, x86 decoding/lifting, `sigil lift`, binary-backed `sigil assess`, and skipped behavior when `clang` is unavailable.

- [ ] **Step 2: Verify RED**

Run: `cargo test`

Expected: x86 and CLI tests fail because object loading and lifting are not implemented.

- [ ] **Step 3: Implement x86 loading, decoding, lifting, and CLI integration**

Use `object` for symbols/sections/relocations and `iced-x86` for x86-64 decoding. Preserve current narrow instruction support.

- [ ] **Step 4: Verify GREEN**

Run: `cargo test`

Expected: Rust `lift` and `assess` tests pass.

### Task 4: Legacy Python Parity and Retirement

**Files:**
- Move: `sigil/` to `legacy/python/sigil/`
- Move: `tests/` to `legacy/python/tests/`
- Move: `pyproject.toml` to `legacy/python/pyproject.toml`
- Modify: `README.md`
- Modify: `demos/*.sh`
- Create: `tests/parity.rs`

- [ ] **Step 1: Write failing parity test**

Add a Rust integration test that compares Rust CLI output with legacy Python CLI for `assess --external-call connect` and, when dependencies exist, fixture-backed `assess`.

- [ ] **Step 2: Verify RED**

Run: `cargo test --test parity`

Expected: failure until legacy paths and Rust CLI are wired.

- [ ] **Step 3: Move Python to legacy and update docs/scripts**

Keep Python available for parity tests but remove it from the primary project root.

- [ ] **Step 4: Verify GREEN**

Run: `cargo test`

Expected: all Rust and parity tests pass.

### Task 5: Final Quality Gates and Commit

**Files:**
- Modify as needed based on verification results.

- [ ] **Step 1: Format**

Run: `cargo fmt --all -- --check`

Expected: no formatting diff.

- [ ] **Step 2: Lint**

Run: `cargo clippy --all-targets --all-features -- -D warnings`

Expected: no warnings.

- [ ] **Step 3: Test**

Run: `cargo test`

Expected: all Rust tests pass.

- [ ] **Step 4: Security review**

Use `codex-security:security-scan` on the final diff and fix any validated findings.

- [ ] **Step 5: Commit**

Run:

```bash
git add .
git commit -m "Rewrite SIGIL core in Rust"
```

Expected: final branch contains the design, plan, Rust implementation, legacy Python location, tests, and documentation.

