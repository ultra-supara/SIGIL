//! SIGIL safety contracts C-1..C-6 (`docs/adr/ADR-002-execution-modes.md`).
//!
//! Syscall tests over **exercised** CLI paths, run under strace. They check the contracts for the
//! commands below; they do not prove that an untested path is compliant, and they are not a
//! runtime sandbox. Linux only. Without a usable strace the tests skip with a printed reason,
//! unless `SIGIL_SAFETY_REQUIRED=1` (set in CI), which turns a missing tracer into a failure.

// The harness launches strace, compilers and the CLI, and the negative controls perform the
// forbidden operations on purpose. The product bans (clippy.toml) do not apply to this file.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

#[cfg(target_os = "linux")]
mod cli;
#[cfg(target_os = "linux")]
mod contracts;
#[cfg(target_os = "linux")]
mod controls;
#[cfg(target_os = "linux")]
mod fixtures;
#[cfg(target_os = "linux")]
mod trace;

#[cfg(not(target_os = "linux"))]
#[test]
fn safety_tests_require_linux() {
    eprintln!("SKIPPED (safety): syscall tests need Linux and strace");
}
