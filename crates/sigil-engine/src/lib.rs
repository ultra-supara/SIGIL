//! `sigil-engine`: what SIGIL v2 does to produce an analysis session (plan §4.3).
//!
//! - [`collect::fs`] is `SafeFs`, the only way the engine reads files: anchored at scan-root
//!   directory fds, one component at a time, symlinks resolved and recorded by the walker,
//!   bounded, and read-only (plan §4.6.2).
//! - [`policy`] loads a `sigil-policy/1` file and evaluates it over a session: decisions for
//!   findings and open questions, policy violations, and the Outcome (plan §4.7). It is a pure
//!   function of the session and the policy.
//!
//! The engine never executes, `dlopen`s, or `mmap`s a target and performs no network I/O
//! (contracts C-1 to C-5, `docs/adr/ADR-002-execution-modes.md`).

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod analyze;
pub mod collect;
pub mod inspect;
pub mod policy;
