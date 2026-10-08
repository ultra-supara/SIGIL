//! Observe mode: reading the running system (plan §4.2, §4.6.8). Only the `/proc` entries of the
//! C-6 allowlist are read, and magic links are read with `readlinkat`, never followed or opened.

pub mod proc;
