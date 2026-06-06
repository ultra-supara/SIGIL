//! Render a single sample AI-BOM to stdout via the native render path.
//! Used by CI as the source of truth when comparing the committed wasm
//! binary's actual output against what `sigil-core::aibom::render_ai_bom`
//! produces.
//!
//! Usage:
//!
//! ```text
//! cargo run -q -p sigil-aibom-wasm --example render_sample -- <path/to/sample.aibom.json>
//! ```
//!
//! Prints the rendered Markdown with no trailing newline beyond what the
//! renderer itself adds, so byte-equality against the wasm output is
//! meaningful.

use std::env;
use std::fs;
use std::io::Write;
use std::process::ExitCode;

use sigil_aibom_wasm::render_aibom_markdown_inner;

fn main() -> ExitCode {
    let path = match env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: render_sample <path/to/sample.aibom.json>");
            return ExitCode::from(2);
        }
    };
    let json = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("could not read {path}: {err}");
            return ExitCode::from(2);
        }
    };
    match render_aibom_markdown_inner(&json) {
        Ok(md) => {
            // Use write_all on stdout so a partial newline-printing run
            // doesn't add a trailing flush newline.
            let _ = std::io::stdout().write_all(md.as_bytes());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}
