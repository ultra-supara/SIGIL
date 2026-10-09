//! The native render of one viewer sample, for CI (`.github/workflows/wasm.yml`): the committed
//! wasm must produce the same bytes.
//!
//! `cargo run -q -p sigil-wasm --example render_sample -- <SAMPLE.json> [--html]`

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: render_sample <SAMPLE.json> [--html]");
        std::process::exit(2);
    };
    let html = args.next().as_deref() == Some("--html");
    let json = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("{path}: {e}");
        std::process::exit(1);
    });
    let rendered = match sigil_wasm::detect_inner(&json) {
        "session" => sigil_wasm::render_session_markdown_inner(&json),
        "aibom-v2" => sigil_wasm::render_aibom_markdown_inner(&json),
        other => Err(format!("{path}: not a sample ({other})")),
    };
    match rendered {
        Ok(md) if html => print!("{}", sigil_wasm::markdown_html_inner(&md)),
        Ok(md) => print!("{md}"),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
