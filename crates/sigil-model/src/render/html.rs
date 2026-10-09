//! HTML from SIGIL's own Markdown, for the browser viewer (U-10; PR-3b-3b design §3).
//!
//! The reports ([`super::markdown`], [`super::aibom::markdown`]) are the one layout. This
//! converts the small Markdown subset they write, and nothing else:
//!
//! | Markdown | HTML |
//! |---|---|
//! | `# ` / `## ` line | `h1` / `h2` |
//! | `\|…\|` lines with a `\|---\|` separator after the first | `table` (`thead`, `tbody`), cells split on unescaped `\|` |
//! | consecutive `- ` lines | `ul` of `li` |
//! | unescaped `**…**`, paired within a line | `strong` |
//! | any other non-blank line | `p` |
//!
//! Inline, `\X` is the character X, and all text is HTML-escaped (`& < > " '`). The output uses
//! only the tags above, and never an attribute.
//!
//! Input-derived text cannot form any of these: `UntrustedText::markdown_inline` escapes every
//! ASCII punctuation character and shows control and bidirectional characters as `\u{…}`. Any
//! other input, however it is built, still yields only escaped text in the tags above.

/// The HTML of `md`, one block per line group, each followed by a newline.
pub fn from_markdown(md: &str) -> String {
    let lines: Vec<&str> = md.lines().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if line.trim().is_empty() {
            i += 1;
            continue;
        }
        if line.starts_with('|') && lines.get(i + 1).is_some_and(|l| is_separator(l)) {
            out.push_str("<table><thead><tr>");
            for cell in split_cells(line) {
                out.push_str("<th>");
                out.push_str(&inline(cell));
                out.push_str("</th>");
            }
            out.push_str("</tr></thead><tbody>");
            i += 2;
            while i < lines.len() && lines[i].starts_with('|') {
                out.push_str("<tr>");
                for cell in split_cells(lines[i]) {
                    out.push_str("<td>");
                    out.push_str(&inline(cell));
                    out.push_str("</td>");
                }
                out.push_str("</tr>");
                i += 1;
            }
            out.push_str("</tbody></table>\n");
            continue;
        }
        if line.starts_with("- ") {
            out.push_str("<ul>");
            while i < lines.len() && lines[i].starts_with("- ") {
                out.push_str("<li>");
                out.push_str(&inline(&lines[i][2..]));
                out.push_str("</li>");
                i += 1;
            }
            out.push_str("</ul>\n");
            continue;
        }
        let (tag, body) = if let Some(body) = line.strip_prefix("## ") {
            ("h2", body)
        } else if let Some(body) = line.strip_prefix("# ") {
            ("h1", body)
        } else {
            ("p", line)
        };
        out.push('<');
        out.push_str(tag);
        out.push('>');
        out.push_str(&inline(body));
        out.push_str("</");
        out.push_str(tag);
        out.push_str(">\n");
        i += 1;
    }
    out
}

/// `|---|---|`: a pipe-delimited line whose every cell is dashes, with optional alignment colons.
fn is_separator(line: &str) -> bool {
    let Some(inner) = line.strip_prefix('|') else {
        return false;
    };
    let inner = inner.strip_suffix('|').unwrap_or(inner);
    !inner.is_empty()
        && inner.split('|').all(|cell| {
            let cell = cell.trim();
            let cell = cell.strip_prefix(':').unwrap_or(cell);
            let cell = cell.strip_suffix(':').unwrap_or(cell);
            !cell.is_empty() && cell.chars().all(|c| c == '-')
        })
}

/// The cells of a table line, split on unescaped `|` (`\|` stays in its cell), without the outer
/// pipes, trimmed.
fn split_cells(line: &str) -> Vec<&str> {
    let mut cells = vec![];
    let mut start = None;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '|' => {
                if let Some(s) = start {
                    cells.push(line[s..i].trim());
                }
                start = Some(i + 1);
            }
            _ => {}
        }
    }
    // Text after the last pipe is a cell too (a row without a closing pipe).
    if let Some(s) = start {
        let rest = line[s..].trim();
        if !rest.is_empty() {
            cells.push(rest);
        }
    }
    cells
}

enum Piece {
    Text(String),
    Strong,
}

/// Inline text: escapes undone, unescaped `**` pairs made `strong`, everything HTML-escaped.
fn inline(text: &str) -> String {
    let mut pieces: Vec<Piece> = vec![];
    let mut current = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(next) => current.push(next),
                None => current.push('\\'),
            },
            '*' if chars.peek() == Some(&'*') => {
                chars.next();
                pieces.push(Piece::Text(std::mem::take(&mut current)));
                pieces.push(Piece::Strong);
            }
            c => current.push(c),
        }
    }
    pieces.push(Piece::Text(current));
    // Markers pair from the left; an odd last one is text.
    let markers = pieces.iter().filter(|p| matches!(p, Piece::Strong)).count();
    let mut paired = markers - markers % 2;
    let mut open = false;
    let mut out = String::new();
    for piece in pieces {
        match piece {
            Piece::Text(t) => escape_into(&mut out, &t),
            Piece::Strong if paired > 0 => {
                out.push_str(if open { "</strong>" } else { "<strong>" });
                open = !open;
                paired -= 1;
            }
            Piece::Strong => out.push_str("**"),
        }
    }
    out
}

fn escape_into(out: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
}
