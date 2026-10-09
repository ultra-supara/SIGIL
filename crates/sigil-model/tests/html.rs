//! `render::html::from_markdown` and the U-10 audit (PR-3b-3b design §3, §8): the viewer's HTML
//! comes from SIGIL's own Markdown, with one escaping contract. Only a fixed set of tags, no
//! attributes, and every input-derived value shown as text.

mod common;

use common::*;
use sigil_model::render::aibom::{markdown as aibom_markdown, project};
use sigil_model::render::html::from_markdown;
use sigil_model::render::markdown::render_session;
use sigil_model::*;

const TAGS: &[&str] = &[
    "h1", "h2", "p", "ul", "li", "table", "thead", "tbody", "tr", "th", "td", "strong",
];

const HOSTILE: &str =
    "x|y `code` <script>alert(1)</script> [a](javascript:alert(1)) *b* _c_ **d**\n# heading\u{202E}";

/// Every `<` opens or closes an allowed tag, and no tag has an attribute.
fn assert_safe(html: &str) {
    let mut rest = html;
    while let Some(i) = rest.find('<') {
        let after = &rest[i + 1..];
        let end = after
            .find('>')
            .unwrap_or_else(|| panic!("an unclosed tag in {html}"));
        let tag = &after[..end];
        let name = tag.strip_prefix('/').unwrap_or(tag);
        assert!(TAGS.contains(&name), "disallowed tag <{tag}> in:\n{html}");
        rest = &after[end + 1..];
    }
    // A stray `>` would mean an unbalanced bracket of SIGIL's own making.
    let lower = html.to_lowercase();
    assert!(
        !lower.contains("<script") && !lower.contains("<a"),
        "{html}"
    );
}

/// The text of the HTML: tags removed, entities decoded.
fn text(html: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

fn zero_sha() -> Sha256Hex {
    Sha256Hex::new("0".repeat(64)).unwrap()
}

// --- the constructs --------------------------------------------------------------------------

#[test]
fn each_construct_becomes_its_element() {
    let cases = [
        ("# Title\n", "<h1>Title</h1>\n"),
        ("## A\\-B\n", "<h2>A-B</h2>\n"),
        ("- one\n- two\n", "<ul><li>one</li><li>two</li></ul>\n"),
        (
            "**Verdict:** PASS · **Completeness:** COMPLETE\n",
            "<p><strong>Verdict:</strong> PASS · <strong>Completeness:</strong> COMPLETE</p>\n",
        ),
        (
            "| A | B |\n|---|---|\n| x\\|y | z |\n",
            "<table><thead><tr><th>A</th><th>B</th></tr></thead><tbody><tr><td>x|y</td><td>z</td></tr></tbody></table>\n",
        ),
        ("plain text\n", "<p>plain text</p>\n"),
        ("first\n\nsecond\n", "<p>first</p>\n<p>second</p>\n"),
        ("", ""),
    ];
    for (md, html) in cases {
        assert_eq!(from_markdown(md), html, "{md:?}");
    }
}

#[test]
fn escapes_are_undone_once_and_text_is_html_escaped() {
    let cases = [
        // An escaped backslash, then an escaped brace: `\u{202E}` as text.
        ("\\\\u\\{202E\\}\n", "<p>\\u{202E}</p>\n"),
        // Escaped strong markers are text.
        ("\\*\\*not bold\\*\\*\n", "<p>**not bold**</p>\n"),
        // Raw HTML specials are escaped.
        (
            "a < b & \"c\" 'd' >\n",
            "<p>a &lt; b &amp; &quot;c&quot; &#39;d&#39; &gt;</p>\n",
        ),
        // Escaped specials too.
        ("\\<b\\>\n", "<p>&lt;b&gt;</p>\n"),
        // A trailing lone backslash stays.
        ("end\\\n", "<p>end\\</p>\n"),
        // An unpaired marker stays text; a pair still makes strong.
        ("a ** b\n", "<p>a ** b</p>\n"),
        ("**x** **\n", "<p><strong>x</strong> **</p>\n"),
    ];
    for (md, html) in cases {
        assert_eq!(from_markdown(md), html, "{md:?}");
    }
}

#[test]
fn only_tables_with_a_separator_are_tables() {
    // No separator: a paragraph, pipes as text.
    assert_eq!(from_markdown("| a | b |\n"), "<p>| a | b |</p>\n");
    // Ragged rows keep their own cells.
    let html = from_markdown("| A | B |\n|---|---|\n| only |\n| x | y | z |\n");
    assert_safe(&html);
    assert!(html.contains("<tr><td>only</td></tr>"), "{html}");
    assert!(html.contains("<td>z</td>"), "{html}");
}

// --- the U-10 audit over the real renderers --------------------------------------------------

#[test]
fn every_golden_report_is_safe_html() {
    for (name, s) in examples() {
        let html = from_markdown(&render_session(&s));
        assert_safe(&html);
        assert!(html.starts_with("<h1>SIGIL session</h1>\n"), "{name}");
        let bom = project(&s, zero_sha());
        let html = from_markdown(&aibom_markdown(&bom));
        assert_safe(&html);
        assert!(html.starts_with("<h1>SIGIL AI-BOM</h1>\n"), "{name}");
    }
}

#[test]
fn hostile_values_show_as_text_exactly_once() {
    let shown = t(HOSTILE).terminal_line();
    // The session report: a hostile root path.
    let mut s = complete_pass();
    s.request.roots[0].path = t(HOSTILE);
    let html = from_markdown(&render_session(&s));
    assert_safe(&html);
    assert_eq!(text(&html).matches(&shown).count(), 1, "{html}");
    // The AI-BOM report: a hostile model name and a non-UTF-8 path.
    let s = store_and_runtime();
    let mut bom = project(&s, zero_sha());
    bom.models[0].name = t(HOSTILE);
    bom.artifacts[0].paths = vec![UntrustedText::from_bytes(vec![0xff, b'<', b'|'])];
    let html = from_markdown(&aibom_markdown(&bom));
    assert_safe(&html);
    let plain = text(&html);
    assert_eq!(plain.matches(&shown).count(), 1, "{html}");
    assert!(plain.contains("hex:ff3c7c"), "{plain}");
    // The bidi override never reaches the HTML as a character.
    assert!(!html.contains('\u{202E}'));
}

// --- robustness: any input, never markup ------------------------------------------------------

#[test]
fn hostile_markdown_never_yields_markup() {
    let flood = "**".repeat(101);
    let inputs = [
        flood.as_str(),
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "[a](javascript:alert(1))",
        "![x](http://e/x.png)",
        "| <b> | **x |\n|---|---|\n| </td><script> | y\\ |",
        "# <h1>\n## </h2>\n- <li onclick=x>",
        "\\",
        "\\\\\\",
        "<",
        ">>>><<<<",
        "&lt;script&gt;",
        "\u{0}\u{1b}[31m",
    ];
    for md in inputs {
        let html = from_markdown(md);
        assert_safe(&html);
    }
    // A seeded generator over the characters that matter.
    let alphabet: Vec<char> = "<>\"'&|*#-\\ \nab:=/()[]!\u{202E}".chars().collect();
    let mut state: u64 = 0x5eed_1234_abcd_ef01;
    for _ in 0..3000 {
        let mut md = String::new();
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let len = (state % 120) as usize;
        for _ in 0..len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            md.push(alphabet[(state % alphabet.len() as u64) as usize]);
        }
        let html = from_markdown(&md);
        assert_safe(&html);
        assert!(
            !html.contains("<script") && !html.contains(" on"),
            "{md:?} -> {html}"
        );
    }
}
