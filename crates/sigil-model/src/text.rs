//! Untrusted, input-derived text (plan §4.10).
//!
//! Every string that comes from an inspected input — paths, symbol names, embedded strings,
//! configuration values, error messages — is an [`UntrustedText`]. It keeps the exact bytes
//! (non-UTF-8 included) and can only be shown through its escape API, so a renderer cannot place
//! attacker-controlled Markdown, HTML, terminal escapes, or bidirectional overrides into a report.
//!
//! JSON form: a UTF-8 value is a plain string; a value that is not valid UTF-8 is
//! `{"hex": "<lowercase hex of the bytes>"}`. The hex form is used only for non-UTF-8 values, so
//! each value has exactly one serialization.

use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Longest text shown by the escape API, in characters. Longer text is truncated with a marker.
pub const MAX_DISPLAY_CHARS: usize = 512;

/// Input-derived text. See the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UntrustedText(Repr);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Repr {
    Utf8(String),
    Bytes(Vec<u8>),
}

impl UntrustedText {
    /// Wraps UTF-8 text.
    pub fn new(text: impl Into<String>) -> Self {
        UntrustedText(Repr::Utf8(text.into()))
    }

    /// Wraps raw bytes, e.g. a Linux path. Valid UTF-8 is stored as text.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        match String::from_utf8(bytes.into()) {
            Ok(text) => UntrustedText(Repr::Utf8(text)),
            Err(e) => UntrustedText(Repr::Bytes(e.into_bytes())),
        }
    }

    /// The text, if it is valid UTF-8. For comparison and matching only, never for output.
    pub fn as_str(&self) -> Option<&str> {
        match &self.0 {
            Repr::Utf8(s) => Some(s),
            Repr::Bytes(_) => None,
        }
    }

    /// The exact bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            Repr::Utf8(s) => s.as_bytes(),
            Repr::Bytes(b) => b,
        }
    }

    /// Escaped for inline Markdown (CommonMark/GFM): every ASCII punctuation character is
    /// backslash-escaped, so the rendered text equals the input and no markup, link, HTML, table
    /// cell break, or autolink can be formed. Control, invisible, and bidirectional-override
    /// characters are shown as `\u{XXXX}`. Non-UTF-8 is shown as `hex:<digits>`. Longer than
    /// [`MAX_DISPLAY_CHARS`] characters is truncated with an explicit marker.
    ///
    /// The result contains no line break, so it is safe in a table cell or after a label. It is
    /// meant for inline use: renderers do not start a line with it.
    pub fn markdown_inline(&self) -> String {
        let mut out = String::new();
        let (shown, cut) = self.display_chars();
        for c in shown.chars() {
            if is_hidden(c) {
                out.push_str(&format!("\\\\u\\{{{:04X}\\}}", u32::from(c)));
            } else if c.is_ascii_punctuation() {
                out.push('\\');
                out.push(c);
            } else {
                out.push(c);
            }
        }
        if cut > 0 {
            out.push_str(&format!(" … \\(truncated\\, {cut} more characters\\)"));
        }
        out
    }

    /// For a terminal line: control, invisible, and bidirectional-override characters are shown
    /// as `\u{XXXX}`, so no escape sequence reaches the terminal. Same truncation and hex rules
    /// as [`UntrustedText::markdown_inline`]; no Markdown escaping.
    pub fn terminal_line(&self) -> String {
        let mut out = String::new();
        let (shown, cut) = self.display_chars();
        for c in shown.chars() {
            if is_hidden(c) {
                out.push_str(&format!("\\u{{{:04X}}}", u32::from(c)));
            } else {
                out.push(c);
            }
        }
        if cut > 0 {
            out.push_str(&format!(" … (truncated, {cut} more characters)"));
        }
        out
    }

    /// The text to show (hex for non-UTF-8), cut to the display limit, and how many characters
    /// were cut.
    fn display_chars(&self) -> (String, usize) {
        let full = match &self.0 {
            Repr::Utf8(s) => s.clone(),
            Repr::Bytes(b) => format!("hex:{}", to_hex(b)),
        };
        let total = full.chars().count();
        if total <= MAX_DISPLAY_CHARS {
            (full, 0)
        } else {
            (
                full.chars().take(MAX_DISPLAY_CHARS).collect(),
                total - MAX_DISPLAY_CHARS,
            )
        }
    }
}

/// Characters never shown literally: C0/C1 controls, line/paragraph separators, zero-width and
/// joiner characters, bidirectional embeddings/overrides/isolates, and the byte-order mark.
fn is_hidden(c: char) -> bool {
    c.is_control()
        || matches!(
            u32::from(c),
            0x00AD
                | 0x200B..=0x200F
                | 0x2028..=0x202E
                | 0x2060..=0x2064
                | 0x2066..=0x2069
                | 0xFEFF
                | 0xFFF9..=0xFFFB
        )
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

impl From<&str> for UntrustedText {
    fn from(text: &str) -> Self {
        UntrustedText::new(text)
    }
}

impl From<String> for UntrustedText {
    fn from(text: String) -> Self {
        UntrustedText::new(text)
    }
}

impl Serialize for UntrustedText {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            Repr::Utf8(s) => serializer.serialize_str(s),
            Repr::Bytes(b) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("hex", &to_hex(b))?;
                map.end()
            }
        }
    }
}

struct TextVisitor;

impl<'de> Visitor<'de> for TextVisitor {
    type Value = UntrustedText;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string, or {\"hex\": <lowercase hex>} for a value that is not valid UTF-8")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<UntrustedText, E> {
        Ok(UntrustedText::new(v))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<UntrustedText, A::Error> {
        let mut hex: Option<String> = None;
        while let Some(key) = map.next_key::<String>()? {
            if key != "hex" {
                return Err(de::Error::unknown_field(&key, &["hex"]));
            }
            if hex.is_some() {
                return Err(de::Error::duplicate_field("hex"));
            }
            hex = Some(map.next_value()?);
        }
        let hex = hex.ok_or_else(|| de::Error::missing_field("hex"))?;
        let bytes = from_hex(&hex).ok_or_else(|| {
            de::Error::custom("`hex` must be an even number of lowercase hex digits")
        })?;
        if std::str::from_utf8(&bytes).is_ok() {
            return Err(de::Error::custom(
                "the `hex` form is only for values that are not valid UTF-8; use a string",
            ));
        }
        Ok(UntrustedText(Repr::Bytes(bytes)))
    }
}

impl<'de> Deserialize<'de> for UntrustedText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(TextVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(t: &UntrustedText) -> String {
        serde_json::to_string(t).unwrap()
    }

    #[test]
    fn utf8_text_serializes_as_a_plain_string() {
        let t = UntrustedText::new("lib/ollama/libggml.so");
        assert_eq!(json(&t), "\"lib/ollama/libggml.so\"");
        assert_eq!(serde_json::from_str::<UntrustedText>(&json(&t)).unwrap(), t);
    }

    #[test]
    fn non_utf8_bytes_round_trip_through_hex() {
        let t = UntrustedText::from_bytes(vec![0x6c, 0x69, 0x62, 0xff]);
        assert_eq!(t.as_str(), None);
        assert_eq!(json(&t), "{\"hex\":\"6c6962ff\"}");
        assert_eq!(serde_json::from_str::<UntrustedText>(&json(&t)).unwrap(), t);
        assert_eq!(t.as_bytes(), &[0x6c, 0x69, 0x62, 0xff]);
    }

    #[test]
    fn valid_utf8_bytes_are_stored_as_text() {
        assert_eq!(
            UntrustedText::from_bytes(b"abc".to_vec()),
            UntrustedText::new("abc")
        );
    }

    #[test]
    fn non_canonical_or_malformed_hex_is_rejected() {
        for bad in [
            r#"{"hex":"616263"}"#,
            r#"{"hex":"FF"}"#,
            r#"{"hex":"f"}"#,
            r#"{"hex":"ff","x":1}"#,
            r#"{"bytes":"ff"}"#,
            r#"{}"#,
            "42",
            "null",
        ] {
            assert!(
                serde_json::from_str::<UntrustedText>(bad).is_err(),
                "{bad} accepted"
            );
        }
    }

    /// Every ASCII punctuation character in the output is escaped by a preceding backslash.
    fn assert_inert(md: &str) {
        let mut chars = md.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                let next = chars.next().expect("dangling backslash");
                assert!(
                    next.is_ascii_punctuation(),
                    "backslash before {next:?} in {md}"
                );
            } else {
                assert!(!c.is_ascii_punctuation(), "unescaped {c:?} in {md}");
                assert!(!is_hidden(c), "hidden {c:?} in {md}");
            }
        }
    }

    #[test]
    fn markdown_escaping_neutralizes_injection_strings() {
        for attack in [
            "a|b|c",
            "`code`",
            "<script>alert(1)</script>",
            "[click](javascript:alert(1))",
            "![img](http://x/y.png)",
            "line1\nline2\r\n| injected | row |",
            "\u{1b}[31mred\u{1b}[0m",
            "evil\u{202e}gpj.so",
            "zero\u{200b}width\u{feff}",
            "https://evil.example/ and www.evil.example",
            "&lt;b&gt; &#x3C;",
            "**bold** _it_ ~~del~~ # h",
            "back\\slash",
        ] {
            let md = UntrustedText::new(attack).markdown_inline();
            assert_inert(&md);
            assert!(!md.contains('\n') && !md.contains('\r'), "{md}");
        }
    }

    #[test]
    fn markdown_escaping_keeps_plain_text_and_shows_hidden_characters() {
        assert_eq!(
            UntrustedText::new("libggml so").markdown_inline(),
            "libggml so"
        );
        assert_eq!(UntrustedText::new("a.so").markdown_inline(), "a\\.so");
        assert_eq!(
            UntrustedText::new("a\u{202e}b").markdown_inline(),
            "a\\\\u\\{202E\\}b"
        );
        assert_eq!(
            UntrustedText::new("a\u{202e}b").terminal_line(),
            "a\\u{202E}b"
        );
        assert_eq!(
            UntrustedText::new("a\u{1b}b").terminal_line(),
            "a\\u{001B}b"
        );
    }

    #[test]
    fn long_text_is_truncated_with_a_marker() {
        let long = "a".repeat(MAX_DISPLAY_CHARS + 88);
        let md = UntrustedText::new(long.clone()).markdown_inline();
        assert!(md.starts_with(&"a".repeat(MAX_DISPLAY_CHARS)));
        assert!(md.contains("truncated\\, 88 more characters"), "{md}");
        assert_inert(&md.replace('…', ""));
        let line = UntrustedText::new(long).terminal_line();
        assert!(line.ends_with("(truncated, 88 more characters)"));
        let exact = UntrustedText::new("b".repeat(MAX_DISPLAY_CHARS));
        assert!(!exact.markdown_inline().contains("truncated"));
    }

    #[test]
    fn non_utf8_is_shown_in_hex() {
        let t = UntrustedText::from_bytes(vec![0xff, 0x00]);
        assert_eq!(t.terminal_line(), "hex:ff00");
        assert_eq!(t.markdown_inline(), "hex\\:ff00");
    }
}
