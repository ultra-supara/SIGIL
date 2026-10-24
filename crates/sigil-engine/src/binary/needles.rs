//! The signature needles (PR-4c-2a spec §3): what the scan looks for in each ELF file, and the
//! feature each match hints at. Data, embedded and parsed once, as `signatures/components.toml`
//! is.

use std::sync::OnceLock;

use serde::Deserialize;
use sigil_model::{FeatureKey, Signal};

const NEEDLES: &str = include_str!("../../signatures/needles.toml");

/// The longest needle value, in bytes.
pub const MAX_NEEDLE: usize = 4096;

/// Where a needle is looked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NeedleKind {
    /// A prefix of the name of an exported dynamic symbol.
    Export,
    /// An exact function name in `.gopclntab`'s function-name table, which the section's header
    /// locates (PR-4c-3a), in an ELF file with Go build info.
    GoFunction,
    /// Exact bytes in `.rodata`, `.rodata.*`, or `.lrodata`.
    String,
}

impl NeedleKind {
    /// The signal of the hints this kind gives.
    pub fn signal(self) -> Signal {
        match self {
            NeedleKind::Export => Signal::Export,
            NeedleKind::GoFunction => Signal::GoFunction,
            NeedleKind::String => Signal::String,
        }
    }

    /// The kind as `needles.toml` spells it.
    fn name(self) -> &'static str {
        match self {
            NeedleKind::Export => "export",
            NeedleKind::GoFunction => "go-function",
            NeedleKind::String => "string",
        }
    }
}

/// One needle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Needle {
    pub feature: FeatureKey,
    pub kind: NeedleKind,
    /// Not empty, at most [`MAX_NEEDLE`] bytes.
    pub value: Vec<u8>,
}

/// The parsed database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Needles {
    /// In file order.
    needles: Vec<Needle>,
}

impl Needles {
    /// The needles of `kind`, in file order.
    pub fn of(&self, kind: NeedleKind) -> Vec<&Needle> {
        self.needles.iter().filter(|n| n.kind == kind).collect()
    }

    /// The bytes two consecutive chunks of a scan for `kind` share, so that a match across their
    /// boundary is in one of them whole: one less than its longest needle, or for `go-function`
    /// the longest needle, since a match is the name and the NUL after it (PR-4c-3a). 0 without
    /// one.
    pub fn overlap(&self, kind: NeedleKind) -> u64 {
        let longest = self.of(kind).iter().map(|n| n.value.len() as u64).max();
        match (kind, longest) {
            (_, None) => 0,
            (NeedleKind::GoFunction, Some(longest)) => longest,
            (_, Some(longest)) => longest.saturating_sub(1),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNeedles {
    needle: Vec<RawNeedle>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNeedle {
    feature: String,
    kind: NeedleKind,
    value: String,
}

static DB: OnceLock<Result<Needles, String>> = OnceLock::new();

/// The embedded database, parsed at first use. `Err` only for an invalid embedded file, which
/// `the_embedded_database_parses` rules out; a caller reports it as an internal error.
pub fn needles() -> Result<&'static Needles, String> {
    DB.get_or_init(|| parse(NEEDLES))
        .as_ref()
        .map_err(Clone::clone)
}

/// Parses a database: each needle a valid feature key, a known kind, and a value that is not
/// empty and at most [`MAX_NEEDLE`] bytes; no (feature, kind, value) listed twice. Public for the
/// tests of the kinds the embedded database has no needle of.
pub fn parse(text: &str) -> Result<Needles, String> {
    let raw: RawNeedles = toml::from_str(text).map_err(|e| format!("needles.toml: {e}"))?;
    let mut needles: Vec<Needle> = vec![];
    for n in raw.needle {
        let feature = FeatureKey::new(n.feature).map_err(|e| format!("needles.toml: {e}"))?;
        let value = n.value.into_bytes();
        if value.is_empty() || value.len() > MAX_NEEDLE {
            return Err(format!(
                "needles.toml: {feature}: a value is 1 to {MAX_NEEDLE} bytes"
            ));
        }
        let needle = Needle {
            feature,
            kind: n.kind,
            value,
        };
        if needles.contains(&needle) {
            return Err(format!(
                "needles.toml: {}: the {} needle {:?} listed twice",
                needle.feature,
                needle.kind.name(),
                String::from_utf8_lossy(&needle.value)
            ));
        }
        needles.push(needle);
    }
    Ok(Needles { needles })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(fields: &str) -> Result<Needles, String> {
        parse(&format!("[[needle]]\n{fields}\n"))
    }

    #[test]
    fn the_embedded_database_parses() {
        let db = needles().unwrap();
        let listed: Vec<(&str, NeedleKind, &[u8])> = db
            .needles
            .iter()
            .map(|n| (n.feature.as_str(), n.kind, n.value.as_slice()))
            .collect();
        assert_eq!(
            listed,
            [
                (
                    "rpc.code_present",
                    NeedleKind::Export,
                    &b"ggml_backend_rpc_"[..]
                ),
                (
                    "ollama.llama_server_launch",
                    NeedleKind::GoFunction,
                    b"github.com/ollama/ollama/llm.SetupLlamaServerCommandEnv"
                ),
                (
                    "ollama.device_discovery",
                    NeedleKind::GoFunction,
                    b"github.com/ollama/ollama/discover.discoverNativeDevices"
                ),
            ]
        );
        assert!(
            db.of(NeedleKind::String).is_empty(),
            "no string needle ships"
        );
    }

    /// The model's `expected_binary_identity` requires the gap `SCAN_NO_SECTIONS` of a Go ELF
    /// without a section header table (`NoSectionsGap::Must`): the embedded database has
    /// Go-function needles, which look in `.gopclntab`.
    #[test]
    fn the_embedded_database_looks_for_go_functions() {
        assert!(!needles().unwrap().of(NeedleKind::GoFunction).is_empty());
    }

    /// The model's `expected_binary_identity` requires the gap `SCAN_NAME_NOT_READ` of a linked
    /// ELF whose loader's dynamic symbols the parse did not read (`DYNSYM_UNREAD_GAPS`): the
    /// embedded database has an export needle, which looks in the exports.
    #[test]
    fn the_embedded_database_looks_for_exports() {
        assert!(!needles().unwrap().of(NeedleKind::Export).is_empty());
    }

    #[test]
    fn each_kind_gives_its_signal() {
        assert_eq!(NeedleKind::Export.signal(), Signal::Export);
        assert_eq!(NeedleKind::GoFunction.signal(), Signal::GoFunction);
        assert_eq!(NeedleKind::String.signal(), Signal::String);
    }

    #[test]
    fn the_overlap_holds_the_longest_match_of_the_kind() {
        let db = parse(
            "[[needle]]\nfeature = \"a.x\"\nkind = \"string\"\nvalue = \"abcd\"\n\
             [[needle]]\nfeature = \"a.y\"\nkind = \"string\"\nvalue = \"abcdefghi\"\n\
             [[needle]]\nfeature = \"a.z\"\nkind = \"go-function\"\nvalue = \"0123456789abcdefghij\"\n",
        )
        .unwrap();
        assert_eq!(db.overlap(NeedleKind::String), 8);
        // A Go function's match is its name and the NUL after it.
        assert_eq!(db.overlap(NeedleKind::GoFunction), 20);
        assert_eq!(db.overlap(NeedleKind::Export), 0);
        let embedded = needles().unwrap();
        assert_eq!(
            embedded.overlap(NeedleKind::GoFunction),
            "github.com/ollama/ollama/llm.SetupLlamaServerCommandEnv".len() as u64
        );
    }

    #[test]
    fn invalid_data_is_an_error_not_a_panic() {
        let ok = "feature = \"a.x\"\nkind = \"string\"\nvalue = \"v\"";
        assert!(one(ok).is_ok());
        let size = Err(format!(
            "needles.toml: a.x: a value is 1 to {MAX_NEEDLE} bytes"
        ));
        assert_eq!(
            one("feature = \"a.x\"\nkind = \"string\"\nvalue = \"\""),
            size
        );
        let long = "v".repeat(MAX_NEEDLE + 1);
        assert_eq!(
            one(&format!(
                "feature = \"a.x\"\nkind = \"string\"\nvalue = \"{long}\""
            )),
            size
        );
        let longest = "v".repeat(MAX_NEEDLE);
        assert!(one(&format!(
            "feature = \"a.x\"\nkind = \"string\"\nvalue = \"{longest}\""
        ))
        .is_ok());
        for bad in [
            // An unknown kind, an unknown field, a missing field, an invalid feature key.
            "feature = \"a.x\"\nkind = \"regex\"\nvalue = \"v\"",
            "feature = \"a.x\"\nkind = \"string\"\nvalue = \"v\"\nsection = \".data\"",
            "feature = \"a.x\"\nkind = \"string\"",
            "feature = \" a\"\nkind = \"string\"\nvalue = \"v\"",
        ] {
            assert!(one(bad).unwrap_err().starts_with("needles.toml: "), "{bad}");
        }
        // An unknown top-level key.
        assert!(parse(&format!("version = 1\n[[needle]]\n{ok}\n"))
            .unwrap_err()
            .starts_with("needles.toml: "));
        let twice = format!("[[needle]]\n{ok}\n[[needle]]\n{ok}\n");
        assert_eq!(
            parse(&twice),
            Err("needles.toml: a.x: the string needle \"v\" listed twice".to_string())
        );
        let go = "feature = \"a.z\"\nkind = \"go-function\"\nvalue = \"p.f\"";
        assert_eq!(
            parse(&format!("[[needle]]\n{go}\n[[needle]]\n{go}\n")),
            Err("needles.toml: a.z: the go-function needle \"p.f\" listed twice".to_string())
        );
        // The same value under another kind or feature is another needle.
        let other_kind = format!(
            "[[needle]]\n{ok}\n[[needle]]\nfeature = \"a.x\"\nkind = \"export\"\nvalue = \"v\"\n"
        );
        assert!(parse(&other_kind).is_ok());
        let other_feature = format!(
            "[[needle]]\n{ok}\n[[needle]]\nfeature = \"a.y\"\nkind = \"string\"\nvalue = \"v\"\n"
        );
        assert!(parse(&other_feature).is_ok());
    }
}
