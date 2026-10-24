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
    /// Not empty, at most [`MAX_NEEDLE`] bytes; for `go-function`, no NUL.
    pub value: Vec<u8>,
    /// Where the value comes from (PR-4c-3a): not blank. Documentation only, never in a session.
    pub source: String,
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
    source: String,
}

static DB: OnceLock<Result<Needles, String>> = OnceLock::new();

/// The embedded database, parsed at first use. `Err` only for an invalid embedded file, which
/// `the_embedded_database_parses` rules out; a caller reports it as an internal error.
pub fn needles() -> Result<&'static Needles, String> {
    DB.get_or_init(|| parse(NEEDLES))
        .as_ref()
        .map_err(Clone::clone)
}

/// Parses a database: each needle a valid feature key, a known kind, a value that is not empty
/// and at most [`MAX_NEEDLE`] bytes (for `go-function`, without a NUL: the scan adds the name's
/// bounds), and a source that is not blank (PR-4c-3a); no (feature, kind, value) listed twice.
/// Public for the tests of the kinds the embedded database has no needle of.
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
        if n.kind == NeedleKind::GoFunction && value.contains(&0) {
            return Err(format!(
                "needles.toml: {feature}: a go-function value has no NUL"
            ));
        }
        if n.source.trim().is_empty() {
            return Err(format!(
                "needles.toml: {feature}: a source is required and not blank"
            ));
        }
        let needle = Needle {
            feature,
            kind: n.kind,
            value,
            source: n.source,
        };
        let listed = |x: &Needle| {
            (&x.feature, x.kind, &x.value) == (&needle.feature, needle.kind, &needle.value)
        };
        if needles.iter().any(listed) {
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
        let listed: Vec<(&str, NeedleKind, &str)> = db
            .needles
            .iter()
            .map(|n| {
                (
                    n.feature.as_str(),
                    n.kind,
                    std::str::from_utf8(&n.value).unwrap(),
                )
            })
            .collect();
        let go = |feature, value| (feature, NeedleKind::GoFunction, value);
        assert_eq!(
            listed,
            [
                ("rpc.code_present", NeedleKind::Export, "ggml_backend_rpc_"),
                go(
                    "ollama.llama_server_launch",
                    "github.com/ollama/ollama/llm.SetupLlamaServerCommandEnv"
                ),
                go(
                    "ollama.device_discovery",
                    "github.com/ollama/ollama/discover.discoverNativeDevices"
                ),
                // PR-4c-3a: the Go standard library's capabilities.
                go("go.process_spawn", "os/exec.(*Cmd).Start"),
                go("go.process_spawn", "os.StartProcess"),
                go("go.process_spawn", "syscall.StartProcess"),
                go("go.process_spawn", "syscall.ForkExec"),
                go("go.process_spawn", "syscall.Exec"),
                go("go.network", "net.(*Dialer).DialContext"),
                go("go.network", "net.(*ListenConfig).Listen"),
                go("go.network", "net.(*ListenConfig).ListenPacket"),
                go("go.file_read", "os.Open"),
                go("go.file_read", "os.ReadFile"),
                go("go.file_write", "os.Create"),
                go("go.file_write", "os.WriteFile"),
                go("go.file_write", "os.Remove"),
                go("go.file_write", "os.RemoveAll"),
                go("go.file_write", "os.Rename"),
                go("go.dynamic_loading", "plugin.Open"),
            ]
        );
        assert!(
            db.of(NeedleKind::String).is_empty(),
            "no string needle ships"
        );
        // The three older needles' sources, exactly.
        let sources: Vec<&str> = db.needles[..3].iter().map(|n| n.source.as_str()).collect();
        assert_eq!(
            sources,
            [
                "llama.cpp b9509 ggml/include/ggml-rpc.h: the RPC backend's functions, ggml_backend_rpc_*",
                "Ollama v0.30.6 llm/llama_server.go: func SetupLlamaServerCommandEnv (plan \u{a7}0.4)",
                "Ollama v0.30.6 package discover: func discoverNativeDevices (plan \u{a7}0.4)",
            ]
        );
        // Each go.* needle names the Go 1.25 source file and the function's declaration.
        for n in db
            .needles
            .iter()
            .filter(|n| n.feature.as_str().starts_with("go."))
        {
            let name = std::str::from_utf8(&n.value).unwrap();
            let base = name.rfind('/').map_or(0, |i| i + 1);
            let dot = base + name[base..].find('.').unwrap();
            let (package, member) = (&name[..dot], &name[dot + 1..]);
            let declaration = match member.strip_prefix("(*").and_then(|m| m.split_once(").")) {
                Some((receiver, method)) => format!(" *{receiver}) {method}("),
                None => format!(": func {member}("),
            };
            let file = n
                .source
                .strip_prefix(&format!("Go 1.25 src/{package}/"))
                .unwrap_or_else(|| panic!("{name}: {}", n.source));
            assert!(
                !file.split(':').next().unwrap().contains('/'),
                "{name}: {}",
                n.source
            );
            assert!(n.source.contains(&declaration), "{name}: {}", n.source);
        }
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
            "[[needle]]\nfeature = \"a.x\"\nkind = \"string\"\nvalue = \"abcd\"\nsource = \"t\"\n\
             [[needle]]\nfeature = \"a.y\"\nkind = \"string\"\nvalue = \"abcdefghi\"\n\
             source = \"t\"\n\
             [[needle]]\nfeature = \"a.z\"\nkind = \"go-function\"\n\
             value = \"0123456789abcdefghij\"\nsource = \"t\"\n",
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
        let ok = "feature = \"a.x\"\nkind = \"string\"\nvalue = \"v\"\nsource = \"s\"";
        assert!(one(ok).is_ok());
        let size = Err(format!(
            "needles.toml: a.x: a value is 1 to {MAX_NEEDLE} bytes"
        ));
        assert_eq!(
            one("feature = \"a.x\"\nkind = \"string\"\nvalue = \"\"\nsource = \"s\""),
            size
        );
        let long = "v".repeat(MAX_NEEDLE + 1);
        assert_eq!(
            one(&format!(
                "feature = \"a.x\"\nkind = \"string\"\nvalue = \"{long}\"\nsource = \"s\""
            )),
            size
        );
        let longest = "v".repeat(MAX_NEEDLE);
        assert!(one(&format!(
            "feature = \"a.x\"\nkind = \"string\"\nvalue = \"{longest}\"\nsource = \"s\""
        ))
        .is_ok());
        for bad in [
            // An unknown kind, an unknown field, a missing field, an invalid feature key.
            "feature = \"a.x\"\nkind = \"regex\"\nvalue = \"v\"\nsource = \"s\"",
            "feature = \"a.x\"\nkind = \"string\"\nvalue = \"v\"\nsource = \"s\"\n\
             section = \".data\"",
            "feature = \"a.x\"\nkind = \"string\"\nsource = \"s\"",
            "feature = \" a\"\nkind = \"string\"\nvalue = \"v\"\nsource = \"s\"",
            // PR-4c-3a: no source.
            "feature = \"a.x\"\nkind = \"string\"\nvalue = \"v\"",
        ] {
            assert!(one(bad).unwrap_err().starts_with("needles.toml: "), "{bad}");
        }
        // A blank source.
        for blank in ["", " \t"] {
            assert_eq!(
                one(&format!(
                    "feature = \"a.x\"\nkind = \"string\"\nvalue = \"v\"\nsource = \"{blank}\""
                )),
                Err("needles.toml: a.x: a source is required and not blank".to_string())
            );
        }
        // A go-function value with a NUL: the scan puts the name between NULs itself. Another
        // kind may have one.
        assert_eq!(
            one(
                "feature = \"a.z\"\nkind = \"go-function\"\nvalue = \"p.f\\u0000\"\nsource = \"s\""
            ),
            Err("needles.toml: a.z: a go-function value has no NUL".to_string())
        );
        assert!(
            one("feature = \"a.x\"\nkind = \"string\"\nvalue = \"v\\u0000\"\nsource = \"s\"")
                .is_ok()
        );
        // An unknown top-level key.
        assert!(parse(&format!("version = 1\n[[needle]]\n{ok}\n"))
            .unwrap_err()
            .starts_with("needles.toml: "));
        let twice = format!("[[needle]]\n{ok}\n[[needle]]\n{ok}\n");
        assert_eq!(
            parse(&twice),
            Err("needles.toml: a.x: the string needle \"v\" listed twice".to_string())
        );
        // Twice with another source is still twice.
        let other_source = format!(
            "[[needle]]\n{ok}\n[[needle]]\nfeature = \"a.x\"\nkind = \"string\"\nvalue = \"v\"\n\
             source = \"t\"\n"
        );
        assert_eq!(
            parse(&other_source),
            Err("needles.toml: a.x: the string needle \"v\" listed twice".to_string())
        );
        let go = "feature = \"a.z\"\nkind = \"go-function\"\nvalue = \"p.f\"\nsource = \"s\"";
        assert_eq!(
            parse(&format!("[[needle]]\n{go}\n[[needle]]\n{go}\n")),
            Err("needles.toml: a.z: the go-function needle \"p.f\" listed twice".to_string())
        );
        // The same value under another kind or feature is another needle.
        let other_kind = format!(
            "[[needle]]\n{ok}\n[[needle]]\nfeature = \"a.x\"\nkind = \"export\"\nvalue = \"v\"\n\
             source = \"s\"\n"
        );
        assert!(parse(&other_kind).is_ok());
        let other_feature = format!(
            "[[needle]]\n{ok}\n[[needle]]\nfeature = \"a.y\"\nkind = \"string\"\nvalue = \"v\"\n\
             source = \"s\"\n"
        );
        assert!(parse(&other_feature).is_ok());
    }
}
