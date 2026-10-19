//! The component database (PR-4c-1 spec §3): which file names and SONAMEs name which component.
//! Data, embedded and parsed once, as `signatures/capabilities.toml` is.
//!
//! A pattern is an exact name, a library name with an optional version, or a literal prefix and
//! suffix around one variant. There are no regular expressions. A name that two entries match
//! names no component: an ambiguity is never resolved by picking one entry.
//!
//! An entry with `scan = false` (PR-4c-2a) names files that the signature scan never reads: the
//! NVIDIA libraries, identified by name and hash only (ADR-010).

use std::sync::OnceLock;

use serde::Deserialize;
use sigil_model::ComponentKey;

const COMPONENTS: &str = include_str!("../../signatures/components.toml");

/// How a name is matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamePattern {
    /// The name itself: `ollama`.
    Exact(Vec<u8>),
    /// `<base>`, or `<base>.<version>` ([`is_version`]): `libggml.so`, `libggml.so.0.13.1`.
    Library(Vec<u8>),
    /// `<prefix><variant><suffix>`, the variant one or more ASCII letters, digits, or `_`:
    /// `libggml-cpu-haswell.so`.
    Affix { prefix: Vec<u8>, suffix: Vec<u8> },
}

impl NamePattern {
    /// Whether `name`, a file name or a SONAME, matches.
    pub fn matches(&self, name: &[u8]) -> bool {
        match self {
            NamePattern::Exact(exact) => name == exact.as_slice(),
            NamePattern::Library(base) => match name.strip_prefix(base.as_slice()) {
                Some([]) => true,
                Some([b'.', version @ ..]) => is_version(version),
                _ => false,
            },
            NamePattern::Affix { prefix, suffix } => name
                .strip_prefix(prefix.as_slice())
                .and_then(|rest| rest.strip_suffix(suffix.as_slice()))
                .is_some_and(|variant| {
                    !variant.is_empty()
                        && variant
                            .iter()
                            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
                }),
        }
    }
}

/// One or more runs of ASCII digits joined by single dots: `0`, `0.13.1`, `12.8.5.5`.
pub fn is_version(text: &[u8]) -> bool {
    text.split(|b| *b == b'.')
        .all(|part| !part.is_empty() && part.iter().all(u8::is_ascii_digit))
}

/// The parsed database.
#[derive(Debug)]
pub struct ComponentDb {
    /// In file order.
    entries: Vec<(ComponentKey, Vec<NamePattern>)>,
    /// The keys of the entries with `scan = false`, in file order.
    unscanned: Vec<ComponentKey>,
}

impl ComponentDb {
    /// The key of every entry with a pattern that `name` matches, in file order.
    pub fn matching(&self, name: &[u8]) -> Vec<&ComponentKey> {
        self.entries
            .iter()
            .filter(|(_, patterns)| patterns.iter().any(|p| p.matches(name)))
            .map(|(key, _)| key)
            .collect()
    }

    /// The component `name` names: the one entry it matches. `None` when it matches no entry,
    /// or more than one.
    pub fn component(&self, name: &[u8]) -> Option<&ComponentKey> {
        let found = self.matching(name);
        if found.len() == 1 {
            found.first().copied()
        } else {
            None
        }
    }

    /// The keys, in file order.
    pub fn keys(&self) -> Vec<&ComponentKey> {
        self.entries.iter().map(|(key, _)| key).collect()
    }

    /// Whether `key` is the key of an entry: a component SIGIL identifies.
    pub fn knows(&self, key: &ComponentKey) -> bool {
        self.entries.iter().any(|(k, _)| k == key)
    }

    /// The keys of the entries with `scan = false`, in file order (PR-4c-2a).
    pub fn unscanned(&self) -> &[ComponentKey] {
        &self.unscanned
    }

    /// Whether the signature scan reads a file named `name` (PR-4c-2a): unless the component
    /// `name` names ([`ComponentDb::component`]) has `scan = false`.
    pub fn scans(&self, name: &[u8]) -> bool {
        self.component(name)
            .is_none_or(|key| !self.unscanned.contains(key))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDb {
    component: Vec<RawComponent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawComponent {
    key: String,
    names: Vec<RawName>,
    /// `false`: the component's files are never scanned (PR-4c-2a). Omitted: `true`.
    scan: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawName {
    exact: Option<String>,
    library: Option<String>,
    prefix: Option<String>,
    suffix: Option<String>,
}

static DB: OnceLock<Result<ComponentDb, String>> = OnceLock::new();

/// The embedded database, parsed at first use. `Err` only for an invalid embedded file, which
/// `the_embedded_database_parses` rules out; a caller reports it as an internal error.
pub fn components() -> Result<&'static ComponentDb, String> {
    DB.get_or_init(|| parse(COMPONENTS))
        .as_ref()
        .map_err(Clone::clone)
}

/// Parses a database: each key a valid component key, listed once, with at least one name; each
/// name one of the three forms, with literals that are not empty; `scan` a boolean, if given.
fn parse(text: &str) -> Result<ComponentDb, String> {
    let raw: RawDb = toml::from_str(text).map_err(|e| format!("components.toml: {e}"))?;
    let mut entries: Vec<(ComponentKey, Vec<NamePattern>)> = vec![];
    let mut unscanned = vec![];
    for c in raw.component {
        let key = ComponentKey::new(c.key).map_err(|e| format!("components.toml: {e}"))?;
        if entries.iter().any(|(k, _)| *k == key) {
            return Err(format!("components.toml: \"{key}\" listed twice"));
        }
        if c.names.is_empty() {
            return Err(format!("components.toml: {key}: no names"));
        }
        let mut patterns = vec![];
        for n in c.names {
            let pattern = match (n.exact, n.library, n.prefix, n.suffix) {
                (Some(exact), None, None, None) if !exact.is_empty() => {
                    NamePattern::Exact(exact.into_bytes())
                }
                (None, Some(base), None, None) if !base.is_empty() => {
                    NamePattern::Library(base.into_bytes())
                }
                (None, None, Some(prefix), Some(suffix))
                    if !prefix.is_empty() && !suffix.is_empty() =>
                {
                    NamePattern::Affix {
                        prefix: prefix.into_bytes(),
                        suffix: suffix.into_bytes(),
                    }
                }
                _ => {
                    return Err(format!(
                        "components.toml: {key}: a name is {{ exact }}, {{ library }}, or \
                         {{ prefix, suffix }}, each not empty"
                    ))
                }
            };
            patterns.push(pattern);
        }
        if c.scan == Some(false) {
            unscanned.push(key.clone());
        }
        entries.push((key, patterns));
    }
    Ok(ComponentDb { entries, unscanned })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shown(name: &[u8]) -> String {
        String::from_utf8_lossy(name).into_owned()
    }

    #[test]
    fn the_embedded_database_parses() {
        let db = components().unwrap();
        let keys: Vec<&str> = db.keys().iter().map(|k| k.as_str()).collect();
        assert_eq!(
            keys,
            [
                "ollama",
                "ggml",
                "ggml-base",
                "ggml-backend/cpu",
                "ggml-backend/cuda",
                "ggml-backend/vulkan",
                "ggml-backend/rpc",
                "llama.cpp",
                "llama.cpp/common",
                "llama.cpp/mtmd",
                "llama.cpp/server",
                "llama.cpp/quantize",
                "gcc/libgomp",
                "cuda-runtime",
                "cuda/cublas",
                "cuda/cublasLt",
            ]
        );
    }

    #[test]
    fn an_exact_name_matches_only_itself() {
        let p = NamePattern::Exact(b"ollama".to_vec());
        assert!(p.matches(b"ollama"));
        for name in [&b"ollama2"[..], b"Ollama", b"ollam", b"", b"ollama.so"] {
            assert!(!p.matches(name), "{}", shown(name));
        }
    }

    #[test]
    fn a_library_matches_its_base_and_its_dotted_versions() {
        let p = NamePattern::Library(b"libggml.so".to_vec());
        for name in [
            &b"libggml.so"[..],
            b"libggml.so.0",
            b"libggml.so.0.13.1",
            b"libggml.so.12.8.5.5",
        ] {
            assert!(p.matches(name), "{}", shown(name));
        }
        for name in [
            &b"libggml.so."[..],
            b"libggml.so.0.",
            b"libggml.so..1",
            b"libggml.so.1a",
            b"libggml.so.a",
            b"libggml.so0",
            b"libggml-base.so",
            b"libggml-base.so.0",
            b"xlibggml.so",
        ] {
            assert!(!p.matches(name), "{}", shown(name));
        }
    }

    #[test]
    fn an_affix_needs_one_plain_variant() {
        let p = NamePattern::Affix {
            prefix: b"libggml-cpu-".to_vec(),
            suffix: b".so".to_vec(),
        };
        for name in [
            &b"libggml-cpu-x64.so"[..],
            b"libggml-cpu-sapphirerapids.so",
            b"libggml-cpu-sse42.so",
            b"libggml-cpu-a_b.so",
        ] {
            assert!(p.matches(name), "{}", shown(name));
        }
        for name in [
            &b"libggml-cpu-.so"[..],
            b"libggml-cpu-x.y.so",
            b"libggml-cpu-x-y.so",
            b"libggml-cpu-x64.so.1",
            b"libggml-cpu-x64",
            b"libggml-cuda.so",
        ] {
            assert!(!p.matches(name), "{}", shown(name));
        }
    }

    /// A sample name of each pattern of the embedded database names that entry's own key, so an
    /// entry added later that overlaps one already there fails here.
    #[test]
    fn each_embedded_pattern_names_its_own_entry() {
        let db = components().unwrap();
        let mut checked = 0;
        for (key, patterns) in &db.entries {
            for pattern in patterns {
                let samples: Vec<Vec<u8>> = match pattern {
                    NamePattern::Exact(name) => vec![name.clone()],
                    NamePattern::Library(base) => {
                        vec![base.clone(), [base.as_slice(), b".0"].concat()]
                    }
                    NamePattern::Affix { prefix, suffix } => {
                        vec![[prefix.as_slice(), b"x", suffix.as_slice()].concat()]
                    }
                };
                for name in samples {
                    assert_eq!(db.component(&name), Some(key), "{key}: {}", shown(&name));
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 27);
    }

    #[test]
    fn the_database_knows_its_keys_only() {
        let db = components().unwrap();
        let key = |k: &str| ComponentKey::new(k).unwrap();
        for k in [
            "ggml-backend/rpc",
            "llama.cpp/common",
            "ollama",
            "cuda/cublasLt",
        ] {
            assert!(db.knows(&key(k)), "{k}");
        }
        for k in [
            "llama.cpp/comon",
            "ggml-backend/metal",
            "llama.cpp/llama",
            "cuda/cublaslt",
        ] {
            assert!(!db.knows(&key(k)), "{k}");
        }
        assert_eq!(
            db.component(b"libggml-rpc.so"),
            Some(&key("ggml-backend/rpc"))
        );
    }

    #[test]
    fn exactly_the_nvidia_entries_are_not_scanned() {
        let db = components().unwrap();
        let unscanned: Vec<&str> = db.unscanned().iter().map(ComponentKey::as_str).collect();
        assert_eq!(unscanned, ["cuda-runtime", "cuda/cublas", "cuda/cublasLt"]);
        for name in [
            &b"libcudart.so.12.8.90"[..],
            b"libcudart.so",
            b"libcublas.so.13.1.1.3",
            b"libcublasLt.so.12",
        ] {
            assert!(!db.scans(name), "{}", shown(name));
        }
        for name in [
            &b"libggml-cuda.so"[..],
            b"ollama",
            b"libggml-base.so.0.13.1",
            b"libcudart.so.x",
            b"unknown.so",
        ] {
            assert!(db.scans(name), "{}", shown(name));
        }
    }

    #[test]
    fn scan_is_a_boolean_that_defaults_to_true() {
        let db = parse(
            "[[component]]\nkey = \"a\"\nnames = [{ exact = \"a\" }]\nscan = false\n\
             [[component]]\nkey = \"b\"\nnames = [{ exact = \"b\" }]\nscan = true\n\
             [[component]]\nkey = \"c\"\nnames = [{ exact = \"c\" }]\n",
        )
        .unwrap();
        assert!(!db.scans(b"a"));
        assert!(db.scans(b"b"));
        assert!(db.scans(b"c"));
        assert!(db.scans(b"d"), "a name no entry matches is scanned");
        // An ambiguity never excludes a file: a name two `scan = false` entries match names no
        // component, so it is scanned.
        let db = parse(
            "[[component]]\nkey = \"e\"\nnames = [{ library = \"libe.so\" }]\nscan = false\n\
             [[component]]\nkey = \"f\"\nnames = [{ exact = \"libe.so.1\" }]\nscan = false\n",
        )
        .unwrap();
        assert!(!db.scans(b"libe.so"));
        assert!(!db.scans(b"libe.so.2"));
        assert_eq!(db.matching(b"libe.so.1").len(), 2);
        assert!(
            db.scans(b"libe.so.1"),
            "a name two entries match is scanned"
        );
        assert!(
            parse("[[component]]\nkey = \"a\"\nnames = [{ exact = \"a\" }]\nscan = \"no\"\n")
                .unwrap_err()
                .starts_with("components.toml: ")
        );
    }

    #[test]
    fn a_name_two_entries_match_names_no_component() {
        let db = parse(
            "[[component]]\nkey = \"a\"\nnames = [{ library = \"liba.so\" }]\n\
             [[component]]\nkey = \"b\"\nnames = [{ exact = \"liba.so.1\" }]\n",
        )
        .unwrap();
        let keys = |name: &[u8]| -> Vec<String> {
            db.matching(name).iter().map(|k| k.to_string()).collect()
        };
        assert_eq!(keys(b"liba.so.1"), ["a", "b"]);
        assert_eq!(db.component(b"liba.so.1"), None);
        assert_eq!(
            db.component(b"liba.so.2").map(ComponentKey::as_str),
            Some("a")
        );
        assert_eq!(db.component(b"libb.so"), None);
    }

    #[test]
    fn invalid_data_is_an_error_not_a_panic() {
        let one = |names: &str| {
            parse(&format!("[[component]]\nkey = \"a\"\nnames = [{names}]")).map(|_| ())
        };
        let form = Err(
            "components.toml: a: a name is { exact }, { library }, or { prefix, suffix }, each not \
             empty"
                .to_string(),
        );
        assert_eq!(one(""), Err("components.toml: a: no names".to_string()));
        for names in [
            "{ exact = \"\" }",
            "{ library = \"\" }",
            "{ prefix = \"p\" }",
            "{ prefix = \"p\", suffix = \"\" }",
            "{ prefix = \"\", suffix = \"s\" }",
            "{ exact = \"x\", library = \"y\" }",
            "{}",
        ] {
            assert_eq!(one(names), form, "{names}");
        }
        assert!(one("{ regex = \"x\" }")
            .unwrap_err()
            .starts_with("components.toml: "));
        let twice = "[[component]]\nkey = \"a\"\nnames = [{ exact = \"x\" }]\n\
                     [[component]]\nkey = \"a\"\nnames = [{ exact = \"y\" }]\n";
        assert_eq!(
            parse(twice).map(|_| ()),
            Err("components.toml: \"a\" listed twice".to_string())
        );
        assert!(parse("[[component]]\nkey = \" a\"\nnames = [{ exact = \"x\" }]").is_err());
    }
}
