//! The capability table and the noreturn list (PR-5a spec §4.3): data, embedded and parsed once.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;

const CAPABILITIES: &str = include_str!("../../signatures/capabilities.toml");
const NORETURN: &str = include_str!("../../signatures/noreturn.toml");

/// One capability import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    /// e.g. `posix.network`.
    pub feature: String,
    /// The SysV argument registers a call can read.
    pub arity: u8,
}

/// The parsed data.
#[derive(Debug)]
pub struct Signatures {
    capabilities: BTreeMap<Vec<u8>, Capability>,
    noreturn_prefixes: Vec<Vec<u8>>,
    noreturn_names: Vec<Vec<u8>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCapabilities {
    capability: Vec<RawCapability>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCapability {
    feature: String,
    symbols: Vec<RawSymbol>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSymbol {
    name: String,
    arity: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNoreturn {
    prefixes: Vec<String>,
    names: Vec<String>,
}

static SIGNATURES: OnceLock<Result<Signatures, String>> = OnceLock::new();

/// The embedded signatures, parsed at first use. `Err` only for invalid embedded files, which
/// `the_embedded_signatures_parse` rules out; a caller reports it as an internal error.
pub fn signatures() -> Result<&'static Signatures, String> {
    SIGNATURES
        .get_or_init(|| parse(CAPABILITIES, NORETURN))
        .as_ref()
        .map_err(Clone::clone)
}

fn parse(capabilities: &str, noreturn: &str) -> Result<Signatures, String> {
    let raw: RawCapabilities =
        toml::from_str(capabilities).map_err(|e| format!("capabilities.toml: {e}"))?;
    let mut table = BTreeMap::new();
    for c in raw.capability {
        sigil_model::FeatureKey::new(c.feature.as_str())
            .map_err(|e| format!("capabilities.toml: {e}"))?;
        for s in c.symbols {
            if s.arity > 6 || s.name.is_empty() {
                return Err(format!(
                    "capabilities.toml: {:?}: arity {}",
                    s.name, s.arity
                ));
            }
            let entry = Capability {
                feature: c.feature.clone(),
                arity: s.arity,
            };
            if table.insert(s.name.clone().into_bytes(), entry).is_some() {
                return Err(format!("capabilities.toml: {} listed twice", s.name));
            }
        }
    }
    let raw: RawNoreturn = toml::from_str(noreturn).map_err(|e| format!("noreturn.toml: {e}"))?;
    // An empty prefix or name would make every call noreturn, and hide the code after it.
    if raw.prefixes.iter().chain(&raw.names).any(String::is_empty) {
        return Err("noreturn.toml: an empty prefix or name".to_string());
    }
    Ok(Signatures {
        capabilities: table,
        noreturn_prefixes: raw.prefixes.into_iter().map(String::into_bytes).collect(),
        noreturn_names: raw.names.into_iter().map(String::into_bytes).collect(),
    })
}

impl Signatures {
    /// The capability of an import named exactly `name`.
    pub fn capability(&self, name: &[u8]) -> Option<&Capability> {
        self.capabilities.get(name)
    }

    /// Whether a call to the symbol `name` never returns. A version suffix (`@…`) is ignored.
    pub fn is_noreturn(&self, name: &[u8]) -> bool {
        let base = name.split(|b| *b == b'@').next().unwrap_or(name);
        self.noreturn_names.iter().any(|n| n.as_slice() == base)
            || self.noreturn_prefixes.iter().any(|p| base.starts_with(p))
    }

    /// The longest capability name: names are read only this far, plus one byte.
    pub fn longest(&self) -> usize {
        self.capabilities.keys().map(Vec::len).max().unwrap_or(0)
    }

    /// How many names the table has.
    pub fn count(&self) -> usize {
        self.capabilities.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_signatures_parse() {
        let s = signatures().unwrap();
        assert_eq!(s.capability(b"connect").unwrap().feature, "posix.network");
        assert_eq!(s.capability(b"connect").unwrap().arity, 3);
        assert_eq!(
            s.capability(b"dlsym").unwrap().feature,
            "posix.dynamic_loading"
        );
        assert_eq!(s.capability(b"ptrace").unwrap().feature, "posix.anti_debug");
        assert!(
            s.capability(b"connect@GLIBC_2.2.5").is_none(),
            "exact names only"
        );
        assert!(s.capability(b"Connect").is_none());
        assert_eq!(s.longest(), "getaddrinfo".len());
        // v0.1's 28 names (7 + 5 + 6 + 4 + 2 + 3 + 1), unchanged.
        assert_eq!(s.count(), 28);
    }

    #[test]
    fn noreturn_names_prefixes_and_versions() {
        let s = signatures().unwrap();
        for n in [
            "abort",
            "exit@GLIBC_2.2.5",
            "_ZSt20__throw_length_errorPKc",
            "__cxa_bad_cast",
            "__stack_chk_fail",
        ] {
            assert!(s.is_noreturn(n.as_bytes()), "{n}");
        }
        for n in ["abortx", "exit_group", "connect", "_ZSt16__throw", "printf"] {
            assert!(!s.is_noreturn(n.as_bytes()), "{n}");
        }
    }

    #[test]
    fn invalid_data_is_an_error_not_a_panic() {
        assert!(parse(
            "[[capability]]\nfeature = \"posix.network\"\nsymbols = [{ name = \"connect\", arity = 7 }]",
            NORETURN
        )
        .is_err());
        assert!(parse(
            "[[capability]]\nfeature = \"posix.network\"\nsymbols = [{ name = \"a\", arity = 1 }, { name = \"a\", arity = 1 }]",
            NORETURN
        )
        .is_err());
        assert!(parse(CAPABILITIES, "prefixes = []").is_err());
        assert!(parse(CAPABILITIES, "prefixes = [\"\"]\nnames = []").is_err());
    }
}
