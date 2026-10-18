//! The capability table and the noreturn list (PR-5a spec §4.3): data, embedded and parsed once.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;
use sigil_model::FeatureKey;

const CAPABILITIES: &str = include_str!("../../signatures/capabilities.toml");
const NORETURN: &str = include_str!("../../signatures/noreturn.toml");

/// One capability import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    /// e.g. `posix.network`.
    pub feature: FeatureKey,
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
        let feature = FeatureKey::new(c.feature).map_err(|e| format!("capabilities.toml: {e}"))?;
        for s in c.symbols {
            if s.name.is_empty() {
                return Err(format!("capabilities.toml: {feature}: an empty name"));
            }
            if s.arity > 6 {
                return Err(format!(
                    "capabilities.toml: {:?}: arity {} is over 6",
                    s.name, s.arity
                ));
            }
            let entry = Capability {
                feature: feature.clone(),
                arity: s.arity,
            };
            if table.insert(s.name.clone().into_bytes(), entry).is_some() {
                return Err(format!("capabilities.toml: {:?} listed twice", s.name));
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

    /// Spec §4.3: v0.1's names, by feature, with their arities.
    const TABLE: [(&str, &str, u8); 28] = [
        ("connect", "posix.network", 3),
        ("getaddrinfo", "posix.network", 4),
        ("send", "posix.network", 4),
        ("sendto", "posix.network", 6),
        ("recv", "posix.network", 4),
        ("recvfrom", "posix.network", 6),
        ("socket", "posix.network", 3),
        ("open", "posix.file_read", 3),
        ("openat", "posix.file_read", 4),
        ("fopen", "posix.file_read", 2),
        ("read", "posix.file_read", 3),
        ("pread", "posix.file_read", 4),
        ("write", "posix.file_write", 3),
        ("pwrite", "posix.file_write", 4),
        ("fwrite", "posix.file_write", 4),
        ("creat", "posix.file_write", 2),
        ("rename", "posix.file_write", 2),
        ("unlink", "posix.file_write", 1),
        ("execve", "posix.process_spawn", 3),
        ("fork", "posix.process_spawn", 0),
        ("posix_spawn", "posix.process_spawn", 6),
        ("system", "posix.process_spawn", 1),
        ("dlopen", "posix.dynamic_loading", 2),
        ("dlsym", "posix.dynamic_loading", 2),
        ("getenv", "posix.environment_access", 1),
        ("setenv", "posix.environment_access", 3),
        ("putenv", "posix.environment_access", 1),
        ("ptrace", "posix.anti_debug", 4),
    ];

    #[test]
    fn the_embedded_signatures_parse() {
        let s = signatures().unwrap();
        for (name, feature, arity) in TABLE {
            let cap = s.capability(name.as_bytes());
            assert_eq!(
                cap,
                Some(&Capability {
                    feature: FeatureKey::new(feature).unwrap(),
                    arity,
                }),
                "{name}"
            );
        }
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
        let one = |symbols: &str| {
            parse(
                &format!("[[capability]]\nfeature = \"posix.network\"\nsymbols = [{symbols}]"),
                NORETURN,
            )
            .map(|_| ())
        };
        assert_eq!(
            one("{ name = \"connect\", arity = 7 }"),
            Err("capabilities.toml: \"connect\": arity 7 is over 6".to_string())
        );
        assert_eq!(
            one("{ name = \"\", arity = 1 }"),
            Err("capabilities.toml: posix.network: an empty name".to_string())
        );
        assert_eq!(
            one("{ name = \"a\", arity = 1 }, { name = \"a\", arity = 1 }"),
            Err("capabilities.toml: \"a\" listed twice".to_string())
        );
        assert!(parse(CAPABILITIES, "prefixes = []").is_err());
        assert!(parse(CAPABILITIES, "prefixes = [\"\"]\nnames = []").is_err());
    }
}
