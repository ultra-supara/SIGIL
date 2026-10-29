//! The capability table and the noreturn list (PR-5a spec §4.3): data, embedded and parsed once.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use sigil_model::{
    FeatureKey, KnowledgeKind, KnowledgeRef, Sha256Hex, CAPABILITY_TABLE_ID, LIBCXX, LIBSYSTEM,
};

const CAPABILITIES: &str = include_str!("../../signatures/capabilities.toml");
const NORETURN: &str = include_str!("../../signatures/noreturn.toml");

/// One capability import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    /// e.g. `posix.network`.
    pub feature: FeatureKey,
    /// The SysV argument registers a call can read.
    pub arity: u8,
    /// Where the name and its meaning come from: a standard, or the library that exports it
    /// (PR-4c-3c). Not blank, and not written to sessions.
    pub source: String,
    /// The dylib a Mach-O import of this name must be bound to for a hint (#105): [`LIBSYSTEM`]
    /// or [`LIBCXX`]. An import found by flat lookup, and an object file's, are looked up for
    /// every name; an ELF import, by its name alone.
    pub macho_dylib: &'static str,
}

/// The parsed data.
#[derive(Debug)]
pub struct Signatures {
    capabilities: BTreeMap<Vec<u8>, Capability>,
    /// The capability table's knowledge entry (#51).
    table: KnowledgeRef,
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
    macho_dylib: String,
    symbols: Vec<RawSymbol>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSymbol {
    name: String,
    arity: u8,
    source: Option<String>,
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
        let macho_dylib = match c.macho_dylib.as_str() {
            LIBSYSTEM => LIBSYSTEM,
            LIBCXX => LIBCXX,
            other => {
                return Err(format!(
                    "capabilities.toml: {feature}: macho_dylib {other:?} is neither libSystem nor libc++"
                ))
            }
        };
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
            let source = match s.source {
                None => return Err(format!("capabilities.toml: {:?}: no source", s.name)),
                Some(t) if t.trim().is_empty() => {
                    return Err(format!("capabilities.toml: {:?}: a blank source", s.name))
                }
                Some(t) => t,
            };
            let entry = Capability {
                feature: feature.clone(),
                arity: s.arity,
                source,
                macho_dylib,
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
    let sha256 = Sha256Hex::new(format!("{:x}", Sha256::digest(capabilities.as_bytes())))
        .map_err(|e| format!("capabilities.toml: {e}"))?;
    Ok(Signatures {
        capabilities: table,
        table: KnowledgeRef {
            kind: KnowledgeKind::SignatureDb,
            id: CAPABILITY_TABLE_ID.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            sha256,
        },
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

    /// The table's feature keys, sorted, each once: what a policy can deny (#51).
    pub fn features(&self) -> Vec<&FeatureKey> {
        let keys: std::collections::BTreeSet<&FeatureKey> =
            self.capabilities.values().map(|c| &c.feature).collect();
        keys.into_iter().collect()
    }

    /// The capability table's knowledge entry (#51): the SHA-256 of the embedded
    /// `capabilities.toml`, under the ID `capabilities`, with sigil-engine's version (which only
    /// says which build wrote it: evaluation compares the SHA-256). A session with binary facts
    /// records it, since its hints and call sites were made with this table, and a capability
    /// denial is judged only on a session that records this build's.
    pub fn knowledge(&self) -> &KnowledgeRef {
        &self.table
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_model::LookedUp;

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

    /// The PR-4c-3c spec's Appendix A: libstdc++'s names, by feature, with their arities.
    const CXX: [(&str, &str, u8); 88] = [
        ("_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC1EPKcSt13_Ios_Openmode", "cxx.file_read", 3),
        ("_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC1ERKNSt7__cxx1112basic_stringIcS1_SaIcEEESt13_Ios_Openmode", "cxx.file_read", 3),
        ("_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC1ERKSsSt13_Ios_Openmode", "cxx.file_read", 3),
        ("_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC2EPKcSt13_Ios_Openmode", "cxx.file_read", 4),
        ("_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC2ERKNSt7__cxx1112basic_stringIcS1_SaIcEEESt13_Ios_Openmode", "cxx.file_read", 4),
        ("_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC2ERKSsSt13_Ios_Openmode", "cxx.file_read", 4),
        ("_ZNSt14basic_ifstreamIcSt11char_traitsIcEE4openEPKcSt13_Ios_Openmode", "cxx.file_read", 3),
        ("_ZNSt14basic_ifstreamIcSt11char_traitsIcEE4openERKNSt7__cxx1112basic_stringIcS1_SaIcEEESt13_Ios_Openmode", "cxx.file_read", 3),
        ("_ZNSt14basic_ifstreamIcSt11char_traitsIcEE4openERKSsSt13_Ios_Openmode", "cxx.file_read", 3),
        ("_ZNSt14basic_ifstreamIwSt11char_traitsIwEEC1EPKcSt13_Ios_Openmode", "cxx.file_read", 3),
        ("_ZNSt14basic_ifstreamIwSt11char_traitsIwEEC1ERKNSt7__cxx1112basic_stringIcS0_IcESaIcEEESt13_Ios_Openmode", "cxx.file_read", 3),
        ("_ZNSt14basic_ifstreamIwSt11char_traitsIwEEC1ERKSsSt13_Ios_Openmode", "cxx.file_read", 3),
        ("_ZNSt14basic_ifstreamIwSt11char_traitsIwEEC2EPKcSt13_Ios_Openmode", "cxx.file_read", 4),
        ("_ZNSt14basic_ifstreamIwSt11char_traitsIwEEC2ERKNSt7__cxx1112basic_stringIcS0_IcESaIcEEESt13_Ios_Openmode", "cxx.file_read", 4),
        ("_ZNSt14basic_ifstreamIwSt11char_traitsIwEEC2ERKSsSt13_Ios_Openmode", "cxx.file_read", 4),
        ("_ZNSt14basic_ifstreamIwSt11char_traitsIwEE4openEPKcSt13_Ios_Openmode", "cxx.file_read", 3),
        ("_ZNSt14basic_ifstreamIwSt11char_traitsIwEE4openERKNSt7__cxx1112basic_stringIcS0_IcESaIcEEESt13_Ios_Openmode", "cxx.file_read", 3),
        ("_ZNSt14basic_ifstreamIwSt11char_traitsIwEE4openERKSsSt13_Ios_Openmode", "cxx.file_read", 3),
        ("_ZNSt10filesystem6removeERKNS_7__cxx114pathE", "cxx.file_write", 1),
        ("_ZNSt10filesystem6removeERKNS_7__cxx114pathERSt10error_code", "cxx.file_write", 2),
        ("_ZNSt10filesystem6removeERKNS_4pathE", "cxx.file_write", 1),
        ("_ZNSt10filesystem6removeERKNS_4pathERSt10error_code", "cxx.file_write", 2),
        ("_ZNSt10filesystem10remove_allERKNS_7__cxx114pathE", "cxx.file_write", 1),
        ("_ZNSt10filesystem10remove_allERKNS_7__cxx114pathERSt10error_code", "cxx.file_write", 2),
        ("_ZNSt10filesystem10remove_allERKNS_4pathE", "cxx.file_write", 1),
        ("_ZNSt10filesystem10remove_allERKNS_4pathERSt10error_code", "cxx.file_write", 2),
        ("_ZNSt10filesystem6renameERKNS_7__cxx114pathES3_", "cxx.file_write", 2),
        ("_ZNSt10filesystem6renameERKNS_7__cxx114pathES3_RSt10error_code", "cxx.file_write", 3),
        ("_ZNSt10filesystem6renameERKNS_4pathES2_", "cxx.file_write", 2),
        ("_ZNSt10filesystem6renameERKNS_4pathES2_RSt10error_code", "cxx.file_write", 3),
        ("_ZNSt10filesystem16create_directoryERKNS_7__cxx114pathE", "cxx.file_write", 1),
        ("_ZNSt10filesystem16create_directoryERKNS_7__cxx114pathERSt10error_code", "cxx.file_write", 2),
        ("_ZNSt10filesystem16create_directoryERKNS_7__cxx114pathES3_", "cxx.file_write", 2),
        ("_ZNSt10filesystem16create_directoryERKNS_7__cxx114pathES3_RSt10error_code", "cxx.file_write", 3),
        ("_ZNSt10filesystem16create_directoryERKNS_4pathE", "cxx.file_write", 1),
        ("_ZNSt10filesystem16create_directoryERKNS_4pathERSt10error_code", "cxx.file_write", 2),
        ("_ZNSt10filesystem16create_directoryERKNS_4pathES2_", "cxx.file_write", 2),
        ("_ZNSt10filesystem16create_directoryERKNS_4pathES2_RSt10error_code", "cxx.file_write", 3),
        ("_ZNSt10filesystem18create_directoriesERKNS_7__cxx114pathE", "cxx.file_write", 1),
        ("_ZNSt10filesystem18create_directoriesERKNS_7__cxx114pathERSt10error_code", "cxx.file_write", 2),
        ("_ZNSt10filesystem18create_directoriesERKNS_4pathE", "cxx.file_write", 1),
        ("_ZNSt10filesystem18create_directoriesERKNS_4pathERSt10error_code", "cxx.file_write", 2),
        ("_ZNSt10filesystem14create_symlinkERKNS_7__cxx114pathES3_", "cxx.file_write", 2),
        ("_ZNSt10filesystem14create_symlinkERKNS_7__cxx114pathES3_RSt10error_code", "cxx.file_write", 3),
        ("_ZNSt10filesystem14create_symlinkERKNS_4pathES2_", "cxx.file_write", 2),
        ("_ZNSt10filesystem14create_symlinkERKNS_4pathES2_RSt10error_code", "cxx.file_write", 3),
        ("_ZNSt10filesystem16create_hard_linkERKNS_7__cxx114pathES3_", "cxx.file_write", 2),
        ("_ZNSt10filesystem16create_hard_linkERKNS_7__cxx114pathES3_RSt10error_code", "cxx.file_write", 3),
        ("_ZNSt10filesystem16create_hard_linkERKNS_4pathES2_", "cxx.file_write", 2),
        ("_ZNSt10filesystem16create_hard_linkERKNS_4pathES2_RSt10error_code", "cxx.file_write", 3),
        ("_ZNSt10filesystem24create_directory_symlinkERKNS_7__cxx114pathES3_", "cxx.file_write", 2),
        ("_ZNSt10filesystem24create_directory_symlinkERKNS_7__cxx114pathES3_RSt10error_code", "cxx.file_write", 3),
        ("_ZNSt10filesystem24create_directory_symlinkERKNS_4pathES2_", "cxx.file_write", 2),
        ("_ZNSt10filesystem24create_directory_symlinkERKNS_4pathES2_RSt10error_code", "cxx.file_write", 3),
        ("_ZNSt10filesystem4copyERKNS_7__cxx114pathES3_NS_12copy_optionsE", "cxx.file_write", 3),
        ("_ZNSt10filesystem4copyERKNS_7__cxx114pathES3_NS_12copy_optionsERSt10error_code", "cxx.file_write", 4),
        ("_ZNSt10filesystem4copyERKNS_4pathES2_NS_12copy_optionsE", "cxx.file_write", 3),
        ("_ZNSt10filesystem4copyERKNS_4pathES2_NS_12copy_optionsERSt10error_code", "cxx.file_write", 4),
        ("_ZNSt10filesystem9copy_fileERKNS_7__cxx114pathES3_NS_12copy_optionsE", "cxx.file_write", 3),
        ("_ZNSt10filesystem9copy_fileERKNS_7__cxx114pathES3_NS_12copy_optionsERSt10error_code", "cxx.file_write", 4),
        ("_ZNSt10filesystem9copy_fileERKNS_4pathES2_NS_12copy_optionsE", "cxx.file_write", 3),
        ("_ZNSt10filesystem9copy_fileERKNS_4pathES2_NS_12copy_optionsERSt10error_code", "cxx.file_write", 4),
        ("_ZNSt10filesystem12copy_symlinkERKNS_7__cxx114pathES3_", "cxx.file_write", 2),
        ("_ZNSt10filesystem12copy_symlinkERKNS_7__cxx114pathES3_RSt10error_code", "cxx.file_write", 3),
        ("_ZNSt10filesystem12copy_symlinkERKNS_4pathES2_", "cxx.file_write", 2),
        ("_ZNSt10filesystem12copy_symlinkERKNS_4pathES2_RSt10error_code", "cxx.file_write", 3),
        ("_ZNSt10filesystem11resize_fileERKNS_7__cxx114pathEm", "cxx.file_write", 2),
        ("_ZNSt10filesystem11resize_fileERKNS_7__cxx114pathEmRSt10error_code", "cxx.file_write", 3),
        ("_ZNSt10filesystem11resize_fileERKNS_4pathEm", "cxx.file_write", 2),
        ("_ZNSt10filesystem11resize_fileERKNS_4pathEmRSt10error_code", "cxx.file_write", 3),
        ("_ZNSt14basic_ofstreamIcSt11char_traitsIcEEC1EPKcSt13_Ios_Openmode", "cxx.file_write", 3),
        ("_ZNSt14basic_ofstreamIcSt11char_traitsIcEEC1ERKNSt7__cxx1112basic_stringIcS1_SaIcEEESt13_Ios_Openmode", "cxx.file_write", 3),
        ("_ZNSt14basic_ofstreamIcSt11char_traitsIcEEC1ERKSsSt13_Ios_Openmode", "cxx.file_write", 3),
        ("_ZNSt14basic_ofstreamIcSt11char_traitsIcEEC2EPKcSt13_Ios_Openmode", "cxx.file_write", 4),
        ("_ZNSt14basic_ofstreamIcSt11char_traitsIcEEC2ERKNSt7__cxx1112basic_stringIcS1_SaIcEEESt13_Ios_Openmode", "cxx.file_write", 4),
        ("_ZNSt14basic_ofstreamIcSt11char_traitsIcEEC2ERKSsSt13_Ios_Openmode", "cxx.file_write", 4),
        ("_ZNSt14basic_ofstreamIcSt11char_traitsIcEE4openEPKcSt13_Ios_Openmode", "cxx.file_write", 3),
        ("_ZNSt14basic_ofstreamIcSt11char_traitsIcEE4openERKNSt7__cxx1112basic_stringIcS1_SaIcEEESt13_Ios_Openmode", "cxx.file_write", 3),
        ("_ZNSt14basic_ofstreamIcSt11char_traitsIcEE4openERKSsSt13_Ios_Openmode", "cxx.file_write", 3),
        ("_ZNSt14basic_ofstreamIwSt11char_traitsIwEEC1EPKcSt13_Ios_Openmode", "cxx.file_write", 3),
        ("_ZNSt14basic_ofstreamIwSt11char_traitsIwEEC1ERKNSt7__cxx1112basic_stringIcS0_IcESaIcEEESt13_Ios_Openmode", "cxx.file_write", 3),
        ("_ZNSt14basic_ofstreamIwSt11char_traitsIwEEC1ERKSsSt13_Ios_Openmode", "cxx.file_write", 3),
        ("_ZNSt14basic_ofstreamIwSt11char_traitsIwEEC2EPKcSt13_Ios_Openmode", "cxx.file_write", 4),
        ("_ZNSt14basic_ofstreamIwSt11char_traitsIwEEC2ERKNSt7__cxx1112basic_stringIcS0_IcESaIcEEESt13_Ios_Openmode", "cxx.file_write", 4),
        ("_ZNSt14basic_ofstreamIwSt11char_traitsIwEEC2ERKSsSt13_Ios_Openmode", "cxx.file_write", 4),
        ("_ZNSt14basic_ofstreamIwSt11char_traitsIwEE4openEPKcSt13_Ios_Openmode", "cxx.file_write", 3),
        ("_ZNSt14basic_ofstreamIwSt11char_traitsIwEE4openERKNSt7__cxx1112basic_stringIcS0_IcESaIcEEESt13_Ios_Openmode", "cxx.file_write", 3),
        ("_ZNSt14basic_ofstreamIwSt11char_traitsIwEE4openERKSsSt13_Ios_Openmode", "cxx.file_write", 3),
    ];

    /// The #105 spec's Appendix A: libc++ 22.1.8's names, by feature, with their arities.
    const LIBCXX_NAMES: [(&str, &str, u8); 17] = [
        ("_ZNSt3__114basic_ifstreamIcNS_11char_traitsIcEEE4openEPKcj", "cxx.file_read", 3),
        ("_ZNSt3__114basic_ifstreamIcNS_11char_traitsIcEEE4openERKNS_12basic_stringIcS2_NS_9allocatorIcEEEEj", "cxx.file_read", 3),
        ("_ZNSt3__14__fs10filesystem8__removeERKNS1_4pathEPNS_10error_codeE", "cxx.file_write", 2),
        ("_ZNSt3__14__fs10filesystem12__remove_allERKNS1_4pathEPNS_10error_codeE", "cxx.file_write", 2),
        ("_ZNSt3__14__fs10filesystem8__renameERKNS1_4pathES4_PNS_10error_codeE", "cxx.file_write", 3),
        ("_ZNSt3__14__fs10filesystem18__create_directoryERKNS1_4pathEPNS_10error_codeE", "cxx.file_write", 2),
        ("_ZNSt3__14__fs10filesystem18__create_directoryERKNS1_4pathES4_PNS_10error_codeE", "cxx.file_write", 3),
        ("_ZNSt3__14__fs10filesystem20__create_directoriesERKNS1_4pathEPNS_10error_codeE", "cxx.file_write", 2),
        ("_ZNSt3__14__fs10filesystem16__create_symlinkERKNS1_4pathES4_PNS_10error_codeE", "cxx.file_write", 3),
        ("_ZNSt3__14__fs10filesystem18__create_hard_linkERKNS1_4pathES4_PNS_10error_codeE", "cxx.file_write", 3),
        ("_ZNSt3__14__fs10filesystem26__create_directory_symlinkERKNS1_4pathES4_PNS_10error_codeE", "cxx.file_write", 3),
        ("_ZNSt3__14__fs10filesystem6__copyERKNS1_4pathES4_NS1_12copy_optionsEPNS_10error_codeE", "cxx.file_write", 4),
        ("_ZNSt3__14__fs10filesystem11__copy_fileERKNS1_4pathES4_NS1_12copy_optionsEPNS_10error_codeE", "cxx.file_write", 4),
        ("_ZNSt3__14__fs10filesystem14__copy_symlinkERKNS1_4pathES4_PNS_10error_codeE", "cxx.file_write", 3),
        ("_ZNSt3__14__fs10filesystem13__resize_fileERKNS1_4pathEmPNS_10error_codeE", "cxx.file_write", 3),
        ("_ZNSt3__114basic_ofstreamIcNS_11char_traitsIcEEE4openEPKcj", "cxx.file_write", 3),
        ("_ZNSt3__114basic_ofstreamIcNS_11char_traitsIcEEE4openERKNS_12basic_stringIcS2_NS_9allocatorIcEEEEj", "cxx.file_write", 3),
    ];

    /// The PR-4c-3c spec's Appendix B: every name but `ptrace` is in POSIX.1-2024.
    fn posix_source(name: &str) -> String {
        if name == "ptrace" {
            "Linux and macOS ptrace(2); not in POSIX".to_string()
        } else {
            format!("POSIX.1-2024 (IEEE Std 1003.1-2024): {name}()")
        }
    }

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
                    source: posix_source(name),
                    macho_dylib: LIBSYSTEM,
                }),
                "{name}"
            );
        }
        for (name, feature, arity) in CXX {
            let cap = s.capability(name.as_bytes());
            assert_eq!(
                cap.map(|c| (c.feature.as_str(), c.arity, c.macho_dylib)),
                Some((feature, arity, LIBSYSTEM)),
                "{name}"
            );
        }
        for (name, feature, arity) in LIBCXX_NAMES {
            let cap = s.capability(name.as_bytes());
            assert_eq!(
                cap.map(|c| (c.feature.as_str(), c.arity, c.macho_dylib)),
                Some((feature, arity, LIBCXX)),
                "{name}"
            );
        }
        assert!(
            s.capability(b"connect@GLIBC_2.2.5").is_none(),
            "exact names only"
        );
        assert!(s.capability(b"Connect").is_none());
        assert!(s
            .capability(b"_ZNSt10filesystem6removeERKNS_7__cxx114pathE@GLIBCXX_3.4.26")
            .is_none());
        // The wchar_t streams' open on the __cxx11 string.
        assert_eq!(s.longest(), 107);
        // v0.1's 28 names (7 + 5 + 6 + 4 + 2 + 3 + 1), unchanged, libstdc++'s 88 (18 + 70), and
        // libc++'s 17 (2 + 15).
        assert_eq!(s.count(), 28 + 88 + 17);
    }

    /// libstdc++.so.6.0.35's exports of the families the `cxx.*` names come from, as the C++
    /// fixture's build.sh listed them: name, version, demangled form.
    const EXPORTS: &str =
        include_str!("../../tests/fixtures/cxx-capabilities/libstdcxx-exports.tsv");

    fn exports() -> BTreeMap<&'static str, (&'static str, &'static str)> {
        let exports: BTreeMap<_, _> = EXPORTS
            .lines()
            .map(|line| {
                let mut f = line.split('\t');
                let (Some(name), Some(version), Some(demangled), None) =
                    (f.next(), f.next(), f.next(), f.next())
                else {
                    panic!("{line:?}")
                };
                (name, (version, demangled))
            })
            .collect();
        // A name listed twice would hide one of its rows.
        assert_eq!(
            exports.len(),
            EXPORTS.lines().count(),
            "a name listed twice"
        );
        exports
    }

    #[test]
    fn the_cxx_names_are_libstdcxx_exports_and_their_sources_say_so() {
        let s = signatures().unwrap();
        let exports = exports();
        let mut cxx = 0;
        for (name, cap) in &s.capabilities {
            if !cap.feature.as_str().starts_with("cxx.") || cap.macho_dylib == LIBCXX {
                continue;
            }
            cxx += 1;
            let name = std::str::from_utf8(name).unwrap();
            let Some((version, demangled)) = exports.get(name) else {
                panic!("not a libstdc++ export: {name}");
            };
            // A constructor's two variants demangle alike.
            let tag = if name.contains("EEC1E") {
                " [C1]"
            } else if name.contains("EEC2E") {
                " [C2]"
            } else {
                ""
            };
            assert_eq!(
                cap.source,
                format!("libstdc++ {version}: {demangled}{tag}"),
                "{name}"
            );
        }
        assert_eq!(cxx, 88);
    }

    /// The parameters of a demangled function, split at the commas outside brackets.
    fn params(list: &str) -> Vec<&str> {
        let (mut depth, mut start, mut out) = (0, 0, vec![]);
        for (i, c) in list.char_indices() {
            match c {
                '<' | '(' => depth += 1,
                '>' | ')' => depth -= 1,
                ',' if depth == 0 => {
                    out.push(list[start..i].trim());
                    start = i + 1;
                }
                _ => {}
            }
        }
        if !list.trim().is_empty() {
            out.push(list[start..].trim());
        }
        out
    }

    /// The rule of the PR-4c-3c spec's §2, applied to the exports list rather than written out:
    /// the std::filesystem operations that create, remove, rename, copy, or resize, and the
    /// ifstream and ofstream constructors and `open` that take a file name. Each arity is the
    /// demangled form's parameters, plus `this` for a stream, plus the VTT for a C2 constructor.
    #[test]
    fn the_cxx_names_are_the_exports_the_rule_selects_with_their_arities() {
        const WRITES: [&str; 12] = [
            "remove",
            "remove_all",
            "rename",
            "create_directory",
            "create_directories",
            "create_symlink",
            "create_hard_link",
            "create_directory_symlink",
            "copy",
            "copy_file",
            "copy_symlink",
            "resize_file",
        ];
        // A file name: a `const char*`, or a string of either ABI.
        const FILE_NAMES: [&str; 3] = [
            "char const*",
            "std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&",
            "std::basic_string<char, std::char_traits<char>, std::allocator<char> > const&",
        ];
        let mut want = BTreeMap::new();
        for (name, (_, demangled)) in exports() {
            let Some((head, rest)) = demangled.split_once('(') else {
                continue;
            };
            let Some(list) = rest.strip_suffix(')') else {
                continue;
            };
            let params = params(list);
            let fs = head.strip_prefix("std::filesystem::");
            if fs.is_some_and(|f| WRITES.contains(&f)) {
                want.insert(name, ("cxx.file_write", params.len()));
                continue;
            }
            for (class, feature) in [
                ("ifstream", "cxx.file_read"),
                ("ofstream", "cxx.file_write"),
            ] {
                for char in ["char", "wchar_t"] {
                    let stream = format!("std::basic_{class}<{char}, std::char_traits<{char}> >::");
                    let Some(member) = head.strip_prefix(&stream) else {
                        continue;
                    };
                    let opens = member == "open" || member == format!("basic_{class}");
                    if opens && params.first().is_some_and(|p| FILE_NAMES.contains(p)) {
                        let vtt = usize::from(name.contains("EEC2E"));
                        want.insert(name, (feature, params.len() + 1 + vtt));
                    }
                }
            }
        }
        let s = signatures().unwrap();
        let got: BTreeMap<&str, (&str, usize)> = s
            .capabilities
            .iter()
            .filter(|(_, c)| c.feature.as_str().starts_with("cxx.") && c.macho_dylib == LIBSYSTEM)
            .map(|(n, c)| {
                let name = std::str::from_utf8(n).unwrap();
                (name, (c.feature.as_str(), usize::from(c.arity)))
            })
            .collect();
        assert_eq!(got, want);
        assert_eq!(got.len(), 88);
    }

    #[test]
    fn the_unmapped_cxx_names_are_exports_not_in_the_table() {
        let s = signatures().unwrap();
        let exports = exports();
        for name in [
            // The mode decides read or write.
            "_ZNSt13basic_fstreamIcSt11char_traitsIcEEC1EPKcSt13_Ios_Openmode",
            "_ZNSt13basic_fstreamIcSt11char_traitsIcEE4openEPKcSt13_Ios_Openmode",
            "_ZNSt13basic_filebufIcSt11char_traitsIcEE4openEPKcSt13_Ios_Openmode",
            // Metadata, not a file's contents or name.
            "_ZNSt10filesystem11permissionsERKNS_7__cxx114pathENS_5permsENS_12perm_optionsE",
            "_ZNSt10filesystem15last_write_timeERKNS_7__cxx114pathE",
            "_ZNSt10filesystem15last_write_timeERKNS_7__cxx114pathENSt6chrono10time_pointINS_12__file_clockENS4_8durationIlSt5ratioILl1ELl1000000000EEEEEE",
            // They change nothing.
            "_ZNSt10filesystem6statusERKNS_7__cxx114pathE",
            "_ZNSt10filesystem7__cxx1118directory_iteratorC1ERKNS0_4pathENS_17directory_optionsEPSt10error_code",
            // They open no file.
            "_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC1Ev",
            "_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC1EOS2_",
            "_ZNSt14basic_ofstreamIcSt11char_traitsIcEEC1Ev",
        ] {
            assert!(exports.contains_key(name), "not a libstdc++ export: {name}");
            assert!(s.capability(name.as_bytes()).is_none(), "{name}");
        }
    }

    /// libc++ 22.1.8's exports of the file families, as the libc++ fixture's build.sh listed
    /// them: name, demangled form.
    const LIBCXX_EXPORTS: &str =
        include_str!("../../tests/fixtures/libcxx-capabilities/libcxx-exports.tsv");

    fn libcxx_exports() -> BTreeMap<&'static str, &'static str> {
        let exports: BTreeMap<_, _> = LIBCXX_EXPORTS
            .lines()
            .map(|line| {
                let mut f = line.split('\t');
                let (Some(name), Some(demangled), None) = (f.next(), f.next(), f.next()) else {
                    panic!("{line:?}")
                };
                (name, demangled)
            })
            .collect();
        assert_eq!(
            exports.len(),
            LIBCXX_EXPORTS.lines().count(),
            "a name listed twice"
        );
        exports
    }

    #[test]
    fn the_libcxx_names_are_libcxx_exports_and_their_sources_say_so() {
        let s = signatures().unwrap();
        let exports = libcxx_exports();
        let mut libcxx = 0;
        for (name, cap) in &s.capabilities {
            if cap.macho_dylib != LIBCXX {
                continue;
            }
            libcxx += 1;
            let name = std::str::from_utf8(name).unwrap();
            let Some(demangled) = exports.get(name) else {
                panic!("not a libc++ export: {name}");
            };
            assert_eq!(cap.source, format!("libc++ 22.1.8: {demangled}"), "{name}");
        }
        assert_eq!(libcxx, 17);
    }

    /// The rule of the #105 spec's §2, applied to libc++'s exports list: the helpers of the
    /// std::filesystem operations that create, remove, rename, copy, or resize, and the ifstream
    /// and ofstream constructors and `open` that take a file name, for `char` and `wchar_t`, as
    /// the issue asks (plan review P2: the constructors and `wchar_t` are in the rule, so an
    /// export of one would be expected here, not missed). Each arity is the demangled form's
    /// parameters, plus `this` for a member. libc++ 22.1.8 exports only `char`'s `open`.
    #[test]
    fn the_libcxx_names_are_the_exports_the_rule_selects_with_their_arities() {
        const WRITES: [&str; 12] = [
            "remove",
            "remove_all",
            "rename",
            "create_directory",
            "create_directories",
            "create_symlink",
            "create_hard_link",
            "create_directory_symlink",
            "copy",
            "copy_file",
            "copy_symlink",
            "resize_file",
        ];
        // A file name: a `const char*`, a string, or (libc++'s overloads) a `path`.
        const FILE_NAMES: [&str; 3] = [
            "char const*",
            "std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char>> const&",
            "std::__1::__fs::filesystem::path const&",
        ];
        let mut want = BTreeMap::new();
        for (name, demangled) in libcxx_exports() {
            let Some((head, rest)) = demangled.split_once('(') else {
                continue;
            };
            let Some(list) = rest.strip_suffix(')') else {
                continue;
            };
            let params = params(list);
            let helper = head.strip_prefix("std::__1::__fs::filesystem::__");
            if helper.is_some_and(|f| WRITES.contains(&f)) {
                want.insert(name, ("cxx.file_write", params.len()));
                continue;
            }
            for (class, feature) in [
                ("ifstream", "cxx.file_read"),
                ("ofstream", "cxx.file_write"),
            ] {
                for char in ["char", "wchar_t"] {
                    let stream =
                        format!("std::__1::basic_{class}<{char}, std::__1::char_traits<{char}>>::");
                    let Some(member) = head.strip_prefix(&stream) else {
                        continue;
                    };
                    let opens = member == "open" || member == format!("basic_{class}");
                    if opens && params.first().is_some_and(|p| FILE_NAMES.contains(p)) {
                        want.insert(name, (feature, params.len() + 1));
                    }
                }
            }
        }
        let s = signatures().unwrap();
        let got: BTreeMap<&str, (&str, usize)> = s
            .capabilities
            .iter()
            .filter(|(_, c)| c.macho_dylib == LIBCXX)
            .map(|(n, c)| {
                let name = std::str::from_utf8(n).unwrap();
                (name, (c.feature.as_str(), usize::from(c.arity)))
            })
            .collect();
        assert_eq!(got, want);
        assert_eq!(got.len(), 17);
        // Measured, and stated: libc++ 22.1.8 exports no ifstream or ofstream constructor (they are
        // inline over basic_filebuf::open) and no wchar_t stream.
        let exports = libcxx_exports();
        for prefix in ["_ZNSt3__114basic_ifstream", "_ZNSt3__114basic_ofstream"] {
            let members: Vec<&str> = exports
                .iter()
                .filter(|(n, _)| n.starts_with(prefix))
                .map(|(_, d)| *d)
                .collect();
            assert_eq!(members.len(), 2, "{prefix}: {members:?}");
            assert!(
                members.iter().all(|d| d.contains(">::open(")),
                "{members:?}"
            );
        }
        assert!(!exports
            .values()
            .any(|d| d.contains("basic_ifstream<wchar_t") || d.contains("basic_ofstream<wchar_t")));
    }

    #[test]
    fn the_unmapped_libcxx_names_are_exports_not_in_the_table() {
        let s = signatures().unwrap();
        let exports = libcxx_exports();
        for name in [
            // The mode decides read or write; a stream's constructor imports it.
            "_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE4openEPKcj",
            // Metadata, not a file's contents or name.
            "_ZNSt3__14__fs10filesystem13__permissionsERKNS1_4pathENS1_5permsENS1_12perm_optionsEPNS_10error_codeE",
            "_ZNSt3__14__fs10filesystem17__last_write_timeERKNS1_4pathEPNS_10error_codeE",
            "_ZNSt3__14__fs10filesystem17__last_write_timeERKNS1_4pathENS_6chrono10time_pointINS1_16_FilesystemClockENS5_8durationInNS_5ratioILl1ELl1000000000EEEEEEEPNS_10error_codeE",
            // They change nothing.
            "_ZNSt3__14__fs10filesystem8__statusERKNS1_4pathEPNS_10error_codeE",
            "_ZNSt3__14__fs10filesystem16__symlink_statusERKNS1_4pathEPNS_10error_codeE",
            "_ZNSt3__14__fs10filesystem18directory_iteratorC1ERKNS1_4pathEPNS_10error_codeENS1_17directory_optionsE",
            // It opens no file.
            "_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEEC1Ev",
        ] {
            assert!(exports.contains_key(name), "not a libc++ export: {name}");
            assert!(s.capability(name.as_bytes()).is_none(), "{name}");
        }
        // libc++ exports nothing of basic_fstream: its constructor and open import filebuf's open.
        assert!(!exports
            .keys()
            .any(|n| n.starts_with("_ZNSt3__113basic_fstream")));
    }

    /// #105: the POSIX names and libstdc++'s are libSystem's, libc++'s are libc++'s, and every
    /// libc++ entry is one the model admits for a libc++ import (C6).
    #[test]
    fn each_name_is_looked_up_for_its_dylib() {
        let s = signatures().unwrap();
        for (name, cap) in &s.capabilities {
            let name = std::str::from_utf8(name).unwrap();
            let want = if name.starts_with("_ZNSt3__1") {
                LIBCXX
            } else {
                LIBSYSTEM
            };
            assert_eq!(cap.macho_dylib, want, "{name}");
            if cap.macho_dylib == LIBCXX {
                assert!(LookedUp::Cxx.admits(&cap.feature), "{name}");
            }
        }
    }

    #[test]
    fn the_features_are_the_table_s_keys_sorted_once_each() {
        let s = signatures().unwrap();
        let got: Vec<&str> = s.features().iter().map(|f| f.as_str()).collect();
        assert_eq!(
            got,
            [
                "cxx.file_read",
                "cxx.file_write",
                "posix.anti_debug",
                "posix.dynamic_loading",
                "posix.environment_access",
                "posix.file_read",
                "posix.file_write",
                "posix.network",
                "posix.process_spawn",
            ]
        );
    }

    /// #51: the entry names the embedded table by its SHA-256, so another text is another entry.
    #[test]
    fn the_table_s_knowledge_entry_is_its_sha256() {
        let k = signatures().unwrap().knowledge();
        assert_eq!(k.kind, KnowledgeKind::SignatureDb);
        assert_eq!(k.id, "capabilities");
        assert_eq!(k.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(
            k.sha256.as_str(),
            format!("{:x}", Sha256::digest(CAPABILITIES.as_bytes()))
        );
        let other = parse(
            &CAPABILITIES.replace("POSIX.1-2024", "POSIX.1-2017"),
            NORETURN,
        )
        .unwrap();
        assert_ne!(other.knowledge().sha256, k.sha256);
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
                &format!(
                    "[[capability]]\nfeature = \"posix.network\"\nmacho_dylib = \"{LIBSYSTEM}\"\nsymbols = [{symbols}]"
                ),
                NORETURN,
            )
            .map(|_| ())
        };
        assert_eq!(
            one("{ name = \"connect\", arity = 7, source = \"s\" }"),
            Err("capabilities.toml: \"connect\": arity 7 is over 6".to_string())
        );
        assert_eq!(
            one("{ name = \"\", arity = 1, source = \"s\" }"),
            Err("capabilities.toml: posix.network: an empty name".to_string())
        );
        assert_eq!(
            one("{ name = \"a\", arity = 1, source = \"s\" }, { name = \"a\", arity = 1, source = \"s\" }"),
            Err("capabilities.toml: \"a\" listed twice".to_string())
        );
        // PR-4c-3c: every entry has a source, and it is not blank.
        assert_eq!(
            one("{ name = \"connect\", arity = 3 }"),
            Err("capabilities.toml: \"connect\": no source".to_string())
        );
        // "\\t\\n" is TOML's escapes: a tab and a newline.
        for blank in ["", " ", "\\t\\n"] {
            assert_eq!(
                one(&format!(
                    "{{ name = \"connect\", arity = 3, source = \"{blank}\" }}"
                )),
                Err("capabilities.toml: \"connect\": a blank source".to_string()),
                "{blank:?}"
            );
        }
        // A source with blanks around it is not blank.
        assert_eq!(
            one("{ name = \"connect\", arity = 3, source = \" s \" }"),
            Ok(())
        );
        // #105: every group names its Mach-O dylib, libSystem's or libc++'s, exactly.
        let group = |dylib: &str| {
            parse(
                &format!(
                    "[[capability]]\nfeature = \"cxx.file_write\"\n{dylib}symbols = [{{ name = \"a\", arity = 1, source = \"s\" }}]"
                ),
                NORETURN,
            )
            .map(|_| ())
        };
        assert_eq!(group(&format!("macho_dylib = \"{LIBCXX}\"\n")), Ok(()));
        let missing = group("");
        assert!(
            missing
                .as_ref()
                .is_err_and(|e| e.contains("missing field `macho_dylib`")),
            "{missing:?}"
        );
        for other in [
            "",
            "/usr/lib/libc++.dylib",
            "/usr/lib/libc++.1.dylib ",
            "libSystem",
        ] {
            assert_eq!(
                group(&format!("macho_dylib = \"{other}\"\n")),
                Err(format!(
                    "capabilities.toml: cxx.file_write: macho_dylib {other:?} is neither libSystem nor libc++"
                )),
                "{other:?}"
            );
        }
        let unknown = one("{ name = \"connect\", arity = 3, source = \"s\", sources = \"s\" }");
        assert!(
            unknown
                .as_ref()
                .is_err_and(|e| e.contains("unknown field `sources`")),
            "{unknown:?}"
        );
        assert!(parse(CAPABILITIES, "prefixes = []").is_err());
        assert!(parse(CAPABILITIES, "prefixes = [\"\"]\nnames = []").is_err());
    }
}
