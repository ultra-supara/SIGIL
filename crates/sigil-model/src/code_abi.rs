//! Archived ABI location knowledge shared by producers and native/WASM verifiers.
//! The v1 bytes are immutable; new knowledge requires a new version, retaining this table.
//! Capability arities are deliberately not consulted. This module performs no I/O or analysis.
use crate::{
    ArgumentLayout, CallId, IdError, KnowledgeKind, KnowledgeRef, MachOLibrary, Reg, Sha256Hex,
    UntrustedText, LIBSYSTEM,
};

pub const ID: &str = "code-abi-signatures";
pub const V1_BYTES: &str = include_str!("../data/code-abi-signatures-v1.toml");
pub const V1_SHA256: &str = "af6afceff3bd76c9e18ae0321cd8260ccc79c96354f4e35bfe09fca61efca735";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeAbi {
    ElfAarch64,
    DarwinArm64,
    DarwinX86_64,
}

#[derive(Debug, Clone, Copy)]
pub struct Signature {
    pub abi: CodeAbi,
    pub symbol: &'static str,
    pub registers: &'static [Reg],
    pub complete: bool,
}

/// A version that this binary actually has; constructor fields stay private.
#[derive(Debug, Clone, Copy)]
pub struct SignatureDb {
    version: &'static str,
    sha256: &'static str,
    signatures: &'static [Signature],
}
pub static V1: SignatureDb = SignatureDb {
    version: "1",
    sha256: V1_SHA256,
    signatures: V1_SIGNATURES,
};

/// Exact lookup of archived version/hash, never a fallback to current knowledge.
pub fn archived(version: &str, sha256: &str) -> Option<&'static SignatureDb> {
    [&V1]
        .into_iter()
        .find(|db| db.version == version && db.sha256 == sha256)
}

impl SignatureDb {
    pub fn knowledge(&self) -> Result<KnowledgeRef, IdError> {
        Ok(KnowledgeRef {
            kind: KnowledgeKind::SignatureDb,
            id: ID.into(),
            version: self.version.into(),
            sha256: Sha256Hex::new(self.sha256)?,
        })
    }

    /// Raw Darwin spellings and an actual positive libSystem ordinal are required.
    /// Flat/unbound/weak lookup is not proof of the library's prototype.
    pub fn lookup(
        &self,
        abi: CodeAbi,
        symbol: &UntrustedText,
        library: Option<&MachOLibrary>,
    ) -> Option<&'static Signature> {
        let admitted = match abi {
            CodeAbi::ElfAarch64 => library.is_none(),
            CodeAbi::DarwinArm64 | CodeAbi::DarwinX86_64 => {
                matches!(library, Some(MachOLibrary::Dylib { ordinal, name: Some(name) }) if *ordinal > 0 && name.as_bytes() == LIBSYSTEM.as_bytes())
            }
        };
        admitted
            .then(|| {
                self.signatures
                    .iter()
                    .find(|s| s.abi == abi && symbol.as_bytes() == s.symbol.as_bytes())
            })
            .flatten()
    }

    /// Producer contract: request these locations only, preserving unknown values.
    /// An unlisted target has an empty proved prefix, never a guessed arity.
    pub fn argument_plan(
        &self,
        abi: Option<CodeAbi>,
        symbol: &UntrustedText,
        library: Option<&MachOLibrary>,
    ) -> ArgumentPlan {
        let signature = abi.and_then(|abi| self.lookup(abi, symbol, library));
        let registers = signature.map_or(&[][..], |s| s.registers);
        let reason = match signature {
            Some(s) if s.complete => None,
            Some(_) => Some("variadic argument positions are not modeled"),
            None => Some("unknown or unsupported ABI prototype"),
        };
        ArgumentPlan {
            registers,
            layout: reason.map_or(ArgumentLayout::Complete, |reason| ArgumentLayout::Partial {
                reason: UntrustedText::new(reason),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgumentPlan {
    pub registers: &'static [Reg],
    pub layout: ArgumentLayout,
}

impl ArgumentPlan {
    /// Diagnostic for this actual call, to retain in its slice's code coverage missing list.
    pub fn coverage_gap(&self, call: &CallId) -> Option<String> {
        match &self.layout {
            ArgumentLayout::Complete => None,
            ArgumentLayout::Partial { reason } => Some(argument_layout_gap(call, reason)),
        }
    }
}

/// Shared producer/verifier spelling for a partial call's code coverage gap.
/// Printable ASCII is retained except that backslash is doubled; every other byte is
/// written as `\xNN`. This is lossless, single-line, and never display-truncated, so
/// different raw reasons cannot acquire the same diagnostic. Render as ordinary text,
/// using the existing escaping API when producing Markdown/HTML.
pub fn argument_layout_gap(call: &CallId, reason: &UntrustedText) -> String {
    let mut gap = format!("code: argument layout incomplete at {call}: ");
    for &byte in reason.as_bytes() {
        match byte {
            b'\\' => gap.push_str("\\\\"),
            b' '..=b'~' => gap.push(char::from(byte)),
            _ => gap.push_str(&format!("\\x{byte:02x}")),
        }
    }
    gap
}

const V1_SIGNATURES: &[Signature] = &[
    Signature {
        abi: CodeAbi::ElfAarch64,
        symbol: "connect",
        registers: &[Reg::X0, Reg::X1, Reg::X2],
        complete: true,
    },
    Signature {
        abi: CodeAbi::ElfAarch64,
        symbol: "open",
        registers: &[Reg::X0, Reg::X1],
        complete: false,
    },
    Signature {
        abi: CodeAbi::ElfAarch64,
        symbol: "openat",
        registers: &[Reg::X0, Reg::X1, Reg::X2],
        complete: false,
    },
    Signature {
        abi: CodeAbi::DarwinArm64,
        symbol: "_connect",
        registers: &[Reg::X0, Reg::X1, Reg::X2],
        complete: true,
    },
    Signature {
        abi: CodeAbi::DarwinArm64,
        symbol: "_open",
        registers: &[Reg::X0, Reg::X1],
        complete: false,
    },
    Signature {
        abi: CodeAbi::DarwinArm64,
        symbol: "_openat",
        registers: &[Reg::X0, Reg::X1, Reg::X2],
        complete: false,
    },
    Signature {
        abi: CodeAbi::DarwinX86_64,
        symbol: "_connect",
        registers: &[Reg::Rdi, Reg::Rsi, Reg::Rdx],
        complete: true,
    },
    Signature {
        abi: CodeAbi::DarwinX86_64,
        symbol: "_open",
        registers: &[Reg::Rdi, Reg::Rsi],
        complete: false,
    },
    Signature {
        abi: CodeAbi::DarwinX86_64,
        symbol: "_openat",
        registers: &[Reg::Rdi, Reg::Rsi, Reg::Rdx],
        complete: false,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// No executable registry entry can be added without changing archived knowledge.
    #[test]
    fn lookup_is_an_exact_transcription_of_archived_v1() {
        let table: toml::Value = toml::from_str(V1_BYTES).unwrap();
        assert_eq!(table["version"].as_str(), Some(V1.version));
        let entries = table["signature"].as_array().unwrap();
        assert_eq!(entries.len(), V1.signatures.len());
        let mut seen = std::collections::BTreeSet::new();
        for (entry, signature) in entries.iter().zip(V1.signatures) {
            let abi = match signature.abi {
                CodeAbi::ElfAarch64 => "elf-aarch64",
                CodeAbi::DarwinArm64 => "darwin-arm64",
                CodeAbi::DarwinX86_64 => "darwin-x86-64",
            };
            assert_eq!(entry["abi"].as_str(), Some(abi));
            assert_eq!(entry["symbol"].as_str(), Some(signature.symbol));
            assert!(seen.insert((abi, signature.symbol)));
            assert_eq!(entry["complete"].as_bool(), Some(signature.complete));
            let regs: Vec<Reg> = entry["registers"].clone().try_into().unwrap();
            assert_eq!(regs, signature.registers);
        }
        let k = V1.knowledge().unwrap();
        assert_eq!(k.id, ID);
        assert_eq!(k.version, "1");
        assert_eq!(k.sha256.as_str(), V1_SHA256);
    }
}
