//! Typed identifiers.
//!
//! Each identity domain gets its own newtype, so an artifact hash cannot be passed where an
//! instance, a check, or a rule is expected. Every identifier is validated when it is constructed
//! **and** when it is deserialized, so a malformed ID never enters a [`crate::Session`].
//!
//! IDs are stable strings derived by the engine from content hashes, scan-root-relative paths,
//! and profile/rule names (plan §4.4.1). They are never memory addresses or list positions.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::artifact::Arch;

/// Longest identifier accepted, in bytes.
pub const MAX_ID_LEN: usize = 1024;

/// Why a string was rejected as an identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdError {
    /// The identifier type, e.g. `"ArtifactId"`.
    pub kind: &'static str,
    /// The rejected value.
    pub value: String,
    /// What is wrong with it.
    pub problem: IdProblem,
}

/// The specific problem with a rejected identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdProblem {
    Empty,
    TooLong,
    ControlCharacter,
    SurroundingWhitespace,
    MissingPrefix(&'static str),
    Malformed(&'static str),
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let problem = match &self.problem {
            IdProblem::Empty => "is empty".to_string(),
            IdProblem::TooLong => format!("is longer than {MAX_ID_LEN} bytes"),
            IdProblem::ControlCharacter => "contains a control character".to_string(),
            IdProblem::SurroundingWhitespace => "has leading or trailing whitespace".to_string(),
            IdProblem::MissingPrefix(prefix) => format!("does not start with `{prefix}`"),
            IdProblem::Malformed(expected) => format!("is not of the form {expected}"),
        };
        write!(f, "invalid {}: {:?} {}", self.kind, self.value, problem)
    }
}

impl std::error::Error for IdError {}

fn err(kind: &'static str, value: &str, problem: IdProblem) -> IdError {
    IdError {
        kind,
        value: value.to_string(),
        problem,
    }
}

/// Non-empty, bounded, no control characters, no surrounding whitespace.
fn check_plain(kind: &'static str, value: &str) -> Result<(), IdError> {
    if value.is_empty() {
        return Err(err(kind, value, IdProblem::Empty));
    }
    if value.len() > MAX_ID_LEN {
        return Err(err(kind, value, IdProblem::TooLong));
    }
    if value.chars().any(char::is_control) {
        return Err(err(kind, value, IdProblem::ControlCharacter));
    }
    if value.trim() != value {
        return Err(err(kind, value, IdProblem::SurroundingWhitespace));
    }
    Ok(())
}

fn check_prefixed(kind: &'static str, value: &str, prefix: &'static str) -> Result<(), IdError> {
    check_plain(kind, value)?;
    match value.strip_prefix(prefix) {
        Some(rest) if !rest.is_empty() => Ok(()),
        _ => Err(err(kind, value, IdProblem::MissingPrefix(prefix))),
    }
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_decimal(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'))
}

fn check_sha256_hex(kind: &'static str, value: &str) -> Result<(), IdError> {
    if value.len() == 64 && is_lower_hex(value) {
        Ok(())
    } else {
        Err(err(
            kind,
            value,
            IdProblem::Malformed("64 lowercase hex digits"),
        ))
    }
}

fn check_artifact(kind: &'static str, value: &str) -> Result<(), IdError> {
    match value.strip_prefix("sha256:") {
        Some(hex) if hex.len() == 64 && is_lower_hex(hex) => Ok(()),
        _ => Err(err(
            kind,
            value,
            IdProblem::Malformed("sha256:<64 lowercase hex>"),
        )),
    }
}

const SLICE_FORM: &str = "sha256:<64 lowercase hex>#<arch>@<decimal offset>";

fn split_slice(value: &str) -> Option<(&str, &str, &str)> {
    let (artifact, rest) = value.split_once('#')?;
    let (arch, offset) = rest.split_once('@')?;
    Some((artifact, arch, offset))
}

fn check_slice(kind: &'static str, value: &str) -> Result<(), IdError> {
    let malformed = || err(kind, value, IdProblem::Malformed(SLICE_FORM));
    let (artifact, arch, offset) = split_slice(value).ok_or_else(malformed)?;
    check_artifact(kind, artifact).map_err(|_| malformed())?;
    if Arch::from_name(arch).is_none() || !is_decimal(offset) || offset.parse::<u64>().is_err() {
        return Err(malformed());
    }
    Ok(())
}

fn check_profile_ref(kind: &'static str, value: &str) -> Result<(), IdError> {
    check_plain(kind, value)?;
    let malformed = || err(kind, value, IdProblem::Malformed("<profile id>@<revision>"));
    let (id, revision) = value.rsplit_once('@').ok_or_else(malformed)?;
    if id.is_empty() || id.contains('@') || id.contains('#') || !is_decimal(revision) {
        return Err(malformed());
    }
    revision.parse::<u32>().map(|_| ()).map_err(|_| malformed())
}

fn digits(s: &str, n: usize) -> Option<u32> {
    if s.len() == n && s.bytes().all(|b| b.is_ascii_digit()) {
        s.parse().ok()
    } else {
        None
    }
}

fn valid_date(s: &str) -> bool {
    let mut parts = s.split('-');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(y), Some(m), Some(d), None) => {
            digits(y, 4).is_some()
                && digits(m, 2).is_some_and(|m| (1..=12).contains(&m))
                && digits(d, 2).is_some_and(|d| (1..=31).contains(&d))
        }
        _ => false,
    }
}

fn check_date(kind: &'static str, value: &str) -> Result<(), IdError> {
    if valid_date(value) {
        Ok(())
    } else {
        Err(err(kind, value, IdProblem::Malformed("YYYY-MM-DD")))
    }
}

fn check_timestamp(kind: &'static str, value: &str) -> Result<(), IdError> {
    let malformed = || {
        err(
            kind,
            value,
            IdProblem::Malformed("RFC 3339 UTC, YYYY-MM-DDTHH:MM:SS[.fraction]Z"),
        )
    };
    let (date, time) = value.split_once('T').ok_or_else(malformed)?;
    let time = time.strip_suffix('Z').ok_or_else(malformed)?;
    let (hms, fraction) = match time.split_once('.') {
        Some((hms, fraction)) => (hms, Some(fraction)),
        None => (time, None),
    };
    let mut parts = hms.split(':');
    let ok_time = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(m), Some(s), None) => {
            digits(h, 2).is_some_and(|h| h < 24)
                && digits(m, 2).is_some_and(|m| m < 60)
                && digits(s, 2).is_some_and(|s| s <= 60)
        }
        _ => false,
    };
    let ok_fraction = fraction
        .is_none_or(|f| (1..=9).contains(&f.len()) && f.bytes().all(|b| b.is_ascii_digit()));
    if valid_date(date) && ok_time && ok_fraction {
        Ok(())
    } else {
        Err(malformed())
    }
}

macro_rules! string_id {
    ($(#[$meta:meta])* $name:ident, $check:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Validates and wraps `value`.
            pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
                let value = value.into();
                ($check)(stringify!($name), value.as_str())?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdError;
            fn try_from(value: String) -> Result<Self, IdError> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> String {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

string_id!(
    /// Content identity: `sha256:<hex>` of the whole file. An artifact is contents, never a path.
    ArtifactId,
    check_artifact
);
string_id!(
    /// One architecture slice of an artifact: `<artifact>#<arch>@<offset>`.
    SliceId,
    check_slice
);
string_id!(
    /// Placement identity: `inst:<scan-root-relative path>`. One artifact may have many instances,
    /// and the same instance ID may hold different artifacts in different sessions.
    InstanceId,
    |k, v| check_prefixed(k, v, "inst:")
);
string_id!(
    /// A scan root declared in the request, e.g. `install` or `models`.
    RootId,
    check_plain
);
string_id!(
    /// A model in a model store: `model:<root id>/<manifest path under manifests/>`.
    ModelId,
    |k, v| check_prefixed(k, v, "model:")
);
string_id!(
    /// A listening socket: `listener:<protocol>/<address>:<port>#<socket inode>`.
    ListenerId,
    |k, v| check_prefixed(k, v, "listener:")
);
string_id!(
    /// A function inside one slice's [`crate::CodeFacts`], e.g. `fn:0xecb0`.
    FnId,
    |k, v| check_prefixed(k, v, "fn:")
);
string_id!(
    /// A call site inside one slice's [`crate::CodeFacts`], e.g. `cs:0xecbe`.
    CallId,
    |k, v| check_prefixed(k, v, "cs:")
);
string_id!(
    /// A [`crate::ProcessValue`] (one value of one key for one role, from one origin).
    ValueId,
    check_plain
);
string_id!(
    /// A [`crate::WriteAccess`] analysis record.
    AccessId,
    check_plain
);
string_id!(
    /// A technical [`crate::Finding`].
    FindingId,
    check_plain
);
string_id!(
    /// An [`crate::OpenQuestion`].
    OpenQuestionId,
    check_plain
);
string_id!(
    /// A condition of a detection rule, e.g. `rule_supported:entry`.
    CondId,
    check_plain
);
string_id!(
    /// An audit check whose coverage decides completeness, e.g. `loader.identify`.
    CheckId,
    check_plain
);
string_id!(
    /// A profile obligation or profile code check decided in the target, e.g.
    /// `filter.reach_predicate`.
    ObligationId,
    check_plain
);
string_id!(
    /// Something a claim depends on that is not established: a profile premise
    /// (`candidate.operands`), an undecided obligation, a binding (`binding:<role>`), a value
    /// (`value:cwd`). Profile obligations and premises share this ID space (plan §4.4.7).
    PremiseId,
    check_plain
);
string_id!(
    /// A detection rule that yields findings or open questions, e.g.
    /// `loader.search_path_untrusted_creator`.
    RuleId,
    check_plain
);
string_id!(
    /// A rule inside a semantic profile, e.g. `filter`, `evaluate`. Always used together with the
    /// profile ([`crate::ProfileRuleRef`]).
    ProfileRuleId,
    check_plain
);
string_id!(
    /// A semantic profile at one revision: `<id>@<revision>`, e.g. `ggml.backend-loader@2`.
    /// The profile's hash is recorded once, in [`crate::Session::knowledge`].
    ProfileRef,
    check_profile_ref
);
string_id!(
    /// A reference-manifest set (official release archives hashed per file).
    RefSetId,
    check_plain
);
string_id!(
    /// An explicit assumption, e.g. `A-3`.
    AssumptionId,
    check_plain
);
string_id!(
    /// A component name used by identification, e.g. `ggml`, `ggml-backend/cpu`.
    ComponentKey,
    check_plain
);
string_id!(
    /// A feature-hint key, e.g. `posix.network`.
    FeatureKey,
    check_plain
);
string_id!(
    /// A process role from a topology rule, e.g. `llama-server (per model)`. Generic: the model
    /// attaches no runtime-specific meaning to it.
    ProcessRole,
    check_plain
);
string_id!(
    /// A profile-named operand of a predicate check, e.g. `T`.
    AtomName,
    check_plain
);
string_id!(
    /// The policy rule a decision came from, e.g. `policy:rules.exposure.bind_public` or
    /// `default:loader.search_path_untrusted_creator`.
    PolicyRuleRef,
    check_plain
);
string_id!(
    /// A requested audit scope, e.g. `backend_loader`.
    AuditScope,
    check_plain
);
string_id!(
    /// The analyzer that derived a fact, e.g. `sigil-engine/code@0.2.0`.
    AnalyzerRef,
    check_plain
);
string_id!(
    /// A ground-truth record (plan §5.9).
    GroundTruthRef,
    check_plain
);
string_id!(
    /// A lowercase hex SHA-256 digest (64 digits).
    Sha256Hex,
    check_sha256_hex
);
string_id!(
    /// An instant in RFC 3339 UTC form: `YYYY-MM-DDTHH:MM:SS[.fraction]Z`.
    Timestamp,
    check_timestamp
);
string_id!(
    /// A calendar date, `YYYY-MM-DD` (policy `expires`).
    Date,
    check_date
);

impl SliceId {
    /// The slice of `artifact` for `arch` at byte `offset`.
    pub fn from_parts(artifact: &ArtifactId, arch: Arch, offset: u64) -> SliceId {
        SliceId(format!("{}#{}@{}", artifact.as_str(), arch.name(), offset))
    }

    /// The artifact this slice belongs to.
    pub fn artifact(&self) -> ArtifactId {
        let artifact = self.0.split_once('#').map_or(self.0.as_str(), |(a, _)| a);
        ArtifactId(artifact.to_string())
    }
}

impl ProfileRef {
    /// The profile ID without the revision.
    pub fn profile_id(&self) -> &str {
        self.0
            .rsplit_once('@')
            .map_or(self.0.as_str(), |(id, _)| id)
    }

    /// The revision number.
    pub fn revision(&self) -> u32 {
        self.0
            .rsplit_once('@')
            .and_then(|(_, r)| r.parse().ok())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "40e1f9070eee43ad95a8f3151b691368ac64db9f826fc5796d5ba84836a1305f";

    #[test]
    fn artifact_ids_are_sha256_of_lowercase_hex() {
        assert!(ArtifactId::new(format!("sha256:{HEX}")).is_ok());
        for bad in [
            "",
            HEX,
            "sha256:40e1f907…",
            &format!("sha256:{}", HEX.to_uppercase()),
            &format!("sha256:{HEX}0"),
            &format!("sha1:{HEX}"),
        ] {
            assert!(ArtifactId::new(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn slice_ids_name_their_artifact_arch_and_offset() {
        let artifact = ArtifactId::new(format!("sha256:{HEX}")).unwrap();
        let slice = SliceId::from_parts(&artifact, Arch::X86_64, 0);
        assert_eq!(slice.as_str(), format!("sha256:{HEX}#x86_64@0"));
        assert_eq!(slice.artifact(), artifact);
        assert!(SliceId::new(slice.as_str()).is_ok());
        for bad in [
            format!("sha256:{HEX}"),
            format!("sha256:{HEX}#x86_64"),
            format!("sha256:{HEX}#mips@0"),
            format!("sha256:{HEX}#x86_64@01"),
            format!("sha256:{HEX}#x86_64@-1"),
            "sha256:40e1f907…#x86_64@0".to_string(),
        ] {
            assert!(SliceId::new(bad.clone()).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn prefixed_ids_require_their_prefix_and_a_body() {
        assert!(InstanceId::new("inst:lib/ollama/libggml.so.0.13.1").is_ok());
        assert!(InstanceId::new("lib/ollama/libggml.so").is_err());
        assert!(InstanceId::new("inst:").is_err());
        assert!(FnId::new("fn:0xecb0").is_ok());
        assert!(FnId::new("cs:0xecb0").is_err());
        assert!(CallId::new("cs:0xecbe").is_ok());
    }

    #[test]
    fn plain_ids_reject_empty_control_and_padded_values() {
        assert!(RuleId::new("loader.search_path_untrusted_creator").is_ok());
        assert!(ProcessRole::new("llama-server (per model)").is_ok());
        for bad in [
            "",
            " x",
            "x ",
            "a\nb",
            "a\u{1b}[31mb",
            &"x".repeat(MAX_ID_LEN + 1),
        ] {
            assert!(CheckId::new(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn profile_refs_are_id_at_revision() {
        let p = ProfileRef::new("ggml.backend-loader@2").unwrap();
        assert_eq!(p.profile_id(), "ggml.backend-loader");
        assert_eq!(p.revision(), 2);
        for bad in [
            "ggml.backend-loader",
            "ggml.backend-loader@",
            "@2",
            "ggml.backend-loader@2#sha256:abc",
            "ggml.backend-loader@x",
            "ggml.backend-loader@99999999999",
        ] {
            assert!(ProfileRef::new(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn timestamps_are_rfc3339_utc_and_dates_are_calendar_dates() {
        for ok in ["2026-10-07T07:00:00Z", "2026-10-07T07:00:00.123456789Z"] {
            assert!(Timestamp::new(ok).is_ok(), "{ok}");
        }
        for bad in [
            "2026-10-07",
            "2026-10-07T07:00:00",
            "2026-10-07T07:00:00+09:00",
            "2026-13-07T07:00:00Z",
            "2026-10-07T24:00:00Z",
            "2026-10-07T07:00:00.Z",
        ] {
            assert!(Timestamp::new(bad).is_err(), "{bad}");
        }
        assert!(Date::new("2027-03-31").is_ok());
        assert!(Date::new("2027-3-31").is_err());
    }

    #[test]
    fn deserialization_rejects_malformed_ids() {
        assert!(serde_json::from_str::<ArtifactId>("\"sha256:40e1f907…\"").is_err());
        assert!(serde_json::from_str::<CallId>("\"0xecbe\"").is_err());
        let ok: CallId = serde_json::from_str("\"cs:0xecbe\"").unwrap();
        assert_eq!(serde_json::to_string(&ok).unwrap(), "\"cs:0xecbe\"");
    }
}
