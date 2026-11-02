//! Shared, pure value rules. Never read this process's environment or infer descendant roles.

use sha2::{Digest, Sha256};
use sigil_model::{ProcessRef, ProcessRole, UntrustedText, ValueId, ValueKey, ValueOrigin};

/// Names for which a complete readable initial environment may establish explicit absence.
/// Wildcard GGML names are retained when encountered, but cannot all be queried in advance.
pub const QUERIED_ENV: &[&[u8]] = &[
    b"CUDA_VISIBLE_DEVICES",
    b"DYLD_LIBRARY_PATH",
    b"GGML_BACKEND_DIR",
    b"GGML_BACKEND_PATH",
    b"HIP_VISIBLE_DEVICES",
    b"LD_LIBRARY_PATH",
    b"OLLAMA_HOST",
    b"OLLAMA_LIBRARY_PATH",
    b"OLLAMA_MODELS",
];

pub fn allowlisted_env(name: &[u8]) -> bool {
    sigil_model::allowlisted_env_name(name)
}

/// Minimize only the URL-like variable. Other allowlisted values are paths/opaque strings;
/// an `@`, `?`, or `#` in one of those is legitimate data and is left intact.
pub fn minimize_env(name: &[u8], value: &[u8]) -> UntrustedText {
    if name != b"OLLAMA_HOST" {
        return UntrustedText::from_bytes(value);
    }
    let end = value
        .iter()
        .position(|b| matches!(b, b'?' | b'#'))
        .unwrap_or(value.len());
    let clean = &value[..end];
    // A scheme belongs at the start; a later :// may be ordinary path data.
    let authority_start = if clean.starts_with(b"//") {
        2
    } else {
        clean
            .iter()
            .position(|b| *b == b':')
            .filter(|&end| {
                clean.first().is_some_and(u8::is_ascii_alphabetic)
                    && clean[..end]
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'+' | b'-' | b'.'))
                    && clean[end..].starts_with(b"://")
            })
            .map_or(0, |end| end + 3)
    };
    let authority_end = clean[authority_start..]
        .iter()
        .position(|b| *b == b'/')
        .map_or(clean.len(), |i| authority_start + i);
    let user_end = clean[authority_start..authority_end]
        .iter()
        .rposition(|b| *b == b'@');
    let Some(user_end) = user_end else {
        return UntrustedText::from_bytes(clean);
    };
    let mut out = clean[..authority_start].to_vec();
    out.extend_from_slice(&clean[authority_start + user_end + 1..]);
    UntrustedText::from_bytes(out)
}

pub fn observed_role(process: &ProcessRef, roles: &[ProcessRole]) -> Result<ProcessRole, String> {
    if let [role] = roles {
        return Ok(role.clone());
    }
    let bytes =
        serde_json::to_vec(process).map_err(|_| "cannot serialize process identity".to_string())?;
    let digest = Sha256::digest(bytes);
    ProcessRole::new(format!("observed:{digest:x}"))
        .map_err(|_| "invalid observation label".to_string())
}

pub fn value_id(
    role: &ProcessRole,
    key: &ValueKey,
    origin: &ValueOrigin,
) -> Result<ValueId, String> {
    // Tuple boundaries are encoded by serde: origin/key/role strings cannot collide by joining.
    let bytes = serde_json::to_vec(&(origin, key, role))
        .map_err(|_| "cannot serialize value identity".to_string())?;
    let digest = Sha256::digest(bytes);
    ValueId::new(format!("value:{digest:x}")).map_err(|_| "invalid value identity".to_string())
}
