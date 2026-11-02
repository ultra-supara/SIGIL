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

/// Project minimized process facts into requested-read coverage without additional I/O.
/// Complete describes individual successful reads, not an atomic process snapshot.
pub fn observed_coverage(facts: &crate::observe::proc::ProcFacts) -> Vec<sigil_model::Coverage> {
    use sigil_model::{
        CheckId, Coverage, CoverageState, NotObservable, Observability, Ref, Unavailability,
    };
    let Ok(check) = CheckId::new("values.observed") else {
        return vec![];
    };
    let entry = |scope, state| Coverage {
        check: check.clone(),
        scope,
        state,
        budget: None,
    };
    let mut missing = vec![];
    if let Observability::NotObservable(why) = facts.process_list {
        missing.push(format!(
            "the process list was not read to its end ({why:?}); process values may be missing"
        ));
    } else if !facts.pid1_visible {
        missing.push(format!(
            "PID 1 is not visible ({:?}); hidden processes may have unobserved values",
            NotObservable::PermissionDenied
        ));
    }
    missing.extend(facts.process_gaps.iter().cloned());
    missing.extend(facts.value_gaps.iter().cloned());
    for detail in &facts.value_details {
        for gap in &detail.missing {
            if gap.contains("process_values") || gap.contains("proc_environ_total_bytes") {
                missing.push(format!("process {}: {gap}", detail.process.pid));
            }
        }
    }
    missing.sort();
    missing.dedup();
    let audit = if missing.is_empty() {
        CoverageState::Complete
    } else {
        CoverageState::Partial { missing }
    };
    let mut out = vec![entry(Ref::Audit, audit)];
    for detail in &facts.value_details {
        let state = if detail.denied {
            CoverageState::Unavailable {
                why: Unavailability::PermissionDenied,
            }
        } else if detail.missing.is_empty() {
            CoverageState::Complete
        } else {
            CoverageState::Partial {
                missing: detail.missing.clone(),
            }
        };
        out.push(entry(Ref::Process(detail.process.clone()), state));
    }
    for process in &facts.value_outside {
        out.push(entry(
            Ref::Process(process.clone()),
            CoverageState::OutOfScope {
                why: "the recorded listener holder is outside the runtime and its descendants"
                    .into(),
            },
        ));
    }
    out
}
