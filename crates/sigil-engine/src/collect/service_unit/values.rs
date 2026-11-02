//! Supplied-file interpretation only. No manager environment, EnvironmentFile, drop-in, PAM,
//! account lookup, or predicted descendant configuration is read or inferred here.

use std::collections::{BTreeMap, BTreeSet};

use sigil_model::{
    ConfigRef, InstanceId, ProcessRole, ProcessValue, TriValue, UnknownReason, UntrustedText,
    ValueKey, ValueOrigin, RUNTIME_ROLE,
};

use super::{is_space, service_lines, ServiceLine, MAX_UNIT_VALUES, SERVICE_UNIT_VALUES};
use crate::analyze::values::{allowlisted_env, minimize_env, value_id, QUERIED_ENV};

struct Setting {
    key: ValueKey,
    value: TriValue,
    line: u32,
    directive: &'static str,
}

fn label(key: &ValueKey) -> String {
    match key {
        ValueKey::Cwd => "Cwd".to_string(),
        ValueKey::User => "User".to_string(),
        ValueKey::Group => "Group".to_string(),
        ValueKey::Env(name) => format!("Env({})", name.terminal_line()),
    }
}

fn unknown(what: String) -> TriValue {
    TriValue::Unknown {
        reason: UnknownReason::NotModeled { what },
    }
}

fn scalar(key: &[u8], raw: &[u8], line: u32) -> TriValue {
    if raw.is_empty() {
        return TriValue::Absent;
    }
    let supported = if key == b"WorkingDirectory" {
        raw.starts_with(b"/")
            && !raw
                .iter()
                .any(|&b| matches!(b, b'\\' | b'%' | b'$' | b'"' | b'\'' | 0..=0x1f | 0x7f))
    } else {
        raw.iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    };
    if supported {
        TriValue::Known(UntrustedText::from_bytes(raw))
    } else {
        let directive = if key == b"WorkingDirectory" {
            "WorkingDirectory"
        } else if key == b"User" {
            "User"
        } else {
            "Group"
        };
        unknown(format!("line {line}: unsupported {directive} syntax"))
    }
}

/// Token boundaries only. Values are copied only after a token's key is allowlisted. Quoting
/// across spaces is recognized; escapes/specifiers are subsequently refused, never decoded.
fn tokens(mut raw: &[u8]) -> Vec<&[u8]> {
    let mut out = vec![];
    while !raw.is_empty() {
        while raw.first().is_some_and(|b| is_space(*b)) {
            raw = &raw[1..];
        }
        if raw.is_empty() {
            break;
        }
        let mut quote = None;
        let mut end = raw.len();
        for (i, &b) in raw.iter().enumerate() {
            if let Some(q) = quote {
                if b == q {
                    quote = None;
                }
            } else if matches!(b, b'\'' | b'"') {
                quote = Some(b);
            } else if is_space(b) {
                end = i;
                break;
            }
        }
        out.push(&raw[..end]);
        raw = &raw[end..];
    }
    out
}

type EnvironmentToken = (Vec<u8>, Result<Vec<u8>, ()>);

/// Return None for unrelated keys. Return an Unknown payload for a recognizable allowlisted
/// name whose assignment syntax is unsupported, including a missing '=' or unclosed quote.
fn environment_token(raw: &[u8]) -> Option<EnvironmentToken> {
    let body = if matches!(raw.first(), Some(b'\'' | b'"')) {
        &raw[1..]
    } else {
        raw
    };
    let eq = body.iter().position(|b| *b == b'=');
    let name = eq.map_or(body, |eq| &body[..eq]);
    let name = name
        .strip_suffix(b"\"")
        .or_else(|| name.strip_suffix(b"'"))
        .unwrap_or(name);
    if !allowlisted_env(name) {
        return None;
    }
    let failed = || Some((name.to_vec(), Err(())));
    if raw
        .iter()
        .any(|&b| matches!(b, b'\\' | b'%' | 0..=0x1f | 0x7f))
    {
        return failed();
    }
    let Some(_) = eq else {
        return failed();
    };
    let assignment = if let Some(&quote @ (b'\'' | b'"')) = raw.first() {
        if raw.len() < 2 || raw.last() != Some(&quote) {
            return failed();
        }
        let inner = &raw[1..raw.len() - 1];
        if inner.contains(&b'\'') || inner.contains(&b'"') {
            return failed();
        }
        inner
    } else {
        raw
    };
    let Some(eq) = assignment.iter().position(|b| *b == b'=') else {
        return failed();
    };
    if &assignment[..eq] != name {
        return failed();
    }
    let value = &assignment[eq + 1..];
    let value = if let Some(&quote @ (b'\'' | b'"')) = value.first() {
        if value.len() < 2 || value.last() != Some(&quote) {
            return failed();
        }
        let inner = &value[1..value.len() - 1];
        if inner.contains(&b'\'') || inner.contains(&b'"') {
            return failed();
        }
        inner
    } else {
        if value.contains(&b'\'') || value.contains(&b'"') {
            return failed();
        }
        value
    };
    Some((name.to_vec(), Ok(value.to_vec())))
}

fn anonymous_malformed(token: &[u8]) -> bool {
    let mut quote = None;
    for &b in token {
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
        } else if matches!(b, b'\'' | b'"') {
            quote = Some(b);
        }
    }
    quote.is_some() || !token.contains(&b'=')
}

/// Charge retained records before inserting. Three scalar predictions plus nine queried-name
/// predictions are reserved initially; each retained wildcard adds its own prediction slot.
fn can_add(
    configured: &BTreeMap<String, Setting>,
    env_names: &BTreeSet<Vec<u8>>,
    settings: usize,
    names: usize,
) -> bool {
    (configured.len() as u64)
        .saturating_add(env_names.len() as u64)
        .saturating_add(3)
        .saturating_add(settings as u64)
        .saturating_add(names as u64)
        <= MAX_UNIT_VALUES
}

fn affected(directive: &str, key: &ValueKey) -> bool {
    match directive {
        "EnvironmentFile" | "PassEnvironment" | "UnsetEnvironment" => {
            matches!(key, ValueKey::Env(_))
        }
        "DynamicUser" => matches!(key, ValueKey::User | ValueKey::Group),
        "PAMName" => matches!(key, ValueKey::Env(_) | ValueKey::User | ValueKey::Group),
        _ => false,
    }
}

pub(super) fn parse(
    text: &[u8],
    file: &InstanceId,
) -> Result<(Vec<ProcessValue>, Vec<String>), String> {
    let role = ProcessRole::new(RUNTIME_ROLE).map_err(|_| "invalid runtime role".to_string())?;
    let mut configured: BTreeMap<String, Setting> = BTreeMap::new();
    let mut env_names: BTreeSet<Vec<u8>> = QUERIED_ENV.iter().map(|n| n.to_vec()).collect();
    let mut blockers: BTreeMap<&'static str, u32> = BTreeMap::new();
    let mut environment_gaps = BTreeSet::new();
    let mut value_limit_exceeded = false;
    for line in service_lines(text)? {
        let ServiceLine { key, value, number } = line?;
        let scalar_key = match key {
            b"User" => Some((ValueKey::User, "User")),
            b"Group" => Some((ValueKey::Group, "Group")),
            b"WorkingDirectory" => Some((ValueKey::Cwd, "WorkingDirectory")),
            _ => None,
        };
        if let Some((value_key, directive)) = scalar_key {
            let delta = usize::from(!configured.contains_key(&label(&value_key)));
            if !can_add(&configured, &env_names, delta, 0) {
                value_limit_exceeded = true;
                continue;
            }
            configured.insert(
                label(&value_key),
                Setting {
                    key: value_key,
                    value: scalar(key, value, number),
                    line: number,
                    directive,
                },
            );
            continue;
        }
        if key == b"Environment" {
            if value.is_empty() {
                configured.retain(|_, setting| !matches!(setting.key, ValueKey::Env(_)));
                environment_gaps.clear();
            }
            for token in tokens(value) {
                let Some((name, parsed)) = environment_token(token) else {
                    if anonymous_malformed(token) {
                        environment_gaps.insert(format!("line {number}: unsupported Environment syntax; affected allowlisted keys unknown"));
                    }
                    continue;
                };
                let key = ValueKey::Env(UntrustedText::from_bytes(name.as_slice()));
                let setting_delta = usize::from(!configured.contains_key(&label(&key)));
                let name_delta = usize::from(!env_names.contains(&name));
                if !can_add(&configured, &env_names, setting_delta, name_delta) {
                    value_limit_exceeded = true;
                    continue;
                }
                env_names.insert(name.clone());
                let value = match parsed {
                    Ok(bytes) => TriValue::Known(minimize_env(&name, &bytes)),
                    Err(()) => unknown(format!(
                        "line {number}: unsupported Environment syntax for {}",
                        label(&key)
                    )),
                };
                configured.insert(
                    label(&key),
                    Setting {
                        key,
                        value,
                        line: number,
                        directive: "Environment",
                    },
                );
            }
            continue;
        }
        let blocker = match key {
            b"EnvironmentFile" => Some("EnvironmentFile"),
            b"PassEnvironment" => Some("PassEnvironment"),
            b"UnsetEnvironment" => Some("UnsetEnvironment"),
            b"DynamicUser" => Some("DynamicUser"),
            b"PAMName" => Some("PAMName"),
            _ => None,
        };
        if let Some(blocker) = blocker {
            if value.is_empty() {
                blockers.remove(blocker);
            } else {
                blockers.insert(blocker, number);
                if matches!(blocker, "PassEnvironment" | "UnsetEnvironment") {
                    for token in tokens(value) {
                        // tokens() retains whole-token quotes; they are syntax, not name bytes.
                        let token = match token {
                            [quote @ (b'\'' | b'"'), inner @ .., end] if quote == end => inner,
                            _ => token,
                        };
                        let name = token.split(|b| *b == b'=').next().unwrap_or_default();
                        if allowlisted_env(name) && !env_names.contains(name) {
                            if can_add(&configured, &env_names, 0, 1) {
                                env_names.insert(name.to_vec());
                            } else {
                                value_limit_exceeded = true;
                            }
                        }
                    }
                }
            }
        }
    }
    let mut values = vec![];
    let mut gaps =
        vec!["supplied unit only: drop-ins and effective unit selection unexamined".to_string()];
    gaps.extend(environment_gaps);
    if value_limit_exceeded {
        gaps.push(format!("{SERVICE_UNIT_VALUES} {MAX_UNIT_VALUES} exceeded"));
    }
    let mut configured_ids = BTreeMap::new();
    for setting in configured.values() {
        if let TriValue::Unknown {
            reason: UnknownReason::NotModeled { what },
        } = &setting.value
        {
            gaps.push(what.clone());
        }
        let origin = ValueOrigin::Configured {
            file: ConfigRef {
                file: file.clone(),
                key: UntrustedText::new(setting.directive),
                line: setting.line,
            },
            directive: UntrustedText::new(setting.directive),
        };
        let id = value_id(&role, &setting.key, &origin)?;
        configured_ids.insert(label(&setting.key), id.clone());
        values.push(ProcessValue {
            id,
            process_role: role.clone(),
            key: setting.key.clone(),
            value: setting.value.clone(),
            origin,
            applies_to: vec![],
        });
    }
    let mut predicted_keys = vec![ValueKey::Cwd, ValueKey::User, ValueKey::Group];
    predicted_keys.extend(
        env_names
            .into_iter()
            .map(|name| ValueKey::Env(UntrustedText::from_bytes(name))),
    );
    for key in predicted_keys {
        let mut reasons = vec![
            "drop-ins unexamined".to_string(),
            "effective unit selection unexamined".to_string(),
        ];
        for (directive, line) in &blockers {
            if affected(directive, &key) {
                let reason = format!("{}: {directive} at line {line} is unmodeled", label(&key));
                gaps.push(reason.clone());
                reasons.push(reason);
            }
        }
        let from: Vec<_> = configured_ids
            .get(&label(&key))
            .cloned()
            .into_iter()
            .collect();
        if from.is_empty() {
            let reason = format!(
                "{}: not set in supplied unit; effective value remains unknown",
                label(&key)
            );
            gaps.push(reason.clone());
            reasons.push(reason);
        } else if let Some(Setting {
            value:
                TriValue::Unknown {
                    reason: UnknownReason::NotModeled { what },
                },
            ..
        }) = configured.get(&label(&key))
        {
            reasons.push(what.clone());
        }
        let origin = ValueOrigin::PredictedLaunch {
            rules: vec!["systemd.supplied-unit-only@1".to_string()],
            from,
        };
        values.push(ProcessValue {
            id: value_id(&role, &key, &origin)?,
            process_role: role.clone(),
            key,
            value: unknown(reasons.join("; ")),
            origin,
            applies_to: vec![],
        });
    }
    values.sort_by(|a, b| a.id.cmp(&b.id));
    gaps.sort();
    gaps.dedup();
    Ok((values, gaps))
}
