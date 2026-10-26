//! Whether a saved session is what its policy gives (#51, plan review P2-2).
//!
//! `Session::validate` checks that a session agrees with itself: a capability violation cites
//! every direct call of its feature's imports, a gap is an open question of the session, and so
//! on. It cannot know what a policy should have decided, since a session records its policy's name
//! and SHA-256, not its rules: one whose violation was removed and whose outcome was set to PASS
//! still validates. [`verify`] evaluates a copy under the policy and compares. It checks what the
//! policy makes of the recorded analysis at the recorded policy time, not the analysis itself:
//! only inspecting the files again does that.

use std::collections::BTreeSet;

use sigil_model::render::{completeness, kind, severity, subject, verdict};
use sigil_model::{KnowledgeKind, Session};

use super::{catalog, evaluate, Policy};

/// Whether `session` is exactly what evaluating it under `policy` gives: `Ok`, or each difference
/// in words.
///
/// - The session names the policy: its one `Policy` knowledge entry has the policy's name and
///   SHA-256.
/// - Each finding's rule is in this build's rule catalog, with the kind and default severity the
///   session records: a finding's default decision rests on them, and the session only records
///   them.
/// - Evaluating a copy under the policy, at the session's recorded `policy_time`, succeeds: a
///   session the policy cannot judge (other required checks, another capability table) is a
///   difference.
/// - The copy equals the session in canonical form. Findings and open questions are named by ID,
///   policy violations by rule and subject; the outcome by verdict and completeness.
///
/// What the policy gives is what this build gives: component denials are matched through its
/// component database and capability denials judged with its capability table, so a session that
/// a build with other data made may differ. The analysis (findings, their conditions and
/// evidence, hints, call sites, coverage, the request) and the policy time are the session's:
/// verify checks what the policy makes of them, not them.
pub fn verify(session: &Session, policy: &Policy) -> Result<(), Vec<String>> {
    let ours = policy.knowledge();
    let named: Vec<_> = session
        .knowledge
        .iter()
        .filter(|k| k.kind == KnowledgeKind::Policy)
        .collect();
    if named.as_slice() != [&ours] {
        let shown: Vec<String> = named
            .iter()
            .map(|k| format!("{} {} ({})", k.id, k.version, k.sha256))
            .collect();
        let shown = if shown.is_empty() {
            "none".to_string()
        } else {
            shown.join(", ")
        };
        return Err(vec![format!(
            "the session records the policy {shown}, not {} {} ({})",
            ours.id, ours.version, ours.sha256
        )]);
    }
    let mut differences = vec![];
    for f in &session.findings {
        match catalog::rule(f.rule.as_str()) {
            None => differences.push(format!(
                "finding {}: rule {} is not in this build's rule catalog",
                f.id, f.rule
            )),
            Some(r) if r.kind != f.kind || r.default != f.default_severity => {
                differences.push(format!(
                    "finding {}: the session records rule {} as {} {}, and this build's catalog \
                     as {} {}",
                    f.id,
                    f.rule,
                    kind(f.kind),
                    severity(f.default_severity),
                    kind(r.kind),
                    severity(r.default)
                ))
            }
            Some(_) => {}
        }
    }
    let mut given = session.clone();
    if let Err(e) = evaluate(&mut given, policy, session.outcome.policy_time.clone()) {
        differences.push(format!("the policy cannot evaluate the session: {e}"));
        return Err(differences);
    }
    let mut recorded = session.clone();
    recorded.canonicalize();
    given.canonicalize();
    differ(
        &mut differences,
        "findings",
        &recorded.findings,
        &given.findings,
        |f| f.id.to_string(),
    );
    differ(
        &mut differences,
        "open questions",
        &recorded.open_questions,
        &given.open_questions,
        |q| q.id.to_string(),
    );
    differ(
        &mut differences,
        "policy violations",
        &recorded.policy_violations,
        &given.policy_violations,
        |v| format!("{} on {}", v.policy_rule, subject(&v.subject)),
    );
    if recorded.outcome != given.outcome {
        let words = |s: &Session| {
            format!(
                "{} + {}",
                verdict(s.outcome.verdict),
                completeness(&s.outcome.completeness)
            )
        };
        let (is, gives) = (words(&recorded), words(&given));
        differences.push(if is == gives {
            format!("the outcome's gaps or counts are not what the policy gives ({is})")
        } else {
            format!("the outcome is {is}, and the policy gives {gives}")
        });
    }
    if differences.is_empty() && recorded != given {
        differences.push("the session differs from what the policy gives".to_string());
    }
    if differences.is_empty() {
        Ok(())
    } else {
        Err(differences)
    }
}

/// How two lists differ, each item by `name`: the ones the policy gives that the session lacks,
/// the ones the session records otherwise, and the ones the policy does not give at all.
fn differ<T: PartialEq>(
    out: &mut Vec<String>,
    what: &str,
    recorded: &[T],
    given: &[T],
    name: impl Fn(&T) -> String,
) {
    let named = |list: &[T]| list.iter().map(&name).collect::<BTreeSet<String>>();
    let (recorded_names, given_names) = (named(recorded), named(given));
    let (mut missing, mut changed, mut extra) = (vec![], vec![], vec![]);
    for x in given.iter().filter(|x| !recorded.contains(x)) {
        let n = name(x);
        if recorded_names.contains(&n) {
            changed.push(n);
        } else {
            missing.push(n);
        }
    }
    for x in recorded.iter().filter(|x| !given.contains(x)) {
        let n = name(x);
        if !given_names.contains(&n) {
            extra.push(n);
        }
    }
    for (list, how) in [
        (missing, "the policy gives, and the session lacks"),
        (
            changed,
            "the session records otherwise than the policy gives",
        ),
        (extra, "the session has, and the policy does not give"),
    ] {
        if !list.is_empty() {
            out.push(format!("{what} {how}: {}", list.join(", ")));
        }
    }
}
