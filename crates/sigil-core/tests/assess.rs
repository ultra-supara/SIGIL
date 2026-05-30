use sigil_core::assess::{
    capability_for_symbol, evaluate_policy, load_policy, Policy, PolicyViolation, Verdict,
};
use sigil_core::evidence::{CapabilityEvidence, Evidence, ExternalCall};
use std::path::PathBuf;

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap()
        .join(path)
}

#[test]
fn maps_symbols_to_capabilities() {
    assert_eq!(capability_for_symbol("connect"), Some("network"));
    assert_eq!(capability_for_symbol("getaddrinfo"), Some("network"));
    assert_eq!(capability_for_symbol("openat"), Some("file_read"));
    assert_eq!(capability_for_symbol("rename"), Some("file_write"));
    assert_eq!(capability_for_symbol("unlink"), Some("file_write"));
    assert_eq!(capability_for_symbol("dlopen"), Some("dynamic_loading"));
    assert_eq!(capability_for_symbol("getenv"), Some("environment_access"));
    assert_eq!(capability_for_symbol("unknown_symbol"), None);
}

#[test]
fn policy_passes_for_allowed_arithmetic() {
    let policy = load_policy(fixture("examples/policies/numeric_kernel.yml")).unwrap();
    let result = evaluate_policy(&policy, ["arithmetic"]);
    assert_eq!(result.verdict, Verdict::Pass);
    assert!(result.violations.is_empty());
}

#[test]
fn policy_fails_for_forbidden_network() {
    let policy = load_policy(fixture("examples/policies/numeric_kernel.yml")).unwrap();
    let result = evaluate_policy(&policy, ["network"]);
    assert_eq!(result.verdict, Verdict::Fail);
    assert_eq!(
        result.violations,
        vec![
            PolicyViolation::new("forbidden.capabilities.network", "network")
                .with_severity(Verdict::Fail),
            PolicyViolation::new("allowed.capabilities.network", "network")
                .with_severity(Verdict::Fail),
        ]
    );
}

#[test]
fn policy_records_per_rule_severity_when_mixed() {
    let policy = Policy::new(
        "mixed",
        ["arithmetic"],
        ["network"],
        [
            ("forbidden_capability", "WARN"),
            ("allowlist_violation", "FAIL"),
        ],
    );
    let result = evaluate_policy(&policy, ["network"]);
    assert_eq!(result.verdict, Verdict::Fail);
    let severities: Vec<_> = result
        .violations
        .iter()
        .map(|v| (v.rule.as_str(), v.severity))
        .collect();
    assert_eq!(
        severities,
        vec![
            ("forbidden.capabilities.network", Verdict::Warn),
            ("allowed.capabilities.network", Verdict::Fail),
        ]
    );
}

#[test]
fn policy_can_warn_for_forbidden_capability() {
    let policy = Policy::new(
        "warn_policy",
        [],
        ["network"],
        [("forbidden_capability", "WARN")],
    );
    let result = evaluate_policy(&policy, ["network"]);
    assert_eq!(result.verdict, Verdict::Warn);
}

#[test]
fn evidence_json_uses_stable_fields() {
    let evidence = Evidence {
        binary: "sample.o".to_string(),
        entry: "kernel".to_string(),
        verdict: Verdict::Fail,
        capabilities: vec![CapabilityEvidence {
            name: "network".to_string(),
            evidence: vec![],
        }],
        external_calls: vec![ExternalCall {
            symbol: "connect".to_string(),
            capability: Some("network".to_string()),
            address: "unknown".to_string(),
        }],
        unsupported_instructions: vec![],
        policy_violations: vec![PolicyViolation::new(
            "forbidden.capabilities.network",
            "network",
        )],
    };

    let json = evidence.to_json().unwrap();
    assert!(json.contains("\"verdict\": \"FAIL\""));
    assert!(json.contains("\"external_calls\""));
    assert!(json.contains("\"policy_violations\""));
}
