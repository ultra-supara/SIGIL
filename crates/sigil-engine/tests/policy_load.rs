//! Loading `sigil-policy/1` (plan §4.7): what loads, what the default requires, and every input
//! that must be fatal rather than silently ignored.

use sigil_engine::policy::{catalog, Policy, PolicyError, TrustedPrincipal};
use sigil_model::{Action, KnowledgeKind, Mode, OqTreatment, RuleId};

fn ids<T: std::fmt::Display>(items: &[T]) -> Vec<String> {
    items.iter().map(ToString::to_string).collect()
}

#[test]
fn the_default_policy_requires_only_implemented_scopes() {
    let policy = Policy::builtin_default().unwrap();
    assert_eq!(policy.name, "default");
    let (audit, required) = policy.scope(Mode::Static);
    assert_eq!(ids(&audit), ["model_store"]);
    assert_eq!(
        ids(&required),
        [
            "model_store.inventory",
            "model_store.integrity",
            "model_store.license"
        ]
    );
    let (audit, required) = policy.scope(Mode::Observe);
    assert_eq!(ids(&audit), ["model_store", "exposure"]);
    assert_eq!(
        ids(&required),
        [
            "model_store.inventory",
            "model_store.integrity",
            "model_store.license",
            "exposure.binds"
        ]
    );
    assert_eq!(policy.open_questions.treatment, OqTreatment::CountAsGap);
    assert!(policy.accept.is_empty() && policy.rules.is_empty() && policy.deny.is_empty());
    assert_eq!(
        policy.trust.principals,
        [TrustedPrincipal::Root, TrustedPrincipal::Runtime]
    );
}

/// The plan's §4.7 example, plus `observe_audit`.
const PLAN_EXAMPLE: &str = r#"
schema = "sigil-policy/1"
name   = "default"

[scope]
audit = ["model_store", "runtime_artifacts", "backend_loader"]
observe_audit = ["exposure"]
extra_required = []

[open_questions]
default = "count_as_gap"

[assumptions]
accept = []

[rules."exposure.bind_public"]
action = "fail"

[rules."model.license_missing"]
action  = "ignore"
reason  = "Internal models have no license layer by design"
expires = "2027-03-31"

[trust]
principals   = ["root", "runtime"]
extra_groups = []

[[components.deny]]
component = "ggml-backend/rpc"
action    = "fail"
reason    = "The RPC backend is outside the internal standard"
"#;

#[test]
fn the_plan_example_loads() {
    let policy = Policy::load(PLAN_EXAMPLE).unwrap();
    let (_, required) = policy.scope(Mode::Static);
    assert_eq!(
        ids(&required),
        [
            "model_store.inventory",
            "model_store.integrity",
            "model_store.license",
            "artifacts.discovery",
            "loader.identify",
            "loader.search_paths",
        ]
    );
    let public = &policy.rules[&RuleId::new("exposure.bind_public").unwrap()];
    assert_eq!(public.action, Action::Fail);
    let license = &policy.rules[&RuleId::new("model.license_missing").unwrap()];
    assert_eq!(license.action, Action::Ignore);
    assert_eq!(license.expires.as_ref().unwrap().as_str(), "2027-03-31");
    assert_eq!(policy.deny.len(), 1);
    assert_eq!(policy.deny[0].component.as_str(), "ggml-backend/rpc");
}

#[test]
fn a_bare_toml_date_is_accepted_for_expires() {
    let text = PLAN_EXAMPLE.replace("expires = \"2027-03-31\"", "expires = 2027-03-31");
    let policy = Policy::load(&text).unwrap();
    let license = &policy.rules[&RuleId::new("model.license_missing").unwrap()];
    assert_eq!(license.expires.as_ref().unwrap().as_str(), "2027-03-31");
}

#[test]
fn extra_keys_trust_and_assumptions_are_validated() {
    let text = r#"
schema = "sigil-policy/1"
name = "strict"
[scope]
audit = ["model_store"]
extra_required = ["exposure.binds"]
[open_questions]
default = "warn"
[assumptions]
accept = ["A-3"]
[trust]
principals = ["root", "uid:1000"]
extra_groups = ["gid:27"]
"#;
    let policy = Policy::load(text).unwrap();
    let (_, required) = policy.scope(Mode::Static);
    assert_eq!(required.last().unwrap().as_str(), "exposure.binds");
    assert_eq!(policy.open_questions.treatment, OqTreatment::Warn);
    assert_eq!(ids(&policy.accept), ["A-3"]);
    assert_eq!(
        policy.trust.principals,
        [TrustedPrincipal::Root, TrustedPrincipal::Uid(1000)]
    );
    assert_eq!(policy.trust.extra_groups, [27]);
}

fn fails(text: &str) -> PolicyError {
    match Policy::load(text) {
        Ok(_) => panic!("loaded:\n{text}"),
        Err(e) => e,
    }
}

/// Whether an error is the expected one.
type Expect = fn(&PolicyError) -> bool;

const HEAD: &str = "schema = \"sigil-policy/1\"\nname = \"t\"\n";

#[test]
fn every_unknown_or_malformed_input_is_fatal() {
    use PolicyError as E;
    let cases: Vec<(String, Expect)> = vec![
        (format!("{HEAD}color = \"red\"\n"), |e| matches!(e, E::Syntax(_))),
        (
            format!("{HEAD}[rules.\"exposure.bind_public\"]\naction = \"fail\"\nseverity = 3\n"),
            |e| matches!(e, E::Syntax(_)),
        ),
        (
            "schema = \"sigil-policy/2\"\nname = \"t\"\n".to_string(),
            |e| matches!(e, E::Schema(_)),
        ),
        (
            format!("{HEAD}[rules.\"model.unheard_of\"]\naction = \"warn\"\n"),
            |e| matches!(e, E::UnknownRule(r) if r == "model.unheard_of"),
        ),
        (
            format!("{HEAD}[scope]\naudit = [\"gpu_drivers\"]\n"),
            |e| matches!(e, E::UnknownScope(s) if s == "gpu_drivers"),
        ),
        (
            format!("{HEAD}[scope]\nobserve_audit = [\"gpu_drivers\"]\n"),
            |e| matches!(e, E::UnknownScope(_)),
        ),
        (
            format!("{HEAD}[scope]\nextra_required = [\"exposure.everything\"]\n"),
            |e| matches!(e, E::UnknownCheck(c) if c == "exposure.everything"),
        ),
        (
            format!("{HEAD}[assumptions]\naccept = [\"A-9\"]\n"),
            |e| matches!(e, E::UnknownAssumption(a) if a == "A-9"),
        ),
        (
            format!(
                "{HEAD}[rules.\"model.license_missing\"]\naction = \"ignore\"\nreason = \"r\"\nexpires = \"2027-3-31\"\n"
            ),
            |e| matches!(e, E::BadDate { .. }),
        ),
        (
            format!("{HEAD}[rules.\"model.license_missing\"]\naction = \"ignore\"\n"),
            |e| matches!(e, E::IgnoreWithoutReason { .. }),
        ),
        (
            format!(
                "{HEAD}[rules.\"model.license_missing\"]\naction = \"ignore\"\nreason = \"  \"\n"
            ),
            |e| matches!(e, E::IgnoreWithoutReason { .. }),
        ),
        (
            format!("{HEAD}[open_questions]\ndefault = \"ignore\"\n"),
            |e| matches!(e, E::IgnoreWithoutReason { .. }),
        ),
        (
            format!("{HEAD}[rules.\"model.license_missing\"]\naction = \"drop\"\n"),
            |e| matches!(e, E::Syntax(_)),
        ),
        (
            format!("{HEAD}[trust]\nprincipals = [\"admin\"]\n"),
            |e| matches!(e, E::BadPrincipal(p) if p == "admin"),
        ),
        (
            format!("{HEAD}[trust]\nextra_groups = [\"wheel\"]\n"),
            |e| matches!(e, E::BadGroup(g) if g == "wheel"),
        ),
        (
            format!("{HEAD}[[components.deny]]\ncomponent = \"x\"\naction = \"ignore\"\nreason = \"r\"\n"),
            |e| matches!(e, E::BadDenyAction { .. }),
        ),
        (
            format!(
                "{HEAD}[[components.deny]]\ncomponent = \"x\"\naction = \"fail\"\nreason = \"r\"\n[[components.deny]]\ncomponent = \"x\"\naction = \"warn\"\nreason = \"r\"\n"
            ),
            |e| matches!(e, E::DuplicateDeny(c) if c == "x"),
        ),
        (
            format!("{HEAD}[[components.deny]]\ncomponent = \"x\"\naction = \"fail\"\nreason = \"\"\n"),
            |e| matches!(e, E::DenyWithoutReason { .. }),
        ),
        ("schema = \"sigil-policy/1\"\nname = \"\"\n".to_string(), |e| {
            matches!(e, E::BadName(_))
        }),
        ("not toml at all [".to_string(), |e| matches!(e, E::Syntax(_))),
    ];
    for (text, expected) in cases {
        let error = fails(&text);
        assert!(expected(&error), "wrong error {error:?} for:\n{text}");
        assert!(!error.to_string().is_empty());
    }
}

#[test]
fn the_policy_hash_follows_the_text() {
    let a = Policy::load(PLAN_EXAMPLE).unwrap().knowledge();
    let b = Policy::load(&PLAN_EXAMPLE.replace("by design", "by design."))
        .unwrap()
        .knowledge();
    assert_eq!(a.kind, KnowledgeKind::Policy);
    assert_eq!(
        (a.id.as_str(), a.version.as_str()),
        ("default", "sigil-policy/1")
    );
    assert_ne!(a.sha256, b.sha256);
}

#[test]
fn the_catalogs_are_consistent() {
    // Every scope's checks are known checks, every rule has a default, and the IDs are valid.
    for scope in catalog::SCOPES {
        assert!(sigil_model::AuditScope::new(scope.id).is_ok());
        for check in scope.checks {
            assert!(sigil_model::CheckId::new(*check).is_ok());
        }
    }
    for rule in catalog::RULES {
        assert!(sigil_model::RuleId::new(rule.id).is_ok());
    }
    let malformed = catalog::rule("model.manifest_digest_malformed").unwrap();
    assert_eq!(malformed.default, sigil_model::Severity::Fail);
    assert_eq!(
        catalog::ASSUMPTIONS
            .iter()
            .map(|a| a.id)
            .collect::<Vec<_>>(),
        ["A-1", "A-2", "A-3", "A-4"]
    );
}
