//! Loading `sigil-policy/1` (plan §4.7): what loads, what the default requires, and every input
//! that must be fatal rather than silently ignored.

use sigil_engine::policy::{catalog, Policy, PolicyError, ScopeInput, TrustedPrincipal};
use sigil_model::{Action, KnowledgeKind, Mode, OqTreatment, RuleId};

fn ids<T: std::fmt::Display>(items: &[T]) -> Vec<String> {
    items.iter().map(ToString::to_string).collect()
}

#[test]
fn the_default_policy_requires_only_implemented_scopes() {
    let policy = Policy::builtin_default().unwrap();
    assert_eq!(policy.name, "default");
    let (audit, required) = policy.scope(&ScopeInput {
        mode: Mode::Static,
        active: false,
        install: false,
        binary: false,
        code: false,
    });
    assert_eq!(ids(&audit), ["model_store"]);
    assert_eq!(
        ids(&required),
        [
            "model_store.inventory",
            "model_store.integrity",
            "model_store.license"
        ]
    );
    let (audit, required) = policy.scope(&ScopeInput {
        mode: Mode::Observe,
        active: false,
        install: false,
        binary: false,
        code: false,
    });
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
    let (_, required) = policy.scope(&ScopeInput {
        mode: Mode::Static,
        active: false,
        install: false,
        binary: false,
        code: false,
    });
    assert_eq!(
        ids(&required),
        [
            "model_store.inventory",
            "model_store.integrity",
            "model_store.license",
            "artifacts.discovery",
            "artifacts.release",
            "artifacts.container",
            "artifacts.identity",
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
    let (_, required) = policy.scope(&ScopeInput {
        mode: Mode::Static,
        active: false,
        install: false,
        binary: false,
        code: false,
    });
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
            format!("{HEAD}[[components.deny]]\ncomponent = \"ggml\"\naction = \"ignore\"\nreason = \"r\"\n"),
            |e| matches!(e, E::BadDenyAction { .. }),
        ),
        (
            format!(
                "{HEAD}[[components.deny]]\ncomponent = \"ggml\"\naction = \"fail\"\nreason = \"r\"\n[[components.deny]]\ncomponent = \"ggml\"\naction = \"warn\"\nreason = \"r\"\n"
            ),
            |e| matches!(e, E::DuplicateDeny(c) if c == "ggml"),
        ),
        (
            format!("{HEAD}[[components.deny]]\ncomponent = \"ggml\"\naction = \"fail\"\nreason = \"\"\n"),
            |e| matches!(e, E::DenyWithoutReason { .. }),
        ),
        (
            format!("{HEAD}[[components.deny]]\ncomponent = \"x\"\naction = \"fail\"\nreason = \"r\"\n"),
            |e| matches!(e, E::UnknownComponent(c) if c == "x"),
        ),
        (
            format!("{HEAD}[[capabilities.deny]]\nfeature = \"posix.network\"\naction = \"ignore\"\nreason = \"r\"\n"),
            |e| matches!(e, E::BadCapabilityAction { feature } if feature == "posix.network"),
        ),
        (
            format!(
                "{HEAD}[[capabilities.deny]]\nfeature = \"posix.network\"\naction = \"fail\"\nreason = \"r\"\n[[capabilities.deny]]\nfeature = \"posix.network\"\naction = \"warn\"\nreason = \"r\"\n"
            ),
            |e| matches!(e, E::DuplicateCapabilityDeny(f) if f == "posix.network"),
        ),
        (
            format!("{HEAD}[[capabilities.deny]]\nfeature = \"posix.network\"\naction = \"fail\"\nreason = \" \"\n"),
            |e| matches!(e, E::CapabilityDenyWithoutReason { feature } if feature == "posix.network"),
        ),
        (
            format!("{HEAD}[[capabilities.deny]]\nfeature = \"posix.network\"\naction = \"fail\"\nreason = \"r\"\nexpires = \"2027-01-01\"\n"),
            |e| matches!(e, E::Syntax(_)),
        ),
        // A misspelt table is refused, never read as a policy that denies nothing.
        (
            format!("{HEAD}[[capabilities.denied]]\nfeature = \"posix.network\"\naction = \"fail\"\nreason = \"r\"\n"),
            |e| matches!(e, E::Syntax(_)),
        ),
        (
            format!("{HEAD}[[capabilities.deny]]\nfeature = \"posix.network\"\naction = \"fail\"\n"),
            |e| matches!(e, E::Syntax(_)),
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

/// A deny entry names a component of the embedded database (`signatures/components.toml`): a
/// typo or a component SIGIL does not identify would otherwise match nothing, silently.
#[test]
fn a_deny_entry_must_name_a_component_sigil_identifies() {
    let deny = |component: &str| {
        format!(
            "{HEAD}[[components.deny]]\ncomponent = \"{component}\"\naction = \"warn\"\nreason = \"r\"\n"
        )
    };
    for known in ["ggml-backend/rpc", "llama.cpp/common", "ollama"] {
        let policy = Policy::load(&deny(known)).unwrap_or_else(|e| panic!("{known}: {e}"));
        assert_eq!(
            ids(&policy.deny.iter().map(|d| &d.component).collect::<Vec<_>>()),
            [known]
        );
    }
    for unknown in ["llama.cpp/comon", "ggml-backend/metal", "llama.cpp/llama"] {
        let error = fails(&deny(unknown));
        assert_eq!(error, PolicyError::UnknownComponent(unknown.to_string()));
        assert_eq!(
            error.to_string(),
            format!("components.deny \"{unknown}\": not a component SIGIL identifies")
        );
    }
    // A key that is not a valid component key at all is still an ID error, as before.
    assert!(matches!(fails(&deny(" ggml")), PolicyError::BadId(_)));
}

/// #51: a denial names a key of the capability-import table (`signatures/capabilities.toml`),
/// whose imports have call sites to judge. Any other key would match nothing, silently.
#[test]
fn a_capability_denial_must_name_a_capability_import_key() {
    let deny = |feature: &str| {
        format!(
            "{HEAD}[[capabilities.deny]]\nfeature = \"{feature}\"\naction = \"fail\"\nreason = \"not here\"\n"
        )
    };
    let policy = Policy::load(&format!(
        "{}[[capabilities.deny]]\nfeature = \"cxx.file_write\"\naction = \"warn\"\nreason = \"r\"\n",
        deny("posix.process_spawn")
    ))
    .unwrap();
    let got: Vec<(&str, Action, &str)> = policy
        .capabilities
        .iter()
        .map(|d| (d.feature.as_str(), d.action, d.reason.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            ("posix.process_spawn", Action::Fail, "not here"),
            ("cxx.file_write", Action::Warn, "r"),
        ]
    );
    let keys = "cxx.file_read, cxx.file_write, posix.anti_debug, posix.dynamic_loading, \
                posix.environment_access, posix.file_read, posix.file_write, posix.network, \
                posix.process_spawn";
    for unknown in ["posix.netwrok", "network", "cxx.process_spawn"] {
        let error = fails(&deny(unknown));
        assert!(
            matches!(&error, PolicyError::UnknownCapability { feature, .. } if feature == unknown)
        );
        assert_eq!(
            error.to_string(),
            format!(
                "capabilities.deny {unknown:?}: not a capability import; a policy can deny {keys}"
            )
        );
    }
    // A signature hint has no call sites to judge, and the error says so.
    for signature in [
        "go.process_spawn",
        "ollama.device_discovery",
        "rpc.code_present",
    ] {
        let error = fails(&deny(signature));
        assert_eq!(
            error.to_string(),
            format!(
                "capabilities.deny {signature:?}: not a capability import (go.*, ollama.*, and \
                 rpc.* hints are names found in a file, with no call sites to judge); a policy \
                 can deny {keys}"
            )
        );
    }
    // Every namespace of the embedded needle database is one the error names: a new one there
    // is noticed here.
    let db = sigil_engine::binary::needles::needles().unwrap();
    for kind in [
        sigil_engine::binary::needles::NeedleKind::Export,
        sigil_engine::binary::needles::NeedleKind::GoFunction,
        sigil_engine::binary::needles::NeedleKind::String,
    ] {
        for needle in db.of(kind) {
            let error = fails(&deny(needle.feature.as_str()));
            assert!(
                error
                    .to_string()
                    .contains("hints are names found in a file"),
                "{}: {error}",
                needle.feature
            );
        }
    }
    // A key that is not a valid feature key at all is an ID error, as for components.
    assert!(matches!(
        fails(&deny(" posix.network")),
        PolicyError::BadId(_)
    ));
    // Without the table, a policy denies no capability.
    assert!(Policy::load(HEAD).unwrap().capabilities.is_empty());
    assert!(Policy::builtin_default().unwrap().capabilities.is_empty());
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

#[test]
fn the_documented_example_loads() {
    let doc = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/policy.md"),
    )
    .unwrap();
    let block: String = doc
        .split("```toml\n")
        .nth(1)
        .and_then(|rest| rest.split("```").next())
        .expect("docs/policy.md has a ```toml example")
        .to_string();
    let policy = Policy::load(&block).unwrap();
    assert_eq!(policy.rules.len(), 2);
    assert_eq!(policy.deny.len(), 1);
}

#[test]
fn an_active_feature_adds_the_active_scopes() {
    let policy = Policy::builtin_default().unwrap();
    assert_eq!(ids(&policy.active_audit), ["runtime_api"]);
    let (audit, required) = policy.scope(&ScopeInput {
        mode: Mode::Static,
        active: true,
        install: false,
        binary: false,
        code: false,
    });
    assert_eq!(ids(&audit), ["model_store", "runtime_api"]);
    assert_eq!(required.last().unwrap().as_str(), "runtime_api.version");
    let (audit, _) = policy.scope(&ScopeInput {
        mode: Mode::Observe,
        active: true,
        install: false,
        binary: false,
        code: false,
    });
    assert_eq!(ids(&audit), ["model_store", "exposure", "runtime_api"]);
    // Without an active feature, the active scopes are not requested.
    let (audit, required) = policy.scope(&ScopeInput {
        mode: Mode::Observe,
        active: false,
        install: false,
        binary: false,
        code: false,
    });
    assert_eq!(ids(&audit), ["model_store", "exposure"]);
    assert!(!ids(&required).contains(&"runtime_api.version".to_string()));
    // A policy may leave them out, and must name known scopes.
    let base = "schema = \"sigil-policy/1\"\nname = \"x\"\n[scope]\naudit = [\"model_store\"]\n";
    let none = Policy::load(&format!("{base}active_audit = []\n")).unwrap();
    assert_eq!(
        ids(&none
            .scope(&ScopeInput {
                mode: Mode::Static,
                active: true,
                install: false,
                binary: false,
                code: false
            })
            .0),
        ["model_store"]
    );
    assert!(matches!(
        Policy::load(&format!("{base}active_audit = [\"nope\"]\n")),
        Err(PolicyError::UnknownScope(s)) if s == "nope"
    ));
}

#[test]
fn the_install_adds_runtime_artifacts_and_its_four_checks() {
    use sigil_engine::policy::ScopeInput;
    let policy = Policy::builtin_default().unwrap();
    let base = ScopeInput {
        mode: Mode::Static,
        active: false,
        install: false,
        binary: false,
        code: false,
    };
    let (audit, required) = policy.scope(&base);
    let (audit_i, required_i) = policy.scope(&ScopeInput {
        install: true,
        ..base
    });
    assert!(!audit.iter().any(|a| a.as_str() == "runtime_artifacts"));
    assert!(audit_i.iter().any(|a| a.as_str() == "runtime_artifacts"));
    let extra: Vec<&str> = required_i
        .iter()
        .filter(|c| !required.contains(c))
        .map(|c| c.as_str())
        .collect();
    assert_eq!(
        extra,
        [
            "artifacts.discovery",
            "artifacts.release",
            "artifacts.container",
            "artifacts.identity"
        ]
    );
}

#[test]
fn a_policy_without_install_audit_still_loads() {
    let text = "schema = \"sigil-policy/1\"\nname = \"old\"\n[scope]\naudit = [\"model_store\"]\n";
    let policy = Policy::load(text).unwrap();
    assert!(policy.install_audit.is_empty());
}

/// PR-4b-2a spec §4.6: a binary inspection audits `binary_audit` only, without `extra_required`.
#[test]
fn a_binary_inspection_audits_binary_audit_only() {
    let binary = ScopeInput {
        mode: Mode::Static,
        active: false,
        install: false,
        binary: true,
        code: false,
    };
    let policy = Policy::builtin_default().unwrap();
    assert_eq!(ids(&policy.binary_audit), ["binary"]);
    let (audit, required) = policy.scope(&binary);
    assert_eq!(ids(&audit), ["binary"]);
    assert_eq!(ids(&required), ["binary.container", "binary.identity"]);
    // An organization's extra checks are for `inspect ollama`.
    let text = "schema = \"sigil-policy/1\"\nname = \"x\"\n[scope]\naudit = [\"model_store\"]\n\
                binary_audit = [\"binary\"]\nextra_required = [\"loader.identify\"]\n";
    let (_, required) = Policy::load(text).unwrap().scope(&binary);
    assert_eq!(ids(&required), ["binary.container", "binary.identity"]);
    // Review of Part B: a policy without binary_audit (any written before it existed) requires
    // the binary scope, so binary inspections fail closed; only an explicit [] requires nothing.
    let old = Policy::load("schema = \"sigil-policy/1\"\nname = \"old\"\n").unwrap();
    assert_eq!(ids(&old.binary_audit), ["binary"]);
    assert_eq!(
        ids(&old.scope(&binary).1),
        ["binary.container", "binary.identity"]
    );
    let none =
        Policy::load("schema = \"sigil-policy/1\"\nname = \"x\"\n[scope]\nbinary_audit = []\n")
            .unwrap();
    assert_eq!(none.scope(&binary), (vec![], vec![]));
    assert!(matches!(
        Policy::load("schema = \"sigil-policy/1\"\nname = \"x\"\n[scope]\nbinary_audit = [\"nope\"]\n"),
        Err(PolicyError::UnknownScope(s)) if s == "nope"
    ));
}

/// PR-5a spec §5: code analysis adds `binary_code_audit` to `binary_audit`.
#[test]
fn binary_code_scope_is_added_only_with_code() {
    let p = Policy::builtin_default().unwrap();
    let base = ScopeInput {
        mode: Mode::Static,
        active: false,
        install: false,
        binary: true,
        code: false,
    };
    let (_, without) = p.scope(&base);
    assert!(!without.iter().any(|c| c.as_str() == "binary.code"));
    let (audit, with) = p.scope(&ScopeInput { code: true, ..base });
    assert!(with.iter().any(|c| c.as_str() == "binary.code"));
    assert!(audit.iter().any(|a| a.as_str() == "binary_code"));
    // `binary_audit` first, then `binary_code_audit`.
    assert_eq!(ids(&p.binary_code_audit), ["binary_code"]);
    assert_eq!(ids(&audit), ["binary", "binary_code"]);
    assert_eq!(
        ids(&with),
        ["binary.container", "binary.identity", "binary.code"]
    );
    // Code is a binary inspection's: `inspect ollama` never adds the scope.
    let (audit, _) = p.scope(&ScopeInput {
        binary: false,
        code: true,
        ..base
    });
    assert!(!audit.iter().any(|a| a.as_str() == "binary_code"));
    // A scope in both lists is audited once.
    let both = Policy::load(
        "schema = \"sigil-policy/1\"\nname = \"x\"\n[scope]\n\
         binary_audit = [\"binary\", \"binary_code\"]\nbinary_code_audit = [\"binary_code\"]\n",
    )
    .unwrap();
    let (audit, required) = both.scope(&ScopeInput { code: true, ..base });
    assert_eq!(ids(&audit), ["binary", "binary_code"]);
    assert_eq!(
        ids(&required),
        ["binary.container", "binary.identity", "binary.code"]
    );
}

#[test]
fn a_policy_without_binary_code_audit_requires_binary_code() {
    let text = include_str!("../policies/default.toml")
        .replace("binary_code_audit = [\"binary_code\"]\n", "");
    assert!(!text.contains("binary_code_audit"));
    let p = Policy::load(&text).unwrap();
    let (_, req) = p.scope(&ScopeInput {
        mode: Mode::Static,
        active: false,
        install: false,
        binary: true,
        code: true,
    });
    assert!(
        req.iter().any(|c| c.as_str() == "binary.code"),
        "fails closed"
    );
    let none = include_str!("../policies/default.toml").replace(
        "binary_code_audit = [\"binary_code\"]",
        "binary_code_audit = []",
    );
    assert!(none.contains("binary_code_audit = []"));
    let p = Policy::load(&none).unwrap();
    let (_, req) = p.scope(&ScopeInput {
        mode: Mode::Static,
        active: false,
        install: false,
        binary: true,
        code: true,
    });
    assert!(!req.iter().any(|c| c.as_str() == "binary.code"));
    assert!(matches!(
        Policy::load("schema = \"sigil-policy/1\"\nname = \"x\"\n[scope]\nbinary_code_audit = [\"nope\"]\n"),
        Err(PolicyError::UnknownScope(s)) if s == "nope"
    ));
}

#[test]
fn scope_input_of_finds_binary_roots() {
    let mut request = sigil_model::RunRequest {
        mode: Mode::Static,
        roots: vec![sigil_model::ScanRoot {
            id: sigil_model::binary_root(1).unwrap(),
            path: sigil_model::UntrustedText::new("/x"),
        }],
        audit: vec![],
        required_checks: vec![],
        budgets: Default::default(),
        observe_env: false,
        model_filter: None,
        active: vec![],
        code: false,
    };
    assert!(ScopeInput::of(&request).binary);
    assert!(!ScopeInput::of(&request).code);
    request.code = true;
    assert!(ScopeInput::of(&request).code);
    request.roots[0].id = sigil_model::RootId::new("models").unwrap();
    assert!(!ScopeInput::of(&request).binary);
}
