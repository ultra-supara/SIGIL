#[allow(dead_code)]
#[path = "../../sigil-model/tests/support/multiarch.rs"]
mod support;
use sigil_engine::policy::{evaluate, Policy, ScopeInput};
use sigil_model::*;

fn policy(deny: bool) -> Policy {
    let mut text = "schema = \"sigil-policy/1\"\nname = \"coverage\"\n[scope]\nbinary_audit = []\nbinary_code_audit = [\"binary_code\"]\n".to_string();
    if deny {
        text.push_str("[[capabilities.deny]]\nfeature = \"posix.network\"\naction = \"fail\"\nreason = \"test\"\n");
    }
    Policy::load(&text).unwrap()
}

#[test]
fn marked_capability_evaluation_fails_without_mutating_the_session() {
    let mut s = support::named();
    s.hints = sigil_engine::analyze::hints::derive(&s.binaries).unwrap();
    let p = policy(true);
    let (audit, checks) = p.scope(&ScopeInput::of(&s.request));
    s.request.audit = audit;
    s.request.required_checks = checks;
    let before = s.clone();
    let result = evaluate(&mut s, &p, Timestamp::new("2026-11-03T00:00:00Z").unwrap());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("multiarch capability policy is not enabled"));
    assert_eq!(s, before);
}

#[test]
fn required_code_check_includes_every_slice_and_supports_explicit_opt_out() {
    for s in support::matrix() {
        for opt_out in [false, true] {
            let p = if opt_out {
                Policy::load("schema = \"sigil-policy/1\"\nname = \"coverage\"\n[scope]\nbinary_audit = []\nbinary_code_audit = []\n").unwrap()
            } else {
                policy(false)
            };
            let mut s = s.clone();
            let expected_complete = opt_out
                || s.coverage
                    .iter()
                    .filter(|c| c.check.as_str() == BINARY_CODE)
                    .all(|c| c.state.can_close());
            let (audit, checks) = p.scope(&ScopeInput::of(&s.request));
            s.request.audit = audit;
            s.request.required_checks = checks;
            evaluate(&mut s, &p, Timestamp::new("2026-11-03T00:00:00Z").unwrap()).unwrap();
            assert_eq!(
                s.outcome.completeness == Completeness::Complete,
                expected_complete
            );
            assert!(s.validate().is_ok(), "{:?}", s.validate());
        }
    }
}

#[test]
fn legacy_capability_policy_remains_enabled() {
    let mut s: Session = serde_json::from_str(include_str!(
        "../../../schemas/examples/session-v1/16-binary-code.json"
    ))
    .unwrap();
    let p = policy(true);
    let (audit, checks) = p.scope(&ScopeInput::of(&s.request));
    s.request.audit = audit;
    s.request.required_checks = checks;
    evaluate(&mut s, &p, Timestamp::new("2026-11-03T00:00:00Z").unwrap()).unwrap();
    assert!(!s.policy_violations.is_empty());
    s.validate().unwrap();
}

#[test]
fn empty_install_and_extra_required_checks_keep_existing_completeness() {
    for extra in [false, true] {
        let text = format!("schema = \"sigil-policy/1\"\nname = \"coverage\"\n[scope]\naudit = []\ninstall_audit = []\ninstall_code_audit = [\"installation_code\"]\nextra_required = [{}]\n", if extra { "\"exposure.binds\"" } else { "" });
        let p = Policy::load(&text).unwrap();
        let mut s = support::installation(support::named());
        s.artifacts.clear();
        s.binaries.clear();
        s.instances.clear();
        s.coverage.retain(|c| matches!(c.scope, Ref::Root(_)));
        let (audit, checks) = p.scope(&ScopeInput::of(&s.request));
        s.request.audit = audit;
        s.request.required_checks = checks;
        evaluate(&mut s, &p, Timestamp::new("2026-11-03T00:00:00Z").unwrap()).unwrap();
        assert_eq!(s.outcome.completeness == Completeness::Complete, !extra);
        s.validate().unwrap();
    }
}

#[test]
fn legacy_macho_parser_does_not_invent_a_code_byte_order_observation() {
    use sha2::{Digest, Sha256};
    use sigil_engine::binary::{parse_artifact, BinaryBudgets};
    let directory = tempfile::tempdir().unwrap();
    let mut containers = Vec::new();
    for big in [false, true] {
        let words = [0xfeed_facfu32, 0x0100_0007, 3, 2, 0, 0, 0, 0];
        let bytes: Vec<_> = words
            .iter()
            .flat_map(|word| {
                if big {
                    word.to_be_bytes()
                } else {
                    word.to_le_bytes()
                }
            })
            .collect();
        let path = directory.path().join(if big { "big" } else { "little" });
        std::fs::write(&path, &bytes).unwrap();
        let file = std::fs::File::open(path).unwrap();
        let digest = Sha256Hex::new(format!("{:x}", Sha256::digest(&bytes))).unwrap();
        let parsed = parse_artifact(
            &file,
            bytes.len() as u64,
            &digest,
            &bytes[..4],
            BinaryBudgets::default(),
            None,
        )
        .unwrap();
        let container = parsed.slices[0].container.clone().unwrap();
        assert!(matches!(&container,ContainerFacts::MachO(m) if m.little_endian.is_none()));
        let mut marked = support::named();
        marked.artifacts[0].format = Format::MachO;
        marked.binaries[0].container = container.clone();
        assert!(marked
            .validate()
            .unwrap_err()
            .iter()
            .any(|e| e.to_string().contains("supported parsed ABI")));
        containers.push(container);
    }
    assert_eq!(
        containers[0], containers[1],
        "legacy saved facts cannot prove byte order"
    );
}
