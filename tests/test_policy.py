from sigil.assess.policy import Policy, evaluate_policy, load_policy
from sigil.assess.verdict import Verdict


def test_policy_pass():
    p = load_policy("examples/policies/numeric_kernel.yml")
    verdict, violations = evaluate_policy(p, ["arithmetic"])
    assert verdict == Verdict.PASS
    assert not violations


def test_policy_fail_for_network():
    p = load_policy("examples/policies/numeric_kernel.yml")
    verdict, violations = evaluate_policy(p, ["network"])
    assert verdict == Verdict.FAIL
    assert violations


def test_policy_fail_for_unsupported_when_configured():
    p = Policy(
        name="unsupported-fail",
        allowed_capabilities={"unsupported_instruction"},
        forbidden_capabilities=set(),
        verdict_rules={"unsupported_instruction": "FAIL"},
    )
    verdict, _ = evaluate_policy(p, ["unsupported_instruction"])
    assert verdict == Verdict.FAIL
