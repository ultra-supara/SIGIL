from sigil.assess.policy import evaluate_policy, load_policy
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
