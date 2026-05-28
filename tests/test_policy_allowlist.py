from sigil.assess.policy import Policy, evaluate_policy
from sigil.assess.verdict import Verdict


def test_allowlist_enforced_for_unlisted_capability():
    p = Policy(
        name="allowlist-only",
        allowed_capabilities={"arithmetic"},
        forbidden_capabilities=set(),
        verdict_rules={},
    )
    verdict, violations = evaluate_policy(p, ["network"])
    assert verdict == Verdict.FAIL
    assert any(v.rule == "allowed.capabilities.network" for v in violations)


def test_allowlist_can_warn_via_verdict_rules():
    p = Policy(
        name="allowlist-warn",
        allowed_capabilities={"arithmetic"},
        forbidden_capabilities=set(),
        verdict_rules={"allowlist_violation": "WARN"},
    )
    verdict, violations = evaluate_policy(p, ["network"])
    assert verdict == Verdict.WARN
    assert any(v.rule == "allowed.capabilities.network" for v in violations)
