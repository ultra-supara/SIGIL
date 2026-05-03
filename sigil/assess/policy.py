from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sigil.assess.verdict import Verdict

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - exercised only in minimal/offline envs
    yaml = None


@dataclass
class Policy:
    name: str
    allowed_capabilities: set[str]
    forbidden_capabilities: set[str]
    verdict_rules: dict[str, str]


@dataclass
class PolicyViolation:
    rule: str
    capability: str
    evidence_address: str | None = None


def _parse_simple_yaml(path: str) -> dict:
    data: dict = {"allowed": {"capabilities": []}, "forbidden": {"capabilities": []}, "verdict_rules": {}}
    section = None
    subsection = None
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip()
            if not line or line.lstrip().startswith("#"):
                continue
            if not line.startswith(" ") and line.endswith(":"):
                section = line[:-1]
                subsection = None
                continue
            if line.startswith("  ") and line.strip().endswith(":"):
                subsection = line.strip()[:-1]
                continue
            if line.startswith("name:"):
                data["name"] = line.split(":", 1)[1].strip()
            elif line.startswith("version:"):
                data["version"] = line.split(":", 1)[1].strip()
            elif line.startswith("entry:"):
                data["entry"] = line.split(":", 1)[1].strip()
            elif line.strip().startswith("- ") and section in {"allowed", "forbidden"} and subsection == "capabilities":
                data[section]["capabilities"].append(line.strip()[2:])
            elif section == "verdict_rules" and ":" in line:
                k, v = line.strip().split(":", 1)
                data["verdict_rules"][k.strip()] = v.strip()
    return data


def _load_yaml(path: str) -> dict[str, Any]:
    if yaml is not None:
        with open(path, "r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f)
        return loaded or {}
    return _parse_simple_yaml(path)


def load_policy(path: str) -> Policy:
    data = _load_yaml(path)
    if "name" not in data:
        raise ValueError("Policy missing required field: name")
    return Policy(
        name=data["name"],
        allowed_capabilities=set(data.get("allowed", {}).get("capabilities", [])),
        forbidden_capabilities=set(data.get("forbidden", {}).get("capabilities", [])),
        verdict_rules=data.get("verdict_rules", {}),
    )


def evaluate_policy(policy: Policy, capabilities: list[str]) -> tuple[Verdict, list[PolicyViolation]]:
    violations: list[PolicyViolation] = []
    verdict = Verdict.PASS
    uniq_caps = sorted(set(capabilities))

    for cap in uniq_caps:
        if cap in policy.forbidden_capabilities:
            violations.append(PolicyViolation(rule=f"forbidden.capabilities.{cap}", capability=cap))
            if policy.verdict_rules.get("forbidden_capability", "FAIL") == "FAIL":
                verdict = Verdict.FAIL

        if policy.allowed_capabilities and cap not in policy.allowed_capabilities:
            violations.append(PolicyViolation(rule=f"allowed.capabilities.{cap}", capability=cap))
            allowlist_rule = policy.verdict_rules.get("allowlist_violation", "FAIL")
            if allowlist_rule == "FAIL":
                verdict = Verdict.FAIL
            elif allowlist_rule == "WARN" and verdict != Verdict.FAIL:
                verdict = Verdict.WARN

        if cap == "unsupported_instruction" and verdict != Verdict.FAIL:
            unsupported_rule = policy.verdict_rules.get("unsupported_instruction", "WARN")
            if unsupported_rule == "FAIL":
                verdict = Verdict.FAIL
            elif unsupported_rule == "WARN":
                verdict = Verdict.WARN

    return verdict, violations
