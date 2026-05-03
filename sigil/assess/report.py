from __future__ import annotations

from sigil.assess.evidence import Evidence


def render_report(evidence: Evidence) -> str:
    lines = [f"# SIGIL Verdict: {evidence.verdict}", ""]
    if evidence.policy_violations:
        lines.append("## Policy Violations")
        for v in evidence.policy_violations:
            lines.append(f"- Rule: `{v['rule']}` capability: `{v['capability']}`")
    else:
        lines.append("No forbidden capabilities detected.")
    return "\n".join(lines) + "\n"
