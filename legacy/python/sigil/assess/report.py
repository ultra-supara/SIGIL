from __future__ import annotations

from sigil.assess.evidence import Evidence


def render_report(evidence: Evidence) -> str:
    lines = [f"# SIGIL Verdict: {evidence.verdict}", ""]
    if evidence.policy_violations:
        lines.append("## Policy Violations")
        for v in evidence.policy_violations:
            addr = f" @ {v['evidence_address']}" if v.get("evidence_address") else ""
            lines.append(f"- Rule: `{v['rule']}` capability: `{v['capability']}`{addr}")
    else:
        lines.append("No forbidden capabilities detected.")

    if evidence.unsupported_instructions:
        lines.append("")
        lines.append("## Unsupported Instructions")
        for item in evidence.unsupported_instructions:
            lines.append(f"- {item['address']}: `{item['instruction']}`")
    return "\n".join(lines) + "\n"
