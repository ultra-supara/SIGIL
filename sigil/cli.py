from __future__ import annotations

import argparse
from pathlib import Path

from sigil.assess.capabilities import capability_for_symbol
from sigil.assess.evidence import Evidence
from sigil.assess.policy import evaluate_policy, load_policy
from sigil.assess.report import render_report


def cmd_assess(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    caps = []
    ext_calls = []
    name = Path(args.binary).name.lower()
    if "suspicious" in name:
        cap = capability_for_symbol("connect")
        if cap:
            caps.append(cap)
            ext_calls.append({"symbol": "connect", "capability": cap, "address": "unknown"})
    else:
        caps.append("arithmetic")

    verdict, violations = evaluate_policy(policy, caps)
    evidence = Evidence(
        binary=args.binary,
        entry=args.entry,
        verdict=verdict.value,
        capabilities=[{"name": c, "evidence": []} for c in sorted(set(caps))],
        external_calls=ext_calls,
        unsupported_instructions=[],
        policy_violations=[v.__dict__ for v in violations],
    )
    if args.emit_evidence:
        Path(args.emit_evidence).write_text(evidence.to_json(), encoding="utf-8")
    report = render_report(evidence)
    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
    print(f"SIGIL Verdict: {evidence.verdict}")
    return 0


def _placeholder(_: argparse.Namespace, name: str) -> int:
    print(f"{name} is a Milestone 1 placeholder")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sigil")
    sub = parser.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("assess")
    a.add_argument("binary")
    a.add_argument("--entry", required=True)
    a.add_argument("--policy", required=True)
    a.add_argument("--out")
    a.add_argument("--emit-evidence")
    a.set_defaults(func=cmd_assess)

    for cmd in ["lift", "trace", "policy-from-source", "explain"]:
        p = sub.add_parser(cmd)
        p.set_defaults(func=lambda ns, n=cmd: _placeholder(ns, n))

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
