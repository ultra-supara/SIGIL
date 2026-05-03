from __future__ import annotations

import argparse
from pathlib import Path

from sigil.assess.capabilities import capability_for_symbol
from sigil.assess.evidence import Evidence
from sigil.assess.policy import PolicyViolation, evaluate_policy, load_policy
from sigil.assess.report import render_report
from sigil.safeisa.emitter import emit_safeisa, render_safeisa
from sigil.x86.decoder import decode_x86_64
from sigil.x86.elf import load_function
from sigil.x86.lifter import lift_instructions


def _analyze(binary: str, entry: str):
    loaded = load_function(binary, entry)
    decoded = decode_x86_64(loaded.code, loaded.address)
    ir = lift_instructions(entry, decoded, loaded.call_symbols)
    safeisa = emit_safeisa(ir)
    return loaded, decoded, ir, safeisa


def _render_ir(ir) -> str:
    lines = [f"func {ir.name}:"]
    for block in ir.blocks:
        lines.append(f"  block {block.name}:")
        for op in block.ops:
            lines.append(f"    {hex(op.source_address or 0)} {op.op} {op.text}")
    return "\n".join(lines) + "\n"


def cmd_lift(args: argparse.Namespace) -> int:
    _, _, ir, safeisa = _analyze(args.binary, args.entry)
    if args.emit_ir:
        Path(args.emit_ir).write_text(_render_ir(ir), encoding="utf-8")
    if args.emit_safeisa:
        Path(args.emit_safeisa).write_text(render_safeisa(safeisa, args.entry), encoding="utf-8")
    return 0


def cmd_assess(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    _, _, ir, _ = _analyze(args.binary, args.entry)
    caps: list[str] = []
    ext_calls = []
    unsupported = []
    cap_evidence: dict[str, list[dict]] = {}
    violations: list[PolicyViolation] = []

    for block in ir.blocks:
        for op in block.ops:
            addr = hex(op.source_address or 0)
            if op.op in {"Add", "Sub", "Mul", "And", "Or", "Xor"}:
                caps.append("arithmetic")
                cap_evidence.setdefault("arithmetic", []).append({"address": addr, "instruction": op.text})
            elif op.op == "ExternalCall":
                symbol = (op.symbol or "unknown").split()[0]
                cap = capability_for_symbol(symbol)
                if cap:
                    caps.append(cap)
                    cap_evidence.setdefault(cap, []).append({"address": addr, "instruction": op.text, "symbol": symbol})
                ext_calls.append({"symbol": symbol, "capability": cap, "address": addr})
            elif op.op == "Unsupported":
                caps.append("unsupported_instruction")
                unsupported.append({"address": addr, "instruction": op.text})
                violations.append(PolicyViolation(rule="unsupported_instruction", capability="unsupported_instruction", evidence_address=addr))

    verdict, policy_violations = evaluate_policy(policy, caps)
    policy_violations.extend(violations)
    evidence = Evidence(
        binary=args.binary,
        entry=args.entry,
        verdict=verdict.value,
        capabilities=[{"name": c, "evidence": cap_evidence.get(c, [])} for c in sorted(set(caps))],
        external_calls=ext_calls,
        unsupported_instructions=unsupported,
        policy_violations=[v.__dict__ for v in policy_violations],
    )
    if args.emit_evidence:
        Path(args.emit_evidence).write_text(evidence.to_json(), encoding="utf-8")
    report = render_report(evidence)
    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
    print(f"SIGIL Verdict: {evidence.verdict}")
    return 0


def _placeholder(_: argparse.Namespace, name: str) -> int:
    print(f"{name} is not implemented yet")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sigil")
    sub = parser.add_subparsers(dest="cmd", required=True)

    l = sub.add_parser("lift")
    l.add_argument("binary")
    l.add_argument("--entry", required=True)
    l.add_argument("--emit-ir", required=True)
    l.add_argument("--emit-safeisa", required=True)
    l.set_defaults(func=cmd_lift)

    a = sub.add_parser("assess")
    a.add_argument("binary")
    a.add_argument("--entry", required=True)
    a.add_argument("--policy", required=True)
    a.add_argument("--out")
    a.add_argument("--emit-evidence")
    a.set_defaults(func=cmd_assess)

    for cmd in ["trace", "policy-from-source", "explain"]:
        p = sub.add_parser(cmd)
        p.set_defaults(func=lambda ns, n=cmd: _placeholder(ns, n))

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
