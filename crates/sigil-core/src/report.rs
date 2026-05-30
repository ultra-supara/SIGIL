use crate::evidence::Evidence;
use crate::safeisa::{render_safeisa, Program};

/// Render a Markdown assessment report for a binary. When `safeisa` is
/// provided, a SafeISA excerpt is appended so the deterministic IR view sits
/// next to the capability evidence in a single artifact.
pub fn render_report(evidence: &Evidence, safeisa: Option<&Program>) -> String {
    let mut lines = Vec::new();
    lines.push(format!("# SIGIL Verdict: [{}]", evidence.verdict.as_str()));
    lines.push(String::new());
    lines.push(format!("- Binary: `{}`", evidence.binary));
    lines.push(format!("- Entry: `{}`", evidence.entry));
    lines.push(String::new());

    push_capabilities(&mut lines, evidence);
    push_violations(&mut lines, evidence);
    push_unsupported(&mut lines, evidence);
    push_safeisa(&mut lines, evidence, safeisa);

    lines.join("\n") + "\n"
}

fn push_capabilities(lines: &mut Vec<String>, evidence: &Evidence) {
    lines.push("## Capabilities".to_string());
    let rows: Vec<_> = evidence
        .capabilities
        .iter()
        .flat_map(|cap| {
            if cap.evidence.is_empty() {
                vec![(cap.name.as_str(), "", "", "")]
            } else {
                cap.evidence
                    .iter()
                    .map(|item| {
                        (
                            cap.name.as_str(),
                            item.address.as_str(),
                            item.instruction.as_str(),
                            item.symbol.as_deref().unwrap_or(""),
                        )
                    })
                    .collect()
            }
        })
        .collect();
    if rows.is_empty() {
        lines.push("_No capabilities observed._".to_string());
        lines.push(String::new());
        return;
    }
    lines.push("| Capability | Address | Instruction | External symbol |".to_string());
    lines.push("|------------|---------|-------------|-----------------|".to_string());
    for (cap, addr, instr, sym) in rows {
        let addr_cell = if addr.is_empty() {
            String::new()
        } else {
            format!("`{addr}`")
        };
        let instr_cell = if instr.is_empty() {
            String::new()
        } else {
            format!("`{instr}`")
        };
        let sym_cell = if sym.is_empty() {
            String::new()
        } else {
            format!("`{sym}`")
        };
        lines.push(format!(
            "| {cap} | {addr_cell} | {instr_cell} | {sym_cell} |"
        ));
    }
    lines.push(String::new());
}

fn push_violations(lines: &mut Vec<String>, evidence: &Evidence) {
    lines.push("## Policy Violations".to_string());
    if evidence.policy_violations.is_empty() {
        lines.push("_No forbidden capabilities detected._".to_string());
        lines.push(String::new());
        return;
    }
    for violation in &evidence.policy_violations {
        let severity = evidence.verdict.as_str();
        // Prefer the explicit address recorded on the violation. When absent,
        // fall back to the first external call that resolves the same
        // capability — this surfaces the call site for forbidden-capability
        // violations that the policy evaluator could not address directly.
        let matching_call = evidence.external_calls.iter().find(|call| {
            if let Some(addr) = &violation.evidence_address {
                addr == &call.address
            } else {
                call.capability.as_deref() == Some(violation.capability.as_str())
            }
        });
        let address = violation
            .evidence_address
            .clone()
            .or_else(|| matching_call.map(|call| call.address.clone()));
        let where_part = address
            .as_deref()
            .map(|addr| format!(" at `{addr}`"))
            .unwrap_or_default();
        let via = matching_call
            .map(|call| format!(" via `{}`", call.symbol))
            .unwrap_or_default();
        lines.push(format!(
            "- [{severity}] `{}` — capability `{}`{where_part}{via}",
            violation.rule, violation.capability
        ));
    }
    lines.push(String::new());
}

fn push_unsupported(lines: &mut Vec<String>, evidence: &Evidence) {
    if evidence.unsupported_instructions.is_empty() {
        return;
    }
    lines.push("## Unsupported Instructions".to_string());
    for item in &evidence.unsupported_instructions {
        lines.push(format!("- `{}`: `{}`", item.address, item.instruction));
    }
    lines.push(String::new());
}

fn push_safeisa(lines: &mut Vec<String>, evidence: &Evidence, safeisa: Option<&Program>) {
    let Some(program) = safeisa else {
        return;
    };
    lines.push("## SafeISA".to_string());
    lines.push("```".to_string());
    let rendered = render_safeisa(program, &evidence.entry);
    for line in rendered.lines() {
        lines.push(line.to_string());
    }
    lines.push("```".to_string());
    lines.push(String::new());
}
