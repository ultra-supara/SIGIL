use crate::evidence::Evidence;

pub fn render_report(evidence: &Evidence) -> String {
    let mut lines = vec![
        format!("# SIGIL Verdict: {}", evidence.verdict.as_str()),
        String::new(),
    ];
    if evidence.policy_violations.is_empty() {
        lines.push("No forbidden capabilities detected.".to_string());
    } else {
        lines.push("## Policy Violations".to_string());
        for violation in &evidence.policy_violations {
            let address = violation
                .evidence_address
                .as_ref()
                .map(|value| format!(" @ {value}"))
                .unwrap_or_default();
            lines.push(format!(
                "- Rule: `{}` capability: `{}`{}",
                violation.rule, violation.capability, address
            ));
        }
    }

    if !evidence.unsupported_instructions.is_empty() {
        lines.push(String::new());
        lines.push("## Unsupported Instructions".to_string());
        for item in &evidence.unsupported_instructions {
            lines.push(format!("- {}: `{}`", item.address, item.instruction));
        }
    }

    lines.join("\n") + "\n"
}
