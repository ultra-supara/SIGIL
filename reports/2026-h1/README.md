# State of Local AI Audit — 2026 H1 (historical, SIGIL 0.1)

This directory holds the data of the 2026-H1 report: five Ollama models, inspected by **SIGIL 0.1.0**, which wrote AI-BOM v1 (`schema_version: "1.1"`). It was generated on 2026-06-14 (`summary.json`, `generated_at`). The report page is [`site/reports/2026-h1/`](../../site/reports/2026-h1/index.html), published at <https://ultra-supara.github.io/SIGIL/reports/2026-h1/>.

## v0.1 semantics

- The Ollama API probe was on by default and was used.
- `PASS` meant "no findings". v0.1 had no coverage, so a `PASS` did not say whether everything required was seen.

The report therefore **cannot be compared directly** with SIGIL v2 sessions or AI-BOM v2, whose outcome has a verdict and a completeness side by side. It **has not been re-evaluated**. A re-evaluation would be generated from new observations as a separate report (for example, `reports/2026-h2-reeval/`), and this one stays as it is.

## Files

| File | What it is |
|---|---|
| `raw/<model>.aibom.json` | The five v1 AI-BOMs, as published. They validate against [`schemas/aibom-v1.schema.json`](../../schemas/aibom-v1.schema.json), which `crates/sigil-model/tests/aibom_v1_schema.rs` checks |
| `summary.json` | The aggregate the report page shows |
| `audit-run.log` | The log of the run |
| `audit-run.sh`, `audit-models.txt` | How the AI-BOMs were produced: `sigil aibom generate` (v0.1) over the listed models |
| `audit-aggregate.sh` | How `summary.json` was computed from `raw/` (jq) |

The scripts use the v0.1 CLI and **do not run on SIGIL v2**; they are kept as the record of how this report was made. Why the v0.1 code was removed: [ADR-006](../../docs/adr/ADR-006-remove-ir-safeisa.md).
