#!/usr/bin/env bash
# State of Local AI Audit — aggregator.
# Reads every AI-BOM JSON under the raw directory and emits one summary JSON
# with the headline distributions (license, verdict, exposure) plus per-model
# rows. The summary is meant to be embedded into the report HTML by hand.
#
# Usage:
#   ./scripts/audit-aggregate.sh
#   ./scripts/audit-aggregate.sh path/to/raw path/to/summary.json
#
# Requires: jq.

set -euo pipefail

IN_DIR="${1:-reports/2026-h1/raw}"
OUT_FILE="${2:-reports/2026-h1/summary.json}"

if ! command -v jq >/dev/null; then
  echo "error: jq not found in PATH" >&2
  exit 1
fi

shopt -s nullglob
files=("$IN_DIR"/*.aibom.json)
if (( ${#files[@]} == 0 )); then
  echo "error: no *.aibom.json files in $IN_DIR" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT_FILE")"

jq -s '
  # Finding ids that indicate manifest-integrity failure. Any of these on a
  # model means the on-disk artifact did not match what the Ollama manifest
  # declared. Source: crates/sigil-core/src/ollama.rs.
  [
    "ollama.invalid_blob_digest",
    "ollama.blob_digest_mismatch",
    "ollama.blob_missing",
    "ollama.model_not_found"
  ] as $INTEGRITY_FAIL_IDS
  |
  def total_model_bytes:
    [.[].models[].files[] | select(.kind == "model") | .size] | add // 0;

  def has_integrity_fail($finding_ids):
    any($finding_ids[]; . as $id | $INTEGRITY_FAIL_IDS | index($id));

  {
    sample_size: length,
    generated_at: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
    sigil_versions: ([.[].tool.version] | unique),
    schema_versions: ([.[].schema_version] | unique),
    verdict_distribution: (
      group_by(.verdict)
        | map({verdict: .[0].verdict, count: length})
        | sort_by(-.count)
    ),
    runtime_exposure_distribution: (
      group_by(.runtime.exposure.class)
        | map({class: .[0].runtime.exposure.class, count: length})
        | sort_by(-.count)
    ),
    license_distribution: (
      [.[].models[] | select(.license != null and .license.spdx_id != null) | .license.spdx_id]
        | group_by(.)
        | map({spdx_id: .[0], count: length})
        | sort_by(-.count)
    ),
    license_status: (
      [
        .[].models[] | (
          if .license == null then "absent"
          elif .license.spdx_id == null then "present_undetected"
          else "present_detected"
          end
        )
      ]
        | group_by(.)
        | map({status: .[0], count: length})
        | sort_by(-.count)
    ),
    license_layer_presence: (
      ([.[].models[]] | length) as $total
      | ([.[].models[] | select(.license != null)] | length) as $with
      | { with_license: $with, total: $total, rate_percent: (if $total == 0 then 0 else ($with * 100 / $total | floor) end) }
    ),
    findings_total: ([.[].findings[]] | length),
    findings_by_severity: (
      [.[].findings[].severity]
        | group_by(.)
        | map({severity: .[0], count: length})
    ),
    findings_by_category: (
      [.[].findings[].category]
        | group_by(.)
        | map({category: .[0], count: length})
    ),
    findings_by_id: (
      [.[].findings[].id]
        | group_by(.)
        | map({id: .[0], count: length})
        | sort_by(-.count)
    ),
    models_with_findings: (
      [.[] | select(.findings | length > 0)] | length
    ),
    manifest_integrity: (
      ([.[]] | length) as $total
      | ([.[] | select(has_integrity_fail([.findings[].id]) | not)] | length) as $pass
      | {
          integrity_pass_count: $pass,
          integrity_fail_count: ($total - $pass),
          total: $total,
          rate_percent: (if $total == 0 then 0 else ($pass * 100 / $total | floor) end),
          fail_ids: $INTEGRITY_FAIL_IDS
        }
    ),
    total_model_bytes: total_model_bytes,
    per_model: [
      .[] | (
        [.findings[].id] as $finding_ids
        | {
            name: (.models[0].name // "unknown"),
            verdict: .verdict,
            license: (.models[0].license.spdx_id // "unknown"),
            license_present: (.models[0].license != null),
            layer_count: (.models[0].files | length),
            model_bytes: ([.models[0].files[] | select(.kind == "model") | .size] | add // 0),
            provenance: (
              .models[0].provenance
              | (.registry // "?") + "/" + (.namespace // "?") + "/" + (.model // "?") + ":" + (.tag // "?")
            ),
            findings_count: (.findings | length),
            finding_ids: $finding_ids,
            integrity_pass: (has_integrity_fail($finding_ids) | not)
          }
      )
    ] | sort_by(.name)
  }
' "${files[@]}" > "$OUT_FILE"

echo "Wrote $OUT_FILE"
echo
jq '
  {
    sample_size,
    license_layer_presence,
    license_status,
    license_distribution,
    verdict_distribution,
    manifest_integrity,
    findings_total,
    findings_by_id,
    models_with_findings
  }
' "$OUT_FILE"
