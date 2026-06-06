#!/usr/bin/env bash
# State of Local AI Audit — runner.
# Pulls every Ollama tag listed in scripts/audit-models.txt and runs
# `sigil aibom generate` against each. One AI-BOM JSON per model is written
# under reports/2026-h1/raw/.
#
# Usage:
#   ./scripts/audit-run.sh                              # default model list + out dir
#   ./scripts/audit-run.sh path/to/models.txt           # custom model list
#   ./scripts/audit-run.sh scripts/audit-models.txt out # custom out dir
#
# Requires: ollama, cargo, ~30 GB free disk for the default 5-model list.

set -euo pipefail

MODELS_FILE="${1:-scripts/audit-models.txt}"
OUT_DIR="${2:-reports/2026-h1/raw}"

if ! command -v ollama >/dev/null; then
  echo "error: ollama not found in PATH" >&2
  exit 1
fi

if [[ ! -f "$MODELS_FILE" ]]; then
  echo "error: model list not found: $MODELS_FILE" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

mapfile -t MODELS < <(grep -vE '^\s*(#|$)' "$MODELS_FILE")

echo "Models: ${#MODELS[@]}  Output: $OUT_DIR"

failures=0
for model in "${MODELS[@]}"; do
  echo
  echo "=== $model ==="
  if ! ollama pull "$model"; then
    echo "  pull failed: $model" >&2
    failures=$((failures + 1))
    continue
  fi
  slug="${model//[:\/]/_}"
  if ! cargo run --release -q -p sigil-cli -- \
    aibom generate \
      --runtime ollama \
      --model "$model" \
      --format json \
      --out "$OUT_DIR/${slug}.aibom.json"; then
    echo "  sigil failed: $model" >&2
    failures=$((failures + 1))
    continue
  fi
done

echo
echo "Done. AI-BOM JSON files in $OUT_DIR"
if (( failures > 0 )); then
  echo "Failures: $failures" >&2
  exit 2
fi
