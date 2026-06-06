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
# Environment:
#   MODELS_DIR  Path to the Ollama model store SIGIL should inspect.
#               Defaults to $OLLAMA_MODELS, then ~/.ollama/models.
#               The systemd-installed Ollama service on Linux stores
#               models under /usr/share/ollama/.ollama/models — set
#               MODELS_DIR to that path and ensure read permission.
#   SKIP_PULL   If "1", skip `ollama pull` for tags already present in
#               `ollama list` (default: 1).
#
# Requires: ollama, cargo, ~30 GB free disk for the default 5-model list.

set -euo pipefail

MODELS_FILE="${1:-scripts/audit-models.txt}"
OUT_DIR="${2:-reports/2026-h1/raw}"
MODELS_DIR="${MODELS_DIR:-${OLLAMA_MODELS:-$HOME/.ollama/models}}"
SKIP_PULL="${SKIP_PULL:-1}"

if ! command -v ollama >/dev/null; then
  echo "error: ollama not found in PATH" >&2
  exit 1
fi

if [[ ! -f "$MODELS_FILE" ]]; then
  echo "error: model list not found: $MODELS_FILE" >&2
  exit 1
fi

if [[ ! -r "$MODELS_DIR" ]]; then
  echo "error: MODELS_DIR is not readable: $MODELS_DIR" >&2
  echo "hint: the systemd Ollama service stores models under" >&2
  echo "      /usr/share/ollama/.ollama/models — run" >&2
  echo "      sudo chmod -R o+rX /usr/share/ollama/.ollama" >&2
  echo "      then re-run with MODELS_DIR=/usr/share/ollama/.ollama/models" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

mapfile -t MODELS < <(grep -vE '^\s*(#|$)' "$MODELS_FILE")

echo "Models:     ${#MODELS[@]}"
echo "Output:     $OUT_DIR"
echo "Models dir: $MODELS_DIR"
echo "Skip pull:  $SKIP_PULL"

# Cache `ollama list` once to decide which tags need pulling.
present_tags=$(ollama list 2>/dev/null | awk 'NR>1 {print $1}' || true)

failures=0
for model in "${MODELS[@]}"; do
  echo
  echo "=== $model ==="
  if [[ "$SKIP_PULL" == "1" ]] && grep -qxF "$model" <<<"$present_tags"; then
    echo "  already present, skipping pull"
  else
    if ! ollama pull "$model"; then
      echo "  pull failed: $model" >&2
      failures=$((failures + 1))
      continue
    fi
  fi
  slug="${model//[:\/]/_}"
  if ! cargo run --release -q -p sigil-cli -- \
    aibom generate \
      --runtime ollama \
      --model "$model" \
      --models-dir "$MODELS_DIR" \
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
