#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This bootstrap script is for macOS only."
  exit 1
fi

if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew is required: https://brew.sh"
  exit 1
fi

brew update
brew install uv llvm

LLVM_PREFIX="$(brew --prefix llvm)"
export PATH="$LLVM_PREFIX/bin:$PATH"

uv venv
source .venv/bin/activate
uv sync --dev

echo "Setup complete."
echo "Run: source .venv/bin/activate"
echo "Then: uv run pytest -q"
