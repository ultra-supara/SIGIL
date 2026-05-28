#!/usr/bin/env bash
set -euo pipefail
mkdir -p examples/binaries out
case "$(uname -s)" in
  Darwin) target="${SIGIL_DEMO_TARGET:-x86_64-apple-macos}" ;;
  *) target="${SIGIL_DEMO_TARGET:-x86_64-unknown-linux-gnu}" ;;
esac
clang -target "$target" -O0 -c examples/src/suspicious_kernel.c -o examples/binaries/suspicious_kernel.o
cargo run -q -p sigil-cli -- assess examples/binaries/suspicious_kernel.o --entry kernel --policy examples/policies/numeric_kernel.yml --out out/suspicious.report.md --emit-evidence out/suspicious.evidence.json
