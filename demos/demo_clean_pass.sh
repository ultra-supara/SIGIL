#!/usr/bin/env bash
set -euo pipefail
mkdir -p examples/binaries out
case "$(uname -s)" in
  Darwin) target="${SIGIL_DEMO_TARGET:-x86_64-apple-macos}" ;;
  *) target="${SIGIL_DEMO_TARGET:-x86_64-unknown-linux-gnu}" ;;
esac
clang -target "$target" -O0 -c examples/src/clean_kernel.c -o examples/binaries/clean_kernel.o
cargo run -q -p sigil-cli -- assess examples/binaries/clean_kernel.o --entry kernel --policy examples/policies/numeric_kernel.yml --out out/clean.report.md --emit-evidence out/clean.evidence.json
