#!/usr/bin/env bash
set -euo pipefail
mkdir -p examples/binaries out
clang -O0 -c examples/src/suspicious_kernel.c -o examples/binaries/suspicious_kernel.o
python -m sigil.cli assess examples/binaries/suspicious_kernel.o --entry kernel --policy examples/policies/numeric_kernel.yml --out out/suspicious.report.md --emit-evidence out/suspicious.evidence.json
