#!/usr/bin/env bash
set -euo pipefail
mkdir -p examples/binaries out
clang -O0 -c examples/src/clean_kernel.c -o examples/binaries/clean_kernel.o
python -m sigil.cli assess examples/binaries/clean_kernel.o --entry kernel --policy examples/policies/numeric_kernel.yml --out out/clean.report.md --emit-evidence out/clean.evidence.json
