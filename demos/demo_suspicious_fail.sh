#!/usr/bin/env bash
python -m sigil.cli assess examples/binaries/suspicious_kernel.o --entry kernel --policy examples/policies/numeric_kernel.yml
