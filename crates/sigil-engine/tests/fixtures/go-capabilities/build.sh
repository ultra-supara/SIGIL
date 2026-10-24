#!/bin/sh
# Builds the Go capability fixture of tests/signatures.rs, once, by hand (PR-4c-3a): a small
# program that uses os/exec, net.Dial, os.Create, and os.Open, built with the real toolchain for
# linux/amd64. Only its .gopclntab and .go.buildinfo section bytes, `go version -m`, and their
# SHA-256s are committed. The tests never run go or the program. Go 1.25.6 gives the committed
# bytes (the build is reproducible: -trimpath, no VCS stamp, no cgo).
set -eu
cd "$(dirname "$0")"
test "$(go env GOVERSION)" = go1.25.6
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags=-s\ -w \
  -o "$tmp/capabilities" .
python3 -I ../go/extract.py "$tmp/capabilities" .gopclntab capabilities.gopclntab
python3 -I ../go/extract.py "$tmp/capabilities" .go.buildinfo capabilities.buildinfo
go version -m "$tmp/capabilities" | sed "s|$tmp/||" > capabilities.txt
sha256sum capabilities.gopclntab capabilities.buildinfo capabilities.txt > SHA256SUMS
cat SHA256SUMS
