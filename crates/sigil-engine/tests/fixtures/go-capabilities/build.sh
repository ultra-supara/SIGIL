#!/bin/sh
# Builds the Go capability fixture of tests/signatures.rs, once, by hand (PR-4c-3a): a small
# program that uses os/exec, net.Dial, os.Create, and os.Open, built with the real toolchain for
# linux/amd64. Only its .gopclntab and .go.buildinfo section bytes, `go version -m`, and their
# SHA-256s are committed. The tests never run go or the program. Go 1.25.6 gives the committed
# bytes (the build is reproducible: -trimpath, no VCS stamp, no cgo; the caller's GOAMD64,
# GOFLAGS, and GOEXPERIMENT are pinned below, also against `go env -w`, because GOENV is off, and
# GOTOOLCHAIN is fixed).
#
# The tests pin offsets in these bytes (tests/signatures.rs). After changing main.go, re-read them,
# and keep syscall.Exec out of the function-name table: it must stay only a file name there.
#
# Everything is written into a temporary directory and moved into place at the end, so a failed
# build leaves the committed files as they were.
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' HUP INT TERM

fail() { echo "build.sh: $*" >&2; exit 1; }

export GOENV=off GOTOOLCHAIN=go1.25.6
v=$(go env GOVERSION) || fail "go env GOVERSION failed"
[ "$v" = go1.25.6 ] || fail "needs go1.25.6, found $v"
GOOS=linux GOARCH=amd64 GOAMD64=v1 GOFLAGS= GOEXPERIMENT= CGO_ENABLED=0 \
  go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$tmp/capabilities" .
python3 -I ../go/extract.py "$tmp/capabilities" .gopclntab "$tmp/capabilities.gopclntab"
python3 -I ../go/extract.py "$tmp/capabilities" .go.buildinfo "$tmp/capabilities.buildinfo"
go version -m "$tmp/capabilities" > "$tmp/version.txt"
sed "s|$tmp/||" "$tmp/version.txt" > "$tmp/capabilities.txt"
(cd "$tmp" && sha256sum capabilities.gopclntab capabilities.buildinfo capabilities.txt) \
  > "$tmp/SHA256SUMS"
mv "$tmp/capabilities.gopclntab" "$tmp/capabilities.buildinfo" "$tmp/capabilities.txt" \
  "$tmp/SHA256SUMS" .
cat SHA256SUMS
