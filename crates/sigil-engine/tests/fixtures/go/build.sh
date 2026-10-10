#!/bin/sh
# Builds the Go build-info pieces of tests/goinfo.rs, once, by hand: a small module with one
# replaced dependency, for amd64, arm64, and s390x (big-endian). Only the .go.buildinfo section
# bytes and `go version -m` are committed. The tests never run go.
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
for arch in amd64 arm64 s390x; do
  GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$tmp/fixture-$arch" .
  python3 -I extract.py "$tmp/fixture-$arch" .go.buildinfo "go-$arch.buildinfo"
  go version -m "$tmp/fixture-$arch" | sed "s|$tmp/||" > "go-$arch.txt"
done
rm -rf "$tmp"
ls -la go-*.buildinfo go-*.txt
