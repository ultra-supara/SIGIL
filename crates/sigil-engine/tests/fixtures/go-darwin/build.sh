#!/bin/sh
# Builds the Go darwin fixture of the engine tests (PR-4c-3b), once, by hand: the program of
# ../go-capabilities (os/exec, net.Dial, os.Create, os.Open), built with the real toolchain for
# darwin/arm64, without cgo. Go's linker writes its imports as LC_DYLD_INFO_ONLY bind opcodes.
# Every byte outside the header, the load commands, and __LINKEDIT is zeroed (zero.py): the tests
# read only those, never run the program, and git compresses the zeros.
# capabilities-darwin-arm64.bind is the full build's imports, as llvm-objdump reads them: LLVM
# 21.1.8's dump, and the script refuses another llvm-objdump. Go 1.25.6 gives the committed bytes
# (the build is reproducible: -trimpath, no VCS stamp, no cgo; the caller's GOARM64, GOFLAGS, and
# GOEXPERIMENT are pinned below, also against `go env -w`, because GOENV is off, and GOTOOLCHAIN is
# fixed).
#
# Everything is written into a temporary directory and moved into place at the end, so a failed
# build leaves the committed files as they were.
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' HUP INT TERM

fail() { echo "build.sh: $*" >&2; exit 1; }

export GOENV=off GOWORK=off GOTOOLCHAIN=go1.25.6
v=$(go env GOVERSION) || fail "go env GOVERSION failed"
[ "$v" = go1.25.6 ] || fail "needs go1.25.6, found $v"
llvm-objdump --version > "$tmp/version" || fail "llvm-objdump --version failed"
v=$(sed -n '/[0-9]\.[0-9]/{s/^[^0-9]*\([0-9][0-9]*\.[0-9][0-9.]*\).*/\1/p;q;}' "$tmp/version")
[ "$v" = 21.1.8 ] || fail "needs LLVM 21.1.8, found llvm-objdump ${v:-unknown}"
(cd ../go-capabilities && GOOS=darwin GOARCH=arm64 GOARM64=v8.0 GOFLAGS= GOEXPERIMENT= \
  CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$tmp/full" .)
python3 -I zero.py "$tmp/full" "$tmp/capabilities-darwin-arm64"
# The dump goes to a file first: /bin/sh may have no pipefail, and a tool that fails must stop
# the build.
llvm-objdump --macho --bind --lazy-bind "$tmp/full" > "$tmp/raw.bind"
sed "s|$tmp/full|capabilities-darwin-arm64|" "$tmp/raw.bind" > "$tmp/capabilities-darwin-arm64.bind"
# The zeroed file binds what the full build binds: zero.py kept every byte of them.
llvm-objdump --macho --bind --lazy-bind "$tmp/capabilities-darwin-arm64" > "$tmp/zeroed.bind"
sed "s|$tmp/capabilities-darwin-arm64|capabilities-darwin-arm64|" "$tmp/zeroed.bind" \
  > "$tmp/zeroed-renamed.bind"
cmp -s "$tmp/zeroed-renamed.bind" "$tmp/capabilities-darwin-arm64.bind" \
  || fail "the zeroed file binds otherwise than the full build"
(cd "$tmp" && sha256sum capabilities-darwin-arm64 capabilities-darwin-arm64.bind) \
  > "$tmp/SHA256SUMS"
mv "$tmp/capabilities-darwin-arm64" "$tmp/capabilities-darwin-arm64.bind" "$tmp/SHA256SUMS" .
cat SHA256SUMS
