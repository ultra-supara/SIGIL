#!/bin/sh
# Builds the Mach-O import fixtures of the engine tests (PR-4c-3b), once, by hand. The tests never
# run this script, a compiler, or a linker; they read the committed files. Needs clang, ld64.lld,
# llvm-lipo, llvm-otool, llvm-objdump, and llvm-nm. LLVM 21.1.8 gives the committed bytes (the
# linker records its version in LC_BUILD_VERSION, and the dump is LLVM's): the script refuses
# another. libSystem.tbd and libfoo.tbd are stubs with the symbols imports.c imports, so no macOS
# SDK is needed.
#
# imports-universal has two slices that a macOS linker would emit:
# - x86_64, macOS 10.15: LC_DYLD_INFO_ONLY, its imports in bind and lazy-bind opcodes;
# - arm64, macOS 12, chained fixups: its imports in LC_DYLD_CHAINED_FIXUPS.
# imports-arm64.o is the arm64 object file it is linked from: its imports are its undefined
# symbols. imports-universal.otool holds each slice's load commands and imports, as LLVM reads
# them.
#
# Everything is written into a temporary directory and moved into place at the end, so a failed
# build leaves the committed files as they were.
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' HUP INT TERM

fail() { echo "build.sh: $*" >&2; exit 1; }

for tool in clang ld64.lld llvm-objdump; do
  v=$("$tool" --version | sed -n '1s/.* \([0-9][0-9.]*\).*/\1/p') || fail "$tool --version failed"
  [ "$v" = 21.1.8 ] || fail "needs LLVM 21.1.8, found $tool ${v:-unknown}"
done

C="-O1 -fno-stack-protector -fno-asynchronous-unwind-tables"
clang -target x86_64-apple-macos10.15 $C -c imports.c -o "$tmp/x86_64.o"
ld64.lld -arch x86_64 -platform_version macos 10.15 10.15 -o "$tmp/x86_64" "$tmp/x86_64.o" \
   libSystem.tbd libfoo.tbd
clang -target arm64-apple-macos12 $C -c imports.c -o "$tmp/imports-arm64.o"
ld64.lld -arch arm64 -platform_version macos 12.0 12.0 -fixup_chains -o "$tmp/arm64" \
   "$tmp/imports-arm64.o" libSystem.tbd libfoo.tbd
llvm-lipo -create "$tmp/x86_64" "$tmp/arm64" -output "$tmp/imports-universal"
# The dump goes to a file first: /bin/sh may have no pipefail, and a tool that fails must stop
# the build.
{
  llvm-otool -f "$tmp/imports-universal"
  for arch in x86_64 arm64; do
    echo "== $arch"
    llvm-otool -hl "$tmp/$arch"
  done
  echo "== x86_64 binds"
  llvm-objdump --macho --bind --lazy-bind "$tmp/x86_64"
  echo "== arm64 chained fixups"
  llvm-objdump --macho --chained-fixups "$tmp/arm64"
  echo "== imports-arm64.o undefined symbols"
  llvm-nm -u "$tmp/imports-arm64.o"
} > "$tmp/raw.otool"
sed "s|$tmp/||g" "$tmp/raw.otool" > "$tmp/imports-universal.otool"
(cd "$tmp" && sha256sum imports-universal imports-arm64.o imports-universal.otool) \
  > "$tmp/SHA256SUMS"
mv "$tmp/imports-universal" "$tmp/imports-arm64.o" "$tmp/imports-universal.otool" \
  "$tmp/SHA256SUMS" .
cat SHA256SUMS
