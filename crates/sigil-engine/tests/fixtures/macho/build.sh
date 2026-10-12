#!/bin/sh
# Builds the linked Mach-O fixture of the engine tests, once, by hand. The tests never run this
# script, a compiler, or a linker; they read the committed files. Needs clang, ld64.lld, llvm-lipo,
# and llvm-otool (LLVM 16 or later, for -fixup_chains). libSystem.tbd is a stub with the one
# symbol hello.c imports, so no macOS SDK is needed.
#
# hello-universal has two slices that a macOS linker would emit:
# - x86_64, macOS 10.15: LC_DYLD_INFO_ONLY, LC_MAIN, LC_RPATH, LC_LOAD_DYLIB;
# - arm64, macOS 12, chained fixups: LC_DYLD_CHAINED_FIXUPS, LC_DYLD_EXPORTS_TRIE, LC_MAIN,
#   LC_RPATH, LC_LOAD_DYLIB, LC_CODE_SIGNATURE (ad hoc).
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
C="-O1 -fno-stack-protector -fno-asynchronous-unwind-tables"
clang -target x86_64-apple-macos10.15 $C -c hello.c -o "$tmp/x86_64.o"
ld64.lld -arch x86_64 -platform_version macos 10.15 10.15 -o "$tmp/x86_64" "$tmp/x86_64.o" \
   libSystem.tbd -rpath @loader_path/../lib
clang -target arm64-apple-macos12 $C -c hello.c -o "$tmp/arm64.o"
ld64.lld -arch arm64 -platform_version macos 12.0 12.0 -fixup_chains -o "$tmp/arm64" \
   "$tmp/arm64.o" libSystem.tbd -rpath @executable_path/../Frameworks
llvm-lipo -create "$tmp/x86_64" "$tmp/arm64" -output hello-universal
{
  llvm-otool -f hello-universal
  for arch in x86_64 arm64; do
    llvm-lipo -thin "$arch" hello-universal -output "$tmp/thin-$arch"
    echo "== $arch"
    llvm-otool -hl "$tmp/thin-$arch" | sed "s|$tmp/thin-$arch|hello-universal ($arch)|"
  done
} > hello-universal.otool
