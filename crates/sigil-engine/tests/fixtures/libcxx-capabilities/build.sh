#!/bin/sh
# Builds the libc++ capability fixtures of the engine tests (#105), once, by hand. The tests never
# run this script, a compiler, a linker, or nm; they read the committed files. Needs LLVM 22.1.8
# (clang++-22, ld.lld-22, ld64.lld-22, llvm-nm-22, llvm-cxxfilt-22, llvm-readelf-22,
# llvm-otool-22, llvm-objdump-22) and libc++ 22.1.8 (Debian's libc++-22-dev and libc++abi-22-dev,
# and libc++1, whose libc++.so.1 a program loads), as COMPILERS records them with two libraries:
# the libc++.so.1 that clang++-22 links against and the one a program loads. Delete COMPILERS to
# adopt another toolchain on purpose.
#
# libcxx-capabilities is a dynamically linked x86_64 PIE from elf.cc, -O2, -stdlib=libc++. It is
# never run. The script checks that it is a PIE and that it imports each name of MAPPED and
# UNMAPPED below.
#
# libcxx-macho is an arm64 Mach-O executable (macOS 13, chained fixups) from macho.cc, which
# declares the libc++ functions it calls instead of including libc++'s headers, so no macOS SDK is
# needed. ld64.lld links it against two stubs: libc++.tbd (/usr/lib/libc++.1.dylib) and
# libSystem.tbd. libc++.tbd also lists _connect, so _connect is bound to libc++: a POSIX name from
# the dylib whose names are C++ ones. The script checks each import's dylib (MACHO_IMPORTS). It is
# never run.
#
# It also writes:
# - libcxx-capabilities.nm: the ELF's undefined dynamic symbols and their demangled forms;
# - libcxx-exports.tsv: the exports of the loaded libc++.so.1 whose mangled names begin
#   _ZNSt3__14__fs10filesystem, _ZNSt3__113basic_fstream, _ZNSt3__113basic_filebuf,
#   _ZNSt3__114basic_ifstream, or _ZNSt3__114basic_ofstream: name, demangled form. The capability
#   table's libc++ names come from it; code::data's tests check every one and its source against
#   it. The linked libc++.so.1 must export the same names, and none may have a version, or the
#   build fails;
# - libcxx-macho.otool: the Mach-O's load commands and chained-fixup imports, as LLVM reads them.
#
# Everything is built and checked in a temporary directory, and moved into place only after every
# step has succeeded: a failed build or check changes no committed file. The final moves are not
# atomic as a set (nor each one, across file systems): if one of them fails, some files are new
# and some old, the script exits non-zero, and `git checkout -- .` in this directory restores the
# committed ones. No pipe is used where a failing command could be lost.
set -eu
cd "$(dirname "$0")"
export LC_ALL=C
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
trap 'exit 1' HUP INT TERM

fail() { echo "build.sh: $*" >&2; exit 1; }

# The ELF's imports among the capability table's libc++ names.
MAPPED='_ZNSt3__114basic_ifstreamIcNS_11char_traitsIcEEE4openEPKcj
_ZNSt3__114basic_ofstreamIcNS_11char_traitsIcEEE4openERKNS_12basic_stringIcS2_NS_9allocatorIcEEEEj
_ZNSt3__14__fs10filesystem11__copy_fileERKNS1_4pathES4_NS1_12copy_optionsEPNS_10error_codeE
_ZNSt3__14__fs10filesystem20__create_directoriesERKNS1_4pathEPNS_10error_codeE
_ZNSt3__14__fs10filesystem8__removeERKNS1_4pathEPNS_10error_codeE
_ZNSt3__14__fs10filesystem8__renameERKNS1_4pathES4_PNS_10error_codeE'
# The ELF's imports that stay unmapped.
UNMAPPED='_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE4openEPKcj
_ZNSt3__14__fs10filesystem13__permissionsERKNS1_4pathENS1_5permsENS1_12perm_optionsEPNS_10error_codeE
_ZNSt3__14__fs10filesystem17__last_write_timeERKNS1_4pathEPNS_10error_codeE
_ZNSt3__14__fs10filesystem8__statusERKNS1_4pathEPNS_10error_codeE'
# Every import of the Mach-O, and its dylib as llvm-objdump names it.
MACHO_IMPORTS='__ZNSt3__14__fs10filesystem13__permissionsERKNS1_4pathENS1_5permsENS1_12perm_optionsEPNS_10error_codeE libc++
__ZNSt3__14__fs10filesystem8__removeERKNS1_4pathEPNS_10error_codeE libc++
_connect libc++
_getenv libSystem'

# The library at path $1, resolved: its file, or the build fails.
library() {
  lib=$(readlink -f "$1") || fail "readlink $1 failed"
  [ -f "$lib" ] || fail "no library at $1"
  echo "$lib"
}

# The exports of library $1 whose names begin as the families' do, sorted, in $2. None may have a
# version, and each must be listed once.
family_exports() {
  llvm-nm-22 -D --defined-only "$1" > "$T/exports.raw"
  awk '{ print $NF }' "$T/exports.raw" > "$T/exports.all"
  grep -E '^_ZNSt3__1(4__fs10filesystem|13basic_fstream|13basic_filebuf|14basic_ifstream|14basic_ofstream)' \
    "$T/exports.all" > "$T/exports.fam" || fail "no exports of the families in $1"
  rc=0
  grep '@' "$T/exports.fam" > "$T/exports.versioned" || rc=$?
  case $rc in
    0) fail "an export of the families with a version in $1: $(sed -n 1p "$T/exports.versioned")" ;;
    1) ;;
    *) fail "grep failed on the exports of $1" ;;
  esac
  sort "$T/exports.fam" > "$2"
  uniq -d "$2" > "$T/exports.dup"
  if [ -s "$T/exports.dup" ]; then
    fail "an export of the families listed twice in $1: $(sed -n 1p "$T/exports.dup")"
  fi
}

# The toolchain and the two libraries, compared with the committed COMPILERS before anything is
# built. Each tool's version: the first dotted number of the first line that has one.
for tool in clang++-22 ld.lld-22 ld64.lld-22 llvm-nm-22 llvm-cxxfilt-22 llvm-readelf-22 \
    llvm-otool-22 llvm-objdump-22; do
  "$tool" --version > "$T/version" || fail "$tool --version failed"
  line=$(sed -n '/[0-9]\.[0-9]/{p;q;}' "$T/version")
  v=$(printf '%s\n' "$line" | sed -n 's/^[^0-9]*\([0-9][0-9]*\.[0-9][0-9.]*\).*/\1/p')
  [ "$v" = 22.1.8 ] || fail "needs LLVM 22.1.8, found $tool ${v:-unknown}"
  echo "$tool: $line" >> "$T/COMPILERS"
done
link=$(clang++-22 -stdlib=libc++ -print-file-name=libc++.so.1) || fail "clang++-22 -print-file-name failed"
link=$(library "$link")
# Where Debian's loader finds libc++.so.1.
load=$(library /usr/lib/x86_64-linux-gnu/libc++.so.1)
sum=$(sha256sum "$link") || fail "sha256sum $link failed"
echo "link: $link sha256:${sum%% *}" >> "$T/COMPILERS"
sum=$(sha256sum "$load") || fail "sha256sum $load failed"
echo "load: $load sha256:${sum%% *}" >> "$T/COMPILERS"
if [ -e COMPILERS ] && ! diff COMPILERS "$T/COMPILERS" >&2; then
  fail "the toolchain differs from COMPILERS (delete COMPILERS to rebuild with this one)"
fi

# The ELF. lld 22.1.8 by path: the unversioned ld.lld may be another LLVM's.
ld=$(command -v ld.lld-22) || fail "no ld.lld-22"
clang++-22 -std=c++17 -O2 -stdlib=libc++ -fPIE -c elf.cc -o "$T/elf.o"
clang++-22 -stdlib=libc++ --ld-path="$ld" -pie "$T/elf.o" -o "$T/libcxx-capabilities" \
  -Wl,--build-id=none
llvm-readelf-22 -h "$T/libcxx-capabilities" > "$T/header"
grep -q '^ *Type: *DYN ' "$T/header" || fail "libcxx-capabilities is not a PIE"

# Its undefined dynamic symbols: name (with a version, if any), and the demangled name.
llvm-nm-22 -D --undefined-only "$T/libcxx-capabilities" > "$T/undefined.raw"
awk '{ print $NF }' "$T/undefined.raw" > "$T/undefined.ver"
sed 's/@.*//' "$T/undefined.ver" > "$T/undefined"
llvm-cxxfilt-22 < "$T/undefined" > "$T/undefined.dem"
paste "$T/undefined.ver" "$T/undefined.dem" > "$T/libcxx-capabilities.nm"
for name in $MAPPED $UNMAPPED; do
  grep -qxF "$name" "$T/undefined" || fail "libcxx-capabilities does not import $name"
done

# The exports of the families: the loaded library's, which the linked one must equal.
family_exports "$link" "$T/link.sorted"
family_exports "$load" "$T/load.sorted"
cmp -s "$T/link.sorted" "$T/load.sorted" \
  || fail "the linked and the loaded libc++ export the families differently"
llvm-cxxfilt-22 < "$T/load.sorted" > "$T/exports.dem"
paste "$T/load.sorted" "$T/exports.dem" > "$T/libcxx-exports.tsv"

# The Mach-O.
clang++-22 -target arm64-apple-macos13 -std=c++17 -O1 -nostdinc++ -fno-exceptions -fno-rtti \
  -fno-stack-protector -fno-asynchronous-unwind-tables -c macho.cc -o "$T/macho.o"
ld64.lld-22 -arch arm64 -platform_version macos 13.0 13.0 -fixup_chains \
  -o "$T/libcxx-macho" "$T/macho.o" libc++.tbd libSystem.tbd
llvm-objdump-22 --macho --chained-fixups "$T/libcxx-macho" > "$T/fixups"
# Each import's name and dylib: lib_ordinal's line precedes name_offset's.
awk '/lib_ordinal = /{ lib = $NF; gsub(/[()]/, "", lib) }
     /name_offset = /{ name = $NF; gsub(/[()]/, "", name); print name, lib }' \
  "$T/fixups" > "$T/macho.imports.raw"
sort "$T/macho.imports.raw" > "$T/macho.imports"
printf '%s\n' "$MACHO_IMPORTS" > "$T/macho.expected.raw"
sort "$T/macho.expected.raw" > "$T/macho.expected"
if ! diff "$T/macho.expected" "$T/macho.imports" >&2; then
  fail "libcxx-macho's imports are not MACHO_IMPORTS"
fi
{
  llvm-otool-22 -hl "$T/libcxx-macho"
  echo "== chained fixups"
  cat "$T/fixups"
} > "$T/raw.otool"
sed "s|$T/||g" "$T/raw.otool" > "$T/libcxx-macho.otool"

(cd "$T" && sha256sum libcxx-capabilities libcxx-capabilities.nm libcxx-exports.tsv \
  libcxx-macho libcxx-macho.otool) > "$T/SHA256SUMS"
mv "$T/libcxx-capabilities" "$T/libcxx-capabilities.nm" "$T/libcxx-exports.tsv" \
  "$T/libcxx-macho" "$T/libcxx-macho.otool" "$T/SHA256SUMS" "$T/COMPILERS" .
cat SHA256SUMS
