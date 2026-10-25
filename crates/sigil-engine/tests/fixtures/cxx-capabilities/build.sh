#!/bin/sh
# Builds the C++ capability fixture of the engine tests (PR-4c-3c), once, by hand. The tests never
# run this script, a compiler, or nm; they read the committed files. Needs g++ 15.3 and binutils
# 2.46 (as, ld, nm, c++filt, readelf), as COMPILERS records them with two libraries: the
# libstdc++.so that g++ links against (GCC 15's), and the system's libstdc++.so.6, which a program
# loads (here GCC 16's libstdc++.so.6.0.35). Delete COMPILERS to adopt another toolchain on
# purpose.
#
# cxx-capabilities is a dynamically linked x86_64 PIE from three units:
# - new_abi.cc, -O2, libstdc++'s default ABI;
# - old_abi.cc, -O0, -D_GLIBCXX_USE_CXX11_ABI=0 (at -O2, g++ inlines its ofstream constructor);
# - derived.cc, -O0 (its constructor calls basic_ifstream's C2, with the VTT).
# It is never run. The script checks that it is a PIE and that it imports each name of MAPPED
# and UNMAPPED below. tests/cxx_capabilities.rs pins one address of it, config_file's VTT
# (_ZTT11config_file): a rebuild that moves it must update that test.
#
# It also writes:
# - cxx-capabilities.nm: its undefined dynamic symbols, with versions, and their demangled forms;
# - libstdcxx-exports.tsv: the exports of the system's libstdc++.so.6 whose mangled names begin
#   _ZNSt10filesystem, _ZNSt13basic_fstream, _ZNSt13basic_filebuf, _ZNSt14basic_ifstream, or
#   _ZNSt14basic_ofstream: name, version, demangled form. The capability table's cxx.* names come
#   from std::filesystem, basic_ifstream, and basic_ofstream; basic_fstream and basic_filebuf are
#   there for the names that stay unmapped. code::data's tests check every cxx.* entry and its
#   source against it. The library g++ links against must export the same names at the same
#   versions, or the build fails.
#
# Everything is built in a temporary directory and moved into place at the end, so a failed build
# leaves the committed files as they were. No pipe is used where a failing command could be lost.
set -eu
cd "$(dirname "$0")"
export LC_ALL=C
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
trap 'exit 1' HUP INT TERM

fail() { echo "build.sh: $*" >&2; exit 1; }

# The imports among the capability table's cxx.* names (spec §5).
MAPPED='_ZNSt10filesystem18create_directoriesERKNS_7__cxx114pathE
_ZNSt10filesystem6removeERKNS_4pathE
_ZNSt10filesystem6removeERKNS_7__cxx114pathERSt10error_code
_ZNSt10filesystem6renameERKNS_7__cxx114pathES3_
_ZNSt10filesystem9copy_fileERKNS_7__cxx114pathES3_NS_12copy_optionsE
_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC1EPKcSt13_Ios_Openmode
_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC2EPKcSt13_Ios_Openmode
_ZNSt14basic_ofstreamIcSt11char_traitsIcEEC1ERKNSt7__cxx1112basic_stringIcS1_SaIcEEESt13_Ios_Openmode
_ZNSt14basic_ofstreamIcSt11char_traitsIcEEC1ERKSsSt13_Ios_Openmode'
# Imports that stay unmapped (spec §3).
UNMAPPED='_ZNSt10filesystem11permissionsERKNS_7__cxx114pathENS_5permsENS_12perm_optionsE
_ZNSt10filesystem15last_write_timeERKNS_7__cxx114pathE
_ZNSt10filesystem6statusERKNS_7__cxx114pathE
_ZNSt10filesystem7__cxx1118directory_iteratorC1ERKNS0_4pathENS_17directory_optionsEPSt10error_code
_ZNSt13basic_filebufIcSt11char_traitsIcEE4openEPKcSt13_Ios_Openmode
_ZNSt13basic_fstreamIcSt11char_traitsIcEEC1EPKcSt13_Ios_Openmode'

# The library at path $1, resolved: its file, or the build fails.
library() {
  lib=$(readlink -f "$1") || fail "readlink $1 failed"
  [ -f "$lib" ] || fail "no library at $1"
  echo "$lib"
}

# The exports of library $1 whose names begin as the families' do, as name@@version lines in $2.
# Each must be a default version (@@), and each name listed once.
family_exports() {
  nm -D --defined-only --with-symbol-versions "$1" > "$T/exports.raw"
  awk '{ print $NF }' "$T/exports.raw" > "$T/exports.all"
  grep -E '^_ZNSt(10filesystem|13basic_fstream|13basic_filebuf|14basic_ifstream|14basic_ofstream)' \
    "$T/exports.all" > "$2" || fail "no exports of the families in $1"
  rc=0
  grep -v '@@' "$2" > "$T/exports.nondefault" || rc=$?
  case $rc in
    0) fail "an export of the families without a default version in $1:" \
         "$(sed -n 1p "$T/exports.nondefault")" ;;
    1) ;;
    *) fail "grep -v failed on the exports of $1" ;;
  esac
  sed 's/@@.*//' "$2" > "$T/exports.names"
  sort "$T/exports.names" > "$T/exports.sorted"
  uniq -d "$T/exports.sorted" > "$T/exports.dup"
  if [ -s "$T/exports.dup" ]; then
    fail "an export of the families at two versions in $1: $(sed -n 1p "$T/exports.dup")"
  fi
}

# The toolchain and the two libraries, compared with the committed COMPILERS before anything is
# built.
for tool in g++ as ld nm c++filt readelf; do
  v=$("$tool" --version) || fail "$tool --version failed"
  printf '%s\n' "$v" | sed -n 1p >> "$T/COMPILERS"
done
link=$(g++ -print-file-name=libstdc++.so) || fail "g++ -print-file-name failed"
link=$(library "$link")
load=$(g++ -print-file-name=libstdc++.so.6) || fail "g++ -print-file-name failed"
load=$(library "$load")
sum=$(sha256sum "$link") || fail "sha256sum $link failed"
echo "link: $link sha256:${sum%% *}" >> "$T/COMPILERS"
sum=$(sha256sum "$load") || fail "sha256sum $load failed"
echo "load: $load sha256:${sum%% *}" >> "$T/COMPILERS"
if [ -e COMPILERS ] && ! diff COMPILERS "$T/COMPILERS" >&2; then
  fail "the toolchain differs from COMPILERS (delete COMPILERS to rebuild with this one)"
fi

g++ -std=c++17 -O2 -fPIE -c new_abi.cc -o "$T/new_abi.o"
g++ -std=c++17 -O0 -fPIE -D_GLIBCXX_USE_CXX11_ABI=0 -c old_abi.cc -o "$T/old_abi.o"
g++ -std=c++17 -O0 -fPIE -c derived.cc -o "$T/derived.o"
g++ -pie "$T/new_abi.o" "$T/old_abi.o" "$T/derived.o" -o "$T/cxx-capabilities" \
  -Wl,--build-id=none
readelf -h "$T/cxx-capabilities" > "$T/header"
grep -q '^ *Type: *DYN ' "$T/header" || fail "cxx-capabilities is not a PIE"

# Its undefined dynamic symbols: name@version, and the demangled name.
nm -D --undefined-only --with-symbol-versions "$T/cxx-capabilities" > "$T/undefined.raw"
awk '{ print $NF }' "$T/undefined.raw" > "$T/undefined.ver"
sed 's/@.*//' "$T/undefined.ver" > "$T/undefined"
c++filt < "$T/undefined" > "$T/undefined.dem"
paste "$T/undefined.ver" "$T/undefined.dem" > "$T/cxx-capabilities.nm"
for name in $MAPPED $UNMAPPED; do
  grep -qxF "$name" "$T/undefined" || fail "cxx-capabilities does not import $name"
done

# The exports of the families: the loaded library's, which the linked one must equal.
family_exports "$link" "$T/link.ver"
sort "$T/link.ver" > "$T/link.sorted"
family_exports "$load" "$T/load.ver"
sort "$T/load.ver" > "$T/load.sorted"
cmp -s "$T/link.sorted" "$T/load.sorted" \
  || fail "the linked and the loaded libstdc++ export the families differently"
sed 's/@@.*//' "$T/load.ver" > "$T/exports.names"
sed 's/.*@@//' "$T/load.ver" > "$T/exports.versions"
c++filt < "$T/exports.names" > "$T/exports.dem"
paste "$T/exports.names" "$T/exports.versions" "$T/exports.dem" > "$T/exports.tsv"
sort "$T/exports.tsv" > "$T/libstdcxx-exports.tsv"

(cd "$T" && sha256sum cxx-capabilities cxx-capabilities.nm libstdcxx-exports.tsv) > "$T/SHA256SUMS"
mv "$T/cxx-capabilities" "$T/cxx-capabilities.nm" "$T/libstdcxx-exports.tsv" "$T/SHA256SUMS" \
  "$T/COMPILERS" .
cat SHA256SUMS
