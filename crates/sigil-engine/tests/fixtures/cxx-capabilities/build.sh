#!/bin/sh
# Builds the C++ capability fixture of the engine tests (PR-4c-3c), once, by hand. The tests never
# run this script, a compiler, or nm; they read the committed files. Needs g++ 15.3, binutils
# 2.46, and the libstdc++.so.6 that g++ links against, as COMPILERS records them (delete COMPILERS
# to adopt another toolchain on purpose).
#
# cxx-capabilities is a dynamically linked x86_64 PIE from three units:
# - new_abi.cc, -O2, libstdc++'s default ABI;
# - old_abi.cc, -O0, -D_GLIBCXX_USE_CXX11_ABI=0 (at -O2, g++ inlines its ofstream constructor);
# - derived.cc, -O0 (its constructor calls basic_ifstream's C2, with the VTT).
# It is never run. The script checks that it imports each name of MAPPED and UNMAPPED below.
#
# It also writes:
# - cxx-capabilities.nm: its undefined dynamic symbols, with versions, and their demangled forms;
# - libstdcxx-exports.tsv: the libstdc++ exports of the families the capability table draws from
#   (std::filesystem, basic_fstream, basic_filebuf, basic_ifstream, basic_ofstream): name,
#   version, demangled form. code::data's tests check every cxx.* entry and its source against it.
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

# The toolchain and the library, compared with the committed COMPILERS before anything is built.
for tool in g++ as ld; do
  v=$("$tool" --version) || fail "$tool --version failed"
  printf '%s\n' "$v" | sed -n 1p >> "$T/COMPILERS"
done
lib=$(g++ -print-file-name=libstdc++.so.6) || fail "g++ -print-file-name failed"
lib=$(readlink -f "$lib") || fail "readlink $lib failed"
[ -f "$lib" ] || fail "no libstdc++.so.6 at $lib"
sum=$(sha256sum "$lib") || fail "sha256sum $lib failed"
echo "$(basename "$lib") sha256:${sum%% *}" >> "$T/COMPILERS"
if [ -e COMPILERS ] && ! diff COMPILERS "$T/COMPILERS" >&2; then
  fail "the toolchain differs from COMPILERS (delete COMPILERS to rebuild with this one)"
fi

g++ -std=c++17 -O2 -c new_abi.cc -o "$T/new_abi.o"
g++ -std=c++17 -O0 -D_GLIBCXX_USE_CXX11_ABI=0 -c old_abi.cc -o "$T/old_abi.o"
g++ -std=c++17 -O0 -c derived.cc -o "$T/derived.o"
g++ -O2 "$T/new_abi.o" "$T/old_abi.o" "$T/derived.o" -o "$T/cxx-capabilities" -Wl,--build-id=none

# Its undefined dynamic symbols: name@version, and the demangled name.
nm -D --undefined-only --with-symbol-versions "$T/cxx-capabilities" > "$T/undefined.raw"
awk '{ print $NF }' "$T/undefined.raw" > "$T/undefined.ver"
sed 's/@.*//' "$T/undefined.ver" > "$T/undefined"
c++filt < "$T/undefined" > "$T/undefined.dem"
paste "$T/undefined.ver" "$T/undefined.dem" > "$T/cxx-capabilities.nm"
for name in $MAPPED $UNMAPPED; do
  grep -qxF "$name" "$T/undefined" || fail "cxx-capabilities does not import $name"
done

# The exports of the families, each a default version (@@), each name once.
nm -D --defined-only --with-symbol-versions "$lib" > "$T/exports.raw"
awk '{ print $NF }' "$T/exports.raw" > "$T/exports.all"
grep -E '^_ZNSt(10filesystem|13basic_fstream|13basic_filebuf|14basic_ifstream|14basic_ofstream)' \
  "$T/exports.all" > "$T/exports.ver" || fail "no exports of the families in $lib"
if grep -v '@@' "$T/exports.ver" > "$T/exports.nondefault"; then
  fail "an export of the families without a default version: $(sed -n 1p "$T/exports.nondefault")"
fi
sed 's/@@.*//' "$T/exports.ver" > "$T/exports.names"
sort "$T/exports.names" | uniq -d > "$T/exports.dup"
[ ! -s "$T/exports.dup" ] || fail "an export of the families at two versions: $(sed -n 1p "$T/exports.dup")"
sed 's/.*@@//' "$T/exports.ver" > "$T/exports.versions"
c++filt < "$T/exports.names" > "$T/exports.dem"
paste "$T/exports.names" "$T/exports.versions" "$T/exports.dem" > "$T/exports.tsv"
sort "$T/exports.tsv" > "$T/libstdcxx-exports.tsv"

(cd "$T" && sha256sum cxx-capabilities cxx-capabilities.nm libstdcxx-exports.tsv) > "$T/SHA256SUMS"
mv "$T/cxx-capabilities" "$T/cxx-capabilities.nm" "$T/libstdcxx-exports.tsv" "$T/SHA256SUMS" \
  "$T/COMPILERS" .
cat SHA256SUMS
