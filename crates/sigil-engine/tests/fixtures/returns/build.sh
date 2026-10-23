#!/bin/sh
# Builds the returned-value fixtures of the engine tests (PR-4c-2b), once, by hand. The tests never
# run this script or a compiler; they read the committed files. Needs gcc 15.3, clang 21.1.8,
# binutils 2.46, and ld.lld 21.1.8.
#
# The toolchain must match COMPILERS (delete COMPILERS to adopt another one on purpose). Everything
# is built into a temporary directory and checked there (README.md lists the checked shapes). Only
# when every check passes are the old outputs replaced; a failed check stops the build (exit 1)
# and leaves the committed files as they were.
set -eu
cd "$(dirname "$0")"
export LC_ALL=C
D=$(pwd)
T=$(mktemp -d)
B="$T/out"
mkdir "$B"
trap 'rm -rf "$T"' EXIT
trap 'exit 1' HUP INT TERM

fail() { echo "build.sh: $*" >&2; exit 1; }

# The toolchain, compared with the committed COMPILERS before anything is built.
toolchain() {
  local tool v p
  # The assembler and linkers are the ones the compilers run, not whatever else is on PATH.
  for tool in gcc clang as ld ld.lld; do
    case $tool in
      as | ld) p=$(gcc -print-prog-name=$tool) || fail "gcc -print-prog-name=$tool failed" ;;
      ld.lld) p=$(clang -print-prog-name=ld.lld) || fail "clang -print-prog-name=ld.lld failed" ;;
      *) p=$tool ;;
    esac
    v=$("$p" --version) || fail "$p --version failed"
    printf '%s\n' "$v" | sed -n 1p
  done
}
tc=$(toolchain) || exit 1
printf '%s\n' "$tc" > "$B/COMPILERS"
if [ -e COMPILERS ] && ! diff COMPILERS "$B/COMPILERS" >&2; then
  fail "the toolchain differs from COMPILERS (delete COMPILERS to rebuild with this one)"
fi

# Every library has SONAME libggml-base.so.0, as v0.30.6's libggml-base.so.0.13.1.
SO="-shared -fPIC -Wl,-soname,libggml-base.so.0 -Wl,-z,nopack-relative-relocs"
gcc -O2 $SO -o "$B/version-gcc-O2.so" version.c
clang -O0 $SO -o "$B/version-clang-O0.so" version.c
gcc -O0 -fcf-protection=full $SO -o "$B/version-cet-gcc-O0.so" version.c
gcc -O2 $SO -DVERSION='"1.0.0"' -o "$B/version-1.0.0-gcc-O2.so" version.c
gcc -O2 -shared -fPIC -Wl,-soname,libggml-base.so.0 -Wl,-z,pack-relative-relocs \
  -o "$B/version-relr-gcc-O2.so" version.c
# A string of 300 bytes: no NUL within the 256 read.
L=$(printf '%0300d' 0 | tr 0 x)
gcc -O2 $SO -DVERSION="\"$L\"" -o "$B/version-long-gcc-O2.so" version.c
gcc -O2 $SO -o "$B/global-gcc-O2.so" global.c
gcc -O0 $SO -o "$B/branch-gcc-O0.so" branch.c
clang --target=aarch64-linux-gnu -fuse-ld=lld -nostdlib -O2 -shared -fPIC \
  -Wl,-soname,libggml-base.so.0 -o "$B/version-aarch64.so" version.c

# ---------------------------------------------------------------------------------------------
# The shapes the tests rely on (README.md lists them). Each check stops the build when it fails.
cd "$B"
X86="version-gcc-O2.so version-clang-O0.so version-cet-gcc-O0.so version-1.0.0-gcc-O2.so
  version-relr-gcc-O2.so version-long-gcc-O2.so global-gcc-O2.so branch-gcc-O0.so"

# Helpers that read a tool's output assign it first, with `|| exit 1`, so a failed tool is never
# read as "no match": `set -e` does not apply inside a function called from a condition.

# The instructions (mnemonic and operands, one per line, without addresses or comments) in the
# st_size bytes of the exported function $2 of $1, from objdump -d.
insns() {
  local sym out
  sym=$(dynsym "$1" "$2") || exit 1
  set -- "$1" "$2" $sym
  out=$(objdump -d -z --no-show-raw-insn --start-address=0x$3 --stop-address=$((0x$3 + $4)) "$1") \
    || fail "objdump -d $1"
  printf '%s\n' "$out" | awk '
    /^[0-9a-f]+ <.*>:$/ { on = 1; next }
    on && /^ *[0-9a-f]+:/ { sub(/^ *[0-9a-f]+:[[:space:]]*/, ""); sub(/[[:space:]]+#.*$/, ""); print }'
}

# The SONAME of $1.
soname() {
  local out
  out=$(readelf -dW "$1") || fail "readelf -d $1"
  printf '%s\n' "$out" | sed -n 's/.*(SONAME).*\[\(.*\)\]$/\1/p'
}

# Whether $1 has the dynamic tag $2 (e.g. RELR).
tag() {
  local out
  out=$(readelf -dW "$1") || fail "readelf -d $1"
  printf '%s\n' "$out" | grep -q "($2)"
}

# "value size type" of the exported symbol $2 of $1, from its .dynsym; fails without exactly one.
dynsym() {
  local out r
  out=$(readelf --dyn-syms -W "$1") || fail "readelf --dyn-syms $1"
  r=$(printf '%s\n' "$out" | awk -v n="$2" '$8 == n && $7 != "UND" { print $2, $3, $4; c++ } END { exit c != 1 }') \
    || fail "$1: not exactly one exported $2"
  echo "$r"
}

for f in $X86 version-aarch64.so; do
  [ "$(soname "$f")" = libggml-base.so.0 ] || fail "$f: SONAME is not libggml-base.so.0"
  for s in ggml_version ggml_commit; do
    r=$(dynsym "$f" $s) || exit 1
    set -- $r
    [ "$3" = FUNC ] || fail "$f: $s is $3, not FUNC"
  done
done
readelf -hW version-aarch64.so | grep -Eq 'Machine: +AArch64' || fail "version-aarch64.so: not AArch64"
for f in $X86 version-aarch64.so; do
  h=$(readelf -hW "$f") || fail "readelf -h $f"
  printf '%s\n' "$h" | grep -Eq 'Type: +DYN' || fail "$f: not ET_DYN"
done
for f in $X86; do
  readelf -hW "$f" | grep -Eq 'Machine: +Advanced Micro Devices X86-64' || fail "$f: not x86-64"
done

# The instructions of the function $2 of $1, its lea displacements written X.
norm() {
  local got
  got=$(insns "$1" "$2") || exit 1
  printf '%s\n' "$got" | sed -E -e 's/lea +0x[0-9a-f]+\(%rip\),%rax/lea    X(%rip),%rax/' \
    -e 's/mov +0x[0-9a-f]+\(%rip\),%rax/mov    X(%rip),%rax/'
}
# Fails unless the function $2 of $1 is the instructions $3, one per line, as `norm` writes them,
# in exactly $4 bytes (its st_size).
same() {
  local got sym
  got=$(norm "$1" "$2") || exit 1
  sym=$(dynsym "$1" "$2") || exit 1
  set -- "$1" "$2" "$3" "$4" $sym
  [ "$6" = "$4" ] || fail "$1: $2 is $6 bytes, expected $4"
  [ "$got" = "$3" ] || fail "$1: $2 is
$got
expected
$3"
}
lea_ret="$(printf 'lea    X(%%rip),%%rax\nret')"
for f in version-gcc-O2.so version-1.0.0-gcc-O2.so version-relr-gcc-O2.so version-long-gcc-O2.so; do
  same "$f" ggml_version "$lea_ret" 8
  same "$f" ggml_commit "$lea_ret" 8
done
framed="$(printf 'push   %%rbp\nmov    %%rsp,%%rbp\nlea    X(%%rip),%%rax\npop    %%rbp\nret')"
same version-clang-O0.so ggml_version "$framed" 13
same version-cet-gcc-O0.so ggml_version "$(printf 'endbr64\n%s' "$framed")" 17
same global-gcc-O2.so ggml_commit "$lea_ret" 8
same global-gcc-O2.so ggml_version \
  "$(printf 'mov    X(%%rip),%%rax\nmov    (%%rax),%%rax\nret')" 11
b=$(insns branch-gcc-O0.so ggml_version) || exit 1
n=$(printf '%s\n' "$b" | grep -Ec '^(je|jne|jmp) ') || true
[ "$n" -ge 2 ] || fail "branch: $n jumps in
$b"
tag version-relr-gcc-O2.so RELR || fail "version-relr-gcc-O2.so: no DT_RELR"
for f in $X86; do
  [ "$f" = version-relr-gcc-O2.so ] && continue
  tag "$f" RELR && fail "$f: has DT_RELR"
  tag "$f" RELA || fail "$f: no DT_RELA"
done
for f in $X86 version-aarch64.so; do
  [ "$f" = version-relr-gcc-O2.so ] || ! tag "$f" RELR || fail "$f: has DT_RELR"
  tag "$f" REL && fail "$f: has DT_REL"
  tag "$f" TEXTREL && fail "$f: has DT_TEXTREL"
done
# The strings: what each version function returns, in .rodata.
for f in $X86; do
  case $f in
    version-1.0.0-*) v=1.0.0 ;;
    version-long-*) v=$L ;;
    *) v=0.13.1 ;;
  esac
  ro=$(readelf -p .rodata "$f") || fail "readelf -p .rodata $f"
  printf '%s\n' "$ro" | awk -v v="$v" '{ sub(/^ *\[ *[0-9a-f]+\] +/, ""); if ($0 == v) f = 1 } END { exit !f }' \
    || fail "$f: no \"$v\" in .rodata"
done

for f in $X86 version-aarch64.so; do
  objdump -d "$f" > "$f.objdump" || fail "objdump -d $f"
done
sha256sum -- *.so > SHA256SUMS

# Every check passed: replace the old outputs.
cd "$D"
rm -f ./*.so ./*.objdump SHA256SUMS COMPILERS
mv -- "$B"/* .
echo "build.sh: all shape checks passed"
