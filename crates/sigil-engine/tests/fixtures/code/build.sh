#!/bin/sh
# Builds the code fixtures of the engine tests (PR-5a), once, by hand. The tests never run this
# script or a compiler; they read the committed files. Needs gcc 15.3, clang 21.1.8, binutils 2.46.
#
# The toolchain must match COMPILERS (delete COMPILERS to adopt another one on purpose). Everything
# is built into a temporary directory and checked there (README.md lists the checked shapes). Only
# when every check passes are the old outputs replaced; a failed check stops the build (exit 1)
# and leaves the committed files as they were.
set -eu
cd "$(dirname "$0")"
export LC_ALL=C
D=$(pwd)
SRC=../src
T=$(mktemp -d)
B="$T/out"
mkdir "$B" "$T/lst"
trap 'rm -rf "$T"' EXIT
trap 'exit 1' HUP INT TERM

fail() { echo "build.sh: $*" >&2; exit 1; }

# The toolchain, compared with the committed COMPILERS before anything is built.
toolchain() {
  local tool v
  for tool in gcc clang as ld; do
    v=$($tool --version) || fail "$tool --version failed"
    printf '%s\n' "$v" | sed -n 1p
  done
}
tc=$(toolchain) || exit 1
printf '%s\n' "$tc" > "$B/COMPILERS"
if [ -e COMPILERS ] && ! diff COMPILERS "$B/COMPILERS" >&2; then
  fail "the toolchain differs from COMPILERS (delete COMPILERS to rebuild with this one)"
fi

# Every output goes to $B; the sources are read here, by the same paths as always.
# ET_REL kernels (v0.1's command, and gcc -O2).
clang -target x86_64-unknown-linux-gnu -O0 -c "$SRC/suspicious_kernel.c" -o "$B/suspicious_kernel-clang-O0.o"
clang -target x86_64-unknown-linux-gnu -O0 -c "$SRC/clean_kernel.c" -o "$B/clean_kernel-clang-O0.o"
gcc -O2 -c "$SRC/suspicious_kernel.c" -o "$B/suspicious_kernel-gcc-O2.o"
gcc -O2 -c "$SRC/clean_kernel.c" -o "$B/clean_kernel-gcc-O2.o"

# ET_REL with an unlinked GOT (review P1-1).
for cc in gcc clang; do for o in O0 O2; do
  $cc -fPIC -fno-plt -$o -c calls.c -o "$B/calls-noplt-$cc-$o.o"
done; done
as gotrel.S -o "$B/gotrel.o"

# Linked: PLT, .plt.sec, GOT (F-C2).
for cc in gcc clang; do
  $cc -O2 -fPIC -shared -o "$B/net-plt-$cc.so" net.c
  $cc -O2 -fPIC -shared -fno-plt -o "$B/net-noplt-$cc.so" net.c
done
gcc -O2 -fPIC -shared -fcf-protection=full -Wl,-z,ibtplt -o "$B/net-pltsec-gcc.so" net.c
gcc -O2 -fPIE -pie -o "$B/net-pie" netexe.c
gcc -O2 -fno-pie -no-pie -o "$B/net-nopie" netexe.c
gcc -O2 -fno-pie -no-pie -o "$B/net-nopie-addr" netnopieaddr.c
gcc -O2 -fPIC -shared -o "$B/net-addr.so" netaddr.c
gcc -O2 -fPIC -shared -o "$B/net-data.so" netdata.c
gcc -O2 -fPIC -shared -fno-asynchronous-unwind-tables -fno-unwind-tables -o "$B/net-noeh.so" net.c
gcc -O2 -fPIC -shared -o "$B/dl.so" dl.c
gcc -O2 -fPIC -shared -o "$B/ownplt.so" ownplt.c
gcc -O2 -fPIC -shared -fno-semantic-interposition -o "$B/ownplt-direct.so" ownplt.c
# The .S files are assembled by `as` into $T and then linked. `gcc x.S` would assemble a randomly
# named temporary object, and ld names it in an STT_FILE symbol when the file has local symbols
# (values.S, cfg.S), so the output would differ on every build.
as values.S -o "$T/values.o"
gcc -shared -nostartfiles -o "$B/values.so" "$T/values.o"
as cfg.S -o "$T/cfg.o"
gcc -shared -nostartfiles -o "$B/cfg.so" "$T/cfg.o"
as textrel.S -o "$T/textrel.o"
gcc -shared -nostartfiles -Wl,-z,notext -o "$B/textrel.so" "$T/textrel.o"

# Aggregate limits (review P1-2): 70,000 direct calls, with and without CFI. The generated
# sources live in $T only, and are deleted with it.
{ printf '\t.text\n\t.globl many\n\t.type many,@function\nmany:\n\t.cfi_startproc\n'
  i=0; while [ $i -lt 70000 ]; do printf '\tcall connect@PLT\n'; i=$((i+1)); done
  printf '\tret\n\t.cfi_endproc\n\t.section .note.GNU-stack,"",@progbits\n'; } > "$T/many.S"
sed '/cfi_/d' "$T/many.S" > "$T/many-noeh.S"
as "$T/many.S" -o "$T/many.o"
gcc -shared -nostartfiles -o "$B/many.so" "$T/many.o"
as "$T/many-noeh.S" -o "$T/many-noeh.o"
gcc -shared -nostartfiles -o "$B/many-noeh.so" "$T/many-noeh.o"

# ---------------------------------------------------------------------------------------------
# The shapes the tests rely on (README.md lists them). Each check stops the build when it fails.
# Helpers that read a tool's output assign it first, with `|| exit 1`, so a failed tool is never
# read as "no match": `set -e` does not apply inside a function called from a condition. Every
# helper keeps its variables local, so a caller's names survive the call.
cd "$B"

# The objdump -dr listing of $1, without raw bytes, in $T/lst/$1.lst.
listing() { objdump -dr --no-show-raw-insn "$1" > "$T/lst/$1.lst" || fail "objdump -dr $1"; }

# The address (hex, no 0x) of the symbol $2 defined in .symtab of $1.
addr() {
  local out
  out=$(nm --defined-only "$1") || fail "nm $1"
  printf '%s\n' "$out" | awk -v n="$2" '$NF == n { print $1; f = 1; exit } END { exit !f }' \
    || fail "$1: no symbol $2"
}

# "start end" (decimal) of the section $2 of $1.
section() {
  local out r
  out=$(objdump -h "$1") || fail "objdump -h $1"
  r=$(printf '%s\n' "$out" | awk -v s="$2" '$2 == s { print $4, $3; f = 1; exit } END { exit !f }') \
    || fail "$1: no section $2"
  set -- $r
  echo "$((0x$1)) $((0x$1 + 0x$2))"
}

# The names of the REL and RELA sections of $1, one per line, in section order.
relocs() {
  local out
  out=$(readelf -SW "$1") || fail "readelf -S $1"
  printf '%s\n' "$out" | awk '{ sub(/^ *\[ *[0-9]+\] /, "") } $2 == "RELA" || $2 == "REL" { print $1 }'
}

# The FDE ranges of $1, one "start end" (hex) per line, from readelf's frame dump.
fdes() {
  local out
  out=$(readelf --debug-dump=frames -wN "$1") || fail "readelf --debug-dump=frames $1"
  printf '%s\n' "$out" | sed -n 's/^.* FDE cie=[0-9a-f]* pc=\([0-9a-f]*\)\.\.\([0-9a-f]*\)$/\1 \2/p'
}

# The number of FDEs of $1.
nfdes() {
  local list
  list=$(fdes "$1") || exit 1
  printf '%s' "$list" | grep -c '^' || true
}

# Whether an FDE of $1 covers the address $2 (hex).
covered() {
  local list a s e
  list=$(fdes "$1") || exit 1
  a=$((0x$2))
  while read -r s e; do
    [ -n "$s" ] || continue
    [ $((0x$s)) -le $a ] && [ $a -lt $((0x$e)) ] && return 0
  done <<EOF
$list
EOF
  return 1
}

# The end (hex) of the FDE of $1 that starts at $2 (hex); fails if there is none.
fde_end() {
  local list s e
  list=$(fdes "$1") || exit 1
  while read -r s e; do
    [ -n "$s" ] || continue
    [ $((0x$s)) -eq $((0x$2)) ] && { echo "$e"; return 0; }
  done <<EOF
$list
EOF
  return 1
}

# The number of FDEs of $1 whose range lies inside the section $2.
fdes_in() {
  local list r n s e
  list=$(fdes "$1") || exit 1
  r=$(section "$1" "$2") || exit 1
  set -- $r
  n=0
  while read -r s e; do
    [ -n "$s" ] || continue
    [ $((0x$s)) -ge $1 ] && [ $((0x$e)) -le $2 ] && n=$((n+1))
  done <<EOF
$list
EOF
  echo $n
}

# The awk program that tracks the function label ("<f>:") of each line in fn, and sets seen
# when the label ENVIRON["F"] occurs.
LABEL='/^[0-9a-f]+ <[^>]*>:$/ { fn = $2; sub(/^</, "", fn); sub(/>:$/, "", fn); if (fn == ENVIRON["F"]) seen = 1 }'

# Whether, in the listing $1, inside the function labelled $2, a line matching the ERE $3 is
# directly followed by a line matching the ERE $4. objdump prints a relocation on the line after
# the instruction it applies to, and the label line "<f>:" is itself a line, so $3 can match it.
follows() {
  F="$2" A="$3" B="$4" awk "$LABEL"'
    fn == ENVIRON["F"] && prev ~ ENVIRON["A"] && $0 ~ ENVIRON["B"] { ok = 1 }
    { prev = $0 }
    END { exit !ok }' "$1"
}

# The number of lines of the function labelled $2 in the listing $1 that match the ERE $3.
# Fails when the listing has no such function.
count() {
  F="$2" A="$3" awk "$LABEL"' /^[0-9a-f]+ <[^>]*>:$/ { next }
    fn == ENVIRON["F"] && $0 ~ ENVIRON["A"] { n++ }
    END { if (!seen) exit 2; print n + 0 }' "$1" || fail "${1##*/}: no function $2"
}

# The lines of the function labelled $2 in the listing $1. Fails when there is no such function.
body() {
  F="$2" awk "$LABEL"' /^[0-9a-f]+ <[^>]*>:$/ { next }
    fn == ENVIRON["F"] { print }
    END { if (!seen) exit 2 }' "$1" || fail "${1##*/}: no function $2"
}

# Fails unless the function $2 of the listing of $1 has exactly $3 lines matching the ERE $4.
expect() {
  local n
  n=$(count "$T/lst/$1.lst" "$2" "$4") || exit 1
  [ "$n" -eq "$3" ] || fail "$1: $2: $n lines match '$4', expected $3"
}

# Fails unless, in the function $2 of $1, a line matching $3 is directly followed by one matching $4.
pair() { follows "$T/lst/$1.lst" "$2" "$3" "$4" || fail "$1: $2: no '$3' followed by '$4'"; }

# The ELF type of $1 (REL, DYN, EXEC).
etype() {
  local out
  out=$(readelf -hW "$1") || fail "readelf -h $1"
  printf '%s\n' "$out" | sed -n 's/^ *Type: *\([A-Z]*\) .*/\1/p'
}

for f in *.o *.so net-pie net-nopie net-nopie-addr; do listing "$f"; done
CALL_GOT='call +\*0x0\(%rip\)'
JMP_GOT='jmp +\*0x0\(%rip\)'
R_CONNECT_GOTX='R_X86_64_GOTPCRELX[[:space:]]+connect-0x4$'
CALL_CONNECT_PLT='call +[0-9a-f]+ <connect@plt>$'
JMP_CONNECT_PLT='jmp +[0-9a-f]+ <connect@plt>$'
STUB_JMP='jmp +\*0x[0-9a-f]+\(%rip\) +# [0-9a-f]+ <connect@'

# The v0.1 kernels: a PLT32 call to connect. The only relocation sections are .rela.text (the
# suspicious kernels) and .rela.eh_frame. clang types .eh_frame SHT_X86_64_UNWIND, gcc PROGBITS.
for f in suspicious_kernel-clang-O0.o suspicious_kernel-gcc-O2.o; do
  pair "$f" kernel 'call +[0-9a-f]+ <' 'R_X86_64_PLT32[[:space:]]+connect-0x4$'
  expect "$f" kernel 1 'R_X86_64_'
  r=$(relocs "$f") || exit 1
  [ "$r" = "$(printf '.rela.text\n.rela.eh_frame')" ] || fail "$f: relocation sections: $r"
done
for f in clean_kernel-clang-O0.o clean_kernel-gcc-O2.o; do
  expect "$f" kernel 0 'R_X86_64_'
  r=$(relocs "$f") || exit 1
  [ "$r" = .rela.eh_frame ] || fail "$f: relocation sections: $r (expected only .rela.eh_frame)"
done
for f in suspicious_kernel-clang-O0.o clean_kernel-clang-O0.o; do
  readelf -SW "$f" | grep -Eq '\] \.eh_frame +X86_64_UNWIND ' \
    || fail "$f: .eh_frame is not SHT_X86_64_UNWIND"
done
for f in suspicious_kernel-gcc-O2.o clean_kernel-gcc-O2.o; do
  readelf -SW "$f" | grep -Eq '\] \.eh_frame +PROGBITS ' || fail "$f: .eh_frame is not SHT_PROGBITS"
done

# calls-noplt-*.o: connect through its unlinked GOT entry (GOTPCRELX, exact).
f=calls-noplt-gcc-O0.o
pair "$f" kernel "$CALL_GOT" "$R_CONNECT_GOTX"
pair "$f" loop "$CALL_GOT" "$R_CONNECT_GOTX"
pair "$f" calls_helper "$CALL_GOT" 'R_X86_64_GOTPCRELX[[:space:]]+helper-0x4$'
pair "$f" calls_helper "$CALL_GOT" "$R_CONNECT_GOTX"
expect "$f" kernel 1 'mov +%edi,-0x4\(%rbp\)$'
pair "$f" kernel 'mov +-0x4\(%rbp\),%eax$' 'mov +\$0x0,%edx$'
expect "$f" kernel 1 'mov +\$0x0,%esi$'
pair "$f" kernel 'mov +%eax,%edi$' "$CALL_GOT"
f=calls-noplt-clang-O0.o
pair "$f" kernel "$CALL_GOT" "$R_CONNECT_GOTX"
pair "$f" loop "$CALL_GOT" "$R_CONNECT_GOTX"
pair "$f" calls_helper 'call +[0-9a-f]+ <' 'R_X86_64_PLT32[[:space:]]+helper-0x4$'
pair "$f" calls_helper "$CALL_GOT" "$R_CONNECT_GOTX"
pair "$f" kernel 'mov +%edi,-0x4\(%rbp\)$' 'mov +-0x4\(%rbp\),%edi$'
pair "$f" kernel 'xor +%eax,%eax$' 'mov +%eax,%esi$'
pair "$f" kernel 'xor +%edx,%edx$' "$CALL_GOT"
f=calls-noplt-gcc-O2.o
pair "$f" kernel "$JMP_GOT" "$R_CONNECT_GOTX"
pair "$f" loop "$CALL_GOT" "$R_CONNECT_GOTX"
pair "$f" calls_helper "$CALL_GOT" 'R_X86_64_GOTPCRELX[[:space:]]+helper-0x4$'
pair "$f" calls_helper "$JMP_GOT" "$R_CONNECT_GOTX"
pair "$f" calls_helper 'mov +%eax,%edi$' "$JMP_GOT"
f=calls-noplt-clang-O2.o
pair "$f" kernel "$JMP_GOT" "$R_CONNECT_GOTX"
pair "$f" loop 'mov +0x0\(%rip\),%r15' 'R_X86_64_REX_GOTPCRELX[[:space:]]+connect-0x4$'
expect "$f" loop 1 'call +\*%r15$'
expect "$f" loop 1 'R_X86_64_'
pair "$f" calls_helper 'call +[0-9a-f]+ <' 'R_X86_64_PLT32[[:space:]]+helper-0x4$'
pair "$f" calls_helper "$JMP_GOT" "$R_CONNECT_GOTX"
expect "$f" calls_helper 1 'mov +%eax,%edi$'

# gotrel.o: each relocation on the field its comment names; connect and extern_data are both
# NOTYPE UND, next to _GLOBAL_OFFSET_TABLE_.
f=gotrel.o
pair "$f" g "$CALL_GOT" 'R_X86_64_GOTPCRELX[[:space:]]+connect$'
pair "$f" g 'lea +0x0\(%rip\),%rax' 'R_X86_64_GOTPCREL[[:space:]]+connect-0x4$'
pair "$f" g 'cmp +%rax,0x0\(%rip\)' 'R_X86_64_GOTPCREL[[:space:]]+connect-0x4$'
pair "$f" g 'lea +0x0\(%rip\),%rcx' 'R_X86_64_PLT32[[:space:]]+connect-0x4$'
pair "$f" g 'mov +0x0\(%rip\),%rdx' 'R_X86_64_PC32[[:space:]]+extern_data-0x4$'
expect "$f" g 5 'R_X86_64_'
out=$(readelf -sW "$f") || fail "readelf -s $f"
u=$(printf '%s\n' "$out" | awk '$7 == "UND" && $8 != "" { print $4, $5, $8 }')
[ "$u" = "$(printf 'NOTYPE GLOBAL _GLOBAL_OFFSET_TABLE_\nNOTYPE GLOBAL connect\nNOTYPE GLOBAL extern_data')" ] \
  || fail "$f: undefined symbols: $u"

# net-plt-*.so: calls to the .plt stub, whose first instruction jumps through connect's slot.
for f in net-plt-gcc.so net-plt-clang.so; do
  objdump -d --no-show-raw-insn -j .plt "$f" > "$T/lst/$f.plt.lst" || fail "objdump $f"
  follows "$T/lst/$f.plt.lst" connect@plt '<connect@plt>:$' "$STUB_JMP" || fail "$f: .plt stub"
  expect "$f" kernel 1 "$CALL_CONNECT_PLT"
  expect "$f" looped 1 "$CALL_CONNECT_PLT"
done
# net-noplt-*.so: calls through the GLOB_DAT slot; clang hoists the slot into r15 in looped.
for f in net-noplt-gcc.so net-noplt-clang.so; do
  grep -q '<connect@plt>' "$T/lst/$f.lst" && fail "$f: has a connect PLT stub"
  readelf -rW "$f" | grep -Eq ' R_X86_64_GLOB_DAT +0+ connect@' || fail "$f: no GLOB_DAT connect"
  expect "$f" kernel 1 'call +\*0x[0-9a-f]+\(%rip\) +# [0-9a-f]+ <connect@'
done
expect net-noplt-gcc.so looped 1 'call +\*0x[0-9a-f]+\(%rip\) +# [0-9a-f]+ <connect@'
expect net-noplt-clang.so looped 1 'mov +0x[0-9a-f]+\(%rip\),%r15 +# [0-9a-f]+ <connect@'
expect net-noplt-clang.so looped 1 'call +\*%r15$'
# net-pltsec-gcc.so: the stub is in .plt.sec and starts with endbr64, then jmp *slot.
f=net-pltsec-gcc.so
objdump -d --no-show-raw-insn -j .plt.sec "$f" > "$T/lst/$f.pltsec.lst" || fail "objdump $f"
follows "$T/lst/$f.pltsec.lst" connect@plt '<connect@plt>:$' 'endbr64$' || fail "$f: .plt.sec stub"
follows "$T/lst/$f.pltsec.lst" connect@plt 'endbr64$' "$STUB_JMP" || fail "$f: .plt.sec stub jmp"
for s in kernel looped; do
  pair "$f" $s "<$s>:\$" 'endbr64$'
  expect "$f" $s 1 "$CALL_CONNECT_PLT"
done

# Executables: main tail-jumps to connect's PLT stub.
[ "$(etype net-pie)" = DYN ] || fail "net-pie: not ET_DYN"
readelf -lW net-pie | grep -q ' INTERP ' || fail "net-pie: no PT_INTERP"
[ "$(etype net-nopie)" = EXEC ] || fail "net-nopie: not ET_EXEC"
expect net-pie main 1 "$JMP_CONNECT_PLT"
expect net-nopie main 1 "$JMP_CONNECT_PLT"
# net-nopie-addr: connect's canonical address (its PLT stub, also its UND st_value) is an
# immediate argument of keep.
f=net-nopie-addr
[ "$(etype $f)" = EXEC ] || fail "$f: not ET_EXEC"
p=$(sed -n 's/^0*\([0-9a-f]*\) <connect@plt>:$/\1/p' "$T/lst/$f.lst")
[ -n "$p" ] || fail "$f: no connect PLT stub"
expect "$f" main 1 "mov +\\\$0x$p,%edi\$"
expect "$f" main 1 'call +[0-9a-f]+ <keep>$'
v=$(readelf --dyn-syms -W "$f" | awk '$7 == "UND" && $8 ~ /^connect@/ { print $2 }')
[ -n "$v" ] && [ $((0x$v)) -eq $((0x$p)) ] || fail "$f: connect's st_value is not its stub"
# net-addr.so: take loads connect's GLOB_DAT slot into rdi and tail-jumps to keep; no PLT stub
# and no call of connect.
f=net-addr.so
expect "$f" take 1 'mov +0x[0-9a-f]+\(%rip\),%rdi +# [0-9a-f]+ <connect@'
expect "$f" take 1 'jmp +[0-9a-f]+ <keep@plt>$'
readelf -rW "$f" | grep -Eq ' R_X86_64_GLOB_DAT +0+ connect@' || fail "$f: no GLOB_DAT connect"
grep -q '<connect@plt>' "$T/lst/$f.lst" && fail "$f: has a connect PLT stub"
# net-data.so: connect only in data (an R_X86_64_64 in .data.rel.ro), never in code.
f=net-data.so
grep -q connect "$T/lst/$f.lst" && fail "$f: code names connect"
o=$(readelf -rW "$f" | awk '$3 == "R_X86_64_64" && $5 ~ /^connect@/ { print $1 }')
r=$(section "$f" .data.rel.ro) || exit 1
[ -n "$o" ] && [ $((0x$o)) -ge ${r% *} ] && [ $((0x$o)) -lt ${r#* } ] \
  || fail "$f: no R_X86_64_64 connect in .data.rel.ro"

# net-noeh.so: kernel and looped call connect, and the file has no FDE. The FDE reader is
# checked first on a file that has the FDE, so an empty parse cannot pass.
a=$(addr net-plt-gcc.so kernel) || exit 1
covered net-plt-gcc.so "$a" || fail "FDE check: net-plt-gcc.so's kernel not covered"
f=net-noeh.so
expect "$f" kernel 1 "$CALL_CONNECT_PLT"
expect "$f" looped 1 "$CALL_CONNECT_PLT"
n=$(nfdes $f) || exit 1
[ "$n" -eq 0 ] || fail "$f: $n FDEs, expected none"

# dl.so: score tail-jumps with rsi = the string's address; byname calls with rsi = rsp (via r10).
f=dl.so
pair "$f" score 'lea +0x[0-9a-f]+\(%rip\),%rsi' 'jmp +[0-9a-f]+ <dlsym@plt>$'
b=$(body "$T/lst/$f.lst" score) || exit 1
t=$(printf '%s\n' "$b" | sed -n 's/^ *[0-9a-f]*:[[:space:]]*lea  *0x[0-9a-f]*(%rip),%rsi  *# \([0-9a-f]*\) .*/\1/p')
o=$(readelf -p .rodata "$f" | sed -n 's/^ *\[ *\([0-9a-f]*\)\]  ggml_backend_score$/\1/p')
r=$(section "$f" .rodata) || exit 1
[ -n "$t" ] && [ -n "$o" ] && [ $((0x$t)) -eq $(( ${r% *} + 0x$o )) ] \
  || fail "$f: score's lea is not \"ggml_backend_score\""
expect "$f" byname 1 'call +[0-9a-f]+ <dlsym@plt>$'
expect "$f" byname 1 'mov +%rsp,%r10$'
expect "$f" byname 1 'mov +%r10,%rsi$'
# ownplt*.so: connect(helper(a)) with helper exported, through its PLT stub or called directly.
f=ownplt.so
expect "$f" kernel 1 'call +[0-9a-f]+ <helper@plt>$'
expect "$f" kernel 1 'mov +%eax,%edi$'
expect "$f" kernel 1 "$JMP_CONNECT_PLT"
readelf --dyn-syms -W "$f" | awk '$4 == "FUNC" && $5 == "GLOBAL" && $7 != "UND" && $8 == "helper" { f = 1 } END { exit !f }' \
  || fail "$f: helper not exported"
readelf -rW "$f" | grep -Eq ' R_X86_64_JUMP_SLOT +[0-9a-f]+ helper \+ 0$' || fail "$f: no helper slot"
f=ownplt-direct.so
expect "$f" kernel 1 'call +[0-9a-f]+ <helper>$'
expect "$f" kernel 1 'mov +%eax,%edi$'
expect "$f" kernel 1 "$JMP_CONNECT_PLT"
grep -q '<helper@plt>' "$T/lst/$f.lst" && fail "$f: has a helper PLT stub"

# values.so: one FDE per CFI function, all in .text, and one more (ld's, for .plt): -nostartfiles
# adds none. Each function calls connect once.
f=values.so
n=$(fdes_in $f .text) || exit 1
[ "$n" -eq 8 ] || fail "$f: $n FDEs in .text, expected 8"
n=$(nfdes $f) || exit 1
[ "$n" -eq 9 ] || fail "$f: $n FDEs, expected 9"
for s in getenv_shape merge_shape local_helper saved_rbx saved_rsi loads partial strs; do
  a=$(addr $f $s) || exit 1
  fde_end $f "$a" > /dev/null || fail "$f: no FDE starts at $s"
done
for s in getenv_shape merge_shape saved_rbx saved_rsi loads partial strs; do
  expect "$f" $s 1 "$CALL_CONNECT_PLT"
done
expect "$f" getenv_shape 1 'call +[0-9a-f]+ <getenv@plt>$'
expect "$f" merge_shape 1 'call +[0-9a-f]+ <getenv@plt>$'
# cfg.so: 5 FDEs in .text and ld's .plt FDE; noeh_code outside every FDE; cold_part its own
# FDE, which hot's FDE ends at and hot branches to; into_insn branches one byte into its mov.
f=cfg.so
n=$(fdes_in $f .text) || exit 1
[ "$n" -eq 5 ] || fail "$f: $n FDEs in .text, expected 5"
n=$(nfdes $f) || exit 1
[ "$n" -eq 6 ] || fail "$f: $n FDEs, expected 6"
a=$(addr $f noeh_code) || exit 1
covered $f "$a" && fail "$f: an FDE covers noeh_code"
c=$(addr $f cold_part) || exit 1
fde_end $f "$c" > /dev/null || fail "$f: no FDE starts at cold_part"
h=$(addr $f hot) || exit 1
e=$(fde_end $f "$h") || fail "$f: no FDE starts at hot"
[ $((0x$e)) -eq $((0x$c)) ] || fail "$f: hot's FDE does not end at cold_part"
expect "$f" hot 1 'jne +[0-9a-f]+ <cold_part>$'
expect "$f" cold_part 1 "$CALL_CONNECT_PLT"
expect "$f" noeh_code 1 "$CALL_CONNECT_PLT"
expect "$f" after_noreturn 1 'call +[0-9a-f]+ <abort@plt>$'
b=$(body "$T/lst/$f.lst" into_insn) || exit 1
t=$(printf '%s\n' "$b" | sed -n 's/^ *[0-9a-f]*:[[:space:]]*jne  *\([0-9a-f]*\) <into_insn+0x[0-9a-f]*>$/\1/p')
[ -n "$t" ] || fail "$f: into_insn has no jne"
m=$(printf '%x' $((0x$t - 1)))
expect "$f" into_insn 1 "^ *$m:[[:space:]]+mov +\\\$0x90909090,%eax\$"
# textrel.so: DT_TEXTREL and DF_TEXTREL, and an R_X86_64_64 against connect on tr's movabs
# immediate.
f=textrel.so
readelf -dW $f | grep -q '(TEXTREL)' || fail "$f: no DT_TEXTREL"
readelf -dW $f | grep -Eq '\(FLAGS\) +TEXTREL' || fail "$f: no DF_TEXTREL"
a=$(addr $f tr) || exit 1
o=$(readelf -rW $f | awk '$3 == "R_X86_64_64" && $5 ~ /^connect@/ { print $1 }')
[ -n "$o" ] && [ $((0x$o)) -eq $((0x$a + 2)) ] || fail "$f: no R_X86_64_64 connect at tr+2"
pair "$f" tr 'movabs +\$0x0,%rax$' 'call +\*%rax$'
# many*.so: 70,000 calls of connect's stub, filling .text; many.so has an FDE at many and ld's
# .plt FDE, many-noeh.so has no FDE.
for f in many.so many-noeh.so; do
  expect "$f" many 70000 "$CALL_CONNECT_PLT"
  r=$(section "$f" .text) || exit 1
  [ $(( ${r#* } - ${r% *} )) -eq 350001 ] || fail "$f: .text is not 350,001 bytes"
done
a=$(addr many.so many) || exit 1
fde_end many.so "$a" > /dev/null || fail "many.so: no FDE starts at many"
n=$(nfdes many.so) || exit 1
[ "$n" -eq 2 ] || fail "many.so: $n FDEs, expected 2"
n=$(nfdes many-noeh.so) || exit 1
[ "$n" -eq 0 ] || fail "many-noeh.so: $n FDEs, expected none"

# values.so, cfg.so, many.so: the one FDE outside .text is ld's, covering exactly .plt.
for f in values.so cfg.so many.so; do
  r=$(section "$f" .plt) || exit 1
  e=$(fde_end "$f" "$(printf '%x' ${r% *})") || fail "$f: no FDE starts at .plt"
  [ $((0x$e)) -eq ${r#* } ] || fail "$f: the .plt FDE does not end at the end of .plt"
done

for f in *.o *.so net-pie net-nopie net-nopie-addr; do
  case "$f" in
    many*) objdump -dr "$f" > "$T/$f.full" || fail "objdump -dr $f"
           head -60 "$T/$f.full" > "$f.objdump" ;;
    *) objdump -dr "$f" > "$f.objdump" || fail "objdump -dr $f" ;;
  esac
done
sha256sum -- *.o *.so net-pie net-nopie net-nopie-addr > SHA256SUMS

# Every check passed: replace the old outputs.
cd "$D"
rm -f ./*.o ./*.so ./*.objdump net-pie net-nopie net-nopie-addr SHA256SUMS COMPILERS
mv -- "$B"/* .
echo "build.sh: all shape checks passed"
