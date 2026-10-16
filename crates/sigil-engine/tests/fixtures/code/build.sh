#!/bin/sh
# Builds the code fixtures of the engine tests (PR-5a), once, by hand. The tests never run this
# script or a compiler; they read the committed files. Needs gcc 15.3, clang 21.1.8, binutils 2.46.
# Every shape the tests rely on is checked after the build; a failed check stops it (exit 1).
set -eu
cd "$(dirname "$0")"
export LC_ALL=C
SRC=../src
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
rm -f ./*.o ./*.so ./*.objdump net-pie net-nopie net-nopie-addr SHA256SUMS COMPILERS

gcc --version | head -1 > COMPILERS
clang --version | head -1 >> COMPILERS
as --version | head -1 >> COMPILERS
ld --version | head -1 >> COMPILERS

# ET_REL kernels (v0.1's command, and gcc -O2).
clang -target x86_64-unknown-linux-gnu -O0 -c "$SRC/suspicious_kernel.c" -o suspicious_kernel-clang-O0.o
clang -target x86_64-unknown-linux-gnu -O0 -c "$SRC/clean_kernel.c" -o clean_kernel-clang-O0.o
gcc -O2 -c "$SRC/suspicious_kernel.c" -o suspicious_kernel-gcc-O2.o
gcc -O2 -c "$SRC/clean_kernel.c" -o clean_kernel-gcc-O2.o

# ET_REL with an unlinked GOT (review P1-1).
for cc in gcc clang; do for o in O0 O2; do
  $cc -fPIC -fno-plt -$o -c calls.c -o calls-noplt-$cc-$o.o
done; done
as gotrel.S -o gotrel.o

# Linked: PLT, .plt.sec, GOT (F-C2).
for cc in gcc clang; do
  $cc -O2 -fPIC -shared -o net-plt-$cc.so net.c
  $cc -O2 -fPIC -shared -fno-plt -o net-noplt-$cc.so net.c
done
gcc -O2 -fPIC -shared -fcf-protection=full -Wl,-z,ibtplt -o net-pltsec-gcc.so net.c
gcc -O2 -fPIE -pie -o net-pie netexe.c
gcc -O2 -fno-pie -no-pie -o net-nopie netexe.c
gcc -O2 -fno-pie -no-pie -o net-nopie-addr netnopieaddr.c
gcc -O2 -fPIC -shared -o net-addr.so netaddr.c
gcc -O2 -fPIC -shared -o net-data.so netdata.c
gcc -O2 -fPIC -shared -fno-asynchronous-unwind-tables -fno-unwind-tables -o net-noeh.so net.c
gcc -O2 -fPIC -shared -o dl.so dl.c
gcc -O2 -fPIC -shared -o ownplt.so ownplt.c
gcc -O2 -fPIC -shared -fno-semantic-interposition -o ownplt-direct.so ownplt.c
# The .S files are assembled by `as` into $T and then linked. `gcc x.S` would assemble a randomly
# named temporary object, and ld names it in an STT_FILE symbol when the file has local symbols
# (values.S, cfg.S), so the output would differ on every build.
as values.S -o "$T/values.o"
gcc -shared -nostartfiles -o values.so "$T/values.o"
as cfg.S -o "$T/cfg.o"
gcc -shared -nostartfiles -o cfg.so "$T/cfg.o"
as textrel.S -o "$T/textrel.o"
gcc -shared -nostartfiles -Wl,-z,notext -o textrel.so "$T/textrel.o"

# Aggregate limits (review P1-2): 70,000 direct calls, with and without CFI. The generated
# sources live in $T only, and are deleted with it.
{ printf '\t.text\n\t.globl many\n\t.type many,@function\nmany:\n\t.cfi_startproc\n'
  i=0; while [ $i -lt 70000 ]; do printf '\tcall connect@PLT\n'; i=$((i+1)); done
  printf '\tret\n\t.cfi_endproc\n\t.section .note.GNU-stack,"",@progbits\n'; } > "$T/many.S"
sed '/cfi_/d' "$T/many.S" > "$T/many-noeh.S"
as "$T/many.S" -o "$T/many.o"
gcc -shared -nostartfiles -o many.so "$T/many.o"
as "$T/many-noeh.S" -o "$T/many-noeh.o"
gcc -shared -nostartfiles -o many-noeh.so "$T/many-noeh.o"

# ---------------------------------------------------------------------------------------------
# The shapes the tests rely on (README.md lists them). Each check stops the build when it fails.
# Helpers that read a tool's output assign it first, with `|| exit 1`, so a failed tool is never
# read as "no match": `set -e` does not apply inside a function called from a condition.

fail() { echo "build.sh: $*" >&2; exit 1; }

# The objdump -dr listing of $1, without raw bytes, in $T/$1.lst.
listing() { objdump -dr --no-show-raw-insn "$1" > "$T/$1.lst" || fail "objdump -dr $1"; }

# The address (hex, no 0x) of the symbol $2 defined in .symtab of $1.
addr() {
  out=$(nm --defined-only "$1") || exit 1
  printf '%s\n' "$out" | awk -v n="$2" '$NF == n { print $1; f = 1; exit } END { exit !f }'
}

# "start end" (decimal) of the section $2 of $1.
section() {
  out=$(objdump -h "$1") || exit 1
  r=$(printf '%s\n' "$out" | awk -v s="$2" '$2 == s { print $4, $3; f = 1; exit } END { exit !f }') \
    || fail "$1: no section $2"
  set -- $r
  echo "$((0x$1)) $((0x$1 + 0x$2))"
}

# The FDE ranges of $1, one "start end" (hex) per line, from readelf's frame dump.
fdes() {
  out=$(readelf --debug-dump=frames -wN "$1") || exit 1
  printf '%s\n' "$out" | sed -n 's/^.* FDE cie=[0-9a-f]* pc=\([0-9a-f]*\)\.\.\([0-9a-f]*\)$/\1 \2/p'
}

# Whether an FDE of $1 covers the address $2 (hex).
covered() {
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

# Whether, in the listing $1, inside the function labelled $2, a line matching the ERE $3 is
# directly followed by a line matching the ERE $4. objdump prints a relocation on the line after
# the instruction it applies to, and the label line "<f>:" is itself a line, so $3 can match it.
follows() {
  F="$2" A="$3" B="$4" awk '
    /^[0-9a-f]+ <[^>]*>:$/ { fn = $2; sub(/^</, "", fn); sub(/>:$/, "", fn) }
    fn == ENVIRON["F"] && prev ~ ENVIRON["A"] && $0 ~ ENVIRON["B"] { ok = 1 }
    { prev = $0 }
    END { exit !ok }' "$1"
}

# The number of lines of the function labelled $2 in the listing $1 that match the ERE $3.
count() {
  F="$2" A="$3" awk '
    /^[0-9a-f]+ <[^>]*>:$/ { fn = $2; sub(/^</, "", fn); sub(/>:$/, "", fn); next }
    fn == ENVIRON["F"] && $0 ~ ENVIRON["A"] { n++ }
    END { print n + 0 }' "$1"
}

# The lines of the function labelled $2 in the listing $1.
body() {
  F="$2" awk '
    /^[0-9a-f]+ <[^>]*>:$/ { fn = $2; sub(/^</, "", fn); sub(/>:$/, "", fn); next }
    fn == ENVIRON["F"] { print }' "$1"
}

# Fails unless the function $2 of the listing $1 has exactly $3 lines matching the ERE $4.
expect() {
  n=$(count "$T/$1.lst" "$2" "$4") || exit 1
  [ "$n" -eq "$3" ] || fail "$1: $2: $n lines match '$4', expected $3"
}

# Fails unless, in the function $2 of $1, a line matching $3 is directly followed by one matching $4.
pair() { follows "$T/$1.lst" "$2" "$3" "$4" || fail "$1: $2: no '$3' followed by '$4'"; }

# The ELF type of $1 (REL, DYN, EXEC).
etype() {
  out=$(readelf -hW "$1") || exit 1
  printf '%s\n' "$out" | sed -n 's/^ *Type: *\([A-Z]*\) .*/\1/p'
}

for f in ./*.o ./*.so net-pie net-nopie net-nopie-addr; do listing "${f#./}"; done
CALL_GOT='call +\*0x0\(%rip\)'
JMP_GOT='jmp +\*0x0\(%rip\)'
R_CONNECT_GOTX='R_X86_64_GOTPCRELX[[:space:]]+connect-0x4$'
CALL_CONNECT_PLT='call +[0-9a-f]+ <connect@plt>$'
JMP_CONNECT_PLT='jmp +[0-9a-f]+ <connect@plt>$'
STUB_JMP='jmp +\*0x[0-9a-f]+\(%rip\) +# [0-9a-f]+ <connect@'

# The v0.1 kernels: a PLT32 call to connect; .eh_frame relocated through .rela.eh_frame; clang
# types .eh_frame SHT_X86_64_UNWIND, gcc SHT_PROGBITS.
for f in suspicious_kernel-clang-O0.o suspicious_kernel-gcc-O2.o; do
  pair "$f" kernel 'call +[0-9a-f]+ <' 'R_X86_64_PLT32[[:space:]]+connect-0x4$'
  expect "$f" kernel 1 'R_X86_64_'
done
for f in clean_kernel-clang-O0.o clean_kernel-gcc-O2.o; do expect "$f" kernel 0 'R_X86_64_'; done
for f in suspicious_kernel-clang-O0.o suspicious_kernel-gcc-O2.o clean_kernel-clang-O0.o \
         clean_kernel-gcc-O2.o; do
  readelf -SW "$f" | grep -Eq '\] \.rela\.eh_frame +RELA ' || fail "$f: no .rela.eh_frame"
done
readelf -SW suspicious_kernel-clang-O0.o | grep -Eq '\] \.eh_frame +X86_64_UNWIND ' \
  || fail "suspicious_kernel-clang-O0.o: .eh_frame is not SHT_X86_64_UNWIND"
readelf -SW suspicious_kernel-gcc-O2.o | grep -Eq '\] \.eh_frame +PROGBITS ' \
  || fail "suspicious_kernel-gcc-O2.o: .eh_frame is not SHT_PROGBITS"

# calls-noplt-*.o: connect through its unlinked GOT entry (GOTPCRELX, exact).
f=calls-noplt-gcc-O0.o
pair "$f" kernel "$CALL_GOT" "$R_CONNECT_GOTX"
pair "$f" loop "$CALL_GOT" "$R_CONNECT_GOTX"
pair "$f" calls_helper "$CALL_GOT" 'R_X86_64_GOTPCRELX[[:space:]]+helper-0x4$'
pair "$f" calls_helper "$CALL_GOT" "$R_CONNECT_GOTX"
f=calls-noplt-clang-O0.o
pair "$f" kernel "$CALL_GOT" "$R_CONNECT_GOTX"
pair "$f" loop "$CALL_GOT" "$R_CONNECT_GOTX"
pair "$f" calls_helper 'call +[0-9a-f]+ <' 'R_X86_64_PLT32[[:space:]]+helper-0x4$'
pair "$f" calls_helper "$CALL_GOT" "$R_CONNECT_GOTX"
f=calls-noplt-gcc-O2.o
pair "$f" kernel "$JMP_GOT" "$R_CONNECT_GOTX"
pair "$f" loop "$CALL_GOT" "$R_CONNECT_GOTX"
pair "$f" calls_helper "$CALL_GOT" 'R_X86_64_GOTPCRELX[[:space:]]+helper-0x4$'
pair "$f" calls_helper "$JMP_GOT" "$R_CONNECT_GOTX"
f=calls-noplt-clang-O2.o
pair "$f" kernel "$JMP_GOT" "$R_CONNECT_GOTX"
pair "$f" loop 'mov +0x0\(%rip\),%r15' 'R_X86_64_REX_GOTPCRELX[[:space:]]+connect-0x4$'
expect "$f" loop 1 'call +\*%r15$'
expect "$f" loop 1 'R_X86_64_'
pair "$f" calls_helper 'call +[0-9a-f]+ <' 'R_X86_64_PLT32[[:space:]]+helper-0x4$'
pair "$f" calls_helper "$JMP_GOT" "$R_CONNECT_GOTX"

# gotrel.o: each relocation on the field its comment names.
f=gotrel.o
pair "$f" g "$CALL_GOT" 'R_X86_64_GOTPCRELX[[:space:]]+connect$'
pair "$f" g 'lea +0x0\(%rip\),%rax' 'R_X86_64_GOTPCREL[[:space:]]+connect-0x4$'
pair "$f" g 'cmp +%rax,0x0\(%rip\)' 'R_X86_64_GOTPCREL[[:space:]]+connect-0x4$'
pair "$f" g 'lea +0x0\(%rip\),%rcx' 'R_X86_64_PLT32[[:space:]]+connect-0x4$'
pair "$f" g 'mov +0x0\(%rip\),%rdx' 'R_X86_64_PC32[[:space:]]+extern_data-0x4$'
expect "$f" g 5 'R_X86_64_'

# net-plt-*.so: calls to the .plt stub, whose first instruction jumps through connect's slot.
for f in net-plt-gcc.so net-plt-clang.so; do
  objdump -d --no-show-raw-insn -j .plt "$f" > "$T/$f.plt.lst" || fail "objdump $f"
  follows "$T/$f.plt.lst" connect@plt '<connect@plt>:$' "$STUB_JMP" || fail "$f: .plt stub"
  expect "$f" kernel 1 "$CALL_CONNECT_PLT"
  expect "$f" looped 1 "$CALL_CONNECT_PLT"
done
# net-noplt-*.so: calls through the GOT slot; clang hoists the slot into r15 in looped.
for f in net-noplt-gcc.so net-noplt-clang.so; do
  grep -q '<connect@plt>' "$T/$f.lst" && fail "$f: has a connect PLT stub"
  expect "$f" kernel 1 'call +\*0x[0-9a-f]+\(%rip\) +# [0-9a-f]+ <connect@'
done
expect net-noplt-gcc.so looped 1 'call +\*0x[0-9a-f]+\(%rip\) +# [0-9a-f]+ <connect@'
expect net-noplt-clang.so looped 1 'mov +0x[0-9a-f]+\(%rip\),%r15 +# [0-9a-f]+ <connect@'
expect net-noplt-clang.so looped 1 'call +\*%r15$'
# net-pltsec-gcc.so: the stub is in .plt.sec and starts with endbr64, then jmp *slot.
f=net-pltsec-gcc.so
objdump -d --no-show-raw-insn -j .plt.sec "$f" > "$T/$f.pltsec.lst" || fail "objdump $f"
follows "$T/$f.pltsec.lst" connect@plt '<connect@plt>:$' 'endbr64$' || fail "$f: .plt.sec stub"
follows "$T/$f.pltsec.lst" connect@plt 'endbr64$' "$STUB_JMP" || fail "$f: .plt.sec stub jmp"
expect "$f" kernel 1 "$CALL_CONNECT_PLT"
expect "$f" looped 1 "$CALL_CONNECT_PLT"

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
p=$(sed -n 's/^0*\([0-9a-f]*\) <connect@plt>:$/\1/p' "$T/$f.lst")
[ -n "$p" ] || fail "$f: no connect PLT stub"
expect "$f" main 1 "mov +\\\$0x$p,%edi\$"
expect "$f" main 1 'call +[0-9a-f]+ <keep>$'
v=$(readelf --dyn-syms -W "$f" | awk '$7 == "UND" && $8 ~ /^connect@/ { print $2 }')
[ -n "$v" ] && [ $((0x$v)) -eq $((0x$p)) ] || fail "$f: connect's st_value is not its stub"
# net-addr.so: take loads connect's GOT slot into rdi; no PLT stub, no call of connect.
f=net-addr.so
expect "$f" take 1 'mov +0x[0-9a-f]+\(%rip\),%rdi +# [0-9a-f]+ <connect@'
grep -q '<connect@plt>' "$T/$f.lst" && fail "$f: has a connect PLT stub"
# net-data.so: connect only in data (an R_X86_64_64), never in code.
f=net-data.so
grep -q connect "$T/$f.lst" && fail "$f: code names connect"
readelf -rW "$f" | grep -Eq ' R_X86_64_64 +0+ connect@' || fail "$f: no R_X86_64_64 connect"

# net-noeh.so: kernel calls connect, and no FDE covers kernel or looped. The FDE reader is
# checked first on a file that has the FDE, so an empty parse cannot pass.
a=$(addr net-plt-gcc.so kernel) || fail "net-plt-gcc.so: no kernel"
covered net-plt-gcc.so "$a" || fail "FDE check: net-plt-gcc.so's kernel not covered"
f=net-noeh.so
expect "$f" kernel 1 "$CALL_CONNECT_PLT"
a=$(addr $f kernel) || fail "$f: no kernel"
covered $f "$a" && fail "$f: an FDE covers kernel"
a=$(addr $f looped) || fail "$f: no looped"
covered $f "$a" && fail "$f: an FDE covers looped"

# dl.so: score tail-jumps with rsi = the string's address; byname calls with rsi = rsp (via r10).
f=dl.so
pair "$f" score 'lea +0x[0-9a-f]+\(%rip\),%rsi' 'jmp +[0-9a-f]+ <dlsym@plt>$'
b=$(body "$T/$f.lst" score) || exit 1
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
grep -q '<helper@plt>' "$T/$f.lst" && fail "$f: has a helper PLT stub"

# values.so: one FDE per CFI function, all in .text (-nostartfiles adds none; ld's .plt FDE is
# outside .text), and each function calls connect once.
f=values.so
n=$(fdes_in $f .text) || exit 1
[ "$n" -eq 8 ] || fail "$f: $n FDEs in .text, expected 8"
for s in getenv_shape merge_shape local_helper saved_rbx saved_rsi loads partial strs; do
  a=$(addr $f $s) || fail "$f: no $s"
  fde_end $f "$a" > /dev/null || fail "$f: no FDE starts at $s"
done
for s in getenv_shape merge_shape saved_rbx saved_rsi loads partial strs; do
  expect "$f" $s 1 "$CALL_CONNECT_PLT"
done
expect "$f" getenv_shape 1 'call +[0-9a-f]+ <getenv@plt>$'
expect "$f" merge_shape 1 'call +[0-9a-f]+ <getenv@plt>$'
# cfg.so: noeh_code outside every FDE; cold_part its own FDE, which hot's FDE ends at and hot
# branches to; into_insn branches one byte into its mov.
f=cfg.so
n=$(fdes_in $f .text) || exit 1
[ "$n" -eq 5 ] || fail "$f: $n FDEs in .text, expected 5"
a=$(addr $f noeh_code) || fail "$f: no noeh_code"
covered $f "$a" && fail "$f: an FDE covers noeh_code"
c=$(addr $f cold_part) || fail "$f: no cold_part"
fde_end $f "$c" > /dev/null || fail "$f: no FDE starts at cold_part"
h=$(addr $f hot) || fail "$f: no hot"
e=$(fde_end $f "$h") || fail "$f: no FDE starts at hot"
[ $((0x$e)) -eq $((0x$c)) ] || fail "$f: hot's FDE does not end at cold_part"
expect "$f" hot 1 'jne +[0-9a-f]+ <cold_part>$'
expect "$f" cold_part 1 "$CALL_CONNECT_PLT"
expect "$f" noeh_code 1 "$CALL_CONNECT_PLT"
expect "$f" after_noreturn 1 'call +[0-9a-f]+ <abort@plt>$'
b=$(body "$T/$f.lst" into_insn) || exit 1
t=$(printf '%s\n' "$b" | sed -n 's/^ *[0-9a-f]*:[[:space:]]*jne  *\([0-9a-f]*\) <into_insn+0x[0-9a-f]*>$/\1/p')
[ -n "$t" ] || fail "$f: into_insn has no jne"
m=$(printf '%x' $((0x$t - 1)))
expect "$f" into_insn 1 "^ *$m:[[:space:]]+mov +\\\$0x90909090,%eax\$"
# textrel.so: DT_TEXTREL, and an R_X86_64_64 against connect on tr's movabs immediate.
f=textrel.so
readelf -dW $f | grep -q '(TEXTREL)' || fail "$f: no DT_TEXTREL"
a=$(addr $f tr) || fail "$f: no tr"
o=$(readelf -rW $f | awk '$3 == "R_X86_64_64" && $5 ~ /^connect@/ { print $1 }')
[ -n "$o" ] && [ $((0x$o)) -eq $((0x$a + 2)) ] || fail "$f: no R_X86_64_64 connect at tr+2"
expect "$f" tr 1 'movabs +\$0x0,%rax$'
# many*.so: 70,000 calls of connect's stub; many.so's FDE covers many, many-noeh.so has none.
for f in many.so many-noeh.so; do expect "$f" many 70000 "$CALL_CONNECT_PLT"; done
a=$(addr many.so many) || fail "many.so: no many"
fde_end many.so "$a" > /dev/null || fail "many.so: no FDE starts at many"
a=$(addr many-noeh.so many) || fail "many-noeh.so: no many"
covered many-noeh.so "$a" && fail "many-noeh.so: an FDE covers many"

for f in ./*.o ./*.so net-pie net-nopie net-nopie-addr; do
  f=${f#./}
  case "$f" in many*) objdump -dr "$f" | head -60 > "$f.objdump" ;; *) objdump -dr "$f" > "$f.objdump" ;; esac
done
sha256sum ./*.o ./*.so net-pie net-nopie net-nopie-addr | sed 's| \./| |' > SHA256SUMS
echo "build.sh: all shape checks passed"
