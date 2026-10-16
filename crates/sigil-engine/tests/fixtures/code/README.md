# Code fixtures (PR-5a)

Inputs of the code analyzer's tests (`sigil-engine::code`, `binary inspect --code`): direct calls
of capability imports in x86-64 ELF.

`build.sh` is run once, by hand. The tests never run it or a compiler; they read only the
committed files. The script also checks every shape listed below and stops (exit 1) when one is
missing, so a rebuild with another toolchain fails loudly instead of changing the fixtures.

Next to the sources and `build.sh`:
- the built files, and an `objdump -dr` dump of each (`<file>.objdump`; the `many*` dumps are cut
  to their first 60 lines);
- `SHA256SUMS` of the built files;
- `COMPILERS`: gcc 15.3.0, clang 21.1.8, GNU as and ld 2.46.50.

The build is reproducible: two runs give the same `SHA256SUMS`.

## Built files

The **Shape** column is what the compilers gave, read from the dumps and checked by `build.sh`.
Where it differs from the PR-5a spec (§8.1) or the plan's source comments, it says so
(**differs:**). The tests' expectations follow this column.

Value notes used below:
- A 32-bit register copy (`mov %eax,%edi`) gives `Low(x, 32)`, never `x` (spec rev. 2).
- A `return f(...)` at -O2 is usually a tail jump (`jmp`), so the site is a `TailJump`, not a
  `Call`.

| File | Source | Flags | Checks | Shape |
|---|---|---|---|---|
| `suspicious_kernel-clang-O0.o` | `../src/suspicious_kernel.c` | `clang -target x86_64-unknown-linux-gnu -O0 -c` (v0.1's command) | ET_REL, `via: Reloc`, FDEs through `.rela.eh_frame`, args `0, 0, 0` | `call rel32` + `R_X86_64_PLT32 connect-0x4`. Args: `xor %edx,%edx; xor %eax,%eax; mov %eax,%esi; mov %edx,%edi`. **differs:** clang types `.eh_frame` `SHT_X86_64_UNWIND` (0x70000001), not `SHT_PROGBITS`, so it must be found by name |
| `suspicious_kernel-gcc-O2.o` | `../src/suspicious_kernel.c` | `gcc -O2 -c` | Same | `call rel32` + `PLT32 connect-0x4`; args `xor %esi,%esi; xor %edx,%edx; xor %edi,%edi`. `.eh_frame` is `SHT_PROGBITS` |
| `clean_kernel-clang-O0.o` | `../src/clean_kernel.c` | as above (clang) | No hint, no call site, `Complete` | No relocation in `.text`; `.rela.eh_frame` only. `.eh_frame` is `SHT_X86_64_UNWIND` |
| `clean_kernel-gcc-O2.o` | `../src/clean_kernel.c` | `gcc -O2 -c` | Same | No relocation in `.text` |
| `calls-noplt-gcc-O0.o` | `calls.c` | `gcc -fPIC -fno-plt -O0 -c` | Unlinked GOT: `Call`, `Import { via: Reloc }`; `helper` through its GOT entry: `Internal { entry: S }` | `kernel`, `loop`, `calls_helper`: `call *0x0(%rip)` + `R_X86_64_GOTPCRELX connect-0x4` (exact). `calls_helper` calls `helper` the same way (`GOTPCRELX helper-0x4`). **differs:** the argument is spilled and reloaded (`mov %edi,-0x4(%rbp)` … `mov -0x4(%rbp),%eax; mov %eax,%edi`), so arg 0 of `kernel` is not `Param(0)`; zeros are `mov $0x0,%esi` / `%edx`. In `calls_helper`, arg 0 is `mov %eax,%edi`: `Low(ReturnOf(helper), 32)` |
| `calls-noplt-clang-O0.o` | `calls.c` | `clang -fPIC -fno-plt -O0 -c` | Same | `kernel`, `loop`, `calls_helper`: `call *0x0(%rip)` + `GOTPCRELX connect-0x4`. Arg 0 is spilled and reloaded too (`mov %edi,-0x4(%rbp)` … `mov -0x4(%rbp),%edi`); zeros are `xor %eax,%eax; mov %eax,%esi` and `xor %edx,%edx`. **differs:** clang calls `helper` directly, `call rel32` + `R_X86_64_PLT32 helper-0x4` (a defined symbol: `Internal { entry: S + A + (next_ip − P) }`), not through its GOT entry |
| `calls-noplt-gcc-O2.o` | `calls.c` | `gcc -fPIC -fno-plt -O2 -c` | -O2 `kernel`: `jmp *[rip]`, a `TailJump` | `kernel`: `jmp *0x0(%rip)` + `GOTPCRELX connect-0x4`. `loop`: `call *0x0(%rip)` + `GOTPCRELX connect-0x4`. `calls_helper`: `call *0x0(%rip)` + `GOTPCRELX helper-0x4`, then `mov %eax,%edi`; **differs:** it also tail-jumps to `connect` (`jmp *0x0(%rip)` + `GOTPCRELX connect-0x4`) |
| `calls-noplt-clang-O2.o` | `calls.c` | `clang -fPIC -fno-plt -O2 -c` | Hoisted GOT load: `mov r15, [rip]` + `REX_GOTPCRELX`, then `call r15`; the site is at the `call` | `kernel`: `jmp *0x0(%rip)` + `GOTPCRELX connect-0x4`. `loop`: `mov 0x0(%rip),%r15` + `R_X86_64_REX_GOTPCRELX connect-0x4`, then `call *%r15` in the loop (its only relocation). **differs:** `calls_helper` calls `helper` with `call rel32` + `PLT32 helper-0x4`, and tail-jumps to `connect` (`jmp *0x0(%rip)` + `GOTPCRELX connect-0x4`) |
| `gotrel.o` | `gotrel.S` | `as` | §4.2 table rows that do not name a call | In `g`, in order: `call *0x0(%rip)` + `R_X86_64_GOTPCRELX connect` (A = 0, field at 2, `next_ip` 6: not exact, +4); `lea 0x0(%rip),%rax` + `R_X86_64_GOTPCREL connect-0x4`; `cmp %rax,0x0(%rip)` (opcode `0x39`, memory is the first operand) + `R_X86_64_GOTPCREL connect-0x4`; `lea 0x0(%rip),%rcx` + `R_X86_64_PLT32 connect-0x4`; `mov 0x0(%rip),%rdx` + `R_X86_64_PC32 extern_data-0x4`. **differs:** the `lea` and the `cmp` get plain `GOTPCREL`, not `GOTPCRELX`/`REX_GOTPCRELX` (gas emits the relaxable types only for forms the linker can relax). Both are exact. `as` accepted every line. The object also has an undefined `_GLOBAL_OFFSET_TABLE_` |
| `net-plt-gcc.so` | `net.c` | `gcc -O2 -fPIC -shared` | F-C2 `Plt` | `kernel`, `looped`: `call <connect@plt>` in `.plt`; the stub is `jmp *slot(%rip)` (`JUMP_SLOT connect`). `.plt.got` holds `__cxa_finalize@plt` |
| `net-plt-clang.so` | `net.c` | `clang -O2 -fPIC -shared` | F-C2 `Plt` | Same as gcc |
| `net-noplt-gcc.so` | `net.c` | `gcc -O2 -fPIC -shared -fno-plt` | F-C2 `Got` | `kernel`, `looped`: `call *slot(%rip)` (`GLOB_DAT connect`); no stub for `connect` |
| `net-noplt-clang.so` | `net.c` | `clang -O2 -fPIC -shared -fno-plt` | F-C2 `Got`, clang's hoisted GOT register call | `kernel`: `call *slot(%rip)`. `looped`: `mov slot(%rip),%r15`, then `call *%r15` |
| `net-pltsec-gcc.so` | `net.c` | `gcc -O2 -fPIC -shared -fcf-protection=full -Wl,-z,ibtplt` | F-C2 `PltSec` (stub at `endbr64` and at `jmp`) | `connect@plt` is in `.plt.sec`: `endbr64; jmp *slot(%rip)` (no `bnd`). `kernel`, `looped` start with `endbr64` and `call` that stub. The lazy `.plt` entries and `.plt.got` also start with `endbr64`. ld gives `.plt`, `.plt.got` and `.plt.sec` FDEs |
| `net-pie` | `netexe.c` | `gcc -O2 -fPIE -pie` | ET_DYN executable (`PT_INTERP`) | **differs:** `main` tail-jumps, `jmp <connect@plt>`: a `TailJump`, not a `Call` |
| `net-nopie` | `netexe.c` | `gcc -O2 -fno-pie -no-pie` | ET_EXEC executable | **differs:** `main` tail-jumps, `jmp <connect@plt>` |
| `net-nopie-addr` | `netnopieaddr.c` | `gcc -O2 -fno-pie -no-pie` | ET_EXEC absolute candidate: `Partial` (`address taken`) | `main`: `mov $0x401030,%edi; call keep`. 0x401030 is `connect@plt`, and also `connect`'s undefined `st_value` (the canonical PLT address). **Source changed:** see below |
| `net-addr.so` | `netaddr.c` | `gcc -O2 -fPIC -shared` | F-B1 variant: hint, no call site, `Partial` (`address taken`) | `take`: `mov slot(%rip),%rdi` (`GLOB_DAT connect`), then `jmp <keep@plt>`. No `connect` stub, no call of `connect` |
| `net-data.so` | `netdata.c` | `gcc -O2 -fPIC -shared` | F-B1 negative: hint, no call site, `Complete` | `connect` only in `.data.rel.ro`, through `R_X86_64_64 connect`; no code names it |
| `net-noeh.so` | `net.c` | `gcc -O2 -fPIC -shared -fno-asynchronous-unwind-tables -fno-unwind-tables` | F-C3: hint, no call site, `Partial` (`outside any FDE`) | `kernel`, `looped`: `call <connect@plt>`. The file has no FDE at all: `.eh_frame` is the 4-byte terminator and there is no `.eh_frame_hdr` (ld adds no `.plt` FDE either) |
| `dl.so` | `dl.c` | `gcc -O2 -fPIC -shared` | F-C1: `ConstStr` vs a stack buffer | `score`: `lea str(%rip),%rsi` (`"ggml_backend_score"` in `.rodata`); **differs:** then `jmp <dlsym@plt>`, a `TailJump`. `byname`: the loop is vectorized (SSE2: `pmuludq`, `pshufd`, …); the buffer argument is `mov %rsp,%r10` … `mov %r10,%rsi`, then `call <dlsym@plt>`: a copy of `rsp`, with no `lea` and no load. `dlsym` is `dlsym@GLIBC_2.34` |
| `ownplt.so` | `ownplt.c` | `gcc -O2 -fPIC -shared` | F-C7: `ReturnOf` → `OwnExportViaPlt` | `kernel`: `call <helper@plt>` (`JUMP_SLOT helper`, `helper` exported at 0x1120), `mov %eax,%edi`, then `jmp <connect@plt>`. **differs:** the `connect` site is a `TailJump`, and arg 0 is `Low(ReturnOf(helper), 32)` |
| `ownplt-direct.so` | `ownplt.c` | `gcc -O2 -fPIC -shared -fno-semantic-interposition` | F-C7: `ReturnOf` → `Internal { export_name }` | `kernel`: `call <helper>` (direct), `mov %eax,%edi`, `jmp <connect@plt>`. No `helper` stub. Same **differs** as `ownplt.so` |
| `values.so` | `values.S` | `as`, then `gcc -shared -nostartfiles` | F-C4, F-C5, the value forms (per function comments) | As written. 8 FDEs in `.text`, one per CFI function, each starting at its symbol; ld adds a 9th FDE for `.plt`, outside `.text` (`-nostartfiles` adds none). The functions have no `.size` (`st_size` 0). `local_helper` is a local symbol. `.Lname` is in `.rodata`, `.Lbuf` in `.data` (writable). `merge_shape`'s `mov $5,%eax` zero-extends: `Const 5` |
| `cfg.so` | `cfg.S` | `as`, then `gcc -shared -nostartfiles` | Unresolved jump table, noreturn import, a branch into an instruction, code without an FDE, a separate `.cold`-style FDE | 5 FDEs in `.text` (`jumptable`, `after_noreturn`, `into_insn`, `hot`, `cold_part`) plus ld's `.plt` FDE. `noeh_code` (0x1072..0x107e) is in no FDE. `hot`'s FDE ends where `cold_part`'s starts (0x1083), and `hot`'s `jne` (2 bytes) targets it. `into_insn`'s `jne` targets 0x1062, one byte into `mov $0x90909090,%eax` at 0x1061; decoding from there gives four `nop`s that rejoin at 0x1066, so the failure must come from the overlap, not from bad bytes. `after_noreturn`: `ff ff` after `call <abort@plt>` (objdump's linear sweep misdecodes what follows; the `je` target is the `xor`) |
| `textrel.so` | `textrel.S` | `as`, then `gcc -shared -nostartfiles -Wl,-z,notext` | Text relocation: unexplained gap, and the function fails | `tr`: `movabs $0x0,%rax` (`R_X86_64_64 connect` in `.rela.dyn` at `tr`+2), `call *%rax`. `DT_TEXTREL` and `DF_TEXTREL` |
| `many.so` | `many.S` (generated, not kept) | `as`, then `gcc -shared -nostartfiles` | §4.10 defaults with CFI: `Partial` (`references limit 65536 reached`), at most 65,536 call sites | 70,000 × `call <connect@plt>` (5 bytes each; `.text` is 350,001 bytes), one FDE over `many`, plus ld's `.plt` FDE. 361,928 bytes |
| `many-noeh.so` | `many-noeh.S` (generated, not kept) | Same | §4.10 defaults without CFI: at most 257 listed gaps, the last counting the rest | Same code; no FDE at all (`.eh_frame` is empty). 361,808 bytes |

All other built files are under 16 KB.

## Changes to the plan's sources and commands

- `netnopieaddr.c`: the plan's `volatile void *p` is a pointer **to** volatile, so the store was
  dead. gcc -O2 then deleted `keep`'s body and the call, and `connect`'s address appeared nowhere.
  The line is now `void *volatile p = (void *)f;`, which keeps the store and gives the immediate
  argument the fixture is for.
- The `.S` files are assembled by `as` into a temporary directory, then linked with gcc. Linking
  `gcc x.S` directly names a random temporary object in an `STT_FILE` symbol whenever the file has
  local symbols (`values.S`, `cfg.S`), so every build differed. The code is the same.
- `many.S` and `many-noeh.S` are generated in that temporary directory, not next to the fixtures.
- `as` accepted every line of `gotrel.S`, `values.S` and `cfg.S` unchanged.
- The `net-noeh.so` check of the plan (`grep 'pc=.*kernel'` in readelf's frame dump) could never
  match, because the dump has no symbol names. `build.sh` now compares each FDE's `pc=` range with
  the symbol's address, and first checks that this comparison finds `kernel`'s FDE in
  `net-plt-gcc.so`, so an empty parse cannot pass.
