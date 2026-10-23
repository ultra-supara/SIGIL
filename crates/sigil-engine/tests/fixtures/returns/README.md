# Returned-value fixtures (PR-4c-2b)

Inputs of the tests of what `ggml_version` and `ggml_commit` return
(`sigil-engine::binary::returns`; `tests/returns.rs`, `tests/signatures.rs`, and the safety case
`binary_returned_value_reads_with_pread_only`).

`build.sh` is run once, by hand. The tests never run it or a compiler; they read only the
committed files.

Next to the sources and `build.sh`:
- the built files, and an `objdump -d` dump of each (`<file>.objdump`);
- `SHA256SUMS` of the built files;
- `COMPILERS`: gcc 15.3.0, clang 21.1.8, GNU as and ld 2.46.50, ld.lld 21.1.8.

What `build.sh` enforces (it stops with exit 1 otherwise):
- **The toolchain.** The first line of `gcc`, `clang`, `as`, `ld`, and `ld.lld --version` must
  equal `COMPILERS`, checked before anything is built. To adopt another toolchain on purpose,
  delete `COMPILERS` first.
- **The shapes.** Every fact in the **Shape** column below is checked on the built files (the
  instructions of each function within its `st_size`, its symbol type, the SONAME, the machine,
  the dynamic tags, and the strings in `.rodata`), except the facts marked †: addresses and
  offsets read from the dumps, which the tests use as constants (`tests/returns.rs`).
- **No half-built tree.** It builds into a temporary directory and replaces the committed files
  only after every check has passed.

Two runs of `build.sh` give the same `SHA256SUMS` (verified by hand, not by the script).

Every file is a shared object with SONAME `libggml-base.so.0`, as v0.30.6's
`libggml-base.so.0.13.1`, built without `DT_RELR` unless its name says `relr`.

| File | Source | Flags | Shape |
|---|---|---|---|
| `version-gcc-O2.so` | `version.c` | gcc `-O2` | both functions `lea X(%rip),%rax; ret` (8 bytes); † `ggml_version` at `0x1100` returns `0x2000` (`0.13.1`), `ggml_commit` at `0x1110` returns `0x2007` (`6f3a9f3de`); † the read-only segment's file bytes end at `0x20c4`, the executable segment's at `0x1121`; † the first `.rela.dyn` entry, at file offset `0x3b0`, is an `R_X86_64_RELATIVE` |
| `version-1.0.0-gcc-O2.so` | `version.c`, `VERSION` `1.0.0` | gcc `-O2` | as `version-gcc-O2.so`; `ggml_version` returns `1.0.0` |
| `version-relr-gcc-O2.so` | `version.c` | gcc `-O2`, `-z pack-relative-relocs` | as `version-gcc-O2.so`, with `DT_RELR`; † `.relr.dyn`'s first entry is an address (even) |
| `version-long-gcc-O2.so` | `version.c`, `VERSION` 300 `x` | gcc `-O2` | the 300 bytes in `.rodata`; † `ggml_version` returns `0x2000`, file offset `0x2000` |
| `version-clang-O0.so` | `version.c` | clang `-O0` | `push %rbp; mov %rsp,%rbp; lea X(%rip),%rax; pop %rbp; ret` (13 bytes) |
| `version-cet-gcc-O0.so` | `version.c` | gcc `-O0 -fcf-protection=full` | `endbr64`, then as clang `-O0` (17 bytes) |
| `global-gcc-O2.so` | `global.c` | gcc `-O2` | `ggml_version` is `mov X(%rip),%rax; mov (%rax),%rax; ret`: a pointer loaded through the GOT |
| `branch-gcc-O0.so` | `branch.c` | gcc `-O0` | `ggml_version` has two or more `je`/`jne`/`jmp` |
| `version-aarch64.so` | `version.c` | clang `--target=aarch64-linux-gnu`, ld.lld, `-nostdlib -O2` | AArch64 |
