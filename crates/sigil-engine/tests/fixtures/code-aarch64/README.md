# AArch64 code fixtures — issue #48, Task 1

These are static test inputs, not programs to execute. Tests consume committed bytes;
they do not invoke this build or a compiler. No SIGIL output participates in the oracle.

`calls.c` is headerless and declares `connect(int, const void *, unsigned)`. The
noinline `zero` and `one` pass `(0,0,0)` and `(1,0,0)` respectively. Adding one to
the return value and disabling sibling-call optimization keeps real calls at O2.
`calls.S` supplies CFI-backed zero, register-copy, agreeing/disagreeing CFG joins,
caller-clobber, helper, reserved-word, indirect-branch and PAC cases. Its Apple/ELF
and AArch64/x86-64 conditionals are explicit; the Mach-O corpus reuses this source.

| Input | Source and independently checked shape |
| --- | --- |
| `elf-clang-o0.o`, `elf-clang-o2.o` | clang 21.1.8 C; `ET_REL`, `R_AARCH64_CALL26 connect`, exact FDEs |
| `elf-gcc-o0.o`, `elf-gcc-o2.o` | GCC 15.3.0 C with GNU as 2.46; same relocation and FDE checks |
| `elf-clang-plt.so`, `elf-gcc-plt.so` | O2 C linked with LLD 21.1.8 / GNU ld 2.46; `BL connect@plt`, `JUMP_SLOT connect` |
| `elf-clang-got.so`, `elf-gcc-got.so` | Actual compiler `-fno-plt` output: ADRP/LDR plus `BLR`, `GLOB_DAT connect`, no `JUMP_SLOT` |
| `elf-no-fde.so` | C with unwind generation disabled; both frame dump tools find no FDE |
| `elf-cases.o`, `elf-cases.so` | Assembly tests; each advertised function has an exact FDE; unsupported functions have no claimed call |

Both pinned compilers really emitted the requested GOT form; no assembly substitute
was needed. The C O0 functions have no local argument spills in this corpus. Their
constant arguments are verified from the emitted instructions. An O0 build of some
other source is not implied to have known arguments.

`oracle.tsv` has the Task 1 columns, in that order. Hex addresses are half-open
`[start,end)` bounds and the address of the call instruction. Linked addresses are
virtual addresses. For ELF objects the `.text` file offset from `llvm-readobj` is
added to the text-relative symbol, FDE and instruction addresses. Thus `0x40` in an
object row is a file offset, not a linked virtual address or an analyzer input.
`slice=arm64` identifies the AArch64 slice.

Arguments are source/ABI expectations checked against the dumps: decimal constants,
`set:0,1` for the two incoming paths, or `unknown:clobbered` for caller-saved values
after a call. These labels are not SIGIL serialization syntax. `coverage` describes
the intended per-function analysis contract; it is not a claim that the future
analyzer has run or that the entire file is complete. Unsupported/malformed rows
have no named-call claim. `-` always means no claim, never numeric zero.

The complete, unedited `.objdump`, `.readobj`, `.frames`, `.nm`, `.gnu-objdump`,
`.gnu-frames` and `.gnu-relocs` files establish emitted instructions, symbol and
section addresses, relocations and exact ranges. LLVM and GNU FDE range maps must
agree before publication. Object call relocations must coincide with the precise
call instruction. No dump is truncated or hand-edited. Duplicated file names in
independent tool headings refer to the same input within that build directory.

Run from anywhere:

```sh
crates/sigil-engine/tests/fixtures/code-aarch64/build.sh OUTPUT_DIRECTORY
```

With no argument the destination is this fixture directory. `build.sh` uses `set
-eu`, `mktemp` under the repository's ignored `target/tmp/issue48`, trap cleanup,
`LC_ALL=C`, `TZ=UTC`, `SOURCE_DATE_EPOCH=0`, fixed SONAMEs and no build ID. No target
libc is used (`-nostdlib`). GCC's bundled binutils are deliberately bypassed with
`-B <repo>/target/tmp/issue48/toolchains/binutils-driver/bin/`; the extracted
binutils 2.46 shared libraries are selected via `LD_LIBRARY_PATH` in the helper.
The exact GCC-selected as, ld and cc1 paths are verified as well as their hashes.

`COMPILERS` is JSON containing each compiler, linker, assembler, dump tool and
Python interpreter's complete version output and executable SHA-256. The helper
rejects a missing or changed pin before creating a build/destination directory.
It never refreshes pins during a build. `record-tools` is an explicit maintainer
operation for reviewing a deliberate toolchain change. The provisioned GCC lives
under `target/tmp/issue48/toolchains/gcc-15.3/gcc-15.3.0-nolibc/aarch64-linux`;
binutils live under `target/tmp/issue48/toolchains/binutils-2.46`. Those toolchains
are not committed and are required to reproduce this corpus.

`fixture_tools.py` is fixture generation/verification code only. It clears compiler
search-path overrides, refuses Python optimization that would disable assertions,
builds and gathers raw dumps first, checks the oracle, computes/rechecks every
checksum, then publishes generated files. The raw dumps require no normalization:
tools receive relative fixture names. In the generated `build.log` command
transcript, the temporary source worktree path is written as `<repo>` and the
`mktemp` path as `<build>`; these are the only path substitutions. The binaries use
prefix maps and no debug paths. Timestamps are emitted as zero, not edited out.

`SHA256SUMS` covers every generated binary, dump, oracle and command transcript.
Sources, build scripts, documentation and compiler pins are versioned with Git.
Acceptance uses two fresh output directories, `diff -r`, and `sha256sum -c
SHA256SUMS` in each; the checked-in files were copied only from that reproduced
corpus. No missing tool or skipped fixture counts as a pass.
