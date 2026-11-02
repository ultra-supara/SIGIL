# Mach-O code fixtures — issue #48, Task 1

These are generated static inputs and independent LLVM 21.1.8 evidence. They are
never executed. The shared headerless C and conditional assembly are in
`../code-aarch64/`; `calls.c` and `calls.S` include them so the cross-format source
expectations remain identical. The `.tbd` files provide link-time import metadata
without a macOS SDK or target libraries.

| Input | Verified evidence and intended use |
| --- | --- |
| `arm64-classic`, `x86-classic` | 64-bit dylibs, classic dyld info and a lazy-bound `_connect` slot, exact DWARF FDEs for `zero` and `one` |
| `arm64-chained`, `x86-chained` | Real `LC_DYLD_CHAINED_FIXUPS`, `DYLD_CHAINED_IMPORT`, `DYLD_CHAINED_PTR_64`, ordinal 1, nonweak `_connect`, exact FDEs |
| `arm64-object.o`, `x86-object.o` | Strong undefined `_connect` branch relocation; explicit object compact-unwind pointer/length plus section relocation |
| `universal` | llvm-lipo fat Mach-O containing the byte-identical `arm64-chained` and `x86-classic` thin files |
| `universal-mixed` | Real fat Mach-O containing `arm64-chained` and a real 32-bit i386 Mach-O object, intentionally unsupported by the planned 64-bit analyzer |
| `compact-object.o` | Native arm64 compact-only object: two explicit lengths of `0x24`, both encoding `0x04000000`, no DWARF FDEs |
| `unwind-folded` | Link of `compact-object.o`; two real functions folded into one native compact entry, no FDE or `LC_FUNCTION_STARTS`; no exact function/call claim |
| `no-unwind` | Real `_connect` stub/bind but neither exact FDEs nor compact unwind; no exact function/call claim |
| `duplicate-name-dylibs` | Explicit synthetic derivative with two `_connect` symbols, two stubs, two slots and two dylib ordinals; details below |
| `arm64-cases.o`, `x86-cases.o`, `arm64-cases`, `x86-cases` | Shared assembly zero/copy/joins/caller-clobber and named malformed/unsupported functions, with explicit object entries or linked FDEs |
| `i386-unsupported.o` | The actual 32-bit Mach-O object embedded in `universal-mixed`; not ELF or a renamed 64-bit file |

The ordinary classic/chained fixtures contain only the healthy C functions.
Negative assembly cases are separate inputs. Every emitted bound in `oracle.tsv`
is checked against a same-file symbol and either a linked FDE or an explicit
`MH_OBJECT __LD,__compact_unwind` pointer/length. The raw object `.frames` dumps
are retained for research but do not establish object addresses: unresolved
Mach-O FDE relocation pairs can make dwarfdump print section-biased PCs. Object
oracle addresses instead use the explicit object compact entries and relocations.

Linked C is compiled with `-fasynchronous-unwind-tables`,
`-femit-dwarf-unwind=always` and `FORCE_DWARF`. The harmless
`DW_CFA_GNU_args_size(0)` escape forces DWARF-mode unwind entries, including on
x86-64 where the linker would otherwise discard the FDE in favor of a native
encoding. Assembly has the same valid CFI escape. The native compact-only case
does not use it. A linked compact successor or sentinel is never substituted for
an exact individual function end.

The complete `.macho` dump uses `llvm-objdump --macho --bind --lazy-bind
--chained-fixups --unwind-info --indirect-symbols --private-headers --dyld-info`.
It includes actual chained pointer bindings in addition to the fixup header and
import list. `.objdump`, `.readobj`, `.frames` and `.nm` preserve independent
instruction, relocation, section, symbol and FDE evidence. Raw dumps are neither
truncated nor edited.

`bindings.tsv` joins independent indirect-symbol indices to each stub and GOT/lazy
slot, then checks the emitted stub load/jump and the actual dyld binding. The
ordinal is the 1-based `LC_LOAD_DYLIB` position; the chained import ordinal and
weak bit are checked separately. Each named linked call's emitted branch target
must match a verified stub with the claimed library. The universal inventory
files record each slice's CPU/subtype, alignment, offset, size and SHA-256; the
generator verifies header/table agreement, nonoverlap and byte identity with the
thin source. Fat objdump/nm commands explicitly select `--arch=all`; readobj and
dwarfdump enumerate both slices. Virtual addresses in the fat oracle stay local
to each named slice.

`oracle.tsv` uses the same columns and value/coverage conventions documented in
`../code-aarch64/README.md`. Linked addresses are virtual. Object addresses add
the `__text` file offset to the section-relative entry/instruction address; they
are slice-relative file offsets. `library=unbound` for object imports is an
explicit unresolved-library witness. `-` is no claim, never zero. Coverage is the
expected per-function contract, not an analyzer run or a whole-file verdict.

`duplicate-name-dylibs.before` is the unmodified linker output. It imports
`_connect` from `/usr/lib/libSystem.B.dylib` and `_connec2` from
`/sigil/libfoo.dylib`. `duplicate-name-dylibs.patch.json` records its SHA-256 and
the two exact byte offsets replaced: `_connec2\0` becomes `_connect\0` in the
symbol string table and classic lazy-bind stream. This equal-length synthetic
transformation changes no instruction, offset, binding opcode or ordinal. The
before file and its full dumps are committed. After transformation independent
dumps and stub checks prove:

| Stub | Slot | Raw symbol | Library ordinal and name |
| --- | --- | --- | --- |
| `0x5bc` | `0x8000` | `_connect` | 1, `/usr/lib/libSystem.B.dylib` |
| `0x5c8` | `0x8008` | `_connect` | 2, `/sigil/libfoo.dylib` |

`zero`/`one` branch to the first stub; `from_foo` branches to the second. The
generator verifies these paths independently before producing oracle rows. This
case is synthetic and is not represented as a normal compiler/linker result.

Run `crates/sigil-engine/tests/fixtures/code-macho/build.sh OUTPUT_DIRECTORY`.
Without the argument it publishes into this directory. The shared helper checks
the complete versions/executable hashes in `COMPILERS` before any build or output
creation. It uses a trapped `mktemp` directory under ignored `target/tmp/issue48`,
fixed environment, reproducible ld64 flags, no UUID or ad-hoc signature, zero
dylib timestamps and fixed install names. Relative input names keep the raw dumps
free of temporary paths. Only the command transcript substitutes `<repo>` for
the temporary source worktree and `<build>` for the mktemp directory. Sources
use prefix maps; no timestamp or path field in a raw dump is edited.

All oracle/shape/hash checks precede publication. `SHA256SUMS` covers every
generated binary, full dump, inventory, patch record, binding/oracle table and
command transcript. The pinned LLVM tools and Python are required; build scripts
never update pins automatically. Both clean builds, recursive diff and checksum
checks must pass. A missing compact-only proof or linker mode is a failed gate,
not a skipped success. This corpus has both requested linker modes and the
separate native compact-only evidence; it makes no claim of product support yet.
