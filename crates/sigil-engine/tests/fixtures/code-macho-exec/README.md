# Minimal MH_EXECUTE call evidence

`arm64-executable` and `x86-executable` are real linked 64-bit little-endian
`MH_EXECUTE` files (header filetype2), with `LC_MAIN`, `LC_LOAD_DYLINKER`, exact
DWARF FDEs and classic lazy `_connect` binding. They are static test inputs and
are never executed. `_zero` is the explicit entry solely to keep the fixture
small; these files make no claim about a deployed application's runtime behavior.

`build.py` reuses Task1's headerless `../code-macho/calls.c`, its shared source,
`libSystem.tbd`, the exact `../code-macho/COMPILERS` pins and the reviewed
`../code-aarch64/fixture_tools.py` builder/oracle. clang/LLVM/LLD21.1.8 compile/link
both architectures. The helper verifies all tool versions and executable hashes
before creating a work directory under `target/tmp/issue48`; it fixes
`LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=0`, strips UUID/ad-hoc signing and uses source
prefix maps. Output must be absent and is staged/renamed after all checks.

The complete raw `.objdump`, `.readobj`, `.frames`, `.nm` and `.macho` dumps prove
the file type, exact function intervals, argument setup, decoded branch, decoded
stub, actual slot and `/usr/lib/libSystem.B.dylib` ordinal1/nonweak identity.
`oracle.tsv` contains four calls, and `bindings.tsv` contains two exact slot
witnesses. `build.log` records commands; only its temporary paths are normalized,
as in Task1. `SHA256SUMS` covers all15 generated files. No SIGIL output supplies
an oracle and normal Rust tests only consume committed bytes.

Run from the repository root, with pinned Task1 tools available:

```sh
python3 -B crates/sigil-engine/tests/fixtures/code-macho-exec/build.py target/tmp/issue48/exec-one
python3 -B crates/sigil-engine/tests/fixtures/code-macho-exec/build.py target/tmp/issue48/exec-two
diff -r target/tmp/issue48/exec-one target/tmp/issue48/exec-two
(cd target/tmp/issue48/exec-one && sha256sum -c SHA256SUMS)
(cd target/tmp/issue48/exec-two && sha256sum -c SHA256SUMS)
```

Builds run sequentially. Both clean builds, full directory diff and all checksums
passed for the Task18 supplement. The original dylib/object/fat corpus is unchanged.
`real_mh_execute_calls_match_independent_oracle_and_public_session` exercises public
`binary_session`, exact oracle addresses/intervals/values/library witness,
Complete child/input coverage, saved-session validation and library-aware denied
network policy reevaluation for both files. This supplement does not exhaust
every executable/fixup/fat combination or close Task10, Task19 or issue48.
