# ADR-017 standalone validation

This crate is excluded from the product workspace by its own `[workspace]`.
It is research code, not an engine dependency or a general A64 decoder. The
prefilter and typed adapter in `src/main.rs` are the exact proposed supported
subset; widening either requires another gate. See the adjacent ADR for the
source path audit and the limitations of these observations.

From the repository root, with the Task 1 pinned toolchains present:

```sh
export CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0
export CARGO_TARGET_DIR="$PWD/target/tmp/issue48/task2/build-193"
cargo +1.93.0 run --manifest-path docs/adr/ADR-017-gate/Cargo.toml --locked
cargo +1.93.0 check --manifest-path docs/adr/ADR-017-gate/Cargo.toml --locked --target wasm32-unknown-unknown
python3 docs/adr/ADR-017-gate/audit_sources.py
python3 docs/adr/ADR-017-gate/check_oracles.py "$CARGO_TARGET_DIR/debug/sigil-adr017-decoder-gate"
python3 docs/adr/ADR-017-gate/check_unwind.py
python3 crates/sigil-engine/tests/fixtures/code-aarch64/check_oracles.py
export CARGO_TARGET_DIR="$PWD/target/tmp/issue48/task2/build-199"
cargo +1.99.0 run --manifest-path docs/adr/ADR-017-gate/Cargo.toml --locked
cargo +1.99.0 check --manifest-path docs/adr/ADR-017-gate/Cargo.toml --locked --target wasm32-unknown-unknown
cargo +1.93.0 fmt --manifest-path docs/adr/ADR-017-gate/Cargo.toml -- --check
```

Builds are sequential and use two jobs. `panic = "abort"` is set in the research
profile. There is no `catch_unwind`. The allocator counter surrounds the actual
adapter loop, including the same raw prefilter and checked target arithmetic.
The default program exits nonzero on any candidate error or allocation. A panic
also fails the process. `words` streams all eligible corpus words; `inspect`
streams each candidate's normalized typed operands for the independent oracle.
Those two modes allocate for trusted validation I/O and are outside the measured
adapter loop. Production must obtain exactly four charged bytes first, never
feed a file reader to either decoder, and charge the caller's work budget.

The corpus contains 1,000,000 xorshift64 words from seed `0x48c0ffee` (13,7,17),
100,000 structured mutations, and 3,289 explicit mask/immediate/register boundary
cases. The same deterministic corpus reaches both candidate adapters. It is
sampling evidence plus a manual source path audit, not a proof of the full ISA.
`check_oracles.py` also reads every arm64 instruction row in the Task 1 dumps,
reassembles the union of those words and the eligible hostile words into a data
only ELF object, then parses LLVM 21.1.8 and GNU 2.46 disassembly independently.
It compares widths, ZR/SP roles, raw classes, memory modes, immediates, shifts,
signed displacements and destinations at the oracle instruction PCs. GNU's
explicit MOVN/Z/K forms check their raw class/immediate/shift; LLVM retains some
MOV aliases despite `no-aliases`, so its effective constant is checked too.
Tool output is streamed to files, and comparisons iterate over those files.
Original fixture addresses are also checked. GNU resolves some object-file branch operands through relocation symbols; the checker records those renderings, removes only `.rela.text` in scratch copies, verifies each unchanged raw word, and checks its encoded destination at the original PC. No inspected fixture is executed.

`check_unwind.py` uses real Task 1 native object, folded linked and DWARF-mode
fixtures. It creates a synthetic regular-page derivative and a compressed local
encoding derivative, asks LLVM to read them, and rejects 15 malformed structures
with its research format checker. These derivatives establish representation
checks, not compiler-emitted regular-page coverage or product parser safety.
The native linked fixture intentionally supplies no exact function intervals.

`results.json` preserves compact measured evidence and checksums. Large corpus,
source downloads, dumps, logs and build outputs remain in
`target/tmp/issue48/task2`. Cargo registry archive checksums in this standalone
lockfile also pin the full comparison graph. Future M3-B integration must resolve
and check the product lockfile independently; this lockfile does not preapprove
an arbitrary future resolution.
