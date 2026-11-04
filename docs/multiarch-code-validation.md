# Multiarchitecture code validation

Task 12 (2026-11-04), base `d54b6cd`, worktree `SIGIL-issue48`.
Toolchain: rustc 1.93.0 (254b59607), cargo 1.93.0 (083ac5135).
All Cargo commands ran sequentially with `CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0`.

| Command | Result |
|---|---|
| `cargo test -p sigil-engine --test macho_code_image` before implementation | Behavioral RED: marked inner endian was `None`, expected `Some(true)`. |
| `cargo test -p sigil-engine --test macho_code_image --test macho_facts --test multiarch_code --test install_code_coverage` | 83 passed; includes existing Mach-O policy gate. |
| `cargo test -p sigil-engine --test macho_code_image` after final mapping edits | 18 passed: nine image/collection tests and nine shared-reader tests. |
| `cargo test -p sigil-engine --lib code_metadata_tests` | One passed; local gaps and CPU ambiguity remain distinct from sibling diagnostics. |
| `cargo clippy -p sigil-engine --lib --test macho_code_image -- -D warnings` | Passed. |
| `cargo test -p sigil-model --test multiarch_code frozen_task0_canonical_bytes_and_reports_are_identical -- --ignored --nocapture` | One baseline comparison passed: 26 canonical sessions, four Markdown/AI-BOM pairs and missing-code legacy report. |
| `cargo fmt --all -- --check`; `git diff --check` | Passed. |

Fixture SHA-256 (existing Task 1 fixtures, unchanged):

```text
154d9bf8aaf028e6d5bc682634343018516586bcf787714d0456ed3f40eecbc5  arm64-classic
8ecf0df0eba33104e40f536a6118704118b30cb2c674f231f4c7e480b9c07a8f  arm64-chained
a347b198c4a20dd4f83ab6d063f8e55c3a1c24063f2ba951cd06c41d6179017f  x86-classic
98c783e74b81a6ff6acdf8363257f9aa48ec64aae88bfc4faa3633cc24db1aa4  arm64-object.o
c594e3535e58f4c02d88bc24619c35b6ee9cd5ae75dea0c24ae419e524ef3379  x86-object.o
bdfaeeb80f0cdbe8aa17b54eb11fa8782016ffed530f9f636efdfc6d92594eb1  universal
```

The universal test compares each raw slice against its independently built thin source and the parser's slice hash. No fixture rebuild or large corpus was run. Mach-O code dispatch and its policy gate remain disabled; actual healthy-sibling call facts await Tasks 13–15. Task 10's mixed x86 resource/alias issue still blocks M3-B.

Task 12 review fix (2026-11-04), base `056e908`: string eligibility now requires R without W or X on the whole segment. The new object/linked R/RX/RW test failed before the fix on an RX noninstruction section returning `hello`; it now passes. RX instruction bytes remain readable as code, and R nonexecutable sections still supply strings. Existing universal/object address assertions are retained.

With the same two-job sequential build environment: `cargo test -p sigil-engine --test macho_code_image --test multiarch_code` passed 42 tests; scoped `cargo clippy -p sigil-engine --lib --test macho_code_image -- -D warnings`, `cargo fmt --all -- --check`, and `git diff --check` passed. No full suite, corpus or baseline rerun. Mach-O dispatch/policy gates and Task 10 HOLD remain unchanged.

## Task 13: exact Mach-O unwind extents (2026-11-04)

Private `macho::unwind::read_bounds` reads the same fd through `SliceWindow` and shared `Run`. It validates explicit compact-object lengths/local unsigned relocations, regular/compressed linked pages, common/local encoding indexes, sentinels and exact DWARF FDE offsets. Accepted intervals are sorted and disjoint; conflicting extents are rejected together. Linked lookup spans and `LC_FUNCTION_STARTS` never supply function ends. Object FDEs without relocations translate section VMs to artifact-file offsets; object FDE relocation pairs and compact personality/LSDA pointers remain explicit gaps. No Mach-O decoder or policy dispatch is enabled.

Fresh LLVM **21.1.8** `llvm-objdump-21 --macho --unwind-info` and `llvm-dwarfdump-21 --eh-frame` agree with the checked fixtures: native `compact-object.o` explicitly records two lengths0x24, translated to `[0x188,0x1ac)`/`[0x1ac,0x1d0)` without FDEs; `arm64-classic` FDE offsets0x14/0x48 record `[0x520,0x544)`/`[0x544,0x568)`; `x86-classic` records `[0x520,0x533)`/`[0x540,0x556)`; `x86-object.o` FDEs and explicit compact lengths agree at file `[0x1d8,0x1eb)`/`[0x1f8,0x20e)`. LLVM also reads the regular and local-encoding derivatives of `unwind-folded` as the same single entry0x4c0/encoding0x04000000. These derivatives are synthetic representation checks. The original and derivatives emit no exact function interval; the0x508 sentinel is only a lookup boundary.

Rust1.93.0; all Cargo commands used `CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0`, sequentially. The initial focused native-object test failed with empty bounds before implementation. Final `cargo test -p sigil-engine --test macho_code_unwind --test macho_code_image` passed **29+19** tests, including the production reader/FDE unit tests compiled into the private integration target. `cargo test -p sigil-engine --lib code::tests` passed35 focused accounting/decoder tests after the unchanged Run/Work source moved into a private module so integration tests use actual counters. Scoped `cargo clippy -p sigil-engine --lib --test macho_code_unwind -- -D warnings`, `cargo fmt --all --check` and `git diff --check` passed. No large corpus, full suite or baseline was rerun.

Negatives cover invalid/duplicate/missing object relocations; zero/oversized/mismatched lengths; unknown/nonfunction encodings; folded compact-only images with and without function starts; wrong CIE, indirect/empty/wrapping/overlapping FDEs and wrong exact offsets; malformed regular/compressed arrays, encoding indexes, order, duplicate entries and sentinels; truncated metadata; byte/FDE/relocation limits shared across slices; object/fat versus linked VM addresses and refusal to read neighboring slice bytes. Existing fixture hashes remain unchanged; additionally `compact-object.o` is `fc1ceb3aa6a6938c8ca4ca5af724c7e24495fd66ce91e319237b05015ccd8fad` and `unwind-folded` is `4ad95ce548779164928f4d111a6f7f121a48297c39d460256fbaa0b1d4ceae85`.

Task 10's mixed x86 budget/alias issue remains open. Task 13 establishes private exact bounds; actual Mach-O calls, healthy sibling call facts and policy integration remain later tasks. M3-B and issue #48 are not complete.

Task 13 review fix (2026-11-04), base `95063fa`: Mach-O exact-record FDE lookup now accepts only CIEs at actual sequentially walked CIE boundaries. Walked CIEs charge the shared entry budget before retention; legacy ELF lazy lookup and its FDE-only accounting remain unchanged. The review's `arm64-classic` mutation embeds CIE-shaped bytes at section offset0x30 inside FDE0x14 and points FDE0x48 to them: the new test was RED before the fix, then GREEN with only `[0x520,0x544)` retained and an explicit CIE-boundary gap. A normal pointer to real CIE0 preserves both extents; the same interior-pointer fixture still preserves the historical legacy ELF result. Exact-record budget1/2/3 controls verify bounded CIE retention.

With two jobs/debug0 and serial builds, `cargo test -p sigil-engine --test macho_code_unwind` passed32 tests; scoped `cargo clippy -p sigil-engine --lib --test macho_code_unwind -- -D warnings`, targeted rustfmt and `git diff --check` passed. No broader suite or oracle/corpus rerun. Task10 mixed x86 HOLD and later Mach-O integration remain unchanged.

Task 14 (2026-11-04), base `3b77e93`: private `macho::bind::read_bindings` joins validated classic/lazy or chained slots with the exact same-slice import inventory (`MachCodeView.imports`, empty until supplied by the artifact owner). Raw names, library ordinal/name and weak flags remain distinct. Actual classic/chained arm64/x86 fixtures match `bindings.tsv`; `duplicate-name-dylibs` retains `_connect` at `0x8000` from libSystem and at `0x8008` from libfoo. DYSYMTAB corroborates pointer witnesses rather than manufacturing them. Duplicate/overlapping claims stay poisoned. Unsupported or malformed source metadata discards its map and records a gap. No dispatch/policy gate changed.

Supported chained pointer formats are unauthenticated `DYLD_CHAINED_PTR_64`/`64_OFFSET` with their 4-byte stride, import formats 1/2/3, uncompressed symbols and zero total addend; layouts checked against [Apple's fixup-chains.h](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h). Authenticated/other pointer formats, multiple starts, threaded/weak-bind streams and nonzero effective addends remain explicit gaps. All reads are on the borrowed fd through `SliceWindow`; imports/opcodes/pages/indirect entries, chain slots, scans and retained name copies charge the actual shared Run. Unbound/FlatLookup policy remains for Task16.

TDD empty-map RED → real-fixture GREEN. Sequential `CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0` checks: `cargo test -p sigil-engine --test macho_code_bind --test macho_code_image --test macho_code_unwind` **21+19+32** passed (bind target includes nine Reader tests); `cargo test -p sigil-engine --test macho_facts -- chained_ bind_opcodes_ an_object_file_s_imports_ an_ordinal_past_ a_linked_image_s_imports_ --skip past_64_mib` **9** passed. Scoped clippy (`--lib --test macho_code_bind -- -D warnings`), targeted rustfmt and diff checks passed. One frozen legacy comparison passed: 26 canonical outputs, four Markdown/AI-BOM pairs and missing-code report. No large corpus/full suite. Task10 HOLD remains separate; real Mach-O call facts await Task15.
