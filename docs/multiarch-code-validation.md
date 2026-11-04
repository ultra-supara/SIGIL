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

Task14 review fix1 (2026-11-04), base `06d8692`: corrected classic/lazy state against Apple's [BindOpcodes initialization, DONE handling and validation](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/BindOpcodes.cpp#L78-L202). Lazy DONE preserves segment/offset/addend/type/name/library/weak. Classic type starts unset; only lazy type defaults to pointer. An absent ordinal is separate from explicit SelfImage ordinal0. Three new regressions reproduced RED (false exact witness after +1 addend, discarded valid inherited state, classic missing-type witness), then GREEN with inherited-state/weak controls, unsupported-type persistence, lazy implicit-type and missing/explicit-zero ordinal controls. Common classic test streams now explicitly SET_TYPE_POINTER.

Sequential two-job/debug0 validation: bind24, existing import-related9 (large tests excluded), scoped clippy, targeted fmt/diff and frozen legacy26+4 comparison passed. No image/unwind rerun, full suite or large experiment. Policy/dispatch and Task10 HOLD remain unchanged.

## Task 15 — Mach-O code producer (2026-11-04)

Base `ce5254535554b29b03421b9a85f953a051278588`; Rust `1.93.0 (254b59607 2026-01-19)`. Same-fd artifact dispatch now supplies the exact per-slice inventory to bounds/bindings/stub/object readers. Only decoded arm64 ADRP/LDR/BR veneers using x16/x17 and decoded x86 RIP-indirect JMP stubs can join actual slot witnesses. Object external strong undefined BRANCH26/disp32 relocations require exact zero-addend matching instructions and retain Unbound identity. Query reservations, per-function CFG/value/return dependencies and transactional commit use the existing architecture solvers and shared artifact counters. Unsupported metadata and references outside exact bounds remain gaps; no fixup is applied. Runtime memory constants/strings are conservatively not recovered by this recorder.

TDD: `cargo test -p sigil-engine --test macho_code_calls` initially failed because `arm64-classic` was Unsupported. Final calls **16** and image **19** tests passed; earlier affected bind **24** and unwind **32** tests passed without changes to those adapters. The call tests cover real thin/fat/object fixtures; zero/one arguments, same-name libSystem/libfoo witnesses, GOT/tail calls, join/clobber values, malformed/middle/scratch-clobber stubs, rejected relocation forms/addends/weak/local/duplicate symbols, two-call transaction rollback, work limits, and retained healthy sibling calls with unparsed/lost descriptors and partial installation parents. Object/libfoo prototypes are absent from ABI v1, so those targets honestly retain empty args, Partial layouts and their required gaps rather than copying the oracle's source-intended values.

Commands (exit 0): `cargo test -p sigil-engine --test macho_code_calls --test macho_code_image`; `cargo test -p sigil-engine --test macho_code_calls --test macho_code_bind --test macho_code_unwind --test macho_code_image`; focused old x86/session regression `cargo test -p sigil-engine --test code_session code_ -- --skip a_code_request_never_changes_the_container_coverage` (**8**); `cargo clippy -p sigil-engine --lib --test macho_code_calls --test macho_code_image -- -D warnings`; `cargo fmt --all -- --check`; `git diff --check`. All Cargo builds used `CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0`, serially, with the existing disk-backed target. No full suite, large corpus, fixture rebuild or repeated baseline experiment. Fixture bytes and independent dumps/oracles are unchanged; the fixture `SHA256SUMS` file hashes to `0b741b5f1d32398b65702b1245942b3731ad2f092f70504008014f381a12f2f1`.

**Mandatory Task16 handoff:** policy and model validator gates remain enabled. Public `binary_session`/CLI `--code` on a Mach-O with produced calls currently returns Invalid (`marked Mach-O call facts await library-aware policy validation`); a denied Mach-O capability also remains gated. The explicit gate test preserves that intermediate behavior. Open both gates only together with Task16's exact-library policy/validator rules and end-to-end session tests. This commit is producer work, not completed/public M3-C support. Task10 mixed-x86 P2 and original issue48 Unknown/PR-5b acceptance remain unresolved.

### Task 15 review fix — conditional CFG edges

Base `0bfea4f`, 2026-11-04: the review's x86-classic JZ/JNZ mutation at `0x528` reproduced a false `_connect` TailJump with no gap (RED). Mach-O target resolution and recording now admit CALL/unconditional JMP only; conditional branches retain ordinary CFG edges, and a reachable conditional edge outside the exact function produces an explicit gap and discards that function before value analysis/commit. The unaffected function survives. Legacy x86 ELF code is unchanged; Task16 gates remain closed.

GREEN (exit 0), two-job/debug0 sequential builds: `cargo test -p sigil-engine --test macho_code_calls -- x86_conditional_stub_edges_discard_the_function_without_becoming_calls real_thin_stubs_join_exact_import_witnesses tail_calls_and_got_calls_require_actual_decoded_targets architecture_cfg_join_and_caller_clobbers_use_real_oracle` (**4** focused tests, both JZ/JNZ and normal direct/unconditional-tail/internal-CFG controls); `cargo clippy -p sigil-engine --lib --test macho_code_calls -- -D warnings`; `cargo fmt --all -- --check`; `git diff --check`. No corpus/full suite/baseline repetition.

## Task 16 — Library-aware Mach-O policy (2026-11-04)

Base `abff5c6`. Marked Mach-O call facts and capability decisions now open together. `capability_calls` partitions exact same-slice raw-name/library/weak witnesses into admitted named-library calls, other named-library calls, and unresolved bindings. Existing `looked_up()` and pinned import-hint derivation are unchanged. An unresolved site with a relevant existing hint retains its own symbol/site question beside any admitted violation; the question uses its slice's applicable check. Legacy and marked ELF validation retain the previous exclusive-results and symbol-only-question rules.

The real `duplicate-name-dylibs` producer retains three calls with their actual witnesses: only the two libSystem sites support `posix.network`; the libfoo site cannot inherit that denial or inflate the capability report count. Thin arm64/x86, universal, mixed unsupported and object sessions validate through the public producer. Markdown shows source libraries and the architecture's argument names, and CLI summaries list Mach-O slice capability counts. Existing AI-BOM projection carries simultaneous violation/question results without copying call facts or changing its schema.

TDD began with the actual public producer returning `MultiarchCapabilitiesNotEnabled`. A deliberate negative control temporarily bypassed library eligibility: the same-name regression failed with **3 violation sites versus 2 expected**. Eligibility was restored before final GREEN. Mutations cover missing/raw-name/weak/ordinal/slice witness mismatch, admitted/unresolved evidence contamination, missing/duplicate references and forged question reasons; coverage controls remove/duplicate children or forge a complete parent. Coherently replacing a witness with another existing import and updating its ABI/result facts is accepted: saved sessions do not authenticate source bytes.

Sequential validation used Rust1.93.0, `CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 TMPDIR="$PWD/target/tmp/issue48"`:

- `cargo test -p sigil-engine --test multiarch_policy -- --test-threads=1`: **7 passed**, covering named libSystem/libfoo/libc++, Unbound/FlatLookup/WeakLookup/SelfImage/MainExecutable/unknown dylib names, existing hint preservation, mixed questions, both applicable checks, deterministic serialization/re-evaluation and escaped report sources.
- `cargo test -p sigil-engine --test macho_code_calls -- --test-threads=1`: **17 passed**; former staged-gate expectation is now a real two-slice public-session and denial verification test. Existing `libcxx_capabilities`: **6 passed**. `multiarch_code marked_`: **4 passed** for the unchanged ELF paths.
- Model `multiarch_code` **29 passed / 1 intentionally ignored**, `capability_rules` **9 passed**, and `--lib render::code` **13 passed**. The ignored frozen comparison was then explicitly run: **26 legacy canonical files plus four Markdown/AI-BOM pairs and missing-code report unchanged**.
- `cargo test -p sigil-cli --test cli -- macho_library_policy --test-threads=1`: **1 passed**, exercising five real fixture kinds, standalone and installation saved-session verification, both ABIs' rendered arguments, Unbound question evidence on both collection routes, witness tampering refusal and unsupported-slice exit3/exit4 precedence.
- Scoped model/engine/CLI library/binary clippy with `-D warnings`, formatting and diff checks passed. Focused logs are retained under `target/tmp/issue48/task16`.

No binding classification adds a parser/decoder gap. The archived ABI table currently gives unresolved/other-library calls an unknown prototype, which independently requires the preexisting argument-layout gap. Complete-search unresolved-binding reason precedence is therefore checked directly in the pure policy helper, while actual object/unresolved sessions retain honest prototype Partial coverage. No claim of a complete unresolved-call producer fixture is made. No full workspace suite, large corpus, safety suite, fixture rebuild or viewer/WASM rebuild was repeated; release/safety/viewer work remains Task17+. Task10 mixed-x86 budget/alias P2 and the M3-B/issue48 HOLD remain unresolved.

Task16 review fix1 (2026-11-04), base `a2085fc`: admission now checks the exact raw symbol, feature and named dylib mapping, instead of admitting all libSystem symbols or all libc++ `cxx.*` symbols. The actual same-name producer session can contain both libc++ and libSystem imports; a libc++-only raw symbol called through libSystem retains the admitted import's no-call question and cannot inherit its denial. The reverse libSystem-mapped C++ case and both-call cases select only the correctly mapped witness. Policy, model validation, native Markdown counts and CLI counts share this mapping.

The model embeds an immutable 133-entry projection of `sigil-engine/signatures/capabilities.toml`, selected only by that source's SHA-256 `2620e766e87f4ecc97f2bc24d3cd0e10cb538ca8c0ece532d69afaaf0ac7215c`. A focused test hashes the original source and compares every `(symbol, feature, dylib)` entry. There is no latest-table fallback: unknown digests cannot validate marked Mach-O capability decisions; rendering without decisions reports call eligibility unavailable, and engine denial evaluation fails closed if its current table lacks an archive. As in existing engine pinning, package-version metadata is informational: identical source bytes under an older build version use the same archive. Only this digest is archived today. Future table changes must add another immutable archive while retaining this one; engine policy verification's preexisting requirement for its current table is unchanged. Marker-absent and marked ELF table semantics remain unchanged, including their model handling of unknown digests.

TDD reproduced the review's wrong-library false violation (**1 vs0 expected**) before the fix. Final sequential two-job/debug0 checks: engine `multiarch_policy` **9 passed** (both raw-name directions, positive controls, same-name both calls, Unbound/FlatLookup, unknown-hash refusal, same-hash prior-build metadata, evidence mutations and renderer checks); model `multiarch_code` **30 passed / 1 ignored**, legacy `capability_rules` **9 passed**; marked ELF **4 passed**; actual CLI **2 passed**. The original review file now fails `session verify` with the exact admitted-evidence diagnostic; a correctly re-evaluated session verifies and renders. The explicit frozen legacy comparison, scoped source clippy `-D warnings`, formatting and diff checks passed. Logs are under `target/tmp/issue48/task16-fix1`.

No dependency, table-source bytes or schema changed; the projection adds no TOML parser to native/WASM model code. No full suite, corpus or viewer build was repeated. **Task17 must rebuild the committed viewer bundle from this updated model, check native/WASM parity and the gzip size budget before release.** The existing bundle does not include this policy-validation fix yet. Task10 mixed-x86 HOLD remains unresolved.

## Task 17 — Mach-O CLI, safety and viewer (2026-11-04)

Base `f705c9f0b7cd68862f5d95cde68f911af796e720`; Rust/Cargo 1.93.0,
Node 22.22.2, strace 7.0. Logs and exact build hashes: `target/tmp/issue48/task17`.
Builds used two jobs, debug0 and disk-backed workspace TMPDIR. No full workspace
suite, large corpus or fixture regeneration was repeated; Task19 retains those gates.

- `cargo test --locked -p sigil-cli --test cli macho_thin_fat_install_service_observe_and_shared_budget`: PASS. Actual thin arm64/x86, healthy/mixed universal bytes have identical calls and child coverage in binary/install/service/observe. Code-off retains no marker/facts and service relations agree. A 7,094-byte cap closes only the first fat slice, with exactly that total use and partial named/content/root summaries.
- `SIGIL_SAFETY_REQUIRED=1 cargo test --locked -p sigil-cli --test safety`: **67 passed, 18 intentionally ignored negative harness controls**; no skipped required tracer. Thin arm64/x86 and fat static/install/service/observe read sequences match; all six safety contracts and unopened symlink-escape sentinels pass. Focused `--lib macho_unstable_recognition` and `--lib macho_changed_or_vanished_reads` pass: changed/replaced/vanished Mach-O reads discard slice/call witnesses, while a stable duplicate can restore content.
- Session/AI-BOM examples 23–28 and viewer copies cover same-name library separation, healthy/mixed fat, Unbound installation calls, unsupported authenticated chain (valid Partial), and the Task16 libc++/libSystem archive regression. Normalization and synthetic edits are described in `site/viewer/samples/README.md`. Saved `session verify --policy` succeeds for the five actual normalized observations; all seven structurally inconsistent Mach-O mutations are refused. Unknown archive hashes do not fall back.
- `cargo test --locked -p sigil-model --test schema every_example_validates_against_the_schema`, corresponding `aibom_schema` filter, `--test examples` (**2**), and `--test aibom` (**22**) pass. All **28** examples validate; prior golden files are unchanged. `cargo test --locked -p sigil-wasm` passes; final focused samples **3** pass.
- CI's native `render_sample` loop produced Markdown and HTML for all **20** viewer samples. `node ci/check-committed-wasm.mjs target/tmp/issue48/task17/expected` matches all **40** renders and refuses all **16** invalid samples with their specific expected diagnostics. `node --test ci/viewer-state.test.mjs`: **6 passed**. The archive sample displays `none found` without a borrowed-library violation; Unbound installation questions retain call-site evidence.
- Pinned `nightly-2026-01-20`, wasm-pack 0.15.0, Binaryen133: `ci/build-viewer-wasm.sh` ran twice with distinct empty Cargo targets and package outputs (`cargo-wasm-one/two`, `pkg-one/two`), sequentially. Every package file equals both builds and committed `site/viewer/pkg`. Actual wasm **1,358,575 bytes**, CI gzip **327,993 bytes**, **184,007 bytes** below 512,000. SHA-256 `21881a76f2d6dece6c951f70cfac394f67e5061b854a115a943e0792b68b39b2`.
- Scoped CLI/engine/WASM all-target clippy `-D warnings`, fmt and diff checks pass. Clippy exposed one stale test-only `CodeOutcome` import in `binary/macho.rs`; removed without behavior changes. No analyzer/model production behavior changed in this task.

Committed fixture SHA-256 values remain those in `code-macho/SHA256SUMS`; no fixture
bytes changed (universal `bdfaeeb80f0cdbe8aa17b54eb11fa8782016ffed530f9f636efdfc6d92594eb1`,
arm64 classic `154d9bf8aaf028e6d5bc682634343018516586bcf787714d0456ed3f40eecbc5`).
Only fixtures were measured, not a real deployed Ollama bundle. Docs and help now
state the exact Mach-O subset, conditional compact bounds, library/ABI limits and
old-reader limits. **Task10 mixed-x86 P2/user choice, M3-B/M3-C release gates and
original #48 predicate/guard acceptance remain unresolved.** No PR/push/external send.

## Task 18: acceptance evidence map (2026-11-04)

Audited base `dda7a14d6ef1c30758f3bf1c91052292ab57056b`. This is an evidence
inventory and focused compatibility supplement, **not acceptance of all §8 gates**.
Task10 still exceeds the unified reference-work contract for mixed marked x86
inputs and can repeat analysis through a newly scannable legacy x86 alias. Its
mixed-x86 budget/alias P2 remains open. Task19 final-revision checks and original
#48 Predicate/Guard acceptance remain open. Earlier passing results below apply
to their recorded task revisions; Task18 did not repeat their large experiments.

Test notation gives an exact runnable command: `E target::name` means
`cargo test --locked -p sigil-engine --test target name -- --exact`;
`M` substitutes `sigil-model`, `C` substitutes `sigil-cli`, and `W` substitutes
`sigil-wasm`. For `E-lib name`, use
`cargo test --locked -p sigil-engine --lib name` (substring module filter).
These references identify existing evidence, not commands rerun in Task18.

| Spec §8 requirement | Exact evidence and command reference | Status / limit |
|---|---|---|
| 1: clang/GCC -O0/-O2 ET_REL, PLT, real `-fno-plt`; intervals, call address, raw symbol, route, x0/x1/x2 | `E multiarch_code::real_aarch64_elf_calls_match_independent_oracle`; `E aarch64_elf::retained_oracle_rows_have_executable_bytes_and_independent_dump_evidence`; `E-lib code::image::aarch64::tests::every_clang_gcc_fixture_matches_independent_oracle_ranges_and_calls` | Eight positive C configurations, two expected source calls each; oracle `-` fields make no value claim. Stack-dependent O0 values remain unknown. Task1 build/oracle evidence and Task9/10 integration evidence; no targets executed. |
| 2: Mach-O arm64/x86 classic/chained, thin/fat/object and exact bounds | `E macho_code_calls::real_thin_stubs_join_exact_import_witnesses` (four thin configurations/eight calls); `object_branches_keep_unbound_identity_without_guessed_prototype` in the same target; `E macho_code_unwind::native_object_explicit_lengths_and_linked_dwarf_offsets_are_separate_proofs`; `x86_linked_dwarf_mode_uses_its_own_architecture_encoding` in that target | Actual linked call positives are dylibs; MH_OBJECT has exact file-offset identities but Unbound/unknown prototypes keep partial argument layouts. Executable container coverage exists in `E macho_facts::a_linked_universal_executable_is_read_in_full`; equivalent end-to-end executable **call** coverage is not established by these dylib tests. |
| 2: folded/missing/overlapping bounds, same-name libraries, authenticated/malformed chains | `E macho_code_calls::absent_or_folded_native_bounds_never_invent_functions`; `E macho_code_unwind::folded_native_regular_compressed_local_and_function_starts_never_supply_ends`; `malformed_indirect_overlapping_and_wrapping_fdes_never_create_bounds` in that target; `E macho_code_bind::malformed_chains_headers_starts_formats_ordinals_and_addends_are_transactional`; `E multiarch_policy::real_same_name_slots_do_not_inherit_another_dylibs_capability` | Negative outcomes stay gaps. Task13/14/15/16 reviewed evidence. No authenticated pointer support. |
| 3: healthy dual-architecture fat, supported+unsupported, actual per-slice `binary.code`, policy and artifact byte sum | `E macho_code_calls::named_universal_session_accepts_exact_witnesses_and_library_aware_policy`; `unsupported_fat_child_preserves_proved_sibling_and_shared_budget` in that target; `E multiarch_policy::fat_questions_use_each_slice_and_reject_missing_duplicate_or_complete_parent`; `C cli::macho_thin_fat_install_service_observe_and_shared_budget` | Task17 cap7094 retains one complete child and partial sibling/parents. This proves the fat artifact case, not Task10's unresolved mixed named-x86 work accounting. |
| 3: healthy arm64 + recorded unparsed x86 child / omitted invalid descriptor; named and install, saved roundtrip and reevaluation | `E macho_code_calls::real_healthy_fat_sibling_survives_unparsed_or_lost_descriptor` | Task18 extends the real two-call sibling case through both public session producers, partial parents, canonical roundtrip, validation and `policy::verify`; both mutations pass. |
| 3: deduplication, deterministic slice order, conflicting CPU/table | `E multiarch_code::stable_duplicates_share_code_and_children_in_binary_and_installation`; `M multiarch_coverage::shared_exhaustion_follows_slice_offsets_not_input_order`; `typed_fat_cpu_conflicts_cannot_claim_complete_inventory_or_code` in that target; `E macho_facts::a_fat_table_that_lists_one_architecture_twice_is_partial`; `a_slice_header_that_disagrees_with_its_table_entry_is_partial` in that target | Stable deduplication verified. The legacy newly-scannable alias case remains the Task10 blocker. |
| 4: truncation, offsets/overflow, overlapping windows/mappings, ULEB and bad fixups | `E macho_code_image::unhashable_overflow_overlap_cpu_and_slice_count_fail_closed`; `section_tables_conflicting_mappings_and_data_in_code_fail_closed` in that target; `E macho_code_unwind::representative_section_and_record_truncations_are_gaps`; `E macho_code_bind::malformed_classic_streams_never_keep_a_partial_named_map`; `malformed_chains_headers_starts_formats_ordinals_and_addends_are_transactional` in that target; `E-lib code::image::aarch64::tests::hostile_metadata_and_truncations_preserve_image_invariants` | Representative boundaries and hostile cases are tested; no claim that every metadata-byte boundary of every format was exhaustively truncated. The literal exhaustive part of §8.4 is unverified. |
| 4: signed displacement, unsupported instruction/write, transaction rollback | `E aarch64_decode::bl_pc_relative_edges`; `addresses_never_wrap_or_accept_unaligned_pcs` in that target; `E-lib code::aarch64::value::tests::rollback_is_per_function_including_actual_256_pass_limit`; `E multiarch_code::failed_reachable_instruction_rolls_back_its_whole_function`; `E macho_code_calls::two_pending_calls_are_rolled_back_after_reachable_unsupported_instruction`; `x86_conditional_stub_edges_discard_the_function_without_becoming_calls` in that target | Actual fixpoint failure/relocation/unsupported instructions discard staged function evidence and retain healthy functions. |
| 4: invented witness, forged summary, missing/duplicate entry, budgets, wrong register, inventory, ABI/hash | `M multiarch_code::exact_macho_witness_and_bounds_are_scoped`; `every_nested_register_belongs_to_its_slice`, `argument_prefix_is_honest`, `marker_requires_code_roots_and_exact_archived_knowledge`, `marked_macho_forged_capability_decisions_are_rejected` in that target; `M multiarch_coverage::rejects_missing_duplicate_wrong_scope_and_forged_budgets`; `inventory_and_unparsed_mutations_are_independent_code_errors`, `child_budgets_use_checked_sums_and_no_synthetic_slice_ids` in that target | Strict saved-session mutations rejected. `E multiarch_policy::mixed_evidence_mutations_are_rejected_but_coherent_existing_import_edits_are_not_authenticated` documents the coherent unauthenticated-fact limit. |
| 4: changed/vanished reads and hostile decoder corpus | `E-lib collect::named::tests::macho_changed_or_vanished_reads_discard_all_slice_facts`; `E-lib collect::install::tests::macho_unstable_recognition_is_separate_from_stable_evidence`; `E aarch64_decode::million_word_production_adapter_gate` plus the independent oracle commands below | Task17 stability controls and Task7 actual production adapter evidence. No repeated million-word or differential experiment in Task18. |
| 5: old/new canonical sessions, strict schema, saved CLI, AI-BOM, escaping, viewer | `M multiarch_code::legacy_json_is_byte_identical`; `review_legacy_install_formats_and_arches_keep_base_validation`, `new_shapes_are_strict_in_serde_and_schema` in that target; `M schema::every_example_validates_against_the_schema`; `W samples::every_sample_is_a_golden_example_and_renders`; `every_invalid_sample_gives_its_error`, `macho_samples_preserve_library_and_slice_uncertainty` in that target; `E multiarch_policy::unknown_library_names_keep_only_existing_uncertainty_and_reports_escape_sources`; `C cli::macho_library_policy_binary_installation_and_saved_verification` | Task17 native/Node actual-package parity: 20 valid samples × Markdown/HTML = 40 renders, 16 invalid samples rejected, state6. Pinned old-reader execution against the new marked examples is not recorded; rejection is documented, not claimed as a measured test. |
| 5: old x86 bytes, default/empty policy, code-off, order/duplicates, static/observe, saved verification | New `C cli::legacy_x86_order_duplicates_observe_and_saved_sessions_keep_the_code_contract`; ignored current-producer and fixed-model tests below; existing `C cli::eleven_inputs_are_summarized_in_argument_order`; `E code_session::without_code_there_is_no_binary_code` | New test covers 20 generated sessions, each CLI verified and rendered. Off omits marker, inventory, slice diagnostics, code facts/checks/budget and ABI knowledge. Exact Task0 bytes exist for default-policy static x86 binary/install only; Task0 did **not** freeze code-off, empty-policy, reordered/duplicate or observe outputs. These new variants prove current behavior, not historic byte equality. |
| 6: full safety/MSRV/stable, bans, fixture/viewer double rebuild | Task1 double builds/checksums; Task5 earlier full workspace; Task17 required safety67, two pinned viewer builds, scoped clippy; commands in those sections above | **Task19 pending on the final revision**: no new full workspace/MSRV/stable/bans/strace/corpus/fixture/viewer rebuild in Task18. Earlier results do not substitute for its final gate. |
| 7: original #48 Unknown1–7 and real-bundle measurement | Matrix below | PR-5b not implemented; #48 remains open. No real Apple Silicon/Ollama bundle survey; fixtures only. |

Pinned fixture evidence is unchanged: clang/LLVM/LLD **21.1.8**, GCC **15.3.0**,
GNU binutils **2.46**. Exact executable paths, full versions and SHA-256 are in
each fixture family's `COMPILERS`; sources/build commands are in `build.log`.
Independent evidence is LLVM objdump/readobj/dwarfdump/nm plus GNU objdump/readelf
for ELF; Mach-O additionally uses bind/lazy-bind/chained-fixup/indirect-symbol
dumps. The 11 ELF binaries have **36** oracle rows and 90 checksum entries; the
18 Mach-O binaries have **65** oracle rows, 13 binding rows and 116 checksum entries.
Oracle rows include deliberate unknown/negative cases; they are not all positive calls.
Task1's reviewed checker accepts ten originals and rejects seventeen actual binary
mutations. Task2's research unwind checker rejects fifteen malformed cases. These
are distinct evidence sets, not a fabricated aggregate count of producer tests.

Task7 actual production prefilter/adapter: seed `0x48c0ffee`, xorshift64 13/7/17;
**1,103,289 visits = 1,000,000 uniform + 100,000 structured + 3,289 boundaries**,
**179,358 eligible**, zero inconsistencies/panics/counted allocations in the
recorded panic-abort harness. Independent LLVM/GNU comparison: **178,917 distinct
eligible words**, zero semantic differences; all 731 thin arm64 fixture rows are
inventoried, with fat-to-thin identities verified. Explicit fixture exclusions:
`00000000`, `0000000f`, `d503233f`, `18000050`. Reproduction commands (already run
in Task7; `$R` is its recorded disk evidence directory):

```sh
SIGIL_A64_ORACLE="$R/words.txt" cargo +1.93.0 test -p sigil-engine --test aarch64_decode --locked export_independent_oracle_input -- --ignored
python3 crates/sigil-engine/tests/support/aarch64_oracle.py "$R/words.txt" "$R/oracle"
SIGIL_A64_ORACLE="$R/oracle/llvm.jsonl" cargo +1.93.0 test -p sigil-engine --test aarch64_decode --locked verify_independent_oracle -- --ignored --nocapture
SIGIL_A64_ORACLE="$R/oracle/gnu.jsonl" cargo +1.99.0 test -p sigil-engine --test aarch64_decode --locked verify_independent_oracle -- --ignored --nocapture
```

Schema/reader inventory: **21 pre-M3 schema session examples plus five frozen
baseline/legacy cases** retain their canonical bytes; the pre-M3 unsupported
Mach-O capture and pre-#127 legacy capture are included. New examples are paired session/AI-BOM
`22-aarch64-code`, `23-macho-same-name`, `24-macho-fat`, `25-macho-mixed`,
`26-macho-install`, `27-macho-unsupported-chain`, `28-macho-archived-library`
under `schemas/examples/{session-v1,aibom-v2}` and matching viewer samples.
Invalid viewer fixtures exercise missing marker, forged library/slice/parent,
wrong register, oversized budget and unknown capability archive in addition to
the earlier multiarch inventory/ABI mutations. No old golden was rewritten.

Coverage remains open for instructions outside the audited whitelist (including
literal loads, flag-setting/general shifted/extended arithmetic, SIMD/SVE/SME,
PAC/BTI/additional hints and unsupported memory modes), unresolved BLR/BR and
unproved veneer/GOT/relocation targets; stack/aggregate/unknown prototypes and
variadic arguments beyond an archived fixed prefix; unsupported/unapplied or
ambiguous relocations/mappings; missing/malformed/overlapping FDEs, relocated
object FDE pairs, compact personality/LSDA and native linked folded compact-only
bounds without independent exact extents; authenticated/other chained pointer
formats, multi-start pages, threaded/weak-bind streams, compressed symbols,
nonzero effective addends and bad/missing ordinals/chains. Unknown writes never
establish preserved constants. Mach-O runtime memory constant/string recovery is
conservative. Unsupported architectures/formats and each work/read/detail-gap
limit retain explicit unsupported/partial coverage; no missing proof closes a search.

| Original §4.6.5 condition | Code-evidence proof | Original #48 acceptance |
|---|---|---|
| 1: no FDE / decode failure | `E multiarch_code::code_failures_preserve_container_and_healthy_functions`; `failed_reachable_instruction_rolls_back_its_whole_function`; Mach-O missing/folded/FDE negatives above | Gap proved; actual Predicate `Unknown` is not implemented. Open. |
| 2: unidentified indirect call in queried iteration | `E aarch64_decode::branch_register_and_conditional_forms`; `E-lib code::image::aarch64::tests::linked_got_provenance_rejects_wrong_register_slot_and_clobber` | No invented import; queried-iteration Predicate `Unknown` unimplemented. Open. |
| 3: unresolved indirect jump in iteration | `E-lib code::aarch64::tests::unresolved_jump_and_outside_branch_fail_transaction` | CFG gap/rollback proved; Predicate `Unknown` unimplemented. Open. |
| 4: unnamed conditions yield Depends | No shipped Predicate/Guard algorithm | PR-5b required. Open. |
| 5: same atom name bound to different values | No shipped Predicate/Guard algorithm | PR-5b required. Open. |
| 6: atom-defining call on a cycle | No shipped Predicate/Guard algorithm | PR-5b required. Open. |
| 7: atom enumeration/state budget | No shipped Predicate/Guard algorithm | PR-5b required. Open. |

Task18 actual runs used Rust1.93.0, `CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0`,
serial builds and `TMPDIR=$PWD/target/tmp/issue48/task18/tmp`; no `/tmp` artifacts.
Logs are `target/tmp/issue48/task18/`.

| Actual command | Result |
|---|---|
| `cargo test --locked -p sigil-cli --test cli legacy_x86_order_duplicates_observe_and_saved_sessions_keep_the_code_contract -- --exact --nocapture` | 1 passed; 20 generation/verify/render cases across default/empty policy and code on/off. |
| `cargo test --locked -p sigil-engine --test code_session frozen_task0_x86_producers_are_byte_identical -- --ignored --exact --nocapture` | 1 passed; two actual current-producer canonical sessions equal frozen default-policy Task0 binary/install bytes. Original filesystem/path prerequisite is explicit. |
| `cargo test --locked -p sigil-model --test multiarch_code frozen_task0_canonical_bytes_and_reports_are_identical -- --ignored --exact --nocapture` | 1 passed; 26 canonical sessions, four Markdown/AI-BOM pairs and missing-code legacy report equal. |
| `cargo test --locked -p sigil-engine --test macho_code_calls real_healthy_fat_sibling_survives_unparsed_or_lost_descriptor -- --exact --nocapture` | 1 passed; both malformed sibling classes retain real healthy calls through named/install roundtrip and policy reevaluation. |
| `cargo clippy --locked -p sigil-cli --test cli -p sigil-engine --test code_session --test macho_code_calls -- -D warnings`; `cargo fmt --all -- --check`; `git diff --check` | All exit 0. |

Task18 does not establish historic-byte coverage for the variants absent from
Task0, exhaustive metadata truncation, executable Mach-O call parity, a measured
old strict reader on marked examples, Task10's mixed-x86 bound/alias fix, Task19's
final gate, or PR-5b. No M3-B/M3-C release, merge, or issue closure is claimed.
