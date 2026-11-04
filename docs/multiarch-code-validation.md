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
