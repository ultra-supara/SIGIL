# Session examples (`sigil-session/1`)

**Specification examples, not SIGIL measurements.** Nothing here was observed on a real system.
Every file is labeled `tool.version: "0.0.0-example"` and uses synthetic hashes. The exception is
`13-loader-slice-spec-example.json`, which reuses the values of the plan's §5.8 example (the
official Ollama v0.30.6 `libggml` hash and addresses found during PR-0 research) to show the
intended shape.

Each file is generated from a builder in `crates/sigil-model/tests/common/mod.rs` and is checked
by `crates/sigil-model/tests/examples.rs`. Each must:
- equal the builder's output;
- validate against `../../session-v1.schema.json`;
- pass `Session::validate`.

After an intended model change, regenerate them with
`SIGIL_BLESS=1 cargo test -p sigil-model --test examples`.

| File | Shows |
|---|---|
| `01-complete-pass` | Nothing found, every required check closed: PASS + COMPLETE |
| `02-complete-fail` | A confirmed finding (every condition `Met`): FAIL + COMPLETE |
| `03-incomplete-pass` | No violation, but a required check is only `Partial`: PASS + INCOMPLETE |
| `04-fail-incomplete` | A confirmed FAIL resting on `TargetVerified` behavior, plus an unrelated check skipped because the mode is disabled: FAIL + INCOMPLETE |
| `05-unsupported-check` | A requested check on an unsupported architecture is a gap, not a pass |
| `06-budget-exceeded` | A budget hit: a truncated analysis, not "nothing found" |
| `07-open-question` | Conditions met plus unknown ones: an open question counted as a gap, no finding |
| `08-profile-mismatch` | An obligation fails: `ProfileMismatch`, a gap |
| `09-feature-match-only` | A `FeatureMatch` candidate: recorded, and only an open question at most |
| `10-target-verified` | Every obligation `Pass` in the target's code, with the C-level code facts |
| `11-reference-verified` | A hash equal to a ground-truth-verified reference |
| `12-conflicting-identity` | A file name and an embedded value disagree on the version; both are kept, and the per-file hash still matches |
| `13-loader-slice-spec-example` | The plan's §5.8 loader slice, corrected to the PR-2 types |
