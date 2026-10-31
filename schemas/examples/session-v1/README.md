# Session examples (`sigil-session/1`)

**Specification examples, not SIGIL measurements.** Nothing here was observed on a real system.
Every file is labeled `tool.version: "0.0.0-example"` and uses synthetic hashes, with these
exceptions. `13-loader-slice-spec-example.json` reuses the values of the plan's §5.8 example (the
official Ollama v0.30.6 `libggml` hash and addresses found during PR-0 research) to show the
intended shape. `16-binary-code.json` reuses the engine's results for its test fixture
`suspicious_kernel-gcc-O2.o` (its hash, facts, hint, code facts, and bytes read); its path and
stat are synthetic, and `18-capability-policy.json` adds a synthetic import to it. `15`, `16`,
and `18` record the real SHA-256 of `crates/sigil-engine/signatures/capabilities.toml`, the
capability table their hints were made with (#51).

Each file is generated from a builder in `crates/sigil-model/tests/common/mod.rs` and is checked
by `crates/sigil-model/tests/examples.rs`. Each must:
- equal the builder's output;
- validate against `../../session-v1.schema.json`;
- pass `Session::validate`.

After an intended model change, regenerate them with
`SIGIL_BLESS=1 cargo test -p sigil-model --test examples`, then their AI-BOMs with
`SIGIL_BLESS=1 cargo test -p sigil-model --test aibom`. The viewer's sample
`site/viewer/samples/session-16-binary-code.json` is a copy of `16-binary-code.json`.

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
| `12-conflicting-identity` | libggml-base's file name says 0.13.1 and its `ggml_version()` returns 0.12.0: under the 0.x rule the majors disagree; both are kept, and the per-file hash still matches |
| `13-loader-slice-spec-example` | The plan's §5.8 loader slice, corrected to the PR-2 types |
| `14-store-and-runtime` | A model store and a running runtime, in observe mode with the API probe: one model (config, weights, MIT license), `ollama serve` listening on loopback, and the probe's answer with a version, one `runtime_api.version` entry: PASS + COMPLETE |
| `15-binary-inspect` | `sigil binary inspect` of two files: a shared object with complete container facts, its `dlopen` and `getenv` imports as hints, the `ggml-base` claim its file name and SONAME give (`NameOnly`, version `0` from the SONAME), and a complete signature scan that found no signature; and a text file, `Unsupported` in both checks. One `binary.container` and one `binary.identity` entry each: PASS + INCOMPLETE |
| `16-binary-code` | A binary inspection with code analysis (`request.code`) of one relocatable object: its `connect` import as a hint, the one direct call of `connect` with its function, `binary.code` `Complete` with its `binary_code_bytes` use, and `binary.identity` `Complete` (with the embedded database, no needle applies to it: a relocatable object has no dynamic symbols and no Go build info): PASS + COMPLETE |
| `17-open-release` | An install whose `libllama-common.so.0.0.1` matches no reference and reports `LLAMA_COMMIT` `6f3a9f3de`, as the official v0.30.5, v0.30.6, and v0.30.7 files do: an open release claim, "consistent with" those three and resting on that commit, and `artifacts.release` `Partial`: PASS + INCOMPLETE |
| `18-capability-policy` | Example 16's object with a second import, `execve`, that its code does not call directly (synthetic: the fixture imports only `connect`), evaluated under a policy that denies `posix.network` and `posix.process_spawn` (#51): the call of `connect` is a policy violation citing its call site, and `execve` an open question counted as a gap, since code analysis does not follow a call that is not direct: FAIL + INCOMPLETE |
| `19-service-unit` | `--service-unit /etc/systemd/system/ollama.service` (PR-4d-1): the unit's `ExecStart=` at line 6 names `/usr/local/bin/ollama`, so `/usr/local` is inspected as with `--install-dir`. The unit is the `service-unit` root's one instance, discovered by `Argument`; `bin/ollama` is discovered by the walk and by the unit (`ServiceUnit`, `ExecStart`, line 6). Discovery is complete: PASS + COMPLETE |
