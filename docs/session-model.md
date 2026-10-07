# Session model (`sigil-model`)

`crates/sigil-model` defines the **analysis session**: everything SIGIL v2 records about one
run, and the source of truth that exports (AI-BOM v2, Markdown) are derived from.

- **What it is:**
  - a pure data crate: no I/O, no parsing, no policy or profile evaluation, no analysis;
  - `wasm32`-safe;
  - its JSON contract is `schemas/session-v1.schema.json`.
- **Status:** the CLI does not emit sessions yet (PR-3b).

The model exists to make wrong security statements hard to write by accident. "I saw something
that looks like this feature" must not quietly become "this dangerous behavior is confirmed".

## Distinctions that must not be collapsed

| Not the same | Represented by | Why |
|---|---|---|
| `Artifact` ≠ `FileInstance` | `Artifact` is contents (`sha256:…`). `FileInstance` is a placement at a path under a scan root | One artifact can be at many paths. One path can hold different contents in another session |
| Present ≠ Candidate ≠ Mapped ≠ Selected ≠ Used | `LoadFacts.present`, `.candidate`, `.mapped`, `.selectable`, `.used_for_inference`: independent facts, not a state machine | There is no `loaded` flag. An empty `mapped` never means "not loaded", and a mapping never says why it happened |
| Declared ≠ Candidate ≠ Bound | `Relation::Declares`, `Relation::Candidate` / `SymbolCandidate`, `BindingPremise` | A name or a file that *could* satisfy it is not what a process *uses* |
| `FeatureHint` ≠ call | `FeatureHint` (B) vs `CallSite` (C) | An import existing is not the import being called |
| Call ≠ behavior | `CallSite` (C) vs `RuleSupport` / `Support` (D) | Behavior is a profile rule applied with a stated support |
| Behavior ≠ finding | `Support` vs `Finding` with its `Condition`s (E) | A finding also needs environment facts (access, values, binding) |
| Finding ≠ policy | `Finding.default_severity` vs `Finding.decision` | Policy never edits the technical result. An ignored finding stays, with its reason |
| Verdict ≠ completeness | `Outcome.verdict` and `Outcome.completeness`, always together | `FAIL` with gaps is still `FAIL`. `PASS` + `INCOMPLETE` is not a clean pass |
| Unknown ≠ pass | `Tri::Unknown`, `CondState::Unknown`, `ObligationState::Unknown`, `TriValue::Unknown`, each with a reason | Unknown is a result. It is never `false`, an empty list, or a missing field |
| Unsupported ≠ not present | `CoverageState::Unsupported` vs `CoverageState::NotPresent { basis }` | Not analyzed is a gap. Absence must state its scope and basis |
| Configured ≠ predicted ≠ observed | `ValueOrigin::Configured` / `PredictedLaunch` / `ObservedProcess` / `ChildDerived` | A unit file's value is not the process's effective value |
| `ReferenceVerified` ≠ `TargetVerified` ≠ `FeatureMatch` | `Support` | Kinds of support, **not ranks**: there is no confidence score and no ordering |

## Flow

```text
facts / evidence
  artifacts · instances · processes · values · code facts · access · coverage
        │
        ▼
claims
  identity (A, ComponentClaim / ReleaseClaim) · hints (B) · code facts (C)
  rule support and load facts (D, each with Basis / Support and unresolved premises)
        │
        ▼
conditions of a detection rule: Met / NotMet / Unknown, each with evidence of its kind
        │
        ├─▶ Finding       every condition Met, no unresolved premise ─▶ PolicyDecision ──────┐
        └─▶ OpenQuestion  some Unknown, none NotMet ─▶ OpenQuestionDecision ─┬─ Warn/Fail ───┤
                                                                             │               ▼
                                                                             │        Outcome.verdict
                                                                             └─ CountAsGap ──┐
request.required_checks ─▶ coverage of each check ──────────────────────────────────────────┤
                                                                                             ▼
                                                                                  Outcome.completeness
```

## When evidence is enough for a condition

A `Met` or `NotMet` condition must carry evidence that meets the rule of its kind (plan §4.4.9).
`Session::validate` rejects anything else.

| Kind | Sufficient | Not sufficient |
|---|---|---|
| `Behavior(Support)` | `ReferenceVerified`, `TargetVerified`, `Assumed` accepted by policy | `FeatureMatch`, `Assumed` not accepted |
| `Access(AccessConclusion)` | `TrustedOnly`, `UntrustedHolder` | `Undetermined` |
| `Value(ValueOrigin)` | `ObservedProcess`, `PredictedLaunch`, `ChildDerived` | `Configured` |
| `Binding(BindingState)` | `Verified`, `Assumed` accepted by policy (a binding is refuted only by `Mismatch`) | `Unknown`, `Mismatch` |
| `Identity(IdentityStatus)` | `ReferenceMatched` | everything else |
| `Observed { facts }` | at least one fact, each an artifact, instance, configuration, or process | none, or a code, value, or access reference (those have their own kinds) |

Insufficient evidence makes the condition `Unknown { reason: InsufficientEvidence, evidence }`.
The rule then yields an open question at most.

## What `Session::validate` checks

- **References resolve:**
  - every ID a fact, claim, evidence pointer, subject, or outcome names exists;
  - IDs are unique in their domain;
  - slice IDs agree with their artifact.
- **Claims do not exceed their evidence:**
  - the sufficiency table above;
  - a finding has every condition `Met` and evidence;
  - an open question has something open and nothing refuted;
  - an identity status is not stronger than its assertions;
  - `TargetVerified` names obligations that passed in a `ProfileMatch` for that profile and slice, with locations;
  - `ReferenceVerified` is about the reference artifact itself.
- **Premises are carried:**
  - a verified support never has unresolved premises;
  - a `FeatureMatch` lists every unresolved premise;
  - `would_evaluate` is never stronger than `candidate`.
- **The recorded outcome is consistent:**
  - the verdict is the maximum recorded action;
  - the counts match the findings' decisions;
  - `Incomplete` names exactly the required checks that are not closed and the open questions treated as gaps;
  - `Complete` requires every required check to have coverage, all of it closing.

It does **not** evaluate policy, derive required checks, or decide whether a `NotPresent` basis
is acceptable for a particular check. Those belong to the engine (PR-3a and later).

## Example: FAIL and INCOMPLETE

This excerpt of `schemas/examples/session-v1/04-fail-incomplete.json` is a specification example,
not a SIGIL measurement. It shows four things together:
- a `TargetVerified` rule;
- a confirmed finding whose four conditions are each `Met` with evidence of their own kind;
- an unrelated required check skipped in static mode;
- the outcome: `Fail` and `Incomplete`.

The full session validates. `crates/sigil-model/tests/docs.rs` checks this excerpt against
`$defs/SessionExcerpt` and against that file.

```json
{
  "rule_support": [
    {
      "profile": "ggml.backend-loader@2",
      "rule": "evaluate",
      "slice": "sha256:1111111111111111111111111111111111111111111111111111111111111111#x86_64@0",
      "support": {
        "TargetVerified": {"obligations": ["evaluate.score_call", "evaluate.close_reached"]}
      }
    }
  ],
  "findings": [
    {
      "id": "finding:loader.candidate_or_library_replaceable@lib/ollama/libggml.so.0.13.1",
      "rule": "loader.candidate_or_library_replaceable",
      "kind": "Loader",
      "subject": {"Instance": "inst:lib/ollama/libggml.so.0.13.1"},
      "summary": "Anyone can replace libggml.so.0.13.1, which the per-model llama-server binds to (specification example)",
      "conditions": [
        {
          "id": "rule_supported:evaluate",
          "state": {
            "Met": {
              "evidence": {
                "Behavior": {
                  "TargetVerified": {
                    "obligations": ["evaluate.score_call", "evaluate.close_reached"]
                  }
                }
              }
            }
          },
          "unresolved": []
        },
        {
          "id": "untrusted_write:library",
          "state": {
            "Met": {
              "evidence": {
                "Access": {
                  "UntrustedHolder": {
                    "who": "Anyone",
                    "via": "/usr/local/lib/ollama",
                    "how": "ModeOther"
                  }
                }
              }
            }
          },
          "unresolved": []
        },
        {
          "id": "runtime_principal_known",
          "state": {
            "Met": {
              "evidence": {
                "Value": {
                  "PredictedLaunch": {
                    "rules": ["systemd.User", "topology.user_inherited"],
                    "from": ["val:ollama serve/user/configured"]
                  }
                }
              }
            }
          },
          "unresolved": []
        },
        {
          "id": "binding:llama-server (per model)",
          "state": {
            "Met": {
              "evidence": {
                "Binding": {"Verified": {"scope": ["inst:lib/ollama/libggml.so.0.13.1"]}}
              }
            }
          },
          "unresolved": []
        }
      ],
      "evidence": [
        {"Instance": {"instance": "inst:lib/ollama/libggml.so.0.13.1"}},
        {"Access": {"access": "access:lib/ollama"}},
        {"Value": {"value": "val:llama-server (per model)/user/predicted"}},
        {
          "Code": {
            "slice": "sha256:1111111111111111111111111111111111111111111111111111111111111111#x86_64@0",
            "loc": {"CallSite": "cs:0xe26d"}
          }
        }
      ],
      "limits": ["ACLs were evaluated only where readable"],
      "default_severity": "Fail",
      "decision": {
        "action": "Fail",
        "source": "default:loader.candidate_or_library_replaceable",
        "reason": null,
        "expires": null
      }
    }
  ],
  "coverage": [
    {
      "check": "exposure.binds",
      "scope": "Audit",
      "state": {"Skipped": {"by": "ModeDisabled"}},
      "budget": null
    }
  ],
  "outcome": {
    "verdict": "Fail",
    "completeness": {"Incomplete": {"missing_required": ["exposure.binds"], "gaps": []}},
    "confirmed_failures": 1,
    "confirmed_warnings": 0,
    "policy_time": "2026-10-07T07:00:00Z"
  }
}
```

## Type map

| Concept | Rust type | Purpose |
|---|---|---|
| Session root | `Session`, `SchemaVersion`, `ToolInfo`, `KnowledgeRef`, `RunRequest`, `ObservationMeta` | One run. Knowledge hashes, the request (deterministic), and observation metadata (not analysis) |
| Content and placement | `Artifact`, `Slice`, `FileInstance`, `InstanceContent`, `StatInfo`, `Stability` | What was read and where it was found, with change detection |
| Process observation | `ProcessObs`, `ProcessRef`, `MappingObs` | What was seen in a process at an instant |
| Evidence | `EvidenceRef`, `Loc`, `ConfigRef`, `Basis` | Typed pointers into the session. How each fact was obtained |
| A: identity | `ComponentClaim`, `IdentityAssertion`, `IdentityStatus`, `VersionAssertion`, `ReleaseClaim` | Every identity source kept. Releases are sets |
| B: presence | `FeatureHint`, `Signal` | A feature signal exists |
| C: code | `CodeFacts`, `Function`, `CallSite`, `ArgValue`, `PredicateCheck`, `CloseCheck`, `GuardRegion`, `ParamMapping` | Reconstructed calls, values, and checks of one slice |
| Relations | `Relation` (`Declares`, `Candidate`, `SymbolCandidate`, `ProfileMatch`, `SearchPath`, `Spawns`), `ObligationResult`, `BindingPremise` | Dependencies, profile obligations, search paths, topology, binding |
| D: behavior | `RuleSupport`, `Support`, `LoadFacts`, `Tri`, `ProcessValue`, `ValueOrigin` | Per-rule support and per-file facts, with premises and value provenance |
| Access | `WriteAccess`, `NodeAccess`, `CapabilityAccess`, `AccessConclusion` | Who can write where, from observed metadata |
| Coverage | `Coverage`, `CoverageState` | What was checked and how far |
| E: findings | `Condition`, `CondState`, `CondEvidence`, `Finding`, `OpenQuestion`, `PolicyViolation` | Technical conclusions, open questions, and organizational violations, kept in separate lists |
| Policy and outcome | `PolicyDecision`, `OpenQuestionDecision`, `Outcome`, `Verdict`, `Completeness` | The policy's treatment, and the two independent results |
| Text and IDs | `UntrustedText`, `ArtifactId`, `InstanceId`, `CheckId`, `RuleId`, `ProfileRef`, … | Escape-only display of input text. One newtype per identity domain |

## Determinism

- Serializing a session value is deterministic: there are no hash maps and no floats.
- `Session::canonicalize` sorts the lists whose order carries no meaning, so discovery order does not change the bytes.
- Lists whose order is evidence are never sorted:
  - call arguments;
  - obligation locations;
  - conditions;
  - predicate atoms;
  - guard branches;
  - link chains and ancestor chains;
  - unresolved premises.
- Timestamps are kept. `ObservationMeta` is recorded but is not part of analysis, and `Outcome.policy_time` is an input that re-analysis reuses.

## Not in the model yet

| Item | Arrives in |
|---|---|
| Model-store and exposure facts | PR-3a, with their collectors |
| AI-BOM v2 and Markdown renderers | PR-3b, with the CLI and viewer that consume them |
| Patch assertions | M2 |
| Active-mode traces | M4 |
