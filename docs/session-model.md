# Session model (`sigil-model`)

`crates/sigil-model` defines the **analysis session**: everything SIGIL v2 records about one
run, and the source of truth that exports (AI-BOM v2, Markdown) are derived from.

- **What it is:**
  - a pure data crate: no I/O, no parsing, no policy or profile evaluation, no analysis;
  - `wasm32`-safe;
  - its JSON contract is `schemas/session-v1.schema.json`.
- **Status:** `sigil inspect ollama` emits sessions. `sigil session render` renders a saved one as
  Markdown (`sigil_model::render::markdown`), and `sigil explain` explains it.

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
| Condition ≠ a copy of a conclusion | `CondEvidence` names the record that decides it: a `RuleSupportRef`, an access record and capability, a value and the state needed, … | A condition cannot claim more than its record, and a changed record changes what the condition may claim |
| A model's facts ≠ its state | `Model` records each layer's digest as written and the blob instance found for it. Missing, malformed, unread, and mismatched are derived from those facts and the instance's content | A stored status could disagree with the facts it summarizes |
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
  rule support (D, the only place a Support is recorded)
  load facts (D, each with a Basis that may name a rule support, and unresolved premises)
        │
        ▼
conditions of a detection rule: Met / NotMet / Unknown, each naming the record that decides it
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

A condition never copies a conclusion. Its evidence **names a record** of the session, and
`Session::settles` reads what that record settles under the rule of its kind (plan §4.4.9). A
`Met` condition needs evidence that settles `Met`, and a `NotMet` condition evidence that settles
`NotMet`. `Session::validate` rejects anything else: evidence that settles neither way is
insufficient, and evidence that settles the other way contradicts the condition.

| Kind | Names | Settles `Met` | Settles `NotMet` | Settles neither |
|---|---|---|---|---|
| `Behavior` | a `rule_support` entry, by profile, rule, and slice | `ReferenceVerified`, `TargetVerified`, `Assumed` accepted by policy | never (a refuted rule is a `ProfileMismatch`) | `FeatureMatch`, `Assumed` not accepted |
| `Load` | one fact of a `loads` entry, by file and context | `Yes` | `No` | `Unknown`, or a basis that is not sufficient, or unresolved premises |
| `Access` | one capability of an `access` entry | `UntrustedHolder` | `TrustedOnly` | `Undetermined` |
| `Value` | a `values` entry, and the state needed (`Known` or `Absent`) | the needed state | the other state | `Unknown`, or a `Configured` origin (never an effective value) |
| `Binding` | a `bindings` entry, by role, call site, and analyzed definer | `Verified`, `Assumed` accepted by policy | `Mismatch` | `Unknown`, `Assumed` not accepted |
| `Identity` | a `components` entry, by slice and component | `ReferenceMatched` | never | any other status |
| `Observed` | facts: artifacts, instances, configuration, processes | either way, with at least one fact | either way | no fact, or a code, value, or access reference (those have their own kinds) |

A basis is sufficient when it is observed, derived, a rule support that settles `Met`, or an
assumption accepted by policy.

Insufficient evidence makes the condition `Unknown { reason: InsufficientEvidence, evidence }`.
The rule then yields an open question at most.

## What `Session::validate` checks

- **References resolve, and keys are unique:**
  - every ID or key a fact, claim, condition, evidence pointer, subject, or outcome names exists;
  - IDs are unique in their domain;
  - so are the keys records are found by: one result per obligation, profile, and slice; one
    support per rule and slice; one knowledge entry per kind, ID, and version; one claim per
    component and slice; one entry per binding premise, load-facts context, coverage scope, and
    write capability. A duplicate is rejected, never resolved by picking one entry;
  - slice IDs agree with their artifact.
- **A model's blobs are its digests' blobs:**
  - a layer's lookup is `NotLookedUp` exactly when its digest is malformed (a well-formed digest
    is `sha256:` + 64 lowercase hex digits);
  - a found blob is the instance at `blobs/sha256-<hex>` in the manifest's root;
  - a license is the text read from the license layer's blob.
- **A listener is an observed socket:**
  - its address is an IP address;
  - a listener owned by a process names a recorded process;
  - a listener counts as an `Observed` fact for a condition.
- **An active probe matches the request (ADR-002 active mode):**
  - each requested target is the canonical text of a specified IP address with a non-zero port, and is loopback unless `allow_remote` is set;
  - each requested target has exactly one probe, and each probe was requested;
  - a probe's ID is `probe:api/<address>:<port>`, with an IPv6 address in brackets;
  - a probe is not an `Observed` fact for a condition: no finding rests on it.
- **Records that repeat a result agree with it:**
  - a predicate check or an identity code check agrees with the obligation result it decides;
  - a `ProfileMismatch` is scoped to a slice and names obligations that failed there;
  - a mapping listed in load facts is one recorded for its process, of that file, and mappings
    are not listed as unobservable;
  - `ReferenceVerified.rule`, and the rule a search path or spawn relation names, agree with the
    rule support they rest on.
- **Claims do not exceed their evidence:**
  - every condition is decided as its record settles (the table above);
  - a finding has every condition `Met` and evidence;
  - an open question has something open and nothing refuted;
  - an identity status is not stronger than its assertions;
  - `TargetVerified`, and the `matched` obligations of a `FeatureMatch`, name obligations that
    passed in a `ProfileMatch` for that profile and slice, with locations;
  - `ReferenceVerified` is about the reference artifact itself.
- **Premises are carried:**
  - a fact or condition resting on a `FeatureMatch` carries its unverified premises as unresolved;
  - a condition resting on a load fact carries the fact's unresolved premises;
  - a `Met` or `NotMet` condition has no unresolved premise;
  - `would_evaluate` is never stronger than `candidate`.
- **The recorded outcome is consistent:**
  - the verdict is the maximum recorded action;
  - the counts match the findings' decisions;
  - `Incomplete` names exactly the required checks that are not closed and the open questions treated as gaps;
  - `Complete` requires every required check to have coverage, all of it closing.

It does **not**:
- evaluate policy, derive required checks, or decide whether a `NotPresent` basis is acceptable
  for a particular check;
- recompute an analysis from its inputs: an access conclusion from the node metadata, a
  predicted value from the values it was predicted from, a binding from the search order, or a
  release set from the identity claims of its files.

Those belong to the engine and its collectors (PR-3a and later). The engine computes decisions and
the outcome from a policy: see [`docs/policy.md`](policy.md).

## Example: FAIL and INCOMPLETE

This excerpt of `schemas/examples/session-v1/04-fail-incomplete.json` is a specification example,
not a SIGIL measurement. It shows four things together:
- a `TargetVerified` rule, with the value, binding, and access records next to it;
- a confirmed finding whose four conditions each name one of those records, which settles `Met`;
- an unrelated required check skipped in static mode;
- the outcome: `Fail` and `Incomplete`.

The full session validates. `crates/sigil-model/tests/docs.rs` checks this excerpt against
`$defs/SessionExcerpt` and against that file.

```json
{
  "values": [
    {
      "id": "val:llama-server (per model)/user/predicted",
      "process_role": "llama-server (per model)",
      "key": "User",
      "value": {"Known": "ollama"},
      "origin": {
        "PredictedLaunch": {
          "rules": ["systemd.User", "topology.user_inherited"],
          "from": ["val:ollama serve/user/configured"]
        }
      },
      "applies_to": []
    }
  ],
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
  "bindings": [
    {
      "process_role": "llama-server (per model)",
      "site": {
        "slice": "sha256:1111111111111111111111111111111111111111111111111111111111111111#x86_64@0",
        "call": "cs:0xe26d"
      },
      "symbol": "_Z15dl_load_libraryRKNSt10filesystem7__cxx114pathE",
      "analyzed_definer": "inst:lib/ollama/libggml.so.0.13.1",
      "state": {"Verified": {"scope": ["inst:lib/ollama/libggml.so.0.13.1"]}}
    }
  ],
  "access": [
    {
      "id": "access:lib/ollama",
      "target": "/usr/local/lib/ollama",
      "runtime": {"Value": {"value": "val:llama-server (per model)/user/predicted"}},
      "chain": [
        {
          "path": "/usr/local/lib/ollama",
          "uid": 0,
          "gid": 0,
          "mode": 16895,
          "sticky": false,
          "is_symlink": false,
          "acl": "Absent",
          "read_only_mount": "No"
        },
        {
          "path": "/usr/local/lib",
          "uid": 0,
          "gid": 0,
          "mode": 16877,
          "sticky": false,
          "is_symlink": false,
          "acl": "Absent",
          "read_only_mount": "No"
        },
        {
          "path": "/usr/local",
          "uid": 0,
          "gid": 0,
          "mode": 16877,
          "sticky": false,
          "is_symlink": false,
          "acl": "Absent",
          "read_only_mount": "No"
        },
        {
          "path": "/usr",
          "uid": 0,
          "gid": 0,
          "mode": 16877,
          "sticky": false,
          "is_symlink": false,
          "acl": "Absent",
          "read_only_mount": "No"
        },
        {
          "path": "/",
          "uid": 0,
          "gid": 0,
          "mode": 16877,
          "sticky": false,
          "is_symlink": false,
          "acl": "Absent",
          "read_only_mount": "No"
        }
      ],
      "capabilities": [
        {
          "capability": {
            "ReplaceEntry": {"dir": "/usr/local/lib/ollama", "entry": "libggml.so.0.13.1"}
          },
          "conclusion": {
            "UntrustedHolder": {"who": "Anyone", "via": "/usr/local/lib/ollama", "how": "ModeOther"}
          }
        }
      ]
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
                  "profile": "ggml.backend-loader@2",
                  "rule": "evaluate",
                  "slice": "sha256:1111111111111111111111111111111111111111111111111111111111111111#x86_64@0"
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
                  "access": "access:lib/ollama",
                  "capability": {
                    "ReplaceEntry": {"dir": "/usr/local/lib/ollama", "entry": "libggml.so.0.13.1"}
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
                "Value": {"value": "val:llama-server (per model)/user/predicted", "needs": "Known"}
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
                "Binding": {
                  "process_role": "llama-server (per model)",
                  "site": {
                    "slice": "sha256:1111111111111111111111111111111111111111111111111111111111111111#x86_64@0",
                    "call": "cs:0xe26d"
                  },
                  "definer": "inst:lib/ollama/libggml.so.0.13.1"
                }
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
| Model store | `Model`, `ModelProvenance`, `ModelLayer`, `LayerRole`, `BlobLookup`, `LicenseText` | One manifest, what its path says, its layers as written with how each blob lookup ended, and the license text read |
| Process observation | `ProcessObs`, `ProcessRef`, `MappingObs`, `NsInode` | What was seen in a process at an instant: its name, arguments, executable, network namespace, whether its fds could be listed, and its mappings |
| Listeners | `Listener`, `Protocol`, `ListenerOwner` | Listening sockets in SIGIL's network namespace, and who holds each one as far as the readable fd tables show. Never attributed by port |
| Active probes | `ActiveFeature`, `ApiProbe`, `ProbeResult`, `ProbePhase` | What `--active` asked for (`request.active`) and how each probe ended. A refused connection is an observation (`NotPresent` with basis `ConnectionRefused`); a timeout is not |
| Evidence | `EvidenceRef`, `Loc`, `ConfigRef`, `Basis`, `RuleSupportRef` | Typed pointers into the session. How each fact was obtained |
| A: identity | `ComponentClaim`, `IdentityAssertion`, `IdentityStatus`, `VersionAssertion`, `ReleaseClaim` | Every identity source kept. Releases are sets |
| B: presence | `FeatureHint`, `Signal` | A feature signal exists |
| C: code | `CodeFacts`, `Function`, `CallSite`, `ArgValue`, `PredicateCheck`, `CloseCheck`, `GuardRegion`, `ParamMapping` | Reconstructed calls, values, and checks of one slice |
| Relations | `Relation` (`Declares`, `Candidate`, `SymbolCandidate`, `ProfileMatch`, `SearchPath`, `Spawns`), `ObligationResult`, `BindingPremise` | Dependencies, profile obligations, search paths, topology, binding |
| D: behavior | `RuleSupport`, `Support`, `LoadFacts`, `LoadFact`, `Tri`, `ProcessValue`, `ValueOrigin` | Per-rule support (recorded once) and per-file facts, with premises and value provenance |
| Access | `WriteAccess`, `NodeAccess`, `CapabilityAccess`, `AccessConclusion` | Who can write where, from observed metadata |
| Coverage | `Coverage`, `CoverageState` | What was checked and how far |
| E: findings | `Condition`, `CondState`, `CondEvidence`, `ValueNeed`, `Settles`, `Finding`, `OpenQuestion`, `PolicyViolation` | Conditions that name their records; technical conclusions, open questions, and organizational violations, kept in separate lists |
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
  - unresolved premises;
  - a model's layers (manifest order).
- Timestamps are kept. `ObservationMeta` is recorded but is not part of analysis, and `Outcome.policy_time` is an input that re-analysis reuses.

## Fields added to `sigil-session/1`

A field added after sessions without it were written is optional on read, so those sessions still load. A missing one reads as empty. SIGIL always writes it, so a session it writes has every field.

| Field | Added in | Missing reads as |
|---|---|---|
| `request.active` | PR-3b-2 | `[]` (nothing active requested) |
| `probes` | PR-3b-2 | `[]` (no probe) |

The schema leaves these fields out of `required`. Every other field is required by both the schema and serde.

## Not in the model yet

| Item | Arrives in |
|---|---|
| AI-BOM v2 renderer | PR-3b-3, with the viewer that consumes it |
| Patch assertions | M2 |
| Active-mode traces | M4 |
