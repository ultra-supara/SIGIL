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
  - `runtime_api.version` coverage is about one probe: it is scoped to a probe (never the audit, a root, or anything else), and every probe has it, so it cannot be moved or dropped to escape the next rule;
  - a probe's `runtime_api.version` coverage closes the check only as its outcome supports: `Complete` needs a 200 answer with a version, `NotPresent` a refused connection on the basis `ConnectionRefused` that cites the probe, and a requested probe is never `OutOfScope` (a timed-out probe therefore never closes it). A gap never contradicts an outcome;
  - the basis `ConnectionRefused` is used only for `runtime_api.version`, and cites probes, each refused;
  - a probe is not an `Observed` fact for a condition: no finding rests on it.
- **Reference rows are the placements' own facts (PR-4a,
  [`docs/runtime-artifacts.md`](runtime-artifacts.md)):**
  - V1: a row's reference set is a `ReferenceManifest` knowledge entry;
  - V2: a row names a placement exactly when it is not `Absent`, and that placement is under the
    `install` root at the row's member path;
  - V3–V5: a `File` row is a stable, read file whose artifact has the observed SHA-256; a `Symlink`
    row a stable link whose first target text is the observed one; a `Directory` row a directory;
  - V6: a `KindDiffers` row names the placement's own kind, and a member kind that differs from it;
  - V7: `NotCompared` exactly for a placement that is not stable, or a file that was not read;
  - V8: `Absent` only when `artifacts.discovery` is `Complete`, and never at a placement's path;
  - V9: one row per reference set, release, and member;
  - V10: a release claim by reference matches lists every placement, rests on a complete
    discovery, and its candidates are exactly the releases every placement matches, recomputed
    from the rows;
  - V11: `artifacts.release` is `Complete` exactly when there is such a claim, discovery is
    complete, and no candidate has an `Absent` row.

  The rows' expected values, and whether a release lists a member at all, come from the reference
  set, which a session does not hold. The engine's verifier checks them
  (`verify_reference_matches`).
- **Binary facts agree with the session (PR-4b-1 and PR-4b-2b,
  [`docs/runtime-artifacts.md`](runtime-artifacts.md#binaries)):**
  - B1: a record names a slice of the session, one record per slice;
  - B2: ELF and Mach-O facts are about an artifact of the matching format. A fat Mach-O slice's
    own header names its table entry's architecture, and no other slice of the table names it,
    unless the slice has the parser's gap for it;
  - B3: the slice's dependency `Declares` relations are unique, and exactly its distinct ELF
    NEEDED or Mach-O loaded-dylib names;
  - B4: imports are sorted, unique, and within `binary_imports`;
  - B5: a data value that is `Unknown` has its gap;
  - B6: a Go version is not empty;
  - B7: `artifacts.container` is `Complete` only with a complete discovery, facts for every ELF
    or Mach-O slice of the install, and no gap;
  - B8: `stripped` is unknown exactly when a `sections: ` gap says why;
  - S2 (PR-4c-2a): a session has at most one `artifacts.identity` entry. It is scoped to the
    install root, and is `Complete` only with a complete discovery and facts for every slice of
    the install's ELF and Mach-O files, none of them a Mach-O, and none a Go ELF without section
    headers or a linked ELF whose loader's dynamic symbols the parse did not read, unless it is an
    NVIDIA library; or `Partial` with its gaps; or the discovery's state
    when discovery did not finish. A session without an install may have it `Skipped` for
    `--install-dir`, scoped to the audit;
  - S3 (PR-4c-2a): a signature hint is of a slice with ELF facts: an `Export` hint at
    `Symbol(value)`, a `GoFunction` hint in `.gopclntab` of a slice with Go build info, a
    `String` hint in `.rodata`, `.rodata.*`, or `.lrodata`. No slice of an input whose
    `binary.identity` is `OutOfScope` has one: it was not scanned.

  Whether the gaps are right is the parser's contract: `validate` checks the stored results
  against each other, not against the file's bytes.
- **A binary inspection's inputs agree with their coverage (PR-4b-2a,
  [`docs/binary-inspect.md`](binary-inspect.md)):**
  - B9: every `binary.container` entry is scoped to the instance of a binary root, and each input
    has exactly one. Its state is the one the input implies (`expected_binary_container`):
    `Complete`; `Partial` with the record's gaps (`not parsed` without a record); `Unsupported` for
    anything but ELF or Mach-O; `Error` for a read that saw a change or a removal; or `BudgetExceeded`
    over `binary_bytes`. The state must match exactly, except that a `BudgetExceeded` needs only
    its budget and limit exact, with `used` at most the limit. Any other state, `NotPresent` and
    `OutOfScope` among them, is invalid. A missing entry is invalid too: `outcome()` closes a
    check when every entry present closes, so a dropped entry would otherwise close it;
  - S1 (PR-4c-2a): a `binary.identity` entry is scoped to the instance of an input of a binary
    inspection. In a session with a `binary_scan_bytes` budget (every session since PR-4c-2a),
    each input has exactly one; otherwise at most one (a session written before has none). It
    names no budget: the scan's limit is in its gap. Its state is one the input implies
    (`expected_binary_identity`): the `binary.container` state when the container was not read;
    `Unsupported` (`string scan: ELF only`) for a Mach-O; `Partial` (`not parsed`) for an ELF
    without facts; otherwise `Complete`, or `Partial` with scan gaps only (`string scan: …`,
    sorted and unique, the budget's naming the request's `binary_scan_bytes`). A Go ELF without
    section headers must list `string scan: no section headers`, and a slice whose section header
    table was read never does. A linked (not relocatable) ELF whose facts carry
    `symbols: no section header table`, `symbols: no readable section header table`, or
    `symbols: no SHT_DYNSYM` must list `string scan: a name not read`: its loader has dynamic
    symbols the parse has no `.dynsym` for, so the export needle could not look at its exports.
    A Go ELF whose section header table was read may list `string scan: no .gopclntab section`
    (the model sees no section names); no other ELF does.
    When a claim on the input's slice names `cuda-runtime`,
    `cuda/cublas`, or `cuda/cublasLt`, `OutOfScope` (ADR-010) is admitted too: the model has no
    name database, so it cannot tell a file the engine excludes by its file name from one whose
    SONAME alone is NVIDIA's, which the engine scans;
  - B10: a session with a binary root is a binary inspection: only binary roots, static, no
    active feature, no model filter, no process environment read, no model, and one instance per
    root, at the root's path, discovered by `Argument`. `Argument` appears on no other instance,
    and the root ID prefix `binary-` is reserved for `binary-<n>`.
- **Code facts agree with the request and the inputs (PR-5a, [below](#code-analysis-pr-5a)):**
  - C1: `request.code` is only for a binary inspection, with a `binary_code_bytes` budget. A
    binary inspection has code facts only with `request.code`;
  - C2: with `request.code`, each input has exactly one `binary.code` entry, scoped to its
    instance. Without it, there is none;
  - C3: each entry is in the state its input implies (`expected_binary_code`, listed below);
  - C4: a binary inspection's code facts are about slices whose input's `binary.code` is
    `Complete` or `Partial`;
  - C5: in every value, a `Load` reads 8, 16, 32, or 64 bits, a `Low` keeps 8, 16, or 32 bits of
    a value that is not a `Low`, and a `Set` has 2 to 4 members, none a `Set` or `Unknown`. The
    values are call arguments, `Indirect` call targets, predicate atoms, and guard comparisons,
    with the values nested in each;
  - C6: an `Import` hint is at `Symbol(value)`, and `value` is an import of its slice's ELF facts.

  C1 and C4 are about a binary inspection. Outside one, code facts are the M1 analyzer's (plan
  §4.6.5), which the golden install examples carry.
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
  - an identity status is the one its assertions support (PR-4c-1): `ReferenceMatched` needs a
    matched `KnownHash`; `Corroborated` a `CodeCheck` whose result is `Match`, and no matched
    `KnownHash`; `NameOnly` a `SelfName`, an `Embedded` value, or a `Required` assertion, and
    neither of those; `Unidentified` none of these; `Conflicting` two identity assertions or
    versions at least. `Signature` counts for none;
  - I1: every `KnownHash` is the reference row, with its reference, release, and member, of a
    placement of the claim's artifact, and `matched` is that row's result;
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
  predicted value from the values it was predicted from, a binding from the search order, a
  release set from the identity claims of its files, or a reference row's expected value from the
  reference set.

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
| Binary facts | `BinaryFacts`, `ContainerFacts`, `ElfFacts`, `ElfImport`, `DataSymbol`, `DataValue`, `GoBuildInfo`, `GoModule`, `GoSetting` | What a binary's own bytes say: interpreter, names, NEEDED in order, search paths, notes, symbol counts and imports, known embedded values, Go build info, and the gaps |
| Reference matches | `ReferenceMatch`, `MemberResult`, `MemberKind`, `EntryKind` | One placement of the install root, or one member absent from it, compared with one release of a reference set. A placement that was not read says why (`NotReadReason`, which gained `Directory` and `NotFollowed`, a symlink of the install, in PR-4a) |
| B: presence | `FeatureHint`, `Signal` | A feature signal exists. Today, one `Import` hint per capability import of a slice |
| C: code | `CodeFacts`, `Function`, `CallSite`, `ArgValue`, `PredicateCheck`, `CloseCheck`, `GuardRegion`, `ParamMapping` | Reconstructed calls, values, and checks of one slice. A binary inspection's code analysis records functions and call sites only |
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

## Binary inspections (PR-4b-2a and PR-4b-2b)

`sigil binary inspect` writes a session whose scan roots are its inputs:
- **Roots.** Each input is a root `binary-<n>`, numbered from 1 in the order of first appearance (a
  file named twice is one input). The root's path
  is the file, after the symlinks in the argument are resolved. The canonical order sorts roots
  as text (`binary-10` before `binary-2`), so reports sort binary roots by their number.
- **Instances.** Each root has one instance: ID `inst:binary-<n>/<file name>`, at the root's path,
  discovered by `Argument` (named on the command line).
- **Coverage.** Each input has one `binary.container` entry, scope `Instance`: its status
  (B9 above), and one `binary.identity` entry (S1 above). Under the default policy, the request's
  audit is `binary`. Without code analysis, its required checks are `binary.container` and
  `binary.identity`. With code analysis, each input also has one `binary.code` entry (below).
  `request.budgets` holds `binary_scan_bytes` (default 64 MiB).
- **Facts.** An ELF or Mach-O input's facts are `BinaryFacts` records and their `Declares`
  relations, as for an installation. A fat Mach-O has one record per valid architecture slice.
- **Signature hints** (PR-4c-2a). An ELF input's scan adds one `FeatureHint` per needle found
  (S3), as an installation's does: `signal` `Export` (`value` the matched export's name, `at`
  `Symbol(<name>)`), `GoFunction`, or `String` (`value` the needle, `at`
  `Section { name, offset }`). A hint says that the name is in the file, never that its code runs
  ([binary inspection](binary-inspect.md#signatures)).

## Code analysis (PR-5a)

A binary inspection can also analyze code. For each input, it records where the capability
imports are called directly. Code analysis is requested with `sigil binary inspect --code` (the
engine's `BinaryRequest`, with code budgets).

**The request.**
- `request.code` is `true`. Only a binary inspection may set it (C1).
- `request.budgets` gains `binary_code_bytes` (default 256 MiB). It is the only code budget
  recorded. The other limits are constants (below).
- Under the default policy, the audit gains `binary_code`, and the required checks gain
  `binary.code` ([`docs/policy.md`](policy.md)).

**`binary.code`.** Each input has exactly one entry, scope `Instance` (C2). Its state is the one
the input implies (C3, `expected_binary_code`):
- **the container's state, copied, with no budget**, when the input has no container to analyze:
  `BudgetExceeded` over `binary_bytes` (with the container's `used`), `Error` for a read that saw
  a change or a removal, or `Unsupported` with `not a supported ELF or Mach-O container`;
- **`Unsupported` with `code analysis: x86-64 ELF64 little-endian only` (`CODE_UNSUPPORTED`),
  with no budget**, for a container whose code is not analyzed: a Mach-O or fat file, an ELF of
  another machine, and an x32 or big-endian ELF. The model records no ELF class or byte order, so
  an x32 or big-endian ELF has the arch `x86_64`, and this state is admitted for it too;
- **`Complete` or `Partial`, with the budget `binary_code_bytes`**: its `used` (the bytes read for
  code) and its `limit` (the request's). `Partial { missing }` lists the gaps. A container with
  gaps of its own is still analyzed. An input whose slice was not parsed is `Partial` with
  `not parsed` and `used` 0.

`Complete` means that every reference to a capability import in the scanned code was confirmed as
a direct call, or turned out to be part of another instruction. A reference that is not confirmed
is a gap, never dropped.

- An analyzed input without a call site has no `code` entry. Without a gap, it is `Complete`.
- Absence is "no direct call site in the scanned code", never "not called". A call through a
  function pointer, a function linked statically into the file, and a raw system call are not
  found.
- One content named at two paths is two inputs of one artifact. It has one `CodeFacts`, for its
  slice, and two identical `binary.code` entries, one per input.

**Hints (B).** Every session with binary facts records one `FeatureHint` per slice and capability
import. This holds with or without code analysis, and for `inspect ollama --install-dir` too.
- `feature`: the capability's key (table below);
- `signal`: `Import`;
- `value`: the import's name. The match is exact, and the import's version is not part of it;
- `at`: `Symbol(<name>)`.

A hint says that the file imports the function. It never says that the function is called: that
is a call site (C). When `binary_imports` cut the import list short, the hints are as short as the
list. A Mach-O slice has no hints yet.

| Key | Imports |
|---|---|
| `posix.network` | `connect`, `getaddrinfo`, `send`, `sendto`, `recv`, `recvfrom`, `socket` |
| `posix.file_read` | `open`, `openat`, `fopen`, `read`, `pread` |
| `posix.file_write` | `write`, `pwrite`, `fwrite`, `creat`, `rename`, `unlink` |
| `posix.process_spawn` | `execve`, `fork`, `posix_spawn`, `system` |
| `posix.dynamic_loading` | `dlopen`, `dlsym` |
| `posix.environment_access` | `getenv`, `setenv`, `putenv` |
| `posix.anti_debug` | `ptrace` |

**Code facts (C).** An analyzed input with at least one call site has one `CodeFacts`, for its
slice. Code analysis records functions and call sites only. `predicate_checks`, `close_checks`,
`guard_regions`, and `param_mappings` stay empty.
- **Call sites.** A call site is either:
  - a direct call or tail jump of a capability import: `target` is `Import { symbol, via }`,
    where `via` is `Plt`, `PltSec`, `Got`, or `Reloc` (a relocation of a relocatable object);
  - a call whose return value a recorded value takes (`ReturnOf`), transitively.

  Its `id` is `cs:0x<addr>`, and `caller` is its function. A call of a capability import has as
  many arguments as the import reads (`connect` 3, `dlopen` 2, …), in SysV order. Any other
  recorded call has all six.
- **Functions.** One `Function` per function with a recorded call site. Its bounds are an FDE of
  `.eh_frame` (`bounds: EhFrameFde`), and its `id` is `fn:0x<entry>`. `names` are the defined
  function symbols at `entry`, sorted. Only code with an FDE is analyzed.
- **Addresses.** In a linked file, an address is a virtual address. In a relocatable object
  (`.o`), it is a file offset.

**Argument values.** Each argument is the register's value at the call, propagated forward over
the function's control flow:
- `ConstInt`, or `ConstStr` for an address that an instruction forms and that holds a
  NUL-terminated string of at most 4 KiB in read-only data. An unrelocated immediate is never a
  `ConstStr`. In a relocatable object, an immediate under an absolute relocation (`R_X86_64_32`,
  `32S`, or `64`) of a defined symbol is an address, and a `ConstStr` when it points at a string;
- `Param { index }`: the function's own argument;
- `ReturnOf { call }`: the return value of a recorded call;
- `Load { base, offset, width, site }`: the bits loaded from `[base+offset]`, zero-extended.
  `width` is in bits: 8, 16, 32, or 64. A sign-extending load (`movsx`, `movsxd`) is
  `Unknown(NotModeled)`;
- `Low { value, bits }`: only the low `bits` are the value's. `Low { bits: 32 }` is a 32-bit
  register copy: `mov edi, edi` on `Param(0)` gives `Low(Param(0), 32)`, never `Param(0)`. 8 and
  16 are partial writes. A `Low` of a `Low` keeps the smaller width;
- `Set { members }`: 2 to 4 values that disagree at a join;
- `Unknown { reason }`: `ClobberedByCall`, `MergedDisagreeing`, `FromMemory`, or `NotModeled`. A
  stack address (a `lea` from an unknown base) is `NotModeled`.

**Budgets and limits.**
- Every byte of code, `.eh_frame`, PLT sections, and string data is charged to
  `binary_code_bytes` before it is read. A read over it is refused, and the analysis stops with
  the gap `binary_code_bytes: <limit> exceeded`. So `binary.code` is `Partial`, not
  `BudgetExceeded`.
- Section headers, symbol and relocation tables, and names are read through the container's parse
  cache, under `binary_parse_bytes`. A refusal there during code analysis is the code gap
  `code: binary_parse_bytes exceeded`, except while the names are filled (`Function.names` and
  an internal callee's `export_name`): a name left out is not a gap. Either way,
  `binary.container` never changes.
- The other limits are constants, not recorded in the request. Legitimate files stay far below
  them.

Each aggregate limit below counts per artifact. Reaching one records its gap and stops the
analysis. What was confirmed is kept, and each reference not yet confirmed is a gap
(`not confirmed: a limit was reached`). The function being decoded when the decoded-instruction
limit is reached gets `not decoded: a limit was reached` instead, and the one being solved when
the value-step limit is reached gets `not solved: a limit was reached`. A limit reached while the
image is built stops the analysis before the search, so no reference has a gap then. That is the
GOT slots, the relocations, the FDEs, the references (by text relocations), or
`binary_code_bytes`.

| Limit | Default | Counts | Gap |
|---|---|---|---|
| references | 65,536 | candidates, relocation references, and text relocations in code, before confirmation | `code: references limit 65536 reached` |
| FDEs | 1,048,576 | FDEs read from `.eh_frame` | `code: FDE limit 1048576 reached` |
| GOT slots | 1,048,576 | `JUMP_SLOT` and `GLOB_DAT` slots collected | `code: GOT-slot limit 1048576 reached` |
| relocations | 1,048,576 | a relocatable object's relocations, on code and on `.eh_frame` | `code: relocation limit 1048576 reached` |
| decoded instructions | 4,000,000 | instructions of all functions together | `code: decoded-instruction limit 4000000 reached` |
| value steps | 134,217,728 (2^27) | register-value work of all functions together, in every pass of each function's fixpoint and in the pass that keeps its calls' values. An instruction's transfer is 1 step, plus the size of a set it copies through part of a register. At a join, each predecessor examined is 4, and each register joined costs both sizes, or 1 beside an unknown value. A compare that must walk two values (their parts separate allocations), at a join or in the check that a block's output settled, costs both sizes. A value's size is its members times one more than its levels of loads | `code: value-step limit 134217728 reached` |
| call sites | 65,536 | recorded call sites, the `ReturnOf` closure included | `code: call-site limit 65536 reached` |
| name bytes | 16 MiB | bytes of names copied into recorded call sites | `code: name-byte limit 16777216 reached` |

The other limits do not stop the analysis:
- **listed gaps**, 256 distinct ones: later gaps are counted, not listed. One entry
  `code: <n> more gaps not listed` is sorted in with the others, where `<n>` counts every gap
  past the cap, repeats included;
- **one read**, 64 MiB (`MAX_READ`): a larger read is refused before it is charged, with the gap
  `code: <what>: a read of <n> bytes over the 64 MiB read limit`;
- **one function**: a function whose FDE is over 16 MiB is not decoded (`code: <symbol>
  referenced at <p>: function at <entry>: <n> bytes`), and one that passes 200,000 decoded
  instructions fails (`… function at <entry>: more than 200000 instructions`). So does one whose
  register values have not settled after 256 passes over one of its blocks (`… function at
  <entry>: values did not settle`). Such a function records no call site, and its references are
  gaps.

**Order.** `Session::canonicalize` sorts `code`, and each entry's `functions` and `call_sites`, by
their JSON text. The order is deterministic, but it is not numeric address order: `fn:0x1000`
sorts before `fn:0x40`. Call arguments keep their register order.

**Example.** This excerpt of `schemas/examples/session-v1/16-binary-code.json` is a specification
example. Its facts are the engine's results for the test fixture `suspicious_kernel-gcc-O2.o`, a
relocatable object whose function `kernel` calls `connect(0, 0, 0)`. Its path and stat are
synthetic. It shows:
- a request with code analysis, and its three required checks;
- the hint: the file imports `connect`;
- the call site: `kernel` (`.text` at file offset 0x40) calls `connect` at 0x4d through a
  relocation, with three constant arguments;
- `binary.code` `Complete`, with the 78 bytes read for code.

`crates/sigil-model/tests/docs.rs` checks it as it checks the example above.

```json
{
  "request": {
    "mode": "Static",
    "roots": [{"id": "binary-1", "path": "/home/user/src/suspicious_kernel-gcc-O2.o"}],
    "audit": ["binary", "binary_code"],
    "required_checks": ["binary.code", "binary.container", "binary.identity"],
    "budgets": {
      "binary_bytes": 68719476736,
      "binary_code_bytes": 268435456,
      "binary_imports": 4096,
      "binary_parse_bytes": 67108864,
      "binary_scan_bytes": 67108864
    },
    "observe_env": false,
    "model_filter": null,
    "active": [],
    "code": true
  },
  "hints": [
    {
      "subject": "sha256:aa3b172e12f6a1e4a0661c2a286bb1eb86901d830bb6d26fa7b1630aef2e0f4a#x86_64@0",
      "feature": "posix.network",
      "signal": "Import",
      "value": "connect",
      "at": {"Symbol": "connect"}
    }
  ],
  "code": [
    {
      "slice": "sha256:aa3b172e12f6a1e4a0661c2a286bb1eb86901d830bb6d26fa7b1630aef2e0f4a#x86_64@0",
      "functions": [
        {"id": "fn:0x40", "entry": 64, "end": 86, "bounds": "EhFrameFde", "names": ["kernel"]}
      ],
      "call_sites": [
        {
          "id": "cs:0x4d",
          "caller": "fn:0x40",
          "addr": 77,
          "kind": "Call",
          "target": {"Import": {"symbol": "connect", "via": "Reloc"}},
          "args": [
            {"ConstInt": {"reg": "rdi", "value": 0}},
            {"ConstInt": {"reg": "rsi", "value": 0}},
            {"ConstInt": {"reg": "rdx", "value": 0}}
          ]
        }
      ],
      "predicate_checks": [],
      "close_checks": [],
      "guard_regions": [],
      "param_mappings": []
    }
  ],
  "coverage": [
    {
      "check": "binary.code",
      "scope": {"Instance": "inst:binary-1/suspicious_kernel-gcc-O2.o"},
      "state": "Complete",
      "budget": {"budget": "binary_code_bytes", "used": 78, "limit": 268435456}
    }
  ]
}
```

## Identification (PR-4c-1)

The engine fills `components` for each ELF slice of an installation or a binary inspection one of
whose names its database knows ([runtime artifacts](runtime-artifacts.md#components)). It reads
nothing for it: the claims come from the instances, the binary facts, and the reference rows. A
claim keeps every source as its own assertion: a `SelfName` per name (`Filename` for each
stable placement that holds the content and each link that leads to one, `Soname`), an
`Embedded` value per known `LLAMA_*` value and Go build info field (`go.version`, and `go.path`
or `go.main`), a `KnownHash` per reference row of a placement that holds the content, and
`Signature { NotChecked }`. Its versions are the dotted numbers after `.so.` of the names that
name its component, and `LLAMA_BUILD_NUMBER`. `Conflicting` (two names of different components,
two first numbers of one kind of version, or two commits) needs the database, so the engine
decides it; `validate` checks the other four statuses, that a `Conflicting` claim has two
identity assertions or versions at least, and I1. `Required` assertions come with PR-4d, and
code checks with M1 profiles.

## Fields added to `sigil-session/1`

A field added after sessions without it were written is optional on read, so those sessions still load. A missing one reads as empty. SIGIL always writes it, so a session it writes has every field.

| Field | Added in | Missing reads as |
|---|---|---|
| `request.active` | PR-3b-2 | `[]` (nothing active requested) |
| `probes` | PR-3b-2 | `[]` (no probe) |
| `reference_matches` | PR-4a | `[]` (no installation compared) |
| `binaries` | PR-4b-1 | `[]` (no binary parsed) |
| `request.code` | PR-5a | `false` (no code analyzed) |

The schema leaves these fields out of `required`. Every other field is required by both the schema and serde.

`reference_matches` and `binaries` are the exceptions to "always writes it": SIGIL writes them only
when they have entries, so a session without `--install-dir` keeps its bytes, and an earlier SIGIL
still reads it.

The schema is **backward compatible, not forward compatible.**
- This SIGIL reads every `sigil-session/1` an earlier SIGIL wrote.
- An earlier SIGIL may refuse a session this one writes. Every type denies unknown fields and variants, so a build from before PR-3b-2 refuses a session with `request.active` or `probes`, one from before PR-4a a session with `reference_matches`, one from before PR-4b-1 a session with `binaries`, one from before PR-4b-2a a binary inspection (`discovered_by: Argument`), and one from before PR-5a a session with `request.code`.
- A change that a newer reader must not ignore needs `sigil-session/2`.

## Not in the model yet

| Item | Arrives in |
|---|---|
| AI-BOM v2 renderer | PR-3b-3, with the viewer that consumes it |
| Patch assertions | M2 |
| Active-mode traces | M4 |
