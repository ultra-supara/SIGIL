# Policy (`sigil-policy/1`)

A policy says what an audit must cover and how SIGIL treats what it finds. It never changes what
was found: technical findings, their conditions and evidence, and their default severity come
from the analysis. The policy decides only what is done with them, and which checks must be
closed for the result to be complete.

- **Status:** `crates/sigil-engine` loads and evaluates policies. `sigil inspect ollama --policy
  FILE` and `sigil binary inspect --policy FILE` load one; without `--policy`, the built-in
  default applies.
- **Source:** plan §4.7. The session it applies to is described in
  [`docs/session-model.md`](session-model.md).

## Format

```toml
schema = "sigil-policy/1"      # required, exactly this
name   = "default"             # required; recorded in the session with the file's SHA-256

[scope]
audit          = ["model_store"]   # audited in every inspect ollama run
observe_audit  = ["exposure"]      # added in observe mode
active_audit   = ["runtime_api"]   # added when an active feature is requested (--active)
install_audit  = ["runtime_artifacts"]  # added when an installation is inspected (--install-dir)
binary_audit   = ["binary"]        # audited in a binary inspection (binary inspect)
binary_code_audit = ["binary_code"]  # added after binary_audit when code is analyzed
extra_required = []                # checks required beyond those of the scopes (inspect ollama)

[open_questions]
default = "count_as_gap"           # count_as_gap | warn | fail | ignore
# reason = "..."                   # required for ignore

[assumptions]
accept = []                        # e.g. ["A-3"]

[rules."exposure.bind_public"]
action = "fail"                    # fail | warn | ignore

[rules."model.license_missing"]
action  = "ignore"
reason  = "Internal models have no license layer by design"   # required for ignore
expires = "2027-03-31"             # or a TOML date: 2027-03-31

[trust]
principals   = ["root", "runtime"] # root | runtime | uid:<n>
extra_groups = []                  # gid:<n>

[[components.deny]]
component = "ggml-backend/rpc"
action    = "fail"                 # fail | warn
reason    = "The RPC backend is outside the internal standard"
```

A deny entry matches a component claim through the claim's component or any of its names: a file
named `libggml-base.so.0` whose SONAME is `libggml-rpc.so` is a `ggml-base` claim, `Conflicting`,
and the entry above matches it. The violation's subject is that claim, and its rule names the
denied component (`policy:components.deny.ggml-backend/rpc`). An `Unidentified` claim never
matches.

Every table is optional. Without `[open_questions]`, open questions count as gaps. Without
`[trust]`, root and the runtime user are trusted. Every list of `[scope]` is optional too: a policy
written before `install_audit` existed loads unchanged, and adds nothing for an installation.

**The scope rule.** The audit scope is `audit`, plus `observe_audit` in observe mode, plus
`active_audit` when an active feature is requested, plus `install_audit` when the session has an
`install` root (`--install-dir`). The session records the result. Evaluation computes it again from
the recorded request, so the two always agree. A policy that lists `runtime_artifacts` in `audit`
gets each of its checks `Skipped { Flag("--install-dir") }` on a run without `--install-dir`, and
the result is INCOMPLETE.

**A binary inspection** (`sigil binary inspect`, a session whose roots are `binary-<n>`) audits
`binary_audit`: `["binary"]`, whose checks are `binary.container` and `binary.identity`, one
entry each per input. The other lists and `extra_required` apply to `inspect ollama` only, so an
organization's extra checks for an installation do not make every binary inspection incomplete.

**With code analysis** (`request.code`), `binary_code_audit` is added after `binary_audit`, without
repeats: `["binary_code"]`, whose check is `binary.code`, one entry per input. Without code
analysis, `binary_code_audit` is ignored. Code analysis is requested with
`sigil binary inspect --code` (the engine's `BinaryRequest`). Evaluation reads `request.code` from
the session, so it adds the same scope.

`binary_audit` is optional, but unlike the other lists, a policy file that omits it gets
`["binary"]`: a policy written before it existed still requires every input to be inspected in
full. Without code analysis, only an explicit `binary_audit = []` requires nothing, and the result
is then `COMPLETE` whatever the inputs' statuses (the summary says so).

Under the default policy, an input whose `binary.identity` does not close makes the session
`INCOMPLETE`: `Partial` for a signature scan cut short or a returned value not read (its gaps say
why), or an ELF without facts; `Unsupported` for a Mach-O (no Mach-O section is read yet) or a
file that is not a container; and the container's `BudgetExceeded` or `Error`. A file named as
an NVIDIA library is not scanned, and its `OutOfScope` closes the check (ADR-010). What
`binary.identity` records: [`docs/binary-inspect.md`](binary-inspect.md#signatures).

`binary_code_audit` fails closed as `binary_audit` does. A policy file that omits it gets `["binary_code"]`,
so a policy written before it existed still requires every input's code to be analyzed in full.
Only an explicit `binary_code_audit = []` requires nothing of code. With code analysis, a binary
inspection requires nothing only when both lists are `[]`: with `binary_audit = []` alone, the
default `binary_code_audit` still requires `binary.code`.

Under the default policy with code analysis, an input whose `binary.code` does not close makes the
session `INCOMPLETE`. That is `Partial`, `BudgetExceeded`, `Error`, or `Unsupported`:
- `Partial`: some code was not analyzed, for example a reference that could not be confirmed, a
  refused read, or a limit reached. Its gaps say why;
- `BudgetExceeded` and `Error`: the input's container state, copied;
- `Unsupported`: a Mach-O or fat file, an ELF of another machine, an x32 or big-endian ELF, or a
  file that is not a container. Only x86-64 ELF64 little-endian code is analyzed.

Code facts are facts, not findings. No rule applies to a call site, so code analysis never changes
the verdict. What `binary.code` records: [`docs/session-model.md`](session-model.md#code-analysis-pr-5a).

## Catalogs

A policy may only name what exists.

**Audit scopes and the checks they require.** Required checks come from the requested scope, not
from what was detected. A scope whose collector is not implemented yet still requires its checks,
so requesting it gives an honest `INCOMPLETE`.

| Scope | Required checks | Collected by |
|---|---|---|
| `model_store` | `model_store.inventory`, `model_store.integrity`, `model_store.license` | PR-3a-2 |
| `exposure` | `exposure.binds` | PR-3a-2 (observe mode) |
| `runtime_api` | `runtime_api.version` | PR-3b-2 (`--active api-probe`) |
| `runtime_artifacts` | `artifacts.discovery`, `artifacts.release`, `artifacts.container`, `artifacts.identity` | PR-4a, PR-4b-1, PR-4c-2a (`--install-dir`) |
| `backend_loader` | `artifacts.discovery`, `loader.identify`, `loader.search_paths` | PR-4 to PR-7 |
| `binary` | `binary.container`, `binary.identity` | PR-4b-2a, PR-4b-2b, and PR-4c-2a (`sigil binary inspect`; [binary-inspect.md](binary-inspect.md)) |
| `binary_code` | `binary.code` | PR-5a (a binary inspection with code analysis) |

**Rules** (kind, default severity):

| Rule | Kind | Default |
|---|---|---|
| `model.blob_missing` | Integrity | WARN |
| `model.blob_digest_mismatch` | Integrity | FAIL |
| `model.manifest_digest_malformed` | Integrity | FAIL |
| `model.manifest_unparseable` | Integrity | WARN |
| `model.license_missing` | Integrity | WARN |
| `model.provenance_unknown` | Integrity | WARN |
| `model.not_found` | Integrity | WARN |
| `exposure.bind_public` | Exposure | WARN |
| `exposure.bind_lan` | Exposure | WARN |

When each `model.*` rule applies, and which coverage it affects: [`docs/model-store.md`](model-store.md).
For the `exposure.*` rules: [`docs/exposure.md`](exposure.md). For the `artifacts.*` checks, which
have no rules: [`docs/runtime-artifacts.md`](runtime-artifacts.md).

**Assumptions** a finding condition may rest on, only if accepted:

| ID | Assumption |
|---|---|
| A-1 | `/etc/passwd` and `/etc/group` reflect the environment (not true with NSS/LDAP) |
| A-2 | The service unit found, with its drop-ins, is the one in effect |
| A-3 | The runtime was launched by this system-instance unit, so an unset `WorkingDirectory=` means cwd `/` |
| A-4 | No symbol interposition in the role: each loader PLT call binds to the analyzed definer |

## Inputs to the analysis

Two parts of a policy decide what the analysis concludes, not only what is done with it:
- **the required checks** (`[scope]`): collection runs for them;
- **the accepted assumptions** (`[assumptions]`): a condition may rest on an assumption only if it
  is accepted, so acceptance decides which conditions are settled.

The session records both before the analysis: the request's `required_checks`, and each
assumption's acceptance (`Accepted`, source `policy:assumptions.accept`, if listed; otherwise
`NotAccepted`).

Evaluation never changes them. It refuses a policy whose required checks or accepted assumptions
differ from those recorded, and leaves the session unchanged. Required checks are compared as a
set: a check added or removed is a difference, their order is not (a session saved as canonical
JSON lists them sorted). Such a policy changes the technical
conclusions, so the session must be analyzed again with it. A policy that differs only in its
decisions (rule overrides, open-question treatment, denied components) can re-evaluate a recorded
session. Deny entries are matched through the evaluating build's component database, so a build
with other names may give other violations for the same session.

## What evaluation does

Evaluation changes only what the policy owns.
- **The applied policy:** the session's policy knowledge entry is replaced with this policy's name
  and SHA-256.
- **Findings:**
  - A rule override applies, with source `policy:rules.<rule>`, its reason, and its expiry.
  - Otherwise the rule's default severity applies, with source `default:<rule>`.
  - An ignored finding stays in the session with its reason.
- **Open questions:** the `[open_questions]` treatment applies, with source
  `policy:open_questions.default`.
- **Denied components:**
  - Every component claim of a denied component, or one that any of the claim's
    names (file name or SONAME) names, becomes a `PolicyViolation`. This includes name-only
    claims and excludes `Unidentified` ones. Claims come from identification
    ([runtime artifacts](runtime-artifacts.md#components)), so a deny entry must name a
    component of the database; any other key is fatal (below).
  - The violation's evidence is the claim's artifact.
  - Policy violations are separate from technical findings.

## Outcome

Two independent results, always shown together.

- **`verdict`:** the maximum action of the findings, the policy violations, and the open questions
  treated as `warn`/`fail`. `ignore` and `count_as_gap` do not count. With none, it is `PASS`. Gaps
  never change it: a confirmed `FAIL` with a skipped check is still `FAIL`.
- **`completeness`:**
  - `INCOMPLETE` lists the required checks that are not closed and the open questions treated
    as `count_as_gap`.
  - A check is closed when it has coverage and every coverage entry for it is `Complete`,
    `NotPresent`, or `OutOfScope`. A required check with no coverage at all is not closed.
  - Findings never change completeness: `PASS` with `INCOMPLETE` is not a clean pass.

## Expiry

- An override is valid through the UTC day in `expires`.
- After that day, the rule's default applies again. The decision's reason says `override expired
  <date>`, and evaluation returns a warning.
- Expiry is judged at `policy_time`, an input recorded in the session's outcome (by default the
  observation start). Re-evaluating a session reuses it, so the result does not change by itself
  over time.

## What is fatal

Loading fails, and nothing is evaluated, for:
- a file that is not TOML;
- an unknown key in any table;
- a value of the wrong type;
- a `schema` other than `sigil-policy/1`;
- an empty `name`;
- an unknown scope, check, rule, or assumption;
- a malformed date;
- `ignore` without a reason (rule or open questions);
- a principal other than `root`, `runtime`, or `uid:<n>`, and a group other than `gid:<n>`;
- a component deny entry with `ignore`, without a reason, listed twice, or naming a component
  that is not in the component database
  ([runtime artifacts](runtime-artifacts.md#components)).

A typo never silently weakens a policy.

## The default policy

`crates/sigil-engine/policies/default.toml`:
- audits `model_store`, plus `exposure` in observe mode, plus `runtime_api` when the API probe is
  requested (`--active api-probe`), plus `runtime_artifacts` when an installation is inspected
  (`--install-dir`);
- in a binary inspection, audits `binary`, plus `binary_code` when code is analyzed;
- counts open questions as gaps;
- accepts no assumption;
- has no overrides.

Each later PR adds its scope to the default when its collector exists. A run never reports a gap
for a check SIGIL cannot perform yet unless that scope was requested.
