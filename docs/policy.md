# Policy (`sigil-policy/1`)

A policy says what an audit must cover and how SIGIL treats what it finds. It never changes what
was found: technical findings, their conditions and evidence, and their default severity come
from the analysis. The policy decides only what is done with them, and which checks must be
closed for the result to be complete.

- **Status:** `crates/sigil-engine` loads and evaluates policies. `sigil inspect ollama --policy
  FILE` loads one; without `--policy`, the built-in default applies.
- **Source:** plan §4.7. The session it applies to is described in
  [`docs/session-model.md`](session-model.md).

## Format

```toml
schema = "sigil-policy/1"      # required, exactly this
name   = "default"             # required; recorded in the session with the file's SHA-256

[scope]
audit          = ["model_store"]   # audited in every mode
observe_audit  = ["exposure"]      # added in observe mode
active_audit   = ["runtime_api"]   # added when an active feature is requested (--active)
install_audit  = ["runtime_artifacts"]  # added when an installation is inspected (--install-dir)
extra_required = []                # checks required beyond those of the scopes

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

Every table is optional. Without `[open_questions]`, open questions count as gaps. Without
`[trust]`, root and the runtime user are trusted. Every list of `[scope]` is optional too: a policy
written before `install_audit` existed loads unchanged, and adds nothing for an installation.

**The scope rule.** The audit scope is `audit`, plus `observe_audit` in observe mode, plus
`active_audit` when an active feature is requested, plus `install_audit` when the session has an
`install` root (`--install-dir`). The session records the result. Evaluation computes it again from
the recorded request, so the two always agree. A policy that lists `runtime_artifacts` in `audit`
gets both its checks `Skipped { Flag("--install-dir") }` on a run without `--install-dir`, and the
result is INCOMPLETE.

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
| `runtime_artifacts` | `artifacts.discovery`, `artifacts.release`, `artifacts.container` | PR-4a, PR-4b-1 (`--install-dir`) |
| `backend_loader` | `artifacts.discovery`, `loader.identify`, `loader.search_paths` | PR-4 to PR-7 |

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
session.

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
  - Every component claim for a denied component becomes a `PolicyViolation`. This includes
    name-only claims and excludes `Unidentified` ones.
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
- a component deny entry with `ignore`, without a reason, or listed twice.

A typo never silently weakens a policy.

## The default policy

`crates/sigil-engine/policies/default.toml`:
- audits `model_store`, plus `exposure` in observe mode, plus `runtime_api` when the API probe is
  requested (`--active api-probe`), plus `runtime_artifacts` when an installation is inspected
  (`--install-dir`);
- counts open questions as gaps;
- accepts no assumption;
- has no overrides.

Each later PR adds its scope to the default when its collector exists. A run never reports a gap
for a check SIGIL cannot perform yet unless that scope was requested.
