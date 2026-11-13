# Policy (`sigil-policy/1`)

A policy says what an audit must cover and how SIGIL treats what it finds. It never changes what
was found: technical findings, their conditions and evidence, and their default severity come
from the analysis. The policy decides only what is done with them, and which checks must be
closed for the result to be complete.

- **Status:** `crates/sigil-engine` loads and evaluates policies. `sigil inspect ollama --policy
  FILE`, `sigil binary inspect --policy FILE`, `sigil session verify --policy FILE`, and
  `sigil compare --policy FILE` load one; without `--policy`, the built-in default applies.
- **Source:** plan §4.7. The session it applies to is described in
  [`docs/session-model.md`](session-model.md).

## Format

```toml
schema = "sigil-policy/1"      # required, exactly this
name   = "default"             # required; recorded in the session with the file's SHA-256

[scope]
audit          = ["model_store"]   # audited in every inspect ollama run
observe_audit  = ["exposure", "runtime_processes"]  # added in observe mode
active_audit   = ["runtime_api"]   # added when an active feature is requested (--active)
install_audit  = ["runtime_artifacts"]  # added when an installation is inspected (--install-dir)
binary_audit   = ["binary"]        # audited in a binary inspection (binary inspect)
binary_code_audit = ["binary_code"]  # added after binary_audit when code is analyzed
# install_code_audit = ["installation_code"]  # omission has this default
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

[[capabilities.deny]]
feature = "posix.process_spawn"    # a key of the capability-import table
action  = "fail"                   # fail | warn
reason  = "The runtime must not start processes"

[compare.changes.ModelAdded]       # a change kind of sigil-diff/1, for sigil compare
action = "ignore"                  # fail | warn | ignore; decided for a new or changed finding or violation
reason = "The ML team adds models daily"   # required for ignore

[compare.not_comparable.Request]   # Coverage | Request | Policy
treatment = "warn"                 # count_as_gap | warn | fail | ignore
```

A deny entry matches a component claim through the claim's component or any of its names: a file
named `libggml-base.so.0` whose SONAME is `libggml-rpc.so` is a `ggml-base` claim, `Conflicting`,
and the entry above matches it. The violation's subject is that claim, and its rule names the
denied component (`policy:components.deny.ggml-backend/rpc`). An `Unidentified` claim never
matches.

A capability denial (#51) is about code, not imports. A slice whose code calls an import of the
denied capability directly is a policy violation that cites each such call site
(`policy:capabilities.deny.posix.process_spawn`). A slice that imports the capability but has no
direct call site of it is an open question (rule `binary.capability_call`), whatever code
analysis says: a call through a function pointer or from data is not followed, so the absence of
a direct call is not proof that there is none. Without code analysis (an inspection without
`--code`), every such import is an open
question. The capabilities a policy can deny are the keys of the capability-import table
(`sigil rules` lists them); allowing one is not listing it.

A denial sees imports of the names its key lists in the capability table, and the direct calls
of them, nothing else. `posix.process_spawn` lists `execve`, `fork`, `posix_spawn`, and `system`:
a file that starts processes through `execvp` or `popen` alone gives no result under it, and
neither does one that imports none of the names (a statically linked Go program that starts
processes through its own system calls, say; #48). The names of each key:
[binary inspection](binary-inspect.md#capabilities-and-code---code). An open question's treatment
is the `[open_questions]` one, not the denial's action, so a `warn` denial of an import that is
never called directly still makes the result INCOMPLETE while open questions count as gaps; no
`[rules."binary.capability_call"]` override exists (it does not load). A file with more imports
than `binary_imports` keeps the first ones in name order, and a denied import past them gives
nothing; the cut leaves `binary.container` (`artifacts.container` for an installation)
`Partial`, which keeps the result INCOMPLETE as long as the policy requires that check (the
default does). Code analysis reads every import, so a direct call of one past the cut may be in
the session's code facts; without its hint it is judged neither way.

A denial judges only the binaries a run reads: `inspect ollama` without `--install-dir` reads
none, so it gives no capability result. With `runtime_artifacts` in `audit`, such a run is
INCOMPLETE, since the installation's checks are required and not run.

Every table is optional. Without `[open_questions]`, open questions count as gaps. Without
`[trust]`, root and the runtime user are trusted. Every list of `[scope]` is optional too: a policy
written before `install_audit` existed loads unchanged, and adds nothing for an installation.
Without `[compare]`, every change kind and cause of `sigil compare` has its default
([comparing sessions](#comparing-sessions-compare)).

**The scope rule.** The audit scope is `audit`, plus `observe_audit` in observe mode, plus
`active_audit` when an active feature is requested, plus `install_audit` when the session has an
`install` root (`--install-dir`). The session records the result. Evaluation computes it again from
the recorded request, so the two always agree. A policy that lists `runtime_artifacts` in `audit`
gets explicit `Skipped { by: Flag("--install-dir") }` coverage at scope `Audit` for its
checks on a run without an installation. The result is INCOMPLETE. Likewise, requiring
`values.observed` outside observe mode produces `Skipped { by: ModeDisabled }` at scope `Audit`.
Requiring a check never opts into process observation, environment reads, a service unit, or
additional filesystem reads.

**A binary inspection** (`sigil binary inspect`, a session whose roots are `binary-<n>`) audits
`binary_audit`: `["binary"]`, whose checks are `binary.container`, `binary.identity`, and
`binary.dependencies`, one entry each per input. The other lists and `extra_required` apply to `inspect ollama` only, so an
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
- `Unsupported`: an unsupported Mach-O slice, an ELF of another machine, an x32 or big-endian ELF, or a
  file that is not a container. x86-64/AArch64 ELF64 little-endian and the [Mach-O subset](binary-inspect.md#mach-o-code) are analyzed.

For `multiarch-v1` ELF sessions, a capability question uses its own slice's
`binary.code` or `artifacts.code` diagnostic. A partial sibling or content summary
cannot turn a complete local search into an incomplete one. Conversely, incomplete
or unsupported local code yields `CheckIncomplete`, never a complete-search reason.
Confirmed direct calls still support a violation with exact slice and call IDs.
Explicit `binary_code_audit = []` / `install_code_audit = []` remove the corresponding
required check; they do not turn missing calls into violations. Marked Mach-O decisions
require the exact call witness and its archived raw-symbol × feature × library mapping.
A same-name import from another dylib cannot confer eligibility. Relevant unresolved
calls retain their own symbol and call-site evidence, even beside an admitted violation.
Unknown capability-table digests fail closed; historical archives must be retained.

Code facts are facts, not findings. Only a capability denial (above) acts on them: without one,
code analysis never changes the verdict. What `binary.code` records:
[`docs/session-model.md`](session-model.md#code-analysis-pr-5a).

## Catalogs

A policy may only name what exists.

**Audit scopes and the checks they require.** Required checks come from the requested scope, not
from what was detected. A scope whose collector is not implemented yet still requires its checks,
so requesting it gives an honest `INCOMPLETE`.

| Scope | Required checks | Collected by |
|---|---|---|
| `model_store` | `model_store.inventory`, `model_store.integrity`, `model_store.license` | PR-3a-2 |
| `exposure` | `exposure.binds` | PR-3a-2 (observe mode) |
| `runtime_processes` | `processes.observed`, `values.observed` | PR-4d-2, PR-4d-3 (observe mode; [runtime artifacts](runtime-artifacts.md#linked-to-the-running-processes-observe-mode-pr-4d-2)) |
| `runtime_api` | `runtime_api.version` | PR-3b-2 (`--active api-probe`) |
| `runtime_artifacts` | `artifacts.discovery`, `artifacts.release`, `artifacts.container`, `artifacts.identity`, `artifacts.dependencies`, `values.configured` | PR-4a, PR-4b-1, PR-4c-2a, PR-4d-3 (`--install-dir` or `--service-unit`) |
| `backend_loader` | `artifacts.discovery`, `loader.identify`, `loader.search_paths` | PR-4 to PR-7 |
| `binary` | `binary.container`, `binary.identity`, `binary.dependencies` | PR-4b-2a, PR-4b-2b, PR-4c-2a, and PR-4d-3 (`sigil binary inspect`; [binary-inspect.md](binary-inspect.md)) |
| `binary_code` | `binary.code` | PR-5a (a binary inspection with code analysis) |
| `installation_code` | `artifacts.code` | Installation inspection with `--code` |

An installation requested with `--code` adds `install_code_audit`. When the key is omitted,
it defaults to `["installation_code"]`; an explicit `install_code_audit = []` opts out.
`artifacts.code` has one root summary and one entry for each distinct recognized binary
content. The root cannot be complete when discovery is incomplete. Each ELF code analysis
has its own `binary_code_bytes` budget; unsupported formats or incomplete analysis do not
close the default check. The same capability policy judges the recorded installation call sites.

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

**Capabilities** a `[[capabilities.deny]]` entry may name (#51), the keys of
`crates/sigil-engine/signatures/capabilities.toml`: `cxx.file_read`, `cxx.file_write`,
`posix.anti_debug`, `posix.dynamic_loading`, `posix.environment_access`, `posix.file_read`,
`posix.file_write`, `posix.network`, and `posix.process_spawn`. A signature key (`go.*`,
`ollama.*`, `rpc.*`) is a name found in a file, with no call site to judge, and does not load.

## Inputs to the analysis

Two parts of a policy decide what the analysis concludes, not only what is done with it:
- **the required checks** (`[scope]`): determine the coverage required; inactive collectors
  record skips rather than gaining permission for additional reads;
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
decisions (rule overrides, open-question treatment, denied components and capabilities) can
re-evaluate a recorded session through the engine's `evaluate`; the CLI re-evaluates a saved
session only to compare it, in `session verify`, so from the CLI another policy means inspecting
again. Component deny entries are matched through the evaluating build's
component database, so a build with other names may give other violations for the same session.
Capability denials are judged by the session's own hints and code facts, which were made with the
capability table the session records (a `SignatureDb` knowledge entry `capabilities`, by
SHA-256): a build with the same table gives the same results. Under a capability denial,
evaluation refuses a session with binary facts that records another table, or none (every session
made before #51), and leaves it unchanged: its hints and call sites name only that table's
imports, so the files must be analyzed again with this build. It also refuses a session whose
`Import` hints are not the ones the table gives its import facts. Without a capability denial
nothing of this is checked.

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
- **Denied capabilities** (#51), for each slice of the session's binary facts and each denial, in
  the policy's order, once the session is known to be made with this build's capability table
  (above). The imports of the capability are those the slice's `Import` hints give it:
  - a slice with a direct call site (`Call` or `TailJump`) of one of them gives a
    `PolicyViolation`: subject the slice, evidence every such call site by ID, the denial's action
    and reason;
  - a slice with none gives an open question: id `capability:<feature>@<slice>`, rule
    `binary.capability_call`, one unknown condition `calls:<feature>`, evidence the imports, and
    the `[open_questions]` treatment. The condition says why: `binary.code` or `artifacts.code` did not close, the code
    was not analyzed, or the code's every direct call was found and these are not among them;
  - a slice that does not import the capability gives nothing.

  Evaluation owns these open questions as it owns the violations: each evaluation removes those of
  rule `binary.capability_call` and makes them again. The analysis's own open questions stay.

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

## Verifying a session against its policy

`sigil session verify <SESSION> [--policy FILE]` (#51) says whether a saved session is what the
policy gives (by default the built-in policy). Validation, which every command that reads a
session runs, checks that a session agrees with itself. It cannot know what a policy should have
decided: a session records its policy's name and SHA-256, not its rules, so one whose violation
was removed and whose verdict was set to PASS still validates. `session verify`:
- re-verifies the session's reference knowledge, as `session render` does;
- checks that the session's one policy knowledge entry has this policy's name and SHA-256;
- evaluates a copy under the policy, at the session's recorded `policy_time` (a policy that cannot
  evaluate it is a difference: most often a capability denial on a session made by a build with
  another capability table, which must be inspected again);
- compares the copy with the session in canonical form, and names each finding, open question, and
  policy violation that the policy gives and the session lacks or records otherwise, each one the
  policy does not give, and an outcome that differs.

It also checks that each finding's rule is in this build's rule catalog with the kind and default
severity the session records. It prints `verified: <SESSION> is what the policy <name> (<sha256>)
gives at <policy_time>: <verdict> + <completeness>` and exits 0, or exits 1 with the first five
differences on stderr (`error: …`, then how many more), as for any execution error. What the
policy gives is what this build gives: component denials are matched through its component
database, and capability denials need its capability table. The analysis
(findings, their conditions and evidence, hints, call sites, coverage, the request) and the policy
time are the session's: `session verify` checks what the policy makes of them, not them. Only
inspecting the files again checks the analysis.
Validation does not check what a decision, a capability open question's ID, or an unknown
condition's reason should be given the recorded analysis; `session verify` does, by evaluating
again.

## Comparing sessions (`[compare]`)

`sigil compare --policy FILE` (#16) judges the differences between two sessions under the
policy's `[compare]` section; without `--policy`, under the built-in policy. A policy never
changes what changed: the diff's changes and the items it could not compare are the same under
any policy. It gives each change kind an action and each cause of an item not comparable a
treatment, and the diff two results, as a session has:

- **`verdict`:** the maximum action of the changes, and of the items not comparable treated as
  `warn` or `fail`. `ignore` does not count. With none, it is `PASS`.
- **`completeness`:** `INCOMPLETE` when either input session is incomplete itself (its recorded
  completeness, which the diff copies into each side), or when an item not comparable is treated
  as `count_as_gap` (the default). The diff names the incomplete inputs and counts the items.
  Otherwise `COMPLETE`. What a session could not see, a comparison with it cannot see either.
  Completeness never changes the verdict.

`--fail-on warn|fail` exits 3 when the verdict reaches that level, and `--fail-on-incomplete` 4
when the diff is incomplete and 3 does not apply
([judging the differences](ai-bom-and-comparison.md#judging-the-differences)).

**Default actions.** Drift that a single session's verdict cannot see fails; a change that
weakens the baseline warns; improvements, and changes that follow from others, are ignored.
`sigil rules` lists them.

| Default | Change kinds |
|---|---|
| `fail` | `LayerChanged` (the same model, other bytes), `FileContentChanged` (an installed file replaced), `BindWidened` |
| `decided` | `FindingNew`, `FindingDecisionChanged` (at least `warn`), `ViolationNew`, `ViolationDecisionChanged` (at least `warn`) |
| `warn` | `PolicyChanged`, `CheckOpened`, `ModelAdded`, `ModelRemoved`, `LicenseChanged`, `FileAdded`, `FileRemoved`, `ReleaseChanged`, `ComponentChanged`, `ListenerAdded` |
| `ignore` | `VerdictChanged`, `CompletenessChanged`, `CheckClosed`, `FindingResolved`, `ViolationResolved`, `ListenerRemoved`, `BindNarrowed` |

Every cause (`Coverage`, `Request`, `Policy`) counts as a gap by default.

By default, an Ollama upgrade (`FileContentChanged`) or an updated model tag (`LayerChanged`)
fails: against a trusted baseline, an intended update is approved by taking a new baseline.

**`decided`.** A new finding or policy violation weighs what its decisions in the current
session say: the maximum of their actions. A new finding of a rule the policy ignores is
ignored; a new `fail` violation fails. A finding or violation whose decisions changed
(`FindingDecisionChanged`, `ViolationDecisionChanged`) weighs its decisions in the current
session too, but never less than `warn`: when an override expires and an ignored finding now
fails, the diff fails, as it does for a new `fail` finding; a weakening (a `fail` finding now
ignored) still warns. Those decisions are the current session's, made by the policy it was
inspected with. Only these four kinds carry decisions, so only they take `decided`; a policy may
give them `fail`, `warn`, or `ignore` instead. `decided` for any other kind does not load. The
Markdown marks a line whose action its decisions gave "(as decided)".

**What the diff records.** The diff's `evaluation` names the policy (its name and SHA-256, as a
session records its policy) and holds the action of every change kind and the treatment of
every cause, each with its source (`default:compare.<Kind>`, `policy:compare.changes.<Kind>`,
`default:compare.not_comparable.<Cause>`, or `policy:compare.not_comparable.<Cause>`) and the
policy's reason. Each change's action can be read from it. The Markdown names each side's
completeness, the result, and each line's action. A reader judges a diff again: one whose table
misses a kind or a cause, or whose recorded verdict or completeness is not what a fresh
judgment gives, does not load.

**`[compare]` and sessions.** Inspection, evaluation, and `session verify` ignore the content of
`[compare]`. It is part of the file, though, and so of the SHA-256 a session records. Editing
`[compare]` changes that digest: a session inspected before the edit no longer verifies against
the edited file (`session verify` names the other digest). A session inspected
after `[compare]` was edited records the new digest. Against a baseline inspected before, the
diff then reports `PolicyChanged` (`warn` by default), and a violation on one side only is not
comparable (cause `Policy`, a gap by default). Taking a new baseline clears both.

Entries have no `expires`: a diff records no time to judge it at.

## What is fatal

Loading fails, and nothing is evaluated, for:
- a file that is not TOML;
- an unknown key in any table;
- a value of the wrong type;
- a `schema` other than `sigil-policy/1`;
- an empty `name`;
- an unknown scope, check, rule, or assumption;
- a malformed date;
- `ignore` without a reason (rule, open questions, or a `[compare]` entry);
- a principal other than `root`, `runtime`, or `uid:<n>`, and a group other than `gid:<n>`;
- a component deny entry with `ignore`, without a reason, listed twice, or naming a component
  that is not in the component database
  ([runtime artifacts](runtime-artifacts.md#components));
- a capability denial with `ignore`, without a reason, listed twice, or naming a key that is not
  in the capability-import table (#51);
- a `[compare.changes]` key that is not a change kind of `sigil-diff/1`, a
  `[compare.not_comparable]` key other than `Coverage`, `Request`, or `Policy`, and `decided` for
  a change kind other than `FindingNew`, `FindingDecisionChanged`, `ViolationNew`, and
  `ViolationDecisionChanged` (#16).

A typo never silently weakens a policy.

## The default policy

`crates/sigil-engine/policies/default.toml`:
- audits `model_store`, plus `exposure` and `runtime_processes` in observe mode, plus `runtime_api` when the API probe is
  requested (`--active api-probe`), plus `runtime_artifacts` when an installation is inspected
  (`--install-dir`);
- in a binary inspection, audits `binary`, plus `binary_code` when code is analyzed;
- in an installation inspection with code analysis, also audits `installation_code`;
- counts open questions as gaps;
- accepts no assumption;
- has no overrides;
- has no `[compare]` section: every change kind and cause takes its default;
- denies no component or capability.

**Sessions from before PR-4d-3.** The expanded scope catalog adds `artifacts.dependencies`,
`values.configured`, `values.observed`, and `binary.dependencies`. The built-in policy text and
SHA-256 intentionally changed too. Older sessions still load, validate, and render, but
`session verify` with the current built-in policy can refuse their policy digest and required
checks (`RequiredChecksChanged`). Earlier changes, including PR-4d-2's `processes.observed`,
have the same boundary. Historical verification needs the original policy and matching build;
to use today's checks, inspect again. Verification evaluates recorded analysis; it never
re-reads the deployment or attests that collection was truthful.

Each later PR adds its scope to the default when its collector exists. A run never reports a gap
for a check SIGIL cannot perform yet unless that scope was requested.
