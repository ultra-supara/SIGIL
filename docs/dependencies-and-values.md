# Dependency candidates and process values

SIGIL can relate an ELF's declared dependencies to files already included in the inspection.
It also records settings from an explicit service unit and values read from observed runtime
processes. The session keeps the source and limitations of each fact.

## Dependency candidates

A `Declares` relation says that a binary names a dependency. A `Candidate` says that a scanned
file could satisfy that name under one modeled search rule. A candidate includes the requester's
placement, search directory, any observed process values it uses, and its hypothetical loader
chain. The same bytes installed in two directories can therefore have different candidates.

SIGIL models `$ORIGIN`, RPATH, RUNPATH, same-process initial LD_LIBRARY_PATH and common default
directories. RPATH inheritance follows a particular candidate chain; RUNPATH is used only for
its direct dependencies. RPATH is considered only when the requester has no RUNPATH;
an ancestor with its own RUNPATH cannot supply inherited RPATH. It retains alternatives
instead of declaring a first-match winner.
Only an original dependency name containing a slash selects pathname search. Token expansion
is separate. A dollar token in a slash-free name such as `lib$ORIGIN.so` is currently an
explicit unsupported-name gap; it never selects DirectPath or an unresolved literal lookup.

Only stable read ELF shared objects with compatible recorded class, byte order and machine
are candidates. Matching a SONAME or a basename alone is insufficient. The search examines
only collected placements. The install collector records normal parents actually checked by
its no-follow traversals; it doesn't add parent files or infer parents from a child's path.
A stable leaf without its own parent proof may use consistent parent observations recorded
with another placement. That is composed snapshot evidence, rather than a claim that this
leaf was read through that other traversal. Conflicting or missing observations remain gaps.
A scanned stable symlink can lead to another collected entry. Both analysis and structural
validation use those recorded directory/link observations to reach the exact candidate;
an unrelated search directory cannot justify a compatible ELF. No dependency-triggered
filesystem read is performed. `$LIB`, `$PLATFORM`, ld.so.cache, hardware-capability selection
and secure-execution details remain explicit coverage gaps. Mach-O dependencies are declared
only, and relocatable objects have no runtime dependency search.

Each detailed candidate has a mandatory `DependencySearch` witness in its optional context.
Entry and component indices are zero based. `DirectPath` names the original slash-containing
dependency; `DefaultDir { index }` selects `/lib`, `/usr/lib`, `/lib64` or `/usr/lib64`;
`Runpath { entry, component }` selects the requester's setting; `Rpath { owner, entry, component }`
identifies the setting's owner in the ordered chain; and `LdLibraryPath { value, component }`
selects an exact observed ValueId. ELF paths split on colon; initial LD_LIBRARY_PATH splits
on colon or semicolon. ORIGIN belongs to the ELF owning the setting, or the chain executable
for LD_LIBRARY_PATH. Empty or relative components need one qualified same-process cwd.
Only the exact required cwd/LD value inputs are listed, and ambiguous duplicate observations
of a used process/key cannot supply them.

Each detailed candidate records which setting supplied its search directory. SIGIL rejects
a Runpath claim without that ELF's RUNPATH, a DefaultDir claim outside its limited defaults,
and loader ancestors without preceding valid candidate edges in that exact process/chain.
A process chain begins at its recorded executable in SIGIL's observed mount namespace;
static chains begin at a compatible stable ELF placement. Recorded ABI compares ELF class,
byte order and machine exactly. The modeled subset is 64-bit little-endian x86-64 and
64-bit AArch64 of either byte order. These checks establish consistency of the recorded
model, without predicting every loader stage or attesting that an observation was truthful.

A candidate doesn't establish what the dynamic loader selected, what a symbol bound to, or
whether code executed. A mapping is a separate observation with no recorded loading cause.
No candidate recorded doesn't mean a library is absent from the host or loading failed.

```sh
sigil inspect ollama --install-dir /usr/local --format md
sigil binary inspect ./app ./libexample.so --format md
```

## Configured values

`--service-unit FILE` reads settings from that one supplied file: User, Group, WorkingDirectory
and allowlisted Environment assignments. It parses the same bytes already read and hashed
for that supplied unit. Each surviving assignment names its file/key/line.
An Environment reset clears earlier assignments, and a later assignment for a key wins within
the supplied file. Unsupported expressions stay unknown.

SIGIL doesn't read drop-ins, manager environment or EnvironmentFile contents. Consequently its
launch predictions are Unknown, with those missing premises named. It always requests
12 base predictions: User, Group, WorkingDirectory, and nine fixed environment keys
(CUDA_VISIBLE_DEVICES, DYLD_LIBRARY_PATH, GGML_BACKEND_DIR, GGML_BACKEND_PATH,
HIP_VISIBLE_DEVICES, LD_LIBRARY_PATH, OLLAMA_HOST, OLLAMA_LIBRARY_PATH and OLLAMA_MODELS).
Seen allowlisted GGML_* keys can add predictions. Supplied-unit rows have a separate fixed
`service_unit_values` budget of 16,384, with no CLI override; exhaustion remains a gap.
A configured value isn't an effective running value, and a parent's environment isn't assigned to a child automatically.
User and Group remain supplied literals; SIGIL reads no account databases to resolve them.
An unset WorkingDirectory doesn't imply `/`, and an unset User doesn't imply root. Accepting
A-2/A-3 does not repair unread effective configuration. ChildDerived values and backend loader
profiles remain future work.

## Observed values

Observe mode reads cwd via readlink and effective Uid/Gid numbers from status for the selected
runtime and its descendants. It never opens the cwd link's target. Each value belongs to the
complete process identity, including boot and start time. Descendants gain no semantic role
or environment merely from their parent; values without a known role use an observation
label. Values read during a detected exec,
exit or PID reuse are invalidated. The reads are sequential observations, not an atomic
snapshot. A pathname in another mount namespace isn't used as a host search path.

Environment reading requires an additional explicit option:

```sh
sigil inspect ollama --mode observe --install-dir /usr/local --observe-env --format md
```

Without `--observe-env`, environ isn't opened and no environment observation is recorded.
With it, SIGIL keeps only GGML_*; LD_LIBRARY_PATH, DYLD_LIBRARY_PATH; OLLAMA_HOST, OLLAMA_MODELS,
OLLAMA_LIBRARY_PATH; CUDA_VISIBLE_DEVICES and HIP_VISIBLE_DEVICES. It omits unrelated keys and
removes URL credentials and query/fragment text from OLLAMA_HOST. PATH and LD_PRELOAD aren't
collected. This limits future binding claims when preload information is unknown.

`/proc/<pid>/environ` describes the initial exec environment; it doesn't generally reflect later
setenv/putenv changes. Its entries are labeled initial environment and don't establish a current
getenv value. A Known empty value differs from Absent. Absence requires a complete read; denied,
malformed, duplicate or truncated streams make every emitted environment value Unknown,
including already completed entries. Independent cwd/ID observations can survive. Permission
denial uses Unknown(NotObservable(PermissionDenied)); incomplete/budget/coherence failures use
Unknown(NotObservable(ReadIncomplete)); confirmed process disappearance/reuse uses
Unknown(NotObservable(NoProcess)). NotModeled describes
unsupported semantics rather than an attempted observation failure. Wildcard GGML_* absence
isn't enumerable.

## Coverage and limits

`artifacts.dependencies` / `binary.dependencies` cover modeled candidate searches;
`values.configured` covers supplied-file values and unavailable launch predictions;
`values.observed` covers requested process value reads. A supplied unit's unexamined effective
configuration leaves its value check incomplete. An installation inspection without a supplied
unit records `values.configured` as OutOfScope. Custom policies requiring an inactive new
check instead receive `Skipped` coverage at scope `Audit`, leaving the outcome incomplete
without additional reads. Opt-out environ isn't part of the requested
observed read set. Outside listener holders are out of scope; a possible runtime with incomplete
identification remains a gap.

The process and candidate limits are recorded in request.budgets. Environment bytes have per
process and total bounds; value rows and dependency contexts/candidates are also bounded.
`dependency_search_paths` counts path components. Raw source components are charged before
expansion, at least one for each empty or unsupported attempt. The initial absolute lookup
also charges any components beyond that prepaid count: root anchors, cwd/ORIGIN additions
and the joined dependency leaf. Each added symlink-target component is charged separately,
including absolute-root restarts, dot/dotdot and synthetic trailing-slash directory markers.
Pending components already charged are not charged twice; unused initial credit cannot pay
for links. Unmatched, duplicate, failed and unsupported attempts receive no refunds.
Read failures and exhausted bounds are coverage gaps, not evidence of absence. Recorded
normal-parent proofs and symlink traversal each have a fixed depth bound of 40; contextual
lookup paths have fixed bounds of 65,536 bytes and 256 components. These path bounds apply
when validating saved sessions as well as when generating candidates.

Markdown and HTML preserve Known, Absent, Unknown, source and candidate qualification,
including escaped search witnesses, owners and value IDs. Text from inputs never becomes
a link or HTML. [Example 21](../schemas/examples/session-v1/21-deps-values.json) is a focused
37-value, three-candidate session, rather than a fixture for the full current policy catalog.
AI-BOM keeps its existing summary projection and session digest; raw process values and relations
remain in the session. PASS and completeness are independent.
