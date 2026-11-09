# ADR-018: discover the request before code analysis

PR #129 previously selected the code mode during single-file collection. An earlier x86
artifact could run with independent text-relocation and reference counters before a later
AArch64 ELF or Mach-O made the session multiarch-v1. A scannable alias could also repeat x86
code analysis to reproduce the parse cache seen by identity scanning.

## Decision

Code-enabled named and installation collection first hash and probe every admitted placement.
The shared probe uses the parser's ELF/Mach-O/Java recognition rules. It retains only placement
metadata, hashes and scan requirements. No code or identity scan runs during discovery. An
unknown probe or incomplete hash chooses the conservative multiarch counters, never legacy.

After discovery, group stable placements by ArtifactId. Prefer a scannable alias, then preserve
discovery order. Reopen one placement at a time through SafeFs, require the same root identity,
rehash the content, and check its expected digest, size and file identity before parsing. The
existing parser runs code and then identity scanning on the same fd and the same bounded cache.
This reproduces the historical code-before-scan cache state without replay or retained fds.
Use one artifact analysis owner; multiarch x86 selects its combined reference counter before
any work. Unsupported Mach-O dispatch remains gated in M3-B.

Publish the result only after the fd/path stability checks and comparison with discovery stat
facts pass. A failed pre-analysis verification may try the next identical placement. Once an
analysis was attempted, never repeat it, even if the post-analysis stability check rejects its
result. Rejecting a result never refunds I/O or analysis work. Healthy independent artifacts
retain their evidence.

## Bounds and saved diagnostics

Discovery hashing and revalidation each have separate cumulative caps derived from the
configured binary_bytes or install_bytes limit, plus one reserved growth-detection byte. Each
read's content limit is at most remaining minus one, so the SafeFs sentinel read fits the cap.
The discovery probe has its own cumulative physical-read cap equal to that configured byte
limit, in addition to its existing per-probe parse-allocation cap. Charge bytes actually returned
on every attempt, including failed reads. Retried placements share the remaining allowance.
Attempts and retained metadata are bounded by the discovered placements; no descriptor or
whole-file data is retained between phases.

Marked sessions record these limits in request.budgets and actual use in Audit-scoped coverage:

| Check | Budget |
| --- | --- |
| binary.collection.hash | binary_discovery_hash_bytes |
| binary.collection.probe | binary_discovery_probe_bytes |
| binary.collection.revalidation | binary_revalidation_bytes |

These entries describe successful enforcement of metering, not successful code analysis.
Analysis failures remain in the existing container/code/identity coverage. All three diagnostics
are optional as a group for older multiarch-v1 sessions; when supplied the model requires their
request limits and rejects usage above the limit. Stable fully identified legacy x86-only
sessions omit them and preserve canonical output. Physical hash I/O in those runs is bounded
by the sum of the two internal hash caps; the historical binary_bytes/install_bytes field
continues to describe discovery hashing. Exhausted or unstable identification cannot establish
the legacy mode, and is deliberately handled conservatively.

## Verification

Tests count actual x86 analysis callbacks and both reference counters. shared-refs.so contains
one text relocation and a PLT candidate: at references=1 legacy admits one of each, while mixed
requests in both orders admit at most one combined reference. AArch64 and Mach-O recognition
after x86 are covered. Named and installation tests compare every collected legacy fact across
both alias orders, normal limits, and small parse/code budgets. Stability tests cover changed,
replaced and vanished inputs between phases, stable-alias recovery, post-analysis rejection,
and actual revalidation I/O use without resets. Canonical CLI comparisons and the workspace,
Clippy, syscall and wasm checks complete validation of the integrated change.

The canonical compatibility comparison is reproducible with
`python3 ci/check-code-collection-compat.py BEFORE AFTER REPOSITORY`: BEFORE is a CLI built
from `a021978`, AFTER is the current CLI. Its 27 sequential cases compare canonical sessions,
Markdown and AI-BOM bytes after normalizing only observation timestamps. No target is executed.
