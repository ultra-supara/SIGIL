# ADR-006: Remove the v0.1 IR, SafeISA, and emulator

- **Status:** Accepted. PR-3b-3c-1 implemented it by removing the `sigil-core` crate.
- **Date:** 2026-10-07 (decided in the v2 plan); implemented 2026-10-09.
- **Scope:** the crates of the SIGIL workspace.

## Context

SIGIL 0.1 analyzed native code in `sigil-core`:
- `x86` loaded objects and decoded them with `iced-x86`;
- `ir` lifted them to an IR that is string-typed and single-block;
- `safeisa` mapped the IR to SafeISA, whose emulator handles only a toy subset of instructions;
- `assess` derived capabilities from that path.

The v2 code analyzer has a contract (v2 plan §4.6.5): typed instructions, PLT resolution, and function bounds from FDEs. None of the v0.1 path can be its base (I-11). The provider for that analyzer is chosen in ADR-005, which is an entry in the plan's ADR table (§8.1.1) and not yet a file here.

Since PR-3b-1, no command reaches `sigil-core`, and no crate depends on it.

## Decision

Remove `sigil-core`. Each v0.1 capability ends as follows.

| v0.1 capability | Now |
|---|---|
| SPDX license detection | **Ported** unchanged with its 18 unit tests (`sigil-engine`, `collect::ollama_store::license`) |
| `/proc/net` listener parsing | **Ported and improved**: byte-order independent, with IPv4-mapped cases (`observe::proc::parse`, `exposure_analysis`) |
| Ollama model-store inspection | **Reimplemented** on `SafeFs`, the store collector, and analysis (PR-3a-2; [model store](../model-store.md)) |
| Listener exposure classification and attribution | **Reimplemented** with fd-table attribution and coverage (PR-3a-3; [exposure](../exposure.md)) |
| Exposure from the configured host (`--host`, `OLLAMA_HOST`) | **Deferred** to PR-4 (E4) |
| Ollama API probe | **Reimplemented** as the active mode in `sigil-probe` ([ADR-002](ADR-002-execution-modes.md), PR-3b-2) |
| IR, SafeISA, emulator, `assess` | **Dropped** on purpose |
| Native binary analysis (`lift`, x86 loading) | **Redesigned** for PR-4 and PR-5. The `connect` → network result returns as call-site evidence through `binary inspect --code` |
| AI-BOM v1 output and its Markdown report | **Dropped**. A session is projected to AI-BOM v2 (PR-3b-3a). The v1 schema stays, frozen and tested (`sigil-model/tests/aibom_v1_schema.rs`) |
| Kernel sources `examples/src/*.c` | **Kept** as PR-5 call-site fixtures (`crates/sigil-engine/tests/fixtures/src/`) |

Every removed test is accounted for:
- they were ported, mapped to a v2 test (the "From v0.1" sections of [model store](../model-store.md) and [exposure](../exposure.md)), or dropped with the code above;
- the v1 schema's tests were rewritten on plain JSON.

## Consequences

- SIGIL has no binary analysis until PR-4 and PR-5.
- The AI-BOM v1 schema and the 2026-H1 report stay as history. The viewer names a v1 file and links to both.
- Issues: the v2 plan (§6.4) proposes closing #19 (`trace`) and #20 (`policy-from-source`) as won't-do. It also proposes amending the criteria of #45, #46, #48, #55, and #9, which mention SafeISA, `assess`, or x86 behavior. This ADR records the proposal and changes no issue.
