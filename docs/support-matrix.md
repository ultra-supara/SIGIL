# Binary inspection support

The matrix describes evidence SIGIL can record, subject to the coverage and budgets of each run.
“Partial” means a bounded subset is modeled, not that missing evidence establishes absence.
Both [standalone binary inspection](binary-inspect.md) and the
[Ollama installation scan](runtime-artifacts.md#binaries) collect container facts, import hints,
ELF identity evidence and component claims. Code analysis is available through
`binary inspect --code` and installation inspection with `--code`.

| Input | Container facts | Capability import hints | Identity scans | Direct call sites | Component claims | Loader analysis |
|---|---|---|---|---|---|---|
| ELF64 x86-64, little-endian | [Supported](binary-inspect.md#what-is-recorded) | [Partial: mapped imports](binary-inspect.md#capabilities-and-code---code) | [Partial: selected signatures](binary-inspect.md#signatures) | [Partial: direct calls](binary-inspect.md#capabilities-and-code---code) | [Partial: known ELF components](binary-inspect.md#components) | [Conditional ELF candidates](dependencies-and-values.md#dependency-candidates); backend loader planned |
| ELF64 AArch64, little-endian | [Supported](binary-inspect.md#what-is-recorded) | [Partial: mapped imports](binary-inspect.md#capabilities-and-code---code) | [Partial: selected signatures](binary-inspect.md#signatures) | [Partial: bounded direct calls](binary-inspect.md#capabilities-and-code---code) | [Partial: known ELF components](binary-inspect.md#components) | [Conditional ELF candidates](dependencies-and-values.md#dependency-candidates); backend loader planned |
| ELF32 or big-endian ELF | [Supported, subject to parsing gaps](binary-inspect.md#what-is-recorded) | [Partial: mapped imports](binary-inspect.md#capabilities-and-code---code) | [Partial: selected signatures](binary-inspect.md#signatures) | Unsupported; [architecture work](https://github.com/ultra-supara/SIGIL/issues/48) | [Partial: known ELF components](binary-inspect.md#components) | [Candidates only for the modeled ABIs](dependencies-and-values.md#dependency-candidates) |
| Thin Mach-O | [Supported](binary-inspect.md#what-is-recorded) | [Partial: library-aware imports](binary-inspect.md#mach-o-imports) | Unsupported | Unsupported; [planned](https://github.com/ultra-supara/SIGIL/issues/48) | Planned | [Declared dependencies only](dependencies-and-values.md#dependency-candidates) |
| Fat Mach-O | [Supported per slice](binary-inspect.md#what-is-recorded) | [Partial: per-slice imports](binary-inspect.md#mach-o-imports) | Unsupported | Unsupported; [planned](https://github.com/ultra-supara/SIGIL/issues/48) | Planned | [Declared dependencies only](dependencies-and-values.md#dependency-candidates) |
| Other formats | Unsupported | Unsupported | Unsupported | Unsupported | Unsupported | Unsupported |

The [multiarchitecture evidence contract](session-model.md#multiarchitecture-evidence-reader-m3-a)
is emitted for code requests that recognize AArch64 ELF or Mach-O. AArch64 ELF
now records bounded direct calls and ABI argument locations, with slice diagnostics.
x86-only requests retain the legacy contract. Mach-O code analysis remains unsupported.

**M3-B release status remains incomplete:** mixed marked x86 analysis still has unresolved
aggregate work-budget accounting and alias-reuse behavior. The ELF implementation and its
slice-aware policy do not resolve that resource contract or close
[#48](https://github.com/ultra-supara/SIGIL/issues/48).

ELF candidates describe possible matches within collected placements, not the library actually
loaded or a symbol binding. The modeled ABIs and loader gaps are described in
[dependency candidates](dependencies-and-values.md#dependency-candidates).

An absent hint does not establish that a capability is absent: statically linked code, dynamic
lookups and raw system calls can bypass import hints. Go function-name hints indicate names
present, not calls. An absent direct call site does not exclude indirect calls or code outside
the searched scope. An absent component claim does not establish that the component is absent.
Consult coverage for unsupported inputs, incomplete reads and budget limits. Canonical output is
deterministic for the same session value; separate inspections record their own timestamps.
