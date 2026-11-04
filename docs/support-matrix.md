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
| ELF64 AArch64 | [Supported](binary-inspect.md#what-is-recorded) | [Partial: mapped imports](binary-inspect.md#capabilities-and-code---code) | [Partial: selected signatures](binary-inspect.md#signatures) | Unsupported; [planned](https://github.com/ultra-supara/SIGIL/issues/48) | [Partial: known ELF components](binary-inspect.md#components) | [Conditional ELF candidates](dependencies-and-values.md#dependency-candidates); backend loader planned |
| ELF32 or big-endian ELF | [Supported, subject to parsing gaps](binary-inspect.md#what-is-recorded) | [Partial: mapped imports](binary-inspect.md#capabilities-and-code---code) | [Partial: selected signatures](binary-inspect.md#signatures) | Unsupported; [architecture work](https://github.com/ultra-supara/SIGIL/issues/48) | [Partial: known ELF components](binary-inspect.md#components) | [Candidates only for the modeled ABIs](dependencies-and-values.md#dependency-candidates) |
| Thin Mach-O | [Supported](binary-inspect.md#what-is-recorded) | [Partial: library-aware imports](binary-inspect.md#mach-o-imports) | Unsupported | Unsupported; [planned](https://github.com/ultra-supara/SIGIL/issues/48) | Planned | [Declared dependencies only](dependencies-and-values.md#dependency-candidates) |
| Fat Mach-O | [Supported per slice](binary-inspect.md#what-is-recorded) | [Partial: per-slice imports](binary-inspect.md#mach-o-imports) | Unsupported | Unsupported; [planned](https://github.com/ultra-supara/SIGIL/issues/48) | Planned | [Declared dependencies only](dependencies-and-values.md#dependency-candidates) |
| Other formats | Unsupported | Unsupported | Unsupported | Unsupported | Unsupported | Unsupported |

The #48 M3-A [multiarchitecture evidence reader](session-model.md#multiarchitecture-evidence-reader-m3-a)
adds schema and validation for future slice-specific code evidence. Inspection writers
still omit its optional marker. This milestone enables no AArch64 or Mach-O direct-call
analyzer and leaves #48 open; the support entries above continue to describe collected evidence.

ELF candidates describe possible matches within collected placements, not the library actually
loaded or a symbol binding. The modeled ABIs and loader gaps are described in
[dependency candidates](dependencies-and-values.md#dependency-candidates).

An absent hint does not establish that a capability is absent: statically linked code, dynamic
lookups and raw system calls can bypass import hints. Go function-name hints indicate names
present, not calls. An absent direct call site does not exclude indirect calls or code outside
the searched scope. An absent component claim does not establish that the component is absent.
Consult coverage for unsupported inputs, incomplete reads and budget limits. Canonical output is
deterministic for the same session value; separate inspections record their own timestamps.
