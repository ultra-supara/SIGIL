The numbered session and AI-BOM samples are exact copies of their schema examples.
Native renderer tests validate them; `ci/check-committed-wasm.mjs` compares their
Markdown and HTML with the committed browser bundle and refuses every invalid
sample named in `invalid/manifest.json`.

Examples 23–27 use the committed `code-macho` fixtures: same-name libSystem/libfoo,
healthy universal, mixed supported/unsupported universal, installation object with
Unbound calls, and an arm64 chained fixture whose pointer-format field is changed
to unsupported authenticated format 1. The last is a valid partial observation,
not an invalid session. No calls are invented from its unsupported chain.
They use a policy named `macho-examples`, empty `binary_audit`, and a `fail` denial
of `posix.network` with reason `example denies admitted network calls`.

Example 28 is a coherent synthetic saved-session mutation of example 23's
observation: a libc++-mapped C++ symbol has two exact imports, but its only call
names libSystem. It must retain the no-admitted-call question and display
`none found`, without borrowing the libc++ import's mapping. Its policy is
`cxx-pinned`, with empty `binary_audit` and a `fail` denial of `cxx.file_write`
(reason `test`). This session checks the archived mapping in the viewer; it is
not an independent binary oracle. Unknown archive hashes are refused separately.

Example paths, tool metadata, observation times and filesystem identities are
normalized for publication. Fixture digests, slice identities, instructions,
import witnesses and code budgets in 23–27 come from static inspection. AI-BOMs
are CLI projections using each normalized session's canonical SHA-256. Saved
verification checks policy consistency; it does not authenticate edited facts.
