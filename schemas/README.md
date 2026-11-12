# SIGIL Schemas

Machine-readable contracts for SIGIL outputs.

## Current schemas

- `session-v1.schema.json`: the analysis session (`schema: "sigil-session/1"`). It is the source of truth that every export (AI-BOM v2, Markdown) is derived from. Defined by `crates/sigil-model`; see `docs/session-model.md`.
  - JSON Schema draft 2020-12, self-contained (no external `$ref`), strict (`additionalProperties: false` on every object). Enums are externally tagged with their variant names, and struct fields are snake_case.
  - SIGIL writes every field. Every property is required, except the fields added to `sigil-session/1` later (from `request.active` and `probes`, PR #76, to `ProcessObs.maps_read`, PR-4d-2; `docs/session-model.md` lists them). Those are optional on read, and a missing one reads as what a session without it did: an empty list, `false`, or `NotRead`.
  - The schema is backward compatible, not forward compatible: an earlier SIGIL may refuse a newer session.
  - `$defs/SessionExcerpt` has the same fields, all optional, for documentation excerpts.
  - `crates/sigil-model/tests/schema.rs` checks that the schema's properties and variants equal the Rust model's, and that every variant has a sample that validates. `tests/compat.rs` reads real sessions written before PR #76.
  - Passing the schema is necessary but not sufficient: `Session::validate` checks references and claim invariants a schema cannot express.
  - `examples/session-v1/` holds specification examples (labeled `tool.version: "0.0.0-example"`), not SIGIL measurements. Each one is produced by a builder in `crates/sigil-model/tests/common`, validated, and compared with the committed file.
- `aibom-v2.schema.json`: the AI-BOM v2 (`schema: "sigil-aibom/2"`), a projection of a session that names it by the SHA-256 of its canonical JSON. Defined by `sigil_model::render::aibom`; see `docs/ai-bom-and-comparison.md`.
  - Same conventions as the session schema. Every field is written and required.
  - Definitions shared with the session (`Outcome`, `Ref`, `ApiProbe`, IDs, …) are copied from `session-v1.schema.json`. `crates/sigil-model/tests/aibom_schema.rs` keeps them equal, and checks the AI-BOM types' names and variants as for the session.
  - `examples/aibom-v2/` holds the AI-BOMs of the session examples, with the same names. `crates/sigil-model/tests/aibom.rs` compares them with their projections.
- `diff-v1.schema.json`: the comparison of two sessions (`schema: "sigil-diff/1"`), written by `sigil compare`. Defined by `sigil_model::diff`; see `docs/ai-bom-and-comparison.md`. Each side records its session's `completeness`, and each diff its `evaluation` under a compare policy: the policy, the action of every change kind and the treatment of every cause, the verdict, and the completeness. A reader judges a diff again and refuses one whose recorded result a fresh judgment does not give. `sigil-diff/1` was revised before its first release (PR-16b): diffs that main wrote between #136 and that change neither validate nor load.
  - Same conventions as the session schema. Every field is written and required.
  - Definitions shared with the session (`Ref`, `Completeness`, IDs, …) are copied from `session-v1.schema.json`, and `ReleaseBasisKind` from `aibom-v2.schema.json`. `crates/sigil-model/tests/diff_schema.rs` keeps them equal and checks the diff types' names and variants.
  - `examples/diff-v1/<case>/` holds a pair of sessions (`baseline.json`, `current.json`), their diff and its Markdown. The sessions are written in canonical form, so each file hashes to the SHA-256 its diff records. `crates/sigil-model/tests/diff_examples.rs` compares them with the builders; regenerate with `SIGIL_BLESS=1 cargo test -p sigil-model --test diff_examples golden_pairs_match_the_builders`.
- `aibom-v1.schema.json`: the AI-BOM of SIGIL 0.1 (`schema_version: "1.x"`). Kept for the reports it wrote (`reports/2026-h1/`). SIGIL v2 no longer writes it, and an AI-BOM v1 document is not an AI-BOM v2.

## Versioning

Breaking changes publish a new file (as `aibom-v2.schema.json` did for
AI-BOM v1) and keep the previous version intact for older consumers. The `$id` of
each schema is version-stamped, so a consumer that pinned v1 keeps
working when v2 ships.

Within a version:

- **`sigil-session/1` and `sigil-aibom/2`:** a field added later is optional on read. It is `#[serde(default)]` and left out of `required`, so files written before it still load (backward compatible). SIGIL always writes it. Types deny unknown fields, so an earlier SIGIL may refuse a newer file (not forward compatible). A change that readers must not ignore needs a new version (`sigil-session/2`, `sigil-aibom/3`).
- **AI-BOM v1 (`schema_version: "1.x"`, historical):** a new required field bumped `schema_version` (e.g. `"1.1"` → `"1.2"`) and extended both `properties` and `required`. A new optional field (`skip_serializing_if`) bumped `schema_version` and extended `properties` only.
