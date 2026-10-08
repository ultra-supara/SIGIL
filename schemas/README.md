# SIGIL Schemas

Machine-readable contracts for SIGIL outputs.

## Current schemas

- `aibom-v1.schema.json` — AI-BOM JSON contract for `schema_version: "1.x"`.
  JSON Schema draft 2020-12. Self-contained (no external `$ref`).
  Strict: `additionalProperties: false` on every object — accidental
  field drift fails validation rather than being silently absorbed.
  Validated against every live AI-BOM produced by `sigil-core` in
  `crates/sigil-core/tests/aibom_schema.rs`.
- `session-v1.schema.json` — the analysis session (`schema: "sigil-session/1"`),
  the source of truth that later exports (AI-BOM v2, Markdown) are derived
  from. Defined by `crates/sigil-model`; see `docs/session-model.md`.
  Same conventions as above. Enums are externally tagged with their variant
  names; struct fields are snake_case; every field is always serialized, so
  every property is required. `$defs/SessionExcerpt` has the same fields,
  all optional, for documentation excerpts.
  - `crates/sigil-model/tests/schema.rs` checks that the schema's properties
    and variants equal the Rust model's and that every variant has a sample
    that validates.
  - Passing the schema is necessary but not sufficient: `Session::validate`
    checks references and claim invariants a schema cannot express.
  - `examples/session-v1/` holds specification examples (labeled
    `tool.version: "0.0.0-example"`), not SIGIL measurements. Each one is
    produced by a builder in `crates/sigil-model/tests/common`, validated,
    and compared with the committed file.
  - Not emitted by the CLI yet (PR-3b). Until then the schema may still
    change in place.

## Versioning

Future breaking changes publish a new file (e.g. `aibom-v2.schema.json`)
and keep the previous version intact for older consumers. The `$id` of
each schema is version-stamped, so a consumer that pinned v1 keeps
working when v2 ships.

Additive changes within a major version:

- A new **required** field bumps `schema_version` (e.g. `"1.1"` → `"1.2"`)
  and extends both `properties` and `required` in this schema in the same
  change.
- A new **optional** field (an `#[serde(skip_serializing_if = "Option::is_none")]`
  in Rust) bumps `schema_version` and extends `properties` only — `required`
  is unchanged. Old consumers can still read v1.x output by ignoring the new
  field; new consumers can detect it by inspecting `schema_version`.
