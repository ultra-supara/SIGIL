# SIGIL Schemas

Machine-readable contracts for SIGIL outputs.

## Current schemas

- `aibom-v1.schema.json` — AI-BOM JSON contract for `schema_version: "1.x"`.
  JSON Schema draft 2020-12. Self-contained (no external `$ref`).
  Strict: `additionalProperties: false` on every object — accidental
  field drift fails validation rather than being silently absorbed.
  Validated against every live AI-BOM produced by `sigil-core` in
  `crates/sigil-core/tests/aibom_schema.rs`.

## Versioning

Future breaking changes publish a new file (e.g. `aibom-v2.schema.json`)
and keep the previous version intact for older consumers. The `$id` of
each schema is version-stamped, so a consumer that pinned v1 keeps
working when v2 ships.

Within a major version, additive fields require a minor `schema_version`
bump (e.g. `"1.1"` → `"1.2"`) and a corresponding additive edit to this
schema's `properties` / `required` block, both in the same change.
