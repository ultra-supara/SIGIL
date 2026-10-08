# Model store (`sigil-engine`)

SIGIL inventories an Ollama-format model store and checks each model's blobs against the digests
its manifest names.

- **Status:** `sigil_engine::inspect::store_session` builds a static-mode session. The CLI uses it
  from PR-3b; until then the v0.1 `runtime inspect ollama` is unchanged.
- **Source:** plan §4.6.7 and the migration table (§6.3). The session types are described in
  [`docs/session-model.md`](session-model.md); policy and outcome in [`docs/policy.md`](policy.md).

## Layout

```
<models dir>/                       scan root `models`
  manifests/<registry>/<namespace...>/<model>/<tag>
  blobs/sha256-<64 lowercase hex>
```

- A manifest path names the model. The display name follows Ollama's `Name.DisplayShortest`:
  - `registry.ollama.ai/library/gemma4/e2b` → `gemma4:e2b`;
  - `registry.ollama.ai/acme/gemma4/e2b` → `acme/gemma4:e2b`;
  - `hf.co/acme/gemma4/e2b` → `hf.co/acme/gemma4:e2b`.
- The default host and namespace are recognized case-insensitively. Other parts keep their
  casing.
- A path with fewer than three parts under `manifests/` is not a model
  (`model.provenance_unknown`).
- The model ID is `model:models/<path under manifests/>`. Unlike the display name, it never
  collides.

## What is read, and what is not

| Item | Read | Not read |
|---|---|---|
| `manifests/` | Walked through SafeFs: sorted, bounded, loops end | FIFOs, sockets, devices, dangling links. A link out of the scan roots is recorded, and makes the inventory `Partial` |
| A manifest | Up to 1 MiB (`manifest_bytes`), once | A larger one: `BudgetExceeded` on that manifest |
| A blob | Only for a well-formed digest (`sha256:` + 64 lowercase hex digits), at `blobs/sha256-<hex>`, once per run, hashed as a stream | A malformed digest is never looked up. A blob reached through a link out of the scan roots is recorded with `OutsideScanRoots` |
| The license | The first 4096 bytes of the license layer's blob (`application/vnd.ollama.image.license`), for an SPDX identifier and a 256-byte excerpt | — |

The model filter (`model_filter`, an exact display name) applies before a manifest is read. Other
manifests are never opened.

## Rules and coverage

| Rule | Default | When | Coverage |
|---|---|---|---|
| `model.manifest_digest_malformed` | FAIL | a digest is malformed (uppercase hex included) | integrity `Partial` |
| `model.blob_missing` | WARN | a well-formed digest's blob is confirmed absent | integrity `Partial` |
| — | — | the blob's path could not be resolved (permission, too many links, I/O): unknown, not absent | integrity `Partial` |
| `model.blob_digest_mismatch` | FAIL | the blob's contents hash to another digest | integrity checked |
| — | — | the blob exists but was not read | integrity `Partial` |
| `model.license_missing` | WARN | no license layer | license checked |
| — | — | the license layer's digest is malformed or its blob is missing | license `Partial` |
| — | — | the license layer's blob exists but was not read, or could not be resolved | license `Error` |
| `model.manifest_unparseable` | WARN | a manifest that is not JSON, or a descriptor without a string digest | inventory `Error` on that manifest |
| `model.provenance_unknown` | WARN | a path too shallow to name a model; never reported with a filter | — |
| `model.not_found` | WARN | a filter matched no manifest, and the listing of `manifests/` was complete | — |

- **`model_store.inventory`** is recorded on the root:
  - `Complete` when `manifests/` was walked and every listed manifest was reached;
  - `Unavailable(NotFound)` when it does not exist;
  - `Partial` or `BudgetExceeded` when the walk could not see everything, or a listed manifest
    could not be reached (it vanished, or its path could not be resolved).

  A manifest that was reached but not read adds its own entry.
- **How a blob lookup ended is recorded** (`BlobLookup`): `Found`, `Absent` (nothing at the
  path), `Unresolved` (the path could not be resolved), or `NotLookedUp` (malformed digest). Only
  `Absent` supports `model.blob_missing`.
- **`model_store.integrity`** and **`model_store.license`** are recorded per model. With no models,
  they have no entry, so they stay open.
- A missing models directory therefore gives `PASS` + `INCOMPLETE`, never a clean `PASS` (I-01).
- **A file that changed while it was read supports no claim.** SafeFs records `ChangedDuringRead`
  or `Vanished` when the file's metadata or identity changed across the read. What was read is
  kept, but:
  - a blob leaves integrity `Partial`, with no mismatch finding;
  - the license blob leaves the license check `Partial`;
  - a manifest yields no finding about its model, and leaves its inventory, integrity, and license
    `Partial`;
  - an unparseable manifest yields no `model.manifest_unparseable`; its inventory stays `Error`.

Each finding has one `Observed` condition naming the files it rests on: the manifest, and for a
mismatch the blob and what it holds. Findings about one layer carry its index in their ID.

## From v0.1

v0.1's tests stay until PR-3b removes `sigil-core`. Each v0.1 case maps to a v2 test as follows.

**`crates/sigil-core/tests/ollama.rs`**

| v0.1 test | v2 |
|---|---|
| `inventories_ollama_model_store_manifest_and_blobs` | `store_session::a_complete_store_passes_and_is_complete`, `ollama_store::one_model_is_inventoried_with_its_blobs_read` |
| `flags_manifest_blob_digest_mismatch_as_fail` | `store_session::a_tampered_blob_fails` |
| `rejects_manifest_digest_with_path_separators_before_blob_lookup` | `store_session::a_malformed_digest_is_fail_and_leaves_integrity_open`, `layout::only_a_well_formed_digest_has_a_blob_path` |
| `license_layer_is_extracted_with_spdx_id` | `ollama_store::the_license_text_is_read_from_the_license_layer` |
| `apache_2_0_license_body_is_detected_as_spdx_id`, `full_bsd_3_clause_body_is_not_misidentified_as_bsd_2_clause` | `store_session::license_bodies_are_identified` |
| `missing_license_layer_emits_warn_not_fail` | `store_session::a_missing_license_layer_warns_and_the_check_is_complete` |
| `shallow_manifest_path_is_flagged_as_unknown_provenance` | `store_session::provenance_unknown_is_reported_only_without_a_filter` |
| the 10 display-name and filter cases | `layout` unit tests, `store_session::the_filter_round_trips_display_names` |
| `runtime_public_bind_listener_warns`, `runtime_localhost_listener_keeps_pass`, `runtime_lan_listener_warns` | [`docs/exposure.md`](exposure.md) (PR-3a-3) |
| `flags_public_bind_host_as_warn_without_network_probe`, `treats_scheme_less_loopback_host_as_local`, `flags_non_local_network_host_as_warn_without_probe` | PR-4 (configured host, E4) |
| `renders_ai_bom_with_model_runtime_and_files`, `ai_bom_includes_runtime_exposure_and_binds`, `ai_bom_runtime_exposure_unknown_when_disabled` | PR-3b (AI-BOM v2) |

**Other v0.1 tests**

- **The 18 SPDX unit tests** in `sigil-core/src/ollama.rs` are ported unchanged to `license`.
- **The 21 listener unit tests** are mapped in [`docs/exposure.md`](exposure.md).
- **The 4 CLI tests** in `sigil-cli/tests/ollama_cli.rs` move to PR-3b.

**New in v2:** each migration row has a test, stated on the outcome (`store_session`). The
adversarial store cases are in `ollama_store`:
- a symlink loop and a FIFO under `manifests/`;
- a manifest over the limit;
- an unparseable manifest next to a good one;
- blobs symlinked inside and outside the store;
- an unreadable blob;
- uppercase and path-like digests.
