# Reference manifests

`crates/sigil-engine/refs/ollama-official/` holds, for each official Ollama release
(linux-amd64):

- `ollama-<tag>-linux-amd64.json`: every archive member with its type (`"0"` file, `"2"` symlink,
  `"5"` directory), mode, and, for a file, its size and SHA-256, for a symlink its target;
- `ollama-<tag>-linux-amd64.tar.zst.sha256`: the archive's SHA-256, equal to the digest published
  with the release;

and, for all of them, `commits.toml` (PR-4c-2c): the value each release's own files report for
each embedded commit field (`role = "commit"` in `crates/sigil-engine/signatures/components.toml`),
with the member it is read from.

The manifests were produced in PR-0 by `tar_manifest.py`, which hashes every member of the tar
stream without extracting anything. SIGIL embeds them unchanged and never runs the script. To add a
release:

```bash
sha256sum ollama-linux-amd64.tar.zst            # must equal the digest published on the release
zstd -dc ollama-linux-amd64.tar.zst | python3 -I tar_manifest.py ollama-<tag>-linux-amd64.json <tag>
```

Add the `.json` manifest to `crates/sigil-engine/refs/ollama-official/` and to `OFFICIAL` in
`crates/sigil-engine/src/reference.rs`; keep the `.tar.zst.sha256` file beside it (it is not in
`OFFICIAL`). Add the release's `commits.toml` entry: run
`sigil inspect ollama --install-dir <DIR>` on an unmodified install of it, and take each commit
field's value from the session JSON, in the claim whose subject slice has the member's SHA-256
(its `Embedded` assertions); the member's SHA-256 must be the manifest's. A release whose files
report no commit gets no entry (an empty entry is refused). Then update the set's version and
pinned SHA-256 in `crates/sigil-engine/src/reference.rs` and `crates/sigil-engine/tests/refset.rs`,
and the tests `every_release_reports_llama_commit_and_ggml_commit` and
`the_official_set_has_three_releases_of_34_files_17_symlinks_3_directories` there, and the set
table in `docs/runtime-artifacts.md`. Release a new SIGIL version.

Matching a file against these is a comparison with the official archives' contents. It is not a
signature check.
