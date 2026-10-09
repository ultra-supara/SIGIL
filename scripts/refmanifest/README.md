# Reference manifests

`crates/sigil-engine/refs/ollama-official/` holds, for each official Ollama release
(linux-amd64):

- `ollama-<tag>-linux-amd64.json`: every archive member with its type (`"0"` file, `"2"` symlink,
  `"5"` directory), mode, and, for a file, its size and SHA-256, for a symlink its target;
- `ollama-<tag>-linux-amd64.tar.zst.sha256`: the archive's SHA-256, equal to the digest published
  with the release.

They were produced in PR-0 by `tar_manifest.py`, which hashes every member of the tar stream
without extracting anything. SIGIL embeds them unchanged and never runs the script. To add a
release:

```bash
sha256sum ollama-linux-amd64.tar.zst            # must equal the digest published on the release
zstd -dc ollama-linux-amd64.tar.zst | python3 -I tar_manifest.py ollama-<tag>-linux-amd64.json <tag>
```

Add both files to `crates/sigil-engine/refs/ollama-official/` and to `OFFICIAL` in
`crates/sigil-engine/src/reference.rs`, update the pinned set SHA-256 in
`crates/sigil-engine/tests/refset.rs`, and release a new SIGIL version.

Matching a file against these is a comparison with the official archives' contents. It is not a
signature check.
