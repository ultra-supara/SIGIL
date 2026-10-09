# Sessions written before PR #76

These three files are real output of the PR #75 CLI, the `sigil-session/1` writer as of
`66e761b` (main, after #75 was merged). They are kept byte for byte, as that CLI wrote them. They
have no `request.active` and no `probes`, the fields that PR #76 added. `tests/compat.rs` and the
CLI tests check that this SIGIL still reads them.

| File | Store | Outcome |
|---|---|---|
| `pass-complete.json` | one model with a license layer | PASS, COMPLETE |
| `warn.json` | one model without a license layer | WARN (`model.license_missing`), COMPLETE |
| `incomplete.json` | a models directory that does not exist | PASS, INCOMPLETE (`model_store.inventory` unavailable) |

How they were made: the stores were built by a script with one manifest at
`manifests/registry.ollama.ai/library/tiny/latest`, a `weights` model blob, a `{}` config blob,
and, for the licensed store, an `MIT License` license blob. Then, with the CLI built from
`66e761b`:

```sh
sigil inspect ollama --models-dir <dir>/licensed   --out out/pass-complete.json
sigil inspect ollama --models-dir <dir>/unlicensed --out out/warn.json
sigil inspect ollama --models-dir <dir>/absent     --out out/incomplete.json
```

The root paths, user, kernel, and times are those of the machine and run that wrote them. Nothing
reads the stores again.

SHA-256:

```
d8216a44d2ab67fe5374a4d34b48f53369286630a14d21362d3c07a5fbfb5cd6  incomplete.json
5cfd7793be034d6a9222b437823d846891f91a742e6fc822a0c983883812f78d  pass-complete.json
b1e1c27e13786075ca504eae9fdb47ffff00694b36793337038dfdd7fe29493e  warn.json
```
