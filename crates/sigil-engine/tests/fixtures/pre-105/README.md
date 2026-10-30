# Sessions saved before #105

`16-binary-code.json` is `schemas/examples/session-v1/16-binary-code.json` byte for byte as main
`0b18437` has it, before #105 added libc++'s names to the capability table. It records the table
it was made with, SHA-256 `432f71b2a3c5f25663e699d5447db24b27590a4dad5ed1186b0f30ac89b26944`.
`tests/evaluate.rs` checks that a later build refuses to judge it under a capability denial and
evaluates it as before without one (#106's contract).

It is the golden example that sigil-model's builders write (`"version": "0.0.0-example"`), not
`sigil binary inspect` output. At `0b18437`, `example_hints` checked that its hints are exactly the
ones table `432f71b2…` derives, so it is a faithful session made with the old table.

How it was made:

```sh
git show 0b18437:schemas/examples/session-v1/16-binary-code.json > 16-binary-code.json
```

SHA-256:

```
13766f762e31c6a37eaf8309f639850125cb92bbd964d01eb6476ecd3f015da5  16-binary-code.json
```

If it ever stops parsing or validating, that is a `sigil-session/1` compatibility break: fix the
reader, not the file. Never re-bless it.
