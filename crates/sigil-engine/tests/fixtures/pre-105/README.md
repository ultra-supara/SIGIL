# Sessions saved before #105

`16-binary-code.json` is `schemas/examples/session-v1/16-binary-code.json` byte for byte as main
`0b18437` has it, before #105 added libc++'s names to the capability table. It records the table
it was made with, SHA-256 `432f71b2a3c5f25663e699d5447db24b27590a4dad5ed1186b0f30ac89b26944`.
`tests/evaluate.rs` checks that a later build refuses to judge it under a capability denial and
evaluates it as before without one (#106's contract). Never re-bless it.
