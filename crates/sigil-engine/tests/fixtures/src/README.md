# Call-site fixtures (PR-5)

Two kernels kept from v0.1 for the code analyzer's call-site evidence (`binary inspect --code`,
v2 plan §6.2 PR-5, ADR-006):

| File | External calls |
|---|---|
| `suspicious_kernel.c` | `connect` |
| `clean_kernel.c` | none |

`../code/build.sh` builds them, by hand, into `../code/` (PR-5a); the tests read the committed
objects.

The other code fixtures, and the shape of each, are listed in
[`../code/README.md`](../code/README.md). The CLI tests run `sigil binary inspect` on some of the
built files, `suspicious_kernel-gcc-O2.o` among them: end to end in `crates/sigil-cli/tests/cli.rs`
(with and without `--code`), and with `--code` under strace in
`crates/sigil-cli/tests/safety/cli.rs`.
