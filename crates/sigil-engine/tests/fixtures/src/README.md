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
[`../code/README.md`](../code/README.md). `crates/sigil-cli/tests/cli.rs` runs
`sigil binary inspect` end to end on some of the built files:
- with `--code`: `suspicious_kernel-gcc-O2.o`, `cfg.so`, `clean_kernel-gcc-O2.o`, and
  `net-plt-gcc.so` (with `--budget binary_imports=0`);
- without it: `suspicious_kernel-gcc-O2.o`, `clean_kernel-gcc-O2.o`, `net-plt-gcc.so` (and a
  stripped copy), and `dl.so`.

`crates/sigil-cli/tests/safety/cli.rs` runs it with `--code`, under strace, on
`suspicious_kernel-gcc-O2.o` and `net-plt-gcc.so`.
