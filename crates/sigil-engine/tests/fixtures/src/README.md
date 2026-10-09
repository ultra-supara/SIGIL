# Call-site fixtures (PR-5)

Two kernels kept from v0.1 for the code analyzer's call-site evidence (`binary inspect --code`,
v2 plan §6.2 PR-5, ADR-006):

| File | External calls |
|---|---|
| `suspicious_kernel.c` | `connect` |
| `clean_kernel.c` | none |

No test builds them yet. v0.1 compiled them at test time and never committed the objects:

    clang -target x86_64-unknown-linux-gnu -O0 -c <src> -o <obj>

PR-5 decides how fixtures are built and checked.
