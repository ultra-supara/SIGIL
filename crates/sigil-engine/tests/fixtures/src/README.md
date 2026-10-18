# Call-site fixtures (PR-5)

Two kernels kept from v0.1 for the code analyzer's call-site evidence (`binary inspect --code`,
v2 plan §6.2 PR-5, ADR-006):

| File | External calls |
|---|---|
| `suspicious_kernel.c` | `connect` |
| `clean_kernel.c` | none |

`../code/build.sh` builds them, by hand, into `../code/` (PR-5a); the tests read the committed
objects.
