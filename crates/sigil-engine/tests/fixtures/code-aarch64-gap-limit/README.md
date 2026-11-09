# AArch64 mandatory-layout-gap boundary fixtures

Static assembler inputs; never executed. Each object has an independent `healthy`
function calling `connect`, then `many` with 255, 256 or 257 calls to `execve`.
The latter has no archived complete ABI layout, requiring one exact diagnostic per
call. CFI supplies separate FDE bounds. Tests consume committed bytes, not a compiler.

Rebuild each N in 255, 256, 257 with:

```sh
clang-19 --target=aarch64-linux-gnu -DCALLS=N -c calls.S -o calls-N.o
```

Compiler used:
```text
Debian clang version 19.1.7 (22)
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/lib/llvm-19/bin
```

The 257 boundary reproduces Task10 independent-review P2. Tests require earlier
healthy evidence to survive failure of the entire `many` function transaction.
