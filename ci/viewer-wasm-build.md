# Rebuilding the viewer wasm bundle

The browser serves the committed files in `site/viewer/pkg/`. Run the build below
after changing the model or wasm bindings, then commit the regenerated package.
CI compares every file with a fresh build and checks rendering against the native
renderer. Ordinary native builds still use stable Rust and their existing profiles.

## Pinned build (Linux x86-64)

From the repository root:

```sh
rustup toolchain install "$(cat ci/viewer-wasm-toolchain)" \
  --target wasm32-unknown-unknown --component rust-src
cargo install wasm-pack --version 0.15.0 --locked
ci/install-viewer-wasm-opt.sh "$PWD/target/viewer-binaryen"
export PATH="$PWD/target/viewer-binaryen/binaryen-version_$(cat ci/viewer-wasm-opt-version)/bin:$PATH"
RUSTUP_TOOLCHAIN=$(cat ci/viewer-wasm-toolchain) ci/build-viewer-wasm.sh
```

The installer verifies the official Binaryen archive against
[`viewer-wasm-opt.sha256`](viewer-wasm-opt.sha256). On other platforms, install the
same Binaryen version from its [official release](https://github.com/WebAssembly/binaryen/releases/tag/version_133).
Linux x86-64 is the tested release environment; CI's byte comparison is authoritative.
An optional output directory keeps a trial build separate:

```sh
RUSTUP_TOOLCHAIN=$(cat ci/viewer-wasm-toolchain) \
  ci/build-viewer-wasm.sh /tmp/rebuilt-viewer
diff -r site/viewer/pkg /tmp/rebuilt-viewer
gzip -c site/viewer/pkg/sigil_wasm_bg.wasm | wc -c
```

The build pins `nightly-2026-01-20`, wasm-pack 0.15.0, wasm-bindgen through
`Cargo.lock`, and Binaryen 133. The dated nightly also fixes the standard-library
source and its own lockfile. Cargo runs with `--locked`. Source paths are remapped;
an inherited `CARGO_ENCODED_RUSTFLAGS` is cleared so it cannot replace the build's
flags.

## Size settings and tradeoffs

[`build-viewer-wasm.sh`](build-viewer-wasm.sh) applies `opt-level=z`, fat LTO,
one codegen unit, and `panic=immediate-abort` only to this build. It rebuilds `std`
and `panic_abort`, and omits panic locations with `-Zlocation-detail=none`.
[Building the standard library](https://doc.rust-lang.org/cargo/reference/unstable.html#build-std)
and immediate-abort require the pinned nightly and `rust-src`.

Unexpected Rust panics trap immediately without formatting a panic message or
running panic hooks. This sacrifices internal panic diagnostics. Validation errors
returned to JavaScript retain their messages; bounds checks and traps are retained.
No renderer, parser, validation rule, or public export was removed.

Binaryen orders functions before optimization, runs `-Oz` with a bounded
single-caller inline threshold of 25, flattens/restructures control flow, runs
`-Oz` again, then orders functions and strips custom metadata. The exact ordered
pass sequence is in the build script. Function ordering and inline thresholds were
chosen by **gzip size**, which can grow even when the uncompressed wasm shrinks.
No trap-ignoring or fast-math option is used.

## Measurements for #107

Measured against source commit `1e2a980584edc105e464d6b2e9626bae689d9185` on Linux
x86-64. Sizes use the CI command above (default gzip level and filename header).
The final result is **256,433 bytes gzip**, down **48.17%** from 494,725. Raw wasm
falls from 2,124,516 to 1,103,506 bytes. The selected margin is **at least 45% of the
512,000-byte budget free**; the result leaves **255,567 bytes (49.92%)** free.
This is a measured minimum among the configurations tried, not a global optimum.

| Configuration | gzip bytes |
|---|---:|
| Original Rust 1.93.0 build | 494,725 |
| Original + Binaryen `-Oz` | 502,185 |
| `opt-level=z` alone | 414,124 |
| `opt-level=s` alone | 439,319 |
| Fat LTO alone | 494,817 |
| One codegen unit alone | 507,386 |
| `panic=abort` alone | 494,756 |
| `s` + fat LTO + one codegen unit + abort | 421,236 |
| Above + `-Oz` | 383,052 |
| `z` + fat LTO + one codegen unit + abort | 395,246 |
| Above + `-Oz` | 344,838 |
| Above, stripping metadata without `-Oz` | 289,430 |
| Best tested stable pass sequence, including ordering and bounded inlining | 272,561 |
| Same sequence, nightly with prebuilt standard library | 267,678 |
| Same sequence, nightly with rebuilt standard library | 265,287 |
| Same sequence, immediate-abort | 257,295 |
| Same sequence, immediate-abort and no panic locations | 257,134 |
| Final: inline threshold 25 and function ordering before and after optimization | **256,433** |

[`viewer-wasm-measurements.csv`](viewer-wasm-measurements.csv) records all 141
successful configurations, their settings, raw/gzip sizes, byte equality, and
behavior checks. A `base` setting names the unoptimized input row; `wasm-opt` gives
the version and ordered arguments. Rust rows start from the original build; the
CSV records extra Rust flags separately from the common path remapping. Nightly
rows use `-Zbuild-std=std,panic_abort --locked` except `nightly-prebuilt`;
immediate-abort rows also use `-Zpanic-immediate-abort`.

For every Rust configuration, two builds started with separate empty Cargo target
directories. Each Binaryen configuration processed both independently built
inputs. All package files were compared byte for byte. Both results passed the
existing checks using 41 valid fixtures (viewer samples plus both schema example
sets), eight invalid fixtures, and the six viewer state tests. The production
script was then run twice with empty target directories, yielding exactly the
selected experimental package.

A further differential check compared the original and final bundles on 5,771
documents, including missing/replaced fields, truncated JSON, and primitive input.
Public exports, schema detection, rendered reports, validation messages, and HTML
escaping matched. Both instances used 1,441,792 bytes of wasm memory after that
comparison. To repeat it, save the old package before rebuilding, then run:

```sh
node ci/compare-viewer-wasm.mjs /path/to/old/pkg site/viewer/pkg
```

The hard CI limit remains **512,000 bytes (500 KiB)**. Above **460,800 bytes (90%)**,
CI emits a warning while allowing the build; above the hard limit it fails. Each
PR's job summary reports raw size, gzip size, thresholds, and remaining bytes.
Re-measure when changing tool versions or model code; the best pass ordering can
change with the input.
