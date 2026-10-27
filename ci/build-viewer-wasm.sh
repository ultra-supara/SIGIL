#!/bin/sh
# Builds the viewer's wasm bundle reproducibly: the same source gives the same bytes on any machine.
# CI rebuilds it and requires every file to equal the committed site/viewer/pkg/ (wasm.yml).
#
#   ci/build-viewer-wasm.sh [OUT_DIR]      (default: site/viewer/pkg)
#
# What is pinned:
# - rustc: the version in ci/viewer-wasm-toolchain (the build stops on any other; run with
#   RUSTUP_TOOLCHAIN=<that version> after `rustup toolchain install <version> --target
#   wasm32-unknown-unknown --component rust-src`);
# - wasm-pack 0.15.0, and wasm-bindgen through Cargo.lock (wasm-pack fetches the matching CLI);
# - Binaryen: ci/viewer-wasm-opt-version; the Linux installer checks the archive's SHA-256;
# - the viewer's release settings and rebuilt std, including its rust-src Cargo.lock. These
#   settings apply only inside this script; ordinary native builds keep their own profiles;
# - paths: dependency sources live under CARGO_HOME, which differs per machine and would be
#   embedded in panic locations, so it is remapped to /cargo. A local rust-src copy is remapped
#   to /rustc/<commit>, as std is built. Workspace crates are built with relative paths.
set -eu
cd "$(dirname "$0")/.."
out="${1:-site/viewer/pkg}"
want=$(cat ci/viewer-wasm-toolchain)
have=$(rustc --version)
if ! expected=$(rustup run "$want" rustc --version 2>/dev/null) || [ "$have" != "$expected" ]; then
  echo "error: the viewer bundle requires $want (ci/viewer-wasm-toolchain); active compiler: $have." >&2
  echo "       Run: rustup toolchain install $want --target wasm32-unknown-unknown --component rust-src" >&2
  echo "       then: RUSTUP_TOOLCHAIN=$want $0 $*" >&2
  exit 1
fi
if [ "$(wasm-pack --version)" != "wasm-pack 0.15.0" ]; then
  echo "error: wasm-pack 0.15.0 is required (cargo install wasm-pack --version 0.15.0 --locked)." >&2
  exit 1
fi
opt_version=$(cat ci/viewer-wasm-opt-version)
if ! command -v wasm-opt >/dev/null 2>&1 || [ "$(wasm-opt --version)" != "wasm-opt version $opt_version (version_$opt_version)" ]; then
  echo "error: Binaryen wasm-opt $opt_version is required; see ci/viewer-wasm-build.md." >&2
  exit 1
fi
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
cargo_home=$(cd "$cargo_home" && pwd -P)
# With the rust-src component installed, rustc replaces std's /rustc/<commit> paths with the local
# copy's, and they end up in panic locations; map them back.
sysroot=$(rustc --print sysroot)
commit=$(rustc -vV | sed -n 's/^commit-hash: //p')
RUSTFLAGS="--remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$sysroot/lib/rustlib/src/rust=/rustc/$commit -Zlocation-detail=none"
# An encoded override would take precedence over the flags above, breaking the pinned build.
unset CARGO_ENCODED_RUSTFLAGS
export RUSTFLAGS
export CARGO_PROFILE_RELEASE_OPT_LEVEL=z
export CARGO_PROFILE_RELEASE_LTO=fat
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_PANIC=immediate-abort
mkdir -p "$out"
out=$(cd "$out" && pwd -P)
wasm-pack build crates/sigil-wasm --target web --release --out-dir "$out" --out-name sigil_wasm \
  -- --locked -Zbuild-std=std,panic_abort -Zpanic-immediate-abort
# Keep the function names through optimization so similar functions can be placed together;
# strip them only after ordering. Unlimited single-caller inlining makes the gzip larger.
wasm-opt "$out/sigil_wasm_bg.wasm" --reorder-functions-by-name \
  -Oz --one-caller-inline-max-function-size=25 \
  --flatten --rereloop -Oz --reorder-functions-by-name \
  --strip-debug --strip-producers --strip-target-features \
  -o "$out/sigil_wasm_bg.wasm.opt"
mv "$out/sigil_wasm_bg.wasm.opt" "$out/sigil_wasm_bg.wasm"
rm -f "$out/.gitignore"
