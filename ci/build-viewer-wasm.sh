#!/bin/sh
# Builds the viewer's wasm bundle reproducibly: the same source gives the same bytes on any machine.
# CI rebuilds it and requires every file to equal the committed site/viewer/pkg/ (wasm.yml).
#
#   ci/build-viewer-wasm.sh [OUT_DIR]      (default: site/viewer/pkg)
#
# What is pinned:
# - rustc: the version in ci/viewer-wasm-toolchain (the build stops on any other; run with
#   RUSTUP_TOOLCHAIN=<that version> after `rustup toolchain install <version> --target
#   wasm32-unknown-unknown`);
# - wasm-pack 0.15.0, and wasm-bindgen through Cargo.lock (wasm-pack fetches the matching CLI);
# - paths: dependency sources live under CARGO_HOME, which differs per machine and would be
#   embedded in panic locations, so it is remapped to /cargo. A local rust-src copy is remapped
#   to /rustc/<commit>, as std is built. Workspace crates are built with relative paths.
set -eu
cd "$(dirname "$0")/.."
out="${1:-site/viewer/pkg}"
want=$(cat ci/viewer-wasm-toolchain)
have=$(rustc --version | cut -d' ' -f2)
if [ "$have" != "$want" ]; then
  echo "error: the viewer bundle is built with rustc $want (ci/viewer-wasm-toolchain), not $have." >&2
  echo "       Run: rustup toolchain install $want --target wasm32-unknown-unknown" >&2
  echo "       then: RUSTUP_TOOLCHAIN=$want $0 $*" >&2
  exit 1
fi
if [ "$(wasm-pack --version)" != "wasm-pack 0.15.0" ]; then
  echo "error: wasm-pack 0.15.0 is required (cargo install wasm-pack --version 0.15.0 --locked)." >&2
  exit 1
fi
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
cargo_home=$(cd "$cargo_home" && pwd -P)
# With the rust-src component installed, rustc replaces std's /rustc/<commit> paths with the local
# copy's, and they end up in panic locations; map them back.
sysroot=$(rustc --print sysroot)
commit=$(rustc -vV | sed -n 's/^commit-hash: //p')
RUSTFLAGS="--remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$sysroot/lib/rustlib/src/rust=/rustc/$commit"
export RUSTFLAGS
mkdir -p "$out"
out=$(cd "$out" && pwd -P)
wasm-pack build crates/sigil-wasm --target web --release --out-dir "$out" --out-name sigil_wasm
rm -f "$out/.gitignore"
