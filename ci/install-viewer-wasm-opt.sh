#!/bin/sh
# Install the pinned Binaryen release for the Linux x86-64 CI runner.
# Usage: ci/install-viewer-wasm-opt.sh DEST_DIR
# Add DEST_DIR/binaryen-version_<version>/bin to PATH before building the viewer.
set -eu
cd "$(dirname "$0")/.."
repo=$(pwd -P)
if [ "$#" -ne 1 ]; then
  echo "usage: $0 DEST_DIR" >&2
  exit 2
fi
if [ "$(uname -sm)" != "Linux x86_64" ]; then
  echo "error: this installer supports Linux x86-64; install the pinned Binaryen version for your platform." >&2
  exit 1
fi
version=$(cat ci/viewer-wasm-opt-version)
archive="binaryen-version_${version}-x86_64-linux.tar.gz"
mkdir -p "$1"
cd "$1"
curl --fail --location --silent --show-error \
  "https://github.com/WebAssembly/binaryen/releases/download/version_${version}/$archive" \
  --output "$archive"
sha256sum --check "$repo/ci/viewer-wasm-opt.sha256"
tar -xzf "$archive"
"./binaryen-version_$version/bin/wasm-opt" --version
