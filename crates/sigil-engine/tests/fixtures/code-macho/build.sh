#!/bin/sh
set -eu
export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=0
if test "$#" -ne 1; then
  printf '%s\n' 'Usage: build.sh DESTINATION (must not exist; see README for fixture refresh)' >&2
  exit 2
fi
src=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$src/../../../../.." && pwd)
helper="$src/../code-aarch64/fixture_tools.py"
python3 "$helper" verify macho
if test -e "$1" || test -L "$1"; then
  printf '%s\n' "Destination already exists: $1" >&2
  exit 1
fi
mkdir -p "$root/target/tmp/issue48"
work=$(mktemp -d "$root/target/tmp/issue48/fixtures-macho.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
export TMPDIR="$work"
python3 "$helper" build macho "$work" "$1"
