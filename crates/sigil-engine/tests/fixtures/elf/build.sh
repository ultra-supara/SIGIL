#!/bin/sh
# Builds the ELF fixtures of the engine tests, once, by hand. The tests never run this script or a
# compiler; they read the committed files. Needs cc (GCC), clang, and ld.lld.
set -eu
cd "$(dirname "$0")"
C="-O1 -fno-asynchronous-unwind-tables"
cc $C -shared -fPIC -o libdata.so libdata.c -lm -Wl,-soname,libdata.so.1 \
   -Wl,--enable-new-dtags -Wl,-rpath,'$ORIGIN' -Wl,--build-id=sha1 -Wl,-z,nopack-relative-relocs
cc $C -shared -fPIC -o libdata-relr.so libdata.c -lm -Wl,-soname,libdata-relr.so.1 \
   -Wl,-z,pack-relative-relocs
cc $C -shared -fPIC -o libsym64.so libsym64.c -Wl,-soname,libsym64.so -Wl,-z,nopack-relative-relocs
cc $C -no-pie -rdynamic -o exe-nopie exe.c -Wl,--disable-new-dtags -Wl,-rpath,/opt/sigil-test/lib
cc $C -nostdlib -static -o static static.c
clang --target=aarch64-linux-gnu -fuse-ld=lld -nostdlib -shared -fPIC $C \
   -o libdata-aarch64.so data-only.c -Wl,-soname,libdata-aarch64.so
for f in libdata.so libdata-relr.so libsym64.so exe-nopie static libdata-aarch64.so; do
  LC_ALL=C readelf -hlndrW --dyn-syms -p .comment "$f" > "$f.readelf" 2>&1 || true
done
