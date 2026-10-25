"""Zeroes every byte of a thin 64-bit little-endian Mach-O outside its header, its load commands,
and its __LINKEDIT segment (PR-4c-3b, build.sh): the import tests read only those, and git
compresses the rest. Usage: python3 -I zero.py IN OUT. Fails on another file."""
import struct
import sys

src, dst = sys.argv[1], sys.argv[2]
data = open(src, 'rb').read()
magic, _, _, _, ncmds, sizeofcmds, _, _ = struct.unpack_from('<IiiIIIII', data, 0)
if magic != 0xfeedfacf:
    raise SystemExit('zero.py: not a thin 64-bit little-endian Mach-O')
keep = [(0, 32 + sizeofcmds)]
at = 32
for _ in range(ncmds):
    cmd, size = struct.unpack_from('<II', data, at)
    # LC_SEGMENT_64: segname at 8, fileoff and filesize at 40.
    if cmd == 0x19 and data[at + 8:at + 24].rstrip(b'\0') == b'__LINKEDIT':
        fileoff, filesize = struct.unpack_from('<QQ', data, at + 40)
        keep.append((fileoff, fileoff + filesize))
    at += size
if len(keep) != 2:
    raise SystemExit('zero.py: not one __LINKEDIT segment')
out = bytearray(len(data))
for start, end in keep:
    out[start:end] = data[start:end]
open(dst, 'wb').write(out)
