"""Writes the bytes of one ELF section (by name) to a file. Usage: extract.py ELF SECTION OUT"""
import struct, sys

elf, want, out = sys.argv[1], sys.argv[2].encode(), sys.argv[3]
data = open(elf, "rb").read()
big = data[5] == 2
is64 = data[4] == 2
e = ">" if big else "<"
if is64:
    shoff, = struct.unpack_from(e + "Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 0x3A)
    def sh(i):
        name, typ, flags, addr, off, size = struct.unpack_from(e + "IIQQQQ", data, shoff + i * shentsize)
        return name, off, size
else:
    shoff, = struct.unpack_from(e + "I", data, 0x20)
    shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 0x2E)
    def sh(i):
        name, typ, flags, addr, off, size = struct.unpack_from(e + "IIIIII", data, shoff + i * shentsize)
        return name, off, size
_, stroff, strsize = sh(shstrndx)
for i in range(shnum):
    name, off, size = sh(i)
    end = data.index(b"\0", stroff + name)
    if data[stroff + name:end] == want:
        open(out, "wb").write(data[off:off + size])
        sys.exit(0)
sys.exit("no section " + want.decode())
