#!/usr/bin/env python3
"""Small MH_EXECUTE supplement; reuse the pinned Task1 tools and oracle."""
from pathlib import Path
import os
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "code-aarch64"))
sys.dont_write_bytecode = True
import fixture_tools as f


def main():
    if not __debug__:
        raise RuntimeError("oracle checks require Python assertions enabled")
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 -B build.py DESTINATION (must not exist)")
    f.verify("macho")
    dest = Path(sys.argv[1]).absolute()
    if dest.exists() or dest.is_symlink():
        raise FileExistsError(f"publication requires an absent destination: {dest}")
    scratch = f.ROOT / "target/tmp/issue48"
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fixtures-macho-exec-", dir=scratch) as temp:
        work = Path(temp)
        os.environ["TMPDIR"] = str(work)
        b = f.Build("macho", work)
        for arch, label in [("arm64", "arm64"), ("x86_64", "x86")]:
            obj, name = label + ".o", label + "-executable"
            b.tool("clang", "-target", arch + "-apple-macos11", "-O2", "-fno-ident",
                   "-fno-optimize-sibling-calls", "-ffile-prefix-map=" + str(f.ROOT) + "=.",
                   "-fasynchronous-unwind-tables", "-DFORCE_DWARF",
                   "-femit-dwarf-unwind=always", "-c", f.MACH / "calls.c", "-o", obj)
            # _zero is an explicit fixture entry, not a claim about a runnable app.
            b.tool("ld64.lld", "-arch", arch, "-platform_version", "macos", "11.0", "11.0",
                   "-e", "_zero", "-no_uuid", "-no_adhoc_codesign", "-no_fixup_chains",
                   obj, f.MACH / "libSystem.tbd", "-o", name)
            d = b.dumps(name, macho=True)
            assert struct.unpack_from("<I", d["image"], 12)[0] == 2  # MH_EXECUTE
            assert "FileType: Executable (0x2)" in d["readobj"]
            assert "LC_MAIN" in d["bind"] and "LC_LOAD_DYLINKER" in d["bind"]
            assert "LC_DYLD_INFO_ONLY" in d["bind"]
            f.oracle(b, name, arch, d, macho=True)
        assert len(b.rows) == 4 and len(b.bindings) == 2
        b.finish(dest)


if __name__ == "__main__":
    main()
