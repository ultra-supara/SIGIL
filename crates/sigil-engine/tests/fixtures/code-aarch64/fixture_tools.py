#!/usr/bin/env python3
"""Fixture-only builds/oracles. Never imports or invokes SIGIL.

All oracle addresses come from the committed independent tool dumps. Expected
argument meanings come from the small, reviewed source programs, not an analyzer.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
MACH = HERE.parent / "code-macho"
TC = ROOT / "target/tmp/issue48/toolchains"
GCC = TC / "gcc-15.3/gcc-15.3.0-nolibc/aarch64-linux"
BIN = TC / "binutils-2.46/usr/bin"
DRIVER = TC / "binutils-driver/bin"
os.environ.update(LC_ALL="C", TZ="UTC", SOURCE_DATE_EPOCH="0")
for key in ("GCC_EXEC_PREFIX", "COMPILER_PATH", "LIBRARY_PATH", "CPATH", "C_INCLUDE_PATH",
            "CPLUS_INCLUDE_PATH", "CCC_OVERRIDE_OPTIONS", "SDKROOT", "MACOSX_DEPLOYMENT_TARGET"):
    os.environ.pop(key, None)
os.environ["LD_LIBRARY_PATH"] = str(TC / "binutils-2.46/usr/lib/x86_64-linux-gnu")
TOOLS = {name: Path("/usr/bin") / (name + "-21") for name in (
    "clang", "ld.lld", "ld64.lld", "llvm-objdump", "llvm-dwarfdump",
    "llvm-readobj", "llvm-nm", "llvm-lipo")}
TOOLS.update({"gcc": GCC / "bin/aarch64-linux-gcc",
              "cc1": GCC / "libexec/gcc/aarch64-linux/15.3.0/cc1"})
TOOLS.update({name: BIN / ("aarch64-linux-gnu-" + name)
              for name in ("as", "ld", "objdump", "readelf")})
TOOLS["python"] = Path(sys.executable).resolve()
COMMON = ["clang", "llvm-objdump", "llvm-dwarfdump", "llvm-readobj", "llvm-nm", "python"]
FAMILY = {"elf": COMMON + ["ld.lld", "gcc", "cc1", "as", "ld", "objdump", "readelf"],
          "macho": COMMON + ["ld64.lld", "llvm-lipo"]}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(args, cwd=None):
    p = subprocess.run([str(x) for x in args], cwd=cwd, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode:
        raise RuntimeError(f"command failed ({p.returncode}): {shlex.join(map(str, args))}\n"
                           + p.stdout + p.stderr)
    return p.stdout + p.stderr


def tool_record(family):
    records = {}
    for name in FAMILY[family]:
        path = TOOLS[name]
        version_args = ["-quiet", "-version", "-fpreprocessed", "-o", "/dev/null", "/dev/null"] if name == "cc1" else ["--version"]
        records[name] = {"path": str(path).replace(str(ROOT) + "/", "<repo>/"),
                         "sha256": sha(path), "version": run([path, *version_args])}
    return records


def verify(family):
    src = HERE if family == "elf" else MACH
    actual = tool_record(family)
    expected = json.loads((src / "COMPILERS").read_text())
    if actual != expected:
        bad = [n for n in actual if actual[n] != expected.get(n)]
        raise RuntimeError("pinned tool mismatch: " + ", ".join(bad))
    if family == "elf":
        for name in ("as", "ld", "cc1"):
            selected = run([TOOLS["gcc"], "-B", str(DRIVER) + "/",
                            "-print-prog-name=" + name]).strip()
            if Path(selected).resolve() != TOOLS[name].resolve():
                raise RuntimeError(f"gcc selected unexpected {name}: {selected}")
    print(f"{family}: all {len(actual)} pinned tool versions and SHA-256 values match")


class Build:
    def __init__(self, family, work):
        self.family, self.work = family, work
        self.log, self.files, self.rows, self.bindings = [], [], [], []

    def command(self, args, log_output=True):
        result = run(args, self.work)
        cmd = shlex.join(map(str, args)).replace(str(ROOT), "<repo>")
        self.log.append("$ " + cmd + "\n" + (result.replace(str(self.work), "<build>") if log_output else ""))
        return result

    def tool(self, name, *args):
        return self.command([TOOLS[name], *args])

    def dump(self, name, suffix, tool, *args):
        # Raw output has its own file; the transcript records the exact command.
        output = self.command([TOOLS[tool], *args, name], log_output=False)
        (self.work / (name + suffix)).write_text(output)
        self.files.append(name + suffix)
        return output

    def dumps(self, name, macho=False, fat=False):
        self.files.append(name)
        arches = ["--arch=all"] if fat else []
        d = {"asm": self.dump(name, ".objdump", "llvm-objdump", *arches, "-dr"),
             "readobj": self.dump(name, ".readobj", "llvm-readobj", "--file-headers", "--sections",
                                   "--symbols", "--relocations"),
             "frames": self.dump(name, ".frames", "llvm-dwarfdump", "--eh-frame"),
             "nm": self.dump(name, ".nm", "llvm-nm", *arches, "--numeric-sort", "--print-size")}
        if macho:
            d["bind"] = self.dump(name, ".macho", "llvm-objdump", *arches, "--macho", "--bind",
                                  "--lazy-bind", "--chained-fixups", "--unwind-info",
                                  "--indirect-symbols", "--private-headers", "--dyld-info")
        else:
            d["gnu"] = self.dump(name, ".gnu-objdump", "objdump", "-dr")
            d["gnu_frames"] = self.dump(name, ".gnu-frames", "readelf", "--debug-dump=frames")
            d["gnu_relocs"] = self.dump(name, ".gnu-relocs", "readelf", "-rW")
        return d

    def row(self, fixture, arch, function, start="-", end="-", call="-", symbol="-",
            library="-", args=("-", "-", "-"), coverage="complete"):
        def addr(x):
            return f"0x{x:x}" if isinstance(x, int) else x
        self.rows.append([fixture, arch, function, addr(start), addr(end), addr(call),
                          symbol, library, *args, coverage])

    def finish(self, dest):
        header = "fixture slice function start end call symbol library arg0 arg1 arg2 coverage".split()
        (self.work / "oracle.tsv").write_text("\t".join(header) + "\n" + "".join(
            "\t".join(row) + "\n" for row in sorted(self.rows)))
        (self.work / "build.log").write_text("\n".join(self.log))
        self.files += ["oracle.tsv", "build.log"]
        if self.bindings:
            header = "fixture slice stub slot symbol library ordinal mode".split()
            (self.work / "bindings.tsv").write_text("\t".join(header) + "\n" + "".join(
                "\t".join(row) + "\n" for row in sorted(self.bindings)))
            self.files.append("bindings.tsv")
        self.files.sort()
        checks = {name: sha(self.work / name) for name in self.files}
        (self.work / "SHA256SUMS").write_text("".join(f"{h}  {n}\n" for n, h in checks.items()))
        for name, checksum in checks.items():
            assert sha(self.work / name) == checksum
        # Publication begins only after all shape/oracle checks and hashes pass.
        dest.mkdir(parents=True, exist_ok=True)
        for name in self.files + ["SHA256SUMS"]:
            shutil.copyfile(self.work / name, dest / name)
        print(f"{self.family}: published {len(self.files)} checked files, {len(self.rows)} oracle rows to {dest}")


def symbols(d):
    return {m[4]: int(m[1], 16) for line in d["nm"].splitlines()
            if (m := re.match(r"^([0-9a-fA-F]+)\s+(?:([0-9a-fA-F]+)\s+)?([Tt])\s+(\S+)$", line))}


def text_offset(d, macho):
    label = "__text" if macho else ".text"
    sections = re.findall(r"  Section \{(.*?)\n  \}", d["readobj"], re.S)
    entry, = [s for s in sections if re.search(r"\n    Name: " + re.escape(label) + r"(?: |\n)", s)]
    m = re.search(r"\n    Offset: (0x[0-9A-Fa-f]+|[0-9]+)", entry)
    return int(m[1], 0)


def ranges(d, object_macho=False):
    if object_macho:
        entries = re.findall(r"start:\s+0x([0-9a-f]+)[^\n]*\n\s+length:\s+0x([0-9a-f]+)", d["bind"])
        assert entries, "missing explicit object compact unwind entries"
        return {int(a, 16): int(a, 16) + int(n, 16) for a, n in entries}
    result = {int(a, 16): int(b, 16) for a, b in re.findall(
        r" FDE .* pc=([0-9a-fA-F]+)\.\.\.([0-9a-fA-F]+)", d["frames"])}
    if "gnu_frames" in d:
        gnu = {int(a, 16): int(b, 16) for a, b in re.findall(
            r" FDE .* pc=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)", d["gnu_frames"])}
        assert result == gnu, "LLVM/GNU FDE range disagreement"
    return result


def insns(d):
    # LLVM default disassembly preserves raw bytes/words in column 2.
    result = []
    for line in d["asm"].splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+(?:[0-9a-f]{8}|(?:[0-9a-f]{2}\s+)+)\s+([a-z][a-z0-9.]*)\s*(.*)", line)
        if m:
            result.append((int(m[1], 16), m[2], m[3]))
    return result


VALUES = {"zero": ("0", "0", "0"), "one": ("1", "0", "0"),
          "asm_zero": ("0", "0", "0"), "copy": ("0", "0", "0"),
          "join_agree": ("0", "0", "0"), "join_disagree": ("set:0,1", "0", "0"),
          "caller_clobber": ("unknown:clobbered",) * 3, "from_foo": ("2", "0", "0")}


def macho_bindings(b, name, arch, d):
    """Join independent indirect-symbol, stub, dyld and dylib-command dumps."""
    libs = re.findall(r"cmd LC_LOAD_DYLIB\n.*?\n\s+name (\S+) \(offset", d["bind"])
    libnames = {"libSystem": "/usr/lib/libSystem.B.dylib", "libfoo": "/sigil/libfoo.dylib"}
    bound = {}
    for line in d["bind"].splitlines():
        fields = line.split()
        if fields and fields[0].startswith("__DATA") and fields[-1] == "_connect" and fields[-2] in libnames:
            slot = int(fields[2], 16)
            library = libnames[fields[-2]]
            assert slot not in bound or bound[slot] == library
            bound[slot] = library
    assert bound, f"no actual connect bind/fixup slots: {name}"
    indirect = {}
    for section, body in re.findall(r"Indirect symbols for \(([^)]+)\) [^\n]*\n(.*?)(?=Indirect symbols for|chained fixups|Contents of|Mach header)", d["bind"], re.S):
        indirect[section] = [(int(a, 16), int(i), sym) for a, i, sym in re.findall(
            r"^(0x[0-9a-fA-F]+)\s+([0-9]+)\s+(\S+)$", body, re.M)]
    stubs = indirect["__TEXT,__stubs"]
    slots = {i: slot for section, entries in indirect.items() if section.startswith("__DATA")
             for slot, i, sym in entries if sym == "_connect"}
    instructions = {pc: (op, arg) for pc, op, arg in insns(d)}
    result = {}
    mode = "chained" if "LC_DYLD_CHAINED_FIXUPS" in d["bind"] else "classic-lazy"
    for stub, index, sym in stubs:
        assert sym == "_connect" and index in slots
        slot = slots[index]
        assert slot in bound
        if arch == "arm64":
            assert instructions[stub][0] == "adrp"
            page = re.match(r"x16, (0x[0-9a-f]+)", instructions[stub][1])
            assert page
            op, arg = instructions[stub + 4]
            load = re.match(r"x16, \[x16(?:, #(0x[0-9a-f]+))?\]", arg)
            assert op == "ldr" and load
            assert int(page[1], 16) + (int(load[1], 16) if load[1] else 0) == slot
            assert instructions[stub + 8] == ("br", "x16")
        else:
            op, arg = instructions[stub]
            jump = re.match(r"\*(0x[0-9a-f]+)\(%rip\).*## (0x[0-9a-f]+)", arg)
            assert op == "jmpq" and jump
            assert stub + 6 + int(jump[1], 16) == slot == int(jump[2], 16)
        library = bound[slot]
        ordinal = libs.index(library) + 1
        b.bindings.append([name, arch, f"0x{stub:x}", f"0x{slot:x}", sym,
                           library, str(ordinal), mode])
        result[stub] = library
    assert len(result) == len(bound)
    if mode == "chained":
        assert "lib_ordinal = 1 (libSystem)" in d["bind"] and len(bound) == 1
        assert "weak_import = 0" in d["bind"] and "pointer_format = 2 (DYLD_CHAINED_PTR_64)" in d["bind"]
    return result


def oracle(b, name, arch, d, macho=False, obj=False, bounds=True):
    syms = symbols(d)
    rs = ranges(d, object_macho=macho and obj) if bounds else {}
    shift = text_offset(d, macho) if obj else 0
    assert syms and (rs or not bounds), f"no parsed symbols/ranges for {name}"
    all_insns = insns(d)
    assert all_insns, f"no parsed instructions for {name}"
    bindings = macho_bindings(b, name, arch, d) if macho and not obj else {}
    for rawname, start in syms.items():
        function = rawname.removeprefix("_") if macho else rawname
        if function not in {*VALUES, "helper", "malformed_reserved", "unsupported_indirect",
                            "unsupported_pac", "malformed_overlap"}:
            continue
        if not bounds:
            # Symbol addresses and LC_FUNCTION_STARTS are not exact end evidence.
            b.row(name, arch, rawname, coverage="partial:missing-exact-bounds")
            continue
        assert start in rs, f"missing exact range: {name}:{rawname} at {start:x}"
        end = rs[start]
        body = [(pc, op, arg) for pc, op, arg in all_insns if start <= pc < end]
        assert body and end > start
        bad = function.startswith(("malformed_", "unsupported_"))
        if bad:
            b.row(name, arch, rawname, start + shift, end + shift,
                  coverage="partial:" + function)
            continue
        calls = [(pc, op, arg) for pc, op, arg in body if op in ("bl", "blr", "callq", "call")]
        if function == "helper":
            assert not calls
            b.row(name, arch, rawname, start + shift, end + shift)
            continue
        assert len(calls) == (2 if function == "caller_clobber" else 1), (name, function, calls)
        pc, op, target = calls[-1]
        # Verify the expected source setup is actually present in the dump.
        if function in ("zero", "one", "from_foo") and arch == "arm64":
            ops = "\n".join(arg for _, _, arg in body[:body.index(calls[-1])])
            setup = r"w0, (?:wzr|w2|#0x0)" if function == "zero" else rf"w0, #0x{VALUES[function][0]}\b"
            assert re.search(setup, ops), (name, ops)
            assert re.search(r"x1, (?:xzr|#0x0)", ops), (name, ops)
            assert re.search(r"w2, (?:wzr|#0x0)", ops), (name, ops)
        if function in ("zero", "one") and arch == "x86_64":
            ops = "\n".join(op + " " + arg for _, op, arg in body[:body.index(calls[-1])])
            setup = "xorl %edi, %edi" if function == "zero" else "movl $0x1, %edi"
            assert setup in ops and "xorl %esi, %esi" in ops and "xorl %edx, %edx" in ops
        if obj:
            offset = pc + (1 if arch == "x86_64" else 0)
            kind = "X86_64_RELOC_BRANCH" if arch == "x86_64" else (
                "ARM64_RELOC_BRANCH26" if macho else "R_AARCH64_CALL26")
            symbol = "_connect" if macho else "connect"
            relocation = rf"^\s*0*{offset:x}:\s+{kind}\s+{symbol}\s*$"
            assert re.search(relocation, d["asm"], re.M), (name, function, relocation)
        library = "/sigil/libfoo.dylib" if function == "from_foo" else (
            "unbound" if macho and obj else "/usr/lib/libSystem.B.dylib" if macho else "-")
        if macho and not obj:
            dest = re.match(r"0x([0-9a-f]+)", target)
            assert dest and bindings.get(int(dest[1], 16)) == library, (name, function, target, bindings)
        b.row(name, arch, rawname, start + shift, end + shift, pc + shift,
              "_connect" if macho else "connect", library, VALUES[function])


def build_elf(b):
    common = ["-fPIC", "-fno-ident", "-fno-optimize-sibling-calls", "-fasynchronous-unwind-tables",
              "-ffile-prefix-map=" + str(ROOT) + "=.", "-fdebug-prefix-map=" + str(ROOT) + "=."]
    for compiler in ("clang", "gcc"):
        driver = [TOOLS[compiler]]
        driver += ["-target", "aarch64-linux-gnu", "--ld-path=" + str(TOOLS["ld.lld"])] if compiler == "clang" else ["-B", str(DRIVER) + "/"]
        for opt in ("0", "2"):
            name = f"elf-{compiler}-o{opt}.o"
            b.command([*driver, *common, "-O" + opt, "-c", HERE / "calls.c", "-o", name])
            d = b.dumps(name)
            assert "R_AARCH64_CALL26" in d["gnu_relocs"]
            oracle(b, name, "arm64", d, obj=True)
        for form in ("plt", "got"):
            name = f"elf-{compiler}-{form}.so"
            obj = f"{compiler}-{form}.o"
            flags = ["-fno-plt"] if form == "got" else []
            b.command([*driver, *common, *flags, "-O2", "-c", HERE / "calls.c", "-o", obj])
            b.command([*driver, "-nostdlib", "-shared", "-Wl,--build-id=none",
                       "-Wl,-soname,libsigil-fixture.so", obj, "-o", name])
            d = b.dumps(name)
            if form == "got":
                assert "R_AARCH64_GLOB_DAT" in d["gnu_relocs"]
                assert len(re.findall(r"\bblr\s+x[0-9]+", d["asm"])) == 2
                assert "R_AARCH64_JUMP_SLOT" not in d["gnu_relocs"]
            else:
                assert "R_AARCH64_JUMP_SLOT" in d["gnu_relocs"] and "connect@plt" in d["asm"]
            oracle(b, name, "arm64", d)
    b.tool("clang", "-target", "aarch64-linux-gnu", *common, "-c", HERE / "calls.S", "-o", "elf-cases.o")
    d = b.dumps("elf-cases.o")
    oracle(b, "elf-cases.o", "arm64", d, obj=True)
    b.tool("ld.lld", "-shared", "--build-id=none", "-soname", "libsigil-fixture.so",
           "elf-cases.o", "-o", "elf-cases.so")
    oracle(b, "elf-cases.so", "arm64", b.dumps("elf-cases.so"))
    b.tool("clang", "-target", "aarch64-linux-gnu", "--ld-path=" + str(TOOLS["ld.lld"]),
           "-fPIC", "-fno-ident", "-O2", "-fno-optimize-sibling-calls", "-fno-unwind-tables",
           "-fno-asynchronous-unwind-tables", "-c", HERE / "calls.c", "-o", "no-fde.o")
    b.tool("ld.lld", "-shared", "--build-id=none", "no-fde.o", "-o", "elf-no-fde.so")
    d = b.dumps("elf-no-fde.so")
    assert not ranges(d) and " FDE " not in d["gnu_frames"]
    oracle(b, "elf-no-fde.so", "arm64", d, bounds=False)


def build_macho(b):
    def cc(arch, src, output, *flags):
        unwind = ["-fasynchronous-unwind-tables", "-DFORCE_DWARF"] if "-femit-dwarf-unwind=always" in flags else []
        b.tool("clang", "-target", arch + "-apple-macos11", "-O2", "-fno-ident",
               "-fno-optimize-sibling-calls", "-ffile-prefix-map=" + str(ROOT) + "=.",
               *unwind, *flags, "-c", MACH / src, "-o", output)

    def link(arch, mode, output, *objects, foo=False, extra=()):
        b.tool("ld64.lld", "-arch", arch, "-platform_version", "macos", "11.0", "11.0",
               "-dylib", "-no_uuid", "-no_adhoc_codesign", "-install_name", "/sigil/fixture.dylib",
               "-fixup_chains" if mode == "chained" else "-no_fixup_chains", *extra,
               *objects, MACH / "libSystem.tbd", *([MACH / "libfoo.tbd"] if foo else []), "-o", output)

    for arch, label in (("arm64", "arm64"), ("x86_64", "x86")):
        obj = label + "-object.o"
        cc(arch, "calls.c", obj, "-femit-dwarf-unwind=always")
        d = b.dumps(obj, True)
        assert ("ARM64_RELOC_BRANCH26" if arch == "arm64" else "X86_64_RELOC_BRANCH") in d["readobj"]
        oracle(b, obj, arch, d, macho=True, obj=True)
        cases = label + "-cases.o"
        cc(arch, "calls.S", cases, "-femit-dwarf-unwind=always")
        oracle(b, cases, arch, b.dumps(cases, True), macho=True, obj=True)
        for mode in ("classic", "chained"):
            name = label + "-" + mode
            link(arch, mode, name, obj)
            d = b.dumps(name, True)
            assert "_connect" in d["bind"] and "/usr/lib/libSystem.B.dylib" in d["bind"]
            if mode == "chained":
                assert "LC_DYLD_CHAINED_FIXUPS" in d["bind"] and "DYLD_CHAINED_PTR_64" in d["bind"]
            else:
                assert "LC_DYLD_INFO_ONLY" in d["bind"] and "Lazy bind table:" in d["bind"]
                assert "LC_DYLD_CHAINED_FIXUPS" not in d["bind"]
            oracle(b, name, arch, d, macho=True)
        link(arch, "classic", label + "-cases", cases)
        oracle(b, label + "-cases", arch, b.dumps(label + "-cases", True), macho=True)

    cc("arm64", "calls.c", "compact-object.o")
    d = b.dumps("compact-object.o", True)
    assert d["bind"].count("compact encoding:     0x04000000") == 2
    assert not ranges(d), "compact-only object unexpectedly has DWARF FDEs"
    oracle(b, "compact-object.o", "arm64", d, macho=True, obj=True)
    link("arm64", "classic", "unwind-folded", "compact-object.o", extra=("-no_function_starts",))
    d = b.dumps("unwind-folded", True)
    assert not ranges(d) and "LC_FUNCTION_STARTS" not in d["bind"]
    assert len(re.findall(r"function offset=.*encoding\[", d["bind"])) == 1
    assert "0x04000000" in d["bind"]
    oracle(b, "unwind-folded", "arm64", d, macho=True, bounds=False)
    cc("arm64", "calls.c", "no-unwind.o", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables")
    link("arm64", "classic", "no-unwind", "no-unwind.o", extra=("-no_function_starts",))
    d = b.dumps("no-unwind", True)
    assert not ranges(d) and "Contents of __unwind_info section:" not in d["bind"]
    oracle(b, "no-unwind", "arm64", d, macho=True, bounds=False)

    cc("arm64", "calls.c", "duplicate-names.o", "-DDUPLICATE_NAMES", "-femit-dwarf-unwind=always")
    link("arm64", "classic", "duplicate-name-dylibs.before", "duplicate-names.o", foo=True)
    b.dumps("duplicate-name-dylibs.before", True)
    data = (b.work / "duplicate-name-dylibs.before").read_bytes()
    offsets = [m.start() for m in re.finditer(b"_connec2\0", data)]
    assert len(offsets) == 2, offsets  # symbol string table and lazy-bind stream
    patched = data.replace(b"_connec2\0", b"_connect\0")
    (b.work / "duplicate-name-dylibs").write_bytes(patched)
    (b.work / "duplicate-name-dylibs.patch.json").write_text(json.dumps({
        "kind": "synthetic-equal-length-import-rename", "source": "duplicate-name-dylibs.before",
        "source_sha256": sha(b.work / "duplicate-name-dylibs.before"),
        "offsets": offsets, "old_hex": b"_connec2\0".hex(), "new_hex": b"_connect\0".hex(),
    }, indent=2) + "\n")
    b.files.append("duplicate-name-dylibs.patch.json")
    d = b.dumps("duplicate-name-dylibs", True)
    slots = re.findall(r"^__DATA\s+__la_symbol_ptr\s+(0x[0-9a-fA-F]+)\s+(libSystem|libfoo)\s+_connect$", d["bind"], re.M)
    assert len(slots) == 2 and len({s[0] for s in slots}) == 2 and {s[1] for s in slots} == {"libSystem", "libfoo"}, slots
    oracle(b, "duplicate-name-dylibs", "arm64", d, macho=True)

    # Real 32-bit Mach-O object, intentionally outside the 64-bit support scope.
    b.tool("clang", "-target", "i386-apple-macos10.13", "-O2", "-fno-ident", "-c",
           MACH / "calls.c", "-o", "i386-unsupported.o")
    d = b.dumps("i386-unsupported.o", True)
    assert "Format: Mach-O 32-bit i386" in d["readobj"]
    b.row("i386-unsupported.o", "i386", "-", coverage="unsupported:32-bit")
    for name, inputs in (("universal", ("arm64-chained", "x86-classic")),
                         ("universal-mixed", ("arm64-chained", "i386-unsupported.o"))):
        b.tool("llvm-lipo", "-create", *inputs, "-output", name)
        fat_dumps = b.dumps(name, True, fat=True)
        for arch in (("x86_64", "arm64") if name == "universal" else ("i386", "arm64")):
            assert f"architecture {arch}" in fat_dumps["asm"] and f"architecture {arch}" in fat_dumps["bind"]
        b.dump(name, ".lipo", "llvm-lipo", "-info")
        data = (b.work / name).read_bytes()
        magic, count = struct.unpack_from(">II", data)
        assert magic == 0xcafebabe and count == 2
        extracted = []
        inventory = []
        for i in range(count):
            cpu, sub, offset, size, align = struct.unpack_from(">IIIII", data, 8 + i * 20)
            matches = [source for source in inputs if data[offset:offset+size] == (b.work / source).read_bytes()]
            assert len(matches) == 1
            source = matches[0]
            assert offset % (1 << align) == 0 and offset + size <= len(data)
            assert struct.unpack_from("<I", data, offset)[0] in (0xfeedface, 0xfeedfacf)
            assert struct.unpack_from("<II", data, offset + 4) == (cpu, sub)
            inventory.append({"source": source, "cpu": cpu, "subtype": sub,
                              "offset": offset, "size": size, "align": align,
                              "sha256": hashlib.sha256(data[offset:offset+size]).hexdigest()})
            extracted.append(source)
            for row in list(b.rows):
                if row[0] == source:
                    b.rows.append([name, *row[1:]])
            for row in list(b.bindings):
                if row[0] == source:
                    b.bindings.append([name, *row[1:]])
        assert set(extracted) == set(inputs)
        a, c = sorted(inventory, key=lambda i: i["offset"])
        assert a["offset"] + a["size"] <= c["offset"]
        (b.work / (name + ".slices.json")).write_text(json.dumps(inventory, indent=2) + "\n")
        b.files.append(name + ".slices.json")


def main():
    if not __debug__:
        raise RuntimeError("oracle checks require Python assertions enabled")
    action, family, *args = sys.argv[1:]
    assert family in FAMILY
    if action == "record-tools":
        # Explicit maintainer operation; neither build.sh calls this path.
        src = HERE if family == "elf" else MACH
        (src / "COMPILERS").write_text(json.dumps(tool_record(family), indent=2) + "\n")
    elif action == "verify":
        verify(family)
    elif action == "build":
        verify(family)
        work, dest = map(lambda p: Path(p).resolve(), args)
        b = Build(family, work)
        (build_elf if family == "elf" else build_macho)(b)
        b.finish(dest)
    else:
        raise ValueError(action)


if __name__ == "__main__":
    main()
