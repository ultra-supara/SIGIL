#!/usr/bin/env python3
"""Manual Task 7 oracle: independent pinned disassembly -> production semantic expectations.

Usage: aarch64_oracle.py <exported-words.txt> <scratch-directory>
Normal cargo tests do not run a compiler or disassembler. This gate reuses ADR-017's reviewed
text parser and complete fixture inventory, but derives the production operation and effects
from LLVM/GNU output, never from either Rust decoder. No target object is executed.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location("adr017", ROOT / "docs/adr/ADR-017-gate/check_oracles.py")
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


def semantics(ins, pc):
    op, *args = ins
    reads = [None] * 3
    writes = [None] * 3
    flags = False
    lr = ("r", 64, 30, "reg")

    def written(reg):
        return None if reg[3] == "zr" else reg

    if op in ("b", "bl"):
        out = ["call" if op == "bl" else "jump", pc + args[0]]
        if op == "bl":
            writes[0] = lr
    elif op.startswith("b."):
        flags = True
        out = ["conditional", pc + args[0]]
    elif op in ("cbz", "cbnz", "tbz", "tbnz"):
        reads[0] = args[0]
        out = ["conditional", pc + args[-1]]
    elif op in ("br", "blr", "ret"):
        reads[0] = args[0]
        out = ["return"] if op == "ret" else ["call_register" if op == "blr" else "jump_register", args[0][2]]
        if op == "blr":
            writes[0] = lr
    elif op in ("adr", "adrp"):
        out = ["address", args[0], (pc & ~4095 if op == "adrp" else pc) + args[1]]
        writes[0] = written(args[0])
    elif op in ("const", "movk"):
        out = [op, *args]
        writes[0] = written(args[0])
        if op == "movk":
            reads[0] = args[0]
    elif op == "orr":
        dst, zero, shift = args
        assert zero[3] == "zr" and shift[:3] == ("shift", "lsl", 0)
        out = ["copy", dst, shift[3]]
        reads[:2] = [zero, shift[3]]
        writes[0] = written(dst)
    elif op in ("add", "sub"):
        dst, src, imm, shift = args
        out = [op, dst, src, imm << shift]
        reads[0] = src
        writes[0] = written(dst)
    elif op in ("ldr", "str", "ldp", "stp"):
        regs, mem = args[:-1], args[-1]
        assert mem[0] == "mem"
        base, offset, mode = mem[1:]
        load = op in ("ldr", "ldp")
        regs = [*regs, None] if len(regs) == 1 else regs
        out = ["memory", load, regs, base, offset, mode]
        reads[0] = base
        if load:
            writes[:2] = [written(r) if r else None for r in regs]
        else:
            reads[1:] = regs
        if mode != "offset":
            writes[2] = base
    elif op == "hint" and args == [0]:
        out = ["nop"]
    else:
        raise AssertionError(ins)
    return dict(op=out, reads=reads, writes=writes, flags=flags)


def main(source, work):
    work = Path(work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    words = set(Path(source).read_text().splitlines())
    excluded = {"00000000", "0000000f", "d503233f", "18000050"}
    for item in oracle.inventory():
        if item["action"] != "compare":
            continue
        for line in (ROOT / item["dump"]).read_text().splitlines():
            match = oracle.ROW.match(line)
            if match and match[2] not in excluded:
                words.add(match[2])
    words = sorted(words)
    assert len(words) == 178917, len(words)
    pins = json.loads((ROOT / "crates/sigil-engine/tests/fixtures/code-aarch64/COMPILERS").read_text())
    for name in ("clang", "llvm-objdump", "objdump"):
        path = Path(pins[name]["path"].replace("<repo>", str(ROOT)))
        assert hashlib.sha256(path.read_bytes()).hexdigest() == pins[name]["sha256"], name
    assembly = work / "corpus.S"
    assembly.write_text(".text\n" + "".join(f".inst 0x{w}\n" for w in words))
    obj = work / "corpus.o"
    subprocess.run([pins["clang"]["path"], "--target=aarch64-linux-gnu", "-c", assembly, "-o", obj], check=True)
    for name, exe in [("llvm", pins["llvm-objdump"]["path"]), ("gnu", str(oracle.GNU))]:
        dump = work / f"{name}.objdump"
        with dump.open("w") as out:
            subprocess.run([exe, "-d", "-M", "no-aliases", "--adjust-vma=4294967296", str(obj)], stdout=out, check=True)
        count = 0
        with (work / f"{name}.jsonl").open("w") as out:
            for line in dump.open():
                match = oracle.ROW.match(line)
                if not match:
                    continue
                pc, word, text = int(match[1], 16), match[2], match[3]
                assert word == words[count], (count, word, words[count])
                expected = semantics(oracle.assembly(text, pc), pc)
                out.write(json.dumps(dict(word=int(word, 16), pc=pc, semantics=expected), separators=(",", ":")) + "\n")
                count += 1
        assert count == len(words)
        print(f"{name}: {count} independent operation/effect rows", flush=True)
    assert (work / "llvm.jsonl").read_bytes() == (work / "gnu.jsonl").read_bytes()
    print("LLVM/GNU expected semantics and effects agree")


if __name__ == "__main__":
    main(*sys.argv[1:])
