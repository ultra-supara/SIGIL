import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest

from sigil.x86.decoder import decode_x86_64
from sigil.x86.elf import load_function


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang not available")
@pytest.mark.skipif(importlib.util.find_spec("capstone") is None, reason="capstone not installed")
@pytest.mark.skipif(importlib.util.find_spec("elftools") is None, reason="pyelftools not installed")
def test_load_and_decode(tmp_path: Path):
    obj = tmp_path / "clean.o"
    subprocess.run(["clang", "-O0", "-c", "examples/src/clean_kernel.c", "-o", str(obj)], check=True)
    fn = load_function(str(obj), "kernel")
    ins = decode_x86_64(fn.code, fn.address)
    assert len(ins) > 0
    assert any(i.mnemonic == "ret" for i in ins)
