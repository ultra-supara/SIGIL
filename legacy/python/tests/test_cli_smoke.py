import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


def test_cli_help():
    r = subprocess.run([sys.executable, "-m", "sigil.cli", "--help"], capture_output=True, text=True)
    assert r.returncode == 0
    assert "assess" in r.stdout


def test_assess_external_call_drives_verdict():
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "sigil.cli",
            "assess",
            "examples/binaries/clean_kernel.o",
            "--entry",
            "kernel",
            "--policy",
            "examples/policies/numeric_kernel.yml",
            "--external-call",
            "connect",
        ],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0
    assert "SIGIL Verdict: FAIL" in r.stdout


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang not available")
@pytest.mark.skipif(importlib.util.find_spec("capstone") is None, reason="capstone not installed")
@pytest.mark.skipif(importlib.util.find_spec("elftools") is None, reason="pyelftools not installed")
def test_integration_assess_kernels(tmp_path: Path):
    clean_o = tmp_path / "clean.o"
    sus_o = tmp_path / "sus.o"
    subprocess.run(["clang", "-O0", "-c", "examples/src/clean_kernel.c", "-o", str(clean_o)], check=True)
    subprocess.run(["clang", "-O0", "-c", "examples/src/suspicious_kernel.c", "-o", str(sus_o)], check=True)

    r1 = subprocess.run([
        sys.executable, "-m", "sigil.cli", "assess", str(clean_o), "--entry", "kernel", "--policy", "examples/policies/numeric_kernel.yml"
    ], capture_output=True, text=True)
    assert r1.returncode == 0
    assert "SIGIL Verdict: PASS" in r1.stdout

    r2 = subprocess.run([
        sys.executable, "-m", "sigil.cli", "assess", str(sus_o), "--entry", "kernel", "--policy", "examples/policies/numeric_kernel.yml"
    ], capture_output=True, text=True)
    assert r2.returncode == 0
    assert ("SIGIL Verdict: FAIL" in r2.stdout) or ("SIGIL Verdict: WARN" in r2.stdout)
