import subprocess
import sys


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
