import subprocess
import sys


def test_cli_help():
    r = subprocess.run([sys.executable, "-m", "sigil.cli", "--help"], capture_output=True, text=True)
    assert r.returncode == 0
    assert "assess" in r.stdout
