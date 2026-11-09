#!/usr/bin/env python3
"""Compare two SIGIL CLI builds on stable x86 inputs and parse/code budget edges.

Usage: python3 ci/check-code-collection-compat.py BEFORE AFTER REPOSITORY
Build BEFORE from a021978 (the pre-refactor HEAD) and AFTER from the current source.
Only observation timestamps are normalized. Comparisons retain canonical JSON bytes and
also render each identical normalized session as Markdown and AI-BOM through both builds.
All target inputs are temporary copies; subprocesses run sequentially.
"""
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

before, after, repo = map(pathlib.Path, sys.argv[1:])
fixed = '2026-10-18T00:00:00Z'
def run(exe, args):
    p = subprocess.run([str(exe), *map(str, args)], capture_output=True)
    assert p.returncode == 0, (exe, args, p.returncode, p.stderr.decode())
    return p.stdout
def normalized(data):
    return re.sub(rb'("(?:started_at|finished_at)"\s*:\s*)"[^"]*"', lambda m: m[1] + json.dumps(fixed).encode(), data)
count = 0
with tempfile.TemporaryDirectory(prefix='sigil129-compat-') as temp:
    root = pathlib.Path(temp)
    model = root / 'models'
    model.mkdir()
    for fixture in ['spawn.so', 'values.so']:
        hidden, scanned = root/'libcudart.so.12', root/'ordinary.so'
        for dest in [hidden, scanned]:
            shutil.copyfile(repo/'crates/sigil-engine/tests/fixtures/code'/fixture, dest)
        for paths in [[hidden], [scanned], [hidden, scanned], [scanned, hidden]]:
            for budget in [[], ['--budget', 'binary_parse_bytes=512'], ['--budget', 'binary_code_bytes=128']]:
                args = ['binary', 'inspect', '--code', *paths, '--policy-time', fixed, *budget]
                a, b = normalized(run(before, args)), normalized(run(after, args))
                assert a == b, ('session differs', fixture, paths, budget)
                session = root/'session.json'
                session.write_bytes(a)
                for fmt in ['md', 'aibom']:
                    args = ['session', 'render', session, '--format', fmt]
                    assert run(before, args) == run(after, args), ('render differs', fmt, fixture, budget)
                count += 1
    install = root/'install'
    (install/'lib/ollama').mkdir(parents=True)
    for name in ['libcudart.so.12', 'ordinary.so']:
        shutil.copyfile(repo/'crates/sigil-engine/tests/fixtures/code/values.so', install/'lib/ollama'/name)
    for budget in [[], ['--budget', 'binary_parse_bytes=512'], ['--budget', 'binary_code_bytes=128']]:
        args = ['inspect', 'ollama', '--models-dir', model, '--install-dir', install, '--code', '--policy-time', fixed, *budget]
        a, b = normalized(run(before, args)), normalized(run(after, args))
        assert a == b, ('install session differs', budget)
        session = root/'session.json'
        session.write_bytes(a)
        for fmt in ['md', 'aibom']:
            args = ['session', 'render', session, '--format', fmt]
            assert run(before, args) == run(after, args), ('install render differs', fmt, budget)
        count += 1
print(f'{count} cases: canonical sessions, Markdown and AI-BOM byte-identical after observation-time normalization')
