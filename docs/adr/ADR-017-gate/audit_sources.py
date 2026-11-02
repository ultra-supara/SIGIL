#!/usr/bin/env python3
"""Pin source/archives and verify the generated decoder's table-index bound.

This mechanical check supplements the manual path audit in ADR-017. It does
not infer ISA correctness or prove the Rust compiler/macro expansions sound.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
WORK=ROOT/'target/tmp/issue48/task2'
m=json.loads(subprocess.run(['cargo','+1.93.0','metadata','--manifest-path',str(HERE/'Cargo.toml'),'--locked','--offline','--format-version','1'],check=True,text=True,capture_output=True).stdout)
packages={p['name']:p for p in m['packages']}
pins={'yaxpeax-arm':('0.5.0','79f8d9808ad0b7e434882c66e50704138e7c0bdf3408a9f3159c50603dc3168c'),
'yaxpeax-arch':('0.3.3','fb869f86d5a365bf741d9df773f7a5347757b1c466b7383b74989324785ef36b'),
'disarm64':('0.2.0','b40cb278f87c9a57ef6bc51a7b04d4b6097fea24ef50921e8de4a51f06304be0')}
summary={}
for name,(version,sha) in pins.items():
    p=packages[name];assert p['version']==version
    directory=Path(p['manifest_path']).parent
    archive=directory.parents[1].parent/'cache'/directory.parent.name/(directory.name+'.crate')
    assert hashlib.sha256(archive.read_bytes()).hexdigest()==sha
    files=['src/armv8/a64.rs'] if name=='yaxpeax-arm' else ['src/reader.rs','src/lib.rs'] if name=='yaxpeax-arch' else ['src/decoder_full.rs']
    summary[name]={'version':version,'archive_sha256':sha,'files':{f:hashlib.sha256((directory/f).read_bytes()).hexdigest() for f in files}}
source=Path(packages['disarm64']['manifest_path']).parent/'src/decoder_full.rs'
s=source.read_text();body=s.split('fn decode_index(insn: u32) -> i32 {',1)[1].split('#[doc = r" Decode a 32-bit instruction word."]')[0]
returns=list(map(int,re.findall(r'return\s+(\d+)\s*;',body)))
assert returns and min(returns)>=0 and max(returns)<3774
# Acyclic decision tree: no loops, recursion, indexing, allocation, panics or calls.
assert not re.search(r'\b(for|while|loop|panic|unreachable|assert)\b|\[|\w+\(',body)
assert body.count('return')==len(re.findall(r'return\s+-?\d+\s*;',body))
assert all(int(x)>=-1 for x in re.findall(r'return\s+(-?\d+)\s*;',body))
assert body.strip().endswith('-1\n}')
assert 'static INSNS: [Insn; 3774]' in s and 'static INSN_IDS: [InsnId; 3774]' in s
summary['disarm64']['decode_index']={'literal_returns':len(returns),'min':min(returns),'max':max(returns),'table_lengths':[3774,3774],'acyclic':True}
summary['lock_sha256']=hashlib.sha256((HERE/'Cargo.lock').read_bytes()).hexdigest()
WORK.mkdir(parents=True,exist_ok=True);(WORK/'source-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2))
