#!/usr/bin/env python3
"""Comparator regressions using actual adapter fields and fresh LLVM/GNU rows."""
import importlib.util
import contextlib
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('adr017_oracle',HERE/'check_oracles.py')
oracle=importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)
WORK=oracle.WORK/'fix'
WORK.mkdir(parents=True,exist_ok=True)
word='2a0103e0'
source=WORK/'shift-regression.S'
source.write_text('.text\n.inst 0x'+word+'\n')
image=WORK/'shift-regression.o'
oracle.run(['/usr/bin/clang-21','-target','aarch64-linux-gnu','-c',source,'-o',image])
oracles={}
for name,command in [('llvm',['/usr/bin/llvm-objdump-21','-d','--disassembler-options=no-aliases',image]),
                     ('gnu',[oracle.GNU,'-d','-M','no-aliases',image])]:
    text=oracle.run(command)
    (WORK/('shift-regression.'+name+'.objdump')).write_text(text)
    rows=[m for line in text.splitlines() if (m:=oracle.ROW.match(line))]
    assert len(rows)==1 and rows[0][2]==word,(name,text)
    oracles[name]=oracle.assembly(rows[0][3],int(rows[0][1],16))
line=oracle.run([Path(sys.argv[1]).resolve(),'inspect'],input=word+'\n').strip()
raw_fields=line.split('\t')
assert raw_fields[0]==word and len(raw_fields)==3
records=[]
for candidate,field in zip(('yaxpeax','disarm64'),raw_fields[1:]):
    assert field.startswith('Ok(Some(') and field.endswith('))'),field
    raw=field[8:-2]
    assert 'RegShift(LSL, 0, W, 1)' in raw
    correct=oracle.typed(raw)
    assert all(correct==expected for expected in oracles.values()),(candidate,correct,oracles)
    record={'candidate':candidate,'word':word,'correct_lsl_0_accepted':True,'mutations':[]}
    for style,amount in [('LSR',0),('LSL',1),('LSR',1)]:
        changed=raw.replace('RegShift(LSL, 0, W, 1)',f'RegShift({style}, {amount}, W, 1)')
        assert changed!=raw
        projected=oracle.typed(changed)
        rejected={name:projected!=expected for name,expected in oracles.items()}
        assert all(rejected.values()),('shift mutation falsely accepted',candidate,style,amount,rejected)
        record['mutations'].append({'style':style,'amount':amount,'rejected_by':rejected})
    records.append(record)
# Independently retain fields when the textual oracle explicitly prints a shift.
for style,amount in [('lsl',0),('lsr',0),('lsl',1),('lsr',1)]:
    explicit=oracle.assembly(f'orr w0, wzr, w1, {style} #{amount}',0)
    changed=raw_fields[1][8:-2].replace('RegShift(LSL, 0, W, 1)',f'RegShift({style.upper()}, {amount}, W, 1)')
    assert oracle.typed(changed)==explicit
# Inventory cannot silently drop the prior omitted fixtures, and universal
# arm64 slices must have byte/hash-verified selected thin counterparts.
inventory=oracle.inventory()
by_name={Path(r['image']).name:r for r in inventory}
for name in ('duplicate-name-dylibs','duplicate-name-dylibs.before'):
    assert by_name[name]['action']=='compare'
for name in ('universal','universal-mixed'):
    slices=[s for s in by_name[name]['slices'] if s['architecture']=='aarch64']
    assert len(slices)==1 and slices[0]['action']=='deduplicate-identical-thin'
    assert slices[0]['sha256']=='8ecf0df0eba33104e40f536a6118704118b30cb2c674f231f4c7e480b9c07a8f'
# Exercise the complete checker with both candidate outputs altered together.
# A single hostile word plus the full fixture inventory keeps this regression
# small; the separate normal gate still compares the entire seeded corpus.
pipeline=[]
binary=Path(sys.argv[1]).resolve()
for style,amount in [('LSL',0),('LSR',0),('LSL',1),('LSR',1)]:
    label=f'{style.lower()}-{amount}'
    dest=WORK/label;dest.mkdir(parents=True,exist_ok=True)
    wrapper=dest/'adapter.py'
    replacement=f'RegShift({style}, {amount}, W, 1)'
    wrapper.write_text("#!/usr/bin/env python3\nimport subprocess,sys\n"
        +f"binary={str(binary)!r}\nword={word!r}\nreplacement={replacement!r}\n"
        +"if sys.argv[1:]==['words']:\n    print(word)\n    raise SystemExit(0)\n"
        +"assert sys.argv[1:]==['inspect']\n"
        +"p=subprocess.Popen([binary,'inspect'],stdin=sys.stdin,stdout=subprocess.PIPE,text=True)\n"
        +"changed=0\nfor line in p.stdout:\n"
        +"    if line.startswith(word+'\\t'):\n"
        +"        assert line.count('RegShift(LSL, 0, W, 1)')==2\n"
        +"        line=line.replace('RegShift(LSL, 0, W, 1)',replacement)\n        changed+=1\n"
        +"    print(line,end='')\nassert p.wait()==0 and changed==1\n")
    wrapper.chmod(0o755)
    oracle.WORK=dest
    failed=False
    with (dest/'oracle.log').open('w') as log, contextlib.redirect_stdout(log):
        try:oracle.main(wrapper)
        except AssertionError:failed=True
    assert failed==((style,amount)!=('LSL',0)),('pipeline shift mutation false accept',style,amount,failed)
    result=json.loads((dest/'oracle-summary.json').read_text())
    assert result['llvm']['errors']==result['gnu']['errors']==int(failed)
    if failed:assert all(result[name]['first'][0][0]==word for name in ('llvm','gnu'))
    pipeline.append({'style':style,'amount':amount,'accepted':not failed,
                     'llvm_errors':result['llvm']['errors'],'gnu_errors':result['gnu']['errors']})
summary={'shift_projection':records,'explicit_text_shift_fields_retained':True,
         'fixture_inventory_regressions':True,'complete_checker_mutations':pipeline}
(WORK/'regression-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2))
