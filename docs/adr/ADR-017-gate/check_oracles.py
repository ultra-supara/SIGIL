#!/usr/bin/env python3
"""Independent LLVM/GNU operand/width/PC oracle for every eligible hostile word.

The Rust side uses no instruction formatter. Only tool disassembly is parsed.
Task 1 words are independently reassembled into this same corpus. Generated
objects/dumps and all large output stay under target/tmp/issue48/task2.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
WORK = ROOT / "target/tmp/issue48/task2"
BIN = Path(sys.argv[1]).resolve()
WORK.mkdir(parents=True, exist_ok=True)
os.environ.update(LC_ALL="C", TZ="UTC", SOURCE_DATE_EPOCH="0")
os.environ['LD_LIBRARY_PATH'] = str(ROOT / 'target/tmp/issue48/toolchains/binutils-2.46/usr/lib/x86_64-linux-gnu')
GNU = ROOT / 'target/tmp/issue48/toolchains/binutils-2.46/usr/bin/aarch64-linux-gnu-objdump'
ROW = re.compile(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.*)$')


def run(args, **kw):
    return subprocess.run(list(map(str,args)),check=True,text=True,capture_output=True,**kw).stdout


def signed(n):
    return n - (1 << 64) if n >= (1 << 63) else n


def reg(s):
    s=s.strip()
    if s in ('sp','wsp'): return ('r',64 if s=='sp' else 32,31,'sp')
    if s in ('xzr','wzr'): return ('r',64 if s=='xzr' else 32,31,'zr')
    assert re.fullmatch('[xw][0-9]+',s),s
    return ('r',64 if s[0]=='x' else 32,int(s[1:]),'reg')


def num(s):
    s=s.strip().removeprefix('#')
    return int(s,16 if '0x' in s else 10)


def typed(text):
    m=re.fullmatch(r'Instruction \{ opcode: (\w+)(?:\((\d+)\))?, operands: \[(.*)\] \}',text)
    assert m,text
    op,cond,body=m.groups()
    parts=[]
    for k,fields in re.findall(r'(\w+)\(([^()]*)\)',body):
        fs=[x.strip() for x in fields.split(',')]
        if k in ('Register','RegisterOrSP','RegShift'):
            width=64 if (fs[0] if k!='RegShift' else fs[2])=='X' else 32
            idx=int(fs[1] if k!='RegShift' else fs[3])
            parts.append(('r',width,idx,('sp' if k=='RegisterOrSP' else 'zr') if idx==31 else 'reg'))
        elif k in ('Immediate','Imm16','PCOffset'):parts.append(int(fs[0]))
        elif k=='ImmShift':parts.append(int(fs[0])<<int(fs[1]))
        elif k in ('RegPreIndex','RegPostIndex'):
            idx=int(fs[0]);base=('r',64,idx,'sp' if idx==31 else 'reg')
            parts.append(('mem',base,int(fs[1]), 'post' if k=='RegPostIndex' else 'pre' if fs[2]=='true' else 'offset'))
        elif k=='ControlReg':parts.append(int(fs[0]))
        else:raise AssertionError(k)
    if op=='Bcc':op='b.'+['eq','ne','hs','lo','mi','pl','vs','vc','hi','ls','ge','lt','gt','le'][int(cond)]
    else:op=op.lower()
    if op in ('movn','movz'):
        value=parts[1] if op=='movz' else ~parts[1]
        return ('const',parts[0], value & ((1<<parts[0][1])-1))
    if op=='movk':
        imm,shift=map(int,re.search(r'ImmShift\((\d+), (\d+)\)',body).groups())
        return (op,parts[0],imm,shift)
    if op in ('add','sub'):
        shifted=re.search(r'ImmShift\((\d+), (\d+)\)',body)
        return (op,*parts[:2],int(shifted[1]) if shifted else parts[2],int(shifted[2]) if shifted else 0)
    if op=='hint':return ('hint',0)
    return (op,*parts)


def assembly(text,pc):
    text=re.split(r'\s*(?://|;|<)',text)[0].strip()
    op,_,args=text.partition(' ')
    if '\t' in op:op,_,args=text.partition('\t')
    op=op.strip();args=args.strip()
    fs=[x.strip() for x in args.split(',')]
    if op=='ret':return ('ret',reg(fs[0]) if args else reg('x30'))
    if op in ('br','blr'):return (op,reg(fs[0]))
    if op=='nop':return ('hint',0)
    if op=='hint':return (op,num(fs[0]))
    if op in ('b','bl') or op.startswith('b.'):
        # GNU condition synonyms carry the same raw class.
        op={'b.cs':'b.hs','b.cc':'b.lo'}.get(op,op)
        return (op,signed((int(fs[-1],16)-pc)&((1<<64)-1)))
    if op in ('cbz','cbnz','tbz','tbnz'):
        return (op,reg(fs[0]),*([num(fs[1])] if op.startswith('tb') else []),signed((int(fs[-1],16)-pc)&((1<<64)-1)))
    if op in ('adr','adrp'):
        origin=pc & ~4095 if op=='adrp' else pc
        return (op,reg(fs[0]),signed((int(fs[1],16)-origin)&((1<<64)-1)))
    if op in ('movn','movz','movk'):
        value=num(fs[1]) << (num(fs[2].removeprefix('lsl ')) if len(fs)>2 else 0)
        if op=='movk':return (op,reg(fs[0]),num(fs[1]),num(fs[2].removeprefix('lsl ')) if len(fs)>2 else 0)
        if op=='movn':value=~value
        return ('const',reg(fs[0]),value&((1<<reg(fs[0])[1])-1))
    if op=='mov':
        if fs[1].startswith('#'):return ('const',reg(fs[0]),num(fs[1])&((1<<reg(fs[0])[1])-1))
        # Accepted aliases: ADD Rd, Rn, #0 or ORR Rd, ZR, Rm.
        if 'sp' in args:return ('add',reg(fs[0]),reg(fs[1]),0,0)
        return ('orr',reg(fs[0]),reg('xzr' if fs[0][0]=='x' else 'wzr'),reg(fs[1]))
    if op in ('add','sub'):
        return (op,reg(fs[0]),reg(fs[1]),num(fs[2]),num(fs[3].removeprefix('lsl ')) if len(fs)>3 else 0)
    if op=='orr':return (op,*map(reg,fs))
    if op in ('ldr','str','stp','ldp'):
        regs,mem=args.split('[',1)
        regs=[reg(x) for x in regs.strip().rstrip(',').split(',')]
        inner,after=mem.split(']',1)
        mfs=inner.split(',');base=reg(mfs[0]);off=num(mfs[1]) if len(mfs)>1 else 0
        mode='offset'
        if after.strip()=='!':mode='pre'
        elif after.strip().startswith(','):mode='post';off=num(after.strip()[1:])
        return (op,*regs,('mem',base,off,mode))
    raise AssertionError((op,args))


words=set(run([BIN,'words']).splitlines())
fixture_rows=0
fixture_instructions=[]
for directory in ('code-aarch64','code-macho'):
    for p in sorted((ROOT/'crates/sigil-engine/tests/fixtures'/directory).glob('*.objdump')):
        if directory=='code-macho' and not p.name.startswith(('arm64','compact','unwind','no-unwind')):continue
        for line in p.read_text().splitlines():
            if m:=ROW.match(line):
                words.add(m[2]);fixture_rows+=1
                fixture_instructions.append((str(p.relative_to(ROOT)),int(m[1],16),m[2],m[3]))
        if directory=='code-aarch64':
            gnu=p.with_name(p.name.removesuffix('.objdump')+'.gnu-objdump')
            assert gnu.exists(),gnu
            for line in gnu.read_text().splitlines():
                if m:=ROW.match(line):fixture_instructions.append((str(gnu.relative_to(ROOT)),int(m[1],16),m[2],m[3]))
words=sorted(words)
input_words='\n'.join(words)+'\n'
(WORK/'words.txt').write_text(input_words)
with (WORK/'words.txt').open() as source, (WORK/'typed.tsv').open('w') as dest:
    subprocess.run([BIN,'inspect'],stdin=source,stdout=dest,check=True)
expected={};raw_wide={};rejected=[]
for line in (WORK/'typed.tsv').open():
    line=line.rstrip('\n')
    word,a,b=line.split('\t')
    if a=='Ok(None)':
        assert b=='Ok(None)';rejected.append(word);continue
    assert a.startswith('Ok(Some(') and b.startswith('Ok(Some('),(word,a,b)
    aa=typed(a[8:-2]);bb=typed(b[8:-2]);assert aa==bb,(word,aa,bb)
    expected[word]=aa
    if mm:=re.search(r'opcode: (MOVN|MOVZ|MOVK),.*ImmShift\((\d+), (\d+)\)',a):
        raw_wide[word]=(mm[1].lower(),int(mm[2]),int(mm[3]))
original_counts={'llvm':0,'gnu':0,'unsupported':0}
rendering_differences=[]
raw_gnu_objects={}
for path,pc,word,asm in fixture_instructions:
    if word not in expected:
        original_counts['unsupported']+=1;continue
    actual=assembly(asm,pc)
    if actual!=expected[word] and path.endswith('.o.gnu-objdump') and expected[word][0] in ('b','bl'):
        rendering_differences.append({'file':path,'pc':hex(pc),'word':word,'gnu_relocated_rendering':asm,'raw_semantics':expected[word]})
        if path not in raw_gnu_objects:
            source=ROOT/path.removesuffix('.gnu-objdump')
            dest=WORK/('raw-'+source.name)
            # Remove only text relocation metadata; preserve every instruction byte.
            run(['/usr/bin/llvm-objcopy-21','--remove-section=.rela.text',source,dest])
            rows={}
            for row in run([GNU,'-d','-M','no-aliases',dest]).splitlines():
                if mm:=ROW.match(row):rows[int(mm[1],16)]=(mm[2],mm[3])
            raw_gnu_objects[path]=rows
        rawword,rawasm=raw_gnu_objects[path][pc]
        assert rawword==word
        actual=assembly(rawasm,pc)
    assert actual==expected[word],(path,hex(pc),word,asm,expected[word])
    original_counts['gnu' if path.endswith('gnu-objdump') else 'llvm']+=1
assembly_source='.text\n'+''.join(f'.inst 0x{w}\n' for w in expected)
(WORK/'corpus.S').write_text(assembly_source)
run(['/usr/bin/clang-21','-target','aarch64-linux-gnu','-c',WORK/'corpus.S','-o',WORK/'corpus.o'])
summary={'gnu_relocation_rendering_differences':{'count':len(rendering_differences),'records':rendering_differences},'original_fixture_address_checks':original_counts,'fixture_rows':fixture_rows,'unique_total_words':len(words),'unique_eligible':len(expected),'rejected_fixture_words':rejected,'input_sha256':hashlib.sha256(input_words.encode()).hexdigest()}
for name,command in [('llvm',['/usr/bin/llvm-objdump-21','-d','--disassembler-options=no-aliases',WORK/'corpus.o']),('gnu',[GNU,'-d','-M','no-aliases',WORK/'corpus.o'])]:
    path=WORK/f'corpus.{name}.objdump'
    with path.open('w') as dest:
        subprocess.run(list(map(str,command)),stdout=dest,check=True)
    count=0;errors=[]
    for line in path.open():
        if not (m:=ROW.match(line)):continue
        pc=int(m[1],16);word=m[2];actual=assembly(m[3],pc)
        if name=='gnu' and word in raw_wide:
            mm=re.match(r'(movn|movz|movk)\s+\w+,\s*#(0x[0-9a-f]+)(?:,\s*lsl\s*#(\d+))?',m[3])
            assert mm and (mm[1],int(mm[2],16),int(mm[3] or 0))==raw_wide[word],(word,m[3],raw_wide[word])
        count+=1
        if actual!=expected[word]:errors.append((word,expected[word],actual))
    summary[name]={'count':count,'errors':len(errors),'first':errors[:10]}
    assert count==len(expected),(name,count,len(expected))
print(json.dumps(summary,indent=2))
(WORK/'oracle-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
assert not any(summary[k]['errors'] for k in ('llvm','gnu'))
