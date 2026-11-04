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
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
WORK = ROOT / "target/tmp/issue48/task2"
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
        if k in ('Register','RegisterOrSP'):
            width=64 if fs[0]=='X' else 32
            idx=int(fs[1])
            parts.append(('r',width,idx,('sp' if k=='RegisterOrSP' else 'zr') if idx==31 else 'reg'))
        elif k=='RegShift':
            style,amount,width,idx=fs[0].lower(),int(fs[1]),64 if fs[2]=='X' else 32,int(fs[3])
            assert style in ('lsl','lsr','asr','ror') and 0<=amount<width,(style,amount,width)
            parts.append(('shift',style,amount,('r',width,idx,'zr' if idx==31 else 'reg')))
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
        return ('orr',reg(fs[0]),reg('xzr' if fs[0][0]=='x' else 'wzr'),('shift','lsl',0,reg(fs[1])))
    if op in ('add','sub'):
        return (op,reg(fs[0]),reg(fs[1]),num(fs[2]),num(fs[3].removeprefix('lsl ')) if len(fs)>3 else 0)
    if op=='orr':
        assert 3<=len(fs)<=4,fs
        shift=re.fullmatch(r'(lsl|lsr|asr|ror)\s+#(0x[0-9a-f]+|[0-9]+)',fs[3]) if len(fs)==4 else None
        assert len(fs)==3 or shift,fs
        return (op,reg(fs[0]),reg(fs[1]),('shift',shift[1] if shift else 'lsl',num(shift[2]) if shift else 0,reg(fs[2])))
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


def architecture(data):
    """Classify bytes, never infer an architecture from a fixture filename."""
    assert len(data)>=8,'truncated fixture header'
    if data[:4]==b'\x7fELF':
        assert data[4:6]==b'\x02\x01','unsupported ELF fixture format'
        return 'elf','aarch64' if struct.unpack_from('<H',data,18)[0]==183 else 'other'
    if data[:4]==b'\xcf\xfa\xed\xfe':
        return 'macho','aarch64' if struct.unpack_from('<I',data,4)[0]==0x100000c else 'other'
    if data[:4]==b'\xce\xfa\xed\xfe':return 'macho32','other'
    if data[:4]==b'\xca\xfe\xba\xbe':return 'fat','multiple'
    raise AssertionError(('unrecognized fixture header',data[:8].hex()))


def inventory():
    """Account for every checked-in dump; prove fat-slice deduplication by bytes."""
    records=[];thin={};fat=[]
    for directory in ('code-aarch64','code-macho'):
        for dump in sorted((ROOT/'crates/sigil-engine/tests/fixtures'/directory).glob('*.objdump')):
            image=dump.with_name(dump.name.removesuffix('.objdump'))
            data=image.read_bytes();fmt,arch=architecture(data)
            record={'dump':str(dump.relative_to(ROOT)),'image':str(image.relative_to(ROOT)),
                    'format':fmt,'architecture':arch,'sha256':hashlib.sha256(data).hexdigest()}
            records.append(record)
            if fmt=='fat':fat.append((image,data,record));continue
            record['action']='compare' if arch=='aarch64' else 'exclude-non-aarch64'
            if arch=='aarch64':thin.setdefault(record['sha256'],[]).append((image,data))
    for image,data,record in fat:
        count=struct.unpack_from('>I',data,4)[0];assert 0<count<=64 and 8+count*20<=len(data)
        manifest=json.loads(image.with_name(image.name+'.slices.json').read_text())
        assert len(manifest)==count
        slices=[]
        for i,item in enumerate(manifest):
            cpu,subtype,offset,size,align=struct.unpack_from('>5I',data,8+i*20)
            assert (cpu,subtype,offset,size,align)==tuple(item[k] for k in ('cpu','subtype','offset','size','align'))
            assert size>0 and offset>=8+count*20 and offset+size<=len(data)
            payload=data[offset:offset+size];sha=hashlib.sha256(payload).hexdigest()
            assert sha==item['sha256'],('fat slice hash mismatch',image,i)
            fmt,arch=architecture(payload)
            assert (arch=='aarch64')==(cpu==0x100000c)
            entry={'slice_index':i,'cpu':cpu,'offset':offset,'size':size,'sha256':sha,'architecture':arch}
            if arch=='aarch64':
                matches=thin.get(sha,[])
                assert matches,('new AArch64 fat slice needs a thin oracle fixture',image,i,sha)
                assert all(payload==raw for _,raw in matches)
                source=image.parent/item['source']
                assert any(source==path for path,_ in matches),('fat source does not match selected thin fixture',source)
                entry.update(action='deduplicate-identical-thin',source=str(source.relative_to(ROOT)))
            else:entry['action']='exclude-non-aarch64'
            slices.append(entry)
        record.update(action='accounted-fat-slices',slices=slices)
    assert records
    return records


def main(binary):
    BIN=Path(binary).resolve()
    words=set(run([BIN,'words']).splitlines())
    fixture_rows=0
    fixture_instructions=[]
    fixture_inventory=inventory()
    for entry in fixture_inventory:
        if entry['action']!='compare':continue
        p=ROOT/entry['dump']
        count=0
        for line in p.read_text().splitlines():
            if m:=ROW.match(line):
                words.add(m[2]);fixture_rows+=1;count+=1
                fixture_instructions.append((str(p.relative_to(ROOT)),int(m[1],16),m[2],m[3]))
        assert count>0,('empty AArch64 fixture dump',p)
        entry['instruction_rows']=count
        if entry['format']=='elf':
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
    summary={'fixture_inventory':fixture_inventory,'gnu_relocation_rendering_differences':{'count':len(rendering_differences),'records':rendering_differences},'original_fixture_address_checks':original_counts,'fixture_rows':fixture_rows,'unique_total_words':len(words),'unique_eligible':len(expected),'rejected_fixture_words':rejected,'input_sha256':hashlib.sha256(input_words.encode()).hexdigest()}
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


if __name__=="__main__":
    main(sys.argv[1])
