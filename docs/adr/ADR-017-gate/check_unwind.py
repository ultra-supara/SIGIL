#!/usr/bin/env python3
"""Research format checks only. Never used as SIGIL's metadata parser."""
from pathlib import Path
import json
import re
import runpy
import struct
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[3]
WORK=ROOT/'target/tmp/issue48/task2'
FIX=ROOT/'crates/sigil-engine/tests/fixtures/code-macho'
api=runpy.run_path(str(FIX.parent/'code-aarch64/fixture_tools.py'))


def sections(data):
    assert len(data)>=32 and struct.unpack_from('<I',data)[0]==0xfeedfacf
    n,sz=struct.unpack_from('<II',data,16);assert n<=64 and 32+sz<=len(data)
    result={};off=32
    for _ in range(n):
        cmd,size=struct.unpack_from('<II',data,off);assert size>=8 and off+size<=32+sz
        if cmd==0x19:
            count=struct.unpack_from('<I',data,off+64)[0];assert 72+count*80<=size
            for i in range(count):
                s=off+72+i*80;name=data[s:s+16].split(b'\0')[0].decode()
                addr,length,offset=struct.unpack_from('<QQI',data,s+32)
                assert offset+length<=len(data)
                result[name]=(offset,length,addr)
        off+=size
    assert off==32+sz
    return result


def table(data):
    def read(fmt,off):
        size=struct.calcsize(fmt);assert off>=0 and off+size<=len(data),'truncated structure'
        return struct.unpack_from(fmt,data,off)
    version,co,cn,po,pn,io,inc=read('<7I',0)
    assert version==1 and 2<=inc<=65536 and cn<=256 and pn<=3,'invalid header/count'
    for off,count,stride in [(co,cn,4),(po,pn,4),(io,inc,12)]:
        assert off>=28 and off+count*stride<=len(data),'invalid table extent'
    common=[read('<I',co+i*4)[0] for i in range(cn)]
    index=[read('<III',io+i*12) for i in range(inc)]
    assert index[-1][1]==0 and all(a[0]<b[0] for a,b in zip(index,index[1:])),'invalid index/sentinel'
    rows=[];kinds=[]
    for (base,page,_),(end,_,_) in zip(index,index[1:]):
        assert page>=28 and page+8<=len(data),'invalid page offset'
        kind,eo,en=read('<IHH',page);assert en>0 and en<=1021,'invalid entry count'
        kinds.append(kind);pageend=min(page+4096,len(data))
        if kind==2:
            assert eo>=8 and page+eo+en*8<=pageend,'invalid regular extent'
            entries=[read('<II',page+eo+i*8) for i in range(en)]
        elif kind==3:
            lo,ln=read('<HH',page+8)
            assert eo>=12 and page+eo+en*4<=pageend,'invalid compressed extent'
            assert lo>=12 and ln<=256 and page+lo+ln*4<=pageend,'invalid local extent'
            assert ln==0 or page+eo+en*4<=page+lo,'overlapping arrays'
            encodings=common+[read('<I',page+lo+i*4)[0] for i in range(ln)]
            assert len(encodings)<=256,'encoding count overflow'
            entries=[]
            for i in range(en):
                raw=read('<I',page+eo+i*4)[0];idx=raw>>24
                assert idx<len(encodings),'invalid encoding index'
                entries.append((base+(raw&0xffffff),encodings[idx]))
        else:raise AssertionError('unknown page kind')
        assert entries[0][0]==base and all(base<=a<end for a,_ in entries),'entry outside index range'
        assert all(a[0]<b[0] for a,b in zip(entries,entries[1:])),'unsorted/duplicate entries'
        assert all(enc!=0 for _,enc in entries),'zero encoding'
        rows.extend(entries)
    return rows,kinds,index


def dump(name,data):
    p=WORK/name;p.write_bytes(data)
    result=subprocess.run(['/usr/bin/llvm-objdump-21','--macho','--unwind-info',str(p)],check=True,capture_output=True,text=True).stdout
    (WORK/(name+'.unwind')).write_text(result)
    return result


folded=(FIX/'unwind-folded').read_bytes();ss=sections(folded)
uo,ul,_=ss['__unwind_info'];original=folded[uo:uo+ul]
rows,kinds,index=table(original)
assert kinds==[3] and rows==[(0x4c0,0x04000000)] and index[-1][0]==0x508
assert '__eh_frame' not in ss and 'LC_FUNCTION_STARTS' not in (FIX/'unwind-folded.macho').read_text()
# Neither this folded lookup range nor two symbol starts proves either function end.
assert re.search(r'00000000000004e4.*_one',(FIX/'unwind-folded.nm').read_text())

# Regular-page derivative: only representation changes. LLVM independently reads
# the same lookup entry; this is synthetic evidence, not LLD-emitted coverage.
page=index[0][1];regular=bytearray(original)
struct.pack_into('<IHHII',regular,page,2,8,1,*rows[0])
assert table(regular)[0]==rows
image=bytearray(folded);image[uo:uo+ul]=regular
assert 'function offset=0x000004c0' in dump('regular-page.macho',image)
assert 'function offset=0x000004c0' in dump('compressed-page.macho',folded)

# Local encoding (index immediately after common array), 24-bit delta and page base.
local=bytearray(original);struct.pack_into('<HH',local,page+8,16,1)
struct.pack_into('<I',local,page+12,1<<24);struct.pack_into('<I',local,page+16,rows[0][1])
assert table(local)[0]==rows
image[uo:uo+ul]=local
assert 'function offset=0x000004c0' in dump('compressed-local-page.macho',image)

mutations=[('version',0,'<I',2),('common extent',4,'<I',0xffffffff),('index count',24,'<I',0xffffffff),
 ('page kind',page,'<I',9),('page count',page+6,'<H',0xffff),('entry offset',page+4,'<H',0xffff),
 ('encoding index',page+12,'<I',0xff000000),('delta escapes range',page+12,'<I',0xffffff),
 ('local count',page+10,'<H',0xffff),('zero encoding',28,'<I',0)]
rejected=[]
for label,off,fmt,value in mutations:
    b=bytearray(original);struct.pack_into(fmt,b,off,value)
    try:table(b)
    except AssertionError:rejected.append(label)
    else:raise AssertionError('accepted malformed '+label)
for length in [0,27,page+7,page+11,page+15]:
    try:table(original[:length])
    except AssertionError:rejected.append('truncate '+str(length))
    else:raise AssertionError('accepted truncation')
# Exact linked FDE correspondence is independently read from LLVM's FDE dump.
fdes={}
for offset,start,end in re.findall(r'^([0-9a-f]+) .* FDE .* pc=([0-9a-f]+)\.\.\.([0-9a-f]+)',(FIX/'arm64-classic.frames').read_text(),re.M):
    fdes[int(offset,16)]=(int(start,16),int(end,16))
image=(FIX/'arm64-classic').read_bytes();sc=sections(image);off,length,_=sc['__unwind_info']
fde_rows,_,_=table(image[off:off+length])
for start,encoding in fde_rows:
    assert encoding&0x0f000000==0x03000000
    assert fdes[encoding&0xffffff][0]==start
assert list(fdes.values())==[(0x520,0x544),(0x544,0x568)]
# Existing fixture oracle independently validates all compact start relocations,
# explicit lengths, section targets and symbols before accepting these ranges.
shutil.copyfile(FIX/'compact-object.o',WORK/'compact-object.o')
b=api['Build']('macho',WORK);d=b.dumps('compact-object.o',True)
assert not api['ranges'](d)
assert api['compact_object_ranges'](d)=={0:0x24,0x24:0x48}
summary={'folded_entries':rows,'folded_lookup_end':index[-1][0], 'regular_and_compressed_equivalent':True,
 'compressed_local_encoding':True,'malformed_rejected':rejected,'fde_exact_intervals':list(fdes.values()),
 'compact_object_text_offsets':[[0,0x24],[0x24,0x48]],'compact_object_file_intervals':[[392,428],[428,464]],
 'native_linked_exact_intervals':[], 'note':'regular page is a synthetic derivative; native compact linked remains a missing-exact-bounds gap'}
(WORK/'unwind-summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))
