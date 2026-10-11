#!/usr/bin/env python3
import sys, struct, re

def u32(x): return x & 0xffffffff

def s8(x): return x-256 if x>=128 else x

def get16(b,i): return b[i] | (b[i+1]<<8)

def sfh_hash(data):
    if isinstance(data,str): data=data.encode('utf-8')
    n=len(data)
    if n<=0: return 0
    h=n
    rem=n & 3
    loops=n>>2
    i=0
    for _ in range(loops):
        h=u32(h + get16(data,i))
        tmp=u32((get16(data,i+2)<<11) ^ h)
        h=u32((h<<16) ^ tmp)
        i += 4
        h=u32(h + (h>>11))
    if rem==3:
        h=u32(h + get16(data,i))
        h=u32(h ^ (h<<16))
        h=u32(h ^ u32(s8(data[i+2])<<18))
        h=u32(h + (h>>11))
    elif rem==2:
        h=u32(h + get16(data,i))
        h=u32(h ^ (h<<11))
        h=u32(h + (h>>17))
    elif rem==1:
        h=u32(h + s8(data[i]))
        h=u32(h ^ (h<<10))
        h=u32(h + (h>>1))
    h=u32(h ^ (h<<3))
    h=u32(h + (h>>5))
    h=u32(h ^ (h<<4))
    h=u32(h + (h>>17))
    h=u32(h ^ (h<<25))
    h=u32(h + (h>>6))
    return h

def parse_quoted(line):
    m=re.search(r'"(.*)"\s*$',line)
    if not m: return ''
    s=m.group(1)
    # po2lmo's extract_string only unescapes \" and \\, while retaining e.g. \\n.
    out=[]; i=0
    while i<len(s):
        if s[i]=='\\' and i+1<len(s) and s[i+1] in ('"','\\'):
            out.append(s[i+1]); i+=2
        else:
            out.append(s[i]); i+=1
    return ''.join(out)

def parse_po(path):
    entries=[]
    cur={'id':None,'str':None,'field':None}
    def flush():
        nonlocal cur
        if cur['id'] is not None and cur['str'] is not None and cur['id']!='' and cur['str']!='':
            entries.append((cur['id'],cur['str']))
        cur={'id':None,'str':None,'field':None}
    with open(path,encoding='utf-8') as f:
        for line in f:
            line=line.rstrip('\n')
            if line.startswith('msgid "'):
                if cur['id'] is not None or cur['str'] is not None: flush()
                cur['id']=parse_quoted(line); cur['field']='id'
            elif line.startswith('msgstr "'):
                cur['str']=parse_quoted(line); cur['field']='str'
            elif line.startswith('"'):
                val=parse_quoted(line)
                if cur['field']=='id': cur['id']=(cur['id'] or '')+val
                elif cur['field']=='str': cur['str']=(cur['str'] or '')+val
            elif line.startswith('msgctxt ') or line.startswith('msgid_plural ') or line.startswith('msgstr['):
                raise SystemExit('plural/context PO not supported by this minimal builder')
        if cur['id'] is not None or cur['str'] is not None: flush()
    return entries

def build(inp,outp):
    vals=bytearray(); idx=[]
    for key,val in parse_po(inp):
        kb=key.encode(); vb=val.encode()
        kh=sfh_hash(kb); vh=sfh_hash(vb)
        if kh==vh: continue
        off=len(vals); vals.extend(vb); vals.extend(b'\0'*((-len(vb))%4))
        idx.append((kh,1,off,len(vb)))
    idx.sort(key=lambda x:x[0])
    data=bytearray(vals)
    for e in idx: data.extend(struct.pack('!IIII',*e))
    data.extend(struct.pack('!I',len(vals)))
    open(outp,'wb').write(data)
if __name__=='__main__':
    if len(sys.argv)!=3: raise SystemExit('usage: po2lmo.py in.po out.lmo')
    build(sys.argv[1],sys.argv[2])
