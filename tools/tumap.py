import re,csv,sys,bisect
ASM="/home/user/work/extract/decompiled_stack/mspdf_154.0.4258.33/assembly/mspdf_full_intel.asm"
FNS="/home/user/work/extract/decompiled_stack/mspdf_154.0.4258.33/indexes/functions.csv"
fns=[]
with open(FNS) as f:
    for r in csv.DictReader(f):
        fns.append((int(r["entry"],16), int(r["body_size"]), r["name"]))
fns.sort()
starts=[x[0] for x in fns]
def owner(a):
    i=bisect.bisect_right(starts,a)-1
    if i>=0:
        e,s,n=fns[i]
        if a < e+s+64: return (e,n,s)
    return (None,None,None)
targets={int(k,16):v for k,v in (x.split(":") for x in sys.argv[1:])}
pat=re.compile(r"^([0-9a-f]+):.*# (0x1[0-9a-f]+)$")
res={v:{} for v in targets.values()}
with open(ASM) as f:
    for line in f:
        m=pat.match(line)
        if not m: continue
        tgt=int(m.group(2),16)-0x180000000
        if tgt in targets:
            a=int(m.group(1),16)
            e,n,s=owner(a)
            if e: res[targets[tgt]].setdefault(e,(n,s,0)); 
            if e:
                n0,s0,c0=res[targets[tgt]][e]; res[targets[tgt]][e]=(n0,s0,c0+1)
for name,d in res.items():
    print(f"=== {name}: {len(d)} functions ===")
    for e in sorted(d):
        n,s,c=d[e]
        print(f"  {e:#x} {n:30s} size={s:6d} refs={c}")
