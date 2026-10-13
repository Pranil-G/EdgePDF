import json,re,sys
IDX=json.load(open("/home/user/work/tools/pc_index.json"))
PC="/home/user/work/extract/decompiled_stack/mspdf_154.0.4258.33/pseudocode/mspdf_all_functions.c"
data=open(PC,"rb").read().decode("utf-8","replace")

# indexed write:  *(T *)(BASE + IDX * K) = ...     with K a power-of-2-ish constant
W = re.compile(r"\*\((?:[a-z0-9_]+) \*\)\(([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*(?:\(\w+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\*\s*(0x[0-9a-f]+|\d+)\)\s*=")
CMP = re.compile(r"[<>]=?|!=|==")

lo,hi = int(sys.argv[1],16), int(sys.argv[2],16)
out=[]
for k,(s,e) in IDX.items():
    ent=int(k,16)
    if not (lo<=ent<=hi): continue
    body=data[s:e]
    # collect all comparison lines
    cmps=[l for l in body.split("\n") if CMP.search(l)]
    cmptext=" ".join(cmps)
    for m in W.finditer(body):
        base,idx,stride=m.group(1),m.group(2),m.group(3)
        if idx.startswith("param_") and base.startswith("param_"): pass
        # is idx ever compared in this function?
        if re.search(r"\b"+re.escape(idx)+r"\b", cmptext): continue
        # skip trivially-bounded loop counters (idx assigned from a constant then only incremented)
        out.append((ent,base,idx,stride,m.group(0)[:100]))
print(f"// {len(out)} indexed writes whose index never appears in any comparison")
seen=set()
for ent,base,idx,stride,txt in out:
    if ent in seen: continue
    seen.add(ent)
    print(f"{ent:#x}  base={base} idx={idx} stride={stride}")
