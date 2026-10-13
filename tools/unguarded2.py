import json,re,sys
IDX=json.load(open("/home/user/work/tools/pc_index.json"))
PC="/home/user/work/extract/decompiled_stack/mspdf_154.0.4258.33/pseudocode/mspdf_all_functions.c"
data=open(PC,"rb").read().decode("utf-8","replace")
CAST=r"(?:\((?:longlong|ulonglong|int|uint|short|ushort|byte|char)\)\s*)?"
PATS=[
  # *(T *)(BASE + IDX * K) =
  re.compile(r"\*\([a-z0-9_]+ \*\)\(([A-Za-z_]\w*)\s*\+\s*"+CAST+r"([A-Za-z_]\w*)\s*\*\s*(0x[0-9a-f]+|\d+)\)\s*="),
  # *(T *)(IDX * K + BASE) =        <-- reversed
  re.compile(r"\*\([a-z0-9_]+ \*\)\("+CAST+r"([A-Za-z_]\w*)\s*\*\s*(0x[0-9a-f]+|\d+)\s*\+\s*([A-Za-z_]\w*)\)\s*="),
  # BASE[IDX] =
  re.compile(r"\b([A-Za-z_]\w*)\[("+CAST+r"[A-Za-z_]\w*)\]\s*="),
]
CMP=re.compile(r"[<>]=?|!=|==")
out={}
for k,(s,e) in IDX.items():
    ent=int(k,16); body=data[s:e]
    cmptext=" ".join(l for l in body.split("\n") if CMP.search(l))
    for pi,P in enumerate(PATS):
        for m in P.finditer(body):
            g=m.groups()
            if pi==0: base,idx,st=g[0],g[1],g[2]
            elif pi==1: base,idx,st=g[2],g[0],g[1]
            else:
                base=g[0]; idx=re.sub(r"^\(\w+\)\s*","",g[1]); st="arr"
            if not re.match(r"^(u?[a-z]Var\d+|param_\d+|local_[0-9a-f]+|i?[A-Za-z]Var\d+)$", idx): continue
            if re.search(r"\b"+re.escape(idx)+r"\b", cmptext): continue
            out.setdefault(ent,set()).add((base,idx,st))
print(f"// {len(out)} functions with an unguarded indexed write (3 operand forms)")
for ent in sorted(out):
    items=sorted(out[ent])[:3]
    print(f"{ent:#x}  " + " ; ".join(f"{b}[{i}]x{s}" for b,i,s in items))
