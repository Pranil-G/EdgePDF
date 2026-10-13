import json,re,sys
IDX=json.load(open("/home/user/work/tools/pc_index.json"))
PC="/home/user/work/extract/decompiled_stack/mspdf_154.0.4258.33/pseudocode/mspdf_all_functions.c"
data=open(PC,"rb").read().decode("utf-8","replace")
# narrowed increments used as loop counters
PATS=[
 (r"=\s*\((?:ulonglong|uint|int|longlong)\)\(byte\)\(\(char\)\s*([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*1\)", "u8"),
 (r"=\s*\((?:ulonglong|uint|int|longlong)\)\(ushort\)\(\(short\)\s*([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*1\)", "u16"),
 (r"=\s*\(byte\)\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*1\)", "u8b"),
 (r"=\s*\(ushort\)\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*1\)", "u16b"),
]
hits={}
for k,(s,e) in IDX.items():
    ent=int(k,16); body=data[s:e]
    for pat,kind in PATS:
        for m in re.finditer(pat, body):
            var=m.group(1)
            # find a loop condition comparing this var
            conds=re.findall(r"while\s*\(([^\n]{0,160})\)", body)
            rel=[c for c in conds if re.search(r"\b"+re.escape(var)+r"\b", c)]
            # also 'bVar = var < X' style
            rel += re.findall(r"=\s*"+re.escape(var)+r"\s*<\s*([^;\n]{0,80});", body)
            hits.setdefault(ent,[]).append((kind,var,rel[:2]))
print(f"// {len(hits)} functions with a narrowed (8/16-bit) increment")
for ent,v in sorted(hits.items()):
    print(f"{ent:#x}  " + " | ".join(f"{k}:{var} cond={c}" for k,var,c in v[:2]))
