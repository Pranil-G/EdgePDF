import json,re,sys
IDX=json.load(open("/home/user/work/tools/pc_index.json"))
PC="/home/user/work/extract/decompiled_stack/mspdf_154.0.4258.33/pseudocode/mspdf_all_functions.c"
data=open(PC,"rb").read().decode("utf-8","replace")

TARGET=sys.argv[1] if len(sys.argv)>1 else "FUN_1809e1e60"

def split_args(s):
    args=[];depth=0;cur=""
    for ch in s:
        if ch=='(' : depth+=1;cur+=ch
        elif ch==')':
            if depth==0: args.append(cur);return args
            depth-=1;cur+=ch
        elif ch==',' and depth==0: args.append(cur);cur=""
        else: cur+=ch
    return args

def base_of(expr):
    """extract the base pointer identifiers of field reads"""
    bases=set()
    for m in re.finditer(r"\*\((?:[a-z0-9_]+ \*)\)\(([A-Za-z_][A-Za-z0-9_]*)\s*\+", expr):
        bases.add(m.group(1))
    for m in re.finditer(r"\b([a-z]Var\d+|param_\d+|local_[0-9a-f]+)\b", expr):
        bases.add(m.group(1))
    return bases

# build function ranges
ents=sorted(((int(k,16),v) for k,v in IDX.items()), key=lambda x:x[1][0])
hits=0; flagged=[]
for ent,(s,e) in ents:
    body=data[s:e]
    if TARGET not in body: continue
    for m in re.finditer(re.escape(TARGET)+r"\(", body):
        tail=body[m.end():]
        args=split_args(tail)
        if len(args)<3: continue
        dst,src,ln=args[0].strip(),args[1].strip(),args[2].strip()
        hits+=1
        # only interesting if length reads a struct field
        if not re.search(r"\*\((?:[a-z0-9_]+ \*)\)\(", ln): continue
        db,lb = base_of(dst), base_of(ln)
        if db and lb and not (db & lb):
            flagged.append((ent,dst,src,ln))
print(f"// {TARGET}: {hits} call sites parsed, {len(flagged)} with length-base disjoint from dest-base")
for ent,dst,src,ln in flagged:
    print(f"\n{ent:#x}\n   dst = {dst[:110]}\n   src = {src[:110]}\n   len = {ln[:130]}")
