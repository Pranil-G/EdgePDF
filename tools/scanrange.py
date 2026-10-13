import json,re,sys
IDX=json.load(open("/home/user/work/tools/pc_index.json"))
PC="/home/user/work/extract/decompiled_stack/mspdf_154.0.4258.33/pseudocode/mspdf_all_functions.c"
data=open(PC,"rb").read().decode("utf-8","replace")
lo,hi=int(sys.argv[1],16),int(sys.argv[2],16)
TARGETS=sys.argv[3].split(",")
def split_args(s):
    args=[];depth=0;cur=""
    for ch in s:
        if ch=='(': depth+=1;cur+=ch
        elif ch==')':
            if depth==0: args.append(cur);return args
            depth-=1;cur+=ch
        elif ch==',' and depth==0: args.append(cur);cur=""
        else: cur+=ch
    return args
for k,(s,e) in sorted(IDX.items(), key=lambda x:int(x[0],16)):
    ent=int(k,16)
    if not(lo<=ent<=hi): continue
    body=data[s:e]
    for T in TARGETS:
        for m in re.finditer(re.escape(T)+r"\(", body):
            args=split_args(body[m.end():])
            if len(args)<3: continue
            a=[x.strip().replace("\n"," ") for x in args[:3]]
            print(f"{ent:#x} {T}\n    dst={a[0][:95]}\n    src={a[1][:95]}\n    len={a[2][:110]}")
