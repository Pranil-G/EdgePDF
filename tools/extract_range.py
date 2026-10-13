import json,sys,csv
IDX=json.load(open("/home/user/work/tools/pc_index.json"))
PC="/home/user/work/extract/decompiled_stack/mspdf_154.0.4258.33/pseudocode/mspdf_all_functions.c"
ranges=[(int(a,16),int(b,16)) for a,b in (x.split("-") for x in sys.argv[1:])]
ents=sorted(int(k,16) for k in IDX)
out=open("/home/user/work/tools/jp2k_all.c","w")
n=0
with open(PC,"rb") as f:
    for e in ents:
        if any(lo<=e<=hi for lo,hi in ranges):
            s,t=IDX["%x"%e]; f.seek(s); out.write(f.read(t-s).decode("utf-8","replace")); n+=1
out.close(); print("extracted",n,"functions")
