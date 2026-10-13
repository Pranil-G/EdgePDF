import csv,sys
lo,hi=int(sys.argv[1],16),int(sys.argv[2],16)
minsz=int(sys.argv[3]) if len(sys.argv)>3 else 0
rows=[]
with open("/home/user/work/extract/decompiled_stack/mspdf_154.0.4258.33/indexes/functions.csv") as f:
    for r in csv.DictReader(f):
        e=int(r["entry"],16)
        if lo<=e<=hi and int(r["body_size"])>=minsz:
            rows.append((e,r["name"],int(r["body_size"]),r["namespace"]))
rows.sort(key=lambda x:-x[2])
for e,n,s,ns in rows: print(f"{e:#x} {n:38s} {s:6d} {ns}")
print(f"// {len(rows)} functions")
