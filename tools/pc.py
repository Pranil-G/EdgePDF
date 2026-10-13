#!/usr/bin/env python3
"""Fast navigator for the mspdf decompiled corpus."""
import json, os, re, sys, bisect

ROOT = "/home/user/work/extract/decompiled_stack/mspdf_154.0.4258.33"
PC   = os.path.join(ROOT, "pseudocode/mspdf_all_functions.c")
IDX  = "/home/user/work/tools/pc_index.json"
FNS  = os.path.join(ROOT, "indexes/functions.csv")
EDG  = os.path.join(ROOT, "indexes/call_edges.csv")
ASM  = os.path.join(ROOT, "assembly/mspdf_full_intel.asm")

def build():
    idx = {}
    hdr = re.compile(rb"^ \* entry: ([0-9a-fA-F]+)\s*$")
    with open(PC, "rb") as f:
        off = 0
        starts = []   # (block_start_off, entry)
        pending = None
        for line in f:
            if line.startswith(b"/* ====="):
                pending = off
            else:
                m = hdr.match(line)
                if m and pending is not None:
                    starts.append((pending, m.group(1).decode()))
                    pending = None
            off += len(line)
        total = off
    for i, (s, e) in enumerate(starts):
        end = starts[i+1][0] if i+1 < len(starts) else total
        idx[e.lower()] = [s, end]
    with open(IDX, "w") as f:
        json.dump(idx, f)
    print(f"indexed {len(idx)} functions")

def _idx():
    with open(IDX) as f:
        return json.load(f)

def norm(a):
    a = a.lower().replace("0x", "").lstrip("f")
    a = a.lower().replace("0x", "")
    if a.startswith("fun_"): a = a[4:]
    if a.startswith("sub_"): a = a[4:]
    if len(a) < 9 and not a.startswith("180") and not a.startswith("181"):
        a = "180" + a.rjust(6, "0")
    return a.lower()

def getfn(args):
    idx = _idx()
    with open(PC, "rb") as f:
        for a in args:
            k = norm(a)
            if k not in idx:
                print(f"// NOT FOUND: {a} (norm {k})"); continue
            s, e = idx[k]
            f.seek(s)
            sys.stdout.write(f.read(e-s).decode("utf-8", "replace"))

def callers(args):
    tgt = {norm(a) for a in args}
    out = []
    with open(EDG) as f:
        next(f)
        for line in f:
            p = line.rstrip("\n").split(",")
            if len(p) < 6: continue
            ce = p[3].strip('"').lower()
            if ce in tgt:
                out.append((p[1].strip('"'), p[0].strip('"'), p[2].strip('"'), p[4].strip('"')))
    seen=set()
    for name, entry, site, cal in out:
        k=(entry,cal)
        if k in seen: continue
        seen.add(k)
        print(f"{entry} {name}  --call@{site}-->  {cal}")
    print(f"// {len(seen)} unique caller->callee pairs")

def callees(args):
    src = {norm(a) for a in args}
    seen = set()
    with open(EDG) as f:
        next(f)
        for line in f:
            p = line.rstrip("\n").split(",")
            if len(p) < 6: continue
            if p[0].strip('"').lower() in src:
                k = (p[3].strip('"'), p[4].strip('"'))
                if k not in seen:
                    seen.add(k)
                    print("  -> %s %s" % k)
    print("// %d unique callees" % len(seen))

def info(args):
    want = {norm(a) for a in args}
    with open(FNS) as f:
        hdr = next(f)
        for line in f:
            p = [x.strip('"') for x in line.rstrip("\n").split(",")]
            if p[1].lower() in want:
                print(f"{p[1]} {p[2]} ns={p[3]} size={p[4]} args={p[5]} thunk={p[6]} status={p[8]}")

if __name__ == "__main__":
    cmd = sys.argv[1]
    {"build":lambda a: build(), "get":getfn, "callers":callers, "callees":callees, "info":info}[cmd](sys.argv[2:])
