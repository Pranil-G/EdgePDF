#!/usr/bin/env python3
"""Bulk-extract pseudocode for whole address regions, so grep-scale scans work.

  extract_range.py <out.c> <lo>-<hi> [<lo>-<hi> ...]

Addresses are bare hex RVAs/VAs as they appear in the corpus (e.g. 180640000).
Requires pc_index.json (build it with `pc.py build`).
"""
import json, sys

IDX = json.load(open("/home/user/work/tools/pc_index.json"))
PC = ("/home/user/work/extract/decompiled_stack/mspdf_154.0.4258.33"
      "/pseudocode/mspdf_all_functions.c")

if len(sys.argv) < 3:
    sys.exit(__doc__)

outpath = sys.argv[1]
ranges = [(int(a, 16), int(b, 16)) for a, b in (x.split("-") for x in sys.argv[2:])]
ents = sorted(int(k, 16) for k in IDX)

n = 0
with open(PC, "rb") as f, open(outpath, "w") as out:
    for e in ents:
        if any(lo <= e <= hi for lo, hi in ranges):
            s, t = IDX["%x" % e]
            f.seek(s)
            out.write(f.read(t - s).decode("utf-8", "replace"))
            n += 1
print("extracted %d functions -> %s" % (n, outpath))
