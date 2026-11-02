#!/usr/bin/env python3
"""Dump a vtable from mspdf.dll and resolve each slot to a function.

  vt.py <vtable-VA> [slots]        e.g. vt.py 180af2dd8 10
  vt.py --find <regex>             list RTTI vftable symbols matching a name

Breaks the virtual-dispatch wall: given an RTTI vftable address from
indexes/symbols.csv, print slot index, byte offset, target VA and the owning
function name/size, so `(**(code **)(*obj + 0xN))()` can be resolved concretely.
"""
import bisect, csv, os, re, struct, sys

ROOT = "/home/user/work/extract/decompiled_stack/mspdf_154.0.4258.33"
DLL = os.path.join(ROOT, "input/mspdf.dll")
FNS = os.path.join(ROOT, "indexes/functions.csv")
SYMS = os.path.join(ROOT, "indexes/symbols.csv")

# (name, file_offset, virtual_size, virtual_address)
SECTIONS = [(".text", 0x400, 0xADD759, 0x180001000),
            (".rdata", 0xADDC00, 0x49F254, 0x180ADF000),
            (".data", 0xF7D000, 0x1B0400, 0x180F7F000)]


def va_to_off(va):
    for _, fo, vs, base in SECTIONS:
        if base <= va < base + vs:
            return fo + (va - base)
    return None


def load_fns():
    fns = []
    for r in csv.DictReader(open(FNS)):
        fns.append((int(r["entry"], 16), int(r["body_size"]), r["name"]))
    fns.sort()
    return fns, [f[0] for f in fns]


def owner(fns, starts, a):
    i = bisect.bisect_right(starts, a) - 1
    if i < 0:
        return None
    e, s, n = fns[i]
    if a < e + s + 16:
        return (e, n, s, a - e)
    return None


def find(pattern):
    pat = re.compile(pattern, re.I)
    for r in csv.reader(open(SYMS)):
        if len(r) >= 3 and r[1] == "vftable" and pat.search(r[2]):
            print("%s  %s" % (r[0], r[2][:150]))


def dump(va, n):
    off = va_to_off(va)
    if off is None:
        sys.exit("VA %#x is outside the mapped sections" % va)
    fns, starts = load_fns()
    with open(DLL, "rb") as f:
        f.seek(off)
        blob = f.read(8 * n)
    for i in range(n):
        tgt = struct.unpack_from("<Q", blob, 8 * i)[0]
        o = owner(fns, starts, tgt) if 0x180000000 <= tgt < 0x182000000 else None
        if o:
            e, name, size, delta = o
            extra = "" if delta == 0 else "  (+%#x into it)" % delta
            print("  slot %-2d  +%#04x  -> %#x  %s  size=%d%s"
                  % (i, 8 * i, tgt, name, size, extra))
        else:
            print("  slot %-2d  +%#04x  -> %#x  <unresolved>" % (i, 8 * i, tgt))


if __name__ == "__main__":
    if sys.argv[1] == "--find":
        find(sys.argv[2])
    else:
        dump(int(sys.argv[1], 16), int(sys.argv[2]) if len(sys.argv) > 2 else 8)
