#!/usr/bin/env python3
"""Navigator for the symbol-assisted Edge PDF glue corpus (msedge.dll).

  glue.py ls   <regex> [...]     symbols whose demangled name matches
  glue.py asm  <rva> [bytes]     disassembly at an RVA from the glue .asm
  glue.py str  <regex>           strings referenced in the glue assembly
  glue.py near <rva> [n]         n symbols either side of an RVA, by address

MSVC names are demangled only to their scope chain (scope1::scope2::name);
the signature is left off, which is enough to navigate.
"""
import csv, os, re, subprocess, sys

ROOT = "/home/user/work/extract/decompiled_stack/edge_glue_154.0.4258.53"
FNS = os.path.join(ROOT, "functions.csv")
ASM = os.path.join(ROOT, "msedge_first_party_pdf_glue.asm")


def demangle(m):
    if not m.startswith("?"):
        return m
    body = m[1:].split("@@")[0]
    return "::".join(reversed([p for p in body.split("@") if p]))


def rows():
    for r in csv.DictReader(open(FNS)):
        names = [demangle(x.strip()) for x in (r["names"] or "").split(" | ")]
        yield int(r["rva"], 16), int(r["size"]), r["boundary"], names


def ls(args):
    pats = [re.compile(a, re.I) for a in args]
    n = 0
    for rva, sz, b, names in rows():
        hit = [x for x in names if any(p.search(x) for p in pats)]
        if hit:
            n += 1
            print("0x%x %6d %-12s %s" % (rva, sz, b, " | ".join(hit)))
    print("// %d symbols" % n)


def near(args):
    tgt = int(args[0], 16)
    k = int(args[1]) if len(args) > 1 else 8
    all_ = sorted(rows())
    i = min(range(len(all_)), key=lambda j: abs(all_[j][0] - tgt))
    for rva, sz, b, names in all_[max(0, i - k):i + k + 1]:
        mark = "->" if rva == all_[i][0] else "  "
        print("%s 0x%x %6d %s" % (mark, rva, sz, " | ".join(names)))


def asm(args):
    rva = int(args[0], 16)
    nb = int(args[1]) if len(args) > 1 else 400
    pat = "^ +0*%x  " % rva
    out = subprocess.run(["grep", "-n", "-m1", "-E", pat, ASM],
                         capture_output=True, text=True).stdout
    if not out:
        print("// no line starting at %x" % rva)
        return
    line = int(out.split(":")[0])
    subprocess.run(["sed", "-n", "%d,+%dp" % (line, nb), ASM])


def strings(args):
    pat = args[0]
    subprocess.run(["grep", "-o", "-i", "-E",
                    r'"[^"]{0,200}%s[^"]{0,200}"' % pat, ASM])


if __name__ == "__main__":
    {"ls": ls, "asm": asm, "str": strings, "near": near}[sys.argv[1]](sys.argv[2:])
