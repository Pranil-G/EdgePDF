# Static-audit tooling for the decompiled mspdf.dll corpus

These operate on the `decompiled_stack` corpus from the release asset, not on this repo.
Set the corpus root first; the scripts default to
`/home/user/work/extract/decompiled_stack/mspdf_154.0.4258.33`.

| tool | purpose |
|---|---|
| `pc.py` | byte-offset index over the 90 MB pseudocode. `build` once, then `get <addr…>` (O(1) function extraction), `callers <addr>`, `callees <addr>`, `info <addr>` |
| `rng.py <lo> <hi> [minsize]` | functions in an address range, largest first — for sizing up an unfamiliar subsystem |
| `tumap.py <rva>:<name> …` | maps a `__FILE__` string's RVA to every function that references it, i.e. **translation-unit recovery**. This is how the jp2k component (13 TUs) and the `t3::color` ICC engine were located without a PDB |
| `extract_range.py <lo>-<hi> …` | bulk-extract pseudocode for whole regions so grep-scale pattern scans work |
| `whichfn.sh <file> <line…>` | line number in an extracted file -> enclosing function |

Usage notes:

- `pc.py build` writes `pc_index.json` next to the script; run it before any other subcommand.
- Addresses may be given bare (`18091503d`), `0x`-prefixed, or as `FUN_…`/`sub_…`.
- `.rdata` reads against the raw DLL need **file offset = RVA - 0x1400**; `.data` needs
  **RVA - 0x2000**. Section containment must use virtual size only — `.text`'s file-aligned raw
  size otherwise swallows `.rdata` RVAs and constant tables decode as plausible x86.
- Pseudocode is reconstructed. Ghidra drops out-parameters on some checked-arithmetic helpers
  (see round 11 §4 for a case that reads as a heap overflow in pseudocode and is correct in
  machine code), so confirm any candidate against `assembly/mspdf_full_intel.asm`.
