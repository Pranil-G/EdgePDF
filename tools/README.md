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
| `scanmemcpy.py` | memcpy sites whose length base is disjoint from the destination base |
| `unguarded.py` / `unguarded2.py` | indexed writes whose index never appears in any comparison (3 operand forms) |
| `narrowctr.py` | narrowed 8/16-bit loop increments compared against wider bounds |
| `glue.py ls <regex>` / `asm <rva>` / `near <rva>` | navigator for the **symbol-assisted Edge glue corpus** (`edge_glue_154.0.4258.53`): 4,352 PDB-named `msedge.dll` functions. Crudely demangles MSVC names to their scope chain, which is enough to map the PDF subsystem's process boundaries |
| `vt.py <vtable-VA> [slots]` / `--find <regex>` | RTTI **vtable resolver**: dumps a vtable from the binary and names each slot's target, for breaking `(**(code **)(*obj + 0xN))()` walls. Caveat: identical COMDAT folding makes trivial 4-5 byte slots (plain getters, deleting-destructor forwarders) shared across unrelated classes, so they identify nothing — useful for substantial slots, misleading for stubs |
| `gen_finding006.py <outdir>` | **PoC generator** for FINDING-006. Builds conforming JPEG 2000 codestreams, JP2 containers and `/JPXDecode` PDF wrappers from scratch, including a tag-tree packet-header encoder, so arbitrary code-block/tile-part configurations can be emitted. Not a corpus tool — it needs nothing but Python |

Usage notes:

- `pc.py build` writes `pc_index.json` next to the script; run it before any other subcommand.
- Addresses may be given bare (`18091503d`), `0x`-prefixed, or as `FUN_…`/`sub_…`.
- `.rdata` reads against the raw DLL need **file offset = RVA - 0x1400**; `.data` needs
  **RVA - 0x2000**. Section containment must use virtual size only — `.text`'s file-aligned raw
  size otherwise swallows `.rdata` RVAs and constant tables decode as plausible x86.
- **`unguarded2.py` has three known false-positive modes.** It flags an indexed write whose
  *index variable* never appears in a comparison. Legitimate code defeats that when (a) the
  index *expression* is checked and only then assigned to the variable, (b) the index is
  bounded by loop structure via a different variable, or (c) Ghidra variable reuse makes a
  `local_*`/`auStack_*` name look like a stack buffer when it is a pointer. All three were
  hit in round 17; every hit in the graphics engine was correct code.
- `unguarded2.py`, `scanmemcpy.py` and `tumap.py` take **address ranges** (`lo-hi`, full VA or
  RVA) to scope a scan to one component; corpus-wide runs are too noisy to triage.
- **Enumerate every `__FILE__` path before concluding a component is absent.**
  `strings -a -n 20 <dll> | grep dcpdf` is 29 lines for `mspdf.dll`. Grepping for a
  component's *identifiers* under one guessed subtree produced a wrong "there is no JS
  engine here" conclusion twice (rounds 12 and 13); the JS bridge is under
  `pdfcontrol\datamodel\dcpdf\js\`, not `t5\`.
- **Ghidra's `local_NN` names are not frame offsets.** They are allocation-order labels, and
  they routinely disagree with the real layout (in `FUN_1805C04BD`, `local_58` sits at
  `[rbp+0x70]` and `local_70` at `[rbp+0x58]`). Before claiming a computed value reaches a
  call, match the stores to the call's actual argument registers in the disassembly, and
  check whether the slot is ever read again. This produced one retracted finding.
- Pseudocode is reconstructed. Ghidra drops out-parameters on some checked-arithmetic helpers
  (see round 11 §4 for a case that reads as a heap overflow in pseudocode and is correct in
  machine code), so confirm any candidate against `assembly/mspdf_full_intel.asm`.
