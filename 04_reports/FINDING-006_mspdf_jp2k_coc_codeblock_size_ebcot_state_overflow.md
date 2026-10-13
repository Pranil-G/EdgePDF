# FINDING-006 — later tile-part `COC` mutates the code-block size after the EBCOT state buffers are sized (heap overflow, mspdf.dll)

| | |
|---|---|
| Module | `mspdf.dll` 154.0.4258.33 (Edge/WebView2 154.0.4258.53; SHA-256 `F21CC09C…1688`) |
| Component | **First-party Microsoft code** — `…\dcpdf\t5\firstparty\jp2k\source\common\src\JP2KImageMap.cpp` |
| Reached by | a `/Filter /JPXDecode` image XObject in **any** PDF — zero-click, no user interaction, default-on |
| Class | Heap buffer overflow (OOB write) **and** heap OOB read, both of attacker-chosen length, into/out of attacker-sized pool chunks |
| Status | **Confirmed exploitable on Windows in Edge 154. Fixed in Edge 155.** Reachable on both tile-decode paths; it passes the one guard that made FINDING-002 non-exploitable. |
| Fix | Edge 155 snapshots `+0x0C`, `+0x0F`, `+0x30` (`xcb`) and `+0x34` (`ycb`) before the `COC` copy and rejects any change when `TPsot != 0` (comparisons near RVAs `0x88D517`/`0x88D523`, error path `0x88D7DB`) — suggested fix #2 below. What the allowlist leaves open: [FINDING-006 follow-up](FINDING-006-followup_edge155_fix_analysis_and_residual_surface.md). |
| Severity | **Critical** (OOB write). Note that the Edge 154 crash lands on a `ud1` at `mspdf.dll+0x900AFF`, which is a compiler-unreachable trap *downstream* of both writes, not a guard in front of them — it clips the follow-on controlled-write escalation. See the follow-up §1. |
| PoC | [`05_poc/FINDING-006/`](../05_poc/FINDING-006/) — `poc_min.pdf` is 786 bytes and **decodes cleanly under both FFmpeg and OpenJPEG** |

## Summary

FINDING-002 established that the per-component `COC` block in `sub_18088C65E` is applied from a
**later tile-part header with no `TPsot` guard**, overwriting a tile-component's 0xE0-byte coding
style. It concluded "not exploitable", because the consumer checks that the decomposition level
`L` (`+0x38`) still matches the value the geometry was built from.

**That check only covers `+0x38`.** The same unguarded 0xE0-byte copy also replaces the code-block
size exponents **`xcb` (`+0x30`)** and **`ycb` (`+0x34`)**, and nothing compares those against the
values the buffers were sized from.

Five heap buffers per code-block are sized from `1 << xcb` / `1 << ycb`, **once, for `TPsot == 0`
only**. The decode path then re-reads the mutated exponents and writes into those same buffers with
lengths derived from the new ones. A small `ycb` in tile-part 0 and a larger one in tile-part 1
selects a 4-byte-per-sample write variant over a 1-byte-per-sample allocation — a 4x length
mismatch — while `xcb` scales both the allocation and the overflow.

## The verified links

### 1. The mutation — `sub_18088C65E`, per-component `COC`, no `TPsot` guard

```c
if (*(char *)(lVar8 + 4) == '\x01') {                 /* tile-part header carries COC entries */
  iVar6 = *(int *)(lVar8 + 0x30);                     /* entry count */
  do {
    lVar13 = *(longlong *)(lVar8 + 0x28);             /* COC array, stride 0xE0 */
    iVar3  = *(int *)(lVar13 + 8 + lVar14);           /* Ccoc, bounds-checked below */
    if ((-1 < (longlong)iVar3) && (iVar3 < (int)plVar4[1])) {
      lVar10 = *(longlong *)(*(longlong *)(*plVar4 + (longlong)iVar3 * 8) + 0x78);
      ...
      FUN_1807BBAAA(lVar11, lVar13 + lVar14);         /* memcpy 0xE0 bytes over the coding style */
      *(undefined4 *)(*(longlong *)(lVar10 + 0x38) + 0x44) = …;   /* only +0x44 restored */
      *(undefined4 *)(*(longlong *)(lVar10 + 0x38) + 0x48) = …;   /* only +0x48 restored */
      *(undefined4 *)(*(longlong *)(lVar10 + 0x38) + 0x40) = …;   /* only +0x40 restored */
```

Verified in machine code at `0x18088CB18`–`0x18088CBCF`:

```
18088cb18: cmp byte ptr [r15 + 0x4], 0x1        ; header carries COC entries?
18088cb84: mov rdx, qword ptr [r15 + 0x28]      ; COC array
18088cb88: movsxd rcx, dword ptr [rdx+rsi+0x8]  ; Ccoc
18088cb90: js   next                            ; sign check only
18088cb97: jge  next                            ; range check only
18088cba1: mov rbx, qword ptr [rax + 0x78]      ; tilecomp->+0x78
18088cb35: mov rax, qword ptr [rbx + 0x38]      ; the coding style
18088cb3f: call 0x1807bbaaa                     ; 0xE0-byte copy -> overwrites xcb/ycb/L
18088cb4f/cb5d/cb6b: restore ONLY +0x44, +0x48, +0x40
18088cb78: add rsi, 0xe0                        ; next entry
```

The block contains **no reference to `+0x4c` (`TPsot`)**. Every `+0x4c` reference in the whole
function is accounted for: `18088c842` writes it, `18088c902` and `18088c9b8` are the **two sibling
blocks' guards** (`if (tile->+0x4C != 0) return …`), and `18088cbfa` reads it *after* the `COC`
block. The asymmetry is the FINDING-002 defect.

### 2. The guard covers only `L` — on **both** tile-decode drivers

`FUN_18088F0E2` (the random-access selector FINDING-002 measured at 100% of 1,569 tile decodes):

```c
FUN_18088C65E();
plVar3  = (longlong *)*param_1;
iVar26  = *(int *)(*(longlong *)(*(longlong *)(*plVar3 + 0x78) + 0x38) + 0x38);   /* ->cs->L */
if (iVar26 != *(int *)(*(longlong *)(*plVar3 + 0x58) + 0x2c)) return 0x1d;
for (each further component)
  if (*(int *)(*(longlong *)(*(longlong *)(plVar3[lVar24] + 0x78) + 0x38) + 0x38) != iVar26)
    return 0x1d;
```

`FUN_18088CE7A`, the other driver, has the identical shape — an `L`-only equality loop across
components, then the same `TPsot` gate:

```c
do {   /* compare every component's +0x38 against component 0's */
  if (*(int *)(*(longlong *)(*(longlong *)(*(longlong *)*param_1 + 0x78) + 0x38) + 0x38) !=
      *(int *)(*(longlong *)(*(longlong *)(((longlong *)*param_1)[lVar18] + 0x78) + 0x38) + 0x38))
    return 0x1d;
} while ((int)uVar23 != ++lVar18);
if (*(int *)((longlong)param_1 + 0x4c) == 0) {               /* TPsot == 0 */
  for (each component) FUN_18088E70A(…);                     /* allocate everything */
}
else if (0 < (int)uVar23 && param_3 != -1) {
  for (each component) FUN_18088E7FC(…);                     /* later tile-part: see link 5 */
}
```

So the behaviour does not depend on which selector Edge takes — the earlier caveat is removed.
Only `+0x38` is compared. Keep `L` identical across both tile-parts and both drivers pass.

### 3. Five buffers per code-block, sized once, for `TPsot == 0` only

`FUN_18088E70A` is the single caller of all four setup routines:

```c
FUN_1808914A3();              /* 2 per-tile-component state holders  */
FUN_180890D5A(param_1, p2);   /* segment / MQ bookkeeping             */
FUN_180890FB4(param_1, p2);   /* the band/precinct/code-block GEOMETRY */
FUN_1808915B6(param_1);       /* per-code-block contexts + 3 buffers each */
```

and it is reached only under the `TPsot == 0` gate shown in link 2 (and the identical gate in
`FUN_18088F0E2`). `FUN_180890FB4`, `FUN_1808914A3` and `FUN_1808915B6` have **exactly one caller
each** — this one — so for a tile-part with `TPsot != 0` nothing is re-sized and no geometry is
rebuilt.

`FUN_1808914A3` sizes the two tile-component holders from the coding style's nominal dimensions:

```c
lVar2  = *(longlong *)(param_1 + 0x38);                  /* the COC-mutable coding style */
iVar8  = 1 << (*(byte *)(lVar2 + 0x34) & 0x1f);          /* nominal cbHeight = 1 << ycb */
iVar10 = 1 << (*(byte *)(lVar2 + 0x30) & 0x1f);          /* nominal cbWidth  = 1 << xcb */
bVar1  = *(byte *)(lVar2 + 0xf);
*(undefined8 *)(param_1 + 0x20) = FUN_180885C7F(0x10, pool);   /* holder A */
*(longlong  *)(param_1 + 0x28) = FUN_180885C7F(0x10, pool);   /* holder B */
if ((iVar8 < 9 | bVar1) == 1) {
    iVar9 = 1; if (*(char *)(lVar2 + 0xf) != '\0') iVar9 = (iVar8 + 3) >> 2;
    FUN_180886CFF(A, iVar10, iVar8, iVar9, pool);        /* alloc words*(W+3)   BYTES  */
    FUN_180886CFF(B, iVar10, iVar8, iVar9, pool);
} else {
    FUN_180886C8C(A, iVar10, iVar8, (iVar8 + 0x1f) >> 5, pool);  /* alloc words*(W+3)*4 */
    FUN_180886C8C(B, iVar10, iVar8, (iVar8 + 0x1f) >> 5, pool);
}
```

`FUN_1808915B6` does the same thing **three more times per code-block**, from the same coding style
(`*(*(param_1 + 0x78) + 0x38)`), into the 0x70-stride decoder-context array:

```c
lVar5  = *(longlong *)(local_a0 + 0x38);          /* same COC-mutable coding style */
iVar9  = 1 << (*(byte *)(lVar5 + 0x30) & 0x1f);   /* 1 << xcb */
iVar13 = 1 << (*(byte *)(lVar5 + 0x34) & 0x1f);   /* 1 << ycb */
plVar3[10] = FUN_180885C7F(0x10, uVar6);          /* cblk ctx +0x50 */
plVar3[0xb] = FUN_180885C7F(0x10, uVar6);         /* cblk ctx +0x58 */
plVar3[0xc] = FUN_180885C7F(0x10, uVar6);         /* cblk ctx +0x60 */
if ((iVar13 < 9 | bVar1) == 1) { FUN_180886CFF(plVar3[10],  iVar9, iVar13, iVar10); … x3 }
else                          { FUN_180886C8C(plVar3[10],  iVar9, iVar13, iVar10); … x3 }
```

Both allocators, disassembly-verified (`mov [rcx],edx; mov [rcx+4],r8d; add edx,3; imul` / `+ shl rcx,2`):

```c
FUN_180886CFF(h, W, H, words) { h[0]=W; h[1]=H; h+2 = alloc(words * (W + 3)    ); }
FUN_180886C8C(h, W, H, words) { h[0]=W; h[1]=H; h+2 = alloc(words * (W + 3) * 4); }
```

### 4. The decode path re-reads the mutated `ycb` and writes from it

`FUN_1808877AE`, the per-code-block decode driver (`FUN_18088A218` is its only caller, looping over
every code-block in every precinct):

```c
lVar7   = *(longlong *)(param_8 + 0x38);                    /* the mutated coding style */
uVar22  = 1 << ((byte)*(uint *)(lVar7 + 0x34) & 0x1f);      /* 1 << ycb_now */
…
uVar9    = param_7[3] - param_7[1];                         /* ACTUAL cblk height, stale geometry */
local_e8 = *(undefined8 *)(param_8 + 0x20);  local_f8 = local_e8;   /* holder A */
local_d0 = *(longlong  *)(param_8 + 0x28);  local_f0 = local_d0;   /* holder B */
local_e0 = param_1[10];  local_148 = param_1[0xb];  local_140 = param_1[0xc];
if ((8 < (int)uVar22 | *(byte *)(lVar7 + 0xf)) == 1) { … local_6c = (uVar9+0x1f) >> 5; … }
else                                                 { local_6c = 1; … }
local_a8 = (ulonglong)(uint)(param_7[2] - *param_7);        /* ACTUAL cblk width, stale geometry */
…
iVar17 = (int)local_a8 + 2;
if (*(char *)(lVar7 + 0xf) == '\0') {
  lVar14 = (longlong)iVar17;
  if ((int)uVar22 < 9) {
    FUN_180885AA5(*(undefined8 *)(local_f0 + 8), 0, lVar14);                 /* memset B */
    FUN_1808F9554(local_100, local_f8, 1);                                   /* copy -> A */
    FUN_1808F9580(local_100, local_f8, local_158, local_150, local_f0, …);
  } else if (uVar22 < 0x21) {
    FUN_180885AA5(*(undefined8 *)(local_d0 + 8), 0, lVar14 << 2);            /* memset B */
    FUN_1808F9500(local_e0, local_e8);                                       /* copy -> A */
    FUN_1808FE180(local_e0, local_e8, local_148, local_140, local_d0, …);
  } else {
    FUN_180885AA5(*(undefined8 *)(local_d0 + 8), 0, lVar14 * local_6c * 4);
    FUN_1808F9527(local_e0, local_e8, local_6c);
    FUN_180902B8C(local_6c, local_e0, local_e8, local_148, local_140, local_d0, …);
  }
} else { … }
```

Disassembly confirms the reads and the three lengths: `18088782c: mov ecx,[r14+0x34]`;
`180888205: cmp r12d,0x8 / jg`; `18088821c: call memset` with `r8=(W+2)`; `18088831d: cmp r12d,0x20 /
ja`; `180888327: shl r8,0x2`; `180888c28/c2f/c33: movsxd rax,[rbp+0x27c]; imul r8,rax; shl r8,0x2`.

The three copy helpers are thin wrappers over the module's dispatching `memcpy`
(`FUN_180885A1D(dst, src, n)`, which picks a `memmove` vtable slot when the ranges overlap):

```c
FUN_1808F9500(src, h)    { memcpy(h->data, src->data, (h[0] + 2) * 4);     }
FUN_1808F9527(src, h, k) { memcpy(h->data, src->data, k * (h[0] + 2) * 4); }
FUN_1808F9554(src, h, k) { memcpy(h->data, src->data, k * (h[0] + 2));     }
```

`h[0]` is the **nominal** width the allocation recorded; `local_a8` is the **actual** width from the
stale geometry. Both are read back correctly — what diverges is the *element size*, chosen from
`ycb_now`, while the allocation's element size came from `ycb_0`.

`FUN_18088A218` does re-check the exponents on the way in, but only for **range**, never for
agreement with the allocation:

```c
iVar7 = *(int *)(lVar2 + 0x30);
if (((iVar7 < 0xb) && (iVar5 = *(int *)(lVar2 + 0x34), iVar5 < 0xb)) && (iVar5 + iVar7 < 0xd)) { … }
```

### 5. The later-tile-part path re-uses the grid on purpose

`FUN_18088E7FC` is what a `TPsot != 0` tile-part runs instead of `FUN_18088E70A`. It calls only
`FUN_180890D5A` (segment bookkeeping), then walks the **existing** band (stride 0x78) / precinct
(0x68) / code-block (0x30) / context (0x70) arrays and merely shifts their offsets:

```c
*(int *)(lVar16 + 0x3c) = iVar12;   *(int *)(lVar17 + 0x38) = iVar12;
piVar10[7] = iVar12;                piVar10[4] = iVar4;      *(int *)(lVar11 + 0x1c) = iVar4;
```

It never calls `FUN_180890FB4`, `FUN_1808914A3` or `FUN_1808915B6`. The code-block grid is
deliberately preserved across tile-parts — which is why `L`, the field that *defines* the grid, is
the one field the drivers compare, and it is also why the packet header of a later tile-part is
parsed against the tile-part-0 grid. `xcb`/`ycb` are left free to change underneath it.

## The mismatch, concretely

Tile-part 0 `xcb_raw = 8, ycb_raw = 0` → `xcb = 10, ycb = 2`. `1 << ycb = 4 < 9` and the
`+0xf` style flag is 0, so every one of the five buffers is allocated by the **byte** allocator with
`words = 1`:

> `FUN_180886CFF(h, W = 1024, H = 4, words = 1)` → `alloc(1 * (1024 + 3))` = **1027 bytes**,
> with `h[0] = 1024`, `h[1] = 4`.

Tile-part 1 `COC` with `xcb_raw = 0, ycb_raw = 2` → `xcb = 2, ycb = 4`, same `L`. Now
`uVar22 = 1 << 4 = 16`, so `9 <= 16 < 0x21` and the **4-byte** branch runs:

| buffer | allocated from | alloc | written by | write length |
|---|---|---|---|---|
| tilecomp `+0x20` (holder A) | `ycb_0` → byte, `words=1` | 1027 | `FUN_1808F9500` **memcpy dst** | `(h[0]+2)*4` = **4104** |
| tilecomp `+0x28` (holder B) | same | 1027 | `FUN_180885AA5` **memset** | `(W_actual+2)*4` = **4104** |
| cblk ctx `+0x50` | same | 1027 | `FUN_1808F9500` **memcpy src** | reads **4104** |
| cblk ctx `+0x58` | same | 1027 | `FUN_1808FE180` bit-plane state | mutated geometry |
| cblk ctx `+0x60` | same | 1027 | `FUN_1808FE180` bit-plane state | mutated geometry |

**→ 3077 bytes written past the end of a 1027-byte pool chunk, and 3077 bytes read past the end of
another, in a single `memcpy` — then the EBCOT decoder writes attacker-controlled bit-plane state
into the same buffers with the same mutated geometry.**

Two things make this better than a plain overflow:

- **The `memcpy` length depends only on `xcb_0`, not on the image.** `h[0]` is the nominal width.
  A 4 x 4 image with `xcb_raw = 8` allocates 1027 bytes and still copies 4104 — which is why
  `poc_min` below is a 4 x 4 image that two reference decoders accept without complaint.
- **The source of that `memcpy` is itself a 1027-byte chunk**, so 3077 bytes of adjacent heap are
  read out of one pool chunk and written past the end of another: corruption and cross-chunk
  disclosure from the same call, with the disclosed bytes landing where the next allocation's
  header lives.

### Primitive bounds

`xcb <= 10` caps the nominal width at 1024, so the byte-variant allocation is `W + 3` (7 … 1027
bytes, attacker-chosen) and the 4-byte write is `(W + 2) * 4`, giving an overflow of `3W + 5` —
**3077 bytes maximum per buffer**, independently selectable from the allocation size.

The generic branch (`1 << ycb_1 >= 33`) does **not** scale this further: its multiplier `local_6c`
is `ceil(H_actual / 32)` taken from the *stale* geometry, so a taller code-block enlarges the
allocation by the same factor. The flag-set branch (`+0xf`) writes `ceil(H_actual/4) * (W + 2)`,
which is smaller. 3077 bytes is the ceiling for a single buffer.

What does scale is the **count**: `FUN_1808915B6` allocates three 1027-byte chunks per code-block,
so an image with N code-blocks leaves `3N + 2` identically sized chunks laid out consecutively by
the same pool, and `FUN_18088A218` runs the overflowing sequence once per code-block. `poc_spray`
uses N = 256 → 770 chunks. Same-size chunks from one pool are about the most groomable layout
available, and the first write of each round is a `memset` of zeros, which is a clean way to flatten
an adjacent chunk header before the decoder writes controlled data into the same region.

## Proof of concept

Generator: [`tools/gen_finding006.py`](../tools/gen_finding006.py). Files and a per-file
description: [`05_poc/FINDING-006/`](../05_poc/FINDING-006/).

Both code-block sizes are legal per ISO/IEC 15444-1 (`xcb + ycb <= 12`: 12 and 6) and satisfy every
constraint in the mspdf marker parser `FUN_18091503D` (`xcb_raw + ycb_raw <= 8`, `ycb_raw <= 8`,
`L <= 32`, `Lcoc` in `[9, 43]`). The tile-part-1 `COC` keeps `L` identical, which is all link 2
compares.

| file | image | code-blocks | role |
|---|---|---|---|
| `poc_min.{j2k,jp2,pdf}` | 4 x 4 | 1 | **submission PoC** — holder A's `memcpy` is `(1024+2)*4` regardless of image size |
| `poc.{j2k,jp2,pdf}` | 1024 x 4 | 1 | actual width 1024 too, so holder B's `memset` overflows as well |
| `poc_tp1empty.*` | 1024 x 4 | 1 | tile-part 1 carries a zero-length packet — parses under any grid |
| `poc_spray.*` | 1024 x 1024 | 256 | 770 same-size chunks, 256 rounds of the overflow |
| `control*.*` | — | — | byte-identical bar the 11-byte tile-part-1 `COC` |

### Reference-decoder validation

FFmpeg 6.x's native `jpeg2000` decoder on the raw codestreams, and OpenJPEG via poppler
`pdftoppm` on the PDF wrappers:

| file | FFmpeg | poppler / OpenJPEG |
|---|---|---|
| `control_min` | decoded (27-byte PGM) | rendered |
| `control` | decoded (4110-byte PGM) | rendered |
| `control_spray` | decoded (1048593-byte PGM) | rendered |
| **`poc_min`** | **decoded (27-byte PGM)** | **rendered** |
| `poc` | `nonzerobits -91 invalid or unsupported` | `segment too long (4) with max (3) for codeblock 187` |
| `poc_tp1empty` | `nonzerobits -91` | rendered |
| `poc_spray` | `Invalid data found` | `segment too long (4) with max (0) for codeblock 0` |

The controls decoding to full frames validates the generator end to end — the hand-written packet
headers, the tag-tree coding (including the 256-leaf case), the two-tile-part split with
`TPsot`/`TNsot`, the `Psot` lengths and the 1024 x 4 code-blocks are all accepted by an independent
implementation.

**`poc_min` is accepted by both, and decodes to byte-identical output to its control.** Under
FFmpeg the two PGMs are identical; under OpenJPEG the two rendered PNGs are identical. With a 4 x 4
image the mutated code-block size still gives a 1 x 1 grid, so for a conforming decoder the
tile-part `COC` is semantically a no-op — the file's decoded result is indistinguishable from a
benign one. There is no "malformed input" counterargument available for it: it is a valid JPEG 2000
image that happens to re-state its code-block size in a tile-part header, which is what that marker
is for.

**The rejections on the wider variants are what correct handling looks like**, and OpenJPEG's
message names the mechanism: it re-derived the code-block grid from the tile-part `COC` — 4 x 16
code-blocks over a 1024-wide band is 256 of them, not 1 — and then walked into inconsistent packet
data. FFmpeg does the same and trips its own sanity check. Both re-derive geometry when a tile-part
`COC` changes the code-block size. mspdf does neither: link 5 shows the grid is deliberately kept,
link 4 shows the exponents are re-read anyway, and link 3 shows the buffers are never re-sized.

## Why this is not a duplicate of FINDING-002

FINDING-002 mutates `L` and is caught by the equality check, which is exactly why it was filed as
"real defect, not exploitable as shipped". This mutates `xcb`/`ycb`, which that check does not read,
so it reaches the decoder. It is also not selector-dependent: link 2 shows `FUN_18088CE7A` carries
the identical `L`-only check and `TPsot` gate, so the earlier caveat about which driver Edge takes
no longer applies. Same root cause — the missing `TPsot` guard on the `COC` block — different field,
and the field chosen is the one no downstream consistency test covers.

## Suggested fix

1. **Root cause.** Give the per-component `COC` block at `0x18088CB18` the
   `if (tile->+0x4C != 0) return …` guard its two sibling blocks in the same function already have,
   so a later tile-part cannot change a coding style at all.
2. **Defence in depth.** Extend the consistency check in `FUN_18088F0E2` *and* `FUN_18088CE7A` from
   `+0x38` alone to the full tuple `(+0x30, +0x34, +0x38, +0xf)` — the four fields the state
   allocation is a function of — exactly as both already do for `L`.
3. Have `FUN_1808877AE` derive the write variant from what the allocation actually used rather than
   from the live coding style. Note that recording `W` is *not* sufficient on its own: the holder
   already stores `W` at `h[0]` and `H` at `h[1]`, and `FUN_1808F9500` already reads `h[0]` back —
   it overflows anyway, because the 1-byte/4-byte element choice still comes from the mutated
   `ycb`. The holder would have to record the allocated byte length, or the `(ycb, flag)` pair it
   was sized from.

(1) is the smallest change and closes FINDING-002 at the same time.

## Verification notes

Links 1–4 were read in pseudocode and in machine code, with the field offsets cross-checked against
the marker parser, which writes `xcb` at `+0x30`, `ycb` at `+0x34`, `L` at `+0x38` and layers at
`+0x44` of a 0xE0-byte coding-style record (`FUN_18091503D`, `case 0xff53`). `+0x4c` as `TPsot` is
from FINDING-002 and is confirmed by the write in `sub_18088C65E`
(`*(uint *)((longlong)local_68 + 0x4c) = (uint)bVar2;`). Link 5 and the second driver in link 2 were
read in pseudocode; the single-caller claims in link 3 come from the corpus call-edge index.

**Not confirmed dynamically.** The prior rounds' Frida harness needs a Windows host, which this
session does not have, so no `--pdf-renderer` crash has been observed. What has been established
without one: every link is a direct read of the shipped code rather than an inference; the PoC files
exist and are byte-level verified; and `poc_min` is a conforming codestream that two independent
reference decoders accept, so the file reaching mspdf's decoder is not in question. Running
`poc_min.pdf` under `--pdf-renderer` with PageHeap enabled is the remaining step before submission.
