# FINDING-006 — later-tile-part `COC` mutates the code-block size after the EBCOT state buffers are sized (heap overflow, mspdf.dll)

| | |
|---|---|
| Module | `mspdf.dll` 154.0.4258.33 (Edge/WebView2 154.0.4258.53; SHA-256 `F21CC09C…1688`) |
| Component | **First-party Microsoft code** — `…\dcpdf\t5\firstparty\jp2k\source\common\src\JP2KImageMap.cpp` |
| Reached by | a `/Filter /JPXDecode` image XObject in **any** PDF — zero-click, no user interaction, default-on |
| Class | Heap buffer overflow (out-of-bounds write), attacker-controlled allocation size and overflow length |
| **Status** | **Reachable on the path Edge actually takes.** It passes the one guard that made FINDING-002 non-exploitable. |
| Severity | **Critical** (renderer RCE candidate) |

## Summary

FINDING-002 established that the per-component `COC` block in `sub_18088C65E` is applied from a
**later tile-part header with no `TPsot` guard**, overwriting a tile-component's 0xE0-byte coding
style. It concluded "not exploitable", because the consumer Edge selects — `sub_18088F0E2` — checks
that the decomposition level `L` (`+0x38`) still matches the value the geometry was built from.

**That check only covers `+0x38`.** The same unguarded 0xE0-byte copy also replaces the
code-block size exponents **`xcb` (`+0x30`)** and **`ycb` (`+0x34`)**, and *nothing* compares those
against the values the buffers were sized from.

The EBCOT bit-plane state buffers are sized from `1 << xcb` / `1 << ycb` **once**, for tile-part 0
only. The decode path re-reads the (now mutated) coding style and `memset`s those same buffers with
a size derived from the new `ycb`. Choosing a large `xcb` with a small `ycb` in tile-part 0 and then
a larger `ycb` in tile-part 1 makes the `memset` several KB larger than the allocation.

## The four verified links

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

`xcb` (+0x30), `ycb` (+0x34) and `L` (+0x38) are all inside the copied 0xE0 bytes and none of them is
restored. The two sibling blocks in the same function reject later tile-parts with
`if (tile->+0x4C != 0) return …`; this one has no such test — the FINDING-002 defect.

### 2. The guard covers only `L`

`sub_18088F0E2`, immediately after applying the header:

```c
FUN_18088C65E();
plVar3  = (longlong *)*param_1;
iVar26  = *(int *)(*(longlong *)(*(longlong *)(*plVar3 + 0x78) + 0x38) + 0x38);   /* ->cs->L */
if (iVar26 != *(int *)(*(longlong *)(*plVar3 + 0x58) + 0x2c)) return 0x1d;
for (each further component)
  if (*(int *)(*(longlong *)(*(longlong *)(plVar3[lVar24] + 0x78) + 0x38) + 0x38) != iVar26)
    return 0x1d;
```

Only `+0x38`. Keep `L` constant across both tile-parts and this passes.

### 3. The buffers are sized once, for `TPsot == 0` only

```c
if ((param_3 == -1) && (*(int *)((longlong)param_1 + 0x4c) == 0)) {   /* +0x4c == TPsot */
    …
    FUN_18088E70A(*(undefined8 *)(*param_1 + lVar13 * 8), param_4);   /* per component */
}
```

`FUN_18088E70A` -> `FUN_1808914A3` (state buffers) + `FUN_180890FB4` (geometry) + `FUN_1808915B6`.
For a tile-part with `TPsot != 0` this whole block is skipped, so **nothing is re-sized**.

`FUN_1808914A3` sizes the state from the coding style's nominal code-block dimensions:

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

with the two allocators being exactly

```c
FUN_180886CFF(h, W, H, words) { h[0]=W; h[1]=H; h+2 = alloc(words * (W + 3)    ); }
FUN_180886C8C(h, W, H, words) { h[0]=W; h[1]=H; h+2 = alloc(words * (W + 3) * 4); }
```

`param_1` here is `tilecomp->+0x78` — the *same* object whose `+0x38` the `COC` overwrote in link 1,
and the same object the decoder receives (link 4).

### 4. The decode path re-reads the mutated `ycb` and `memset`s from it

`FUN_1808877AE` (the per-code-block decode driver, 13 call sites):

```c
lVar7   = *(longlong *)(param_8 + 0x38);                    /* the mutated coding style */
uVar22  = 1 << ((byte)*(uint *)(lVar7 + 0x34) & 0x1f);      /* 1 << ycb_now */
…
local_d0 = *(longlong *)(param_8 + 0x28);                   /* holder B from link 3 */
local_f0 = local_d0;
…
iVar17 = (int)local_a8 + 2;                                 /* actual cbWidth + 2 */
lVar14 = (longlong)iVar17;
if (*(char *)(lVar7 + 0xf) == '\0') {
  if ((int)uVar22 < 9)        FUN_180885AA5(*(undefined8 *)(local_f0 + 8), 0, lVar14);
  else if (uVar22 < 0x21)     FUN_180885AA5(*(undefined8 *)(local_d0 + 8), 0, lVar14 << 2);
  else                        FUN_180885AA5(*(undefined8 *)(local_d0 + 8), 0, lVar14 * local_6c * 4);
} else                        FUN_180885AA5(*(undefined8 *)(local_f0 + 8), 0, local_6c * (longlong)iVar17);
```

`local_a8 = param_7[2] - *param_7` is the **actual** code-block width from the tile-part-0 geometry;
`local_6c` is `ceil(actualHeight/32)` (or `ceil(actualHeight/4)`). The variant and the length come
from `ycb_now`; the buffer came from `ycb_0`.

`FUN_18088A218` does re-check the exponents on the way in, but only for **range**, never for
agreement with the allocation:

```c
iVar7 = *(int *)(lVar2 + 0x30);
if (((iVar7 < 0xb) && (iVar5 = *(int *)(lVar2 + 0x34), iVar5 < 0xb)) && (iVar5 + iVar7 < 0xd)) { … }
```

## Proof of concept

Parser constraints on both `COD` and `COC` are `xcb_raw <= 8`, `ycb_raw <= 8`,
`xcb_raw + ycb_raw <= 8` (from `(int)(ycb_raw + xcb + 2) < 0xd` with `xcb = xcb_raw + 2`), and
`L <= 32`. Both configurations below satisfy all of them.

| | tile-part 0 | tile-part 1 |
|---|---|---|
| `xcb_raw`, `ycb_raw` | `8, 0` -> `xcb = 10, ycb = 2` | `0, 2` -> `xcb = 2, ycb = 4` |
| sum check | `8 <= 8` ok | `2 <= 8` ok |
| nominal code-block | 1024 x 4 | 4 x 16 |
| `L` | *L* | **same *L*** (passes link 2) |
| `TPsot` | 0 -> buffers sized | 1 -> **not re-sized** (link 3) |

Make the subband at least 1024 samples wide (e.g. a 2048 x 64 single-tile image, `L = 0`) so the
actual code-block width is the full 1024.

- Allocation (tile-part 0): `iVar8 = 4 < 9`, flag 0 -> `words = 1` ->
  `FUN_180886CFF(B, 1024, 4, 1)` -> **`1 * (1024 + 3) = 1027` bytes**.
- `memset` (tile-part 1): `uVar22 = 1 << 4 = 16`, so `9 <= 16 < 0x21` ->
  `lVar14 << 2 = (1024 + 2) * 4 = `**`4104` bytes**.

**-> 3077 bytes written past a 1027-byte heap allocation**, for *each* of holders A and B, before
`FUN_1808FE180` then decodes attacker-controlled EBCOT state into the same buffer.

Pick `ycb = 6` in tile-part 1 instead and the generic branch runs
`(1024 + 2) * ceil(4/32) * 4`, i.e. the same 4104; with a taller code-block in tile-part 0 the
generic branch scales to `(W+2) * ceil(H/32) * 4`, up to ~131 KB.

### Why this is a strong primitive

- **The victim chunk size is attacker-chosen**: `1 << xcb_0 + 3`, anywhere from 7 to 1027 bytes in
  the byte variant.
- **The overflow length is independently attacker-chosen**: via the actual code-block width and
  `ycb_1`, from a few bytes to ~131 KB.
- Both are selected by plain marker fields, so the heap can be groomed and the overflow extent
  tuned to the target chunk — and the first write is a `memset` of zeros, which is a clean way to
  smash an adjacent header before the decoder writes controlled data.

## Why this is not a duplicate of FINDING-002

FINDING-002 mutates `L` and is caught by `sub_18088F0E2`'s equality check, which is exactly why it
was filed as "real defect, not exploitable as shipped". This mutates `xcb`/`ycb`, which that check
does not read, so it reaches the decoder on the path Edge always takes (FINDING-002 measured
`sub_18088F3EB0` returning the random-access selector on 100% of 1,569 tile decodes). Same root
cause — the missing `TPsot` guard on the `COC` block — different field, and the field chosen is the
one no downstream consistency test covers.

## Suggested fix

Any one of these closes it; the first is the root-cause fix FINDING-002 already recommended:

1. Give the per-component `COC` block at `0x18088CB18` the `if (tile->+0x4C != 0) return …` guard its
   two sibling blocks already have, so a later tile-part cannot change the coding style at all.
2. Extend `sub_18088F0E2`'s consistency check from `+0x38` alone to the full tuple
   `(+0x30, +0x34, +0x38)`, i.e. compare `xcb` and `ycb` against the values the geometry and state
   buffers were built from, exactly as it already does for `L`.
3. Have `FUN_1808877AE` take the variant and the `memset` length from the dimensions **recorded in
   the holder** rather than from the live coding style — `FUN_180886CFF`/`FUN_180886C8C` already
   store `W` at `h[0]` and `H` at `h[1]` for precisely this purpose, and neither is currently read
   back.

(3) is the cheapest and is strictly local: the allocation's own `W`/`H` are already sitting unused
in the holder.

## Verification notes

Every link was read in the pseudocode and the field offsets cross-checked against the marker
parser, which writes `xcb` at `+0x30`, `ycb` at `+0x34`, `L` at `+0x38`, layers at `+0x44` on a
0xE0-byte coding-style record (`FUN_18091503D`, `case 0xff53`). `+0x4c` as `TPsot` is from
FINDING-002 and is confirmed by the write in `sub_18088C65E`
(`*(uint *)((longlong)local_68 + 0x4c) = (uint)bVar2;`).

Not yet confirmed dynamically — the prior rounds' Frida harness needs a Windows host, which this
session does not have. The static chain is complete and each step is a direct read, but a live
`--pdf-renderer` crash with a PoC built to the table above is the remaining step before submission.
