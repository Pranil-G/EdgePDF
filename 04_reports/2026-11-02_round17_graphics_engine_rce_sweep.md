# Round 17 — graphics engine, RCE sweep

Systematic hunt for memory corruption in `mspdf.dll` 154.0.4258.33's rendering engine.
**Result: a negative.** Every write path examined is bounded, several of them twice. The engine's
defensive structure is documented below so this ground is not re-walked, along with the one item
from round 16 that remains a latent hazard and the two places still unverified.

## 1. Locating the engine

Round 16 identified the namespace; this round pinned the **code** by resolving the painter
family's vtables with `tools/vt.py` (the `__shared_ptr_emplace` control blocks found via RTTI
are not the class vtables — the class vtables had to be located separately):

| class | vtable | slot 4 (main entry) |
|---|---|---|
| `FastPixelBufferRasterPainter` | `0x180B11D18` | `FUN_1802C1F40` (409 B) |
| `ConvertedRasterPainter` | `0x180AFA708` | `FUN_1802C2D60` (123 B) |
| `GrayToAlphaRasterPainter` | `0x180AFA778` | `FUN_1802C53A0` (165 B) |
| `TransparencyBackdropRasterPainter` | `0x180AFACB8` | `FUN_1802CDC10` (394 B) |
| `OperationRasterPainter` | `0x180AFAD58` | `FUN_1802CEAD0` (157 B) |
| `SuperSamplingBezierRasterPainter` | `0x180AF80A8` | `FUN_180172BE0` (328 B) |

So the painter family lives at **`0x1802C0000`–`0x1802E0000`** and the supersampling bezier
rasterizer at **`0x180172000`–`0x18017B000`**. Round 16's guess of `0x180160000`–`0x1801A0000`
was too wide and caught the t5 **stream** class at `0x180161xxx` instead (see §6).

## 2. Scans

`tools/unguarded2.py` and `tools/scanmemcpy.py` both gained address scoping this round. Against
the painter family:

```
unguarded indexed writes (3 operand forms) : 0 functions
memcpy with length-base disjoint from dest : 0 of 7  (FUN_1809E1E60)
memset with length-base disjoint from dest : 0 of 5  (FUN_1809E2510)
```

Against the wider imaging region, six unguarded-write candidates surfaced; all six resolve clean
(§3, §4), and two of them are instructive **false-positive modes** of the scanner — recorded in
`tools/README.md`.

## 3. The write paths, and why each is bounded

### 3.1 Coverage span writer — `FUN_180172BE0`

The heart of the rasterizer. Writes a coverage byte per pixel:

```c
if (this->+0x118 <= x) { this->+0x2d4 = 0x7fffffff; return x_end; }   /* right clip: done */
if (x < this->+0x110) { this->+0x2d4 = this->+0x110; }                /* left clip: skip */
…
puVar3 = (this->+0x2d0 - this->+0x88) + this->+0x40;   /* buffer + (x - x_origin) */
do {
    if (x_end <= this->+0x2d4) break;
    *puVar3 = (char)uVar2;
    if (++this->+0x2d4 == this->+0x118) { this->+0x3f0 = 0; break; }  /* right clip */
    puVar3 = puVar3 + 1;
} while (…);
```

Entry guarantees `this->+0x110 <= x < this->+0x118`, the counter increments by one so the
equality test against `+0x118` is reached exactly, and `x_end` short-circuits on the first
iteration when it is below `x`. The write is therefore confined to the clip range.

### 3.2 Bezier subdivision stack — `FUN_18016D34E`

A 760-byte stack array holding 16-byte entries (a `double` plus a flag), i.e. 47 usable slots:

```c
undefined1 auStack_a68 [760];
if (0x2f < local_148) { … t5::corrupt_data … }          /* depth > 47 -> reject */
for (uVar30 = 0; uVar30 < local_148; uVar30++) {
    if (0x2f < ~uVar30 + local_148) { invalidInstructionException(); }   /* re-check at use */
    lVar24 = (~uVar30 + local_148) * 0x10;
    *(double *)(auStack_a68 + lVar24 - 8) = …;
    auStack_a68[lVar24] = 1;
}
```

Bounded twice: a real rejection on the attacker-controlled depth, plus an unreachable `ud2`
assert immediately before the write. 47 × 16 = 752, flag at 752, inside 760.

### 3.3 Supersampling crossing lists — `FUN_180178A78` / `FUN_180178B32` / `FUN_180179680`

This was the most promising shape found. `FUN_180178A78` initialises **16** sub-scanline records
of `0x1028` bytes (16× supersampling), and `FUN_180178B32` walks each record's crossing list
with an **unbounded** sentinel scan:

```c
piVar9 = *(int **)(lVar8 + 0x1018);      /* cursor */
iVar6 = *piVar9;
while (iVar6 <= iVar1) {                 /* no upper bound on piVar9 */
    piVar9 = piVar9 + 1;
    *(int **)(lVar8 + 0x1018) = piVar9;
    iVar6 = *piVar9;
}
```

With 16 records packed contiguously, running off record *k* lands in record *k+1*. Safety rests
entirely on a sentinel always being present. **It is, by two independent mechanisms:**

- the fillers `FUN_180179680` / `FUN_1801799A2` clamp every stored crossing with
  `if (iVar10 < 0x7ffffffe)`, reserving `0x7FFFFFFF` as the terminator, and saturate every
  `double`→`int` conversion (`dVar15 <= 2147483647.0`, `-2147483648.0 <= dVar15`);
- the crossing list is **not** a fixed inline array. `param_2` is a `std::vector<int>`
  (`{data, size, capacity}` at `*param_2`, `param_2[1]`, `param_2[2]`), and *every* push checks
  capacity:

```c
piVar7 = (int *)(param_2[1] * 4 + *param_2);
if (param_2[1] == param_2[2]) FUN_180179CA2(param_2, …, piVar7, 1, …);   /* grow + insert */
else { *piVar7 = …; param_2[1] = param_2[1] + 1; }
```

The painter's array destructor `FUN_18017A320` confirms the structure definitively and gives
the full template signature:

```
SuperSamplingBezierRasterPainter<
    OverscanBezierSamplerDef<ByteSignalTraits<TetraphiliaAppTraits>, 32, 32>,
    16,                                                    /* 16 sub-samples */
    FilteringBezierSamplerEdgeAdder<BaseOverscanBezierSamplerDef<…,32,32,1>>,
    TextToleranceTraits<TetraphiliaAppTraits>>
```

and its teardown per record is

```c
if ((capacity != 0) && (data != inline_address))
    FUN_180962370(data, capacity << 2);     /* operator delete(data, capacity * 4) */
```

The `data != inline_address` test is the standard **small-vector** teardown: each record carries
inline storage and spills to the heap once the inline capacity is exceeded. `capacity << 2`
confirms 4-byte (`int`) elements. So `+0x1018` is a cursor into whichever storage is live, and a
path with many edges on one sub-scanline grows the vector rather than overflowing a record.
Each painter instance is `0x10680` bytes (16 × `0x1028` records plus a `0x400` header), which the
constructor `FUN_180172400` confirms with its `while (lVar10 != 0x10280)` init loop.

### 3.4 Painter entry — `FUN_1802C1F40`

Not a pixel loop: it registers up to three sub-painters into a vector, three times, with the
same capacity-checked `push_back` as §3.3. Correct.

### 3.5 FreeType glyph names — `FUN_18018B1D2`

In FINDING-005's neighborhood and the same general class, but correct:

```c
undefined8 local_148 [32];                       /* exactly 0x100 bytes */
puVar5 = FUN_18016C35D(pool, num_glyphs);        /* alloc num_glyphs * 8, zeroed */
FUN_1809E2510(local_148, 0, 0x100);
FUN_180ABBCA6(face, (int)uVar9 - 1, local_148, 0x100);   /* FT_Get_Glyph_Name, max 0x100 */
sVar6 = strlen((char *)local_148);
pcVar7 = FUN_18016C0C1(pool, (int)sVar6 + 1);
FUN_1809E1A20(pcVar7, local_148);                /* strcpy into strlen+1 */
puVar5[uVar8] = pcVar7;
```

Buffer size matches the limit passed to FreeType exactly, the memset makes `strlen` safe even
if FreeType writes nothing, and the array index is bounded by the loop shape — it writes
`puVar5[k]` while `k + 1 < num_glyphs`, so the last write is at `num_glyphs - 1`.

## 4. Scanner false-positive modes (added to `tools/README.md`)

`unguarded2.py` matches an indexed write whose **index variable** never appears in a comparison.
Two shapes defeat that heuristic legitimately:

1. **The index expression is checked, then assigned.** §3.2 tests `0x2f < ~uVar30 + local_148`
   and only then computes `lVar24 = (~uVar30 + local_148) * 0x10`. The variable `lVar24` is
   never compared, but the value is.
2. **The index is bounded by loop structure.** §3.5 writes `puVar5[uVar8]` with the loop
   condition on a *different* variable (`uVar9 < num_glyphs`) that trails the index by one.

Both were flagged and both are correct code. Combined with the round-11 note (Ghidra variable
reuse making `local_*` names unreliable evidence of a stack buffer), that is three documented
false-positive modes for this scanner.

## 5. What remains unverified

1. **Whether the §3.1 coverage buffer at `+0x40` is sized to the full clip extent.** The write
   is confined to `[+0x110, +0x118)` and indexed `buffer + (x - +0x88)`, so safety needs
   `+0x88 <= +0x110` and `+0x118 - +0x88` to fit the allocation at `+0x40`. **Still open.** I
   located the painter's constructor (`FUN_180172400`) and its array destructor
   (`FUN_18017A320`) via the vtable xrefs at `0x180172436` and `0x18017A359`, but neither sets
   those three header fields — they come from a "set destination surface" path I did not find.
   Typed greps for `*(int *)(X + 0x118) = ` and the 8-byte `+0x110`/`+0x118` pair kept landing on
   unrelated objects with coincidental offsets (a store id counter at `FUN_180291AB4`, the
   clip/graphics-state object at `FUN_180174930`, whose `+0x158`/`+0x15a` fields place it far
   below the painter's `0x10680`).

   The likely invariant, by analogy with §6, is the same tile∩clip intersection that bounds the
   raster allocation: the buffer covers the tile and the clip is intersected with it, giving
   `+0x88 <= +0x110 < +0x118 <= +0x88 + buffer_width`. That is plausible and consistent with
   everything else in this engine, but **it is unproven**, and if it does not hold this is a
   controlled heap write of a coverage byte at an attacker-chosen offset. Finding the
   "set destination surface" caller is the way to close it.
2. **The three surface builders** `FUN_180118EA6` / `FUN_1801189C6` / `FUN_180119484`, dispatched
   on `ctx->+0x1c`. They build a self-referential embedded object graph (`param_1 + 0x1c` set to
   `param_1`; `+0x1e` to `param_1 + 0x2e`; two fields pointing at the embedded sub-object), with
   geometry at `param_1[0x2e..0x38]`. Deeply templated and expensive to verify; nothing
   obviously wrong, but not cleared either.

## 6. Carried forward from round 16

`FUN_18011EACA`, the per-tile BGRA raster allocation, computes `width * height * 4` with a bare
32-bit `imul`/`shl` (verified at `0x18011EB1D`) while both dimensions come from the module's
trapping checked-subtraction helper in the same function. Unreachable today because the single
caller passes a tile∩clip intersection, so the dimensions are tile-bounded — **safe by geometry
rather than by validation.** Still the best hardening item found in the engine.

Also noted in passing and **not** graphics: `FUN_180161F1E` is the t5 stream buffer-grow (43
callers). It allocates `param_3` then copies `+0x90 - +0x88` into it, so it needs
`live_length <= param_3`. It does carry a checked add (`CARRY8(this->+0x78, param_3)` → throw).
Verifying the invariant across 43 call sites is a separate job with low expected yield.

## 7. Assessment

The rendering engine is defensively written in a consistent style: trapping checked-arithmetic
helpers for subtraction, capacity-checked `push_back` everywhere a list grows, saturated
`double`→`int` conversions, clip-bounded span writes, reserved sentinels enforced by clamping,
and re-validation at the point of use (§3.2 checks the same bound twice). The one real deviation
found — the unchecked raster product in §6 — is held safe by an invariant maintained two frames
up rather than by a local check.

I did not find an RCE candidate here. §5.1 is the single remaining question worth answering
before calling the engine clear.
