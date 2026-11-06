# Round 18 — mesh shadings and PDF function objects

Next untouched zero-click surface after the graphics-engine sweep: **shading types 4–7**
(bit-packed vertex/patch streams) and **PDF function objects** (Type 0 sampled, Type 4
PostScript calculator). Both are attacker-controlled, both are in `mspdf.dll` in full.

**Result: a negative for RCE.** One real spec-conformance gap with a denial-of-service
consequence (out of scope) is recorded in §2.

## 1. Where it lives

Both surfaces are implemented — the keys are all present in the binary (`ShadingType`,
`BitsPerCoordinate`, `BitsPerComponent`, `BitsPerFlag`, `VerticesPerRow`, `Decode`, `Coords`,
`Extend`, `Background`, `AntiAlias`, `FunctionType`, `Domain`, `Range`, `Encode`,
`BitsPerSample`), as is a Type 4 PostScript operator set (`atan cos div dup eq exp floor ge gt
if le ln log lt ne or pop sin sqrt true false`).

Located by string xref:

| component | handler |
|---|---|
| `ShadingType` dispatch | `FUN_1803683CA` |
| type 4, free-form Gouraud | `FUN_180373AD2` (params), `FUN_180373D70` (vertex read) |
| type 5, lattice-form | `FUN_1803774E0`, `VerticesPerRow` at `FUN_180376C40` |
| types 6/7, Coons / tensor patch | `FUN_18037CECA` |
| Type 0 sampled function | `FUN_180247108` (8,710 B) |

The class family, from RTTI: `PDFGouraudVertexStream` (abstract — slot 2 is `_purecall`),
`FreeFormGouraudVertexStream`, `LatticeFormGouraudVertexStream`, `CoonsPatchStream`,
`TensorPatchStream`, each with a `ColorConverter*` wrapper and a matching
`t3::imaging_model::*StreamSampler`.

## 2. The one real gap: bit widths validated only as non-negative

`FUN_180373AD2` builds the vertex stream and reads the bit widths:

```c
FUN_18003C514(local_50, "BitsPerCoordinate", local_32);
uVar2 = FUN_1800C522E(local_70);
if ((int)uVar2 < 0) { FUN_1801151C3(); }      /* reject only if negative */
else { param_1[1] = (ulonglong)uVar2;
       … "BitsPerComponent" …
       if (-1 < (int)uVar2) { param_1[2] = (ulonglong)uVar2; … } }
```

PDF 32000 restricts `BitsPerCoordinate` to {1, 2, 4, 8, 12, 16, 24, 32} and `BitsPerComponent`
to {1, 2, 4, 8, 12, 16}. **Neither set is enforced** — any value in `[0, 0x7FFFFFFF]` is
accepted.

**This is not memory-unsafe.** The consumer is `FUN_1803740B6(bitreader, nbits)`:

```c
uVar5 = min(nbits, uVar3);                       /* uVar3 is bits left in the byte, <= 8 */
iVar4 = (iVar4 << (uVar5 & 0x1f)) + (((0xff >> ((8 - uVar3) & 0x1f)) & bVar1) >> ((uVar3 - uVar5) & 0x1f));
nbits -= uVar5;
```

Every shift is masked `& 0x1f` and `uVar5 <= 8`, the accumulator is an `int` that simply wraps,
and the loop decrements `nbits` by at least one per iteration so it always terminates. A huge
`BitsPerCoordinate` therefore costs up to ~268M iterations **per coordinate, per vertex** — a
hang, not corruption. DoS is out of scope for this engagement, so it is recorded rather than
filed.

## 3. The vertex read is bounded

`FUN_180373FB6` reads the coordinates and colour components:

```c
uVar6 = FUN_1801A65F4(decode, lVar5 + 1);        /* Decode[2k+5] */
uVar7 = FUN_1801A65F4(decode, lVar5);            /* Decode[2k+4] */
uVar4 = FUN_18037414A(bitreader, this->+0x10, uVar7, uVar6);
*(undefined8 *)(param_2[3] + -0x10 + lVar5 * 4) = uVar4;   /* colour write at out[3] + 8k */
lVar5 = lVar5 + 2;
```

`/Decode` is attacker-supplied and its length is independent of the colour space's component
count, which is the classic opening. It is closed: the accessor chain
`FUN_1801A65F4` → `FUN_180197ADE` → **`FUN_1800DE180`** ends in an explicit bound with a throw:

```c
uVar2 = FUN_18028E10A(param_1 + 0x10);     /* array size */
if (param_2 < uVar2) { FUN_18028E09A(param_1 + 0x10, param_2); return; }
FUN_180229D40();                            /* out of range -> throw */
```

Both `/Decode` reads happen **before** the colour write in each iteration, so a short `/Decode`
aborts the loop before that iteration writes. And the loop count is `ncomponents`, so the write
count is `min(ncomponents, Decode-permitted)` — never more than the colour space asks for.

## 4. Type 0 sampled functions

`FUN_180247108` (8,710 B) is mostly libc++ vector plumbing. Its allocations are all 64-bit with
explicit max-size guards, e.g.

```c
if (uVar10 >> 0x3e == 0) { uVar9 = FUN_18002C0E9(uVar10 * 4); … }
else FUN_1800C9989("get_next_capacity, allocator's max size reached");
```

`uVar10 >> 0x3e == 0` bounds the count below 2^62 so the ×4 cannot wrap a 64-bit size. Correct.

## 5. Scans

Both scanners, scoped:

```
shading region  0x180368000-0x180380000 : 1 unguarded-write candidate
function region 0x180240000-0x180250000 : 0
```

The single candidate, `FUN_18037C503`, is **de Casteljau cubic subdivision**:

```c
*param_2        = param_1[0];
param_3[s*3]    = param_1[s*3];
*param_3        = (param_1[s*2] + param_1[s]) * 0.5;
param_2[s]      = (param_1[s] + param_1[0]) * 0.5;
…
```

`param_4` is a **stride**, not an index — the accesses are `[0]`, `[s]`, `[s*2]`, `[s*3]`, the
four control points of a cubic. Both callers pass an immediate: `mov r9d, 0x1` at `0x18037C11F`
(contiguous) and `mov r9d, 0x4` at `0x18037C40F` (one row of a 4×4 tensor control grid).

**Fourth false-positive mode for `unguarded2.py`: stride/pitch parameters.** Added to
`tools/README.md` alongside the three from round 17.

## 6. Assessment

Mesh shadings and PDF functions are not where the next bug is. The pattern matches the rest of
this engine: array indices bounds-checked with a throw at the accessor, allocation counts
guarded against overflow before the multiply, and shift amounts masked. The one deviation —
bit widths accepted outside their spec-allowed sets — lands in DoS territory rather than
memory corruption because the bit reader is written defensively.
