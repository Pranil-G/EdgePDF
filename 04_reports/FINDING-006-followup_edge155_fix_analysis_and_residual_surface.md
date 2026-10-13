# FINDING-006 follow-up — the Edge 155 fix, what it covers, and what it leaves open

| | |
|---|---|
| Status of FINDING-006 | **Fixed in Edge 155.** Confirmed exploitable on Windows in Edge 154 before the fix. |
| Fix shape | a field allowlist: snapshot `+0x0C`, `+0x0F`, `+0x30` (`xcb`), `+0x34` (`ycb`) before the `COC` copy; when `TPsot != 0`, compare and branch to the shared decoder error path at RVA `0x88D7DB` on any difference. Rejection points near RVAs `0x88D517` / `0x88D523`. |
| Relation to the filed advice | this is suggested fix **#2** (extend the consistency check to the state-shaping tuple), not **#1** (give the `COC` block the `TPsot != 0` guard its two sibling blocks already have). |
| Residual risk | the 0xE0-byte copy still runs on later tile-parts. Of the 0xE0 bytes it carries, Edge 155 checks **4** offsets and restores **3**. The rest are still freely mutable mid-tile. |

Addresses below are Edge 154 RVAs from the corpus (`mspdf.dll` 154.0.4258.33). Edge 155's
`mspdf.dll` was not available to this analysis, so the fix itself is characterised only from
the reported RVAs; everything about the *surrounding* code is read from 154.

---

## 1. Correcting the severity reading of the `UD1`

The Edge 154 crash lands on `mspdf.dll+0x900AFF`. That address is **not a security guard
in front of the overflow** — it is a shared trap target the compiler treats as unreachable:

```
180900af8: or    dword ptr [rax + 4*rbp + 0x4], r15d     ; tail of a jump-table arm
180900afd: jmp   0x180900a7f
180900aff: ud1   eax, dword ptr [eax + 0x12]             ; <- the trap
```

Three range checks inside `FUN_1808FE180` — the 4-byte-variant EBCOT bit-plane decoder from
FINDING-006 link 4 — branch to it:

| site | check | meaning |
|---|---|---|
| `0x8FE66B` | `cmp r12, 0x4 / je` | a dispatch value the switch treats as impossible |
| `0x8FE6BB` | `cmp rcx, 0x2e / ja` | index into a 0x2E-entry table |
| `0x8FE74E` | `cmp rdx, 0x1f / ja` | shift count must be ≤ 31 |

So reaching the `UD1` is a **symptom of the corrupted state being read back** as MQ contexts
and shift counts, not a check that prevented a write. The ordering in `FUN_1808877AE` is
explicit and unchanged from the finding:

```c
} else if (uVar22 < 0x21) {
  FUN_180885AA5(*(undefined8 *)(local_d0 + 8), 0, lVar14 << 2);  /* OOB write #1: memset  4104 into 1027 */
  FUN_1808F9500(local_e0, local_e8);                             /* OOB write #2: memcpy  4104 into 1027,
                                                                    sourced by reading 4104 from another 1027 */
  FUN_1808FE180(local_e0, local_e8, local_148, local_140, local_d0, …);  /* only now the decoder runs */
}
```

Both out-of-bounds writes complete before the decoder is entered. The `UD1` therefore clips
the *follow-on* ability to write attacker-chosen bit-plane state through the decoder, but it
does not prevent the 3,077-byte zero-fill or the 3,077-byte heap-to-heap copy. FINDING-006
remains a genuine out-of-bounds write; what the trap removes is the easiest controlled-write
escalation path, so "renderer RCE candidate" should be read with that caveat.

---

## 2. The 0xE0-byte record, and what the copy actually does

`FUN_1807BBAAA` is **not** a raw `memcpy` — it is a deep clone. This matters, and it kills
one obvious follow-up before it starts:

```c
FUN_1807BBAAA(dst, src) {
  memcpy(dst, src, 0xE0);                                  /* shallow copy ... */
  dst[0x20] = dst[0x28] = dst[0x98] = dst[0xA0] = 0;       /* ... then null the 4 pointers */
  dst[0x98] = alloc(400);
  dst[0xA0] = alloc(400);
  dst[0x20] = alloc((src->L + 1) * 4);
  dst[0x28] = alloc((src->L + 1) * 4);
  if (all four) {
    memcpy(dst[0x98], src[0x98], (src->L * 3 + 1) * 4);
    memcpy(dst[0xA0], src[0xA0], (src->L * 3 + 1) * 4);
    memcpy(dst[0x20], src[0x20], (src->L + 1) * 4);
    memcpy(dst[0x28], src[0x28], (src->L + 1) * 4);
  }
}
```

**Disproved hypothesis 1 — pointer aliasing / UAF / double free.** Because the four pointer
fields are reallocated and their *contents* copied, the live coding style never ends up
sharing a heap pointer with the parser's `COC` array entry. No aliasing, no double free.

### Field map (from the `COC` handler, `FUN_18091503D` case `0xFF53`)

| offset | field | how it is set | protected in 155? |
|---|---|---|---|
| `+0x08` | `Ccoc` component index | read from the marker | — (bounds-checked at use) |
| `+0x0C` | cbstyle bit 0 — selective arithmetic bypass | `bVar7 & 1` | **yes** (snapshot) |
| `+0x0D` | cbstyle bit 1 — reset context probabilities | `bVar7 >> 1 & 1` | no |
| `+0x0E` | cbstyle bit 2 — terminate on each coding pass | `bVar7 >> 2 & 1` | **no** |
| `+0x0F` | cbstyle bit 3 — vertically causal context | `bVar7 >> 3 & 1` | **yes** (snapshot) |
| `+0x10` | cbstyle bit 4 — predictable termination | `bVar7 >> 4 & 1` | no |
| `+0x11` | cbstyle bit 5 — segmentation symbols | `bVar7 >> 5 & 1` | no |
| `+0x14`, `+0x18` | cached `PPx[0]`, `PPy[0]` | `0xF0000000F` when precincts are default | **no** |
| `+0x20` | → `PPx[]` array, `(L+1)*4` bytes | allocated and filled in the handler | **no** (contents replaced by the clone) |
| `+0x28` | → `PPy[]` array, `(L+1)*4` bytes | same | **no** (contents replaced) |
| `+0x30` | `xcb` = `xcb_raw + 2` | validated `< 0xB` | **yes** (snapshot) |
| `+0x34` | `ycb` = `ycb_raw + 2` | validated, `ycb_raw < 9`, sum `< 0xD` | **yes** (snapshot) |
| `+0x38` | `L` decomposition levels | validated `< 0x21` | compared by both drivers, **after** the copy |
| `+0x3C` | transform / reconstruction mode | `(byte == 0)` | **no** |
| `+0x40`, `+0x44`, `+0x48` | progression, layers, MCT | — | **yes** (written back after the copy) |
| `+0x4C` | `TPsot` | set by `sub_18088C65E` | n/a (the guard field itself) |
| `+0x98`, `+0xA0` | two fixed **400-byte** arrays | reallocated by the clone, filled `(3L+1)*4` | **no** (contents replaced) |
| `+0x50`, `+0x58`, `+0x60`, `+0x6C`, `+0x90`, `+0x94` | read by the decode driver; semantics not yet pinned | — | **no** |

### Offsets the decode driver reads

`FUN_1808877AE` reads these coding-style offsets, with read counts:

```
0x0C ×6   0x44 ×6   0x0E ×5   0x0F ×3   0x94 ×3   0x90 ×3
0x4C ×2   0x34 ×2   0x6C ×1   0x60 ×1   0x58 ×1   0x50 ×1   0x3C ×1
```

Nine of the thirteen are still mutable by a later tile-part in Edge 155.

**Disproved hypothesis 2 — oversized `L` via write-before-validate.** The handler writes
`+0x38` *before* checking it:

```c
bVar7 = FUN_1808F4580(param_2, 1);
*(uint *)(lVar23 + 0x38) = (uint)bVar7;     /* committed first */
if (bVar7 < 0x21) { … }                     /* checked second */
```

and by that point the entry has already been appended (`*(int *)(param_1+0x30) = iVar15+1`)
and the "header carries COC entries" flag set. An entry carrying `L` up to 255 would make the
clone's `memcpy(dst[0x98], src[0x98], (255*3+1)*4 = 3064)` overflow a 400-byte allocation by
2,664 bytes, twice. **But it fails closed:** the handler `break`s out of the switch, and the
marker loop is a `goto`-based loop whose only continue edge is `goto LAB_1809151FF` from the
success paths. A `break` falls through to `return 10`, aborting the header parse before
`sub_18088C65E` can apply anything. Not exploitable as written.

Worth recording as a hardening note regardless: the `+0x98`/`+0xA0` pair is allocated at a
fixed 400 bytes and filled `(3L+1)*4`, which is 388 bytes at the `L = 32` limit — **12 bytes
of slack**. Any future raise of the `L` cap, or any path that reaches the clone with an
unvalidated `+0x38`, overflows both arrays.

---

## 3. Residual candidates, ranked

### 3.1 Precinct size exponents — `+0x20` / `+0x28` (and cached `+0x14` / `+0x18`)

**The strongest candidate: structurally identical to FINDING-006, on an unprotected field.**

The geometry builder `FUN_180890FB4` runs **only** under the `TPsot == 0` gate (it has
exactly one caller, `FUN_18088E70A`, which both drivers invoke only when
`*(int *)(param_1 + 0x4C) == 0`). It derives the precinct grid from the `PPx`/`PPy` arrays:

```c
lVar16 = *(longlong *)(lVar3 + 0x38);                                   /* the coding style */
… *(longlong *)(lVar16 + 0x28) + (longlong)((int)fVar19 + 1) * 4        /* PPy[res+1] */
… *(longlong *)(lVar16 + 0x20) + (longlong)((int)fVar19 + 1) * 4        /* PPx[res+1] */
lVar7  = *(longlong *)(lVar3 + 0x38);
… *(undefined4 *)(*(longlong *)(lVar7 + 0x28) + uVar17 * 4)             /* PPy[i] */
… *(undefined4 *)(*(longlong *)(lVar7 + 0x20) + uVar17 * 4)             /* PPx[i] */
```

and in the same function allocates the band array as `(3L + 1)` records of 0x30 and 0x78
bytes. `FUN_1808915B6` then allocates the per-code-block contexts, and `FUN_18088A218`
iterates with the precinct counts `+0x5C` / `+0x60` as loop bounds.

A later tile-part `COC` with `Scoc` bit 0 set carries `L+1` explicit `PPx`/`PPy` nibble pairs,
and the clone copies them straight over the live arrays. Nothing snapshots or compares them.
So the precinct *size* changes while the precinct grid, the 0x30-stride code-block records
and the 0x70-stride decoder contexts all remain as built from the old sizes.

This is worth more than FINDING-006 was, because the precinct exponents determine **array
dimensions and loop bounds**, not just a `memset` length.

Audit order:
1. Which decode-time consumers re-read `+0x20`/`+0x28`/`+0x14`/`+0x18` rather than the cached
   grid — the packet iterator is the first place to look, since it runs per tile-part.
2. Whether `+0x5C`/`+0x60` are re-derived anywhere on the `TPsot != 0` path. `FUN_18088E7FC`
   walks the existing arrays and only shifts offsets, so the expectation is no.
3. `FUN_18088A218` bounds-checks its code-block index against the array's own `+0x20`/`+0x24`
   dimensions and fails closed to null — so the win, if there is one, is more likely in
   `FUN_1808915B6`, whose inner index is only sign-checked
   (`(int)((uint)lVar14 | (uint)lVar13) < 0`) with the outer one compared against `+0x60`.

### 3.2 `+0x0E` — terminate on each coding pass

The cbstyle byte is unpacked into six separate bytes at `+0x0C`…`+0x11`. Edge 155 snapshots
`+0x0C` and `+0x0F` and leaves the other four. `+0x0E` is read five times in the decode
driver, in the *same* `if` chains as the protected `+0x0C`:

```c
cVar8 = *(char *)(lVar7 + 0xE);
if ((cVar8 == '\x01') && (local_64 != 0)) {
  if ((9 < (int)local_a0 && *(char *)(lVar7 + 0xC) == '\x01') && (*piVar24 != 2)) goto LAB_180888184;
  FUN_1808F944A(local_b0);
  cVar8 = *(char *)(lVar7 + 0xE);
}
if (((cVar8 == '\0') && (*(char *)(lVar7 + 0xC) == '\x01')) && …) FUN_1808F944A(local_b0);
```

Flipping `+0x0E` mid-tile changes the codeword-segment model — whether each coding pass is its
own MQ segment — against a segment-state array (`plVar3[1]`, sized `(layers + 1) * 0x28`) and a
per-layer segment counter laid out under the old model. The protection asymmetry between two
bits of the same byte, used side by side, is the clearest sign that the fix was derived from
the PoC rather than from the field set.

### 3.3 `+0x3C` — transform / reconstruction mode

Captured by the geometry builder at setup time into a local:

```c
local_100 = CONCAT71(local_100._1_7_, *(int *)(*(longlong *)(lVar3 + 0x38) + 0x3C) == 1);
```

and re-read by the decode driver to select the reconstruction bias:

```c
if (*(int *)(lVar7 + 0x44) - 1U == local_68 && *(int *)(lVar7 + 0x3C) == 1) uVar29 = 0x3F000000; /* 0.5f */
else                                                                        uVar29 = 0;
```

Setup-time capture plus decode-time re-read of an unprotected field is the FINDING-006 shape
again. Reversible vs irreversible also governs integer vs float coefficient handling further
down, which is where a mismatch would be worth something.

### 3.4 `+0x90` / `+0x94`, gated by `+0x6C`

```c
if ((*(char *)(lVar7 + 0x6C) == '\x01') && (local_68 == *(int *)(lVar7 + 0x44) - 1U)) {
  if (*(int *)(lVar7 + 0x90) < *(int *)(lVar7 + 0x94)) {
    if (0 < (int)local_a8 && 0 < (int)local_c8) { … }
```

A compared `int` pair gating a loop over the actual code-block dimensions, read three times
each, all three fields unprotected. Semantics not yet pinned — identify which marker writes
`+0x6C`/`+0x90`/`+0x94` first (they are outside the `COC` handler's writes, so probably `RGN`,
`POC` or a `COD`-only field).

---

## 4. The structural point, for the MSRC thread

Edge 155 fixes the reported instance. It does not close the class. The underlying defect is
still that `sub_18088C65E`'s per-component `COC` block applies a later tile-part's coding
style at all, while its **two sibling blocks in the same function** reject later tile-parts
outright with `if (tile->+0x4C != 0) return …` (guards at `0x88C902` and `0x88C9B8` in 154).
Adding that one test to the `COC` block — suggested fix #1 — would have covered every field
in the record, including all nine the decode driver still reads unprotected, rather than the
four the allowlist names.

As shipped, the fix has to be re-audited every time a field is added to the coding-style
record, and it is already incomplete with respect to §3.1–§3.4.

**Next step:** build the §3.1 PoC. Same two-tile-part skeleton as
`05_poc/FINDING-006/poc_min.j2k`, with `xcb`/`ycb` held constant so the Edge 155 comparison
passes, `Scoc` bit 0 set in both the `COD` and the tile-part `COC`, and different explicit
`PPx`/`PPy` nibbles in each. `tools/gen_finding006.py` already emits conforming two-tile-part
codestreams and only needs the precinct bytes added to `cod()` / `coc()`.
