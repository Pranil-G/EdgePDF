# Round 11 — niche zero-click decoders, the ICC engine, and the functions Ghidra could not decompile

Target: `mspdf.dll` 154.0.4258.33 (`F21CC09C…1688`), the Acrobat/T5-derived PDF engine loaded by
Edge's `--pdf-renderer --pdf-shared-library` process, plus the `edge_glue` corpus.

Scope: **exploitable memory corruption, web-reachable, critical only. DoS is out of scope**, so
`ud2` / `int3` / `invalidInstructionException` / `t5::corrupt_data` outcomes are mitigations that
close a path, not findings.

Method for this round: rounds 1–10 closed the high-traffic surfaces (JBIG2 in full, libjpeg in
full, the PDF-array chokepoint module-wide, transport, and the whole browser-integration
boundary). So this round deliberately targeted **only** surfaces that no prior round read at all,
picked on two criteria: zero-click reachable from a document, and structurally invisible to a
fuzzer or to a decompiler.

## Result

**No exploitable memory-corruption bug confirmed.** Seven surfaces were audited, four of which had
never been examined in any prior round. Two concrete specification deviations were found and both
are provably compensated at their use sites. The value of the round is negative-space plus the
specific invariants each surface depends on, recorded so a future build can be regression-checked
against them cheaply.

---

## 1. CCITTFax pixel-emit path — round 10's open question, answered NEGATIVE

Round 10 left this explicitly open: *"the pixel-emit path … was not located. So the question 'is
`(Columns + 7) / 8` computed in 32 bits anywhere' is still open and is the right place to resume:
an unbounded `Columns` feeding a 32-bit byte-count computation would wrap to a tiny allocation
against a row the decoder then fills."*

Located and closed. `t3::data_io::CCITTDataBlockStream` vtable is at `0x180b159c0` and has four
slots: `{180164b80 dtor, 180162ee0, 18002dcd0, 180160f30}`. **Slot 1, `FUN_180162ee0` (487 B), is
the emit path.**

Two independent reasons there is no bug:

**(a) There is no internal row buffer at all.** The function emits directly from the
changing-element run state into the *caller's* destination buffer. Every write is clamped to the
minimum of three quantities:

```c
iVar6        = *(int *)(param_1 + 100);        // A: bytes left in current output row
local_74[1]  = (int)param_3 - (int)uVar12;     // B: bytes left in the caller's buffer
local_74[2]  = uVar2 >> 3;                     // C: whole bytes available in current run
/* signed min of A,B,C -> iVar6 */
if (lVar8 < 8) { switch(iVar6) { case 7..1: byte stores; default: -> int3 } }
else           { FUN_1809e2510(pcVar1, cVar5, lVar8); }   // memset(dst+pos, fill, n)
```

Because `min <= B = param_3 - uVar12`, every write stays inside `dst[0, param_3)`. A zero or
negative minimum lands on the `default:` arm, which traps. The bit-granular path (`uVar2 < 8`)
writes `dst[uVar12] = 0` once per outer iteration, and the outer loop re-tests
`if (param_3 <= uVar12) return` at `LAB_180162ff5` before every iteration, so `uVar12 < param_3`
holds at that store.

**(b) The row byte count cannot wrap.** In the constructor `FUN_18016463c`:

```c
iVar7 = FUN_18002b57f();                             // Columns + 7, signed-overflow CHECKED
*(int *)((longlong)param_1 + 0xfc) = iVar7 >> 3;     // row bytes
*(int *)((longlong)param_1 + 100)  = iVar7 >> 3;
```

`FUN_18002b57f` is a signed-overflow-checked add that traps rather than returning
(`sar/adc/cmp; jne -> int3` at `18002b5a9`). So `Columns > INT_MAX - 7` aborts before the shift.
Round 10's premise — an unbounded `Columns` reaching a 32-bit byte-count computation — is correct
about `Columns` (it really is only lower-bounded, `if (Columns < 1) Columns = 0x6c0`) but the
multiply/add is checked and the product is never used as an allocation size.

**CCITTFax G3/G4 is now fully closed** and should not be re-audited.

## 2. The `t3::color` ICC engine — never audited in any prior round, clean

The register listed `ICCBased` only as a string seed under the paused family B. There is in fact a
complete bespoke ICC colour-management engine in `mspdf.dll`, **zero-click reachable from
`/ColorSpace [/ICCBased <stream>]` in any PDF**, at RVA `0x180200000`–`0x180212000`:

`ICCColorConverterImpl`, `ICCEngineStep`, `ICCStep1DTable`, `ICCStepMDTable{,Linear,Tetrahedral,Hedral}`,
`ICCStepAffineTransform3D`, `ICCStepGamma`, `ICCStepParametricCurve{,1,2,3,4}`, `ICCStepLabToXYZ`,
`ICCStepNull`. Tag parsers: `mft1 -> FUN_18020e795`, `mft2 -> FUN_1802101cd`,
`mAB  -> FUN_18021069e`, `mBA  -> FUN_180211ab0`, dispatched by `FUN_18020e68e`.

This is the classic lcms-style bug surface (CLUT grid points, channel counts, A2B/B2A offsets).
It is hardened on every axis that matters:

| check | location | effect |
|---|---|---|
| `inputChan`, `outputChan` each in **[1,4]** | `FUN_18020f0f2`: `if (4 < bVar1 \|\| 4 < inputChan) -> t5::unimplemented`; `== 0 -> t5::corrupt_data` | far stricter than the ICC spec's 15/16 |
| CLUT grid points **>= 2** | `FUN_18020ebd4`: `if (1 < bVar1)` else `t5::corrupt_data` | no zero/one-point tables |
| CLUT element count via **checked multiply** | `FUN_18015ad86` (wraps `FUN_1801154c6`, traps on overflow) accumulated `nOut * grid^nIn` | `grid^4 * 4` cannot wrap |
| colour space -> channel count is a **closed enum** | `FUN_1802034a8`: GRAY=1, 2CLR=2, 3CLR/Lab/RGB/XYZ/YCbr=3, 4CLR/CMYK=4; **5CLR–8CLR -> `t5::unimplemented`**; anything else -> `corrupt_data` | no 5..8-channel profiles at all |
| **lut channel counts cross-checked against the profile header** | `FUN_18020228e` | closes the classic mismatch |

That last one is the important one, and it is explicit:

```c
uVar2 = *(uint *)(*param_4 + 0x10);     // lut->inputChan
uVar8 = FUN_1802034a8(iVar17);          // channels(profile data colour space)
if (uVar8 != uVar2) -> t5::corrupt_data
uVar2 = *(uint *)(*param_4 + 0x14);     // lut->outputChan
uVar8 = FUN_1802034a8(iVar14);          // channels(profile PCS)
if (uVar8 != uVar2) -> t5::corrupt_data
```

So a profile declaring CMYK in its header while its A2B0 tag declares 3 input channels is rejected
at pipeline-build time, before any interpolator runs. **This is the invariant to re-check on future
builds**: if either equality test is ever relaxed, the MDTable interpolators become indexable with
a channel count the CLUT was not sized for.

Note: the `png_icc_check_*` family at `0x180ad9a1f` / `0x180ad9c28` is **libpng's** ICC validator,
not this engine. Its tag-table walk reads a tag count from header offset 0x80 with no bound against
the profile length in that function, but round 7 already established libpng has no
attacker-controlled producer in mspdf, so it is not reachable.

## 3. LZW (`t3::data_io::LzwDataBlockStream`) — never audited, clean

Decode is `FUN_180166fa0` (373 B) via vtable `0x180b15a80` slot 1; the code reader / dictionary
builder is `FUN_180167116` (666 B). Legacy filter, therefore under-fuzzed, and zero-click.

There is a genuine hazard shape here worth recording, because it is subtle: the expansion of a
code is written **backwards** from `dst + written + predicted_len - 1`, and the walk terminates
only when the prefix chain reaches a literal — there is no lower-bound check on the write pointer.
If `predicted_len` ever under-estimated the true chain length, the walk would write *below* the
destination buffer (a heap **underwrite**, not an overflow).

It cannot. Three facts close it:

1. **Every defined entry's length byte is >= 2.** `FUN_180167116` sets it to `2` when the prefix is
   a literal (`if ((int)uVar12 < 0x100)`), otherwise to `prefix_len + 1` saturating:
   `cVar8 = *(char *)(lVar11 + 2) + 1; cVar14 = (cVar8 != 0) ? cVar8 : -1;` so 255 is a sentinel,
   never a wrap to 0.
2. **The 0xFF sentinel forces an exact recomputation.** `FUN_180166fa0` walks the same chain the
   write loop will walk (`uVar6 = 2; while (prefix > 0x101) { prefix = prefix(prefix); uVar6++; }`),
   yielding exactly `k+1` for a chain of `k` non-literal links — identical to the bytes written.
3. **A length byte of 0 is only possible for an *undefined* entry, and undefined codes are
   unreachable.** When the dictionary is full (`nextfree >= 0xEFF`) `FUN_180167116` returns the raw
   code without the `uVar12 < nextfree + 0x102` validation — but at that point the code width has
   saturated at 12 bits, so the largest expressible code is `0xFFF`, whose index `0xEFD` is below
   `nextfree`. The bypass and the undefined range are mutually exclusive. After a CLEAR,
   `nextfree = 0` and the mask resets to `0x1FF`, so every non-literal code is rejected to EOD.

All index guards land on `invalidInstructionException`: `0xeff`, `0xefe`, `0x1001`, `0xf00`.
Max dictionary write offset is `0x43 + 0xf00*4 = 0x3c43`, inside the `0x48..0x3c48` table region.

## 4. JBIG2 custom Huffman tables, segment type 53 — the one sub-surface round 7 left, clean

Round 7 audited symbol dictionary (both variants), text region, refinement (both templates),
generic region (all four templates incl. arbitrary AT), halftone and pattern dictionary — but not
the **tables** segment. Dispatcher `FUN_1808e4fa0` `case 0x35 -> FUN_1808e4308` (998 B).

This is a two-pass count-then-fill parser, the exact shape where FINDING-002-style mismatches live.
Pass 1 counts entries; the count is then `+2` (or `+3` with HTOOB) and three arrays are allocated;
pass 2 rewinds the bit reader and refills. Proven consistent:

- both passes start from the same saved byte pointer (`*plVar4 = (int)(local_60 - (int)*plVar4) + *plVar4`,
  the 32-bit-difference idiom for `ptr = local_60`) **and** the same bit position (`+0x15 = 8` is
  set before each pass);
- both read the same widths, `HTPS = ((flags>>1)&7)+1` and `HTRS = ((flags>>4)&7)+1`, each in [1,8],
  so the range-length value fits a byte and the store/reload in pass 2 is lossless — pass 1's shift
  operand and pass 2's reloaded `rangeLen[i]` are necessarily equal;
- the running value uses the checked add `FUN_18015ad63` and the counter the checked add
  `FUN_18015ac86`, both bailing on overflow;
- indices written are `0..N+1` (no OOB) or `0..N+2` (HTOOB) against an allocation of `N+2` / `N+3`.
  Exact fit.

**Correction to a decompiler artifact:** Ghidra renders the int-array sizing as
`local_54 = 0; FUN_18015ac40(4, local_50); lVar14 = FUN_18015a2b4(local_54);`, which would be a
zero-byte allocation followed by `4*(N+2)` bytes of writes — a heap overflow. The machine code shows
`FUN_18015ac40` takes an out-pointer that Ghidra dropped:

```
1808e4467: 4c 8d 44 24 64     lea  r8, [rsp + 0x64]     ; &local_54
1808e447c: e8 bf 67 87 ff     call 0x18015ac40          ; checked mul -> local_54 = 4*count
```

So the allocation is `4*count`. Anyone re-reading this function from pseudocode alone will see a
false positive here.

## 5. The functions Ghidra could not decompile — triaged, two read

The register listed these as unexamined (lead D). Sizes: `180003180` 24 B, `1802bac34` 113 B,
`1802bb0b4` 113 B, `1804a2d9d` 235 B, `180a97411` 217 B, **`18082d385` 13,727 B**,
**`1804ee626` 22,875 B**. The two large ones are real attacker-reachable parsers that no prior
round read, because there is no pseudocode for them.

### 5a. `FUN_18082d385` (13.7 KB) — annotation / Widget form-field processor

Identified from its referenced strings: `Subtype`, `Widget`, `FT`, `Ff`, `Parent`, `AP`, `AS`,
`Rect`, `BBox`, `Contents`, `IC`, `Off`, `Btn`, `Text`, `Stamp`. Zero-click: annotations are
processed on page render. Called from `FUN_1806d5266` and `FUN_1808366e0`.

**It contains zero register-indexed memory operands and zero `rep movs/stos` in all 13,727 bytes.**
Every memory access uses a constant displacement off `rbp`/`rsp` or an object pointer. The call
profile is `FUN_1807270e8` ×67 (sptr release), `FUN_18003e3c3` ×34 (string dtor),
`FUN_18003c514` ×33 (key construction), `FUN_1800abbda` ×19 (dict lookup), `strcmp` ×7.

It is a flat, dictionary-driven dispatcher. Ghidra timed out on the RAII/exception edge explosion
(67 release sites × unwind paths), not on arithmetic. **With no array indexing there is no OOB
write primitive in this function.**

### 5b. `FUN_1804ee626` (22.9 KB) — image soft-mask / stencil-mask processor

Strings: `SMask`, `Mask`, `SMaskInData`, `Matte`, `ColorSpace`, `DeviceGray`. Zero-click on any
masked image. This is the largest undecompiled function in the module.

Exactly **three** register-indexed memory operands in 22,875 bytes, of which one is a write. That
write is a vector copy, and it is in bounds:

```
1804f0d23: mov rsi, [rbp + 0x710]      ; n  <- source vector size
1804f0e6a: sub rsi, -0x2               ; n + 2
1804f0e6e: jae 0x1804f3f26             ; wrap -> error            (checked)
1804f0e7d: cmovae rbx, rsi             ; capacity = max(8, n+2)
1804f0e91: shr rax, 0x3d
1804f0e95: jne 0x1804f3d06             ; n+2 >= 2^61 -> error     (checked)
1804f0e9b: lea rcx, [8*rbx]            ; alloc capacity*8
...
1804f0ee9: mov qword [rax], 0          ; dst[0] = 0.0
1804f0f01: mov qword [rax+8], 1.0      ; dst[1] = 1.0
1804f0f05: mov rax, [rbp + 0x710]      ; n  (reload)
1804f0f2c: movsd [rdx + r8 + 0x10], xmm0   ; dst[2 + i] = src[i], i < n
```

Destination holds `n + 2` elements and `2 + n` are written. The copy count is a *reload* of
`[rbp+0x710]`, so the pair is only safe if that slot is stable across the window — it is: writes to
`[rbp+0x710]` occur at `1804efc9c`, `1804f04b5`, `1804f0cd2`, then not again until `1804f151a`,
which is after the copy, and neither intervening call (`18053eb7c`, the allocator `18002c0e9`)
receives a pointer to that slot.

Every other write loop in the function is standard libc++ `__split_buffer` growth — the
`mov [rax-0x18], rax / mov [rax-0x10], 0 / mov [rax-0x8], N` triple followed by begin/end/cap
updates — instantiated for byte, word, dword and double element types (the `/Decode`, `/Mask`,
`/Matte` arrays).

`/SMaskInData` handling is guarded: read only on the JPX path, `js -> error` on a negative value,
and mutually exclusive with `/SMask` (`and al, bl; cmp al, 1; je error`). Even if a value selected
an alpha channel the codestream lacks, the jp2k side re-checks component indices
(`FUN_18089a314`: `if ((int)uVar4 < 0 || *(int *)(param_1 + 0xc) <= (int)uVar4) -> 10`).

## 6. JPEG 2000 — the marker parser, the JPX box layer, and the allocators

FINDING-002 found the module's only real unguarded state mutation in `t5\firstparty\jp2k`
(Microsoft's own JPEG 2000 implementation, `/JPXDecode`, zero-click). That made it the best prior
on weaker hardening, so the surrounding code was re-read.

**Component mapped**: 13 translation units, `JP2KLibCApiGlue / JP2KLib / JP2KMemFuncDefs /
JP2KGeometry / JP2KApiGlue / JP2KImageMap / JP2KSafePointer / JP2KImage / JP2KFileFormat /
JP2KCompTransform / JP2KDecDataMgr / JP2KEbcotDecodingPasses_{8g,gen}`, spanning
`0x1807bc000-0x1807be000`, `0x180885000-0x1808a0000`, `0x1808f0000-0x180918000`.

**Codestream marker parser `FUN_18091503d` (6112 B)** — all size-bearing fields validated:

| field | guard |
|---|---|
| `Csiz` | `!= 0` and `Csiz*3 + 0x26 <= Lsiz` |
| `XRsiz`/`YRsiz` | `!= 0` (no divide-by-zero) |
| `Ssiz` depth | `(byte)(v - 0x27) < 0xda -> reject`, i.e. depth in [1,38] |
| COD/COC `xcb`,`ycb` | raw each `<= 8`, sum `<= 8`, then `+2` => `xcb,ycb in [2,10]`, `xcb+ycb <= 12` — exactly the spec |
| COD/COC levels `L` | `<= 0x20` (32) |
| precinct arrays | allocated `(L+1)*4`, filled `0..L` — exact fit, in both COD and COC |
| QCD/QCC step sizes | bounded `<= 3L+1` (or 97 when `L == 0`) against 100-int arrays allocated in `FUN_1809148f0` |
| QCC deep copy | `FUN_1807bbc04` memcpy's the 0x40 struct, **then nulls and reallocates** both array pointers before copying `(3L+1)*4` bytes — no pointer sharing, no double free |

**JPX box layer `FUN_180895ce2` (10.6 KB)** — full box set (`pclr`, `cmap`, `cdef`, `opct`, `asoc`,
`cgrp`, `cref`, `ftbl`, `jpch`, `jplh`, `lbl`, `rreq`, …). The palette path, historically the
richest JPEG 2000 OOB-write source (cf. OpenJPEG `opj_jp2_apply_pclr`), is safe:

- `pclr`: `NE <= 1024`, box length `>= (NE+1)*NPC + 3`, per-column depth byte constrained by
  `(B & 0x7e) <= 0x25`. Each column allocates `((B + 8) >> 3) * NE` using the **full** `B`, while
  the data loop writes `((B & 0x78) + 8 >> 3)` bytes per entry — and `B & 0x78 <= B` for all `B`,
  so the writes are always within an over-allocation.
- `cmap`: requires `N >= NPC`; per channel, `CMP < componentCount` and `PCOL < NPC` are both
  checked, and the column pointer is **moved** out of the palette (`source = 0` after transfer),
  so a duplicate `PCOL` fails the `!= 0` test and takes the cleanup path instead of double-freeing.

**Allocator wrappers** — one genuine asymmetry, bounded:

| wrapper | check |
|---|---|
| `FUN_180885adf(size,count)` | 64-bit product, rejects `& 0xffffffff80000000` (>= 2^31) and negatives -> trap |
| `FUN_180885943(size)` | checks only `(int)param_1 < 0`, i.e. **the low 32 bits**, then allocates the full 64-bit value — weaker, but the allocation is not truncated, so it fails rather than under-allocates |
| `FUN_180885c9a(size,count,pool)` | **when `pool != 0` the 2^31 check is skipped entirely** and it tail-calls `FUN_1807bd0ea(pool, count*size)` |

That third row is the FINDING-002 shape (sibling paths, one unguarded). It is not exploitable:
`FUN_1807bd0ea` opens with `if (param_2 >> 0x20 != 0) -> error`, so the pool path still rejects
anything `>= 2^32`; it merely permits `[2^31, 2^32)` where the non-pool path would reject. Every
pool-path call site computes its size with operands widened to `longlong` first, so none can wrap.
Recorded as a hardening note, not a finding.

**`FUN_1808f5a55` / `FUN_180890fb4`** — the stride-0x30 subband array write at
`param_8[(3*(param_5 - uVar25) + 1) * 0xc]` reaches at most index `3L-2` of an array allocated
`(3L+1)*0x30`; and `FUN_1808f5a55` has exactly one caller, `FUN_180890fb4`, which is the function
that performs the allocation — so the `L` used to size and the `L` used to index are the same
variable. No FINDING-002-style split.

## 7. Two concrete deviations found — both compensated

**(a) COC/QCC component index is accepted as `<= Csiz` rather than `< Csiz`.**
`FUN_18091503d` COC: `if ((-1 < iVar14) && (iVar14 <= *(int *)(param_1 + 0x7c)))`; QCC:
`if (*(int *)(param_1 + 0x7c) < (int)sVar9) return 10;`. Valid indices are `0..Csiz-1`, so
`Ccoc == Csiz` / `Cqcc == Csiz` are wrongly accepted.

Harmless, because the stored index is a **match key**, never an array index, and every use site
re-bounds-checks it. In `FUN_18088c65e`:

```c
iVar3 = *(int *)(*(longlong *)(lVar8 + 0x40) + 8 + lVar14);     // Cqcc
if ((-1 < (longlong)iVar3) && (iVar3 < (int)plVar4[1])) {       // 0 <= Cqcc < numComponents
```

An entry with `C == Csiz` simply never matches a real component and is never applied.

**(b) COD explicit-precinct length check is off by one.**
`if (uVar10 - 0xc < *(uint *)(param_1 + 0x6c)) return 10;` accepts `Lcod >= L + 12`, but the loop
then consumes `L + 1` precinct bytes (`do { ... } while (iVar14 <= L)`), i.e. it needs
`Lcod >= L + 13`. With `Lcod == L + 12` exactly it reads one byte past the marker segment, using
the raw cursor (`bVar7 = **(byte **)(param_2 + 0x18)`) rather than the bounds-checked reader. The
preceding `FUN_1808f3ec2(param_2, uVar10)` availability check means that byte is still inside the
buffered codestream in any realistic case; at absolute end-of-buffer it is a **1-byte over-read**.
Not critical, and the array writes stay in bounds (`L+1` entries into `(L+1)*4` bytes).

## 8. Type 4 (PostScript calculator) functions — pipeline mapped, one lead closed

Zero-click via a `/Separation` or `/DeviceN` tint transform or a shading `/Function`. Not audited
in any prior round. Mapped:

- `Type4Function` vtable `0x180af96c8` = `{FUN_180253420 dtor, FUN_180252f10 (returns object size 0x2a0)}`
  — the `Function` interface has no virtual `evaluate`, so dispatch is by stored type tag, which is
  what round 6's polymorphic-cache hypothesis was really about.
- `Type4FunctionParser` vtable `0x180b139d0`; the parser is embedded at object `+0x168` and parsing
  is kicked off by `FUN_180253180` -> `FUN_180259218(stream, …, parser, FUN_18022d1f0, …)`, i.e. it
  reuses the shared `t3::pdf::content` tokenizer.
- Token handlers `FUN_180252f20…FUN_180253030` emit **16-byte instruction records** into a
  chunked vector at object `+0x128` (a second one at `+0x258`), via the shared helper
  `FUN_18002b5ce`.

`FUN_18002b5ce` is the one place in this round where a bound is genuinely **absent**: when
`elemcount == 0` but chunks already exist, it returns the first chunk with no fullness test, unlike
the normal path which tests `cursor == data_end` before chaining or allocating:

```c
if (param_1[4] == 0) {                       // elemcount == 0
    if (*param_1 == 0) { FUN_18002b64c(param_1, plVar1, 1); }   // allocate
    else { plVar1 = param_1 + 1; }                              // first chunk, UNCHECKED
    *param_2 = *plVar1;
}
```

Closed. Every append increments `elemcount` immediately after its 16-byte store, so
`elemcount == 0` implies no store has happened and the first chunk's cursor is still at
`chunk + 0x40`. The only way to break that pairing is an exception between the store and the
increment — and the unwind funclet `Unwind_1800379c8` restores exactly that invariant:

```c
*(longlong *)(param_2 + 0x38) = param_2 + 0x40;   // cursor := data start
```

The destructors (`FUN_180253420`, `FUN_1802531e0`) destroy the chunked vectors rather than clearing
and reusing them, so there is no "reset count, keep chunks" path. The chunk full-test `==` is also
exact, since the cursor only ever advances by `0x10` from a `0x10`-aligned start and chunk capacity
is a whole number of records (`0x20` for the first chunk, `0x100` after).

## 9. JPX packet iteration, POC clamping and the per-layer array — clean

Follow-on from §6, reaching the layer that lead 4 named. The progression walker is
`FUN_18088f0e2` (random access; measured by FINDING-002 as the path Edge always takes) with
`FUN_18088ce7a` as the sequential sibling. Per-precinct dispatch is `FUN_18088ebca` ->
`FUN_18088b6c6` -> `FUN_18088a218`.

`FUN_18088b6c6` both reads and writes a per-layer array at `param_1[3] + layerIdx * 8` **before**
any bound test on `layerIdx` (its own guards are `layerIdx <= param_1[2]`, the last-layer
watermark, and an equality against `layers - 1`). That array is allocated in `FUN_18088b238` as

```c
lVar2 = FUN_180885adf((longlong)*(int *)(*(longlong *)(*param_1 + 0x38) + 0x44), 8);  // layers * 8
```

so it has exactly `layers` entries and the write is only safe if `layerIdx < layers` is guaranteed
by the caller. It is — and the interesting part is that the guarantee survives a **POC**
(progression-order change) marker, which is where this bug class normally lives:

```c
local_108 = *(uint *)(*(longlong *)(lVar13 + 0x38) + 0x44);        // cs->layers, from COD
if (*(char *)(lVar13 + 0x50) == '\0') { local_a0 = local_108; }    // no POC
else {
    uVar2    = *(ushort *)(*(longlong *)(lVar24 + 0x20) + local_110 * 2);   // LYEpoc
    local_a0 = (uint)uVar2;
    if ((int)local_108 < (int)(uint)uVar2) local_a0 = local_108;    // CLAMP to cs->layers
}
for (uVar25 = 0; (int)uVar25 < (int)local_a0; uVar25 = uVar25 + 1)  // layer loop
```

All three POC end values are clamped to their COD/SIZ-derived maxima, not trusted:
`LYEpoc -> min(LYEpoc, cs->layers)`, `REpoc -> min(REpoc - 1, cs->L)`, and
`CEpoc -> min(CEpoc, numComponents)`. COD itself rejects `layers == 0`
(`if ((uVar12 & 0xffff) == 0) return 10`), so the range is [1, 65535] and the loop cannot run with
an index the array was not sized for.

The precinct index is bounded too, in `FUN_18088ebca`:

```c
param_2 < *(int *)(lVar5 + 0x4c) * *(int *)(lVar5 + 0x48)      // idx < precinctsW * precinctsH
```

That 32-bit product cannot wrap: SIZ caps tile dimensions at `0x7ffe`
(`if (0x7ffe < uVar17) return 0xe`) and precinct sizes are at least 1, so each count is at most
32768 and the product at most 2^30.

The resolution index is the one quantity *not* re-checked here — which is exactly FINDING-002's
latent path, already documented and guarded upstream by `sub_18088F0E2`'s decomposition-level
equality test.

## Leads left open, in priority order

1. **The Type 4 evaluator itself.** The compiler/emitter is mapped; the interpreter that consumes
   the 16-byte instruction stream and maintains the operand stack was not located, because
   evaluation is non-virtual. It is the highest-complexity attacker-driven code left unaudited.
   Find it by instrumenting `FUN_180259218` with a Type-4-bearing `/Separation` tint transform and
   tracing what reads object `+0x128`.
2. **`FUN_1804ee626` semantics, not shape.** This round proved it has no OOB *write* primitive of
   its own (one indexed write, in bounds). What was not done is checking whether it hands a
   **component count** downstream that disagrees with the base colour space — the `/Matte` and
   colour-key `/Mask` arrays are the candidates. Round 1 closed `ColorKeyMaskImagePipe`
   (`FUN_1803bc390`) and the LUT builder (`FUN_180505b15`) as internally consistent, so this is
   about whether this producer can violate the premise those proofs rely on.
3. **EBCOT.** `FUN_180902b8c` (53,671 B), `FUN_18090fd34` (19,386 B), `FUN_1808fe180` (18,955 B),
   `FUN_1808f9580` (18,870 B) — the generated JPEG 2000 coding-pass bodies. Four functions, ~110 KB,
   entirely unread by any round. Lowest density of validation logic per byte, but the highest raw
   volume of attacker-driven index arithmetic in the module.
4. **The JPX packet *header* parse proper** — tag trees, Lblock growth, coding-pass counts and
   code-block segment lengths, inside `FUN_18088b3c0` and `FUN_18088a218`. §9 audited the
   *iteration* around it (progression order, POC clamping, precinct and layer indexing) and that
   is clean; the bit-level header decode itself is still unread, and it is where every real-world
   JPEG 2000 RCE has lived. Highest-value remaining lead.
5. **`msPdfToEmfConverterMemorySafetyFix`** — a feature flag named after a memory-safety fix in the
   PDF->EMF print converter, still unexamined (round 10 noted it). Requires print, so user
   interaction caps severity.

## Tooling added

Under `/home/user/work/tools/` (regenerable, not committed):
`pc.py` (byte-offset index over the 90 MB pseudocode: `build` / `get` / `callers` / `callees` /
`info`), `rng.py` (functions in an address range by size), `tumap.py` (map a `__FILE__` string to
the functions that reference it, i.e. translation-unit recovery), `extract_range.py` (bulk
pseudocode extraction for grep-scale scanning), `whichfn.sh` (line -> enclosing function).

`tumap.py` is the reusable one: it recovered all 13 jp2k translation units and both ICC regions
from `__FILE__` xrefs, which is how the ICC engine was found at all.

## Honest status

No exploitable memory-corruption bug in round 11. Five surfaces that no prior round had touched
(the `t3::color` ICC engine, LZW, JBIG2 segment type 53, the two large undecompiled functions, and
the JPX packet-iteration/POC layer) are now read and clean, round 10's open CCITT question is
answered in the negative with proof, two real spec deviations were found and shown compensated at
their use sites, and one decompiler artifact that reads as a heap overflow was corrected against
machine code so it is not re-reported.

The module's pattern continues to hold across every new surface: checked add/multiply helpers that
trap rather than return, unsigned comparisons so wrapped values fail closed, allocation sizes and
loop bounds derived from the same variable, and cross-field consistency enforced at parse time
rather than at point of use.
