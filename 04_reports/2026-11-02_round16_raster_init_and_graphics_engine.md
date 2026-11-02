# Round 16 — raster buffer initialization and the graphics rendering engine

Audit of `mspdf.dll` 154.0.4258.33's rasterization path. **Two concrete results, neither a
confirmed bug yet**: an unchecked 32-bit product in the per-tile raster allocation that deviates
from the module's own house style, and a raster-clear flag that 10 of 13 call sites pass as
false. The specific remaining question is stated in §5.

## 1. The engine

Recovered via RTTI (`tools/vt.py --find`). The graphics engine is **`t3::imaging_model`**:

| class | role |
|---|---|
| `t3::imaging_model::SuperSamplingBezierRasterPainter<OverscanBezierSamplerDef<…>>` | the rasterizer |
| `t3::imaging_model::SurfaceEncoder<t5::pdf::pdf_detail::surface_traits_bgra, …>` | BGRA surface encoding (3 instantiations) |
| `t3::imaging_model::ByteSignalTraits` / `DoubleSignalTraits` | 8-bit and double signal paths |
| `t5::tile_cache::tile_cache<t5::pdf::pdf_detail::tc_client<…TileCacheClient>>` | the tile cache |
| `t5::tile_cache::tile_cache_detail::bitmap_pool_impl<…BitmapFactory>` | **a bitmap pool** |
| `t5::tile_cache::tile_cache_detail::tracked_bitmap_impl<…BitmapFactory>` | pooled bitmap handle |
| `t5::pdf::content::image_tile` + `image_tile_cache` | a second, image-level tile cache |

The component occupies roughly `0x18010C000`–`0x18013A000`, which matches the
`dcpdf_tile_cache_async_renderer.cc` / `dcpdf_tile_cache_handler.cc` `__FILE__` anchors from
round 14.

## 2. The per-tile raster allocation — an unchecked product

`FUN_18011EACA(out, rect)` (178 B, single caller) builds a BGRA raster from a rect:

```c
width  = checked_sub(rect[2], rect[0]);      /* FUN_1800DE4B9 */
height = checked_sub(rect[3], rect[1]);
out->data   = operator_new(width * height * 4);
out->+0x08  = rect[0];                        /* x0 */
out->+0x0c  = rect[2];                        /* x1 */
out->+0x10  = data;
out->+0x18  = checked_sub(rect[2], rect[0]) << 2;   /* stride = width * 4 */
```

`FUN_1800DE4B9` is one of the module's **trapping checked-arithmetic helpers** — it performs the
standard signed-subtraction overflow test and throws on mismatch:

```c
if ((((int)a >> 31) - ((int)b >> 31)) - (uint)(a < b) == (int)(a - b) >> 31) return;  /* ok */
FUN_180A0AF8C(...); FUN_180996BA0(..., &DAT_180d36be0);  /* overflow -> throw */
```

So both **dimensions** are overflow-checked. The **product is not**, verified in machine code:

```
18011eb00: call 0x1800de4b9     ; checked sub -> width
18011eb18: call 0x1800de4b9     ; checked sub -> height
18011eb1d: imul eax, r14d       ; bare 32-bit signed multiply — no jo, no seto, no helper
18011eb21: shl  eax, 0x2        ; bare x4
18011eb24: movsxd rcx, eax      ; sign-extend the 32-bit result to 64
18011eb2d: call 0x18002c0e9     ; operator new
```

A wrapped product gives a small or zero allocation while `stride = width * 4` is stored
separately, so the consumer would write `height` rows of `stride` bytes into an undersized
buffer. A product that wraps negative instead sign-extends to an enormous size and fails closed
via `std::bad_alloc`.

**Reachability: currently closed, by geometry rather than by validation.** The single caller
`FUN_18011CF0A` passes the **intersection** of the tile rect with a clip rect, and skips the
allocation entirely when the intersection is empty:

```c
iVar13 = max(x0_tile, x0_clip);  iVar17 = min(y1_tile, y1_clip);   /* … intersect … */
if ((iVar13 <= iVar12) || (iVar17 <= iVar10)) goto LAB_18011d538;  /* empty -> no alloc */
FUN_18011EACA(&local_98);
```

An intersection is never larger than the smaller input, so the dimensions are bounded by the
tile grid. At any plausible tile size the 32-bit product cannot wrap.

**Assessment: a latent hazard, not a bug.** It is worth reporting as a hardening item precisely
because the same 178-byte function uses the checked helper twice and then drops it for the
multiply — the module's own idiom says this product should be checked, and the only thing
keeping it safe is an invariant maintained two frames up.

## 3. Raster initialization is opt-in, and usually off

`FUN_180118954(out, rect, ctx, bool clear)` is the surface factory. It copies the 4-int rect,
dispatches to one of three builders on `ctx->+0x1c`, and then clears **only if asked**:

```c
if (*(int *)(param_3 + 0x1c) == 1)      FUN_180118EA6(...);
else if (*(int *)(param_3 + 0x1c) == 0) FUN_1801189C6(...);
else                                     FUN_180119484(...);
if (param_4 != '\0')
    FUN_1809E2510(*(undefined8 *)(param_1 + 4), 0, *(undefined8 *)(param_1 + 8));
```

`param_1` is `undefined4 *`, so that is `memset(surface->+0x10, 0, surface->+0x20)` — the pixel
buffer and its byte size. (`FUN_1809E2510` is the AVX memset.)

Reached through the forwarder `FUN_1801183EC`, which sets only `rcx` and a stack argument and
passes `rdx`/`r8`/`r9` straight through. Across its **13 call sites**, the clear flag is:

| flag | sites | addresses |
|---|---|---|
| `xor r9d, r9d` → **false** | **10** | `0x180117932`, `0x1802D102C`, `0x1805A0870`, `0x1806726C5`, `0x18067644A`, `0x1806773E2`, `0x1806781E6`, `0x18067E81C`, `0x180688F61`, `0x1806A57C8` |
| `mov r9b, 0x1` → true | 1 | `0x18068804E` |
| `mov r9b, [mem]` → runtime | 2 | `0x1802BE81B` (`[rdi]`), `0x18068464A` (`[r14]`) |

Two of the ten false sites issue their own memset immediately beforehand
(`0x180117911` and `0x1805A084C` both `call 0x1809E2510`), so for those the flag is false to
avoid a double clear — deliberate and correct.

That leaves **eight sites that create a pixel buffer with no zero-fill and no adjacent clear**.
`clear = false` is the right choice whenever the renderer is about to paint every pixel of the
surface, which is the normal case for an opaque page background. It is only a defect where a
path creates an uncleared surface and then paints *partially*, leaving `operator new` memory
visible in rendered output.

The two runtime-flag sites are themselves forwarders — both dereference a caller-supplied
`bool *` (`mov r9b, byte ptr [rdi]` after `rdi = r9`; likewise `[r14]`) — so the decision is
made further up, in the renderer entry points.

## 4. Why this class matters here

This is an **information-disclosure** shape, not memory corruption: uninitialized heap, or a
recycled tile's previous contents, rendered into visible pixels. The `bitmap_pool_impl` in §1
raises the stakes, because a pooled buffer's prior contents are a *previously rendered tile*,
potentially from another page or another document in the same renderer process, rather than
merely unpredictable heap.

It is also zero-click and needs no exotic input — just a PDF whose painting leaves part of a
tile untouched.

## 5. The specific open question

For each of the eight uncleared sites, does the subsequent paint sequence cover the full
surface? Concretely, for a tile whose content does not cover it — a page with a transparent or
undefined region, a clip that excludes part of the tile, or a draw that fails partway — are the
uncovered pixels written by a background fill, or left as returned by `operator new`?

Two things settle it, both reachable in `mspdf.dll`:

1. **The pool acquire path.** `bitmap_pool_impl`'s acquire/recycle: if a pooled bitmap is
   returned to a caller that then passes `clear = false`, the previous tile's pixels are the
   starting state. The pool's control-block vtable is at `0x180AF3258`; its methods sit near
   `0x180133180`–`0x180138FC0`.
2. **The two runtime-flag callers** — who computes the `bool` that `FUN_1802BE7E5` and
   `FUN_18068460A` dereference. A data-dependent "should I clear" decision is the most likely
   place for an attacker-influenced input to select the uncleared path.

## 6. Method note

`FUN_18002C0E9` is `operator new` (calls `FUN_18002C15B`, throws `std::bad_alloc` with the
literal `"bad allocation"` on null). `FUN_1809E2510` is the AVX memset. `FUN_1800DE4B9` is the
trapping checked subtraction. All three are worth remembering — they appear throughout the
module and Ghidra drops their arguments, so call sites must be read in disassembly to recover
sizes and flags. That is how both findings in this round were established.
