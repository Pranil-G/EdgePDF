# FINDING-005 — glyph-bitmap clone copies `pitch * rows` into a `width * rows` buffer (mspdf.dll)

| | |
|---|---|
| Module | `mspdf.dll` 154.0.4258.33 (Edge/WebView2 154.0.4258.53; SHA-256 `F21CC09C…1688`) |
| Component | `t3::fonts::parsers::FreeType` / `FTBitmapCache` — statically linked FreeType |
| Function | `sub_18018BCAB` (257 B), reached from `sub_18018BBD0` and `sub_18075BBE0` |
| Reached by | any embedded font in a PDF whose glyph is produced as, or rendered to, an `FT_Bitmap` |
| **Status** | **NOT exploitable in Edge as shipped.** The overflow is prevented solely by an *undocumented FreeType invariant* that the code never checks. Reported as a hardening / defence-in-depth defect. |
| Severity | Low (latent). Becomes an attacker-controlled heap overflow if any producer ever yields `FT_PIXEL_MODE_GRAY` with `pitch > width`. |

## The defect

`sub_18018BCAB` clones a glyph bitmap. It builds the destination from the source's **width and
rows**, then copies using the source's **pitch**:

```c
lVar5 = *param_1;                                  /* source FT_BitmapGlyph */
iVar1 = *(int *)(lVar5 + 0x30);                    /* src->bitmap.pitch     */
iVar4 = -iVar1; if (0 < iVar1) iVar4 = iVar1;      /* abs(pitch)            */

local_68 = *(int *)(lVar5 + 0x20);                 /* rect.xMin = left          */
local_64 = -*(int *)(lVar5 + 0x24);                /* rect.yMin = -top          */
local_60 = local_68 + *(int *)(lVar5 + 0x2c);      /* rect.xMax = left + width  */
local_5c = *(int *)(lVar5 + 0x28) - *(int *)(lVar5 + 0x24);  /* rect.yMax = rows - top */

lVar5 = FUN_18017B7BC(param_4, param_2, &local_68, param_3);   /* dst from that rect */
lVar2 = *local_30;
if (*(char *)(lVar2 + 0x42) != '\x02') { /* t5::corrupt_data */ }   /* GRAY only */

FUN_1809E1E60(*(undefined8 *)(lVar5 + 0x38),       /* dst->buffer */
              *(undefined8 *)(lVar2 + 0x38),       /* src->bitmap.buffer */
              iVar4 * *(int *)(lVar2 + 0x28));     /* abs(pitch) * rows  <-- LENGTH */
```

The destination is a tightly packed 8-bit surface — **one byte per pixel, no row padding**:

- `FUN_18017D5D4` stores the rect at `obj+0x20..0x2c`, then
  `obj+0x30 = FUN_18017D63C(rect)` and `obj+0x38 = alloc(FUN_180114C19(rect))`;
- `FUN_180114C19(rect)` = `(xMax-xMin) * (yMax-yMin)` = `width * rows` (0 when empty);
- `FUN_18017D63C(rect)` = `width * height + 0x40` via a checked multiply.

So **destination size = `width * rows`, copy length = `abs(pitch) * rows`**, and the function never
compares the two. Whenever `abs(pitch) > width` it writes `(abs(pitch) - width) * rows` bytes past
the end of the destination heap allocation, with content taken straight from the glyph bitmap.

## Why the structure is confirmed, not inferred

The source field offsets match **`FT_BitmapGlyphRec` compiled for Windows LLP64** exactly — on
Windows `FT_Pos`/`FT_Fixed`/`FT_Long` are 4 bytes, so `FT_GlyphRec` is 0x20, not 0x28:

| offset | field | corroboration |
|---|---|---|
| +0x10 | `root.format` | tested against `0x62697473` = `'bits'` in `sub_18018AFDC` |
| +0x20 | `left` | used as `rect.xMin` |
| +0x24 | `top` | negated for `rect.yMin` |
| +0x28 | `bitmap.rows` | `rect.yMax = rows - top` |
| +0x2c | `bitmap.width` | `rect.xMax = left + width` |
| +0x30 | `bitmap.pitch` | `abs()`-ed, i.e. FreeType's signed top-down/bottom-up pitch |
| +0x38 | `bitmap.buffer` | memcpy source |
| +0x42 | `bitmap.pixel_mode` | tested `== 2` = `FT_PIXEL_MODE_GRAY` |

`sub_1807C6DAD(&glyph, 0, 0, 0)` is `FT_Glyph_To_Bitmap(&glyph, FT_RENDER_MODE_NORMAL, NULL, 0)`.
The renderer registry confirms the module layout independently: at `.rdata` RVA `0xd0c4f0` the
`smooth` renderer class has `module_name -> "smooth"` at +0x08, `glyph_format = 'outl'` at +0x38 and
`render_glyph = sub_1808D0EE0` at +0x40 (`raster1` and `bsdf` match, the last with
`glyph_format = 'bits'`).

## Why it is not exploitable as shipped

The copy accepts **only** `FT_PIXEL_MODE_GRAY`, and every FreeType producer that yields GRAY sets
`pitch == width`. This was verified in mspdf's own statically linked copy, not from upstream
memory — `ft_glyphslot_preset_bitmap` is `sub_1807C4011` (called at the top of
`sub_1808D0EE0 = ft_smooth_render`), and its per-mode pitch is:

| render mode | `pixel_mode` written to slot+0x82 | `width` (slot+0x6c) | `pitch` (slot+0x70) |
|---|---|---|---|
| 2 `MONO` | 1 | w | `((w+15)>>3) & ~1` — **padded** |
| 3 `LCD` | 5 | w*3 | `(w*3+3) & ~3` — **padded** |
| 4 `LCD_V` | 6 | w | w |
| else (`NORMAL`/`LIGHT`) | **2 `GRAY`** | w | **w** |

The two padded cases are exactly the two that `sub_18018BCAB` rejects at `+0x42 != 2`. The
TrueType embedded-bitmap decoder agrees: bit depth 8 is the only one mapped to `GRAY`, and it sets
`pitch = width` (depths 1/2/4 map to `MONO`/`GRAY2`/`GRAY4`, depth 32 to `BGRA`).

So a mono embedded bitmap — the common case for `EBDT`/`pcf`/`bdf`/`winfonts`, all of which are
linked in — takes the `t5::corrupt_data` trap rather than the overflow.

## What would unlock it

Any of the following makes `abs(pitch) > width` reachable with `pixel_mode == GRAY`:

1. **`FT_Bitmap_Convert`** anywhere upstream. It sets `target->pitch = FT_PAD_CEIL(width, alignment)`
   and `pixel_mode = GRAY`; with the usual `alignment = 4`, a 5-pixel-wide glyph becomes
   `width = 5, pitch = 8`. mspdf does not call it on this path today precisely *because*
   `sub_18018BCAB` demands GRAY instead of converting — a conversion added to satisfy that demand
   would introduce the overflow.
2. A FreeType uprev that pads the GRAY pitch (FreeType documents pitch as *"the number of bytes
   taken by one bitmap row, **including padding**"*, so this is explicitly permitted).
3. Any new producer of GRAY bitmap glyphs: an `sbix`/`CBDT` 8-bit gray strike with row padding, or
   a first-party rasterizer feeding `FT_BitmapGlyph` into this helper.

## Suggested fix

One line. Either clamp the copy:

```c
rowBytes = min(abs(src->bitmap.pitch), (int)src->bitmap.width);
for (row = 0; row < rows; row++) memcpy(dst + row*width, src + row*pitch, rowBytes);
```

or reject the mismatch up front (`if (abs(pitch) != (int)width) throw t5::corrupt_data;`), which
matches the module's prevailing style — `sub_18018BCAB` already traps on an unexpected
`pixel_mode`, so trapping on an unexpected `pitch` is consistent and costs nothing.

## Note on reading this function from pseudocode

`FUN_18017B7BC`/`FUN_18017B7F5` lose arguments in Ghidra's output and `FUN_18017B7F5` is typed
`void` although it returns the new object in `rax`; the 0x40-byte object size and the
`alloc(width*rows)` both have to be read out of `FUN_18017D5D4` to see the mismatch. Reading only
the decompiled `sub_18018BCAB` makes the copy look self-consistent.
