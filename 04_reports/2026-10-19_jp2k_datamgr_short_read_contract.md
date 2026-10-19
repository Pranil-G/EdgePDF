# JP2KDecDataMgr refill contract — short-read success path

**Verdict: the reported contract mismatch is real and machine-code confirmed. It is not a
memory-safety bug, for a structural reason, and it is below a critical bar. Worth reporting as
a correctness/robustness defect; not worth chaining.**

Module `mspdf.dll` 154.0.4258.33, TU `…\dcpdf\t5\firstparty\jp2k\source\dec\src\JP2KDecDataMgr.cpp`.

## The buffer object

`FUN_1808F3EC2(buf, n)` is `ensure at least n bytes buffered`; returns 0 on success, non-zero
otherwise. Field map recovered from its callers and accessors:

| offset | type | meaning |
|---|---|---|
| `+0x00` | int | hard cap on a single request (`*buf < n` → return 5) |
| `+0x04` | int | **capacity** — size of the current allocation |
| `+0x08` | byte | external / non-owning buffer mode |
| `+0x09` | byte | sticky short/EOF flag |
| `+0x10` | `void*` | buffer base |
| `+0x18` | `byte*` | `cur` — read cursor |
| `+0x20` | `byte*` | `end` — end of valid data |
| `+0x28` | byte | last byte read |
| `+0x2c` | int | bytes-consumed counter |
| `+0x30` | `void*` | source object; read = vtable slot `+0x10`, EOF probe = slot `+0x30` |

The source read `FUN_18089930C` is a virtual call returning an int where `>= 0` is a byte count,
so **short reads are part of the source contract**.

## The four refill paths, and which one is wrong

| path | short-read handling | correct? |
|---|---|---|
| already-enough, in place | `if (n <= end - cur) return 0; else { +0x09 = 1; return -1; }` | yes |
| grow via realloc (`0x1808F40A5`) | `if (bytes_read < shortfall) { +0x09 = 1; return -1; }` | yes |
| realloc to cap (`0x1808F40B8`) | `+0x09 = (bytes_read < shortfall)` — records the shortfall | yes |
| **compact-and-refill (`0x1808F4027`)** | **`if (bytes_read < 1 && capacity != available) fail` — nothing else** | **no** |

The bad path in machine code:

```
1808f402a: cmp  edi, edx                     ; requested vs capacity
1808f402c: jg   0x1808f40a5                  ; larger -> the grow paths
...
1808f406f: mov  qword ptr [rsi + 0x18], rdx  ; cur = base   (compaction)
1808f407e: mov  r8d, dword ptr [rsi + 0x4]
1808f4082: sub  r8d, r12d                    ; n = capacity - available
1808f4085: call 0x18089930c                  ; bytes_read = read(src, end, n)
1808f408a: test eax, eax
1808f408c: jle  0x1808f4099                  ; <= 0 only
1808f4090: add  qword ptr [rsi + 0x20], rax  ; end += bytes_read
1808f4094: jmp  0x1808f3f90                  ; -> return 0 = SUCCESS
1808f4099: cmp  dword ptr [rsi + 0x4], r12d  ; capacity == available ?
1808f409d: jne  0x1808f4019                  ; no -> +0x09 = 1, return -1
```

`edi` (the requested count) is never compared against `available + bytes_read`, and `+0x09` is
never set. This is the **only** path that can return success with `end - cur < n` *and* leave
`+0x09` clear — and `+0x09` is exactly the flag the per-byte getter relies on:

```c
FUN_1808F447C(buf, &flag) {
  if (buf->+0x08 || buf->end <= buf->cur) FUN_1808F3EC2(buf, buf->capacity);
  if (buf->+0x09 == 1 && buf->end <= buf->cur) { *flag = 1; return 0xFF; }   /* defeated */
  return *buf->cur++;
}
```

## Why it is still not memory-unsafe

`FUN_1808F4580` (multi-byte read) goes through that getter, which refills whenever
`cur >= end`. After a short success the next refill finds `available == 0`, takes the
`bytes_read < 1` arm, sets `+0x09` and returns -1 — so the getter fails closed one call later
and never dereferences past `end`.

The exposed consumers are the ones that bypass the getter:

- `FUN_1808F4602(buf, idx)` is a bare `return cur[idx]` — no check, no refill. The codestream
  marker loop does `ensure(4)` then `cur[0]`, `cur[1]`.
- 16 raw `*cur++` dereference sites, 14 in `FUN_180895CE2` and 2 in `FUN_18091503D` (the `COC`
  explicit-precinct loop among them).

Both read stale bytes, but **inside the allocation**, because of three facts that hold together:

1. the bad path runs only when `requested <= capacity` (`cmp edi, edx / jg`);
2. it compacts `cur` to `base` and fills toward `base + capacity`;
3. `capacity` is only ever written as the realloc'd size (`param_1[1] = iVar12` after
   `FUN_180885BEB(base, old, new)`) or as `available + bytes_read` — so `capacity <= allocation`.

So every byte a trusting consumer can reach lies in `[base, base + capacity)`.

*(A grep hit suggesting a third capacity write in `FUN_1808F3C8C` is a false positive — that
function's `param_1` is the tile-part index table, not the buffer. `FUN_1808F3C8C` is the
tile-part index builder.)*

## Actual impact

**Use of stale or uninitialized memory (CWE-908) plus parser desync**, not an OOB access:

- after a compaction, `[end, base+capacity)` holds already-consumed codestream bytes —
  attacker-authored, but surfacing at the wrong parse offset;
- on a freshly allocated buffer it is uninitialized pool memory;
- the forged bytes become marker codes and marker-segment fields, all of which still pass
  through the parser's own range checks (`L < 0x21`, `xcb < 0xb`, `xcb + ycb < 0xd`,
  `Lcoc` in `[9,43]`, …).

**Reachability requires a *positive* short read.** At true EOF the source returns 0, the
`jle` fires and the path fails closed. So it needs a genuinely incremental source — which Edge
has (progressive PDF load: `edge_pdf::pdf_host::ContentPdfStreamImpl`, `HttpOperation`,
`ReadResponseBodyOperation`, `PdfUtilityInstance::TransferPdfStream`/`FinalizePdfStream`).
Inducible by controlling HTTP delivery boundaries, but **racy** — it depends on a specific
chunk boundary landing inside a specific `ensure()`.

## The corroborating detail worth putting in a report

The binary contains **18** independent `(end - cur) < requested → error` re-checks that
compensate for exactly this defect. **All 18 are in `FUN_180895CE2`** (`JP2KFileFormat.cpp`,
the JP2 box parser), covering 18 of its 24 `ensure()` sites — e.g.

```c
iVar12 = FUN_1808F3EC2(param_2, uVar13);
if ((iVar12 != 0) ||
    ((uint)(*(int *)(param_2 + 0x20) - *(int *)(param_2 + 0x18)) < uVar13)) goto error;
```

Every other consumer trusts the return value alone: `FUN_18091503D` (codestream marker parser,
11 sites), the `FUN_180914*` per-marker helpers (~12), `FUN_1808877AE` (code-block decode
driver, 3), `FUN_18088B3C0`, `FUN_1808874AD`, `FUN_180891AE4`, `FUN_180898668`,
`FUN_180898AB1`, `FUN_1808F4774`, `FUN_1808F46AC`.

So the unreliability of this contract was known to whoever wrote the box parser and did not
propagate to the codestream parser. That is a good argument for fixing it at the source even
though the current consequence is not critical.

## What would upgrade it

1. A write to `+0x04` that can exceed the allocation. None exists in the refill logic; the
   object's actual constructor was not located and is the one place left to check.
2. A consumer whose read index or loop count is not bounded by its own `ensure()` argument
   *and* can exceed `capacity - cur_offset`. Checked: peek indices are constants 0–10, and the
   raw loops are bounded by marker lengths (≤ 0xC6) against a capacity of at least 0x400
   (forced by the parser's entry `FUN_1808F3EC2(buf, 0x400)`).
3. The `+0x08` external-buffer mode, which routes through `FUN_1808F42AA` and skips this path
   entirely — its own short-read handling is unaudited.

Item 1 is the load-bearing invariant; if it breaks, the same path becomes a true OOB read.
