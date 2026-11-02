# Round 13 — unvalidated `/T` in the linearization dictionary yields a negative range start

| | |
|---|---|
| Module | `mspdf.dll` 154.0.4258.33, `FUN_1805C04BD` (the `/Linearized` dictionary handler) |
| Reached by | a **linearized** PDF — zero-click, no interaction. The linearization dict is the document's first object, so this runs during initial load. |
| Class | unvalidated signed offset + unchecked length handed to the document data source's range/prefetch entry point |
| **Status** | **Lead with the arithmetic verified in machine code.** Whether it is a bug depends on one unresolved question (§5). |

## 1. Why this surface

The brief was something remotely reachable with no interaction that a fuzzer structurally
cannot reach. Two candidates were considered and one was dropped:

- **PDF JavaScript** (`edge_pdf::js_host`) is the ideal fuzzer blind spot — it needs
  semantically valid JS calling specific host methods in order, which byte mutation will never
  produce. But `mspdf.dll` contains **no JS engine**: it parses the keys (`JavaScript`, `JS`,
  `AA`, `OpenAction`, `AcroForm`, `XFA`) and hands them off, and zero `*script*`/`*java*`
  source paths appear in the `dcpdf/t5` tree. The engine lives in `msedge.dll` on a Blink
  isolate (`PdfUtilityInstance::GetScopedBlinkIsolate`), i.e. behind the same filtered-corpus
  wall that stopped the URL-loader lead. What *is* visible there is well built:
  `js_host::VClient::ClientProxy::Access` (`0x887DC2C`) does **three** liveness checks and
  holds a scoped strong reference across the callback invoke, and `PdfJSMemoryHost::Malloc`
  / `Free` are thin wrappers with no arithmetic.
- **Linearized / progressive loading** is in `mspdf.dll` in full, and is the one PDF path whose
  inputs a file-based harness cannot vary (§4).

## 2. The code

`FUN_1805C04BD` (1,482 bytes), sole caller `FUN_1805B2D48`, which stores the boolean result at
`doc->+0xA1`. Key names were read out of `.rdata` rather than assumed:
`0x180B3184C` = `"L"`, `0x180B31CAC` = `"T"`, `0x180B357F4` = `"E"`.

Flow:

```c
/* 1. first object must be a dict carrying /Linearized, version 1.0 <= v < 2.0 */
uVar15 = L + doc->base;                       /* declared length   */
uVar16 = (**(code **)(*stream + 0x18))();     /* data source size, vtable slot 3 */
if (uVar16 < uVar15) return 0;                /* declared > available -> not linearized */

if ((uVar15 < uVar16) || (doc->+0xA0 != 0)) { /* MISMATCH path: declared < available */
    T = lookup("T");                          /* type-checked only, never range-checked */
    ...
} else {
    /* exact match: read "endobj", take stream->+0x78 */
}
```

The `/T` read checks only the object *type* — `9` (bignum) or `2` (integer), anything else
takes `FUN_180229D40` — and then uses the value directly. Machine code:

```
1805c0867: movsxd r14, dword ptr [rax + 0x8]   ; T from an int32, SIGN-EXTENDED
     - or -
1805c0871: mov    r14, qword ptr [rax]         ; T from a 64-bit bignum

1805c0886: add  r14, -0x32                     ; start  = T - 50
1805c088a: lea  rdx, [rbp + 0x58]
1805c088e: mov  qword ptr [rdx], r14           ; range.start  = start
1805c089a: sub  r15, r14                       ; length = available_size - start
1805c089d: mov  r8, rbp
1805c08a0: mov  qword ptr [r8], r15            ; range.length = length
1805c08a7: call 0x1807de040                    ; construct the out-parameter
1805c08ad: mov  rcx, qword ptr [rsi + 0x10]    ; doc->data_source
1805c08b1: mov  rax, qword ptr [rcx]
1805c08b4: mov  rax, qword ptr [rax + 0x20]    ; vtable slot 4
1805c08c0: call qword ptr [rip + 0x76638a]     ; CFG dispatch -> ranged read / ensure-range
```

**There is no instruction between the subtraction and the call that compares `start` against
`length`, against the size, or against zero.** The two stores and the call follow immediately.

## 3. What the call is for

The result is thrown away three instructions later:

```
1805c08c7: mov  rcx, qword ptr [rbp + 0x30]
1805c08d8: call 0x18002c914                   ; destroy the object just produced
1805c08dd: movapd xmmword ptr [rdx], xmm0      ; zero the slot
1805c08e9: mov  r8d, 0x400
1805c08f2: call 0x1805b211e                   ; the real work
```

`FUN_1805B211E` independently scans back from the data source's size for `"%%EOF"` and then
`"startxref"` within a `0x400` window. So the slot-`+0x20` call is a **prefetch / ensure-range**
on the data source — "make `[T-50, EOF)` resident, I am about to scan there". Prefetch paths
are exactly where range validation tends to be skipped on the assumption that the later real
read will validate.

## 4. Attacker control, and the fuzzer-invisible axis

`/T` is unconstrained, so:

| `/T` | `start = T - 50` | `length = available - start` |
|---|---|---|
| `0` | **−50** | `available + 50` — longer than the stream |
| `-1000` | **−1050** | `available + 1050` |
| `0x7FFFFFFF` | `0x7FFFFFCD` | **underflows** to ~2^64 |

Being honest about the fuzzer claim: the *path* is reachable from a static file — set `/L`
smaller than the file and the mismatch branch runs — so a structure-aware PDF fuzzer carrying
a linearization grammar could reach it. A plain byte-mutation fuzzer is unlikely to, because it
must keep the first object a well-formed linearization dict (`/Linearized` present, version in
`[1.0, 2.0)`, `/L` an integer that passes the `<=` gate) while driving `/T` out of range.

The axis **no file-based harness can explore** is the second operand: `uVar16` is the data
source's *currently available* size, not the final file size. Under progressive HTTP loading an
attacker who controls delivery chooses, independently of `/T`, both whether the mismatch branch
is taken at all (`L + base < available`) and what `length` comes out. A file fuzzer holds that
value fixed at "the whole file" and so only ever samples one point of a two-dimensional space.
This is the same structural blind spot behind the two earlier leads this session (the
`JP2KDecDataMgr` short-read contract and the multipart loader).

## 5. The open question

Does the data source's vtable slot `+0x20` validate the range?

Resolving it needs the concrete class behind `doc->+0x10`, which was not pinned down:
`FUN_1805BE4B0` is just `&doc->+0x10`, there are 8 sibling call sites of slot `+0x20` and 45 of
the slot `+0x18` size accessor, and an RTTI sweep of the corpus's 429k symbol rows surfaced the
boost/iostreams plumbing and `edge_pdf::datamodel::DCPdfDocumentHandlerImpl::ReadPdfStreamBytes`
/ `ReadPdfStreamBytesInBlocks` (so the source bridges back to the Edge glue) but not the
concrete implementation.

Two outcomes:

- **If slot `+0x20` clamps** — likely for an in-memory/mapped source that checks against its own
  extent — this is a correctness wart, not a bug, and the honest answer is that it is dead.
- **If it does not** — a negative start means pointer arithmetic below the buffer base for a
  mapped source, or a bogus `Range:` header / huge length for the HTTP source.

## 6. PoC recipe, ready to run against a debugger

A breakpoint at `0x1805C0886` with `/T` logged settles reachability in one load; a breakpoint on
the slot-`+0x20` target settles §5.

1. First object a linearization dict: `<< /Linearized 1.0 /L <small> /T 0 /E .. /O .. /N .. /H [..] >>`.
2. `/L` **strictly less** than the served size, so `L + base < available` and the mismatch
   branch is taken. (`L + base > available` is rejected by the earlier gate.)
3. `/T 0` → `start = -50`, `length = available + 50`.
4. Serve over HTTP with `Accept-Ranges: bytes` so Edge takes the progressive path; to exercise
   the fuzzer-invisible axis, withhold the tail so `available` is attacker-chosen at the moment
   the dict is parsed.

`tools/gen_finding006.py` already emits a minimal `/JPXDecode` PDF and can supply the container;
only the first object and the xref offsets need replacing.
