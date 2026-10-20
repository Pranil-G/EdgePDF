# PDF URL loader — multipart short-read / negative byte count lead

**Verdict: cannot validate from this corpus. The precondition is verifiably present; the scan
itself sits in a coverage gap. The main downstream consumer is hardened against a negative
count, so the lead's value hinges on one specific question stated in §4.**

Corpus: `edge_glue_154.0.4258.53` — a **PDB-symbol-filtered** disassembly of `msedge.dll`
(4,352 named functions). `msedge.dll` itself is not in the corpus; only `mspdf.dll` is.
RVAs below are Edge 154.0.4258.53 and will have moved in 155+.

## 1. The precondition is present and confirmed

`edge_pdf::URLLoaderWrapperImpl::ReadResponseBody` (`0x838D8C0`) stores the caller's buffer
span into the object as two fields:

```
0838d907  mov  r14, qword ptr [r14 + 8]      ; span.size
0838d923  mov  qword ptr [rdi + 0x70], rbx   ; this->buffer     = span.ptr
0838d927  mov  qword ptr [rdi + 0x78], r14   ; this->buffer_cap = span.size
```

`edge_pdf::URLLoaderWrapperImpl::ReadResponseBodyImpl` (`0x838DA00`) then hands **that stored
capacity** — not any received count — to the inner loader:

```
0838dabc  mov  rax, qword ptr [rdi + 0x70]   ; ptr
0838dac5  mov  qword ptr [rdx], rax
0838dac8  mov  rax, qword ptr [rdi + 0x78]   ; capacity
0838dacc  mov  qword ptr [rdx + 8], rax
0838dad0  mov  rax, qword ptr [rbx]          ; inner loader vtable  (rbx = this->+0x08)
0838dad3  mov  rax, qword ptr [rax + 0x18]   ; slot 3
0838dada  call qword ptr [rip + 0xb5e9fa8]   ; CFG-guarded dispatch
```

So the requested capacity is live in the object and is exactly the value a later scan would
reach for. Both plumbing layers also carry the count as a **signed 32-bit int**, which is the
necessary condition for a negative to propagate rather than be rejected by an unsigned type:

- the callback type is literally `base::OnceCallback<void(int)>` (from the demangled
  `ReadResponseBodyImpl` signature);
- host side, `edge_pdf::pdf_host::UrlLoaderWrapperHelper::ReadResponseBody` (`0x8878DCA`) does
  `0x8878E28: movsxd r14, ebp` then `0x8878E33: mov dword ptr [rbx + 0x48], r14d` — the
  requested count sign-extended and stored as an int.

## 2. The scan is not in the corpus

Both layers are pure plumbing; the read completion and any multipart processing live in
unnamed `base::BindOnce` state/invoker thunks, which were never selected because they have no
PDB name:

| side | registration | invoke target | corpus coverage |
|---|---|---|---|
| renderer | `0x838DA87: lea rax, [rip + 0x92]` | **`0x838DB20`** | corpus jumps `0x838DA00` → `0x838ED40`; **~4.6 KB missing** |
| host | `0x8878E96: lea rax, [rip + 0x103]` | **`0x8878FA0`** | falls in the `0x8878F9E` → `0x88790DE` gap |

(For contrast, `ReadResponseBody`'s own BindState invoke target resolves to
`0x838DA87 + 7 + 0x90 = 0x838DA00` = `ReadResponseBodyImpl`, i.e. the task that performs the
read — which is how the chain was traced.)

Nothing else in the 4,352-symbol set holds a per-read multipart boundary scan.
`UrlLoaderWrapperHelper::GetPdfStreamHeader` (`0x8878BC4`) and `PdfStreamHeaderImpl`'s
`IsMultipart` / `GetByteRangeStart` / `GetStatusCode` / `IsAcceptRangesBytes` parse the
*response* header once at open time, not the per-read body.

## 3. The main consumer is hardened against a negative count

This part **is** in the corpus, and it matters for triage. The downloaded-range accumulator is
`chrome_pdf`-style `ChunkStream` with a 0x10000 chunk size.

`ChunkStream::IsRangeAvailable` (`0x8449BBE`):

```
08449bd9  mov  edx, dword ptr [rdx]       ; range.start
08449bdb  mov  ecx, dword ptr [rdi + 4]   ; range.end
08449be0  and  eax, ecx
08449be2  cmp  eax, -1
08449be5  sete al                         ; invalid sentinel: (start & end) == -1
08449be8  cmp  edx, ecx
08449bea  seta r8b                        ; start > end          [UNSIGNED]
08449bee  or   r8b, al
08449bf1  jne  0x188449c06                ; -> return false
08449bf3  mov  eax, dword ptr [rsi + 0x18]; document size
08449bfc  cmp  eax, ecx
08449bfe  setb al                         ; size < end           [UNSIGNED]
08449c04  je   0x188449c23                ; else -> return false
```

Three independent closes: an explicit `(start & end) == -1` invalid sentinel, and **unsigned**
`start > end` and `size < end` comparisons. A negative count widened into a range becomes a
huge unsigned value and is rejected whichever field it lands in.

`ChunkStream::ReadData` (`0x844B5A6`) gates on that call first
(`0844B5BF: call 0x188449BBE` / `test al, al` / `je` out), then independently bounds the chunk
index against the chunk vector (`0844B5F9: cmp qword ptr [rbx + 8], rbp` / `jbe` out), and
derives its `memcpy` length as `min` of two chunk-size-bounded values via `cmovb`.

So a negative byte count that reaches the range/chunk layer **fails closed**.

## 4. The one question that decides whether this is worth pursuing

Does the negative get used as a **length** before it is converted into a range?

Upstream Chromium's equivalent does, in `DidRead`, after locating the multipart header: it
shifts the body down with a `memmove` whose length is derived from `result`. A negative there
is an immediate `size_t` catastrophe, and that code is precisely what lies at `0x838DB20`.

- **If** the completion handler computes `scan_len - header_offset` from the *capacity* and
  feeds it to `memmove`/`memcpy` or to `SetChunkData` as a length → real bug, likely critical.
- **If** the negative only ever becomes a `gfx::Range` → §3 eats it, and the lead is moot.

## 5. What is needed

`msedge.dll` for the build under test. The corpus ships `build_edge_glue_assembly.py` (driven
by `edge_pdf_publics_full_154.0.4258.53.json`) to regenerate the glue assembly, but it needs
the binary. A disassembly of just the two ranges would also do:

- renderer: `0x838DB20` for ~0x400 bytes
- host: `0x8878FA0` for ~0x140 bytes

At a debugger, the specific thing to look for at `0x838DB20`:

1. **Where the scan length comes from.** `[this + 0x78]` (the stored capacity) is the bug;
   the callback's `int` argument — arriving in `edx`/`esi` per the BindState invoker — is
   correct.
2. **Whether the result is sign-checked.** Upstream's `if (result < 0)` lowers to a
   `test`/`js` or `cmp …, 0` / `jl` near the top of the handler. Its absence is the finding.
3. **Whether a subtraction of a found header offset feeds a length** without a `>= 0` or
   `<= result` bound. That is the exploitable form.
