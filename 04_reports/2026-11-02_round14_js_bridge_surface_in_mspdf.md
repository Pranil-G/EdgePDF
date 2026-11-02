# Round 14 — a JS↔document bridge **inside** `mspdf.dll` (corrects round 12/13)

**No finding yet. This records a correction, a newly opened surface, and a new tool.**

## 1. The correction

Round 12 and round 13 both concluded that `mspdf.dll` contains no JavaScript engine, so the
PDF-JS surface had to be audited in `msedge.dll` — behind the filtered-corpus wall. **That was
wrong, and it was a search error on my part.** I grepped two things:

- Acrobat API names (`setTimeOut`, `mailForm`, `submitForm`, `getField`, …) — these are the
  *scripting-language* identifiers, which live in the JS engine, not in the bridge;
- `*script*` / `*java*` under the **`t5\`** subtree only.

The bridge is in a different subtree. A full sweep of the 29 `__FILE__` paths in the binary
turns up:

```
..\msinternal\pdfcontrol\datamodel\dcpdf\js\js_document_impl.cc
..\msinternal\pdfcontrol\datamodel\dcpdf\js\dom_change_listener_impl.cc
..\msinternal\pdfcontrol\datamodel\dcpdf\js\thread_host_impl.cc
..\msinternal\pdfcontrol\datamodel\dcpdf\tile_cache\dcpdf_tile_cache_async_renderer.cc
..\msinternal\pdfcontrol\datamodel\dcpdf\tile_cache\dcpdf_tile_cache_handler.cc
..\msinternal\pdfcontrol\datamodel\dcpdf\dcpdf_parser_factory.cc
```

So the JS **engine** is indeed in `msedge.dll` (on a Blink isolate), but the JS→document
**bridge** is here, in the binary available in full. That matters: it is the half where
JS-driven mutation enters the document, which is where reentrancy and lifetime bugs live.

Method lesson, recorded in `tools/README.md`: enumerate *all* `__FILE__` paths in a binary
before concluding a component is absent. `strings -n 20 | grep dcpdf` is 29 lines and would
have settled it in one command.

## 2. The surface

Recovered with `tools/tumap.py` from `__FILE__` anchors; the component sits at roughly
`0x180147000`–`0x18014C000`.

| TU | anchors | what it is |
|---|---|---|
| `dom_change_listener_impl.cc` | `FUN_180148950` (455 B, line 0x25), `FUN_180148D60` (312 B) | emits **`field_modified`** and **`all_field_modified`** to JS |
| `js_document_impl.cc` | `FUN_18014A1A8` (353 B) | the `Doc` object JS calls into |
| `thread_host_impl.cc` | `FUN_18014A770` (351 B, line 0x1F) | **`post_to_background_thread_and_wait`** |
| `dcpdf_tile_cache_async_renderer.cc` | `FUN_18010D9B0`, `FUN_18010E540`, `FUN_18010E6B0` | async tile rendering |
| `dcpdf_tile_cache_handler.cc` | `FUN_180132400` (767 B) | tile cache |

### Why this is the fuzzer-blind surface

`field_modified` fires on form-field mutation. Field initialisation, `/AA` format and calculate
actions all run **on document open**, so this is zero-click. Reaching a bug here needs JS
executing and mutating the document at a specific point in another mutation — a byte-mutating
fuzzer has no JS at all, and a grammar-aware one still has to produce a semantically meaningful
mutation sequence.

`post_to_background_thread_and_wait` is the sharper one: the JS thread host posts work to a
background thread and blocks. Its shape (`FUN_18014A770`):

```c
plVar1 = *(longlong **)(param_1 + 8);          /* the task runner */
plVar4 = FUN_180109F08();                      /* DCPdfTaskCreatorImpl singleton */
... copy the callable out of param_2 ...
local_80 = FUN_180995400(0x28);                /* heap task payload */
*(undefined8 *)(local_80 + 8)    = local_48;   /* captured callable */
(**(code **)(*plVar4 + 8))(plVar4, local_50, 1, local_88);   /* create task, flag 1 */
(**(code **)(*plVar1 + 0x20))(plVar1, &local_40, local_60, local_50);  /* post + wait */
if ((code *)local_68[1] != (code *)0x0) (*(code *)local_68[1])(local_80);  /* destroy payload */
```

The payload is destroyed **after** the post-and-wait returns, which is correct only if the wait
genuinely guarantees the background task is finished. An early return — timeout, cancellation,
or the event being signalled by anything else — leaves the background thread holding
`local_80`. That is the bug shape to chase, and it is a cross-thread lifetime question no file
fuzzer can express.

## 3. Where it stalled

The wait is `(**(code **)(*plVar1 + 0x20))(...)` on the runner at `thread_host->+0x08`, whose
concrete type is not reachable from these anchors. `FUN_180A97B7C`, which looked like the wait,
is not — it is the shared task status/error-propagation idiom, the same one the DOM listener
uses:

```c
state  = (**(code **)(*task + 0x10))();   /* status getter */
status = (**(code **)(*state + 8))(state);
if (status == 2) (**(code **)(*task + 0x20))(task);   /* propagate */
```

I resolved the task chain concretely —
`DCPdfTaskCreatorImpl::vftable` (`0x180AF2DD8`, only 2 virtuals) → slot 1 `FUN_180109FF0`
→ a 0x50-byte task built by `FUN_1805A2CE4` → vtable `0x180B068F0` — but the slots that matter
(`+0x10`, `+0x20`, `+0x28`) are **ICF-folded trivial accessors** (`return *(uint32 *)(this+8)`,
a deleting-destructor forwarder, `operator delete(p, 0x20)`) shared across every class of that
shape, so they identify nothing. Resolving the runner needs the thread host's constructor, which
these anchors do not reach.

Incidentally: `FUN_180109FF0` allocates `0x18` bytes, constructs it with tag 7, then overwrites
the pointer with its second allocation — the first object leaks unless `FUN_18010A104` registers
it elsewhere. A leak, not a security bug, but worth noting.

## 4. New tool — `tools/vt.py`

An RTTI vtable resolver, for breaking virtual-dispatch walls:

```
vt.py <vtable-VA> [slots]   # slot index, offset, target VA, owning function + size
vt.py --find <regex>        # search the 429k-row symbol index for vftable symbols
```

Caveat learned here: **identical COMDAT folding makes trivial slots useless for type
identification.** A 4–5 byte getter body is shared across unrelated classes. The tool is
informative for substantial slots and misleading for stubs.

## 5. Next

Two live targets, both in code available in full:

1. **`FUN_18014B70E`** (4,042 bytes) — turned out *not* to be JS. It contains
   `"adbe.pkcs7.detached"`, so it is the **digital-signature** driver. Combined with what round
   12 found in this binary (`asn1c::ParseSignedData`, a bespoke `pdf_signature::PKCS1::ParseSignature`,
   statically linked BoringSSL), that is a large, niche, first-party CMS/X.509 parser that runs
   on open for signed PDFs. Not structurally fuzzer-proof, but signature paths are commonly
   stubbed or unreached in harnesses because they need a well-formed signature to get past the
   early checks.
2. **The thread-host runner**, via the `thread_host_impl.cc` constructor, to settle §2's
   cross-thread lifetime question.
