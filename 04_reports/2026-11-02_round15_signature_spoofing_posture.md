# Round 15 — signature-spoofing posture (a non-memory-safety hunt)

**Class: signature forgery / shadow attacks — document integrity, not memory corruption.**
Zero-click (validation runs on open for signed PDFs), high impact for signed contracts and
invoices, and completely outside what a fuzzer can express: the question is not "does it crash"
but "does it say *valid* for a document the signer never saw".

**Result: mostly a negative. Edge's defences here are deliberate and non-trivial.** One concrete
gap is named in §5 with the specific next step. Recorded so this area is not re-hunted blindly.

## 1. Why the obvious attack does not work

Round 14 established that `/ByteRange` is collected with only non-negativity checks
(`FUN_180647B78`), folded to `max_end = max(offset + length) - 1` (`FUN_180666600`), and gated
by `FUN_180648F16` with `if (max_end < extent)`.

A `<` bound on the *top* of the signed region says nothing about **coverage** — bytes after
`max_end`, and bytes in gaps between the declared ranges, are unsigned. That is the
incremental-save / shadow-attack primitive, and it looked open.

**It is not.** `FUN_180648F16` passes `max_end` into `FUN_18064EF36`, which runs two further
checks, and a third mechanism parses `/DocMDP`.

## 2. `/XFA` is refused outright

`FUN_18064EF36` resolves `/AcroForm`, looks up `"XFA"`, and on a non-zero result raises
`t5::unimplemented`:

```c
FUN_18003C514(&local_68, "AcroForm", local_88);
FUN_1800B56A4(local_d8, local_d8 + 4, &local_68);
if (local_98 == 1) {
    FUN_18003C514(local_88, "XFA", local_6a);      /* DAT_180b278c4 == "XFA" */
    piVar8 = FUN_1800ABBDA(&local_68);
    if (*piVar8 != 0) { ... t5::unimplemented ... }
}
```

That closes the XFA-based variants (dynamic XFA forms can rewrite their own presentation) by
refusing the format rather than trying to validate it.

## 3. Appended JavaScript is detected — an explicit shadow-attack defence

`FUN_180650D20(doc, max_end)` builds a closure capturing `{doc, &flag, &status, &max_end}` with
`FUN_180666950` as the per-object callback, seeds a status byte to `1`, walks the document via
`FUN_18064F3A4`, and returns `status ^ 3`. The caller treats `3` as abort.

`FUN_180666950` is the callback. For `/Annot` + `/Subtype /Widget` + `/Sig` objects it reads
`/ByteRange`, `/Filter`, `/Contents`. For every other object it does this:

```c
puVar1 = (undefined8 *)param_1[3];                  /* -> &max_end */
lookup "JS"  (DAT_180c966d8) in the object  -> local_68
if (!present) {
    lookup "JavaScript" -> merged into local_68
    bVar3 = true;                                   /* DEFAULT ALLOW */
    if (!present_now) goto done;                    /* no offset check at all */
}
/* present: */
if (is_indirect_ref(local_68)) {
    offset = object_offset(local_68);               /* FUN_180293275 */
    bVar3 = true;
    if (offset < *(ulonglong *)*puVar1) goto done;  /* inside the signed region -> OK */
}
bVar3 = false;
done:
if (!bVar3) { *(undefined1 *)param_1[2] = 0; }      /* status = 0 -> validation aborts */
```

So the rule is: **a signed document may contain JavaScript, but only JavaScript that was itself
signed.** Append a new `/JS` action in an incremental update after `max_end` and its object
offset is `>= max_end`, so validation aborts rather than reporting valid. That is a deliberate,
targeted defence against the most dangerous shadow variant.

## 4. `/DocMDP` is parsed *and* translated into permissions

`FUN_18062A8A4` (1,400 B) walks `/Perms` → `/Reference[]`, matches
`/TransformMethod == "DocMDP"`, reads `/TransformParams` → `/P` (`DAT_180b2de3c == "P"`), and:

- **defaults `P` to `2.0`** when absent — which is the PDF 32000 default;
- converts the float to int with full saturation and a NaN arm
  (`dVar8 <= 2147483647.0`, `-2147483648.0 <= dVar8`, `NAN(dVar8) -> 0`) — no undefined
  behaviour on a hostile `/P`;
- hands the result to `FUN_18062B798(perms, P, which)`, which writes a **3-entry × 10-byte
  permissions table** at `perms+0x20` (or `perms+0x3E`), with `P == 1` zeroing all three
  entries and `P == 3` taking a separate arm.

So DocMDP is not merely recorded, it is turned into an enforcement structure. `FUN_180651010`
additionally maps `max_end` onto a document **revision** through a sorted lookup (with
`0xFFFFFFFFFFFFFFFF` special-cased), which is the structure needed to say "this signature covers
revision N of M" rather than a flat valid/invalid.

## 5. The full validator — six stages, abort by default

**§3 is only one stage of six, and my first reading of this section overstated the gap.**
`FUN_18064EF36` compares the signed revision against the current document and, if anything
changed, runs a chain whose **default is abort**:

```c
if ((tree1_size == 0) && (tree2_size == 0) && (ctx->+0xf0 == 0)) {
    uVar10 = 1;                                   /* nothing changed -> clean */
} else {
    uVar10 = 3;                                   /* DEFAULT: ABORT */
    if (FUN_180650D20(ctx, max_end) != 3 && FUN_180650E1E(ctx) != 3) {
        FUN_180651010(ctx, &rev, max_end);        /* map max_end -> revision */
        if (rev != 0 && (ctx->+0x38 == 3 ||
             (FUN_1806512B6(ctx) && FUN_180653162(ctx) && FUN_1806542B2(ctx))))
            uVar10 = FUN_180655082(ctx) ^ 3;
    }
}
```

The two red-black trees (`ctx+0xb0`/`+0xb8`/`+0xc0` and `+0xc8`/`+0xd0`/`+0xd8`, walked in-order
by `FUN_18064F3A4`, which stops early when the visitor returns 0) are the **change set** between
the signed revision and the current document. The stages and what each covers, from their key
references:

| stage | size | keys checked |
|---|---|---|
| `FUN_180650D20` | 168 | per-object `/JS` + `/JavaScript` must lie inside the signed range (§3) |
| `FUN_180650E1E` | 255 | structural; skipped when `ctx+0x38 == 3` |
| `FUN_1806512B6` | 4,252 | `/Perms` `/DocMDP` `/Legal` `/OpenAction` `/Contents` |
| `FUN_180653162` | 2,624 | `/Names` `/JavaScript` `/EmbeddedFiles` `/XFAImages` |
| `FUN_1806542B2` | 2,263 | `/AcroForm` `/Fields` `/SigFlags` |
| `FUN_180655082` | 2,503 | `TemplateInstantiated` |

That is ~11.9 KB of post-signature change validation, covering catalog permissions, the
`/OpenAction` entry, the document-level `/Names` JavaScript tree, embedded files, the form field
set and `/SigFlags`.

### 5.1 The `ctx+0x38 == 3` short-circuit is correct, not a bypass

`ctx+0x38` is set by `FUN_18064EA82` from its third argument (`param_1[0xe] = param_3` — note
`param_1` is `undefined4 *`, so index `0xe` **is** byte offset 0x38; the nearby
`*(undefined4 **)(param_1 + 0x38)` stores are byte offset 0xE0, the same Ghidra pointer-scaling
trap that caused the round-13 retraction). Its value comes from the signature's `+0x50` / `+0x54`,
which `FUN_18064805A` sets by dispatching on `/TransformMethod`:

| `/TransformMethod` | field | value | validation |
|---|---|---|---|
| `DocMDP` | `+0x50` | `P - 1` → **0, 1, 2** | `(uint)(P-1) <= 2`, i.e. `P ∈ {1,2,3}`, else `t5::corrupt_data`; `P` defaults to 2 |
| `FieldMDP` | `+0x54` | **3** | delegates to `FUN_18064C9E6` (the locked-field list) |
| `UR3` | `+0x50` | 4 | usage-rights signature |
| anything else | — | — | `t5::unimplemented` |

So `+0x50` can never hold 3, and the `== 3` short-circuit fires only on the **FieldMDP** pass
(`FUN_180648F16` runs the verification once per field, for `+0x50` then `+0x54`). Skipping the
document-wide catalog/name-tree/form checks for a transform whose entire purpose is to lock
specific *form fields* is the correct behaviour, not a bypass. A DocMDP signature always runs
the full chain.

## 6. The one remaining untested question

No stage's key set mentions `/OCProperties`, `/Annots`, `/AP`, `/Pages` or `/Root`. The
shadow-attack variants that work through those — Hide (toggle optional-content visibility),
Replace (swap annotation appearance streams) and Hide-and-Replace (substitute the page tree) —
are therefore not covered by any *per-key* stage.

Whether they are caught **structurally** is the open question: the chain's default is abort, and
the change set is enumerated object-by-object, so a changed object that no stage affirmatively
permits may already fail. Settling it means determining what populates the two trees and whether
any stage returns a pass for an object it did not recognise. That is reachable in `mspdf.dll`.

A second question needs the Edge side and cannot be settled here: **how a partial-coverage or
changed-since-signing document is reported to the user.** `FUN_180651010`'s revision mapping
exists, so the engine has the information; whether `msedge.dll` surfaces "covers an earlier
revision" or flattens it to a green check is a UI decision behind the filtered-corpus wall. That
distinction is the entire impact of this class — a forgery only matters if the UI says valid.

## 7. Assessment

**This area is hardened; it is not a productive hunting ground.** The `/XFA` refusal, the
`/TransformMethod` allowlist with `t5::unimplemented` on anything unknown, the strict `P ∈ {1,2,3}`
range check, the signed-JavaScript rule, the DocMDP-to-permissions translation and a six-stage
change validator with abort as its default are all things an implementation can easily omit, and
Edge omits none of them. I came in expecting the `max_end < extent` bound to be the whole story
and it was not.

Two of my own readings in this round were wrong and are corrected above: the `/JS` check is one
stage of six, not the only one (§5), and the `== 3` short-circuit is FieldMDP dispatch rather
than a DocMDP `P=3` bypass (§5.1). Recording both so the corrected model is what survives.
