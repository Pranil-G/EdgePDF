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

## 5. The one concrete gap, and what settles it

The offset-inside-signed-range check of §3 is keyed **only on `/JS` and `/JavaScript`**. An
object carrying neither takes the `bVar3 = true` default and is **never offset-checked** by this
path.

The published shadow-attack variants (Mainka, Mladenov et al., *Shadow Attacks on PDF
Signatures*) split three ways, and only one involves JavaScript:

| variant | mechanism | covered by §3? |
|---|---|---|
| Hide | toggle `/OCProperties` optional-content visibility | **no** |
| Replace | swap `/Annots` `/AP` appearance streams, or fonts | **no** |
| Hide-and-Replace | new `/Root` with a substituted `/Pages` tree | **no** |

Whether those are caught **elsewhere** is the open question, and there are exactly two places
left to look:

1. **`FUN_18064F3A4`** — the walker `FUN_180650D20` drives. If it visits *every* object in the
   newest revision, an appended `/OCProperties` or `/Pages` override is at least *seen*, even if
   this callback only acts on `/JS`. If it visits only annotations, the non-JS variants are not
   even enumerated.
2. **The consumers of the `FUN_18062B798` permissions table** — whether `P` actually gates
   rendering of post-signature changes, or only gates UI affordances such as form filling.

Both are in `mspdf.dll`, so both are reachable with the corpus in hand.

A third question needs the Edge side and cannot be settled here: **how a partial-coverage
signature is reported to the user.** `FUN_180651010`'s revision mapping exists, so the engine
has the information; whether `msedge.dll` surfaces "covers an earlier revision" or flattens it
to a green check is a UI decision in the binary behind the filtered-corpus wall. That
distinction is the whole impact of this bug class — a forgery only matters if the UI says
"valid".

## 6. Assessment

This is a hardened area. The `/XFA` refusal, the signed-JavaScript rule and the DocMDP-to-
permissions translation are all things an implementation can easily omit and Edge does not. The
honest read is that the shadow-attack class was considered here, and the remaining doubt is
narrow and specific (§5) rather than a likely oversight.
