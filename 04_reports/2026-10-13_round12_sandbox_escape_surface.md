# Round 12 — sandbox-escape surface reachable from a compromised Edge PDF engine process

Follow-on to FINDING-006, which is now **confirmed on Windows**. This round answers a
different question: given code execution in the process that loads `mspdf.dll`, what is
the reachable higher-privilege surface?

Sources: the full `mspdf.dll` 154.0.4258.33 binary and corpus, plus the symbol-assisted
first-party Edge glue corpus (`edge_glue_154.0.4258.53`, 4,352 PDB-named functions out of
`msedge.dll`). Tooling added this round: `tools/glue.py`.

---

## 1. The headline: `mspdf.dll` has essentially no privileged Windows surface

The import table is the whole story. `mspdf.dll` imports **three DLLs**:

| DLL | imports |
|---|---|
| `KERNEL32.dll` | 139 functions — threads, fibers, SRW locks, TLS/FLS, file I/O, section mapping, IOCP, VirtualAlloc/Protect/Query, locale/codepage, unwind |
| `WINMM.dll` | `timeGetTime` |
| `WS2_32.dll` | two **ordinal-only** imports, `0x73`/`0x74` — the `WSAStartup`/`WSACleanup` pair; no socket function is imported at all |

What is **absent** is the interesting part: no `USER32`, `GDI32`, `ADVAPI32`, `OLE32`,
`COMBASE`, `RPCRT4`, `CRYPT32`, `WINTRUST`, `D3D*`, `DWRITE`, `SHELL32`, `NTDLL`-by-name.
So from inside `mspdf.dll` there is:

- **no COM / WinRT activation** → no `CoCreateInstance`/`RoActivateInstance` escape surface
- **no RPC / ALPC client** → no `NdrClientCall` to a privileged service
- **no win32k-backed call** → consistent with the process running under **Win32k lockdown**,
  which closes the single most productive Windows sandbox-escape class (win32k/GDI EoP)
- **no registry, no `CryptoAPI`, no shell**

Dynamic resolution does not widen this. Exactly two DLL names appear as strings without a
matching import descriptor, and both are library boilerplate:

| string | adjacent string | what it is |
|---|---|---|
| `USER32.dll` | `LoadStringW` | the MSVC CRT's resource-message fallback. Fails closed under win32k lockdown; the CRT degrades to a default message. |
| `kernel32.dll` | `GetFileSizeEx`, `failed create mapping`, `failed mapping view`, `at most one of 'mode' and 'flags' may be specified` | `boost::iostreams::mapped_file` |

**Conclusion:** a compromised PDF engine process cannot escape by calling Windows APIs. It
must escape through Edge's own IPC. That moves the whole question into `msedge.dll`.

---

## 2. The PDF subsystem's cross-process surface is small

Searching the PDB-named glue for Mojo binding points returns **two** explicit ones, plus
the generated stubs/proxies of four interface families and one private extension API.

### 2.1 Mojo interfaces

| family | interfaces | methods seen in the generated params/validators |
|---|---|---|
| `edge_pdf_ocr::mojom` | `EdgePdfOcrServiceFactory`, `EdgePdfOcrService`, `OcrClient`, `EdgePdfOcrShutdownHandler` | `InitializeOcr() -> (…)`, `BindShutdownHandler(…)`, `BindOcrClient(…)`, `OcrClient::RecognizeText(…) -> (…)`, `OcrClient::GetMaxImageDimension() -> (…)`, `ShuttingDownOnIdle() -> ()` |
| `edge_pdf_viewer_btr::mojom` | `EdgePdfViewerBtrPageHandlerFactory`, `EdgePdfViewerBtrPageHandler`, `EdgePdfViewerBtrPage` | `GetToolbarState() -> (ToolbarState)`, `NotifyToolbarReady(…)`, `OnToolbarStateChanged(…)`, `OnToolbarActionAcknowledged(…)` |
| PDF digital signature | `PDFDigitalSignatureService` | bound at `edge_pdf::PDFDigitalSignatureServiceImpl::GetRemotePDFDigitalSignatureService` (`0x7F621B2`); callers `SendSignerInfo` (`0x7F62350`), `GetCertificate` (`0x7F62B46`), `ValidateSignature` (`0x7F62B96`), and `edge_pdf::PDFCertificateService::CertVerifyRequest` (`0x7F6175E`) |

`0x7F621B2` is a textbook lazily-bound `mojo::Remote`: `cmp qword [rcx+0x28], 0` / `jne` to
return the cached remote, otherwise construct the pipe, allocate a 0x38-byte disconnect
context storing `this` at `+0x30`, and register the disconnect handler. Confirmed
cross-process.

### 2.2 Private extension API — `chrome.edgePdfPrivate`

Four methods, each with a browser-process JSON→C++ `Params::Create` deserializer:

| method | `Params::Create` |
|---|---|
| `validateDigitalSignature` | `0xBE5BB44` |
| `viewSignerCertificate` | `0xBE5BB44` |
| `executeToolbarAction` | `0xEC91AF0` |
| `executeUpsellAction` | `0xEC91A32` |

Extension function dispatch happens in the **browser process**, so these four are a direct
renderer→browser parsing surface for the PDF viewer frame.

### 2.3 What is *not* a process boundary

`edge_pdf::pdf_host::PdfHostImpl` looks like IPC from its naming — `GetPdfRenderHost`,
`GetPdfControlHost`, `GetPdfFormHost`, `GetPdfFindHost`, `GetPdfOcrHost`,
`GetPdfDigSigHost`, `GetPdfTelemetryHost`, `GetPdfVerboseTelemetryHost` — and so does the
whole `edge_pdf::service::*` manager family (annotations, ink, find, selection, undo/redo,
keyphrases, stamps, shapes, text notes, scanned PDFs). Neither carries any Mojo symbol.
They are built on a bespoke in-process async framework (`edge_pdf::pdf_base::TaskImpl`,
`TaskOperationWithResult`, `ChainableTaskOperationBase`, `single_ptr`). **Treat these as
in-process and not escape surface** unless a live check shows otherwise — the `Transfer*`
methods (`DataImpl::TransferBuffer`, `PdfUtilityInstance::TransferPdfStream`,
`DocumentImpl::TransferMIPEncryptionHandler`) are ownership moves, not marshalling.

---

## 3. Prioritised escape targets

### Tier 1 — `OcrClient::RecognizeText` → the OCR utility process

The strongest candidate, because it is the one interface where the *receiving* process is
near-certainly **less** sandboxed than the sender. Edge's PDF OCR has to reach the platform
OCR engine, which a win32k-locked-down, no-COM renderer token cannot do; so the OCR service
runs in its own utility process with a relaxed policy. The compromised engine process holds
the `OcrClient` remote and sends it an attacker-controlled bitmap.

Audit targets:
- `OcrClient_RecognizeText_Params_Data::Validate` and the hand-written `RecognizeText`
  implementation in the OCR process — dimensions, stride, pixel format, and the
  shared-memory region's claimed vs. actual size.
- `GetMaxImageDimension()` exists, which implies a limit is *negotiated*. Check whether it
  is enforced on the **receiving** side or only consulted by the sender. A sender-side-only
  check is directly exploitable from a compromised sender.
- Engine-side context: `edge_pdf::pdf_host::PdfOcrHostImpl`, `edge_pdf::service::OcrBitmapResult`,
  `edge_pdf::service::ServicesImpl::GetScannedPdfManager`.

### Tier 2 — the digital-signature service

`asn1c::ParseSignedData`, `pdf_signature::PKCS1::ParseSignature` and a statically linked
BoringSSL (`crypto/asn1/*`, `x509/x_name.cc`, `bytestring/internal.h`) all live **inside
`mspdf.dll`**, so CMS/X.509 parsing is renderer-side — it is step-1 surface, not escape
surface. What crosses the boundary is the *already-parsed* result:
`edge_pdf::pdf_base::DigitalCert` records, via `SendSignerInfo`, `GetCertificate` and
`CertVerifyRequest`.

So the target is the **browser-side consumer of renderer-produced `DigitalCert` data**:
- `viewSignerCertificate` — almost certainly ends in the Windows certificate dialog. A
  browser-process UI fed a renderer-controlled certificate blob.
- `CertVerifyRequest` (`0x7F6175E`, 1,174 bytes) — check whether it re-validates the
  DER it is handed or trusts the renderer's parse.
- `edge_pdf::datamodel::DocumentHandlerImpl::ProcessDigSigInfo`,
  `edge_pdf::service::DigSigManagerImpl::VerifyAllDigitalSignaturesAsync`.

Worth noting for its own sake: `asn1c`-generated CMS types (`AttributeCertificateV1/V2`,
`CertificateChoices`, `CertificateSet`, `CMSVersion`, `DocMDP`, `ByteRange`) plus a bespoke
`PKCS1::ParseSignature` is a large, niche, probably-underfuzzed parser sitting right next to
FINDING-006 — a good source of *additional renderer* bugs.

### Tier 3 — MIP / Purview protected documents

`edge_pdf::PdfMipHttpRequestRouter`, `MIPEncryptionHandler`, `MIPCryptoHandler`,
`MIPSecurityHandler`, `MIPPDFiumEncryptionHandler`, `PdfMipPolicyLabel`, and the
diagnostics `LogPDFMipAuthResult`, `LogPDFMipHttpStatus`, `LogPDFMipNetError`,
`LogPDFMipCrossTenantChallengeOutcome`. A policy engine that issues **authenticated HTTP**
driven by data in the PDF. Two distinct angles: a parsing bug in whichever process runs the
router, and — independent of memory corruption — request-routing abuse
(`CrossTenantChallenge` naming suggests tenant-boundary logic worth auditing on its own).

### Tier 4 — the BTR WebUI

`EdgePdfViewerBtrUI::BindInterface` (`0xC60A584`) → `CreateEdgePdfViewerBtrPageHandler`
(`0xC60A620`). The binder itself does no origin check, which is **normal** — the gate is the
WebUI interface-broker registry upstream, not the controller. Only interesting if the
registry can be reached from a frame that is not the BTR WebUI frame. Low priority, but a
cheap live check.

### Also worth a look

`edge_pdf::RenderPDFPageUsingD2D` (`0xC7E248C`). `mspdf.dll` imports no D3D/DWrite, so D2D
rendering happens on the `msedge.dll` side. If it runs outside the engine process on
engine-supplied geometry, D2D/DWrite is a rich surface.

---

## 4. Three things this corpus cannot answer — and how to get them

The glue corpus is **PDF-symbol-filtered**: an interface the engine process can bind whose
name is not PDF-ish does not appear in it. That matters, because the realistic escape path
may well be the standard Chromium renderer surface rather than anything PDF-specific.

1. **The sandbox policy of the engine process.** Which process type is
   `--pdf-renderer --pdf-shared-library`, and what token/mitigation set does it get? Get it
   live: attach to the process and read its token (integrity level, AppContainer/lowbox SID,
   restricted SIDs) plus `GetProcessMitigationPolicy` for `ProcessSystemCallDisablePolicy`
   (win32k lockdown), `ProcessDynamicCodePolicy` (ACG) and `ProcessSignaturePolicy` (CIG).
   `edge://sandbox` lists it in one screen.
2. **The interface broker allowlist for that process.** Which Mojo interfaces it may bind at
   all. Cheapest read: `edge://histograms` after exercising the viewer, or instrument
   `mojo::internal::…BindInterface` / the `BrowserInterfaceBroker` receiver and log names.
3. **Whether the engine process is the same process as the PDF viewer frame.** This decides
   whether the `edgePdfPrivate` extension API and the BTR WebUI are reachable from the
   corrupted process or only from a different renderer.
   `edge_pdf::PdfUtilityInstance::GetScopedBlinkIsolate` says the engine process hosts a
   Blink isolate, which hints they are co-located — confirm on the box with Process Explorer
   against the `--type=` command lines.

Answering (1) and (2) collapses the target list quickly, and both take minutes on the host
where FINDING-006 was just confirmed.

---

## 5. Honest note on chain economics and the step-2 gap

**Step 2 is not done.** FINDING-006 gives a 3,077-byte heap overflow of a 1,027-byte pool
chunk (and, via `FUN_1808F9500`, a `memcpy` that also over-*reads* an adjacent 1,027-byte
chunk). Turning that into controlled execution is still real work, and the escape only
matters afterwards. Two observations from the import table that bear on it:

- `VirtualAlloc` / `VirtualProtect` are statically imported. That is weak evidence against
  ACG being enforced on this process — worth confirming via (1) above, because it changes
  step 2 substantially.
- `CreateFiber` / `ConvertThreadToFiber` / `SwitchToFiber` / `DeleteFiber` and `QueueUserAPC`
  are imported, and fiber contexts are heap-allocated structures holding a saved stack
  pointer and instruction pointer. A heap overflow adjacent to a fiber context is a
  materially easier control-flow path than a return address under CFG. `t5` uses fibers for
  the engine's cooperative scheduling, so these structures are plentiful and their
  allocation is driven by document content.

On scope: Microsoft's Edge bounty pays for the renderer bug on its own merits, and pays more
for a chain — but the escape has to be its *own* new bug. If the escape ends up in upstream
Chromium rather than Edge-specific code, it is likely a duplicate and belongs to a different
programme. Of the targets above, Tiers 1–3 are first-party Microsoft code and therefore both
in-scope and far less fuzzed; Tier 4 and the generic Chromium renderer surface are not.

**Recommendation:** report FINDING-006 now rather than holding it for a chain. Then pursue
Tier 1, which is the only target where the privilege gradient is near-certain.
