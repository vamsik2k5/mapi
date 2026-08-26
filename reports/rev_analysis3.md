# Malware Sample Analysis — Findings

**Method note:** Everything below is *static* analysis only. The sample was
never executed, double-clicked, or run in any way — only read as bytes,
decrypted from its zip, and parsed as data (PE header parser, string scanner,
entropy calculator). All work was done directly on this machine (no isolated
VM was available to me); if you want true OS/network isolation for deeper
work (see "Next steps"), that requires spinning up an actual VM, which I
can't do from here.

## Sample inventory

| Item | Status |
|---|---|
| `9551d858…0304e.zip` | Present, AES-256 encrypted, password `infected` (standard MalwareBazaar/VirusShare convention) |
| `9551d858…0304e/sample.bin` | Decrypted payload, saved with inert `.bin` extension (never `.exe`) so it can't be accidentally launched |
| `d2a74301…5ce4f73f/` | Still empty — no zip provided for this hash yet |
| `f7ca7837…76dc6c08e7/` | Still empty — no zip provided for this hash yet |

## Sample 1: `9551d8577c3653ac1f51fc47670c1117885d3f1725695e6a4c580f4de030304e`

### Identity
- **SHA256:** `9551d8577c3653ac1f51fc47670c1117885d3f1725695e6a4c580f4de030304e` (matches zip/folder name — this is a known-catalogued sample, not something newly created)
- **SHA1:** `267c1a1bba47298da13e7444676d98ae6b259739`
- **MD5:** `9fc48479d52b55e98ac1fb4c5b052419`
- **Size:** 862,615 bytes
- **Format:** Win32 PE, GUI subsystem, 32-bit (i386)

### File type: NSIS installer (Nullsoft Install System v3.12)
Confirmed via the embedded manifest string (`Nullsoft.NSIS.exehead`,
`Nullsoft Install System v3.12`) and the NSIS "firstheader" magic bytes
(`DE AD BE EF` + `"Nullsoft"`) found at the start of the overlay data.
This is **not** a custom/fake format — it's a real NSIS-built installer stub,
which is a legitimate open-source installer framework very commonly abused
to wrap malicious payloads (fake cracks, fake software updaters, trojanized
installers) because it's free, ubiquitous, and not inherently suspicious to
users or naive AV heuristics.

### Structural red flags
| Observation | Why it matters |
|---|---|
| `.ndata` section: 221,184 bytes virtual size, **0 bytes on disk**, entropy 0.000 | Standard NSIS runtime-decompression buffer — expected for NSIS, not by itself malicious, but confirms packed/self-extracting behavior |
| **Overlay** (data appended after the last PE section) is 622,999 bytes = **72.2% of the entire file**, entropy **7.998 / 8.0** | This is where NSIS stores the compressed installer script + all bundled files/payloads. Entropy this close to the theoretical max confirms it's compressed or encrypted — and it is completely opaque to static string scanning, which is why no C2 URLs/IPs/dropped-filenames turned up in the plaintext string search below |
| Version-info resource strings (`CompanyName`, `FileDescription`, `Comments`, `LegalCopyright`, `LegalTrademarks`) are **nonsense dictionary words** (e.g. `"ingluviitis forbandelsens heliocentrically"`, `"kontroversers zamorin skdes"`) | Legitimate software has coherent, human-meaningful metadata. Randomized/gibberish metadata is a well-known technique from malware builders/crypters to (a) give every build a unique hash and (b) pad out fields so the binary doesn't look empty, while avoiding any real branding that could be searched/blacklisted |
| No embedded secondary PE found in the visible (non-overlay) portion | All 8 extra `"MZ"` byte matches besides offset 0 were verified against `e_lfanew` + PE signature and are **coincidental bytes inside the icon resources**, not real embedded executables. (This does *not* rule out a payload — it's just hidden inside the compressed overlay, not sitting in plaintext.) |
| PE timestamp: 2026-04-19 | PE timestamps are trivially attacker-controlled and not trustworthy evidence either way; noted for completeness only |

### Imports of note
- `CreateProcessW`, `ShellExecuteExW` — process launching (expected for an installer, but also how a dropper launches its payload)
- `RegSetValueExW`, `RegCreateKeyExW` — registry writes (installers commonly write `Software\Microsoft\Windows\CurrentVersion\...` / uninstall keys; this alone is not proof of persistence malware, but is worth flagging since Run-key persistence uses the same APIs)
- `CopyFileW`, `MoveFileW`, `MoveFileExW`, `DeleteFileW`, `SetFileAttributesW`, `GetTempPathW`, `GetSystemDirectoryW`, `GetWindowsDirectoryW` — typical installer/dropper file-staging behavior (drop to temp/system dirs, set attributes, clean up)
- No plaintext IOCs (URLs, IPs, mutex names, hardcoded paths) surfaced — expected, since the NSIS script + any bundled payload lives in the compressed overlay, not the cleartext PE

### Assessment
This has the structural fingerprint of a **generic malicious/trojanized NSIS
installer** (crypter-randomized metadata + high-entropy hidden payload
region), consistent with how initial-access droppers (fake installers,
"cracked software," fake updaters) are commonly built. Static analysis of
the outer PE alone is **not sufficient to identify the malware family or
final payload** — that logic is inside the compressed NSIS data block that
the installer's own runtime decompresses. I did not attempt to run it, so no
runtime behavior (network calls, dropped files, persistence) was observed —
only the static structural indicators above.

## Next steps

**To go deeper on this sample (still static, no execution):**
1. Unpack the NSIS payload itself (e.g., `7-Zip` has native NSIS-format
   support: `7z x sample.bin` in a **throwaway VM**, not this machine) to
   pull out the compressed `.nsi` script and any bundled files/executables,
   then repeat this same static process (hash, strings, PE parse) on each
   dropped file.
2. Submit just the **SHA256 hash** (not the file) to VirusTotal/MalwareBazaar
   to check existing detections, family tags, and sandbox reports already
   published by other researchers — this avoids uploading anything yourself.
3. If you want real behavioral data, that requires detonating it in an
   isolated, network-contained VM (snapshot/revert, no shared folders, fake
   DNS/INetSim or similar to catch C2 attempts) — genuinely separate from
   this host, which I have no way to provision from here.

**For the other two samples** (`d2a74301…` and `f7ca7837…`): no zip has been
supplied for either yet — folders are still empty. Send those zips (with
password) the same way and I'll run the same static pipeline.

**For your stated goal (AI-resilient anti-malware system):** the static
features that were actually diagnostic here — and would generalize well as
detector inputs — are:
- Section-table anomalies: zero-raw-size/high-virtual-size sections, per-section entropy
- Overall/overlay entropy as a packing signal (>7.5 is a strong "packed or encrypted" tell)
- Version-info coherence checks (dictionary-word/gibberish detection in `CompanyName`/`FileDescription` etc. as a crypter fingerprint, vs. checking metadata against known-legitimate vendor strings)
- Installer-framework fingerprinting (NSIS/Inno/InstallShield magic/section signatures) combined with the above, since installer wrappers are a very common malware delivery shape
- Import-table clustering (process-creation + file-staging + registry-write combos) as installer/dropper behavior features

These are the kinds of static, pre-execution features that are cheap to
compute at scale and would feed directly into a detection-model feature
set, without needing to run every sample through a sandbox first.
