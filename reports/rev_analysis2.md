# Malware Sample Analysis — `d2a74301bdf3c50d57a5a08aacf69b26fdf32fe9a8a4dd299a3d73125ce4f73f`

**Method note:** Static analysis only. The sample was decrypted from its zip
directly into memory and parsed as bytes (PE header parser, entropy, string
scan, certificate parse) — **never written to disk as an `.exe`, never
executed, never double-clicked.** No isolated VM was available in this
environment; everything here is safe, non-executing byte-level inspection.

## Identity
- **SHA256:** `d2a74301bdf3c50d57a5a08aacf69b26fdf32fe9a8a4dd299a3d73125ce4f73f` (matches zip/folder name)
- **SHA1:** `279a06088b51a4c42009c0ae09720ceb96e2387a`
- **MD5:** `ef4c9e9473853e02e7056c338d535388`
- **Size:** 3,704,192 bytes
- **Format:** Win64 PE (AMD64), GUI subsystem, statically-linked **Go (Golang)** binary

## Windows Defender verdict (independent confirmation)
When this sample was briefly written to disk during initial extraction,
Windows Defender's real-time protection **independently flagged it**:

- **Threat name:** `Trojan:Win32/Egairtigado!rfn`
- **Severity:** High (5) — Action: quarantine, `ActionSuccess: True`

Note: the `!rfn` suffix indicates this is a **machine-learning/heuristic
detection**, not a hand-written signature for a named malware family — these
carry real signal but also a non-trivial false-positive rate on unusual
packed/Go binaries. I did not attempt to un-quarantine, restore, or exclude
the file from Defender to keep analyzing it — the AV doing its job here is
the correct outcome, not an obstacle.

## Structural findings

| Observation | Detail |
|---|---|
| Sections | 8 sections (`.text`, `.rdata`, `.data`, `.pdata`, `.xdata`, `.idata`, `.reloc`, `.symtab`) — normal for an *unstripped* Go binary |
| TimeDateStamp | `0` — zeroed out. Go's linker sets this to 0 by default for reproducible builds, so this is normal for Go, not necessarily evasion |
| No version info, no resources | Common for Go binaries (Go doesn't embed Win32 version resources unless explicitly added via a manifest tool) |
| Imports | Minimal: `VirtualAlloc`, `LoadLibraryW`, `LoadLibraryExW`, `GetSystemDirectoryA`, `GetProcAddress` from `kernel32.dll` — this is the **normal Go runtime's own OS interface** on Windows, not necessarily attacker-added dynamic-loading logic. Not a strong signal by itself. |
| "Overlay" | 2,432 bytes, entropy 7.608 — **verified to be a genuine Authenticode `WIN_CERTIFICATE` structure** (`wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA`), not hidden encrypted payload data |

### The digital signature is forged/self-signed junk
Parsed the PKCS7 certificate embedded in the signature block:

```
Subject: CN=dadada.dododo, O=fyIUWTujrgqylj, L=BUtvp1TD0, ST=rm42Qed, C=US
Issuer:  CN=dadada.dododo, O=fyIUWTujrgqylj, L=BUtvp1TD0, ST=rm42Qed, C=US
Serial:  2032690409200969085
Valid:   2026-08-12 21:57 UTC  →  2027-08-12 21:57 UTC
```

This is **self-signed** (issuer == subject) with **randomized garbage
identity fields** — not a real company, not any recognizable CA — and was
issued literally the day before this analysis. This is a well-known malware
builder technique: sign the binary with a throwaway self-signed cert so it
*appears* signed to superficial/automated triage, even though Windows would
show it as an untrusted, unverified publisher (this does **not** grant
"Verified Publisher" trust — a real user would still see an untrusted
publisher warning on execution). This is a strong, concrete forgery
indicator, independent of Defender's heuristic call.

### Unusual string content: embedded "maze pathfinder" logic
The string scan turned up a large, distinctive block of pathfinding/maze
debug text baked into the binary — e.g.:

```
=== MAZE PATHFINDER SIMULATION ===
Maze dimensions:  Goal position: (
Initial Maze Layout:
Player starts at (
Walkable cells: Move ... Executing <token>:
- HIT WALL at (... Wall collisions: Move ...: Executing <token>:
- SUCCESS, now at ( Valid ...: Move ...: Executing <token>:
Manhattan distance to goal:
Trajectory previews:
Final position: ( Final Maze State:
```

...paired with **dozens** of `Executing <random-token>:` lines, where each
token is a distinct pseudo-random alphanumeric string (`lhjcz`, `mrlpp`,
`gxddtwuaaayktnetmxp`, `xexxuyrgqfsmjwzknzida`, etc.) — this reads like a
command/task dispatcher logging each unit of work it executes, wrapped in
maze-solving flavor text. This does **not** match typical stealer/backdoor
string signatures (no browser credential paths, no C2 domains/IPs, no
persistence registry keys were found in this sample, unlike the companion
sample `f7ca7837…` — see `MALWARE_f7ca7837.md`).

**Honest interpretation:** the maze content could be genuine functionality
(e.g. obfuscation filler, a CTF-style component, or literally an unrelated
bundled program), a decoy to pad/confuse static analysis, or a naming
scheme for dynamically dispatched malicious tasks ("Executing <job-id>")
where the maze theme is just flavor text for a generic task runner. Static
strings alone can't disambiguate this — but combined with **(a)** Defender's
heuristic flag and **(b)** the freshly-forged self-signed certificate, the
balance of evidence points to this being a deliberately obfuscated/packaged
malicious tool, most plausibly a **loader, dropper, or generic task-executing
implant** — not a benign game, and not something to run to find out.

## No embedded secondary payload found in cleartext
14 occurrences of `"MZ"` bytes were scanned; only offset 0 (the file's own
header) is a verified real PE signature. No second embedded executable was
found sitting in plaintext — if there is a second-stage payload, it is
either fetched at runtime or encoded/compressed in a way this static pass
didn't decode.

## Assessment
- **Confidence: Medium-High that this is malicious**, based on: Defender's
  heuristic detection + a certificate that was clearly forged specifically
  for this build (random identity, self-signed, issued the day before this
  analysis) — the certificate finding in particular is hard to explain for
  a benign binary.
- **Low confidence on the specific family/purpose** — no C2 indicators,
  credential-theft strings, or persistence mechanisms were found in this
  static pass; the visible behavior signature (Go runtime + minimal WinAPI
  imports + maze-themed task dispatcher strings) is most consistent with a
  **generic loader/dropper/task-runner**, but this is not confirmed.

## Next steps
1. Submit the SHA256 hash to VirusTotal/MalwareBazaar to see how many other
   engines flag it and whether a family name has already been assigned by
   other researchers — resolves the "heuristic FP vs. real malware"
   question much more reliably than a single AV engine's ML verdict.
2. If deeper analysis is wanted, detonate only inside a genuinely isolated,
   network-contained, snapshot/revert VM — not this host. Watch specifically
   for: outbound network connections (since no C2 strings were found
   in-clear, any C2 config is likely fetched or decoded at runtime), and
   what the `Executing <token>:` dispatcher actually does per token.
3. Treat the forged certificate as a durable IOC/detection feature in its
   own right: "self-signed cert with randomized CN/O/L/ST issued shortly
   before first sighting" is a cheap, high-signal static feature worth
   encoding directly into the anti-malware system's rule set.
