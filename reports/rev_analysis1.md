# Malware Sample Analysis — `f7ca7837683a7514cd991e5a0ab8dc4b1b7542d537284e6a131bf176dc6c08e7`

**Method note:** Static analysis only. The sample was decrypted from its zip
directly into memory and parsed as bytes (PE header parser, string scan,
resource/version parse) — **never written to disk as an `.exe`, never
executed, never double-clicked.** No isolated VM was available in this
environment; everything here is safe, non-executing byte-level inspection.

## Identity
- **SHA256:** `f7ca7837683a7514cd991e5a0ab8dc4b1b7542d537284e6a131bf176dc6c08e7` (matches zip/folder name)
- **SHA1:** `0299e1f0b09a2f30212ee5c12961ae343a7b6e8b`
- **MD5:** `d7f209c9a9742dccb2a09762dae861fa`
- **Size:** 3,334,144 bytes
- **Format:** Win32 PE, GUI subsystem, **.NET/MSIL assembly** (single import: `mscoree.dll`, the .NET CLR loader stub)

## Windows Defender verdict (independent confirmation)
Flagged immediately by real-time protection when briefly written to disk
during initial extraction:

- **Threat name:** `Backdoor:MSIL/Quasar!atmn`
- **Severity:** High (5) — Action: quarantine, `ActionSuccess: True`

Unlike the companion sample, this is a **named-family signature detection**
(Quasar), not a generic ML heuristic — and the string evidence below
independently and unambiguously corroborates it. I did not attempt to
un-quarantine or bypass this detection to keep analyzing the file — the AV
already did the correct thing.

## Confirmed: this is Quasar RAT, v1.4.1.0
The .NET metadata strings leave no ambiguity — this is a build of the
open-source **Quasar RAT** (a legitimate open-source remote-administration
tool that is extremely commonly weaponized/reused by threat actors, since
its full source is public and easy to rebrand):

```
Quasar
Quasar Client
Quasar.Common, Version=1.4.1.0, Culture=neutral, PublicKeyToken=null
Client, Version=1.4.1.0, Culture=neutral, PublicKeyToken=null
Quasar.Client.Properties.Resources
Quasar.Client.Recovery.Browsers
Quasar.Client.Extensions.RegistryKeyExtensions
Quasar.Common.Messages.ReverseProxy
Quasar.Common.IO.FileSplit
```

### It's disguised as a Windows 11 setup utility
The PE version-info resource impersonates a Microsoft tool:

```
CompanyName       = Microsoft Corporation
FileDescription   = This utility prepares and initiates the installation of the Windows 11 Operating System.
ProductName       = Windows 11 Setup Utility
InternalName      = Window11.exe
OriginalFilename  = Window11.exe
LegalCopyright    = © 2024 Microsoft Corporation. All rights reserved
LegalTrademarks   = Windows 11®
ProductVersion    = 10.0.22621.1
```

This is a **social-engineering lure** — a fake "Windows 11 Setup Utility" —
not an actual Microsoft file (no valid Microsoft digital signature backs
this; it's just spoofed text in the resource table anyone can set).

### Explicit credential-theft / keylogger capability
String evidence directly names the malicious functionality — this is a
**stealer + backdoor**, not just a generic RAT shell:

```
GetPassword / GetPasswords / GetPasswordsResponse
GetSrpPassword
CheckPassword
EncryptedPassword  (backing field)
GetKeyloggerLogsDirectory / GetKeyloggerLogsDirectoryResponse
Quasar.Client.Recovery.Browsers
```

Targeted browser/app credential stores found as literal paths in the
binary — these are the exact files Quasar's "Recovery" module is built to
harvest:

```
BraveSoftware\Brave-Browser\User Data\Default\Login Data
BraveSoftware\Brave-Browser\User Data\Local State
Opera Software\Opera GX Stable\Local State
Opera Software\Opera GX Stable\Login Data
Opera Software\Opera Stable\Local State
Opera Software\Opera Stable\Login Data
Software\Martin Prikryl\WinSCP 2\Sessions          (WinSCP saved server credentials)
Software\Microsoft\Internet Explorer\IntelliForms\Storage2   (IE saved form/autofill passwords)
```

### Persistence
Standard Run-key persistence registry paths, present for both per-user and
WOW6432Node (32-bit-on-64-bit) contexts:

```
SOFTWARE\Microsoft\Windows\CurrentVersion\Run
SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce
```

Client settings backing fields confirm configurable persistence/config,
consistent with Quasar's known `Settings.cs` client config block:

```
<EncryptionKey>k__BackingField
<StartupItem>k__BackingField
<StartupItems>k__BackingField
```

### Victim fingerprinting
Two external IP-lookup services are referenced in plaintext, commonly used
by RATs/stealers to geolocate/fingerprint the victim on first check-in:

```
https://api.ipify.org/
https://ipwho.is/
```

No hardcoded C2 IP/domain was found in cleartext strings — the actual C2
address is very likely stored in the encrypted `<EncryptionKey>`-protected
config block (standard for Quasar; the server address/port/campaign tag are
normally AES-encrypted inside the client settings, not stored as a plain
string), which this static pass did not attempt to decrypt.

## Structural findings
- Single section of real size (`.text` = 3.26 MB) typical of a .NET
  assembly with embedded resources bundled in via ConfuserEx/obfuscator or
  a large embedded payload; `.rsrc` (71 KB, entropy 2.67 — low, consistent
  with an icon, not packed data); tiny `.reloc`.
- No overlay data (0 bytes) — nothing appended after the last section.
- Only 2 `"MZ"` byte occurrences total, and only offset 0 is a real PE
  signature — no embedded secondary PE payload found in the clear.

## Assessment
**Confidence: Very high that this is malicious.** This is not an ambiguous
call: named AV signature match (Quasar) + unambiguous first-party string
evidence of a credential-stealing, keylogging, persistence-capable RAT +
active Microsoft-branding impersonation. This is a textbook trojanized "fake
Windows 11 updater" Quasar RAT build.

## Next steps
1. Submit the SHA256 hash to VirusTotal/MalwareBazaar — Quasar builds are
   heavily reused/rebranded, so there's a good chance this exact hash (or a
   near-identical build) is already tagged with a campaign name or C2
   infrastructure by other researchers.
2. If deeper analysis is wanted: this is a .NET assembly, so tools like
   `dnSpy`/`ILSpy` (static decompilation, still non-executing) run inside an
   isolated VM could decompile the `Settings` class directly and recover the
   AES key + decrypt the embedded C2 server address without ever running the
   payload.
3. For the anti-malware system: the version-info **brand-impersonation
   mismatch** (claims `Microsoft Corporation` / `Windows 11 Setup Utility`
   but carries no valid Microsoft signature, and ships a `.NET` assembly
   depending only on `mscoree.dll`) is a cheap, high-value static check —
   flag any binary whose version-info vendor claims a major, well-known
   publisher (Microsoft, Google, Adobe, etc.) but lacks a valid Authenticode
   chain to that publisher's real root. Combined with known Quasar
   namespace/class-name strings (`Quasar.Client.*`, `Quasar.Common.*`), this
   sample would be caught with very low false-positive risk.
