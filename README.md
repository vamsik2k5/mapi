# Windows Defensive Agent (EDR Prototype)

A small, from-scratch EDR (Endpoint Detection & Response) prototype for Windows,
combining static PE analysis, real-time Sysmon-driven behavioral detection, and
an active process/module sweep — plus a scored heuristic engine that can
auto-mitigate (suspend + terminate) a process that crosses a threat threshold.

Built and hardened through live-fire testing on a real Windows machine, not
just unit tests — several of the design decisions below exist specifically
because a naive version of that rule produced a real false positive (or
worse) when run against real system activity. Those are called out inline.

---

## Table of contents

- [How it works](#how-it-works)
- [Architecture](#architecture)
- [What each detector actually catches](#what-each-detector-actually-catches)
- [Safety model](#safety-model-read-this-before-running-it)
- [Setup](#setup)
- [Running it](#running-it)
- [Workflows](#workflows)
- [Project layout](#project-layout)
- [Known limitations / roadmap](#known-limitations--roadmap)
- [Credits / inspiration](#credits--inspiration)

---

## How it works

The agent runs three independent detection surfaces in parallel, all feeding
one shared scoring engine:

1. **Static scan** (`src/static_scanner.py`) — reads pre-extracted PE
   features (`data/binaries.json`, produced offline by
   `tools/extract_features.py`) and scores structural red flags: RWX
   sections, high-entropy sections (packing), dangerous import combinations
   (process injection, keylogging, LSASS dumping), unsigned binaries
   impersonating a known vendor, and "metamorphic clone" detection (two
   files with identical structure but different hashes — the same malware
   family repacked).

2. **Behavioral telemetry** (`src/telemetry_monitor.py` +
   `src/heuristic_engine.py`) — subscribes to the
   `Microsoft-Windows-Sysmon/Operational` event log in real time
   (`EvtSubscribe`, push-based) and scores live process/file/registry
   activity: credential-access attempts against LSASS, process-hollowing
   attempts against `svchost.exe`, Defender-tampering commands, obfuscated
   PowerShell, Office-macro-style dropper chains, Run-key persistence, and
   ransomware-style mass file writes.

3. **Active module sweep** (`src/module_inspector.py`) — every 30 seconds,
   walks the live process table (independent of Sysmon) looking for DLLs
   already mapped into high-value system processes from dropper-style
   staging directories (`Temp`, `Public`, Recycle Bin). This catches
   injection that happened *before* the agent started, or isn't covered by
   the Sysmon config.

Every finding adds points to a per-process (or per-file-hash, for static
findings) score in `HeuristicEngine`. Scores **decay over time** (~20
points/minute) so only activity that compounds *quickly* — the actual shape
of an attack chain — can reach the action thresholds:

| Score | Action |
|---|---|
| ≥ 50 | `[WARNING]` logged, simulated memory snapshot (no action taken) |
| ≥ 80 | `[CRITICAL THREAT]` — `mitigate()` is called: the process is suspended, then terminated |

## Architecture

```
                    ┌─────────────────────┐
tools/extract_       │  data/binaries.json  │
features.py  ───────▶│  (PE features, once  │
(offline, run         │   per sample set)    │
 manually)            └──────────┬───────────┘
                                  │
                                  ▼
┌──────────────┐        ┌─────────────────┐
│ static_       │──────▶│                 │
│ scanner.py    │        │                 │
└──────────────┘        │                 │
                         │  Heuristic       │      score ≥ 80
┌──────────────┐        │  Engine          │──────────────────▶ mitigate()
│ Sysmon        │──EvtSubscribe──▶ telemetry_ │  (per-PID /       (suspend +
│ Operational   │        │  monitor.py │ per-file-hash    terminate,
│ log           │        │                 │  scoring,          PROTECTED
└──────────────┘        │                 │  decay,           processes
                         │                 │  PID-reuse        refused)
┌──────────────┐        │                 │  guard)
│ module_       │─every─▶│                 │
│ inspector.py  │ 30s     └─────────────────┘
│ (live sweep)  │
└──────────────┘
```

`src/main.py` wires all three detection surfaces into one process and keeps
it alive so the Sysmon subscription callback and the periodic module sweep
both keep running.

## What each detector actually catches

| Detector | File | MITRE-ish technique |
|---|---|---|
| RWX / high-entropy sections | `static_scanner.py` | Packing / injected code |
| Injection & keylogger IAT patterns | `static_scanner.py` | T1055 injection, T1056 keylogging |
| LSASS dump IAT pattern (`MiniDumpWriteDump`+`OpenProcess`) | `static_scanner.py` | T1003.001 |
| Vendor-impersonation (unsigned + claims Microsoft/Google/etc.) | `static_scanner.py` | T1036 masquerading |
| Metamorphic clone detection | `static_scanner.py` | Polymorphic malware family clustering |
| Execution from staging dirs (`Temp`, `Public`) | `heuristic_engine.py` | T1036 / T1105 |
| Defender-tamper command lines | `heuristic_engine.py` | T1562.001 |
| Obfuscated/download-execute PowerShell | `heuristic_engine.py` | T1059.001, T1027 |
| Office app → LOLBin child process | `heuristic_engine.py` | T1204.002 |
| LSASS credential access (real bitmask check) | `heuristic_engine.py` | T1003.001 |
| Process hollowing via `svchost.exe` access | `heuristic_engine.py` | T1055.012 |
| Run-key persistence | `heuristic_engine.py` | T1547.001 |
| Ransomware-style file-write burst | `heuristic_engine.py` | T1486 |
| Injected module in a high-value process | `module_inspector.py` | T1055 |

Matching Sigma rules for the Sysmon-driven detections live in
[`rules/sigma.yml`](rules/sigma.yml); YARA rules for the static/family
detections live in [`rules/static.yar`](rules/static.yar) and
[`rules/family_signatures.yar`](rules/family_signatures.yar).

## Safety model (read this before running it)

This agent can **suspend and kill real processes** on your machine. Two
incidents during development directly shaped the current safety design —
documented here so anyone running this understands exactly what guardrails
exist and why:

- **A rate-only ransomware detector killed a running IDE twice**, because a
  bare "N files created in T seconds" counter can't distinguish mass
  encryption from an IDE indexing a workspace, `git status`, or a build. Fix:
  the ransomware rule now excludes known dev-tool/sync-client process names
  and is scoped to only the folder types Windows' own **Controlled Folder
  Access** protects by default (Desktop/Documents/Pictures/Music/Videos/
  Downloads) — not the whole filesystem.

- **A scoring bug caused a full system freeze.** `mitigate()` had no
  awareness that some PIDs are core OS processes (`csrss.exe` in particular —
  suspending it halts the entire Win32 subsystem session-wide, which is
  exactly why Task Manager and Process Explorer both hard-refuse to touch
  it). A repeating, individually-low-severity false positive against a
  trusted-path system process was able to climb past the mitigation
  threshold given enough time, since "trusted path" only ever *reduced*
  score — it was never true immunity.

  The fix is a **hard, unconditional, two-layer floor**, not a smarter
  heuristic:
  1. `HeuristicEngine._add_score()` refuses to accumulate *any* score for a
     fixed set of protected process names (`csrss.exe`, `wininit.exe`,
     `winlogon.exe`, `services.exe`, `smss.exe`, `lsass.exe`, `svchost.exe`,
     `dwm.exe`, `explorer.exe`, `System`/`System Idle Process`/`Registry`/
     `MemCompression`), PID 0, PID 4, and the agent's own PID.
  2. `mitigate()` independently refuses to call `suspend()`/`terminate()`
     against that same set — deliberately redundant with #1, so the
     refusal holds even if some future code path calls `mitigate()`
     directly, bypassing scoring entirely.

  **This protected list is a floor, not a substitute for caution.** It
  covers the processes whose termination is catastrophic; it does not make
  every other kill "safe." Review `[CRITICAL THREAT]` log lines before
  trusting auto-mitigation in any environment that matters to you.

- **Two false-positive noise sources were found and removed rather than
  patched over**: Windows Defender's own platform DLLs and, more broadly,
  the entire `ProgramData` directory (Visual Studio installer components,
  Windows Terminal's MSIX packaged-COM proxy, OEM vendor helper DLLs all
  legitimately live there) were dropped from the module-injection staging
  path list rather than chasing an endless per-vendor allowlist.

**Everything above is unit-tested**, but if you want detection without any
auto-kill risk while you build trust in a new environment, the simplest
change is to comment out the `self.mitigate(pid)` call in
`HeuristicEngine._check_threshold()` and just log at that severity instead.

## Setup

Requires Windows, Python 3.11+, and (for real-time behavioral detection)
[Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
running as Administrator.

```bash
cd mal_project
python -m venv .venv
.venv\Scripts\pip install pefile psutil pywin32
```

### Installing Sysmon

The static scanner works standalone, but real-time behavioral detection
needs Sysmon installed and running. Download it fresh (do **not** commit
Sysmon binaries to this repo — they're excluded via `.gitignore`):

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath tools\sysmon -Force
```

Then, **from an elevated (Administrator) PowerShell**, install it with the
config in this repo — scoped deliberately narrow to only the event types
this agent actually consumes (`ProcessCreate`, `ProcessAccess` on
lsass/svchost, `FileCreate`, `RegistryEvent` on Run keys, `ImageLoad` into
high-value processes), rather than a generic noisy community config:

```powershell
cd tools\sysmon
.\Sysmon64.exe -accepteula -i config.xml
```

Verify it's running:

```powershell
Get-Service Sysmon64
```

## Running it

The behavioral monitor needs Administrator to subscribe to the Sysmon
event log, so run from an **elevated** PowerShell:

```powershell
cd mal_project\src
..\.venv\Scripts\python.exe main.py
```

You should see:

```
[*] Starting Static Ingress Scanner on ../data/binaries.json...
[+] Static Scan Complete.
[*] Starting Behavioral Telemetry Monitor...
[+] Sysmon push subscription active. Awaiting real-time events...
[*] EDR Engine is active. Press Ctrl+C to terminate.
```

If Sysmon isn't installed/running, you'll instead see `[-] Telemetry
monitor failed to start. Continuing with static analysis only.` — the
static scan and its findings still run fine standalone.

Press `Ctrl+C` to stop.

## Workflows

### Extracting features from a new sample

Static analysis is entirely offline and never executes a sample — it parses
PE bytes directly (`pefile`).

```bash
cd mal_project/samples
# drop your .exe file(s) here
cd ../tools
# add the filename(s) to target_files in extract_features.py
../.venv/Scripts/python.exe extract_features.py
```

This regenerates `data/binaries.json`, which `static_scanner.py` reads on
the next `main.py` run.

### Running just the static scan (no admin needed)

```python
import sys; sys.path.insert(0, "src")
from heuristic_engine import HeuristicEngine
from static_scanner import StaticScanner

engine = HeuristicEngine()
StaticScanner(engine, "data/binaries.json").scan()
print(engine.static_scores)
```

### Testing a behavioral rule without waiting for a real trigger

`heuristic_engine.py`'s `evaluate_event()` takes raw Sysmon event XML, so
any rule can be exercised with synthetic XML instead of needing a live
attack technique:

```python
import sys; sys.path.insert(0, "src")
from heuristic_engine import HeuristicEngine

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
def event(event_id, **fields):
    data = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in fields.items())
    return f'<Event xmlns="{NS}"><System><EventID>{event_id}</EventID></System><EventData>{data}</EventData></Event>'

engine = HeuristicEngine()
engine.evaluate_event(event(1,
    ProcessId=1234,
    Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    CommandLine="powershell -WindowStyle Hidden -EncodedCommand aQBlAHgA...",
))
```

### Adding a new detection rule

1. Add the scoring logic to the relevant `_handle_*` method in
   `heuristic_engine.py` (or a new one, dispatched from `evaluate_event()`).
2. If it needs a Sysmon event type not already logged, add an
   include/exclude rule to `tools/sysmon/config.xml` and reinstall
   (`Sysmon64.exe -c config.xml` updates the running config without a full
   reinstall).
3. Document it as a Sigma rule in `rules/sigma.yml` for portability to other
   tooling.
4. Test it with synthetic XML (see above) before trusting it against real
   traffic — every rule in this repo that skipped that step caused a real
   false positive during development.

## Project layout

```
mal_project/
├── src/                    Agent runtime
│   ├── main.py             Entry point - wires static scan + telemetry + module sweep
│   ├── heuristic_engine.py Central scoring engine, all detection logic, mitigate()
│   ├── static_scanner.py   Reads data/binaries.json, scores static PE findings
│   ├── telemetry_monitor.py  Sysmon EvtSubscribe wiring
│   └── module_inspector.py Active live-process module sweep
├── tools/
│   ├── extract_features.py Offline PE feature extractor (pefile-based, never executes samples)
│   └── sysmon/              Sysmon config.xml (binaries gitignored - see Setup)
├── rules/
│   ├── static.yar            Structural YARA rules (RWX, entropy, LSASS-dump IAT, impersonation)
│   ├── family_signatures.yar YARA rules for specific known samples analyzed in reports/
│   └── sigma.yml              Sigma rules mirroring every Sysmon-driven heuristic
├── data/
│   └── binaries.json        Extracted PE features (output of extract_features.py)
├── samples/                 Raw samples go here locally - not committed (see samples/README.md)
├── reports/                 Manual malware analysis write-ups for specific samples
└── scripts/
    └── monitor.ps1           Earlier PowerShell-only prototype of the telemetry monitor
```

## Known limitations / roadmap

- **EventID 7 (ImageLoad) has a Sigma rule but no engine handler.**
  `rules/sigma.yml`'s "DLL Loaded Into High-Value Process From Staging
  Directory" rule documents the technique and the Sysmon config emits those
  events, but `heuristic_engine.py`'s `evaluate_event()` doesn't dispatch
  EventID 7 yet. Coverage for that specific pattern currently exists only
  via `module_inspector.py`'s separate active sweep.
- **No trusted-publisher (Authenticode) verification at runtime** — the
  static scanner's impersonation check compares version-info claims against
  signature *presence*, not signature *validity*. A properly-signed
  malicious binary with a stolen/valid cert would not be caught by this
  check.
- **Scoring is per-PID / per-file-hash, not per-ProcessGuid.** A PID-reuse
  guard (comparing OS process start time) mitigates the most common failure
  mode, but Sysmon's `ProcessGuid` field would be a more robust key long-term.
- **`mitigate()`'s "simulated memory snapshot" at score ≥ 50 does nothing
  yet** — it's a log line, not an actual forensic capture.
- No persistence/config file yet — thresholds, decay rate, and the
  protected-process list are all constants in `heuristic_engine.py`.

## Credits / inspiration

Detection design in this project draws on ideas from two much larger,
mature open-source projects (no code copied — these informed *what* to
detect, not *how* the Python is written):

- **[Fibratus](https://github.com/rabbitstack/fibratus)** — a Go-based
  Windows security sensor with a mature ETW-driven, MITRE-ATT&CK-mapped
  rule catalog. The LSASS credential-access detection, the process-hollowing
  access-mask logic, and the ransomware/Office-LOLBin/Defender-tamper
  Sigma rules in this project are modeled on patterns from Fibratus's
  `rules/` directory.
- **[System Informer](https://github.com/winsiderss/systeminformer)**
  (formerly Process Hacker) — a deep Windows process/handle/module
  inspection tool. `module_inspector.py`'s active live-process module sweep
  is inspired by its process/module enumeration view: where Sysmon
  telemetry is passive and event-driven, this periodically inspects what's
  already mapped into running processes.
