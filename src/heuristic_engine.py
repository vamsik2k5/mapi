import os
import json
import time
import psutil
import logging
from collections import defaultdict

from detection_config import load_config

# Known-good SHA-256 -> {"reason": ..., "source": ..., "added": ...}, checked
# in add_static_score() before any static finding (hardcoded rule, imphash
# match, or custom rule_engine.py hit) is allowed to accumulate score.
# Mirrors ClamAV's .fp/.sfp false-positive-suppression hash database:
# a human-vetted, unconditional override sitting in front of detection,
# not another rule competing for weight inside it. Absent by default, same
# as data/known_imphashes.json - deleting/never creating this file changes
# nothing.
DEFAULT_KNOWN_GOOD_HASHES_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'known_good_hashes.json')


def _load_known_good_hashes(path):
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}

# Commands/args consistent with an attacker (or malware with local admin)
# disabling Windows Defender out-of-band. Found necessary because a live
# audit of this host showed Tamper Protection is OFF - nothing in Defender
# itself alerts when its own protections get turned off, so this compensates
# for that gap independently of the AV.
DEFENDER_TAMPER_PATTERNS = (
    'set-mppreference', 'disablerealtimemonitoring', 'disableantispyware',
    'disableantivirus', 'disablebehaviormonitoring', 'disableioavprotection',
    'add-mppreference -exclusionpath', 'remove-mppreference',
    'sc stop windefend', 'sc.exe stop windefend', 'sc config windefend',
    'net stop windefend', 'taskkill /im msmpeng.exe', 'taskkill /f /im msmpeng.exe',
)

# Classic PowerShell/LOLBin obfuscation and download-execute markers - the
# post-exploitation technique ASR rules would normally block, compensating
# for the fact that this host has zero ASR rules configured.
POWERSHELL_ABUSE_PATTERNS = (
    '-enc ', '-encodedcommand', '-e ', 'frombase64string', 'downloadstring',
    'downloadfile', 'iex(', 'invoke-expression', '-windowstyle hidden',
    '-w hidden', '-executionpolicy bypass', '-ep bypass', '-noprofile -nop',
)

# Office apps spawning a shell/scripting interpreter is the classic
# macro-dropper chain - exactly what an ASR "Block Office applications
# from creating child processes" rule blocks. This host has no ASR rules,
# so this parent/child heuristic compensates for that specific gap.
OFFICE_PARENTS = ('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'mspub.exe')
LOLBIN_CHILDREN = ('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe',
                    'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe')

# Ransomware-style behavior: one process creating/renaming a large number
# of files in a short window. Compensates for Controlled Folder Access
# being disabled on this host (no ransomware folder guarding at all).
#
# Live-fire testing killed VS Code (twice) under this rule: a bare file-
# creation rate has no way to distinguish encryption from an IDE indexing
# a workspace, git status, npm install, or a build. Scoped down to match
# what Controlled Folder Access itself actually protects by default (the
# user's document-type folders, not arbitrary project/cache directories),
# plus an explicit exclusion for common dev-tool/sync-client processes
# that legitimately churn many files fast.
RANSOMWARE_FILE_EVENT_WINDOW_SECONDS = 20
RANSOMWARE_FILE_EVENT_THRESHOLD = 60
RANSOMWARE_MONITORED_DIRS = (
    '\\desktop\\', '\\documents\\', '\\pictures\\', '\\music\\',
    '\\videos\\', '\\downloads\\', '\\favorites\\',
)
RANSOMWARE_EXCLUDED_PROCESSES = (
    'code.exe', 'code - insiders.exe', 'devenv.exe', 'git.exe', 'node.exe',
    'python.exe', 'pythonw.exe', 'dotnet.exe', 'msbuild.exe', 'java.exe',
    'explorer.exe', 'onedrive.exe', 'dropbox.exe', 'searchindexer.exe',
    'msedge.exe', 'chrome.exe', 'firefox.exe', 'docker.exe', 'svchost.exe',
    'trustedinstaller.exe', 'werfault.exe',
)

# All process_scores decay over time rather than accumulating forever.
# Live-fire testing showed a repeating, individually-benign low-severity
# signal (trusted-path svchost.exe access, +15 every ~30-90s) climbing
# 15->30->45->60->75 purely from patience, heading straight for a false
# CRITICAL mitigation given enough runtime. Decaying means only signals
# that actually compound *quickly* - the real shape of an attack chain -
# can cross the mitigation threshold.
SCORE_DECAY_PER_SECOND = 1.0 / 3.0  # ~20 points/minute

# Individual PROCESS_* access rights (winnt.h). Bits actually needed to read
# or tamper with another process's memory/threads - i.e. rights that matter
# for hollowing/credential-dumping. Deliberately excludes
# PROCESS_QUERY_LIMITED_INFORMATION (0x1000), PROCESS_QUERY_INFORMATION
# (0x0400), SYNCHRONIZE (0x100000) and READ_CONTROL (0x20000): those alone
# are what nearly every process on the system requests just to check "is
# this PID still alive" and are not, by themselves, evidence of anything.
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_DUP_HANDLE = 0x0040
PROCESS_ALL_ACCESS = 0x1FFFFF

# LSASS: reading its memory *is* the credential-theft primitive (that's
# literally what MiniDumpWriteDump/Mimikatz do) - no write capability
# needed, so VM_READ alone is genuine signal here. DUP_HANDLE is included
# too (indirect handle-theft, e.g. via seclogon).
LSASS_DANGEROUS_BITS = (
    PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ
    | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE
)

# Process hollowing requires *writing* a replacement payload into the
# target and redirecting its execution - VM_READ alone proves nothing.
# Live-fire testing showed WmiPrvSE.exe (Windows' own WMI provider host)
# routinely opens svchost.exe with VM_READ as part of completely normal
# Win32_Process/Win32_Service queries; including VM_READ here caused it to
# be repeatedly (and wrongly) auto-terminated. Require actual write/thread
# capability instead.
HOLLOWING_DANGEROUS_BITS = (
    PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE
)

# Processes whose suspend/termination can hang or crash the ENTIRE OS, not
# just misbehave - traced directly to a real incident: this engine
# mitigated (suspend+terminate) a false-positive score against a core
# Windows subsystem process and froze the whole machine solid (blank
# screen, zero keyboard/mouse input, required a hard reboot). csrss.exe in
# particular is why Task Manager and Process Explorer both hard-refuse to
# end or suspend it - it IS the Win32 subsystem; suspending it halts every
# session on the box. This is an unconditional, hard-coded floor: no
# heuristic, no matter how it's scored or how confident it looks, ever
# gets to suspend or terminate anything in this set. "Trusted-path" in the
# rules above only ever *reduces* score - it was never true immunity, and
# that gap is exactly what let this happen.
PROTECTED_PROCESS_NAMES = frozenset({
    'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'smss.exe',
    'lsass.exe', 'svchost.exe', 'dwm.exe', 'explorer.exe',
    'system', 'system idle process', 'registry', 'memcompression',
})
# PID 0 (System Idle Process) and 4 (System) are always these processes
# regardless of what psutil.Process(pid).name() would report or whether
# that call even succeeds - check by number first, before touching psutil.
PROTECTED_PIDS = frozenset({0, 4})


def _parse_granted_access(raw):
    """Sysmon's GrantedAccess field as an int, or 0 if unparseable."""
    try:
        return int(raw, 16)
    except (TypeError, ValueError):
        return 0


def _is_dangerous_access(access_int, dangerous_bits):
    """True if the mask carries any of the given dangerous right(s), or is
    PROCESS_ALL_ACCESS. Bitwise, not substring - a naive '0x10' substring
    check on the hex string wrongly matched PROCESS_QUERY_LIMITED_INFORMATION
    (0x1000) as if it were PROCESS_VM_READ, and live-fire testing confirmed
    it was auto-terminating harmless processes as a result."""
    if access_int == 0:
        return False
    return access_int == PROCESS_ALL_ACCESS or bool(access_int & dangerous_bits)


class HeuristicEngine:
    def __init__(self, rule_engine=None, config=None, known_good_hashes=None):
        # Optional additive YAML rule pack (src/rule_engine.py) - evaluated
        # after every hardcoded rule below, routed through the same
        # _add_score() every hardcoded rule uses, so a custom rule inherits
        # the protected-process floor and decay for free. None (the
        # default) is the exact behavior this engine had before rule packs
        # existed.
        self.rule_engine = rule_engine
        # Numeric tunables (decay rate, thresholds, ransomware window/count)
        # - see detection_config.py. Deliberately does NOT cover the safety
        # floor below (PROTECTED_PROCESS_NAMES, access-mask bitmasks,
        # pattern lists) - those stay hardcoded so a config file can never
        # loosen them. A missing/malformed config file yields the exact
        # hardcoded values this engine always used.
        self.config = config if config is not None else load_config()
        # Known-good SHA-256 allowlist (data/known_good_hashes.json by
        # default) - see add_static_score(). Unlike config/rule_engine
        # above, this is meant to be hand-edited by a human vetting a
        # specific false positive, the same trust model as this engine's
        # other operator-editable inputs.
        self.known_good_hashes = known_good_hashes if known_good_hashes is not None else _load_known_good_hashes(DEFAULT_KNOWN_GOOD_HASHES_PATH)
        self.process_scores = {}
        self.static_scores = {}
        # pid -> list of recent FileCreate timestamps, for the ransomware
        # rate detector in _handle_file_create.
        self._file_event_timestamps = defaultdict(list)
        # pid -> that process's OS start time, so a score accumulated
        # against a short-lived process doesn't get inherited by a
        # completely different, later process that Windows happens to
        # reuse the same PID for. Live-fire testing showed WmiPrvSE.exe
        # instances (very short-lived, frequently recreated) repeatedly
        # reusing one PID, which compounded a benign per-instance access
        # pattern into a runaway score and a mitigate() loop.
        self._pid_start_times = {}
        # pid -> monotonic time of last score change, for the decay applied
        # in _add_score.
        self._last_score_time = {}
        self._own_pid = os.getpid()
        # Raw telemetry heartbeat, independent of scoring: every Sysmon
        # event that reaches evaluate_event() increments this, whether or
        # not any heuristic below fires on it. Most process/file/registry
        # activity on a normal machine matches none of the suspicious
        # patterns in this file by design, so it produces no score and no
        # log line - which looks identical to "the subscription is dead"
        # from the outside. This counter is what a dashboard should watch
        # to tell those two situations apart.
        self.total_events_seen = 0
        self.last_event_time = None
        # Optional callable(event_id, data_dict) invoked for every raw
        # Sysmon event regardless of scoring - lets an external observer
        # (e.g. the web dashboard's Process Explorer) see all activity
        # without this engine taking on any storage/rendering concerns of
        # its own, and without changing what gets scored.
        self.on_event = None
        logging.basicConfig(level=logging.INFO, format='[*] %(message)s')

    def _is_protected(self, pid):
        """True if `pid` must never be scored or mitigated - core OS
        processes (see PROTECTED_PROCESS_NAMES) plus this agent's own PID."""
        if pid in PROTECTED_PIDS or pid == self._own_pid:
            return True
        try:
            name = psutil.Process(pid).name().lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
        return name in PROTECTED_PROCESS_NAMES

    def is_allowlisted(self, file_hash):
        """True if `file_hash` is in the known-good allowlist - callers
        (e.g. static_scanner.py's clone-detection log line) that need to
        check this ahead of calling add_static_score() use this instead of
        reaching into known_good_hashes directly."""
        return file_hash in self.known_good_hashes

    def add_static_score(self, file_hash, score, context):
        if file_hash in self.known_good_hashes:
            # Single choke point every static finding already routes
            # through - hardcoded rules, imphash-family matches, and
            # rule_engine.py's static_pe hits alike - so allowlisting a
            # hash here suppresses all of them uniformly, unconditionally,
            # before any score is ever recorded. Never a rule competing
            # for weight inside the scoring system, always a hard override
            # in front of it.
            entry = self.known_good_hashes[file_hash]
            reason = entry.get('reason', '?') if isinstance(entry, dict) else '?'
            logging.info(f"[ALLOWLIST] {file_hash} -> ignoring finding, hash is known-good (reason: {reason}) | Would-be: +{score} ({context})")
            return
        if file_hash not in self.static_scores:
            self.static_scores[file_hash] = 0
        self.static_scores[file_hash] += score
        logging.info(f"[STATIC] {file_hash} -> +{score} ({context}) | Total: {self.static_scores[file_hash]}")

    def evaluate_event(self, xml_content):
        """
        Parses Sysmon XML event and scores it.
        """
        import xml.etree.ElementTree as ET
        try:
            # Sysmon event namespace
            root = ET.fromstring(xml_content)
            
            system = root.find('{http://schemas.microsoft.com/win/2004/08/events/event}System')
            if system is None:
                return

            event_id_elem = system.find('{http://schemas.microsoft.com/win/2004/08/events/event}EventID')
            if event_id_elem is None:
                return
            event_id = int(event_id_elem.text)
            self.total_events_seen += 1
            self.last_event_time = time.time()

            event_data = root.find('{http://schemas.microsoft.com/win/2004/08/events/event}EventData')
            if event_data is None:
                return

            data_dict = {}
            for data in event_data.findall('{http://schemas.microsoft.com/win/2004/08/events/event}Data'):
                name = data.get('Name')
                value = data.text
                if name:
                    data_dict[name] = value

            if self.on_event:
                try:
                    self.on_event(event_id, data_dict)
                except Exception:
                    pass  # an observer's bug must never break detection

            if event_id == 1:
                self._handle_process_create(data_dict)
            elif event_id == 10:
                self._handle_process_access(data_dict)
            elif event_id == 11:
                self._handle_file_create(data_dict)
            elif event_id == 13:
                self._handle_registry_event(data_dict)

            if self.rule_engine:
                self.rule_engine.evaluate_behavioral(event_id, data_dict, self)

        except Exception as e:
            logging.error(f"[ERROR] Parsing event XML failed: {e}")

    def _add_score(self, pid, score, context):
        if self._is_protected(pid):
            # Never even accumulate score for a protected process - no
            # heuristic gets to push this PID toward mitigate(), full stop.
            logging.warning(f"[PROTECTED] Ignoring score for PID {pid} - protected core OS process, never auto-scored/mitigated. Would-be reason: {context}")
            return

        self._reset_score_if_pid_reused(pid)
        self._apply_decay(pid)

        if pid not in self.process_scores:
            self.process_scores[pid] = 0

        self.process_scores[pid] += score
        self._last_score_time[pid] = time.monotonic()
        current_score = self.process_scores[pid]

        logging.info(f"[TELEMETRY] PID {pid} -> +{score} ({context}) | Total Score: {round(current_score, 1)}")

        self._check_threshold(pid)

    def _apply_decay(self, pid):
        """Fade this PID's score by elapsed time since its last update, so
        only signal that compounds quickly - not slow, spaced-out benign
        activity - can reach the mitigation threshold."""
        last_time = self._last_score_time.get(pid)
        if last_time is None or pid not in self.process_scores:
            return
        elapsed = time.monotonic() - last_time
        decayed = self.process_scores[pid] - (elapsed * self.config['decay_points_per_second'])
        self.process_scores[pid] = max(0.0, decayed)

    def _reset_score_if_pid_reused(self, pid):
        """If the live process currently holding `pid` isn't the same OS
        process we last scored under that PID, its accumulated score
        belongs to a process that's already gone - start that PID fresh."""
        try:
            current_start = psutil.Process(pid).create_time()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Already exited (common for short-lived hosts like
            # WmiPrvSE.exe) - nothing to compare against, leave as-is.
            return

        last_start = self._pid_start_times.get(pid)
        if last_start is not None and last_start != current_start:
            self.process_scores[pid] = 0
        self._pid_start_times[pid] = current_start

    def _check_threshold(self, pid):
        score = self.process_scores.get(pid, 0)
        critical = self.config['thresholds']['critical']
        warning = self.config['thresholds']['warning']
        if score >= critical:
            logging.warning(f"[CRITICAL THREAT] PID {pid} crossed mitigation threshold (Score {score}). Mitigating...")
            self.mitigate(pid)
            self.process_scores[pid] = 0 # reset after mitigation
        elif score >= warning:
            logging.warning(f"[WARNING] PID {pid} score >= {warning}. Taking memory snapshot... (Simulated)")

    def _handle_process_create(self, data):
        # Event ID 1: Flag execution from staging directories
        pid = int(data.get('ProcessId', 0))
        image = data.get('Image', '').lower()
        parent_image = data.get('ParentImage', '').lower()
        command_line = (data.get('CommandLine') or '').lower()

        if 'temp' in image or 'users\\public' in image:
            self._add_score(pid, 30, f"Execution from staging directory: {image}")

        if any(pattern in command_line for pattern in DEFENDER_TAMPER_PATTERNS):
            self._add_score(pid, 90, f"Attempted Defender tampering: {command_line}")

        if any(pattern in command_line for pattern in POWERSHELL_ABUSE_PATTERNS):
            self._add_score(pid, 45, f"Obfuscated/download-execute command line: {command_line}")

        parent_name = os.path.basename(parent_image)
        child_name = os.path.basename(image)
        if parent_name in OFFICE_PARENTS and child_name in LOLBIN_CHILDREN:
            self._add_score(pid, 60, f"Office app '{parent_name}' spawned LOLBin '{child_name}' - likely macro dropper")

    def _handle_process_access(self, data):
        # Event ID 10: Suspicious memory access (PROCESS_VM_WRITE to svchost.exe)
        source_pid = int(data.get('SourceProcessId', 0))
        source_image = data.get('SourceImage', '').lower()
        target_image = data.get('TargetImage', '').lower()
        granted_access = data.get('GrantedAccess', '').lower()

        access_int = _parse_granted_access(granted_access)
        trusted_callers = ('\\windows\\system32\\', '\\windows\\syswow64\\')
        is_trusted_path = any(source_image.startswith(p) or f'c:{p}' in source_image for p in trusted_callers)

        if 'svchost.exe' in target_image and _is_dangerous_access(access_int, HOLLOWING_DANGEROUS_BITS):
            # Signed System32 tools (SCM, WMI, admin utilities) routinely
            # request elevated rights against svchost.exe for legitimate
            # reasons - only score at full severity for untrusted sources.
            score = 15 if is_trusted_path else 50
            context = f"{'Trusted-path' if is_trusted_path else 'Untrusted'} access to {target_image} (Access: {granted_access}) - Potential Process Hollowing"
            self._add_score(source_pid, score, context)

        # LSASS credential-access detection, modeled on Fibratus's
        # credential_access_suspicious_lsass_process_access /
        # credential_access_remote_thread_creation_into_lsass rules: flag
        # OpenProcess handles to lsass.exe carrying rights that let a tool
        # actually read/write its memory or duplicate a handle to it - the
        # capability Mimikatz/procdump-style LSASS dumpers need, regardless
        # of which specific combined mask (0x1010, 0x1410, 0x1438, 0x1fffff,
        # etc.) a given tool happens to request.
        if 'lsass.exe' in target_image and _is_dangerous_access(access_int, LSASS_DANGEROUS_BITS):
            # Signed, known-good tools (Task Manager, Process Explorer/
            # System Informer, WerFault) legitimately open LSASS for
            # diagnostics - only score this when the source isn't one
            # of the well-known OS/AV callers, to keep false positives down.
            score = 30 if is_trusted_path else 70
            context = f"{'Trusted-path' if is_trusted_path else 'Untrusted'} process access to LSASS (Access: {granted_access}) - Potential credential dumping"
            self._add_score(source_pid, score, context)

    def _handle_file_create(self, data):
        # Event ID 11: Ransomware-style rate detector - a burst of file
        # creates/renames from one PID within a short window. Sysmon fires
        # FileCreate on rename-in-place too, which is exactly how most
        # ransomware "writes" (encrypt-to-new-name, delete original).
        #
        # Scoped to known dev-tool/sync-client processes excluded, and to
        # only the document-type folders Controlled Folder Access itself
        # protects by default - a bare rate counter over the whole
        # filesystem can't tell encryption apart from an IDE indexing a
        # workspace, git status, or a build, and live-fire testing proved
        # it: this rule killed VS Code twice before this scoping was added.
        pid = int(data.get('ProcessId', 0))
        image_name = os.path.basename((data.get('Image') or '').lower())
        target = (data.get('TargetFilename') or '').lower()

        if image_name in RANSOMWARE_EXCLUDED_PROCESSES:
            return
        if not any(d in target for d in RANSOMWARE_MONITORED_DIRS):
            return

        window_seconds = self.config['ransomware']['file_event_window_seconds']
        threshold = self.config['ransomware']['file_event_threshold']

        now = time.monotonic()

        timestamps = self._file_event_timestamps[pid]
        timestamps.append(now)
        cutoff = now - window_seconds
        while timestamps and timestamps[0] < cutoff:
            timestamps.pop(0)

        if len(timestamps) == threshold:
            self._add_score(
                pid, 80,
                f"{len(timestamps)} file creates/renames in {window_seconds}s - "
                f"potential mass encryption (ransomware)"
            )

    def _handle_registry_event(self, data):
        # Event ID 13: Unauthorized writes to Run registry keys
        pid = int(data.get('ProcessId', 0))
        target_obj = data.get('TargetObject', '').lower()
        
        if '\\currentversion\\run' in target_obj:
            self._add_score(pid, 40, f"Persistence attempt in Run key: {target_obj}")

    def mitigate(self, pid):
        # Last-resort, unconditional refusal - deliberately redundant with
        # the _add_score guard above. This check must hold even if some
        # future code path ever calls mitigate() directly, bypassing
        # scoring entirely, because the failure mode on the other side of
        # this line isn't "one process dies wrongly" - it's a frozen OS.
        if pid in PROTECTED_PIDS or pid == self._own_pid:
            logging.critical(f"[REFUSED] Refusing to mitigate PID {pid} - protected system PID. Manual review required.")
            return

        try:
            proc = psutil.Process(pid)
            name = proc.name()
        except psutil.NoSuchProcess:
            logging.info(f"[-] Process {pid} no longer exists.")
            return
        except Exception as e:
            logging.error(f"[!] Failed to inspect process {pid} before mitigation: {e}")
            return

        if name.lower() in PROTECTED_PROCESS_NAMES:
            logging.critical(
                f"[REFUSED] Refusing to suspend/terminate PID {pid} ({name}) - protected core OS "
                f"process. Suspending a process like this can freeze or crash the entire system. "
                f"Flagged for manual review instead of auto-mitigating."
            )
            return

        try:
            # Suspend before kill for forensic safety
            proc.suspend()
            proc.terminate()
            logging.info(f"[+] Successfully terminated malicious process: {name} (PID: {pid})")
        except psutil.NoSuchProcess:
            logging.info(f"[-] Process {pid} no longer exists.")
        except Exception as e:
            logging.error(f"[!] Failed to terminate process {pid}: {e}")
