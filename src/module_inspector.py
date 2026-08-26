"""
Active process/module provenance sweep, inspired by System Informer's
process/module enumeration view (winsiderss/systeminformer): where the
Sysmon-driven telemetry_monitor.py is passive/event-driven, this module
periodically walks the *current* process table and inspects what's already
mapped into each process, catching injected modules that loaded before
monitoring started or that Sysmon config doesn't cover.
"""

import logging
import psutil

# Paths a legitimate, unpacked DLL should basically never load from.
# Modules mapped into a process from here are consistent with a dropper
# staging a payload and DLL-injecting/side-loading it into a running
# process, rather than a compiler-emitted, installed dependency.
#
# ProgramData was in this list originally but live-fire testing pulled it
# in three unrelated legitimate cases in a single run (Windows Defender's
# own platform DLLs, Visual Studio's installer component, and Windows
# Terminal's MSIX AppRepository packaged-COM proxy DLL - the last one even
# crossed the WARNING threshold). Unlike Temp/Public, ProgramData is
# routinely and legitimately used by installers, MSIX package machinery,
# and OEM vendor software for exactly this kind of shared component, so it
# isn't a good staging-directory signal on its own - dropped rather than
# chasing an endless per-vendor allowlist.
SUSPICIOUS_MODULE_DIRS = (
    '\\appdata\\local\\temp\\',
    '\\windows\\temp\\',
    '\\users\\public\\',
    '\\recycle.bin\\',
)

# System processes worth extra scrutiny if they carry modules from the
# paths above - these are exactly the "living off the land" hollowing/
# injection targets Fibratus's defense-evasion rules watch (svchost.exe,
# explorer.exe, lsass.exe, spoolsv.exe, taskhostw.exe, etc).
HIGH_VALUE_TARGETS = (
    'svchost.exe', 'explorer.exe', 'lsass.exe', 'spoolsv.exe',
    'taskhostw.exe', 'winlogon.exe', 'services.exe', 'dwm.exe',
)


class ModuleInspector:
    def __init__(self, engine):
        self.engine = engine
        # (pid, module_path) pairs already scored, so a repeated sweep
        # doesn't re-flag (and re-mitigate-threshold) the same finding.
        self._seen = set()

    def sweep(self):
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                self._inspect_process(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _inspect_process(self, proc):
        pid = proc.info['pid']
        name = (proc.info['name'] or '').lower()

        try:
            maps = proc.memory_maps()
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            return

        for m in maps:
            path = (m.path or '').lower()
            if not path or not path.endswith('.dll'):
                continue

            if any(bad_dir in path for bad_dir in SUSPICIOUS_MODULE_DIRS):
                key = (pid, path)
                if key in self._seen:
                    continue
                self._seen.add(key)

                is_high_value = name in HIGH_VALUE_TARGETS
                score = 60 if is_high_value else 35
                context = (
                    f"{'High-value target' if is_high_value else 'Process'} "
                    f"'{name}' (PID {pid}) has module loaded from staging path: {path}"
                )
                logging.warning(f"[MODULE] {context}")
                self.engine._add_score(pid, score, context)
