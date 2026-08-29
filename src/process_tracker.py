"""
In-memory parent/child process lineage tracker (Velociraptor's process-
tracker pattern, simplified): built incrementally from ProcessCreate
events, resolving a PID's ancestor chain by PID linkage
(ParentProcessId) rather than by parent image path, which Sysmon also
provides but nothing else in this project currently reads.

Purely additive and display-only - never scores anything, never touches
HeuristicEngine. Feeds the web dashboard's Process Explorer "Lineage"
column.
"""

import os
import time
from collections import OrderedDict

DEFAULT_MAX_ENTRIES = 2000
DEFAULT_MAX_DEPTH = 10


class ProcessTracker:
    def __init__(self, max_entries=DEFAULT_MAX_ENTRIES):
        self.max_entries = max_entries
        # pid -> {"image": str|None, "ppid": int|None, "ts": float}.
        # OrderedDict so a bounded eviction can drop the least-recently-
        # updated entry first, same "bounded ring buffer" spirit as
        # AlertStore/ProcessActivityStore in web_server.py.
        self._entries = OrderedDict()

    def add(self, event_id, data):
        if event_id != 1:  # ProcessCreate only
            return
        try:
            pid = int(data.get('ProcessId', 0))
        except (TypeError, ValueError):
            return

        ppid_raw = data.get('ParentProcessId')
        try:
            ppid = int(ppid_raw) if ppid_raw is not None else None
        except (TypeError, ValueError):
            ppid = None

        self._entries[pid] = {'image': data.get('Image'), 'ppid': ppid, 'ts': time.time()}
        self._entries.move_to_end(pid)
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)

    def get_chain(self, pid, max_depth=DEFAULT_MAX_DEPTH):
        """Image names from the oldest known ancestor down to `pid` itself
        (inclusive), stopping at an untracked ancestor, a cycle, or
        max_depth. Empty list if `pid` itself was never observed."""
        chain = []
        current = pid
        seen = set()
        for _ in range(max_depth):
            if current is None or current in seen:
                break
            seen.add(current)
            entry = self._entries.get(current)
            if entry is None:
                break
            chain.append(entry['image'] or f'pid:{current}')
            current = entry['ppid']
        chain.reverse()
        return chain

    def lineage_string(self, pid, max_depth=DEFAULT_MAX_DEPTH):
        """'explorer.exe -> cmd.exe -> evil.exe'-style summary for display,
        basenames only (full paths would make the dashboard column
        unreadably wide)."""
        names = [os.path.basename(c) if isinstance(c, str) else c for c in self.get_chain(pid, max_depth=max_depth)]
        return ' -> '.join(names)
