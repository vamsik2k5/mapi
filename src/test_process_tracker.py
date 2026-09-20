"""Self-check for process_tracker.py. Run: python test_process_tracker.py"""

from process_tracker import ProcessTracker


def _create(pid, ppid, image):
    return (1, {'ProcessId': str(pid), 'ParentProcessId': str(ppid) if ppid is not None else None, 'Image': image})


def test_chain_resolves_three_generations():
    t = ProcessTracker()
    t.add(*_create(1, None, r'C:\Windows\explorer.exe'))
    t.add(*_create(2, 1, r'C:\Windows\System32\cmd.exe'))
    t.add(*_create(3, 2, r'C:\Users\bob\evil.exe'))
    assert t.get_chain(3) == [r'C:\Windows\explorer.exe', r'C:\Windows\System32\cmd.exe', r'C:\Users\bob\evil.exe']


def test_lineage_string_uses_basenames():
    t = ProcessTracker()
    t.add(*_create(1, None, r'C:\Windows\explorer.exe'))
    t.add(*_create(2, 1, r'C:\Windows\System32\cmd.exe'))
    assert t.lineage_string(2) == 'explorer.exe -> cmd.exe'


def test_untracked_pid_yields_empty_chain():
    t = ProcessTracker()
    assert t.get_chain(999) == []
    assert t.lineage_string(999) == ''


def test_untracked_ancestor_truncates_chain_gracefully():
    t = ProcessTracker()
    # pid 2's parent (pid 1) was never observed - chain should stop there,
    # not crash or loop.
    t.add(*_create(2, 1, r'C:\evil.exe'))
    assert t.get_chain(2) == [r'C:\evil.exe']


def test_cycle_does_not_infinite_loop():
    t = ProcessTracker()
    t.add(*_create(1, 2, 'a.exe'))
    t.add(*_create(2, 1, 'b.exe'))  # artificial cycle: 1 <-> 2
    chain = t.get_chain(1, max_depth=10)
    assert len(chain) <= 10  # terminates rather than looping forever


def test_ignores_non_process_create_events():
    t = ProcessTracker()
    t.add(10, {'SourceProcessId': '1'})  # ProcessAccess, not ProcessCreate
    assert t.get_chain(1) == []


def test_bounded_eviction_drops_oldest():
    t = ProcessTracker(max_entries=3)
    for pid in range(1, 6):
        t.add(*_create(pid, None, f'{pid}.exe'))
    # only the 3 most recently added PIDs should remain trackable
    assert t.get_chain(1) == []
    assert t.get_chain(5) == ['5.exe']


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
