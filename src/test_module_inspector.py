"""
Self-check for module_inspector.py's active sweep: monkeypatches
psutil.process_iter/memory_maps so this never depends on what's actually
running on the machine. Run: python test_module_inspector.py
"""

import module_inspector as mi
from heuristic_engine import HeuristicEngine


class _FakeMap:
    def __init__(self, path):
        self.path = path


class _FakeProc:
    def __init__(self, pid, name, maps):
        self.info = {"pid": pid, "name": name, "exe": None}
        self._maps = maps

    def memory_maps(self):
        return self._maps


def _run_sweep(engine, procs):
    original = mi.psutil.process_iter
    mi.psutil.process_iter = lambda attrs=None: iter(procs)
    try:
        inspector = mi.ModuleInspector(engine)
        inspector.sweep()
        return inspector
    finally:
        mi.psutil.process_iter = original


def test_high_value_process_with_staged_module_scores_full():
    engine = HeuristicEngine()
    proc = _FakeProc(7001, "svchost.exe", [_FakeMap(r"C:\Windows\Temp\payload.dll")])
    _run_sweep(engine, [proc])
    assert engine.process_scores[7001] == 60


def test_ordinary_process_with_staged_module_scores_reduced():
    engine = HeuristicEngine()
    proc = _FakeProc(7002, "mytool.exe", [_FakeMap(r"C:\Users\Public\payload.dll")])
    _run_sweep(engine, [proc])
    assert engine.process_scores[7002] == 35


def test_module_from_normal_path_scores_nothing():
    engine = HeuristicEngine()
    proc = _FakeProc(7003, "svchost.exe", [_FakeMap(r"C:\Windows\System32\ntdll.dll")])
    _run_sweep(engine, [proc])
    assert 7003 not in engine.process_scores


def test_non_dll_paths_are_ignored():
    engine = HeuristicEngine()
    proc = _FakeProc(7004, "svchost.exe", [_FakeMap(r"C:\Windows\Temp\notes.txt")])
    _run_sweep(engine, [proc])
    assert 7004 not in engine.process_scores


def test_repeated_sweep_does_not_double_count_the_same_finding():
    engine = HeuristicEngine()
    proc = _FakeProc(7005, "svchost.exe", [_FakeMap(r"C:\Windows\Temp\payload.dll")])
    inspector = None
    original = mi.psutil.process_iter
    mi.psutil.process_iter = lambda attrs=None: iter([proc])
    try:
        inspector = mi.ModuleInspector(engine)
        inspector.sweep()
        first_score = engine.process_scores[7005]
        inspector.sweep()  # second sweep, same finding
        assert engine.process_scores[7005] == first_score, "a repeated sweep must not re-flag the same (pid, module) pair"
    finally:
        mi.psutil.process_iter = original


def test_access_denied_process_is_skipped_not_crashed():
    class _DeniedProc:
        info = {"pid": 7006, "name": "locked.exe", "exe": None}

        def memory_maps(self):
            raise mi.psutil.AccessDenied()

    engine = HeuristicEngine()
    _run_sweep(engine, [_DeniedProc()])  # must not raise
    assert 7006 not in engine.process_scores


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
