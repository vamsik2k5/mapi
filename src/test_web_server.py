"""Self-check for web_server.py's self-elevation logic - monkeypatches
ShellExecuteW so this never pops a real UAC prompt. Run: python test_web_server.py"""

import os
import subprocess
import sys
import time

import web_server as ws


class _FakeShell32:
    def __init__(self, return_value=None, raises=None):
        self.return_value = return_value
        self.raises = raises
        self.calls = []

    def ShellExecuteW(self, hwnd, op, exe, params, cwd, show):
        self.calls.append((hwnd, op, exe, params, cwd, show))
        if self.raises:
            raise self.raises
        return self.return_value


def test_relaunch_success_uses_absolute_script_path_and_cwd():
    fake = _FakeShell32(return_value=42)  # ShellExecuteW: >32 means success
    ws.ctypes.windll.shell32 = fake
    sys.argv = ["web_server.py", "--extra"]

    assert ws._relaunch_elevated() is True
    _, op, exe, params, cwd, _ = fake.calls[0]
    assert op == "runas"
    assert exe == sys.executable
    assert cwd == os.getcwd()
    expected_script = os.path.abspath("web_server.py")
    assert params == subprocess.list2cmdline([expected_script, "--extra"])


def test_relaunch_declined_returns_false():
    ws.ctypes.windll.shell32 = _FakeShell32(return_value=5)  # UAC declined / access denied
    assert ws._relaunch_elevated() is False


def test_relaunch_exception_returns_false_not_raises():
    ws.ctypes.windll.shell32 = _FakeShell32(raises=OSError("boom"))
    assert ws._relaunch_elevated() is False


class _FakeResponse:
    def __init__(self, status):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_wait_for_dashboard_true_when_reachable():
    ws.urllib.request.urlopen = lambda url, timeout=1: _FakeResponse(200)
    assert ws._wait_for_dashboard(timeout=0) is True


def test_wait_for_dashboard_false_when_unreachable():
    def _raise(url, timeout=1):
        raise ws.urllib.error.URLError("connection refused")
    ws.urllib.request.urlopen = _raise
    assert ws._wait_for_dashboard(timeout=0) is False


def test_process_activity_store_captures_process_create_only():
    store = ws.ProcessActivityStore()
    store.add(1, {"ProcessId": "123", "Image": r"C:\Windows\System32\notepad.exe", "ParentImage": r"C:\Windows\explorer.exe", "CommandLine": "notepad.exe", "User": "DESKTOP\\bob"})
    store.add(10, {"SourceProcessId": "999"})  # not a ProcessCreate event - must be ignored
    rows = store.snapshot()
    assert len(rows) == 1
    assert rows[0]["pid"] == "123"
    assert rows[0]["image"] == r"C:\Windows\System32\notepad.exe"


def test_process_activity_store_newest_first_and_bounded():
    store = ws.ProcessActivityStore(maxlen=2)
    for pid in ("1", "2", "3"):
        store.add(1, {"ProcessId": pid, "Image": "x.exe"})
    rows = store.snapshot()
    assert len(rows) == 2, "maxlen must actually bound the buffer"
    assert [r["pid"] for r in rows] == ["3", "2"], "newest event must be first"


def test_backend_wires_engine_events_into_process_activity_and_tracker():
    backend = ws.Backend()
    assert backend.engine.on_event == backend._on_raw_event  # bound methods: '==' not 'is'
    # Backend wires a ProcessCorrelator unconditionally (see process_correlator.py),
    # so a ProcessCreate event no longer dispatches synchronously - it's held
    # for up to fuse_window in case a matching ETW event arrives to fuse
    # with. Shrink the window and drive the GC directly instead of sleeping
    # out the real (2s) default in a test.
    backend.correlator.fuse_window = 0.01
    backend.engine.evaluate_event(
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System><EventID>1</EventID></System>'
        '<EventData><Data Name="ProcessId">4242</Data><Data Name="ParentProcessId">1</Data>'
        '<Data Name="Image">calc.exe</Data></EventData>'
        '</Event>'
    )
    time.sleep(0.02)
    backend.correlator._gc_once()
    rows = backend.process_activity.snapshot()
    assert len(rows) == 1
    assert rows[0]["pid"] == "4242"
    # the same fan-out point must also have fed the lineage tracker
    assert backend.process_tracker.get_chain(4242) == ["calc.exe"]


def test_backend_constructs_rule_engine_and_config():
    backend = ws.Backend()
    assert backend.engine.rule_engine is backend.rules
    assert backend.engine.config is backend.config
    # RuleEngine() picks up the real rules/custom/*.yml, which ships with
    # one example rule - a real, non-mocked integration check that the
    # shipped example actually loads.
    ids = [r['id'] for r in backend.rules.summary()]
    assert 'custom_lolbin_from_appdata_roaming' in ids


def test_rules_endpoint_reflects_rule_engine_summary():
    backend = ws.Backend()
    baseline_count = len(backend.rules.summary())
    # simulate an additional loaded rule without needing a real YAML file on disk
    from rule_engine import Rule
    fake_rule = Rule({'id': 'r1', 'applies_to': 'process_create', 'score': 10,
                       'match': {'all': [{'field': 'image', 'op': 'contains', 'value': 'x'}]}}, source_file='<test>')
    backend.rules.rules.append(fake_rule)
    backend.rules.hit_counts['r1'] = 0
    summary = backend.rules.summary()
    assert len(summary) == baseline_count + 1
    assert any(r['id'] == 'r1' for r in summary)


def test_dashboard_server_refuses_to_share_a_port():
    # The bug this guards against: http.server's default
    # allow_reuse_address=True let two separate elevated instances bind
    # 127.0.0.1:8787 at once on Windows, silently round-robining requests
    # across two different HeuristicEngine states. A second instance must
    # fail loudly (Address already in use), never coexist silently.
    assert ws.DashboardServer.allow_reuse_address is False


if __name__ == "__main__":
    test_relaunch_success_uses_absolute_script_path_and_cwd()
    test_relaunch_declined_returns_false()
    test_relaunch_exception_returns_false_not_raises()
    test_wait_for_dashboard_true_when_reachable()
    test_wait_for_dashboard_false_when_unreachable()
    test_process_activity_store_captures_process_create_only()
    test_process_activity_store_newest_first_and_bounded()
    test_backend_wires_engine_events_into_process_activity_and_tracker()
    test_backend_constructs_rule_engine_and_config()
    test_rules_endpoint_reflects_rule_engine_summary()
    test_dashboard_server_refuses_to_share_a_port()
    print("OK")
