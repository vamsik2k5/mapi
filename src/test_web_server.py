"""Self-check for web_server.py's self-elevation logic - monkeypatches
ShellExecuteW so this never pops a real UAC prompt. Run: python test_web_server.py"""

import os
import subprocess
import sys

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


def test_backend_wires_engine_events_into_process_activity():
    backend = ws.Backend()
    assert backend.engine.on_event == backend.process_activity.add  # bound methods: '==' not 'is'
    backend.engine.evaluate_event(
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System><EventID>1</EventID></System>'
        '<EventData><Data Name="ProcessId">4242</Data><Data Name="Image">calc.exe</Data></EventData>'
        '</Event>'
    )
    rows = backend.process_activity.snapshot()
    assert len(rows) == 1
    assert rows[0]["pid"] == "4242"


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
    test_backend_wires_engine_events_into_process_activity()
    test_dashboard_server_refuses_to_share_a_port()
    print("OK")
