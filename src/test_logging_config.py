"""
Regression check for a real bug found via live testing: importing
etw_monitor (which pulls in pywintrace's etw/common.py) calls
logging.basicConfig(level=logging.ERROR) as an import-time side effect.
logging.basicConfig() is a no-op once any handler exists, so main.py's and
web_server.py's own basicConfig call would silently lose - leaving every
INFO-level log (the entire static scan, rule loading, sensor startup)
invisible - unless it passes force=True. This must run in a subprocess:
logging config is global interpreter state, and other test files in this
suite already import modules that configure it, which would mask the bug
if checked in-process. Run: python test_logging_config.py
"""

import os
import subprocess
import sys

_SRC_DIR = os.path.dirname(os.path.abspath(__file__))

_PROBE = """
import logging
from etw_monitor import start_etw_monitor  # import-time side effect: basicConfig(level=ERROR)

# Without force=True, this call is a documented no-op once a handler
# already exists - exactly what the import above just did.
logging.basicConfig(level=logging.INFO, format='[*] %(message)s', force=True)

logging.info('probe info line')
"""


def test_force_true_recovers_our_own_logging_config_after_etw_import():
    result = subprocess.run(
        [sys.executable, "-c", _PROBE],
        cwd=_SRC_DIR,
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "[*] probe info line" in result.stderr, f"expected our custom format+level to win; got stdout={result.stdout!r} stderr={result.stderr!r}"


def test_without_force_the_bug_reproduces():
    # Documents the bug this test file guards against: the exact same call
    # minus force=True silently loses to etw.common's import-time config.
    probe_without_force = _PROBE.replace(", force=True", "")
    result = subprocess.run(
        [sys.executable, "-c", probe_without_force],
        cwd=_SRC_DIR,
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "[*] probe info line" not in result.stderr, "if this now passes, either the bug is gone or basicConfig's no-op behavior changed - update test_force_true_recovers_our_own_logging_config_after_etw_import's justification"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
