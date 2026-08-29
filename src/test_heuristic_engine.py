"""
Exhaustive self-check for heuristic_engine.py: exercises every behavioral
rule in the README's detection table, plus the safety floor (protected
processes, decay, PID-reuse guard, mitigate()). Uses the same
synthetic-Sysmon-XML technique README documents for testing a rule without
a live attack. Run: python test_heuristic_engine.py
"""

import subprocess
import sys
import time

import psutil

import heuristic_engine as he
from heuristic_engine import HeuristicEngine

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def event(event_id, **fields):
    data = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in fields.items())
    return f'<Event xmlns="{NS}"><System><EventID>{event_id}</EventID></System><EventData>{data}</EventData></Event>'


def fresh_pid():
    """A PID number guaranteed not to belong to a real process, so
    _is_protected/_reset_score_if_pid_reused treat it as an ordinary,
    unprotected, non-reused process."""
    fresh_pid.counter += 1
    return 900000 + fresh_pid.counter


fresh_pid.counter = 0


# ---- EventID 1: ProcessCreate ---------------------------------------------

def test_execution_from_staging_directory():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(1, ProcessId=pid, Image=r"C:\Users\bob\AppData\Local\Temp\evil.exe"))
    assert engine.process_scores[pid] == 30


def test_defender_tamper_command_line():
    # +90 alone crosses the >=80 mitigation threshold in one shot, so
    # _check_threshold() calls mitigate() (a no-op against this fake PID)
    # and resets the score to 0 - that reset to 0 is the correct, designed
    # outcome for a single-event critical, not a sign scoring didn't happen.
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(1, ProcessId=pid, Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                 CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"))
    assert engine.process_scores[pid] == 0


def test_powershell_obfuscation():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(1, ProcessId=pid, Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                 CommandLine="powershell -WindowStyle Hidden -EncodedCommand aQBlAHgA"))
    assert engine.process_scores[pid] == 45


def test_office_macro_dropper_chain():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(1, ProcessId=pid, Image=r"C:\Windows\System32\cmd.exe",
                                 ParentImage=r"C:\Program Files\Microsoft Office\WINWORD.EXE", CommandLine="cmd.exe /c whoami"))
    assert engine.process_scores[pid] == 60


def test_benign_launch_scores_nothing_but_still_counts_as_seen():
    engine = HeuristicEngine()
    pid = fresh_pid()
    before = engine.total_events_seen
    engine.evaluate_event(event(1, ProcessId=pid, Image=r"C:\Windows\System32\notepad.exe", ParentImage=r"C:\Windows\explorer.exe", CommandLine="notepad.exe"))
    assert pid not in engine.process_scores
    assert engine.total_events_seen == before + 1
    assert engine.last_event_time is not None


# ---- EventID 10: ProcessAccess --------------------------------------------

def test_hollowing_untrusted_source_scores_full():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(10, SourceProcessId=pid, SourceImage=r"C:\Users\bob\AppData\Local\Temp\evil.exe",
                                 TargetImage=r"C:\Windows\System32\svchost.exe", GrantedAccess="0x2A"))
    assert engine.process_scores[pid] == 50


def test_hollowing_trusted_path_source_scores_reduced():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(10, SourceProcessId=pid, SourceImage=r"C:\Windows\System32\wbem\WmiPrvSE.exe",
                                 TargetImage=r"C:\Windows\System32\svchost.exe", GrantedAccess="0x2A"))
    assert engine.process_scores[pid] == 15


def test_hollowing_ignores_query_only_access():
    # Regression test for the exact false positive documented in
    # heuristic_engine.py: PROCESS_QUERY_LIMITED_INFORMATION (0x1000) alone
    # is not evidence of hollowing and must not score.
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(10, SourceProcessId=pid, SourceImage=r"C:\Windows\System32\wbem\WmiPrvSE.exe",
                                 TargetImage=r"C:\Windows\System32\svchost.exe", GrantedAccess="0x1000"))
    assert pid not in engine.process_scores


def test_lsass_untrusted_source_scores_full():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(10, SourceProcessId=pid, SourceImage=r"C:\Users\bob\AppData\Local\Temp\mimikatz.exe",
                                 TargetImage=r"C:\Windows\System32\lsass.exe", GrantedAccess="0x1010"))
    assert engine.process_scores[pid] == 70


def test_lsass_trusted_path_source_scores_reduced():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(10, SourceProcessId=pid, SourceImage=r"C:\Windows\System32\taskmgr.exe",
                                 TargetImage=r"C:\Windows\System32\lsass.exe", GrantedAccess="0x1010"))
    assert engine.process_scores[pid] == 30


def test_lsass_ignores_query_only_access():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(10, SourceProcessId=pid, SourceImage=r"C:\Users\bob\AppData\Local\Temp\tool.exe",
                                 TargetImage=r"C:\Windows\System32\lsass.exe", GrantedAccess="0x1000"))
    assert pid not in engine.process_scores


# ---- EventID 11: FileCreate (ransomware burst) ----------------------------

def test_ransomware_burst_fires_at_threshold():
    # +80 also crosses the mitigation threshold in one shot - see the
    # comment in test_defender_tamper_command_line about the reset to 0.
    engine = HeuristicEngine()
    pid = fresh_pid()
    for i in range(he.RANSOMWARE_FILE_EVENT_THRESHOLD):
        engine.evaluate_event(event(11, ProcessId=pid, Image=r"C:\Users\bob\ransom.exe",
                                     TargetFilename=fr"C:\Users\bob\Documents\file{i}.locked"))
    assert engine.process_scores[pid] == 0


def test_ransomware_burst_ignores_excluded_dev_tools():
    engine = HeuristicEngine()
    pid = fresh_pid()
    for i in range(he.RANSOMWARE_FILE_EVENT_THRESHOLD):
        engine.evaluate_event(event(11, ProcessId=pid, Image=r"C:\Program Files\Microsoft VS Code\Code.exe",
                                     TargetFilename=fr"C:\Users\bob\Documents\file{i}.txt"))
    assert pid not in engine.process_scores, "VS Code indexing Documents must never look like ransomware"


def test_ransomware_burst_ignores_files_outside_monitored_dirs():
    engine = HeuristicEngine()
    pid = fresh_pid()
    for i in range(he.RANSOMWARE_FILE_EVENT_THRESHOLD):
        engine.evaluate_event(event(11, ProcessId=pid, Image=r"C:\Users\bob\tool.exe",
                                     TargetFilename=fr"C:\mal_project\.venv\Lib\file{i}.pyc"))
    assert pid not in engine.process_scores


# ---- EventID 13: RegistryEvent (persistence) ------------------------------

def test_run_key_persistence():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(13, ProcessId=pid, TargetObject=r"HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\Updater"))
    assert engine.process_scores[pid] == 40


# ---- Safety floor: protected processes ------------------------------------

def test_protected_pid_never_scored():
    engine = HeuristicEngine()
    engine._add_score(4, 1000, "should be ignored")  # PID 4 = System
    assert 4 not in engine.process_scores


def test_protected_process_name_never_scored():
    engine = HeuristicEngine()
    pid = fresh_pid()
    original = he.psutil.Process
    he.psutil.Process = lambda p: type("F", (), {"name": lambda self: "csrss.exe"})()
    try:
        engine._add_score(pid, 1000, "should be ignored")
    finally:
        he.psutil.Process = original
    assert pid not in engine.process_scores


def test_own_pid_never_scored():
    engine = HeuristicEngine()
    engine._add_score(engine._own_pid, 1000, "should be ignored")
    assert engine._own_pid not in engine.process_scores


# ---- Score decay + PID-reuse guard ----------------------------------------

def test_score_decays_over_time():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine._add_score(pid, 60, "initial")
    assert engine.process_scores[pid] == 60
    # Simulate 30 elapsed seconds without touching the monotonic clock.
    engine._last_score_time[pid] -= 30
    engine._apply_decay(pid)
    expected = 60 - 30 * he.SCORE_DECAY_PER_SECOND
    assert abs(engine.process_scores[pid] - expected) < 0.01


def test_pid_reuse_discards_old_score():
    engine = HeuristicEngine()
    pid = fresh_pid()
    original = he.psutil.Process
    try:
        he.psutil.Process = lambda p: type("F", (), {"create_time": lambda self: 100.0, "name": lambda self: "old.exe"})()
        engine._add_score(pid, 50, "first process")
        assert engine.process_scores[pid] == 50

        he.psutil.Process = lambda p: type("F", (), {"create_time": lambda self: 200.0, "name": lambda self: "new.exe"})()
        engine._add_score(pid, 10, "different process, same PID")
        assert engine.process_scores[pid] == 10, "a PID reused by a new OS process must not inherit the old score"
    finally:
        he.psutil.Process = original


# ---- Threshold -> mitigate() wiring, and mitigate() itself ----------------

def test_threshold_crossing_calls_mitigate_and_resets():
    engine = HeuristicEngine()
    pid = fresh_pid()  # doesn't correspond to a real process
    engine._add_score(pid, 85, "over the mitigation threshold")
    assert engine.process_scores[pid] == 0, "mitigate() should reset the score even though the fake PID can't really be killed"


def test_mitigate_refuses_protected_pid():
    engine = HeuristicEngine()
    engine.mitigate(4)  # must not raise, must not touch anything


def test_mitigate_refuses_protected_name():
    engine = HeuristicEngine()
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        original = he.psutil.Process
        he.psutil.Process = lambda p: type("F", (), {"name": lambda self: "csrss.exe"})()
        try:
            engine.mitigate(proc.pid)
        finally:
            he.psutil.Process = original
        assert psutil.pid_exists(proc.pid), "a process merely reported as csrss.exe must never actually be touched"
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_mitigate_actually_terminates_a_real_disposable_process():
    engine = HeuristicEngine()
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    time.sleep(0.3)
    engine.mitigate(proc.pid)
    proc.wait(timeout=5)
    assert not psutil.pid_exists(proc.pid)


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
