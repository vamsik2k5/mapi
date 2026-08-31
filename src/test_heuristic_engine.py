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


# ---- known-good hash allowlist ---------------------------------------------

def test_allowlisted_hash_suppresses_static_score():
    engine = HeuristicEngine(known_good_hashes={"deadbeef": {"reason": "verified vendor installer"}})
    engine.add_static_score("deadbeef", 90, "should be ignored")
    assert "deadbeef" not in engine.static_scores


def test_non_allowlisted_hash_scores_normally():
    engine = HeuristicEngine(known_good_hashes={"deadbeef": {"reason": "test"}})
    engine.add_static_score("cafebabe", 40, "unrelated finding")
    assert engine.static_scores["cafebabe"] == 40


def test_allowlist_suppresses_across_multiple_findings_for_the_same_hash():
    # The allowlist check lives in add_static_score() itself, so it must
    # suppress every call for that hash, not just the first.
    engine = HeuristicEngine(known_good_hashes={"deadbeef": {"reason": "test"}})
    engine.add_static_score("deadbeef", 30, "finding one")
    engine.add_static_score("deadbeef", 40, "finding two")
    engine.add_static_score("deadbeef", 50, "finding three")
    assert "deadbeef" not in engine.static_scores


def test_is_allowlisted_helper():
    engine = HeuristicEngine(known_good_hashes={"deadbeef": {"reason": "test"}})
    assert engine.is_allowlisted("deadbeef") is True
    assert engine.is_allowlisted("cafebabe") is False


def test_default_engine_has_no_allowlist_entries():
    # data/known_good_hashes.json won't exist in a normal checkout/test run
    # - the loader must fail open to an empty allowlist, not crash and not
    # suppress everything.
    engine = HeuristicEngine()
    assert engine.known_good_hashes == {}
    engine.add_static_score("anyhash", 30, "must still score normally")
    assert engine.static_scores["anyhash"] == 30


def test_load_known_good_hashes_missing_file_returns_empty():
    import os
    import tempfile
    missing_path = os.path.join(tempfile.gettempdir(), "definitely_does_not_exist_xyz.json")
    assert he._load_known_good_hashes(missing_path) == {}


def test_load_known_good_hashes_malformed_file_returns_empty():
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write("{not valid json")
        path = f.name
    try:
        assert he._load_known_good_hashes(path) == {}
    finally:
        import os
        os.unlink(path)


# ---- evaluate_etw_process_start (ETW Kernel-Process sensor) ---------------

def test_etw_process_start_scores_staging_dir_rule():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_etw_process_start(pid, parent_pid=1, image_name=r"C:\Users\bob\AppData\Local\Temp\evil.exe")
    assert engine.process_scores[pid] == 30


def test_etw_process_start_counts_toward_heartbeat():
    engine = HeuristicEngine()
    before = engine.total_events_seen
    engine.evaluate_etw_process_start(fresh_pid(), parent_pid=1, image_name=r"C:\Windows\System32\notepad.exe")
    assert engine.total_events_seen == before + 1
    assert engine.last_event_time is not None


def test_etw_process_start_respects_protected_floor():
    engine = HeuristicEngine()
    engine.evaluate_etw_process_start(4, parent_pid=1, image_name=r"C:\Users\bob\AppData\Local\Temp\evil.exe")
    assert 4 not in engine.process_scores


def test_etw_process_start_tags_source():
    # _dispatch's on_event hook is how Process Explorer would see this -
    # confirm the '_source' tag a dashboard needs is actually present.
    seen = []
    engine = HeuristicEngine()
    engine.on_event = lambda event_id, data: seen.append(data)
    engine.evaluate_etw_process_start(fresh_pid(), parent_pid=1, image_name=r"C:\Windows\System32\notepad.exe")
    assert len(seen) == 1
    assert seen[0]['_source'] == 'etw'


def test_etw_process_start_cannot_fire_command_line_dependent_rules():
    # The real, permanent capability gap versus Sysmon: raw kernel
    # ProcessStart has no CommandLine, so a command-line rule structurally
    # cannot match - this is the documented boundary, verified as a test,
    # not just a comment.
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_etw_process_start(
        pid, parent_pid=1,
        image_name=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    )
    assert pid not in engine.process_scores, "no CommandLine was ever supplied, so Defender-tamper/PowerShell-abuse cannot fire"


def test_evaluate_etw_process_start_never_raises_on_bad_input():
    engine = HeuristicEngine()
    engine.evaluate_etw_process_start(None, parent_pid=None, image_name=None)  # must not raise


# ---- _dispatch regression: evaluate_event behavior is unchanged -----------

def test_dispatch_extraction_preserves_evaluate_event_behavior():
    # Same scenario as test_execution_from_staging_directory, run through
    # the real XML entry point - proves the _dispatch extraction didn't
    # change evaluate_event()'s observable behavior.
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine.evaluate_event(event(1, ProcessId=pid, Image=r"C:\Users\bob\AppData\Local\Temp\evil.exe"))
    assert engine.process_scores[pid] == 30


def test_dispatch_extraction_preserves_heartbeat_even_without_event_data():
    # Original evaluate_event() increments the heartbeat as soon as
    # EventID parses, *before* checking whether EventData exists - this
    # locks that exact ordering in so a future refactor can't silently
    # move the heartbeat "inside" _dispatch and stop counting this case.
    engine = HeuristicEngine()
    before = engine.total_events_seen
    xml = f'<Event xmlns="{NS}"><System><EventID>1</EventID></System></Event>'  # no EventData at all
    engine.evaluate_event(xml)
    assert engine.total_events_seen == before + 1


# ---- dedup guard (_score_once) --------------------------------------------

def test_score_once_with_no_dedup_key_behaves_exactly_like_add_score():
    engine = HeuristicEngine()
    pid = fresh_pid()
    scored = engine._score_once(None, 'some_check', pid, 25, 'test')
    assert scored is True
    assert engine.process_scores[pid] == 25


def test_score_once_deduplicates_same_check_and_key():
    engine = HeuristicEngine()
    pid = fresh_pid()
    key = (pid, 12345.6)
    first = engine._score_once(key, 'staging_dir', pid, 30, 'first dispatch')
    second = engine._score_once(key, 'staging_dir', pid, 30, 'second dispatch of the same event')
    assert first is True
    assert second is False
    assert engine.process_scores[pid] == 30, "the duplicate must not add another 30"


def test_score_once_allows_a_different_check_under_the_same_key():
    # This is the actual point of keying by (dedup_key, check_id) rather
    # than dedup_key alone: the fused dispatch's NEW command-line-dependent
    # finding must still score even though the provisional dispatch already
    # scored a different (path-based) check under the same key. Scores
    # are chosen to stay under the critical threshold so this test isn't
    # confounded by mitigate()'s reset-to-0 (see test_handle_process_create_dedup_end_to_end
    # for a case that deliberately crosses it).
    engine = HeuristicEngine()
    pid = fresh_pid()
    key = (pid, 12345.6)
    engine._score_once(key, 'staging_dir', pid, 30, 'provisional: path-based')
    scored = engine._score_once(key, 'powershell_abuse', pid, 45, 'fused: command-line-based')
    assert scored is True
    assert abs(engine.process_scores[pid] - 75) < 0.01, "decay between back-to-back calls is expected to shave a negligible fraction"


def test_score_once_different_keys_are_independent():
    engine = HeuristicEngine()
    pid = fresh_pid()
    engine._score_once((pid, 1.0), 'staging_dir', pid, 30, 'event A')
    scored = engine._score_once((pid, 2.0), 'staging_dir', pid, 30, 'event B - different create_time, different real event')
    assert scored is True
    assert abs(engine.process_scores[pid] - 60) < 0.01


def test_handle_process_create_dedup_end_to_end():
    # Simulates the correlator's provisional-then-fused pair for the same
    # real event via the actual _handle_process_create path, not just
    # _score_once directly.
    engine = HeuristicEngine()
    pid = fresh_pid()
    dedup_key = (pid, 999.9)
    provisional = {'ProcessId': pid, 'Image': r'C:\Users\bob\AppData\Local\Temp\evil.exe', '_dedup_key': dedup_key}
    fused = {'ProcessId': pid, 'Image': r'C:\Users\bob\AppData\Local\Temp\evil.exe',
             'CommandLine': 'powershell -enc aGVsbG8=', '_dedup_key': dedup_key}
    engine._handle_process_create(provisional)
    engine._handle_process_create(fused)
    # staging_dir (30) once + powershell_abuse (45) once = 75, NOT 30+30+45
    assert abs(engine.process_scores[pid] - 75) < 0.01


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
