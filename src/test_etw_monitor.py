"""
Self-check for etw_monitor.py's event-pump/scoring decoupling and task-name
filtering. No real elevated ETW trace session - callback is invoked directly
with synthetic (event_id, event_dict) tuples shaped like pywintrace's actual
output. Run: python test_etw_monitor.py
"""

import logging
import queue
import threading
import time

import etw_monitor as em


class _FakeEngine:
    def __init__(self, on_evaluate=None):
        self.calls = []
        self.on_evaluate = on_evaluate

    def evaluate_etw_process_start(self, pid, parent_pid, image_name, create_time):
        self.calls.append((pid, parent_pid, image_name, create_time))
        if self.on_evaluate:
            self.on_evaluate()


def _wait_until(predicate, timeout=2.0, interval=0.01):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def _process_start_event(pid=1234, parent_pid=1, image_name="evil.exe", create_time=100.0, task_name="PROCESSSTART"):
    return (1, {
        "Task Name": task_name,
        "EventHeader": {"EventDescriptor": {"Task": em.TASK_PROCESS_START}},
        "ProcessID": pid,
        "ParentProcessID": parent_pid,
        "ImageName": image_name,
        "CreateTime": create_time,
    })


def test_pywintrace_internal_warnings_are_silenced():
    # Confirmed on a real elevated run: pywintrace's own logger
    # (etw/etw.py -> "etw.etw") emits a WARNING for every single field TDH
    # fails to format (e.g. Flags/SecurityMitigations on a real
    # ProcessStart event) - harmless per pywintrace's own handling, but
    # without this suppression every process launch on the system would
    # add these as dashboard alerts via AlertLogHandler on the root logger.
    # An ERROR from the same logger (e.g. a real exception inside the
    # callback) must still get through.
    noisy = logging.getLogger('etw.etw')
    assert noisy.getEffectiveLevel() >= logging.ERROR
    assert not noisy.isEnabledFor(logging.WARNING)
    assert noisy.isEnabledFor(logging.ERROR)


def test_process_start_event_is_enqueued():
    q = queue.Queue()
    em._on_etw_event(_process_start_event(), q)
    assert q.get_nowait() == (1234, 1, "evil.exe", 100.0)


def test_task_name_matches_regardless_of_spacing():
    # pywintrace uppercases the manifest string but the exact spacing of the
    # raw manifest text isn't verified live - normalized matching must still
    # work whether it comes through as "PROCESSSTART" or "PROCESS START".
    q = queue.Queue()
    em._on_etw_event(_process_start_event(task_name="Process Start"), q)
    assert q.get_nowait() == (1234, 1, "evil.exe", 100.0)


def test_falls_back_to_numeric_task_id_when_name_is_unrecognized():
    q = queue.Queue()
    em._on_etw_event(_process_start_event(task_name="SOMETHING-ELSE"), q)
    assert q.get_nowait() == (1234, 1, "evil.exe", 100.0)


def test_non_process_start_events_are_ignored():
    q = queue.Queue()
    event = (2, {
        "Task Name": "PROCESSSTOP",
        "EventHeader": {"EventDescriptor": {"Task": 2}},
        "ProcessID": 1234,
    })
    em._on_etw_event(event, q)
    assert q.empty()


def test_malformed_event_does_not_raise():
    q = queue.Queue()
    em._on_etw_event((1, {"Task Name": "PROCESSSTART"}), q)  # missing EventHeader entirely -> must not raise
    assert q.empty() or q.get_nowait()[0] is None


def test_queue_full_drops_and_does_not_raise():
    q = queue.Queue(maxsize=1)
    q.put_nowait((1, 1, "already-here.exe", 1.0))
    em._on_etw_event(_process_start_event(), q)  # must not raise
    assert q.qsize() == 1


def test_on_heartbeat_fires_for_a_matched_event():
    q = queue.Queue()
    calls = []
    em._on_etw_event(_process_start_event(), q, on_heartbeat=lambda: calls.append(1))
    assert calls == [1]


def test_on_heartbeat_does_not_fire_for_an_ignored_event():
    q = queue.Queue()
    calls = []
    event = (2, {"Task Name": "PROCESSSTOP", "EventHeader": {"EventDescriptor": {"Task": 2}}})
    em._on_etw_event(event, q, on_heartbeat=lambda: calls.append(1))
    assert calls == []


def test_scoring_worker_drains_queue_on_its_own_thread():
    engine = _FakeEngine()
    q = queue.Queue()
    q.put((1234, 1, "evil.exe", 100.0))
    threading.Thread(target=em._scoring_worker, args=(engine, q), daemon=True).start()
    assert _wait_until(lambda: engine.calls == [(1234, 1, "evil.exe", 100.0)])


def test_slow_scoring_does_not_block_the_callback_thread():
    release = threading.Event()

    def _slow_evaluate():
        release.wait(timeout=2)

    engine = _FakeEngine(on_evaluate=_slow_evaluate)
    q = queue.Queue()
    threading.Thread(target=em._scoring_worker, args=(engine, q), daemon=True).start()

    start = time.monotonic()
    em._on_etw_event(_process_start_event(), q)
    elapsed = time.monotonic() - start
    release.set()  # let the worker's slow call finish so the test process can exit cleanly

    assert elapsed < 0.2, f"_on_etw_event took {elapsed}s - it must never block on scoring"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
