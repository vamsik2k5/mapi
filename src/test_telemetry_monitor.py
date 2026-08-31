"""
Self-check for telemetry_monitor.py's event-pump/scoring decoupling.
Monkeypatches win32evtlog.EvtRender so this never needs a real Sysmon event
handle. Run: python test_telemetry_monitor.py
"""

import queue
import threading
import time

import telemetry_monitor as tm


class _FakeEngine:
    def __init__(self, on_evaluate=None):
        self.calls = []
        self.on_evaluate = on_evaluate

    def evaluate_event(self, xml_content):
        self.calls.append(xml_content)
        if self.on_evaluate:
            self.on_evaluate()


def _wait_until(predicate, timeout=2.0, interval=0.01):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def test_on_sysmon_event_enqueues_rendered_xml():
    tm.win32evtlog.EvtRender = lambda handle, fmt: "<Event>fake</Event>"
    q = queue.Queue()
    tm.on_sysmon_event(tm.win32evtlog.EvtSubscribeActionDeliver, q, event_handle=object())
    assert q.get_nowait() == "<Event>fake</Event>"


def test_on_sysmon_event_ignores_non_deliver_actions():
    tm.win32evtlog.EvtRender = lambda handle, fmt: "<Event>fake</Event>"
    q = queue.Queue()
    tm.on_sysmon_event(action=999, context=q, event_handle=object())
    assert q.empty()


def test_on_sysmon_event_drops_and_does_not_raise_when_queue_full():
    tm.win32evtlog.EvtRender = lambda handle, fmt: "<Event>fake</Event>"
    q = queue.Queue(maxsize=1)
    q.put_nowait("<Event>already here</Event>")
    tm.on_sysmon_event(tm.win32evtlog.EvtSubscribeActionDeliver, q, event_handle=object())  # must not raise
    assert q.qsize() == 1
    assert q.get_nowait() == "<Event>already here</Event>"


def test_on_sysmon_event_handles_render_failure_without_raising():
    def _raise(handle, fmt):
        raise OSError("event handle invalidated")
    tm.win32evtlog.EvtRender = _raise
    q = queue.Queue()
    tm.on_sysmon_event(tm.win32evtlog.EvtSubscribeActionDeliver, q, event_handle=object())  # must not raise
    assert q.empty()


def test_scoring_worker_drains_queue_on_its_own_thread():
    engine = _FakeEngine()
    q = queue.Queue()
    q.put("<Event>one</Event>")
    threading.Thread(target=tm._scoring_worker, args=(engine, q), daemon=True).start()
    assert _wait_until(lambda: engine.calls == ["<Event>one</Event>"])


def test_slow_scoring_does_not_block_the_callback_thread():
    # The whole point of the decoupling: on_sysmon_event must return
    # immediately even if the engine consuming the queue is slow.
    release = threading.Event()

    def _slow_evaluate():
        release.wait(timeout=2)

    engine = _FakeEngine(on_evaluate=_slow_evaluate)
    q = queue.Queue()
    threading.Thread(target=tm._scoring_worker, args=(engine, q), daemon=True).start()

    tm.win32evtlog.EvtRender = lambda handle, fmt: "<Event>slow</Event>"

    start = time.monotonic()
    tm.on_sysmon_event(tm.win32evtlog.EvtSubscribeActionDeliver, q, event_handle=object())
    elapsed = time.monotonic() - start
    release.set()  # let the worker's slow evaluate_event finish so the test process can exit cleanly

    assert elapsed < 0.2, f"on_sysmon_event took {elapsed}s - it must never block on scoring"


def test_on_heartbeat_fires_on_successful_event():
    tm.win32evtlog.EvtRender = lambda handle, fmt: "<Event>fake</Event>"
    q = queue.Queue()
    calls = []
    tm.on_sysmon_event(tm.win32evtlog.EvtSubscribeActionDeliver, q, event_handle=object(), on_heartbeat=lambda: calls.append(1))
    assert calls == [1]


def test_on_heartbeat_fires_even_when_queue_is_full():
    # The sensor observed a real event even though the queue couldn't take
    # it - that's a scoring-worker backlog, not a dead sensor, so the
    # heartbeat must still fire.
    tm.win32evtlog.EvtRender = lambda handle, fmt: "<Event>fake</Event>"
    q = queue.Queue(maxsize=1)
    q.put_nowait("<Event>already here</Event>")
    calls = []
    tm.on_sysmon_event(tm.win32evtlog.EvtSubscribeActionDeliver, q, event_handle=object(), on_heartbeat=lambda: calls.append(1))
    assert calls == [1]


def test_on_heartbeat_does_not_fire_on_render_failure():
    def _raise(handle, fmt):
        raise OSError("event handle invalidated")
    tm.win32evtlog.EvtRender = _raise
    q = queue.Queue()
    calls = []
    tm.on_sysmon_event(tm.win32evtlog.EvtSubscribeActionDeliver, q, event_handle=object(), on_heartbeat=lambda: calls.append(1))
    assert calls == [], "a failed render never reached the OS event, so it must not count as a heartbeat"


def test_on_heartbeat_does_not_fire_for_non_deliver_actions():
    calls = []
    tm.on_sysmon_event(action=999, context=queue.Queue(), event_handle=object(), on_heartbeat=lambda: calls.append(1))
    assert calls == []


def test_missing_on_heartbeat_is_a_safe_default():
    # Every pre-existing call site (and every test above this one) omits
    # on_heartbeat entirely - confirms that stays valid.
    tm.win32evtlog.EvtRender = lambda handle, fmt: "<Event>fake</Event>"
    q = queue.Queue()
    tm.on_sysmon_event(tm.win32evtlog.EvtSubscribeActionDeliver, q, event_handle=object())  # must not raise
    assert q.get_nowait() == "<Event>fake</Event>"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
