"""Self-check for sensor_health.py - uses a fake monotonic clock, no real
sleeps. Run: python test_sensor_health.py"""

import sensor_health as sh
from sensor_health import SensorHealth, watchdog_loop


class _FakeClock:
    def __init__(self, start=0.0):
        self.t = start

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


def test_never_touched_is_stale():
    sensor = SensorHealth("test")
    assert sensor.is_stale() is True
    assert sensor.seconds_since_heartbeat() is None


def test_touch_then_fresh():
    clock = _FakeClock()
    original = sh.time.monotonic
    sh.time.monotonic = clock
    try:
        sensor = SensorHealth("test", stale_after=60)
        sensor.touch()
        assert sensor.is_stale() is False
        clock.advance(30)
        assert sensor.is_stale() is False
        assert sensor.seconds_since_heartbeat() == 30
    finally:
        sh.time.monotonic = original


def test_goes_stale_after_threshold():
    clock = _FakeClock()
    original = sh.time.monotonic
    sh.time.monotonic = clock
    try:
        sensor = SensorHealth("test", stale_after=60)
        sensor.touch()
        clock.advance(61)
        assert sensor.is_stale() is True
    finally:
        sh.time.monotonic = original


def test_touch_resets_staleness():
    clock = _FakeClock()
    original = sh.time.monotonic
    sh.time.monotonic = clock
    try:
        sensor = SensorHealth("test", stale_after=60)
        sensor.touch()
        clock.advance(61)
        assert sensor.is_stale() is True
        sensor.touch()
        assert sensor.is_stale() is False
    finally:
        sh.time.monotonic = original


def test_watchdog_logs_once_on_transition_into_stale():
    # Exercises the real watchdog_loop() - never touched, so it's stale
    # from tick 1. A fake time.sleep counts ticks and breaks the
    # otherwise-infinite loop after N ticks via a sentinel exception.
    calls = []
    original_sleep = sh.time.sleep
    original_warning = sh.logging.warning
    sh.logging.warning = lambda msg: calls.append(msg)

    tick_count = {"n": 0}

    class _StopLoop(Exception):
        pass

    def _fake_sleep(seconds):
        tick_count["n"] += 1
        if tick_count["n"] > 3:
            raise _StopLoop()

    sh.time.sleep = _fake_sleep

    try:
        sensor = SensorHealth("etw")
        try:
            watchdog_loop([sensor], interval=1)
        except _StopLoop:
            pass
        assert len(calls) == 1, f"must log once on the transition, not once per poll tick, got {calls}"
        assert "etw" in calls[0]
    finally:
        sh.time.sleep = original_sleep
        sh.logging.warning = original_warning


def test_watchdog_does_not_log_for_a_healthy_sensor():
    original_sleep = sh.time.sleep
    original_warning = sh.logging.warning
    calls = []
    sh.logging.warning = lambda msg: calls.append(msg)

    clock = _FakeClock()
    original_monotonic = sh.time.monotonic
    sh.time.monotonic = clock

    tick_count = {"n": 0}

    class _StopLoop(Exception):
        pass

    def _fake_sleep(seconds):
        tick_count["n"] += 1
        if tick_count["n"] > 3:
            raise _StopLoop()

    sh.time.sleep = _fake_sleep

    try:
        sensor = SensorHealth("sysmon", stale_after=60)
        sensor.touch()  # healthy, well under stale_after
        try:
            watchdog_loop([sensor], interval=1)
        except _StopLoop:
            pass
        assert calls == [], f"a healthy sensor must never trigger a watchdog warning, got {calls}"
    finally:
        sh.time.sleep = original_sleep
        sh.logging.warning = original_warning
        sh.time.monotonic = original_monotonic


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
