"""
Passive liveness tracking for the two independent telemetry sensors
(Sysmon, ETW) - each sensor's start_monitor()/start_etw_monitor() calls
touch() every time it actually delivers an event, so a dead/tampered
sensor is visibly distinguishable from one that's merely quiet.

Deliberately observe-only: this watchdog logs staleness transitions and
exposes them to the dashboard, it never tries to restart a dead sensor.
Tearing down and re-establishing an EvtSubscribe handle or an ETW trace
session safely needs real handle-lifecycle care and live-fire testing
against genuine sensor death - both beyond what a non-elevated dev shell
can responsibly exercise. Auto-restart is a deliberate, separate follow-on.
"""

import logging
import threading
import time

DEFAULT_STALE_AFTER_SECONDS = 60
DEFAULT_WATCHDOG_INTERVAL_SECONDS = 15


class SensorHealth:
    def __init__(self, name, stale_after=DEFAULT_STALE_AFTER_SECONDS):
        self.name = name
        self.stale_after = stale_after
        self._lock = threading.Lock()
        self._last_heartbeat = None

    def touch(self):
        with self._lock:
            self._last_heartbeat = time.monotonic()

    def seconds_since_heartbeat(self):
        with self._lock:
            if self._last_heartbeat is None:
                return None
            return time.monotonic() - self._last_heartbeat

    def is_stale(self):
        age = self.seconds_since_heartbeat()
        return age is None or age > self.stale_after


def watchdog_loop(sensors, interval=DEFAULT_WATCHDOG_INTERVAL_SECONDS):
    """Runs forever (call on a daemon thread). Logs once on each
    fresh -> stale transition per sensor, not on every poll tick, so a
    long-dead sensor doesn't spam the alert feed every `interval` seconds."""
    was_stale = {sensor.name: False for sensor in sensors}
    while True:
        time.sleep(interval)
        for sensor in sensors:
            stale_now = sensor.is_stale()
            if stale_now and not was_stale[sensor.name]:
                age = sensor.seconds_since_heartbeat()
                age_desc = "no events ever received" if age is None else f"last event {round(age)}s ago"
                logging.warning(f"[WATCHDOG] {sensor.name} sensor stale - {age_desc}")
            was_stale[sensor.name] = stale_now
