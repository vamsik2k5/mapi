"""
Web dashboard for the EDR prototype: stdlib-only HTTP server (no Flask/
Django - nothing new to install) serving a Falcon/Singularity-style
single-page dashboard (stat tiles, charts, live detections feed, endpoint
process table with a Terminate response action, static-scan verdicts).

Wires the exact same detection surfaces main.py does (StaticScanner,
Sysmon telemetry, ModuleInspector) into one HeuristicEngine - this file
only adds a JSON API + static file serving on top, no detection logic
changes.
"""

import os
import re
import sys
import json
import time
import ctypes
import logging
import socket
import subprocess
import threading
import urllib.request
import urllib.error
import webbrowser
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

from heuristic_engine import HeuristicEngine
from static_scanner import StaticScanner
from telemetry_monitor import start_monitor
from etw_monitor import start_etw_monitor, stop_etw_monitor
from module_inspector import ModuleInspector
from process_correlator import ProcessCorrelator
from rule_engine import RuleEngine
from sensor_health import (
    SensorHealth, watchdog_loop, sensor_label, current_blind_state,
    negative_evidence_caveat, BLIND_STATE_HEALTHY,
)
from detection_config import load_config
from self_test import self_test_loop
from process_tracker import ProcessTracker
import dashboard_data as dd

HOST = "127.0.0.1"  # loopback only - this server exposes a process-kill endpoint
PORT = 8787
BINARIES_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'binaries.json')
WEBAPP_DIR = os.path.join(os.path.dirname(__file__), 'webapp')
MODULE_SWEEP_INTERVAL_SECONDS = 30
MAX_ALERTS = 2000

STATIC_CONTENT_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
}

PID_TERMINATE_RE = re.compile(r"^/api/processes/(\d+)/terminate$")


class AlertStore:
    """Thread-safe, bounded buffer of structured alerts, fed by a logging
    handler attached to the root logger - every finding the engine/scanner/
    monitor/inspector already log becomes a dashboard alert for free."""

    def __init__(self, maxlen=MAX_ALERTS):
        self._lock = threading.Lock()
        self._alerts = deque(maxlen=maxlen)
        self._next_id = 1

    def add(self, record: logging.LogRecord):
        with self._lock:
            entry = {
                "id": self._next_id,
                "ts": record.created,
                "time": time.strftime("%H:%M:%S", time.localtime(record.created)),
                "severity": dd.severity_of(record),
                "category": dd.categorize(record.getMessage()),
                "message": record.getMessage(),
            }
            self._next_id += 1
            self._alerts.appendleft(entry)

    def snapshot(self, limit=None):
        with self._lock:
            items = list(self._alerts)
        return items[:limit] if limit else items


class AlertLogHandler(logging.Handler):
    def __init__(self, store: AlertStore):
        super().__init__()
        self.store = store

    def emit(self, record):
        self.store.add(record)


class ProcessActivityStore:
    """Thread-safe, bounded buffer of every ProcessCreate Sysmon event seen,
    scored or not - the Falcon/Singularity-style "Process Explorer" view.
    Kept entirely separate from AlertStore: dumping every process launch
    into the Detections feed would drown the actual security signal that
    feed exists to surface."""

    def __init__(self, maxlen=500):
        self._lock = threading.Lock()
        self._events = deque(maxlen=maxlen)

    def add(self, event_id, data):
        if event_id != 1:  # ProcessCreate only
            return
        with self._lock:
            self._events.appendleft({
                "ts": time.time(),
                "time": time.strftime("%H:%M:%S"),
                "pid": data.get("ProcessId"),
                "image": data.get("Image"),
                "parent_image": data.get("ParentImage"),
                "command_line": data.get("CommandLine"),
                "user": data.get("User"),
                # 'sysmon' (default, pre-correlator/single-sensor rows),
                # 'etw' (provisional - ETW's own thin fields only), or
                # 'fused' (ETW's low latency + Sysmon's richer fields
                # merged) - see process_correlator.py.
                "source": data.get("_source", "sysmon"),
            })

    def snapshot(self, limit=None):
        with self._lock:
            items = list(self._events)
        return items[:limit] if limit else items


class Backend:
    """Owns the engine + detection surfaces, mirroring main.py's wiring."""

    def __init__(self):
        self.session_start = time.time()
        self.alert_store = AlertStore()
        logging.getLogger().addHandler(AlertLogHandler(self.alert_store))
        logging.getLogger().setLevel(logging.INFO)

        # Additive YAML rule pack + config-driven tunables - same instances
        # main.py's CLI entrypoint constructs, so the dashboard and the CLI
        # never quietly diverge in what they detect.
        self.rules = RuleEngine()
        self.config = load_config()
        self.engine = HeuristicEngine(rule_engine=self.rules, config=self.config)
        self.process_activity = ProcessActivityStore()
        self.process_tracker = ProcessTracker()
        self.engine.on_event = self._on_raw_event
        self.inspector = ModuleInspector(self.engine)
        self._sysmon_handle = None
        self._etw_handle = None
        self.correlator = ProcessCorrelator(self.engine, fuse_window=self.config['correlator']['fuse_window_seconds'])
        self.engine.correlator = self.correlator
        self.sysmon_health = SensorHealth("sysmon")
        self.etw_health = SensorHealth("etw")

    def _on_raw_event(self, event_id, data):
        """Single fan-out point for HeuristicEngine.on_event - every raw
        Sysmon event feeds both the Process Explorer buffer and the
        lineage tracker, without either of them knowing about the other or
        heuristic_engine.py's on_event contract needing to support more
        than one observer."""
        self.process_activity.add(event_id, data)
        self.process_tracker.add(event_id, data)

    def _pid_seen(self, pid):
        """self_test.py's pid_seen_fn for this entrypoint - reuses
        ProcessActivityStore (every ProcessCreate event, scored or not)
        rather than a new observer, since it already records exactly this.
        str() on both sides because a pid recorded from Sysmon's XML text
        and one from ETW's decoded int field can differ in type for the
        same real PID."""
        return any(str(row.get("pid")) == str(pid) for row in self.process_activity.snapshot())

    def start(self):
        logging.info("[*] Starting Static Ingress Scanner...")
        StaticScanner(self.engine, BINARIES_PATH, rule_engine=self.rules).scan()
        logging.info("[+] Static Scan Complete.")

        logging.info("[*] Starting Behavioral Telemetry Monitors (Sysmon + ETW)...")
        self.correlator.start()
        self._sysmon_handle = start_monitor(self.engine, on_heartbeat=self.sysmon_health.touch)
        self._etw_handle = start_etw_monitor(self.engine, on_heartbeat=self.etw_health.touch, correlator=self.correlator)
        threading.Thread(
            target=watchdog_loop,
            args=([self.sysmon_health, self.etw_health],),
            kwargs={"blind_state_fn": self._blind_state},
            daemon=True,
        ).start()

        threading.Thread(target=self._module_sweep_loop, daemon=True).start()

        # Benign, periodic self-test (see self_test.py) - proves the
        # telemetry pipeline actually delivers real events end-to-end, and
        # (only here, since this is the entrypoint with an AlertStore) that
        # the alert-generation pipeline is actually wired.
        threading.Thread(
            target=self_test_loop,
            args=(self._pid_seen, self.alert_store),
            kwargs={
                "interval": self.config['self_test']['interval_seconds'],
                "timeout": self.config['self_test']['timeout_seconds'],
            },
            daemon=True,
        ).start()

    def stop(self):
        """Release the ETW session so the process can exit (see
        etw_monitor.stop_etw_monitor). Every other thread here is a daemon;
        pywintrace's consumer thread is the one that isn't. Idempotent."""
        etw_session, self._etw_handle = self._etw_handle, None
        stop_etw_monitor(etw_session)

    def _module_sweep_loop(self):
        while True:
            time.sleep(MODULE_SWEEP_INTERVAL_SECONDS)
            self.inspector.sweep()

    def _blind_state(self):
        """Aggregate visibility state across both behavioral sensors (see
        sensor_health.compute_blind_state) - computed fresh on every call,
        same as the per-sensor labels below, so it reflects a sensor dying
        (or recovering) mid-run with no state to re-set anywhere."""
        return current_blind_state(
            [(self._sysmon_handle, self.sysmon_health), (self._etw_handle, self.etw_health)],
            self.engine.total_events_seen,
        )

    def summary(self):
        alerts = self.alert_store.snapshot()
        last_event = self.engine.last_event_time
        # 'unavailable' means the sensor never came up at startup (e.g.
        # EvtSubscribe/ETW trace failed) - permanent for this run. 'stale'/
        # 'live' come from SensorHealth's heartbeat, computed fresh on every
        # call so a sensor dying mid-run (e.g. `sc stop sysmon64`) is
        # reflected here without needing sensor_status to be re-set anywhere.
        sysmon_label = sensor_label(self._sysmon_handle, self.sysmon_health)
        etw_label = sensor_label(self._etw_handle, self.etw_health)
        blind_state = self._blind_state()
        return {
            "hostname": socket.gethostname(),
            "session_start": self.session_start,
            "sensor_status": f"Sysmon: {sysmon_label} | ETW: {etw_label}",
            # Per-sensor liveness (see sensor_health.py) - observe-only, not
            # auto-restarted. A stale sensor doesn't mean detection stopped:
            # the other sensor (and the correlator's sysmon-only/etw-only
            # fallback dispatch) keeps working independently.
            "sysmon_stale": self.sysmon_health.is_stale(),
            "etw_stale": self.etw_health.is_stale(),
            # Structured per-sensor state ("live"/"stale"/"unavailable") for
            # the dashboard's sensor-health gauge - sensor_status above is
            # the same information as one display string, kept for the
            # existing badge rendering.
            "sysmon_state": sysmon_label,
            "etw_state": etw_label,
            # Aggregate visibility state (see sensor_health.compute_blind_state)
            # - HEALTHY/DEGRADED/PARTIALLY_BLIND/CRITICALLY_BLIND, driven by
            # telemetry integrity rather than just "is the process running".
            "blind_state": blind_state,
            # Negative-evidence protection (threat-model item #19): whether
            # the alert counts below can actually be read as "no activity
            # observed" (only true when blind_state is HEALTHY) versus
            # "activity could not be observed" - and a human-readable reason
            # why, for the dashboard to show directly next to those counts
            # rather than making a viewer infer it from blind_state alone.
            "negative_evidence_reliable": blind_state == BLIND_STATE_HEALTHY,
            "visibility_caveat": negative_evidence_caveat(blind_state),
            "thresholds": self.config['thresholds'],
            "total_alerts": len(alerts),
            "critical_count": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
            "warning_count": sum(1 for a in alerts if a["severity"] == "WARNING"),
            "processes_monitored": len(self.engine.process_scores),
            "samples_scanned": len(self.engine.static_scores),
            # Raw telemetry heartbeat - most process/file/registry activity
            # matches none of the suspicious patterns in heuristic_engine.py
            # and produces no alert by design, which looks identical to "the
            # Sysmon subscription is dead" from the dashboard alone. This is
            # what actually proves events are flowing in real time.
            "telemetry_events_seen": self.engine.total_events_seen,
            "seconds_since_last_event": (time.time() - last_event) if last_event else None,
        }


class DashboardServer(ThreadingHTTPServer):
    # http.server.HTTPServer sets allow_reuse_address=1, which on Windows
    # lets a *second* process bind the same host:port while the first is
    # still listening - no error, no warning, just two independent servers
    # silently sharing one port and round-robining requests across two
    # completely different in-memory HeuristicEngine states. That's exactly
    # what happened here: repeated runs left multiple elevated instances
    # alive, and the dashboard looked "wrong" because every poll could land
    # on a different one. A genuine second instance must fail loudly
    # (Address already in use) instead of silently corrupting the data.
    allow_reuse_address = False


class DashboardHandler(BaseHTTPRequestHandler):
    backend: Backend = None  # set by main() before serve_forever

    def log_message(self, fmt, *args):
        pass  # avoid spamming the terminal with an access log line every poll

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_static(self, rel_path):
        full_path = os.path.normpath(os.path.join(WEBAPP_DIR, rel_path))
        if not full_path.startswith(os.path.normpath(WEBAPP_DIR)) or not os.path.isfile(full_path):
            self._send_json({"error": "not found"}, 404)
            return
        ext = os.path.splitext(full_path)[1]
        with open(full_path, 'rb') as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", STATIC_CONTENT_TYPES.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        query = parse_qs(urlsplit(self.path).query)
        backend = self.backend

        if path == "/" or path == "/index.html":
            self._send_static("index.html")
        elif path in ("/app.js", "/style.css"):
            self._send_static(path.lstrip("/"))
        elif path == "/api/summary":
            self._send_json(backend.summary())
        elif path == "/api/alerts":
            limit = int(query.get("limit", [100])[0])
            self._send_json(backend.alert_store.snapshot(limit))
        elif path == "/api/alerts/timeseries":
            self._send_json(dd.bucket_alerts(backend.alert_store.snapshot(), minutes=20))
        elif path == "/api/alerts/categories":
            self._send_json(dd.category_counts(backend.alert_store.snapshot()))
        elif path == "/api/processes":
            self._send_json(dd.build_process_rows(backend.engine))
        elif path == "/api/static":
            self._send_json(dd.build_static_rows(backend.engine, BINARIES_PATH))
        elif path == "/api/process-activity":
            limit = int(query.get("limit", [200])[0])
            rows = backend.process_activity.snapshot(limit)
            for row in rows:
                try:
                    row["lineage"] = backend.process_tracker.lineage_string(int(row["pid"]))
                except (TypeError, ValueError):
                    row["lineage"] = ""
            self._send_json(rows)
        elif path == "/api/rules":
            self._send_json(backend.rules.summary())
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlsplit(self.path).path
        backend = self.backend

        match = PID_TERMINATE_RE.match(path)
        if match:
            pid = int(match.group(1))
            backend.engine.mitigate(pid)
            self._send_json({"status": "requested", "pid": pid})
            return

        if path == "/api/host/isolate":
            # Falcon/Singularity's "network containment" cuts the host off
            # the network in one click. Actually flipping firewall rules on
            # the operator's own machine from a prototype dashboard is a
            # real, hard-to-reverse system change - simulated only, same
            # line the engine already draws at its score>=50 "simulated
            # memory snapshot" action.
            logging.warning("[ISOLATE] Host isolation requested - simulated only, no firewall changes made.")
            self._send_json({"status": "simulated"})
            return

        self._send_json({"error": "not found"}, 404)


def _is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _relaunch_elevated():
    """Re-invoke this same script, with the same args, via Windows' own
    UAC consent dialog - the Sysmon behavioral monitor needs Administrator
    to subscribe to the event log (see telemetry_monitor.py), and Falcon/
    Singularity-style agents run elevated without the operator having to
    remember to open an elevated terminal by hand. Windows' UAC prompt is
    the actual consent gate here, not this code - a user who clicks "No"
    falls through to the degraded static-only mode below, same as today.
    lpDirectory is set explicitly because ShellExecuteW otherwise launches
    into a different working directory, which would break every relative
    path (BINARIES_PATH, webapp/) this module resolves at import time.

    A True return only means Windows *accepted the request to launch* -
    not that the user approved the prompt or that the new process is
    actually up yet. Callers must confirm with _wait_for_dashboard()
    before treating this as a success."""
    script = os.path.abspath(sys.argv[0])
    params = subprocess.list2cmdline([script] + sys.argv[1:])
    try:
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, os.getcwd(), 1)
    except Exception:
        return False
    return result > 32  # ShellExecuteW's own success contract


def _dashboard_url():
    return f"http://{HOST}:{PORT}"


def _wait_for_dashboard(timeout, interval=0.5):
    """Poll the dashboard's own API until it responds or `timeout` seconds
    pass. Used two ways: a near-zero-timeout check for "is one already
    running" before we start a second one, and a longer wait to confirm an
    elevated relaunch actually came up before treating it as a success."""
    deadline = time.monotonic() + timeout
    url = _dashboard_url() + "/api/summary"
    while True:
        try:
            with urllib.request.urlopen(url, timeout=1) as resp:
                return resp.status == 200
        except (urllib.error.URLError, OSError):
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


def main():
    # force=True is load-bearing, not stylistic: importing etw_monitor (via
    # `from etw import ...`) pulls in pywintrace's etw/common.py, which
    # calls logging.basicConfig(level=logging.ERROR) as an import-time side
    # effect - before this line ever runs. logging.basicConfig() is a no-op
    # once any handler exists, so without force=True this call would
    # silently lose (confirmed live: it left the whole app logging in
    # pywintrace's bare ERROR-only, default-format setup instead of ours).
    # Safe to force here specifically because nothing else has added a
    # handler yet at this point in startup - Backend() (which adds
    # AlertLogHandler) isn't constructed until further down this function.
    logging.basicConfig(level=logging.INFO, format='[*] %(message)s', force=True)

    if _wait_for_dashboard(timeout=0):
        logging.info(f"A dashboard is already running at {_dashboard_url()} - opening it instead of starting a duplicate.")
        webbrowser.open(_dashboard_url())
        return

    if os.name == "nt" and not _is_admin() and not os.environ.get("EDR_NO_ELEVATE"):
        logging.info("Not running elevated - requesting Administrator so Sysmon telemetry starts with no manual steps (approve the UAC prompt if one appears)...")
        if _relaunch_elevated() and _wait_for_dashboard(timeout=20):
            logging.info(f"Elevated dashboard is live at {_dashboard_url()} - opening it now. This window can be closed.")
            webbrowser.open(_dashboard_url())
            return
        logging.warning("Elevated instance never came up (declined, blocked, or failed) - continuing here without admin; Sysmon telemetry will be unavailable, static analysis and the module sweep still run.")

    backend = Backend()
    try:
        backend.start()

        DashboardHandler.backend = backend
        try:
            server = DashboardServer((HOST, PORT), DashboardHandler)
        except OSError as e:
            logging.error(f"Could not bind {HOST}:{PORT} ({e}). A dashboard is probably already running under a different account/elevation level - close it first.")
            return

        logging.info(f"Dashboard live at {_dashboard_url()}")
        webbrowser.open(_dashboard_url())
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logging.info("Shutting down dashboard server...")
            server.shutdown()
    finally:
        # Every way out of main() - Ctrl+C, a failed bind, an unexpected error -
        # must release the ETW session or the process can't exit.
        backend.stop()


if __name__ == "__main__":
    main()
