"""
Second, independent telemetry sensor: Microsoft-Windows-Kernel-Process via
ETW, consumed directly (not through Sysmon/the Windows Event Log). Same
decoupled shape as telemetry_monitor.py's Sysmon path - a bounded queue
between the ETW consumer callback and a separate scoring-worker thread, so
a slow scoring pass can never stall event delivery.

Empirically confirmed on a real Windows 11 machine via `Get-WinEvent
-ListProvider Microsoft-Windows-Kernel-Process`: the raw kernel
ProcessStart event (task ID 1) only ever carries ProcessID, CreateTime,
ParentProcessID, SessionID, ImageName - no CommandLine, no parent *image
path* (only a parent PID). That's a real, permanent capability gap versus
Sysmon (whose CommandLine capture is Sysmon's own enrichment work) - see
HeuristicEngine.evaluate_etw_process_start's docstring for how that's
handled (CommandLine/ParentImage set to None, so command-line-dependent
rules structurally cannot fire on this thin data, correctly, with no
special-casing).

Starting a real-time ETW trace session needs Administrator
(SeSystemProfilePrivilege) - identical requirement to Sysmon's
EvtSubscribe, so web_server.py's existing self-elevation already covers
both sensors with no new UAC prompt.
"""

import logging
import queue
import threading

from etw import ETW, GUID, ProviderInfo

# pywintrace's own internal logger (etw/etw.py: logging.getLogger(__name__)
# == "etw.etw") logs a WARNING for every single field TDH can't format -
# confirmed via a real elevated run that Kernel-Process ProcessStart events
# routinely fail to decode their Flags/SecurityMitigations fields this way
# (pywintrace handles it gracefully itself: sets the field to None and
# keeps parsing the rest of the event - neither field is one this module
# reads). Left at WARNING, every process launch on the system would emit
# these as root-logger records, which AlertLogHandler (web_server.py) turns
# into dashboard alerts - flooding the Detections feed with internal
# library noise. Raised to ERROR only for this specific logger, so a
# genuine problem (e.g. logger.error() on an exception inside our own
# event callback, at etw/etw.py's dispatch site) still surfaces.
logging.getLogger('etw.etw').setLevel(logging.ERROR)

# Microsoft-Windows-Kernel-Process. GUID confirmed on this machine via
# `wevtutil gp Microsoft-Windows-Kernel-Process`.
KERNEL_PROCESS_PROVIDER_NAME = "Microsoft-Windows-Kernel-Process"
KERNEL_PROCESS_PROVIDER_GUID = "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"

# Task ID for the ProcessStart event within that provider (confirmed via
# Get-WinEvent -ListProvider): 1 = ProcessStart, 2 = ProcessStop, 3/4 =
# ThreadStart/Stop, 5 = ImageLoad. Only ProcessStart is consumed here.
TASK_PROCESS_START = 1

EVENT_QUEUE_MAXSIZE = 2000


def _on_etw_event(event_tufo, event_queue, on_heartbeat=None):
    """pywintrace's ETW callback shape: event_tufo = (event_id, event_dict).
    Filters to ProcessStart, extracts the thin field set, enqueues a plain
    tuple (not the raw event_dict) so the scoring worker doesn't need to
    know anything about pywintrace's decoding conventions. Mirrors
    telemetry_monitor.on_sysmon_event: do the minimum here, hand off the
    rest, never block this callback on scoring."""
    try:
        _event_id, event = event_tufo
        # pywintrace uppercases the manifest task name before handing it to
        # the callback (etw/etw.py: `task_name = task_name.strip().upper()`
        # - confirmed by reading pywintrace's source this session), so this
        # can never be the literal string "ProcessStart". Match normalized
        # (whitespace-stripped, uppercased) text, plus the nested numeric
        # Task ID as a second, independent signal - Get-WinEvent already
        # confirmed ProcessStart is task ID 1 on this provider.
        task_name = "".join(str(event.get("Task Name", "")).split()).upper()
        task_id = event.get("EventHeader", {}).get("EventDescriptor", {}).get("Task")
        if task_name != "PROCESSSTART" and task_id != TASK_PROCESS_START:
            return
        pid = event.get("ProcessID")
        parent_pid = event.get("ParentProcessID")
        image_name = event.get("ImageName")
        create_time = event.get("CreateTime")
    except Exception as e:
        logging.error(f"[ETW] Error extracting fields from a Kernel-Process event: {e}")
        return

    if on_heartbeat:
        on_heartbeat()

    try:
        event_queue.put_nowait((pid, parent_pid, image_name, create_time))
    except queue.Full:
        logging.warning("[ETW] Event queue full - dropping an event because scoring is falling behind.")


def _scoring_worker(engine_instance, event_queue, correlator=None):
    """Drains (pid, parent_pid, image_name, create_time) tuples off the
    queue and runs them through the heuristic engine (or the correlator, if
    one is wired in - see start_etw_monitor), on a thread separate from the
    ETW consumer callback above."""
    while True:
        pid, parent_pid, image_name, create_time = event_queue.get()
        try:
            if correlator is not None:
                correlator.submit_etw(pid, parent_pid, image_name, create_time)
            else:
                engine_instance.evaluate_etw_process_start(pid, parent_pid, image_name, create_time)
        except Exception as e:
            logging.error(f"[ETW] Scoring worker failed on an event: {e}")


def start_etw_monitor(engine_instance, on_heartbeat=None, correlator=None):
    """correlator (process_correlator.ProcessCorrelator), if given, receives
    every decoded ProcessStart instead of the engine directly - None (the
    default) preserves the exact single-sensor behavior this module had
    before ProcessCorrelator existed."""
    try:
        logging.info(f"[*] Starting ETW capture on {KERNEL_PROCESS_PROVIDER_NAME}...")
        event_queue = queue.Queue(maxsize=EVENT_QUEUE_MAXSIZE)
        threading.Thread(target=_scoring_worker, args=(engine_instance, event_queue, correlator), daemon=True).start()

        def _callback(event_tufo):
            _on_etw_event(event_tufo, event_queue, on_heartbeat=on_heartbeat)

        # ProviderInfo stores whatever `guid` it's given verbatim, and
        # pywintrace's EventProvider.start()/stop() later does
        # ct.byref(provider.guid) - which needs a real ctypes GUID
        # structure, not a plain string. Confirmed by reading pywintrace's
        # source and by an actual run: passing the bare string here raised
        # "byref() argument 1 must be _ctypes._CData, not str".
        # GUID(string) converts via Windows' own CLSIDFromString.
        provider = ProviderInfo(KERNEL_PROCESS_PROVIDER_NAME, GUID(KERNEL_PROCESS_PROVIDER_GUID))
        etw_session = ETW(providers=[provider], event_callback=_callback)
        # ETW.start() is non-blocking - EventConsumer.start() (which it
        # delegates to internally) spawns its own consumer thread and
        # returns immediately, so no extra threading wrapper is needed here.
        etw_session.start()

        logging.info("[+] ETW kernel-process capture active. Awaiting real-time events...")
        return etw_session
    except Exception as e:
        logging.error(f"[!] Failed to start ETW capture (Ensure you are running as Administrator): {e}")
        return None
