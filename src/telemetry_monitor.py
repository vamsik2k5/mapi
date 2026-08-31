import win32evtlog
import logging
import queue
import threading

# Bounded so a scoring engine that's falling badly behind can't grow this
# queue without limit - past this many buffered-but-unprocessed events,
# new ones are dropped (and logged) rather than consumed indefinitely.
EVENT_QUEUE_MAXSIZE = 2000


def on_sysmon_event(action, context, event_handle, on_heartbeat=None):
    """EvtSubscribe callback. `context` is the shared queue.Queue this
    module hands to EvtSubscribe at registration time (see start_monitor).
    `on_heartbeat` is a new, optional keyword-only-in-practice parameter
    (defaults to None) so every existing positional call site/test keeps
    working unchanged - EvtSubscribe itself owns `context`'s shape, so
    liveness reporting is threaded through as a separate parameter instead
    of being smuggled into it.

    EvtRender must happen synchronously, here, on this callback - the OS
    invalidates `event_handle` once this function returns, so rendering
    can't be deferred to the worker thread. Everything else (parsing,
    scoring, custom rules, mitigate()) is deliberately NOT done here -
    it's handed off to _scoring_worker on its own thread so a slow scoring
    pass can never stall this callback and risk the OS dropping buffered
    Sysmon events. Same split osquery's WindowsEventLogPublisher uses for
    the identical reason.
    """
    if action != win32evtlog.EvtSubscribeActionDeliver:
        return
    try:
        xml_content = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
    except Exception as e:
        logging.error(f"[TELEMETRY] Error rendering event: {e}")
        return

    # Heartbeat fires as soon as the sensor itself has observed a real OS
    # event - independent of whether the queue below can accept it. A full
    # queue means the *scoring worker* is falling behind, not that the
    # sensor is dead; conflating the two would make a chronically-backed-up
    # (but perfectly alive) sensor look stale to the watchdog.
    if on_heartbeat:
        on_heartbeat()

    try:
        context.put_nowait(xml_content)
    except queue.Full:
        logging.warning("[TELEMETRY] Event queue full - dropping an event because scoring is falling behind.")


def _scoring_worker(engine_instance, event_queue):
    """Drains rendered Sysmon XML off the queue and runs it through the
    heuristic engine, on a thread separate from the EvtSubscribe callback
    above. Runs until the process exits (daemon thread)."""
    while True:
        xml_content = event_queue.get()
        try:
            engine_instance.evaluate_event(xml_content)
        except Exception as e:
            logging.error(f"[TELEMETRY] Scoring worker failed on an event: {e}")


def start_monitor(engine_instance, on_heartbeat=None):
    try:
        logging.info("[*] Subscribing to Microsoft-Windows-Sysmon/Operational via EvtSubscribe...")
        event_queue = queue.Queue(maxsize=EVENT_QUEUE_MAXSIZE)
        threading.Thread(target=_scoring_worker, args=(engine_instance, event_queue), daemon=True).start()

        def _callback(action, context, event_handle):
            on_sysmon_event(action, context, event_handle, on_heartbeat=on_heartbeat)

        subscription_handle = win32evtlog.EvtSubscribe(
            "Microsoft-Windows-Sysmon/Operational",
            win32evtlog.EvtSubscribeToFutureEvents,
            None,
            _callback,
            event_queue,
            "*"
        )
        logging.info("[+] Sysmon push subscription active. Awaiting real-time events...")
        return subscription_handle
    except Exception as e:
        logging.error(f"[!] Failed to subscribe to Sysmon events (Ensure you are running as Administrator and Sysmon is installed): {e}")
        return None
