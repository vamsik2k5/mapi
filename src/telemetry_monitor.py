import win32evtlog
import xml.etree.ElementTree as ET
import logging

def on_sysmon_event(action, context, event_handle):
    if action == win32evtlog.EvtSubscribeActionDeliver:
        try:
            xml_content = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
            # Parse XML and dispatch to context (HeuristicEngine instance)
            context.evaluate_event(xml_content)
        except Exception as e:
            logging.error(f"[TELEMETRY] Error rendering or parsing event: {e}")

def start_monitor(engine_instance):
    try:
        logging.info("[*] Subscribing to Microsoft-Windows-Sysmon/Operational via EvtSubscribe...")
        subscription_handle = win32evtlog.EvtSubscribe(
            "Microsoft-Windows-Sysmon/Operational",
            win32evtlog.EvtSubscribeToFutureEvents,
            None,
            on_sysmon_event,
            engine_instance,
            "*"
        )
        logging.info("[+] Sysmon push subscription active. Awaiting real-time events...")
        return subscription_handle
    except Exception as e:
        logging.error(f"[!] Failed to subscribe to Sysmon events (Ensure you are running as Administrator and Sysmon is installed): {e}")
        return None
