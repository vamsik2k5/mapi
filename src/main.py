import threading
import time
import logging
from static_scanner import StaticScanner
from telemetry_monitor import start_monitor
from etw_monitor import start_etw_monitor
from heuristic_engine import HeuristicEngine
from module_inspector import ModuleInspector
from process_correlator import ProcessCorrelator
from rule_engine import RuleEngine
from sensor_health import SensorHealth, watchdog_loop
from detection_config import load_config

MODULE_SWEEP_INTERVAL_SECONDS = 30

def main():
    # force=True is load-bearing, not stylistic: importing etw_monitor (via
    # `from etw import ...`) pulls in pywintrace's etw/common.py, which
    # calls logging.basicConfig(level=logging.ERROR) as an import-time side
    # effect - before this line ever runs. logging.basicConfig() is a no-op
    # once any handler exists, so without force=True this call (and the
    # equivalent one HeuristicEngine.__init__ makes) would silently lose,
    # leaving every INFO-level log (the entire static scan, rule loading,
    # sensor startup) invisible - confirmed live: exactly this happened
    # before this line was added.
    logging.basicConfig(level=logging.INFO, format='[*] %(message)s', force=True)

    print("=====================================================")
    print("      Windows Defensive Agent (EDR Prototype)        ")
    print("=====================================================")

    # 1. Initialize Heuristic Engine - the same additive YAML rule pack
    # (rules/custom/*.yml) and config-driven tunables (config/detection.yml)
    # the web dashboard uses, so this CLI entrypoint and web_server.py never
    # quietly diverge in what they detect.
    rules = RuleEngine()
    config = load_config()
    engine = HeuristicEngine(rule_engine=rules, config=config)

    # 2. Static Ingress & PE Scanner
    binaries_path = "../data/binaries.json"  # Path to pre-extracted features
    logging.info(f"[*] Starting Static Ingress Scanner on {binaries_path}...")
    scanner = StaticScanner(engine, binaries_path, rule_engine=rules)
    scanner.scan()
    logging.info("[+] Static Scan Complete.")
    
    # 3. Behavioral Telemetry Monitors - two independent kernel sensors
    # (Sysmon via the Event Log, and raw ETW on Microsoft-Windows-Kernel-
    # Process) fused by a ProcessCorrelator so neither sensor's operation
    # depends on the other, plus a watchdog that observes (never
    # auto-restarts - see sensor_health.py) whether each is still alive.
    logging.info("[*] Starting Behavioral Telemetry Monitors...")
    correlator = ProcessCorrelator(engine, fuse_window=config['correlator']['fuse_window_seconds'])
    engine.correlator = correlator
    correlator.start()

    sysmon_health = SensorHealth("sysmon")
    etw_health = SensorHealth("etw")
    sub_handle = start_monitor(engine, on_heartbeat=sysmon_health.touch)
    etw_handle = start_etw_monitor(engine, on_heartbeat=etw_health.touch, correlator=correlator)
    threading.Thread(target=watchdog_loop, args=([sysmon_health, etw_health],), daemon=True).start()

    if not sub_handle:
        logging.warning("[-] Sysmon telemetry monitor failed to start. Continuing with reduced telemetry.")
    if not etw_handle:
        logging.warning("[-] ETW telemetry monitor failed to start. Continuing with reduced telemetry.")

    # 4. Active Module Provenance Sweeper (System Informer-style)
    # Complements the passive Sysmon subscription above by periodically
    # walking the live process table for already-mapped injected modules -
    # catches injection that happened before this agent started, or isn't
    # covered by the local Sysmon config.
    inspector = ModuleInspector(engine)

    try:
        logging.info("[*] EDR Engine is active. Press Ctrl+C to terminate.")
        last_sweep = 0
        while True:
            time.sleep(1)
            last_sweep += 1
            if last_sweep >= MODULE_SWEEP_INTERVAL_SECONDS:
                last_sweep = 0
                logging.info("[*] Running module provenance sweep...")
                inspector.sweep()
    except KeyboardInterrupt:
        logging.info("\n[*] Shutting down Defensive Agent...")

if __name__ == "__main__":
    main()
