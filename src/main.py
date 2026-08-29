import time
import logging
from static_scanner import StaticScanner
from telemetry_monitor import start_monitor
from heuristic_engine import HeuristicEngine
from module_inspector import ModuleInspector
from rule_engine import RuleEngine
from detection_config import load_config

MODULE_SWEEP_INTERVAL_SECONDS = 30

def main():
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
    
    # 3. Behavioral Telemetry Monitor
    logging.info("[*] Starting Behavioral Telemetry Monitor...")
    sub_handle = start_monitor(engine)
    
    if not sub_handle:
        logging.warning("[-] Telemetry monitor failed to start. Continuing with static analysis only.")

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
