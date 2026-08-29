"""
Config-driven tunables for HeuristicEngine: decay rate, mitigation
thresholds, and the ransomware burst window/count. Deliberately does NOT
cover the safety floor (protected process names/PIDs, LSASS/hollowing
access-mask bitmasks, Defender-tamper/PowerShell-abuse pattern lists) -
those stay hardcoded in heuristic_engine.py on purpose, so a bad or
malicious config file can never loosen the one thing that must never move.

A missing or malformed config file must never change behavior - it falls
back to exactly the hardcoded defaults that shipped before this file
existed.
"""

import logging
import os

import yaml

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'config', 'detection.yml')

DEFAULTS = {
    'decay_points_per_second': 1.0 / 3.0,  # ~20 points/minute
    'thresholds': {
        'warning': 50,
        'critical': 80,
    },
    'ransomware': {
        'file_event_window_seconds': 20,
        'file_event_threshold': 60,
    },
}


def _deep_merge(base, override):
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(path=DEFAULT_CONFIG_PATH):
    """Hardcoded DEFAULTS merged with (and overridden by) whatever the YAML
    at `path` provides. Absent file, empty file, or malformed YAML all fall
    back to DEFAULTS untouched - this must never be the reason detection
    behavior changes unexpectedly."""
    try:
        with open(path, 'r') as f:
            user_config = yaml.safe_load(f)
    except (FileNotFoundError, OSError):
        return dict(DEFAULTS)
    except yaml.YAMLError as e:
        logging.warning(f"[CONFIG] Failed to parse {path}, using defaults: {e}")
        return dict(DEFAULTS)

    if not isinstance(user_config, dict):
        return dict(DEFAULTS)

    return _deep_merge(DEFAULTS, user_config)
