"""Self-check for detection_config.py. Run: python test_detection_config.py"""

import os
import tempfile

from detection_config import load_config, DEFAULTS


def test_missing_file_returns_hardcoded_defaults():
    missing_path = os.path.join(tempfile.gettempdir(), 'definitely_does_not_exist_xyz.yml')
    assert load_config(missing_path) == DEFAULTS


def test_malformed_yaml_falls_back_to_defaults():
    with tempfile.NamedTemporaryFile('w', suffix='.yml', delete=False) as f:
        f.write("not: valid: yaml: [")
        path = f.name
    try:
        assert load_config(path) == DEFAULTS
    finally:
        os.unlink(path)


def test_non_mapping_yaml_falls_back_to_defaults():
    with tempfile.NamedTemporaryFile('w', suffix='.yml', delete=False) as f:
        f.write("- just\n- a\n- list\n")
        path = f.name
    try:
        assert load_config(path) == DEFAULTS
    finally:
        os.unlink(path)


def test_partial_override_merges_with_defaults():
    with tempfile.NamedTemporaryFile('w', suffix='.yml', delete=False) as f:
        f.write("thresholds:\n  critical: 90\n")
        path = f.name
    try:
        config = load_config(path)
        assert config['thresholds']['critical'] == 90
        assert config['thresholds']['warning'] == DEFAULTS['thresholds']['warning'], "unset sibling key must keep its default"
        assert config['decay_points_per_second'] == DEFAULTS['decay_points_per_second']
    finally:
        os.unlink(path)


def test_full_override():
    with tempfile.NamedTemporaryFile('w', suffix='.yml', delete=False) as f:
        f.write("decay_points_per_second: 1.0\nransomware:\n  file_event_threshold: 10\n")
        path = f.name
    try:
        config = load_config(path)
        assert config['decay_points_per_second'] == 1.0
        assert config['ransomware']['file_event_threshold'] == 10
        assert config['ransomware']['file_event_window_seconds'] == DEFAULTS['ransomware']['file_event_window_seconds']
    finally:
        os.unlink(path)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
