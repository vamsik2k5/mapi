"""
Exhaustive self-check for static_scanner.py: exercises every static PE
finding in the README's detection table using synthetic entries in the
same schema tools/extract_features.py produces. Run:
python test_static_scanner.py
"""

import json
import logging
import os
import tempfile

from heuristic_engine import HeuristicEngine
from static_scanner import StaticScanner


def _scan(entries, known_imphashes=None, known_good_hashes=None, rule_engine=None):
    """Run StaticScanner against a synthetic binaries.json (and optional
    known_imphashes.json) and return the resulting HeuristicEngine."""
    engine = HeuristicEngine(known_good_hashes=known_good_hashes)
    with tempfile.TemporaryDirectory() as d:
        binaries_path = os.path.join(d, "binaries.json")
        with open(binaries_path, "w") as f:
            json.dump(entries, f)

        imphashes_path = os.path.join(d, "known_imphashes.json")
        with open(imphashes_path, "w") as f:
            json.dump(known_imphashes or {}, f)

        StaticScanner(engine, binaries_path, known_imphashes_path=imphashes_path, rule_engine=rule_engine).scan()
    return engine


class _CaptureLogs:
    """Minimal log-record capture for asserting a specific WARNING was (or
    wasn't) emitted, without pulling in a test framework's caplog fixture."""

    def __enter__(self):
        self.records = []
        self.handler = logging.Handler()
        self.handler.emit = self.records.append
        logging.getLogger().addHandler(self.handler)
        return self.records

    def __exit__(self, *exc):
        logging.getLogger().removeHandler(self.handler)


def _entry(sha256, **overrides):
    base = {
        "file_name": overrides.pop("file_name", f"{sha256[:8]}.exe"),
        "hashes": {"sha256": sha256},
        "sections": overrides.pop("sections", []),
        "imports": overrides.pop("imports", {}),
    }
    base.update(overrides)
    return base


def test_rwx_section():
    engine = _scan([_entry("a" * 64, sections=[{"name": "UPX0", "is_rwx": True, "entropy": 1.0, "virtual_size": 100}])])
    assert engine.static_scores["a" * 64] == 30


def test_high_entropy_section():
    engine = _scan([_entry("b" * 64, sections=[{"name": "UPX1", "is_rwx": False, "entropy": 7.9, "virtual_size": 100}])])
    assert engine.static_scores["b" * 64] == 30


def test_injection_iat_pattern():
    engine = _scan([_entry("c" * 64, imports={"kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory"]})])
    assert engine.static_scores["c" * 64] == 40


def test_keylogger_iat_pattern():
    engine = _scan([_entry("d" * 64, imports={"user32.dll": ["SetWindowsHookExA"], "wininet.dll": ["HttpSendRequestA"]})])
    assert engine.static_scores["d" * 64] == 40


def test_lsass_dump_iat_pattern():
    engine = _scan([_entry("e" * 64, imports={"dbghelp.dll": ["MiniDumpWriteDump"], "kernel32.dll": ["OpenProcess"]})])
    assert engine.static_scores["e" * 64] == 60


def test_amsi_bypass_pattern():
    engine = _scan([_entry("f" * 64, imports={"amsi.dll": ["AmsiScanBuffer"], "kernel32.dll": ["VirtualProtect"]})])
    assert engine.static_scores["f" * 64] == 45


def test_etw_patch_pattern():
    engine = _scan([_entry("1" * 64, imports={"ntdll.dll": ["EtwEventWrite"], "kernel32.dll": ["VirtualProtect"]})])
    assert engine.static_scores["1" * 64] == 45


def test_sedebug_privilege_pattern():
    engine = _scan([_entry("2" * 64, imports={"advapi32.dll": ["AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA"]})])
    assert engine.static_scores["2" * 64] == 25


def test_native_syscall_plus_injection_pattern():
    engine = _scan([_entry("3" * 64, imports={"ntdll.dll": ["NtWriteVirtualMemory"], "kernel32.dll": ["VirtualAllocEx"]})])
    assert engine.static_scores["3" * 64] == 35


def test_ransomware_static_pattern():
    engine = _scan([_entry("4" * 64, imports={"kernel32.dll": ["FindFirstFileW", "FindNextFileW"], "bcrypt.dll": ["BCryptEncrypt"]})])
    assert engine.static_scores["4" * 64] == 45


def test_string_indicators_each_score_independently():
    entry = _entry("5" * 64, string_indicators={
        "btc_address_pattern": True,
        "discord_webhook": True,
        "pastebin_raw": False,  # explicitly false must not score
    })
    engine = _scan([entry])
    assert engine.static_scores["5" * 64] == 50  # 25 + 25, the False one contributes nothing


def test_imphash_match_against_known_family():
    entry = _entry("6" * 64, imphash="deadbeefcafebabe")
    engine = _scan([entry], known_imphashes={"deadbeefcafebabe": {"family": "AsyncRAT", "sample_count": 12, "source": "malwarebazaar"}})
    assert engine.static_scores["6" * 64] == 70


def test_imphash_with_no_match_scores_nothing():
    entry = _entry("7" * 64, imphash="0000000000000000")
    engine = _scan([entry], known_imphashes={"deadbeefcafebabe": {"family": "AsyncRAT"}})
    assert "7" * 64 not in engine.static_scores


def test_brand_impersonation_unsigned_claims_known_vendor():
    entry = _entry("8" * 64, has_authenticode_signature=False,
                    version_info={"CompanyName": "Microsoft Corporation", "ProductName": "Windows 11 Setup"})
    engine = _scan([entry])
    assert engine.static_scores["8" * 64] == 50


def test_brand_claim_with_valid_signature_does_not_score():
    entry = _entry("9" * 64, has_authenticode_signature=True,
                    version_info={"CompanyName": "Microsoft Corporation", "ProductName": "Windows 11 Setup"})
    engine = _scan([entry])
    assert "9" * 64 not in engine.static_scores


def test_metamorphic_clone_detection():
    shared_sections = [{"name": ".text", "is_rwx": False, "entropy": 1.0, "virtual_size": 4096}]
    shared_imports = {"kernel32.dll": ["CreateFileW"]}
    entry_a = _entry("a1" * 32, sections=shared_sections, imports=shared_imports, file_name="original.exe")
    entry_b = _entry("b2" * 32, sections=shared_sections, imports=shared_imports, file_name="repacked_clone.exe")
    engine = _scan([entry_a, entry_b])
    assert "a1" * 32 not in engine.static_scores, "the first-seen file of a structural match is not itself flagged"
    assert engine.static_scores["b2" * 32] == 50, "the second file sharing structure but a different hash is the clone"


def test_unrelated_files_do_not_collide_as_clones():
    entry_a = _entry("c3" * 32, sections=[{"name": ".text", "is_rwx": False, "entropy": 1.0, "virtual_size": 111}], imports={})
    entry_b = _entry("d4" * 32, sections=[{"name": ".data", "is_rwx": False, "entropy": 1.0, "virtual_size": 222}], imports={})
    engine = _scan([entry_a, entry_b])
    assert engine.static_scores == {}


# ---- known-good hash allowlist, exercised through the real scan pipeline --

def test_allowlist_suppresses_a_hardcoded_rule_hit():
    entry = _entry("e" * 64, sections=[{"name": "UPX0", "is_rwx": True, "entropy": 1.0, "virtual_size": 100}])
    engine = _scan([entry], known_good_hashes={"e" * 64: {"reason": "known packer, verified benign"}})
    assert "e" * 64 not in engine.static_scores


def test_allowlist_does_not_affect_other_samples_in_the_same_scan():
    # Distinct virtual_size on each so they aren't structural clones of one
    # another - this test is only about allowlist isolation, not the
    # separate metamorphic-clone detector.
    allowlisted = _entry("e" * 64, sections=[{"name": "UPX0", "is_rwx": True, "entropy": 1.0, "virtual_size": 100}])
    normal = _entry("f" * 64, sections=[{"name": "UPX0", "is_rwx": True, "entropy": 1.0, "virtual_size": 200}])
    engine = _scan([allowlisted, normal], known_good_hashes={"e" * 64: {"reason": "test"}})
    assert "e" * 64 not in engine.static_scores
    assert engine.static_scores["f" * 64] == 30


def test_allowlist_suppresses_a_custom_rule_engine_hit_too():
    # The allowlist lives in add_static_score(), which every static finding
    # already routes through - hardcoded checks AND rule_engine.py hits
    # alike - so this must be suppressed with zero special-casing in
    # static_scanner.py's rule_engine integration.
    from rule_engine import RuleEngine
    with tempfile.TemporaryDirectory() as rules_dir:
        with open(os.path.join(rules_dir, "r.yml"), "w") as f:
            json.dump({
                "id": "custom_static_test_rule",
                "applies_to": "static_pe",
                "score": 40,
                "match": {"all": [{"field": "imports_flat", "op": "contains", "value": "writeprocessmemory"}]},
                "message": "suspicious import",
            }, f)
        rules = RuleEngine(rules_dir=rules_dir)

    entry = _entry("1a" * 32, imports={"kernel32.dll": ["WriteProcessMemory"]})
    engine = _scan([entry], known_good_hashes={"1a" * 32: {"reason": "test"}}, rule_engine=rules)
    assert "1a" * 32 not in engine.static_scores


def test_metamorphic_clone_log_and_score_both_suppressed_for_allowlisted_clone():
    shared_sections = [{"name": ".text", "is_rwx": False, "entropy": 1.0, "virtual_size": 4096}]
    shared_imports = {"kernel32.dll": ["CreateFileW"]}
    entry_a = _entry("a1" * 32, sections=shared_sections, imports=shared_imports, file_name="original.exe")
    entry_b = _entry("b2" * 32, sections=shared_sections, imports=shared_imports, file_name="repacked_clone.exe")

    with _CaptureLogs() as records:
        engine = _scan([entry_a, entry_b], known_good_hashes={"b2" * 32: {"reason": "test"}})

    assert "b2" * 32 not in engine.static_scores, "score must still be suppressed"
    warnings = [r.getMessage() for r in records if r.levelno == logging.WARNING and "Metamorphic Clone Detected" in r.getMessage()]
    assert warnings == [], f"an allowlisted file must never produce this alert, got: {warnings}"


def test_metamorphic_clone_log_still_fires_when_clone_is_not_allowlisted():
    # Regression guard for the fix above: only the allowlisted file's own
    # clone-detection line is suppressed - an unrelated, non-allowlisted
    # clone must still alert normally.
    shared_sections = [{"name": ".text", "is_rwx": False, "entropy": 1.0, "virtual_size": 4096}]
    shared_imports = {"kernel32.dll": ["CreateFileW"]}
    entry_a = _entry("a1" * 32, sections=shared_sections, imports=shared_imports, file_name="original.exe")
    entry_b = _entry("b2" * 32, sections=shared_sections, imports=shared_imports, file_name="repacked_clone.exe")

    with _CaptureLogs() as records:
        engine = _scan([entry_a, entry_b])

    assert engine.static_scores["b2" * 32] == 50
    warnings = [r.getMessage() for r in records if r.levelno == logging.WARNING and "Metamorphic Clone Detected" in r.getMessage()]
    assert len(warnings) == 1


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
