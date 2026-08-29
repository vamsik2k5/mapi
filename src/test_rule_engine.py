"""
Self-check for rule_engine.py: every operator/combinator, malformed-file
resilience, and - critically - that a custom rule inherits the real
protected-process safety floor by going through the real HeuristicEngine,
not a mock. Run: python test_rule_engine.py
"""

import os
import tempfile

import yaml

from rule_engine import RuleEngine, Rule, _field_matches
from heuristic_engine import HeuristicEngine


def _write_rule(dir_path, filename, content):
    with open(os.path.join(dir_path, filename), 'w') as f:
        if isinstance(content, str):
            f.write(content)
        else:
            yaml.safe_dump(content, f)


def _basic_rule(**overrides):
    rule = {
        'id': 'test_rule',
        'name': 'Test Rule',
        'applies_to': 'process_create',
        'score': 25,
        'match': {'all': [{'field': 'image', 'op': 'contains', 'value': 'evil'}]},
        'message': 'hit on {image}',
    }
    rule.update(overrides)
    return rule


# ---- operator matching (pure, no engine needed) ---------------------------

def test_operator_equals():
    assert _field_matches('evil.exe', 'equals', 'EVIL.EXE') is True
    assert _field_matches('evil.exe', 'equals', 'notevil.exe') is False


def test_operator_contains_scalar_and_list():
    assert _field_matches(r'c:\temp\evil.exe', 'contains', 'temp') is True
    assert _field_matches(r'c:\temp\rundll32.exe', 'contains', ['regsvr32.exe', 'rundll32.exe']) is True
    assert _field_matches(r'c:\temp\notepad.exe', 'contains', ['regsvr32.exe', 'rundll32.exe']) is False


def test_operator_in_and_not_in():
    assert _field_matches('rundll32.exe', 'in', ['rundll32.exe', 'mshta.exe']) is True
    assert _field_matches('notepad.exe', 'in', ['rundll32.exe', 'mshta.exe']) is False
    assert _field_matches('notepad.exe', 'not_in', ['rundll32.exe', 'mshta.exe']) is True


def test_operator_regex():
    assert _field_matches('powershell -enc aGVsbG8=', 'regex', r'-enc\s+[A-Za-z0-9+/=]+') is True
    assert _field_matches('powershell -File script.ps1', 'regex', r'-enc\s+[A-Za-z0-9+/=]+') is False


def test_operator_gt_lt_numeric():
    assert _field_matches(7.9, 'gt', 7.5) is True
    assert _field_matches(7.9, 'lt', 7.5) is False


def test_field_matches_over_list_values():
    # e.g. imports_flat is a list - "any element matches" semantics.
    assert _field_matches(['createfilew', 'writeprocessmemory'], 'contains', 'writeprocessmemory') is True
    assert _field_matches(['createfilew'], 'contains', 'writeprocessmemory') is False


def test_missing_field_never_matches():
    assert _field_matches(None, 'contains', 'anything') is False


def test_any_combinator():
    rule = Rule(_basic_rule(match={'any': [
        {'field': 'image', 'op': 'contains', 'value': 'nomatch'},
        {'field': 'command_line', 'op': 'contains', 'value': 'hit'},
    ]}), source_file='<test>')
    assert rule.matches({'image': 'notepad.exe', 'command_line': 'run --hit'}) is True


def test_all_combinator_requires_every_condition():
    rule = Rule(_basic_rule(match={'all': [
        {'field': 'image', 'op': 'contains', 'value': 'evil'},
        {'field': 'command_line', 'op': 'contains', 'value': 'hidden'},
    ]}), source_file='<test>')
    assert rule.matches({'image': 'evil.exe', 'command_line': 'evil.exe'}) is False
    assert rule.matches({'image': 'evil.exe', 'command_line': 'run -hidden'}) is True


def test_message_template_renders_and_falls_back_safely():
    rule = Rule(_basic_rule(message="hit: {image}"), source_file='<test>')
    assert rule.render_message({'image': 'evil.exe'}) == "hit: evil.exe"
    rule_missing_field = Rule(_basic_rule(message="hit: {nonexistent}"), source_file='<test>')
    assert rule_missing_field.render_message({'image': 'evil.exe'}) == "hit: {nonexistent}"


# ---- loading -----------------------------------------------------------

def test_loads_valid_rule_and_skips_malformed_file():
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, 'good.yml', _basic_rule(id='good_rule'))
        _write_rule(d, 'bad.yml', "not: valid: yaml: [")
        _write_rule(d, 'wrong_shape.yml', {'id': 'no_match_key', 'applies_to': 'process_create', 'score': 10})
        engine = RuleEngine(rules_dir=d)
    ids = [r.id for r in engine.rules]
    assert ids == ['good_rule']


def test_missing_rules_dir_yields_empty_rule_set():
    engine = RuleEngine(rules_dir=os.path.join(tempfile.gettempdir(), 'definitely_does_not_exist_xyz'))
    assert engine.rules == []


def test_disabled_rule_never_fires():
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, 'disabled.yml', _basic_rule(id='disabled_rule', enabled=False))
        engine = RuleEngine(rules_dir=d)
    he = HeuristicEngine()
    he.rule_engine = engine
    he.rule_engine.evaluate_behavioral(1, {'ProcessId': '900101', 'Image': r'C:\evil.exe'}, he)
    assert 900101 not in he.process_scores


# ---- integration through the REAL HeuristicEngine -------------------------

def test_custom_rule_scores_through_real_engine():
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, 'lolbin.yml', _basic_rule(id='lolbin_rule', score=35,
                                                   match={'all': [{'field': 'image', 'op': 'contains', 'value': 'evil'}]}))
        rules = RuleEngine(rules_dir=d)
    he = HeuristicEngine(rule_engine=rules)
    he.rule_engine.evaluate_behavioral(1, {'ProcessId': '900102', 'Image': r'C:\Users\bob\evil.exe'}, he)
    assert he.process_scores[900102] == 35
    assert rules.hit_counts['lolbin_rule'] == 1


def test_custom_rule_cannot_score_a_protected_pid():
    # The whole point of routing through _add_score(): a custom rule must
    # inherit the safety floor for free, not just avoid an obvious PID.
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, 'always_matches.yml', _basic_rule(
            id='always_matches', score=999,
            match={'all': [{'field': 'image', 'op': 'contains', 'value': ''}]}))
        rules = RuleEngine(rules_dir=d)
    he = HeuristicEngine(rule_engine=rules)
    he.rule_engine.evaluate_behavioral(1, {'ProcessId': '4', 'Image': r'C:\Windows\System32\svchost.exe'}, he)
    assert 4 not in he.process_scores, "a custom rule must never be able to score a protected PID"


def test_evaluate_static_returns_hits_for_caller_to_score():
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, 'static_rule.yml', {
            'id': 'custom_static_rule',
            'applies_to': 'static_pe',
            'score': 40,
            'match': {'all': [{'field': 'imports_flat', 'op': 'contains', 'value': 'writeprocessmemory'}]},
            'message': 'suspicious import in {filename}',
        })
        rules = RuleEngine(rules_dir=d)
    hits = rules.evaluate_static({'filename': 'sample.exe', 'imports_flat': ['createfilew', 'writeprocessmemory']})
    assert len(hits) == 1
    rule, message = hits[0]
    assert rule.id == 'custom_static_rule'
    assert message == 'suspicious import in sample.exe'


def test_one_broken_rule_does_not_stop_others_from_evaluating():
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, 'broken.yml', _basic_rule(id='broken_rule', match={'all': [{'field': 'image', 'op': 'gt', 'value': 'not_a_number'}]}))
        _write_rule(d, 'fine.yml', _basic_rule(id='fine_rule', score=20))
        rules = RuleEngine(rules_dir=d)
    he = HeuristicEngine(rule_engine=rules)
    he.rule_engine.evaluate_behavioral(1, {'ProcessId': '900103', 'Image': r'C:\evil.exe'}, he)
    assert he.process_scores[900103] == 20


def test_summary_shape():
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, 'r.yml', _basic_rule(id='r1', technique='T1218', score=35))
        rules = RuleEngine(rules_dir=d)
    summary = rules.summary()
    assert summary == [{'id': 'r1', 'name': 'Test Rule', 'technique': 'T1218', 'score': 35,
                         'applies_to': 'process_create', 'enabled': True, 'hit_count': 0}]


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
