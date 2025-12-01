import pytest
from pathlib import Path
from analyzers.security_tools.yara.services.rule_service import RuleService


def test_rule_service_no_rules(monkeypatch, tmp_path: Path):
    # Point to empty directory
    monkeypatch.setattr(RuleService, 'RULES_DIR', tmp_path)
    monkeypatch.setattr(RuleService, 'ALTERNATIVE_PATHS', [tmp_path])
    svc = RuleService()
    assert svc.rules is None


def test_rule_service_loads_rules(monkeypatch, tmp_path: Path):
    (tmp_path / 'test_rule.yar').write_text('rule test_rule { condition: true }')
    monkeypatch.setattr(RuleService, 'RULES_DIR', tmp_path)
    monkeypatch.setattr(RuleService, 'ALTERNATIVE_PATHS', [tmp_path])
    svc = RuleService()
    assert svc.rules is not None  # compiled
