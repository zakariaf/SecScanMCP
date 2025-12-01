from pathlib import Path
from analyzers.security_tools.yara.services.scan_service import ScanService
from analyzers.security_tools.yara.services.rule_service import RuleService

class DummyRuleService:
    def __init__(self, rules):
        self.rules = rules

class DummyRules:
    def __init__(self, matches):
        self._matches = matches
    def match(self, path, timeout=None):
        return self._matches

class DummyMatch:
    def __init__(self):
        self.meta = {'severity': 'low', 'category': 'secret'}
        self.rule = 'dummy'
        self.namespace = 'default'
        self.tags = []
        self.strings = []


def test_scan_file_no_rules(tmp_path):
    svc = ScanService(DummyRuleService(None))
    f = tmp_path / 'file.txt'
    f.write_text('data')
    assert svc.scan_file(f, tmp_path) == []


def test_scan_file_with_match(tmp_path):
    match = DummyMatch()
    svc = ScanService(DummyRuleService(rules=DummyRules([match])))
    f = tmp_path / 'file.txt'
    f.write_text('data')
    findings = svc.scan_file(f, tmp_path)
    assert len(findings) == 1
    assert findings[0].title.startswith('YARA Detection')
