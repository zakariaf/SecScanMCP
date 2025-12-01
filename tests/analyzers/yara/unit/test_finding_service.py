from pathlib import Path
from types import SimpleNamespace
from analyzers.security_tools.yara.services.finding_service import FindingService
from models import SeverityLevel, VulnerabilityType


def _mock_match(meta=None, rule='test_rule', strings=None):
    # Simulate yara match object
    if strings is None:
        strings = []
    return SimpleNamespace(meta=meta or {'severity': 'high', 'category': 'malware'},
                           rule=rule,
                           namespace='default',
                           tags=['test'],
                           strings=strings)


def test_convert_basic(tmp_path):
    svc = FindingService()
    fpath = tmp_path / 'file.txt'
    fpath.write_text('hello world')
    match = _mock_match()
    finding = svc.convert_match_to_finding(match, fpath, tmp_path)
    assert finding.severity == SeverityLevel.HIGH
    assert finding.vulnerability_type in {VulnerabilityType.MALWARE, VulnerabilityType.GENERIC}
    assert finding.location.startswith('file.txt')


def test_string_matches_with_offsets(tmp_path):
    svc = FindingService()
    content = 'first line\nsecond line with secret\nthird line'
    fpath = tmp_path / 'sample.txt'
    fpath.write_text(content)
    # Simulate tuple-based yara pre-4.3 format: (offset, identifier, data)
    s = [(content.index('secret'), '$a', b'secret')]
    match = _mock_match(strings=s)
    finding = svc.convert_match_to_finding(match, fpath, tmp_path)
    assert finding.evidence['matched_strings']
    ms = finding.evidence['matched_strings'][0]
    assert ms['line'] == 2
    assert 'secret' in ms['line_content']
