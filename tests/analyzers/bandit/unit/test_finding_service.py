import pytest
from analyzers.bandit.services.finding_service import FindingService
from models import SeverityLevel, VulnerabilityType


@pytest.fixture
def service():
    return FindingService()


def test_convert_to_finding_basic(service):
    bandit_result = {
        'test_id': 'B303',
        'test_name': 'md5_usage',
        'issue_text': 'Use of insecure MD5 hash function.',
        'issue_severity': 'HIGH',
        'issue_confidence': 'HIGH',
        'filename': 'vuln.py',
        'line_number': 12,
        'more_info': 'https://bandit.readthedocs.io/en/latest/plugins/b303_md5.html',
        'code': 'hashlib.md5(b"data").hexdigest()',
        'line_range': [12]
    }
    finding = service.convert_to_finding(bandit_result)
    assert finding.severity == SeverityLevel.HIGH
    assert finding.vulnerability_type == VulnerabilityType.INSECURE_CONFIGURATION
    assert 'md5_usage' in finding.title
    assert finding.location.endswith(':12')
    assert finding.evidence['test_id'] == 'B303'


@pytest.mark.parametrize("test_id,expected", [
    ("B607", VulnerabilityType.COMMAND_INJECTION),
    ("B608", VulnerabilityType.SQL_INJECTION),
    ("UNKNOWN", VulnerabilityType.GENERIC),
])
def test_vulnerability_type_mapping(service, test_id, expected):
    res = {'test_id': test_id, 'test_name': 'x', 'issue_text': 'y'}
    finding = service.convert_to_finding(res)
    assert finding.vulnerability_type == expected


@pytest.mark.parametrize("severity,expected", [
    ('HIGH', SeverityLevel.HIGH),
    ('LOW', SeverityLevel.LOW),
    ('MISSING', SeverityLevel.MEDIUM),  # default path
])
def test_severity_mapping(service, severity, expected):
    res = {'test_id': 'B301', 'test_name': 'pickle', 'issue_text': 'x', 'issue_severity': severity}
    finding = service.convert_to_finding(res)
    assert finding.severity == expected


def test_confidence_mapping(service):
    res = {'test_id': 'B301', 'test_name': 'pickle', 'issue_text': 'x', 'issue_confidence': 'LOW'}
    finding = service.convert_to_finding(res)
    assert finding.confidence == 0.5
