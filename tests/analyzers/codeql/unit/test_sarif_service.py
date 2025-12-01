import json
from pathlib import Path
from analyzers.security_tools.codeql.services.sarif_service import SarifService
from analyzers.base import BaseAnalyzer
from models import VulnerabilityType, SeverityLevel

class DummyAnalyzer(BaseAnalyzer):
    async def analyze(self, repo_path, project_info):
        return []

def test_parse_minimal_sarif(tmp_path):
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"rules": [
                    {"id": "js/sql-injection", "shortDescription": {"text": "SQL injection"},
                     "properties": {"tags": ["SQL-Injection"], "precision": "high", "security-severity": "8.5"}}
                ]}},
                "results": [
                    {"ruleId": "js/sql-injection", "level": "warning", "message": {"text": "Unsanitized input"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.js"}, "region": {"startLine": 10}}}]}
                ]
            }
        ]
    }
    sarif_path = tmp_path / 'res.sarif'
    sarif_path.write_text(json.dumps(sarif))
    svc = SarifService(DummyAnalyzer())
    findings = svc.parse_sarif_results(sarif_path, tmp_path)
    assert findings
    f = findings[0]
    assert f.vulnerability_type == VulnerabilityType.SQL_INJECTION
    assert f.severity in {SeverityLevel.HIGH, SeverityLevel.CRITICAL}
    assert f.location.endswith(':10')
