import tempfile
from pathlib import Path
import pytest

from analyzers.security_tools.yara.main_analyzer import YARAAnalyzer
from analyzers.security_tools.yara.services.rule_service import RuleService

@pytest.mark.asyncio
async def test_yara_integration_basic(monkeypatch, tmp_path):
    # Dynamic rule directory
    (tmp_path / 'int_rule.yar').write_text(
        'rule integration_secret : secret {\n'
        ' meta:\n  severity = "medium"\n  category = "secret"\n'
        ' strings:\n  $s = /API_KEY=\w{6,20}/\n'
        ' condition:\n  $s\n}'
    )
    monkeypatch.setattr(RuleService, 'RULES_DIR', tmp_path)
    monkeypatch.setattr(RuleService, 'ALTERNATIVE_PATHS', [tmp_path])
    analyzer = YARAAnalyzer()

    with tempfile.TemporaryDirectory() as d:
        repo = Path(d)
        (repo / 'file.py').write_text('API_KEY=ABCDEF123456')
        findings = await analyzer.analyze(str(repo), {'language': 'python'})
        assert findings
        assert any('YARA Detection' in f.title for f in findings)
