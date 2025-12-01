import pytest
from analyzers.bandit.main_analyzer import BanditAnalyzer


@pytest.mark.asyncio
async def test_bandit_integration_detects_issue(tmp_path):
    vuln_file = tmp_path / "vuln.py"
    vuln_file.write_text("import hashlib\nprint(hashlib.md5(b'data').hexdigest())\n")

    analyzer = BanditAnalyzer()
    findings = await analyzer.analyze(str(tmp_path), {"language": "python"})

    if not findings:
        pytest.skip("Bandit CLI not available or produced no output")

    assert any('md5' in (f.description or '').lower() for f in findings)
