import pytest
from pathlib import Path
from analyzers.security_tools.codeql.main_analyzer import CodeQLAnalyzer

@pytest.mark.asyncio
async def test_codeql_integration_skip_if_cli_missing(tmp_path):
    analyzer = CodeQLAnalyzer()
    if not analyzer.cli_service.cli_path:
        pytest.skip('CodeQL CLI not available in test environment')
    # Create simple repository
    (tmp_path / 'a.py').write_text('print(1)')
    findings = await analyzer.analyze(str(tmp_path), {'language': 'python'})
    assert isinstance(findings, list)
