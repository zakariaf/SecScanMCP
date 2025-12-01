from pathlib import Path
from analyzers.security_tools.codeql.services.language_service import LanguageService
from analyzers.base import BaseAnalyzer
import tempfile

class DummyAnalyzer(BaseAnalyzer):
    async def analyze(self, repo_path, project_info):
        return []

def test_detect_languages_from_files(tmp_path):
    (tmp_path / 'a.py').write_text('print(1)')
    (tmp_path / 'b.js').write_text('console.log(1)')
    analyzer = DummyAnalyzer()
    svc = LanguageService(analyzer)
    langs = svc.detect_languages(tmp_path, {'language': 'python'})
    assert 'python' in langs
    assert 'javascript' in langs


def test_is_language_supported():
    analyzer = DummyAnalyzer()
    svc = LanguageService(analyzer)
    assert svc.is_language_supported('python')
    assert not svc.is_language_supported('brainfuck')
