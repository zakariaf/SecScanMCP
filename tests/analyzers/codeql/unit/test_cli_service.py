import subprocess
import pytest
from analyzers.security_tools.codeql.services.cli_service import CLIService

class DummyCompleted:
    def __init__(self, returncode=0, stdout='codeql 2.15.0', stderr=''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

@pytest.mark.parametrize('which_return', [0, 1])
def test_discover_cli(monkeypatch, which_return):
    def fake_run(cmd, capture_output=False, text=False, timeout=None):
        if cmd[:2] == ['which', 'codeql']:
            if which_return == 0:
                return subprocess.CompletedProcess(cmd, 0, stdout='/usr/bin/codeql\n', stderr='')
            return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='')
        return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='')
    monkeypatch.setattr(subprocess, 'run', fake_run)
    svc = CLIService()
    svc.discover_cli()
    if which_return == 0:
        assert svc.cli_path.endswith('codeql')
    else:
        assert svc.cli_path is None
