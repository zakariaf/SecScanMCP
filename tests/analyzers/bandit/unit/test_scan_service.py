import asyncio
import json
import pytest
from analyzers.bandit.services.scan_service import ScanService


class DummyProcess:
    def __init__(self, stdout_data: bytes, stderr_data: bytes = b""):
        self._stdout = stdout_data
        self._stderr = stderr_data

    async def communicate(self):
        return self._stdout, self._stderr


@pytest.mark.asyncio
async def test_build_command_and_parse(monkeypatch, tmp_path):
    service = ScanService()
    repo = str(tmp_path)

    sample_output = {
        "results": [
            {
                "test_id": "B303",
                "test_name": "md5_usage",
                "issue_text": "Use of insecure MD5 hash function.",
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "filename": "vuln.py",
                "line_number": 1,
            }
        ]
    }

    async def fake_subprocess_exec(*cmd, **kwargs):
        # ensure command ordering
        assert list(cmd[0:3]) == service.BASE_COMMAND_PREFIX
        assert repo in cmd
        stdout_bytes = json.dumps(sample_output).encode()
        return DummyProcess(stdout_bytes)

    monkeypatch.setattr(asyncio, 'create_subprocess_exec', fake_subprocess_exec)

    results = await service.run_scan(repo)
    assert 'results' in results and len(results['results']) == 1


@pytest.mark.asyncio
async def test_parse_empty_output(monkeypatch, tmp_path):
    service = ScanService()

    async def fake_subprocess_exec(*cmd, **kwargs):
        return DummyProcess(b"")

    monkeypatch.setattr(asyncio, 'create_subprocess_exec', fake_subprocess_exec)
    results = await service.run_scan(str(tmp_path))
    assert results == {}
