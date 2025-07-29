"""
Test suite for ClamAV malware detection analyzer
"""

import pytest
import asyncio
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

from analyzers.security_tools.clamav_analyzer import ClamAVAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType


class TestClamAVAnalyzer:
    """Test cases for ClamAV analyzer"""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance"""
        return ClamAVAnalyzer()

    @pytest.fixture
    def mock_project_info(self):
        """Mock project information"""
        return {
            'type': 'python',
            'language': 'python',
            'is_mcp': True,
            'mcp_config': {}
        }

    @pytest.mark.asyncio
    async def test_malware_detection(self, analyzer, mock_project_info):
        """Test detection of EICAR test virus"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create EICAR test file
            eicar_content = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
            test_file = Path(temp_dir) / 'test_virus.txt'
            test_file.write_text(eicar_content)

            # Mock ClamAV connection and response
            with patch.object(analyzer, '_connect', new_callable=AsyncMock):
                with patch.object(analyzer, '_ping', new_callable=AsyncMock, return_value=True):
                    with patch.object(analyzer, '_get_version', new_callable=AsyncMock,
                                    return_value='ClamAV 1.4.0/27123'):
                        with patch.object(analyzer, '_scan_stream', new_callable=AsyncMock,
                                        return_value=('FOUND', 'Win.Test.EICAR_HDB-1')):
                            findings = await analyzer.analyze(temp_dir, mock_project_info)

            assert len(findings) == 1
            finding = findings[0]
            assert finding.vulnerability_type == VulnerabilityType.MALWARE
            assert finding.severity == SeverityLevel.HIGH
            assert 'EICAR' in finding.title
            assert finding.confidence == 0.99

    @pytest.mark.asyncio
    async def test_pattern_detection(self, analyzer, mock_project_info):
        """Test detection of suspicious patterns"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file with suspicious pattern
            malicious_code = '''
import subprocess
subprocess.Popen("rm -rf /", shell=True)
'''
            test_file = Path(temp_dir) / 'malicious.py'
            test_file.write_text(malicious_code)

            # Mock ClamAV connection
            with patch.object(analyzer, '_connect', new_callable=AsyncMock):
                with patch.object(analyzer, '_ping', new_callable=AsyncMock, return_value=True):
                    with patch.object(analyzer, '_get_version', new_callable=AsyncMock,
                                    return_value='ClamAV 1.4.0/27123'):
                        with patch.object(analyzer, '_scan_stream', new_callable=AsyncMock,
                                        return_value=None):  # No malware found by ClamAV
                            findings = await analyzer.analyze(temp_dir, mock_project_info)

            # Should find pattern-based detection
            pattern_findings = [f for f in findings if 'Suspicious Pattern' in f.title]
            assert len(pattern_findings) > 0
            assert any('ShellExec' in f.title for f in pattern_findings)

    @pytest.mark.asyncio
    async def test_connection_failure(self, analyzer, mock_project_info):
        """Test handling of ClamAV connection failure"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Mock connection failure
            with patch.object(analyzer, '_connect', new_callable=AsyncMock,
                            side_effect=ConnectionRefusedError("Connection refused")):
                findings = await analyzer.analyze(temp_dir, mock_project_info)

            # Should return empty findings on connection failure
            assert findings == []

    @pytest.mark.asyncio
    async def test_large_file_skip(self, analyzer, mock_project_info):
        """Test skipping of large files"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create large file (over 100MB limit)
            large_file = Path(temp_dir) / 'large_file.bin'
            large_file.write_bytes(b'0' * (101 * 1024 * 1024))

            with patch.object(analyzer, '_connect', new_callable=AsyncMock):
                with patch.object(analyzer, '_ping', new_callable=AsyncMock, return_value=True):
                    with patch.object(analyzer, '_get_version', new_callable=AsyncMock,
                                    return_value='ClamAV 1.4.0/27123'):
                        with patch.object(analyzer, '_scan_stream', new_callable=AsyncMock) as mock_scan:
                            findings = await analyzer.analyze(temp_dir, mock_project_info)

            # Should not scan large file
            mock_scan.assert_not_called()

    def test_severity_determination(self, analyzer):
        """Test malware severity determination"""
        assert analyzer._determine_severity('Trojan.Generic') == SeverityLevel.CRITICAL
        assert analyzer._determine_severity('Backdoor.Agent') == SeverityLevel.CRITICAL
        assert analyzer._determine_severity('Ransomware.Cryptolocker') == SeverityLevel.CRITICAL
        assert analyzer._determine_severity('Virus.Generic') == SeverityLevel.HIGH
        assert analyzer._determine_severity('Adware.Generic') == SeverityLevel.MEDIUM
        assert analyzer._determine_severity('Unknown.Malware') == SeverityLevel.HIGH

    def test_file_hash_calculation(self, analyzer):
        """Test SHA256 hash calculation"""
        with tempfile.NamedTemporaryFile() as temp_file:
            test_content = b'test content'
            temp_file.write(test_content)
            temp_file.flush()

            file_hash = analyzer._calculate_file_hash(Path(temp_file.name))
            # SHA256 of 'test content'
            expected_hash = '1b4f0e9851971998e732078544c96b36c3d01cedf7caa332359d6f1d83567014'
            assert file_hash == expected_hash

    def test_should_skip_files(self, analyzer):
        """Test file skipping logic"""
        assert analyzer._should_skip(Path('.git/config'))
        assert analyzer._should_skip(Path('README.md'))
        assert analyzer._should_skip(Path('config.yml'))
        assert analyzer._should_skip(Path('.gitignore'))
        assert not analyzer._should_skip(Path('script.py'))
        assert not analyzer._should_skip(Path('binary.exe'))


if __name__ == '__main__':
    pytest.main([__file__, '-v'])