"""
Test suite for CodeQL semantic code analysis analyzer
"""

import pytest
import asyncio
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

from analyzers.security_tools.codeql_analyzer import CodeQLAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType


class TestCodeQLAnalyzer:
    """Test cases for CodeQL analyzer"""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance"""
        return CodeQLAnalyzer()

    @pytest.fixture
    def mock_project_info(self):
        """Mock project information"""
        return {
            'type': 'python',
            'language': 'python',
            'is_mcp': True,
            'mcp_config': {}
        }

    @pytest.fixture
    def mock_sarif_result(self):
        """Mock SARIF output from CodeQL"""
        return {
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [{
                            "id": "py/command-line-injection",
                            "name": "Command injection",
                            "shortDescription": {"text": "Command injection vulnerability"},
                            "help": {"text": "User input flows to dangerous function. Recommendation: Validate input."},
                            "properties": {
                                "tags": ["security", "injection", "cwe-78"],
                                "precision": "high"
                            }
                        }]
                    }
                },
                "results": [{
                    "ruleId": "py/command-line-injection",
                    "level": "error",
                    "message": {"text": "User input flows to subprocess.call"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/vulnerable.py"},
                            "region": {"startLine": 10, "endLine": 10}
                        }
                    }],
                    "codeFlows": [{
                        "threadFlows": [{
                            "locations": [
                                {
                                    "location": {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "src/vulnerable.py"},
                                            "region": {"startLine": 5}
                                        }
                                    }
                                },
                                {
                                    "location": {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "src/vulnerable.py"},
                                            "region": {"startLine": 10}
                                        }
                                    }
                                }
                            ]
                        }]
                    }]
                }]
            }]
        }

    @pytest.mark.asyncio
    async def test_command_injection_detection(self, analyzer, mock_project_info):
        """Test detection of command injection vulnerability"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create vulnerable Python code
            vulnerable_code = '''
import subprocess

def process_user_input(user_input):
    # Vulnerable to command injection
    cmd = f"echo {user_input}"
    subprocess.call(cmd, shell=True)

    # Safe version
    subprocess.call(["echo", user_input])
'''
            Path(temp_dir, 'vulnerable.py').write_text(vulnerable_code)

            # Mock CodeQL availability and execution
            with patch.object(analyzer, '_codeql_available', True):
                with patch.object(analyzer, '_create_database', new_callable=AsyncMock, return_value=True):
                    with patch.object(analyzer, '_analyze_database', new_callable=AsyncMock, return_value=True):
                        # Mock SARIF parsing
                        mock_sarif = self.mock_sarif_result
                        with patch('json.load', return_value=mock_sarif):
                            with patch('builtins.open', create=True):
                                findings = await analyzer.analyze(temp_dir, mock_project_info)

            assert len(findings) == 1
            finding = findings[0]
            assert finding.vulnerability_type == VulnerabilityType.COMMAND_INJECTION
            assert finding.severity == SeverityLevel.CRITICAL
            assert 'Command injection' in finding.title
            assert finding.confidence >= 0.90  # High precision

    @pytest.mark.asyncio
    async def test_language_detection(self, analyzer):
        """Test programming language detection"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create files of different languages
            Path(temp_dir, 'main.py').write_text('print("Python")')
            Path(temp_dir, 'app.js').write_text('console.log("JavaScript")')
            Path(temp_dir, 'util.ts').write_text('console.log("TypeScript")')
            Path(temp_dir, 'Main.java').write_text('class Main {}')

            # Test detection
            assert analyzer._detect_language(temp_dir, {}) == 'python'

            # Remove Python file
            Path(temp_dir, 'main.py').unlink()
            assert analyzer._detect_language(temp_dir, {}) == 'javascript'

    @pytest.mark.asyncio
    async def test_build_command_detection(self, analyzer):
        """Test build command detection for compiled languages"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Java with Maven
            Path(temp_dir, 'pom.xml').write_text('<project></project>')
            assert analyzer._detect_build_command(temp_dir, 'java') == 'mvn compile'

            # Java with Gradle
            Path(temp_dir, 'pom.xml').unlink()
            Path(temp_dir, 'build.gradle').write_text('apply plugin: "java"')
            assert analyzer._detect_build_command(temp_dir, 'java') == 'gradle build'

            # Go project
            Path(temp_dir, 'go.mod').write_text('module example.com/app')
            assert analyzer._detect_build_command(temp_dir, 'go') == 'go build ./...'

            # C++ with Makefile
            Path(temp_dir, 'Makefile').write_text('all:\n\tgcc main.c')
            assert analyzer._detect_build_command(temp_dir, 'cpp') == 'make'

    @pytest.mark.asyncio
    async def test_sarif_parsing(self, analyzer, mock_sarif_result):
        """Test SARIF result parsing"""
        with tempfile.TemporaryDirectory() as temp_dir:
            sarif_path = Path(temp_dir, 'results.sarif')

            # Write mock SARIF
            with open(sarif_path, 'w') as f:
                json.dump(mock_sarif_result, f)

            findings = analyzer._parse_sarif_results(sarif_path, temp_dir)

            assert len(findings) == 1
            finding = findings[0]
            assert 'py/command-line-injection' in finding.evidence['rule_id']
            assert finding.evidence['precision'] == 'high'
            assert 'cwe-78' in finding.evidence['cwe']
            assert finding.location == 'src/vulnerable.py:10'

    @pytest.mark.asyncio
    async def test_data_flow_extraction(self, analyzer, mock_sarif_result):
        """Test data flow information extraction"""
        result = mock_sarif_result['runs'][0]['results'][0]
        data_flow = analyzer._extract_data_flow(result)

        assert data_flow['steps'] == 2
        assert 'vulnerable.py:5' in data_flow['source']
        assert 'vulnerable.py:10' in data_flow['sink']

    @pytest.mark.asyncio
    async def test_codeql_not_available(self, analyzer, mock_project_info):
        """Test handling when CodeQL is not available"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Mock CodeQL as unavailable
            with patch.object(analyzer, '_codeql_available', False):
                findings = await analyzer.analyze(temp_dir, mock_project_info)

            assert findings == []

    @pytest.mark.asyncio
    async def test_unsupported_language(self, analyzer):
        """Test handling of unsupported languages"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create PHP file (not supported)
            Path(temp_dir, 'index.php').write_text('<?php echo "Hello"; ?>')

            project_info = {'language': 'php'}

            with patch.object(analyzer, '_codeql_available', True):
                findings = await analyzer.analyze(temp_dir, project_info)

            assert findings == []

    def test_severity_mapping(self, analyzer):
        """Test severity level mapping"""
        assert analyzer.SEVERITY_MAP['error'] == SeverityLevel.CRITICAL
        assert analyzer.SEVERITY_MAP['warning'] == SeverityLevel.HIGH
        assert analyzer.SEVERITY_MAP['recommendation'] == SeverityLevel.MEDIUM
        assert analyzer.SEVERITY_MAP['note'] == SeverityLevel.LOW

    def test_vulnerability_type_determination(self, analyzer):
        """Test vulnerability type determination"""
        # Command injection
        rule = {'name': 'Command injection vulnerability'}
        assert analyzer._determine_vuln_type(rule, '') == VulnerabilityType.COMMAND_INJECTION

        # SQL injection
        rule = {'name': 'SQL injection risk'}
        assert analyzer._determine_vuln_type(rule, '') == VulnerabilityType.SQL_INJECTION

        # Path traversal
        rule = {'name': 'Path injection vulnerability'}
        assert analyzer._determine_vuln_type(rule, '') == VulnerabilityType.PATH_TRAVERSAL

        # Generic security issue
        rule = {'name': 'Security vulnerability', 'properties': {'tags': ['security']}}
        assert analyzer._determine_vuln_type(rule, '') == VulnerabilityType.GENERIC

    def test_recommendation_extraction(self, analyzer):
        """Test recommendation extraction from help text"""
        # With explicit recommendation
        help_text = "This is a vulnerability. Recommendation: Use parameterized queries."
        assert "Use parameterized queries" in analyzer._extract_recommendation(help_text)

        # Injection-related
        help_text = "SQL injection vulnerability detected"
        recommendation = analyzer._extract_recommendation(help_text)
        assert "parameterized" in recommendation or "sanitize" in recommendation

        # Encryption-related
        help_text = "Weak encryption algorithm used"
        recommendation = analyzer._extract_recommendation(help_text)
        assert "encryption" in recommendation


if __name__ == '__main__':
    pytest.main([__file__, '-v'])