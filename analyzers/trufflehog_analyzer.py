"""
TruffleHog analyzer - Searches for secrets in code
"""

import json
import asyncio
from pathlib import Path
from typing import List, Dict, Any

from .base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType


class TruffleHogAnalyzer(BaseAnalyzer):
    """
    Integrates TruffleHog - Searches for secrets in git repos
    https://github.com/trufflesecurity/trufflehog
    """

    # Map detector types to our vulnerability types
    SECRET_TYPE_MAP = {
        'AWS': VulnerabilityType.API_KEY_EXPOSURE,
        'GitHub': VulnerabilityType.API_KEY_EXPOSURE,
        'GitLab': VulnerabilityType.API_KEY_EXPOSURE,
        'Slack': VulnerabilityType.API_KEY_EXPOSURE,
        'PrivateKey': VulnerabilityType.HARDCODED_SECRET,
        'JWT': VulnerabilityType.HARDCODED_SECRET,
        'Password': VulnerabilityType.HARDCODED_SECRET,
        'Generic': VulnerabilityType.HARDCODED_SECRET,
    }

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Run TruffleHog to find secrets"""
        findings = []

        try:
            # Run trufflehog on filesystem (not git history for speed)
            cmd = [
                'trufflehog',
                'filesystem',
                repo_path,
                '--json',
                '--no-update',  # Don't update detectors
                '--concurrency', '4',
                '--exclude-paths', '.git',
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Process output line by line (TruffleHog outputs JSON lines)
            findings_data = []
            while True:
                line = await process.stdout.readline()
                if not line:
                    break

                try:
                    result = json.loads(line.decode().strip())
                    if result:
                        findings_data.append(result)
                except json.JSONDecodeError:
                    continue

            await process.wait()

            # Convert to our finding format
            for result in findings_data:
                finding = self._convert_to_finding(result, repo_path)
                if finding:
                    findings.append(finding)

            self.logger.info(f"TruffleHog found {len(findings)} secrets")

        except Exception as e:
            self.logger.error(f"TruffleHog analysis failed: {e}")

        return findings

    def _convert_to_finding(self, trufflehog_result: Dict[str, Any], repo_path: str) -> Finding:
        """Convert TruffleHog result to our Finding model"""

        # Extract detector information
        detector_name = trufflehog_result.get('DetectorName', 'Unknown')
        detector_type = trufflehog_result.get('DetectorType', 0)

        # Map to our vulnerability type
        vuln_type = VulnerabilityType.HARDCODED_SECRET
        for key, vtype in self.SECRET_TYPE_MAP.items():
            if key.lower() in detector_name.lower():
                vuln_type = vtype
                break

        # All secrets are high severity by default
        severity = SeverityLevel.HIGH
        if 'test' in detector_name.lower() or 'example' in detector_name.lower():
            severity = SeverityLevel.MEDIUM

        # Get source metadata
        source_metadata = trufflehog_result.get('SourceMetadata', {})
        data = source_metadata.get('Data', {})

        # Build file location
        file_path = data.get('Filesystem', {}).get('file', 'unknown')
        try:
            file_path = Path(file_path).relative_to(repo_path)
        except:
            pass

        line_num = data.get('Filesystem', {}).get('line', 0)

        # Mask the actual secret in evidence
        raw_secret = trufflehog_result.get('Raw', '')
        if len(raw_secret) > 8:
            masked_secret = raw_secret[:4] + '*' * (len(raw_secret) - 8) + raw_secret[-4:]
        else:
            masked_secret = '*' * len(raw_secret)

        return self.create_finding(
            vulnerability_type=vuln_type,
            severity=severity,
            confidence=trufflehog_result.get('VerifiedResult', False) and 0.95 or 0.7,
            title=f"{detector_name} Secret Detected",
            description=f"Found {detector_name} credentials in source code",
            location=f"{file_path}:{line_num}",
            recommendation="Remove the secret immediately and rotate the credentials. Use environment variables or a secret management system instead.",
            references=[
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"
            ],
            evidence={
                'detector': detector_name,
                'masked_secret': masked_secret,
                'verified': trufflehog_result.get('Verified', False),
                'secret_type': detector_type,
                'line_content': data.get('Filesystem', {}).get('line_content', '')
            }
        )