"""
TruffleHog Scan Service

Handles TruffleHog execution and streaming JSON line parsing
Following clean architecture with single responsibility
"""

import json
import asyncio
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class ScanService:
    """Handles TruffleHog scan execution with streaming output"""
    
    # TruffleHog command template
    COMMAND_TEMPLATE = [
        'trufflehog',
        'filesystem',
        '--json',
        '--no-update',        # Don't update detectors
        '--concurrency', '4',
        '--exclude-paths', '.git',
    ]
    
    async def run_scan(self, repo_path: str) -> List[Dict[str, Any]]:
        """Run TruffleHog scan and collect results"""
        try:
            cmd = self._build_command(repo_path)
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Process streaming JSON lines
            results = await self._process_streaming_output(process)
            
            await process.wait()
            return results
            
        except Exception as e:
            logger.error(f"TruffleHog scan execution failed: {e}")
            return []
    
    def _build_command(self, repo_path: str) -> list:
        """Build TruffleHog command"""
        cmd = self.COMMAND_TEMPLATE.copy()
        cmd.append(repo_path)
        return cmd
    
    async def _process_streaming_output(self, process) -> List[Dict[str, Any]]:
        """Process TruffleHog's streaming JSON output line by line"""
        results = []
        
        # TruffleHog outputs JSON lines, not a single JSON object
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            
            parsed_result = self._parse_json_line(line)
            if parsed_result:
                results.append(parsed_result)
        
        return results
    
    def _parse_json_line(self, line: bytes) -> Dict[str, Any]:
        """Parse a single JSON line from TruffleHog output"""
        try:
            decoded_line = line.decode().strip()
            if decoded_line:
                return json.loads(decoded_line)
        except json.JSONDecodeError as e:
            logger.debug(f"Failed to parse TruffleHog JSON line: {e}")
        except UnicodeDecodeError as e:
            logger.debug(f"Failed to decode TruffleHog output line: {e}")
        
        return {}