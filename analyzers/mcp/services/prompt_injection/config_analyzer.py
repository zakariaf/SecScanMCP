"""Configuration prompt injection analyzer."""

import json
import logging
from pathlib import Path
from typing import List, Any

from models import Finding
from .patterns import PromptInjectionPatterns
from .utils import check_text_for_patterns

logger = logging.getLogger(__name__)


class ConfigPromptAnalyzer:
    """Analyzes config files for prompt injection patterns."""

    CONFIG_PATTERNS = ['mcp.json', 'mcp.yaml', 'mcp.yml', '.mcp/**']

    def analyze(self, repo: Path) -> List[Finding]:
        """Analyze all config files for injection patterns."""
        findings = []
        for pattern in self.CONFIG_PATTERNS:
            for config_file in repo.glob(pattern):
                if config_file.is_file():
                    findings.extend(self._check_config(config_file))
        return findings

    def _check_config(self, config_file: Path) -> List[Finding]:
        """Check configuration file for injection."""
        findings = []
        try:
            content = config_file.read_text()
            config_data = self._parse_config(content, config_file)

            if config_data and isinstance(config_data, dict):
                if 'resources' in config_data:
                    findings.extend(self._analyze_resources(
                        config_data['resources'], str(config_file)
                    ))
                if 'prompts' in config_data:
                    findings.extend(self._analyze_prompts(
                        config_data['prompts'], str(config_file)
                    ))

            findings.extend(check_text_for_patterns(
                content, str(config_file), PromptInjectionPatterns.get_all_patterns()
            ))
        except Exception as e:
            logger.warning(f"Error analyzing config {config_file}: {e}")
        return findings

    def _parse_config(self, content: str, config_file: Path) -> Any:
        """Parse config file based on type."""
        try:
            if config_file.suffix == '.json':
                return json.loads(content)
            elif config_file.suffix in ['.yaml', '.yml']:
                import yaml
                return yaml.safe_load(content)
        except:
            pass
        return None

    def _analyze_resources(self, resources: Any, location: str) -> List[Finding]:
        """Analyze resources section."""
        findings = []
        items = resources.items() if isinstance(resources, dict) else enumerate(resources) if isinstance(resources, list) else []
        for key, resource in items:
            loc = f"{location}:resources[{key}]" if isinstance(resources, list) else f"{location}:resources.{key}"
            findings.extend(self._check_item(resource, loc, PromptInjectionPatterns.RESOURCE_PATTERNS))
        return findings

    def _analyze_prompts(self, prompts: Any, location: str) -> List[Finding]:
        """Analyze prompts section."""
        findings = []
        items = prompts.items() if isinstance(prompts, dict) else enumerate(prompts) if isinstance(prompts, list) else []
        for key, prompt in items:
            loc = f"{location}:prompts[{key}]" if isinstance(prompts, list) else f"{location}:prompts.{key}"
            findings.extend(self._check_prompt(prompt, loc))
        return findings

    def _check_item(self, item: Any, location: str, patterns: list) -> List[Finding]:
        """Check item description and URI."""
        if not isinstance(item, dict):
            return []
        findings = []
        for field in ['description', 'uri']:
            if field in item:
                findings.extend(check_text_for_patterns(
                    item[field], f"{location}:{field}", patterns
                ))
        return findings

    def _check_prompt(self, prompt: Any, location: str) -> List[Finding]:
        """Check prompt item for injection patterns."""
        if not isinstance(prompt, dict):
            return []
        findings = []
        if 'description' in prompt:
            findings.extend(check_text_for_patterns(
                prompt['description'], f"{location}:description",
                PromptInjectionPatterns.INJECTION_PATTERNS
            ))
        if 'arguments' in prompt and isinstance(prompt['arguments'], list):
            for i, arg in enumerate(prompt['arguments']):
                if isinstance(arg, dict) and 'description' in arg:
                    findings.extend(check_text_for_patterns(
                        arg['description'], f"{location}:arguments[{i}]:description",
                        PromptInjectionPatterns.INJECTION_PATTERNS
                    ))
        return findings
