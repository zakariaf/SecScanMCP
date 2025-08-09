"""
Pack Synthesis Service for CodeQL Analysis

Manages CodeQL query packs and suite configurations
Following clean architecture with single responsibility
"""

import shutil
import logging
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class PackService:
    """Manages CodeQL query packs and suite synthesis"""
    
    # Root where language-specific queries are mounted (read-only in container)
    RULES_ROOT = Path("/app/rules/codeql/mcp-security-queries")
    
    # Official code-scanning suites by language
    OFFICIAL_SUITES = {
        "javascript": "codeql/javascript-queries:codeql-suites/javascript-code-scanning.qls",
        "python": "codeql/python-queries:codeql-suites/python-code-scanning.qls", 
        "java": "codeql/java-queries:codeql-suites/java-code-scanning.qls",
        "go": "codeql/go-queries:codeql-suites/go-code-scanning.qls",
        "cpp": "codeql/cpp-queries:codeql-suites/cpp-code-scanning.qls",
        "csharp": "codeql/csharp-queries:codeql-suites/csharp-code-scanning.qls",
        "ruby": "codeql/ruby-queries:codeql-suites/ruby-code-scanning.qls",
    }
    
    # Core language dependencies for packs
    CORE_DEPENDENCIES = {
        "javascript": "codeql/javascript-all",
        "python": "codeql/python-all",
        "java": "codeql/java-all", 
        "go": "codeql/go-all",
        "cpp": "codeql/cpp-all",
        "csharp": "codeql/csharp-all",
        "ruby": "codeql/ruby-all",
    }
    
    def __init__(self, cli_service):
        self.cli_service = cli_service
        self.local_suite_for_lang: Dict[str, Path] = {}
    
    async def synthesize_language_packs(self, packs_root: Path) -> None:
        """Set up language-specific packs from RULES_ROOT"""
        if not self.RULES_ROOT.exists():
            logger.info(f"No local CodeQL rules found at {self.RULES_ROOT}")
            return
        
        # Process JavaScript pack
        await self._setup_javascript_pack(packs_root)
        
        # Process Python pack
        await self._setup_python_pack(packs_root)
    
    def get_official_suite_for_language(self, language: str) -> Optional[str]:
        """Get official CodeQL suite for language"""
        return self.OFFICIAL_SUITES.get(language)
    
    def get_core_dependency_for_language(self, language: str) -> Optional[str]:
        """Get core dependency for language pack"""
        return self.CORE_DEPENDENCIES.get(language)
    
    def get_local_suite_for_language(self, language: str) -> Optional[Path]:
        """Get local MCP suite path for language"""
        return self.local_suite_for_lang.get(language)
    
    async def _setup_javascript_pack(self, packs_root: Path):
        """Setup JavaScript MCP security pack"""
        js_pack_path = self.RULES_ROOT
        
        if not (js_pack_path / "qlpack.yml").exists() or not (js_pack_path / "javascript").exists():
            logger.debug("JavaScript MCP security pack not found")
            return
        
        logger.info("Found JavaScript MCP security pack")
        
        # Copy to working directory
        js_work_pack = packs_root / "mcp-security-queries-javascript"
        shutil.copytree(js_pack_path, js_work_pack, dirs_exist_ok=True)
        
        # Clean up Python directory if present
        python_dir = js_work_pack / "python"
        if python_dir.exists():
            shutil.rmtree(python_dir)
        
        # Set suite path
        self.local_suite_for_lang["javascript"] = js_work_pack / "mcp-javascript-suite.qls"
        
        # Install dependencies
        await self._install_pack_dependencies(js_work_pack, "JavaScript")
    
    async def _setup_python_pack(self, packs_root: Path):
        """Setup Python MCP security pack"""
        py_pack_path = self.RULES_ROOT / "python"
        
        if not (py_pack_path / "qlpack.yml").exists():
            logger.debug("Python MCP security pack not found")
            return
        
        logger.info("Found Python MCP security pack")
        
        # Copy to working directory
        py_work_pack = packs_root / "mcp-security-queries-python"
        shutil.copytree(py_pack_path, py_work_pack, dirs_exist_ok=True)
        
        # Set suite path
        self.local_suite_for_lang["python"] = py_work_pack / "mcp-python-suite.qls"
        
        # Install dependencies
        await self._install_pack_dependencies(py_work_pack, "Python")
    
    async def _install_pack_dependencies(self, pack_path: Path, language_name: str):
        """Install dependencies for a CodeQL pack"""
        try:
            logger.info(f"Installing {language_name} MCP CodeQL pack from {pack_path}")
            await self.cli_service.run_command(
                ["pack", "install"], 
                cwd=str(pack_path), 
                timeout=300
            )
        except Exception as e:
            logger.error(f"CodeQL pack install failed for {language_name} pack: {e}")