"""
YARA Rule Service

Manages YARA rule loading and compilation
Following clean architecture with single responsibility
"""

import os
import yara
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class RuleService:
    """Manages YARA rules and compilation"""
    
    # Rule directory paths
    RULES_DIR = Path("/app/rules/yara")
    ALTERNATIVE_PATHS = [
        Path("/app/rules/yara"),
        Path("./rules/yara"),
        Path(os.path.join(os.path.dirname(__file__), "../../../rules/yara"))
    ]
    
    def __init__(self):
        self.rules: Optional[yara.Rules] = None
        self._load_rules()
    
    def _load_rules(self):
        """Load all YARA rules from rules directory"""
        try:
            rules_path = self._find_rules_directory()
            if not rules_path:
                logger.error("No YARA rules directory found")
                return
            
            # Compile rules from directory
            rules_dict = self._collect_rule_files(rules_path)
            if not rules_dict:
                logger.warning(f"No .yar files found in {rules_path}")
                return
            
            # Compile all rules
            self.rules = yara.compile(filepaths=rules_dict)
            logger.info(f"Successfully loaded {len(rules_dict)} YARA rules")
            
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            self.rules = None
    
    def _find_rules_directory(self) -> Optional[Path]:
        """Find the YARA rules directory"""
        # Check primary path
        if self.RULES_DIR.exists():
            return self.RULES_DIR
        
        logger.warning(f"YARA rules directory not found at {self.RULES_DIR}")
        
        # Try alternative paths
        for alt_path in self.ALTERNATIVE_PATHS:
            if alt_path.exists():
                logger.info(f"Found YARA rules at {alt_path}")
                return alt_path
        
        return None
    
    def _collect_rule_files(self, rules_path: Path) -> dict:
        """Collect all .yar files from directory"""
        rules_dict = {}
        rule_files = list(rules_path.glob("*.yar"))
        
        for rule_file in rule_files:
            try:
                # Use absolute path for rule file
                rule_path = str(rule_file.absolute())
                logger.info(f"Loading YARA rule: {rule_path}")
                rules_dict[rule_file.stem] = rule_path
            except Exception as e:
                logger.error(f"Failed to load rule {rule_file}: {e}")
        
        return rules_dict