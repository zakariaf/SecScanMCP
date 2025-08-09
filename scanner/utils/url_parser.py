"""URL parsing utilities for repository URLs."""

import re
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class GitHubURLParser:
    """Parses GitHub URLs to extract repository information."""
    
    # URL pattern definitions
    PATTERNS = [
        # https://github.com/owner/repo/tree/branch/path/to/dir
        r'github\.com/([^/]+)/([^/]+)/tree/([^/]+)/(.+)',
        # https://github.com/owner/repo/tree/branch
        r'github\.com/([^/]+)/([^/]+)/tree/([^/]+)/?$',
        # https://github.com/owner/repo
        r'github\.com/([^/]+)/([^/]+)/?$'
    ]
    
    def parse(self, url: str) -> Dict[str, Optional[str]]:
        """
        Parse GitHub URL to extract repo info and subdirectory.
        
        Args:
            url: GitHub repository URL
            
        Returns:
            Dictionary with git_url, branch, subdirectory
        """
        for pattern in self.PATTERNS:
            match = re.search(pattern, url)
            if match:
                return self._extract_info(match)
        
        # Handle non-matching GitHub URLs
        if 'github.com' in url:
            logger.warning(f"GitHub URL didn't match expected patterns: {url}")
        
        return {
            'git_url': url,
            'branch': None,  # Let git determine the default branch
            'subdirectory': None
        }
    
    def _extract_info(self, match: re.Match) -> Dict[str, Optional[str]]:
        """Extract information from regex match."""
        groups = match.groups()
        
        result = {
            'owner': groups[0],
            'repo': groups[1],
            'git_url': f"https://github.com/{groups[0]}/{groups[1]}.git"
        }
        
        # Extract branch if present
        if len(groups) >= 3:
            result['branch'] = groups[2]
        else:
            result['branch'] = None
        
        # Extract subdirectory if present
        if len(groups) >= 4:
            result['subdirectory'] = groups[3]
        else:
            result['subdirectory'] = None
        
        return result