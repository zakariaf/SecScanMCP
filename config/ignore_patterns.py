"""
Ignore patterns for security scanning - directories and files to skip
"""

import os
from pathlib import Path
from typing import List, Set
import fnmatch

class IgnorePatterns:
    """
    Centralized ignore patterns for all security analyzers
    """
    
    # Core directories that should never be scanned
    IGNORE_DIRECTORIES = {
        # Version control
        '.git', '.svn', '.hg', '.bzr',
        
        # CI/CD and workflows  
        '.github', '.gitlab', '.circleci', '.travis', '.appveyor',
        '.azure-pipelines', '.buildkite', '.jenkins',
        
        # IDE and editor files
        '.vscode', '.idea', '.eclipse', '.sublime-text',
        
        # Build and cache directories
        'node_modules', '__pycache__', '.pytest_cache', '.coverage',
        'build', 'dist', 'target', 'bin', 'obj', 'out',
        '.gradle', '.maven', '.sbt',
        
        # Package managers
        'vendor', 'packages', '.nuget', 'bower_components',
        
        # Documentation (usually safe)
        'docs', 'documentation', 'doc', 'man', 'help',
        
        # Test fixtures and mock data (can contain intentional vulnerabilities)
        'fixtures', 'mocks', 'stubs', 'samples', 'examples',
        
        # Temporary and log directories
        'tmp', 'temp', 'logs', 'log', 'cache', '.cache',
        
        # OS specific
        '.DS_Store', 'Thumbs.db', 'desktop.ini',
        
        # Language specific
        '.venv', 'venv', 'env', '.env', 'virtualenv',  # Python
        '.tox', '.nox', '.mypy_cache',
        'elm-stuff',  # Elm
        '_site',  # Jekyll
        '.next',  # Next.js
        '.nuxt',  # Nuxt.js
    }
    
    # File patterns to ignore
    IGNORE_FILE_PATTERNS = {
        # Compiled/binary files
        '*.pyc', '*.pyo', '*.class', '*.jar', '*.war', '*.ear',
        '*.exe', '*.dll', '*.so', '*.dylib', '*.a', '*.lib',
        '*.o', '*.obj', '*.bin',
        
        # Archives
        '*.zip', '*.tar', '*.gz', '*.bz2', '*.xz', '*.7z', '*.rar',
        
        # Images and media (rarely contain code vulnerabilities)
        '*.jpg', '*.jpeg', '*.png', '*.gif', '*.bmp', '*.ico', '*.svg',
        '*.mp4', '*.avi', '*.mov', '*.wmv', '*.mp3', '*.wav',
        
        # Fonts
        '*.ttf', '*.otf', '*.woff', '*.woff2', '*.eot',
        
        # Lock files (dependency files, not source code)
        'package-lock.json', 'yarn.lock', 'Pipfile.lock', 'poetry.lock',
        'Gemfile.lock', 'composer.lock', 'pnpm-lock.yaml',
        
        # Generated files
        '*.min.js', '*.min.css', '*.bundle.js', '*.chunk.js',
        '*.generated.*', '*.gen.*',
        
        # Log files
        '*.log', '*.out', '*.err',
        
        # Backup files
        '*~', '*.bak', '*.backup', '*.swp', '*.swo',
        
        # OS files
        '.DS_Store', 'Thumbs.db', 'desktop.ini',
    }
    
    # File extensions that are typically safe to ignore
    SAFE_EXTENSIONS = {
        # Documentation
        '.md', '.rst', '.txt', '.rtf', '.pdf', '.doc', '.docx',
        
        # Configuration that's usually safe
        '.gitignore', '.dockerignore', '.editorconfig',
        
        # Licenses and legal
        'LICENSE', 'COPYING', 'COPYRIGHT', 'NOTICE',
    }
    
    # Special patterns for security tools (some tools need different ignore patterns)
    TOOL_SPECIFIC_IGNORES = {
        'bandit': {
            # Bandit is Python-specific, so we can ignore more
            'ignore_dirs': {'node_modules', 'vendor', 'elm-stuff', '.next'},
            'ignore_files': {'*.js', '*.ts', '*.go', '*.rs', '*.java'},
        },
        'opengrep': {
            # OpenGrep can scan many languages, but skip test files
            'ignore_dirs': {'test', 'tests', '__tests__', 'spec', 'specs'},
            'ignore_files': {'*.test.*', '*.spec.*', '*_test.*'},
        },
        'codeql': {
            # CodeQL needs source code, so be less aggressive
            'ignore_dirs': {'node_modules', '__pycache__', 'build'},
            'ignore_files': {'*.min.js', '*.bundle.js'},
        },
        'yara': {
            # YARA should scan more broadly for malware patterns
            'ignore_dirs': {'node_modules', '__pycache__'},
            'ignore_files': {'*.min.js'},
        },
        'trivy': {
            # Trivy scans for vulnerabilities and secrets, include more files
            'ignore_dirs': {'node_modules', 'vendor'},
            'ignore_files': set(),
        }
    }
    
    @classmethod
    def should_ignore_directory(cls, dir_path: str, tool_name: str = None) -> bool:
        """
        Check if a directory should be ignored
        """
        dir_name = os.path.basename(dir_path.rstrip('/'))
        
        # Check core ignore patterns
        if dir_name in cls.IGNORE_DIRECTORIES:
            return True
            
        # Check tool-specific patterns
        if tool_name and tool_name in cls.TOOL_SPECIFIC_IGNORES:
            tool_ignores = cls.TOOL_SPECIFIC_IGNORES[tool_name].get('ignore_dirs', set())
            if dir_name in tool_ignores:
                return True
        
        # Check if it's a hidden directory (starts with .)
        if dir_name.startswith('.') and dir_name not in {'.', '..'}:
            # Allow some important hidden directories
            allowed_hidden = {'.mcp', '.env.example'}
            if dir_name not in allowed_hidden:
                return True
        
        return False
    
    @classmethod
    def should_ignore_file(cls, file_path: str, tool_name: str = None) -> bool:
        """
        Check if a file should be ignored
        """
        file_name = os.path.basename(file_path)
        file_ext = os.path.splitext(file_name)[1].lower()
        
        # Check file patterns
        for pattern in cls.IGNORE_FILE_PATTERNS:
            if fnmatch.fnmatch(file_name, pattern):
                return True
        
        # Check safe extensions
        if file_ext in cls.SAFE_EXTENSIONS:
            return True
            
        # Check tool-specific patterns
        if tool_name and tool_name in cls.TOOL_SPECIFIC_IGNORES:
            tool_ignores = cls.TOOL_SPECIFIC_IGNORES[tool_name].get('ignore_files', set())
            for pattern in tool_ignores:
                if fnmatch.fnmatch(file_name, pattern):
                    return True
        
        # Check if file is too large (> 10MB, likely not source code)
        try:
            if os.path.getsize(file_path) > 10 * 1024 * 1024:
                return True
        except (OSError, IOError):
            pass
        
        return False
    
    @classmethod
    def get_filtered_files(cls, repo_path: str, tool_name: str = None, 
                          include_extensions: Set[str] = None) -> List[str]:
        """
        Get list of files that should be scanned, applying ignore patterns
        """
        filtered_files = []
        repo_path = Path(repo_path)
        
        for root, dirs, files in os.walk(repo_path):
            # Filter directories in-place to avoid walking into ignored dirs
            dirs[:] = [d for d in dirs if not cls.should_ignore_directory(os.path.join(root, d), tool_name)]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                # Skip ignored files
                if cls.should_ignore_file(file_path, tool_name):
                    continue
                
                # If specific extensions are requested, filter by them
                if include_extensions:
                    file_ext = os.path.splitext(file)[1].lower()
                    if file_ext not in include_extensions:
                        continue
                
                filtered_files.append(file_path)
        
        return filtered_files
    
    @classmethod
    def create_gitignore_style_list(cls, tool_name: str = None) -> List[str]:
        """
        Create a .gitignore style list for tools that support it
        """
        patterns = []
        
        # Add directory patterns
        for dir_name in cls.IGNORE_DIRECTORIES:
            patterns.append(f"{dir_name}/")
            patterns.append(f"**/{dir_name}/")
        
        # Add file patterns
        patterns.extend(cls.IGNORE_FILE_PATTERNS)
        
        # Add tool-specific patterns
        if tool_name and tool_name in cls.TOOL_SPECIFIC_IGNORES:
            tool_config = cls.TOOL_SPECIFIC_IGNORES[tool_name]
            for dir_name in tool_config.get('ignore_dirs', set()):
                patterns.append(f"{dir_name}/")
                patterns.append(f"**/{dir_name}/")
            patterns.extend(tool_config.get('ignore_files', set()))
        
        return patterns
    
    @classmethod
    def get_scan_summary(cls, repo_path: str) -> dict:
        """
        Get summary of what will be scanned vs ignored
        """
        total_files = 0
        ignored_files = 0
        scanned_files = 0
        ignored_dirs = set()
        
        for root, dirs, files in os.walk(repo_path):
            # Check for ignored directories
            original_dirs = dirs.copy()
            dirs[:] = [d for d in dirs if not cls.should_ignore_directory(os.path.join(root, d))]
            ignored_dirs.update(set(original_dirs) - set(dirs))
            
            for file in files:
                total_files += 1
                file_path = os.path.join(root, file)
                
                if cls.should_ignore_file(file_path):
                    ignored_files += 1
                else:
                    scanned_files += 1
        
        return {
            'total_files': total_files,
            'scanned_files': scanned_files,
            'ignored_files': ignored_files,
            'ignored_directories': list(ignored_dirs),
            'scan_efficiency': f"{(scanned_files/total_files)*100:.1f}%" if total_files > 0 else "0%"
        }