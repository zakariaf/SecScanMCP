"""Granular tests for IgnorePatterns logic."""
from pathlib import Path
import tempfile

from config.ignore_patterns import IgnorePatterns


def test_should_ignore_directory_core():
    assert IgnorePatterns.should_ignore_directory('/tmp/repo/node_modules')
    assert IgnorePatterns.should_ignore_directory('/tmp/repo/.git')
    assert not IgnorePatterns.should_ignore_directory('/tmp/repo/src')


def test_should_ignore_directory_tool_specific():
    # bandit ignores node_modules explicitly
    assert IgnorePatterns.should_ignore_directory('/tmp/repo/node_modules', 'bandit')


def test_should_ignore_file_patterns(tmp_path: Path):
    f = tmp_path / 'test.pyc'
    f.write_text('x')
    assert IgnorePatterns.should_ignore_file(str(f))


def test_should_ignore_file_tool_specific(tmp_path: Path):
    js_file = tmp_path / 'a.js'
    js_file.write_text('console.log(1)')
    assert IgnorePatterns.should_ignore_file(str(js_file), 'bandit')
    # codeql should not ignore js by default (except minified)
    assert not IgnorePatterns.should_ignore_file(str(js_file), 'codeql')


def test_large_file_ignored(tmp_path: Path):
    big = tmp_path / 'big.bin'
    big.write_bytes(b'0' * (10 * 1024 * 1024 + 10))
    assert IgnorePatterns.should_ignore_file(str(big))


def test_get_filtered_files_respects_tool(tmp_path: Path):
    (tmp_path / 'src').mkdir()
    (tmp_path / 'src' / 'a.py').write_text('print(1)')
    (tmp_path / 'tests').mkdir()
    (tmp_path / 'tests' / 'test_a.py').write_text('print(2)')
    files_all = IgnorePatterns.get_filtered_files(str(tmp_path), tool_name='codeql')
    files_opengrep = IgnorePatterns.get_filtered_files(str(tmp_path), tool_name='opengrep')
    assert any(p.endswith('a.py') for p in files_all)
    # opengrep config ignores test dirs
    assert not any('test_a.py' in p for p in files_opengrep)
