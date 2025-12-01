"""Tests for StringMatcherService"""

from pathlib import Path
from types import SimpleNamespace
from analyzers.security_tools.yara.services.string_matcher import (
    StringMatcherService, MAX_MATCHES, MAX_CONTENT_LENGTH
)


def _mock_match_pre43(strings):
    """Create mock match with pre-4.3 tuple format"""
    return SimpleNamespace(strings=strings)


def _mock_match_post43(strings):
    """Create mock match with post-4.3 StringMatch format"""
    mock_strings = []
    for identifier, offset, data in strings:
        instance = SimpleNamespace(offset=offset, matched_data=data)
        mock_strings.append(SimpleNamespace(
            identifier=identifier,
            instances=[instance]
        ))
    return SimpleNamespace(strings=mock_strings)


def test_extract_pre43_format(tmp_path):
    """Test extraction with pre-4.3 tuple format"""
    svc = StringMatcherService()
    content = 'line one\nline two with secret\nline three'
    fpath = tmp_path / 'test.txt'
    fpath.write_text(content)

    offset = content.index('secret')
    match = _mock_match_pre43([(offset, '$a', b'secret')])

    result = svc.extract_matched_strings(match, fpath)

    assert len(result) == 1
    assert result[0]['identifier'] == '$a'
    assert result[0]['line'] == 2
    assert 'secret' in result[0]['line_content']


def test_extract_post43_format(tmp_path):
    """Test extraction with post-4.3 StringMatch format"""
    svc = StringMatcherService()
    content = 'first\nsecond with password\nthird'
    fpath = tmp_path / 'test.txt'
    fpath.write_text(content)

    offset = content.index('password')
    match = _mock_match_post43([('$pwd', offset, b'password')])

    result = svc.extract_matched_strings(match, fpath)

    assert len(result) == 1
    assert result[0]['identifier'] == '$pwd'
    assert result[0]['line'] == 2


def test_max_matches_limit(tmp_path):
    """Test that results are limited to MAX_MATCHES"""
    svc = StringMatcherService()
    fpath = tmp_path / 'test.txt'
    fpath.write_text('test content')

    # Create more matches than limit
    strings = [(i, f'$s{i}', b'test') for i in range(MAX_MATCHES + 5)]
    match = _mock_match_pre43(strings)

    result = svc.extract_matched_strings(match, fpath)

    assert len(result) == MAX_MATCHES


def test_content_truncation(tmp_path):
    """Test that long content is truncated"""
    svc = StringMatcherService()
    fpath = tmp_path / 'test.txt'
    fpath.write_text('x' * 200)

    long_data = b'a' * 200
    match = _mock_match_pre43([(0, '$long', long_data)])

    result = svc.extract_matched_strings(match, fpath)

    assert len(result[0]['content']) == MAX_CONTENT_LENGTH


def test_empty_strings(tmp_path):
    """Test handling of empty strings list"""
    svc = StringMatcherService()
    fpath = tmp_path / 'test.txt'
    fpath.write_text('content')

    match = _mock_match_pre43([])
    result = svc.extract_matched_strings(match, fpath)

    assert result == []


def test_file_not_found():
    """Test handling of non-existent file"""
    svc = StringMatcherService()
    fpath = Path('/nonexistent/file.txt')

    match = _mock_match_pre43([(0, '$a', b'test')])
    result = svc.extract_matched_strings(match, fpath)

    # Should not crash, returns match without line info
    assert len(result) == 1
    assert result[0]['line'] is None


def test_multiple_lines(tmp_path):
    """Test matches on multiple lines"""
    svc = StringMatcherService()
    content = 'first\nsecret1\nthird\nsecret2\nfifth'
    fpath = tmp_path / 'test.txt'
    fpath.write_text(content)

    strings = [
        (content.index('secret1'), '$s1', b'secret1'),
        (content.index('secret2'), '$s2', b'secret2'),
    ]
    match = _mock_match_pre43(strings)

    result = svc.extract_matched_strings(match, fpath)

    assert len(result) == 2
    assert result[0]['line'] == 2
    assert result[1]['line'] == 4
