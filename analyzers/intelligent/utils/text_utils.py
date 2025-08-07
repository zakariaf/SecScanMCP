"""Text processing utilities."""

import re
from typing import List, Set


def extract_keywords(text: str, keywords: List[str]) -> Set[str]:
    """Extract matching keywords from text."""
    text_lower = text.lower()
    return {kw for kw in keywords if kw in text_lower}


def clean_text(text: str) -> str:
    """Clean and normalize text."""
    if not text:
        return ""
    
    # Remove special characters and normalize whitespace
    cleaned = re.sub(r'[@\-_/]', ' ', text.lower())
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    return cleaned


def extract_sentences(text: str) -> List[str]:
    """Extract sentences from text."""
    if not text:
        return []
        
    sentences = re.split(r'[.!?]+', text.lower())
    return [s.strip() for s in sentences if len(s.strip()) > 5]


def calculate_text_overlap(text1: str, text2: str) -> float:
    """Calculate word overlap between two texts."""
    if not text1 or not text2:
        return 0.0
        
    words1 = set(text1.lower().split())
    words2 = set(text2.lower().split())
    
    overlap = len(words1 & words2)
    total = len(words1 | words2)
    
    return overlap / total if total > 0 else 0.0