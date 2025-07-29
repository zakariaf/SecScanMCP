#!/usr/bin/env python3
"""
MCP Security Scanner - Simplified API Service
Focuses purely on scanning functionality
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
import tempfile
import shutil
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
import asyncio
import uvicorn

from scanner import SecurityScanner
from models import ScanRequest, ScanResult

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="MCP Security Scanner",
    description="Security vulnerability scanner for MCP servers",
    version="2.0.0"
)

# Initialize scanner
scanner = SecurityScanner()


@app.get("/health")
async def health_check():
    """Simple health check endpoint"""
    return {
        "status": "healthy",
        "service": "mcp-security-scanner",
        "version": "2.0.0"
    }


@app.post("/scan", response_model=ScanResult)
async def scan_repository(request: ScanRequest):
    """
    Scan a repository for security vulnerabilities

    This is the only endpoint you need. Submit a repository URL
    and get back comprehensive security analysis results.
    """
    temp_dir = None

    try:
        # Create temporary directory for cloning
        temp_dir = tempfile.mkdtemp(prefix="mcp_scan_")
        logger.info(f"Starting scan for {request.repository_url}")

        # Run security scan
        result = await scanner.scan_repository(
            repository_url=str(request.repository_url),
            temp_dir=temp_dir,
            scan_options=request.options
        )

        logger.info(f"Scan completed. Score: {result.security_score}")
        return result

    except Exception as e:
        logger.error(f"Scan failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {str(e)}"
        )

    finally:
        # Cleanup temporary directory
        if temp_dir and Path(temp_dir).exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
            logger.debug(f"Cleaned up temp directory: {temp_dir}")


@app.get("/tools")
async def list_security_tools():
    """List all security tools used by the scanner"""
    return {
        "tools": [
            {
                "name": "yara",
                "version": "4.5.0",
                "description": "Advanced pattern matching engine for APTs and polymorphic malware",
                "type": "pattern-matching",
                "capabilities": ["apt-detection", "polymorphic-malware", "complex-patterns", "threat-hunting"]
            },
            {
                "name": "clamav",
                "version": "1.4.0",
                "description": "Enterprise malware detection engine with 8M+ signatures",
                "type": "malware",
                "capabilities": ["malware", "virus", "trojan", "backdoor", "rootkit", "ransomware"]
            },
            {
                "name": "trivy",
                "version": "0.60.0",
                "description": "Comprehensive vulnerability scanner by Aqua Security",
                "type": "universal",
                "capabilities": ["vulnerabilities", "secrets", "misconfigurations", "licenses"]
            },
            {
                "name": "grype",
                "version": "0.84.0",
                "description": "Fast vulnerability scanner by Anchore",
                "type": "universal",
                "capabilities": ["vulnerabilities", "sbom-scan"]
            },
            {
                "name": "syft",
                "version": "1.18.0",
                "description": "SBOM generator and component analyzer",
                "type": "universal",
                "capabilities": ["sbom", "licenses", "components"]
            },
            {
                "name": "bandit",
                "version": "1.7.10",
                "description": "Security linter for Python code",
                "type": "static",
                "languages": ["python"]
            },
            {
                "name": "semgrep",
                "version": "1.97.0",
                "description": "Static analysis with custom rules",
                "type": "static",
                "languages": ["python", "javascript", "typescript", "go", "rust", "java", "ruby", "php"]
            },
            {
                "name": "trufflehog",
                "version": "3.82.0",
                "description": "Searches for secrets in code",
                "type": "secrets",
                "capabilities": ["secrets", "api-keys", "credentials"]
            },
            {
                "name": "mcp-analyzer",
                "version": "1.0.0",
                "description": "Custom MCP-specific security checks",
                "type": "mcp",
                "capabilities": ["prompt-injection", "tool-poisoning", "permission-abuse"]
            }
        ]
    }


if __name__ == "__main__":
    # Run with uvicorn for development
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )