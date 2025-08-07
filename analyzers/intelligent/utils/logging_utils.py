"""Structured logging utilities with scan ID tracking."""

import uuid
import structlog
import logging
from contextvars import ContextVar
from typing import Dict, Any, Optional
from contextlib import contextmanager

# Context variable to store scan ID across async calls
scan_id_context: ContextVar[Optional[str]] = ContextVar('scan_id', default=None)


class ScanContextLogger:
    """Logger that automatically includes scan ID in all log messages."""
    
    def __init__(self, name: str):
        self.name = name
        self._logger = structlog.get_logger(name)
    
    def _get_context(self, **kwargs) -> Dict[str, Any]:
        """Get current logging context with scan ID, handling keyword conflicts."""
        context = {}
        
        scan_id = scan_id_context.get()
        if scan_id:
            context['scan_id'] = scan_id
        
        # Use provided component or default to logger name
        context['component'] = kwargs.pop('component', self.name)
        
        # Merge any additional context from kwargs
        context.update(kwargs)
        return context
    
    def debug(self, msg: str, **kwargs):
        """Log debug message with context."""
        context = self._get_context(**kwargs)
        self._logger.debug(msg, **context)
    
    def info(self, msg: str, **kwargs):
        """Log info message with context."""
        context = self._get_context(**kwargs)
        self._logger.info(msg, **context)
    
    def warning(self, msg: str, **kwargs):
        """Log warning message with context."""
        context = self._get_context(**kwargs)
        self._logger.warning(msg, **context)
    
    def error(self, msg: str, **kwargs):
        """Log error message with context."""
        context = self._get_context(**kwargs)
        self._logger.error(msg, **context)
    
    def exception(self, msg: str, **kwargs):
        """Log exception with context."""
        context = self._get_context(**kwargs)
        self._logger.exception(msg, **context)


def get_scan_logger(name: str) -> ScanContextLogger:
    """Get a scan-aware logger for the given component."""
    return ScanContextLogger(name)


@contextmanager
def scan_context(project_name: str = None):
    """Context manager for scan ID tracking."""
    scan_id = generate_scan_id(project_name)
    token = scan_id_context.set(scan_id)
    
    try:
        logger = get_scan_logger('scan_manager')
        logger.info("Scan started", scan_id=scan_id, project_name=project_name)
        yield scan_id
    finally:
        logger = get_scan_logger('scan_manager')
        logger.info("Scan completed", scan_id=scan_id)
        scan_id_context.reset(token)


def generate_scan_id(project_name: str = None) -> str:
    """Generate unique scan ID."""
    base_id = str(uuid.uuid4())[:8]
    
    if project_name:
        # Include project name prefix for easier identification
        safe_name = ''.join(c for c in project_name if c.isalnum())[:8]
        return f"{safe_name}-{base_id}"
    
    return f"scan-{base_id}"


def configure_structured_logging(level: str = "INFO", format_json: bool = True):
    """Configure structured logging for the application."""
    
    # Configure structlog
    if format_json:
        # JSON format for production
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.add_log_level,
                structlog.processors.StackInfoRenderer(),
                structlog.dev.set_exc_info,
                structlog.processors.JSONRenderer()
            ],
            wrapper_class=structlog.make_filtering_bound_logger(
                getattr(logging, level.upper())
            ),
            logger_factory=structlog.WriteLoggerFactory(),
            cache_logger_on_first_use=True,
        )
    else:
        # Human-readable format for development
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.add_log_level,
                structlog.processors.StackInfoRenderer(),
                structlog.dev.set_exc_info,
                structlog.dev.ConsoleRenderer(colors=True)
            ],
            wrapper_class=structlog.make_filtering_bound_logger(
                getattr(logging, level.upper())
            ),
            logger_factory=structlog.WriteLoggerFactory(),
            cache_logger_on_first_use=True,
        )
    
    # Configure standard logging to work with structlog
    logging.basicConfig(
        format="%(message)s",
        level=getattr(logging, level.upper()),
    )