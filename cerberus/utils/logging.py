"""
Centralized structured logging for Cerberus SAST.

Provides:
- Rich console output with colors and formatting
- Optional JSON format for machine parsing
- File logging with rotation
- Component-aware logging with context
"""

import logging
import sys
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Any
from logging.handlers import RotatingFileHandler

from rich.logging import RichHandler
from rich.console import Console

# Global console instance for consistent output
console = Console()

# Default log format
DEFAULT_FORMAT = "%(asctime)s | %(name)s | %(levelname)s | %(message)s"
JSON_FORMAT = "json"


class JSONFormatter(logging.Formatter):
    """Format log records as JSON for machine parsing."""

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record as a JSON string."""
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra context if present
        if hasattr(record, "context"):
            log_data["context"] = record.context

        return json.dumps(log_data, default=str)


def setup_logging(
    level: str = "INFO",
    log_file: Optional[Path] = None,
    json_format: bool = False,
    max_file_size_mb: int = 10,
    backup_count: int = 5,
) -> logging.Logger:
    """
    Configure application-wide logging.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path for file logging
        json_format: Use JSON format for log output
        max_file_size_mb: Maximum log file size before rotation
        backup_count: Number of backup files to keep

    Returns:
        Configured root logger
    """
    # Get the root logger for cerberus
    logger = logging.getLogger("cerberus")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Clear existing handlers
    logger.handlers.clear()

    # Configure console handler
    if json_format:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler = RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            rich_tracebacks=True,
            tracebacks_show_locals=True,
            markup=True,
        )
        console_handler.setFormatter(logging.Formatter("%(message)s"))

    console_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.addHandler(console_handler)

    # Configure file handler if path provided
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_file_size_mb * 1024 * 1024,
            backupCount=backup_count,
        )

        if json_format:
            file_handler.setFormatter(JSONFormatter())
        else:
            file_handler.setFormatter(logging.Formatter(DEFAULT_FORMAT))

        file_handler.setLevel(logging.DEBUG)  # File gets all messages
        logger.addHandler(file_handler)

    # Prevent propagation to root logger
    logger.propagate = False

    return logger


class ComponentLogger:
    """
    Logger with component context for structured logging.

    Provides a consistent interface for logging from different components
    with automatic context injection.
    """

    def __init__(self, component: str, parent: Optional[str] = None):
        """
        Initialize a component logger.

        Args:
            component: Name of the component (e.g., "tree_sitter", "llm_gateway")
            parent: Optional parent component for hierarchical logging
        """
        self.component = component
        logger_name = f"cerberus.{parent}.{component}" if parent else f"cerberus.{component}"
        self._logger = logging.getLogger(logger_name)

    def _format_message(self, msg: str, **context: Any) -> str:
        """Format message with context."""
        if context:
            context_str = " | ".join(f"{k}={v}" for k, v in context.items())
            return f"{msg} | {context_str}"
        return msg

    def _add_context(self, **context: Any) -> dict[str, Any]:
        """Add component name to context."""
        return {"component": self.component, **context}

    def debug(self, msg: str, **context: Any) -> None:
        """Log debug message with context."""
        extra = {"context": self._add_context(**context)}
        self._logger.debug(self._format_message(msg, **context), extra=extra)

    def info(self, msg: str, **context: Any) -> None:
        """Log info message with context."""
        extra = {"context": self._add_context(**context)}
        self._logger.info(self._format_message(msg, **context), extra=extra)

    def warning(self, msg: str, **context: Any) -> None:
        """Log warning message with context."""
        extra = {"context": self._add_context(**context)}
        self._logger.warning(self._format_message(msg, **context), extra=extra)

    def error(self, msg: str, exc: Optional[Exception] = None, **context: Any) -> None:
        """Log error message with optional exception."""
        extra = {"context": self._add_context(**context)}
        if exc:
            self._logger.error(
                self._format_message(msg, **context),
                exc_info=exc,
                extra=extra,
            )
        else:
            self._logger.error(self._format_message(msg, **context), extra=extra)

    def critical(self, msg: str, exc: Optional[Exception] = None, **context: Any) -> None:
        """Log critical message with optional exception."""
        extra = {"context": self._add_context(**context)}
        if exc:
            self._logger.critical(
                self._format_message(msg, **context),
                exc_info=exc,
                extra=extra,
            )
        else:
            self._logger.critical(self._format_message(msg, **context), extra=extra)

    def exception(self, msg: str, **context: Any) -> None:
        """Log exception with traceback."""
        extra = {"context": self._add_context(**context)}
        self._logger.exception(self._format_message(msg, **context), extra=extra)


class ScanLogger(ComponentLogger):
    """
    Specialized logger for scan operations with progress tracking.
    """

    def __init__(self, scan_id: str):
        """Initialize scan logger with scan ID context."""
        super().__init__("scan")
        self.scan_id = scan_id

    def _add_context(self, **context: Any) -> dict[str, Any]:
        """Add scan ID to all log context."""
        return {"scan_id": self.scan_id, **super()._add_context(**context)}

    def phase_start(self, phase: str, **context: Any) -> None:
        """Log the start of a scan phase."""
        self.info(f"Starting phase: {phase}", phase=phase, **context)

    def phase_complete(self, phase: str, duration_ms: float, **context: Any) -> None:
        """Log the completion of a scan phase."""
        self.info(
            f"Completed phase: {phase}",
            phase=phase,
            duration_ms=round(duration_ms, 2),
            **context,
        )

    def finding(self, vuln_type: str, severity: str, file: str, line: int, **context: Any) -> None:
        """Log a vulnerability finding."""
        self.warning(
            f"Finding: {vuln_type}",
            severity=severity,
            file=file,
            line=line,
            **context,
        )


def get_logger(component: str, parent: Optional[str] = None) -> ComponentLogger:
    """
    Factory function to get a component logger.

    Args:
        component: Name of the component
        parent: Optional parent component name

    Returns:
        ComponentLogger instance
    """
    return ComponentLogger(component, parent)


def get_scan_logger(scan_id: str) -> ScanLogger:
    """
    Factory function to get a scan-specific logger.

    Args:
        scan_id: Unique identifier for the scan

    Returns:
        ScanLogger instance
    """
    return ScanLogger(scan_id)
