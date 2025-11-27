"""
Core enums and base classes used throughout Cerberus SAST.

This module defines the fundamental data types for:
- Severity levels
- Taint labels (Source, Sink, Sanitizer, Propagator)
- Verification verdicts
- Code symbol types
- Source code locations
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class Severity(Enum):
    """Severity levels for vulnerability findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Create Severity from string, case-insensitive."""
        return cls(value.lower())

    def __lt__(self, other: "Severity") -> bool:
        """Allow comparison for sorting by severity."""
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return order[self] < order[other]

    def __le__(self, other: "Severity") -> bool:
        return self == other or self < other


class TaintLabel(Enum):
    """Labels for taint analysis classification."""

    SOURCE = "source"
    SINK = "sink"
    SANITIZER = "sanitizer"
    PROPAGATOR = "propagator"
    NONE = "none"

    @classmethod
    def from_string(cls, value: str) -> "TaintLabel":
        """Create TaintLabel from string, case-insensitive."""
        return cls(value.lower())


class Verdict(Enum):
    """Verification verdicts from the Multi-Agent Council."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"

    @classmethod
    def from_string(cls, value: str) -> "Verdict":
        """Create Verdict from string, case-insensitive."""
        return cls(value.lower())


class SymbolType(Enum):
    """Types of code symbols."""

    FUNCTION = "function"
    METHOD = "method"
    CLASS = "class"
    VARIABLE = "variable"
    IMPORT = "import"
    CONSTANT = "constant"
    INTERFACE = "interface"
    ENUM = "enum"
    MODULE = "module"

    @classmethod
    def from_string(cls, value: str) -> "SymbolType":
        """Create SymbolType from string, case-insensitive."""
        return cls(value.lower())


class VulnerabilityType(Enum):
    """Common vulnerability types (CWE-based)."""

    SQL_INJECTION = "CWE-89"
    XSS = "CWE-79"
    COMMAND_INJECTION = "CWE-78"
    PATH_TRAVERSAL = "CWE-22"
    SSRF = "CWE-918"
    XXE = "CWE-611"
    DESERIALIZATION = "CWE-502"
    LDAP_INJECTION = "CWE-90"
    XPATH_INJECTION = "CWE-643"
    CODE_INJECTION = "CWE-94"
    LOG_INJECTION = "CWE-117"
    OPEN_REDIRECT = "CWE-601"
    SENSITIVE_DATA_EXPOSURE = "CWE-200"
    HARDCODED_CREDENTIALS = "CWE-798"
    WEAK_CRYPTO = "CWE-327"
    INSECURE_RANDOM = "CWE-330"
    BUFFER_OVERFLOW = "CWE-120"
    USE_AFTER_FREE = "CWE-416"
    NULL_POINTER = "CWE-476"
    RACE_CONDITION = "CWE-362"
    OTHER = "CWE-000"


@dataclass
class CodeLocation:
    """
    Location in source code.

    Represents a specific position in a source file, optionally
    with an end position for ranges.
    """

    file_path: Path
    line: int
    column: int
    end_line: Optional[int] = None
    end_column: Optional[int] = None

    def __post_init__(self) -> None:
        """Ensure file_path is a Path object."""
        if isinstance(self.file_path, str):
            self.file_path = Path(self.file_path)

    def to_uri(self) -> str:
        """
        Convert to URI string format.

        Returns:
            String in format "file:line:column"
        """
        return f"{self.file_path}:{self.line}:{self.column}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "file_path": str(self.file_path),
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "end_column": self.end_column,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CodeLocation":
        """Deserialize from dictionary."""
        return cls(
            file_path=Path(data["file_path"]),
            line=data["line"],
            column=data["column"],
            end_line=data.get("end_line"),
            end_column=data.get("end_column"),
        )

    def __hash__(self) -> int:
        """Make CodeLocation hashable for use in sets and dicts."""
        return hash((str(self.file_path), self.line, self.column))

    def __eq__(self, other: object) -> bool:
        """Check equality with another CodeLocation."""
        if not isinstance(other, CodeLocation):
            return False
        return (
            self.file_path == other.file_path
            and self.line == other.line
            and self.column == other.column
        )


@dataclass
class TimeRange:
    """Time range for tracking operation durations."""

    start: datetime = field(default_factory=datetime.utcnow)
    end: Optional[datetime] = None

    def complete(self) -> None:
        """Mark the time range as complete."""
        self.end = datetime.utcnow()

    @property
    def duration_ms(self) -> Optional[float]:
        """Get duration in milliseconds."""
        if self.end is None:
            return None
        return (self.end - self.start).total_seconds() * 1000

    @property
    def duration_seconds(self) -> Optional[float]:
        """Get duration in seconds."""
        if self.end is None:
            return None
        return (self.end - self.start).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "start": self.start.isoformat(),
            "end": self.end.isoformat() if self.end else None,
            "duration_ms": self.duration_ms,
        }


@dataclass
class PhaseResult:
    """Result from a pipeline phase."""

    phase: str
    success: bool
    timing: TimeRange
    error: Optional[str] = None
    metrics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "phase": self.phase,
            "success": self.success,
            "timing": self.timing.to_dict(),
            "error": self.error,
            "metrics": self.metrics,
        }


# SARIF-compatible severity mapping
SARIF_SEVERITY_MAP: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def severity_to_sarif(severity: Severity) -> str:
    """Convert Severity to SARIF level."""
    return SARIF_SEVERITY_MAP.get(severity, "warning")


# CWE descriptions for common vulnerability types
CWE_DESCRIPTIONS: dict[str, str] = {
    "CWE-89": "SQL Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-78": "OS Command Injection",
    "CWE-22": "Path Traversal",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-90": "LDAP Injection",
    "CWE-643": "XPath Injection",
    "CWE-94": "Code Injection",
    "CWE-117": "Log Injection",
    "CWE-601": "Open Redirect",
    "CWE-200": "Sensitive Data Exposure",
    "CWE-798": "Hardcoded Credentials",
    "CWE-327": "Use of Broken Crypto Algorithm",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-120": "Buffer Overflow",
    "CWE-416": "Use After Free",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-362": "Race Condition",
}


def get_cwe_description(cwe_id: str) -> str:
    """Get description for a CWE ID."""
    return CWE_DESCRIPTIONS.get(cwe_id, f"Unknown ({cwe_id})")
