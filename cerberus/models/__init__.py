"""Data models for Cerberus SAST."""

from cerberus.models.base import (
    Severity,
    TaintLabel,
    Verdict,
    SymbolType,
    VulnerabilityType,
    CodeLocation,
    TimeRange,
    PhaseResult,
    severity_to_sarif,
    get_cwe_description,
)
from cerberus.models.repo_map import (
    Symbol,
    FileInfo,
    RepoMap,
)
from cerberus.models.spec import (
    TaintSpec,
    DynamicSpec,
)
from cerberus.models.finding import (
    TraceStep,
    SliceLine,
    ProgramSlice,
    VerificationResult,
    Finding,
    ScanResult,
)

__all__ = [
    # Base types
    "Severity",
    "TaintLabel",
    "Verdict",
    "SymbolType",
    "VulnerabilityType",
    "CodeLocation",
    "TimeRange",
    "PhaseResult",
    "severity_to_sarif",
    "get_cwe_description",
    # Repository map (Phase I)
    "Symbol",
    "FileInfo",
    "RepoMap",
    # Specification (Phase II)
    "TaintSpec",
    "DynamicSpec",
    # Findings (Phase III/IV)
    "TraceStep",
    "SliceLine",
    "ProgramSlice",
    "VerificationResult",
    "Finding",
    "ScanResult",
]
