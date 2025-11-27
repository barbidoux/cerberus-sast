"""
API Request/Response Models.

Pydantic models for the REST API.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    """Scan status enum."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityLevel(str, Enum):
    """Severity level enum."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VerdictType(str, Enum):
    """Verification verdict type."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"


# Request Models


class ScanRequest(BaseModel):
    """Request to start a new scan."""

    repository_path: str = Field(..., description="Path to repository to scan")
    repository_name: Optional[str] = Field(None, description="Optional repository name")
    languages: Optional[list[str]] = Field(None, description="Languages to scan (auto-detect if not specified)")
    exclude_patterns: Optional[list[str]] = Field(None, description="Glob patterns to exclude")

    # Phase toggles
    run_inference: bool = Field(True, description="Run spec inference phase")
    run_detection: bool = Field(True, description="Run detection phase")
    run_verification: bool = Field(True, description="Run verification phase")

    # Feedback loop settings
    enable_feedback_loop: bool = Field(True, description="Enable feedback from verification to inference")
    max_iterations: int = Field(3, ge=1, le=3, description="Maximum feedback iterations (hard limit: 3)")

    # Output settings
    output_formats: list[str] = Field(
        default=["json"],
        description="Output formats (json, sarif, html, markdown)",
    )
    min_severity: Optional[str] = Field(None, description="Minimum severity to report")

    class Config:
        json_schema_extra = {
            "example": {
                "repository_path": "/path/to/repo",
                "repository_name": "my-project",
                "languages": ["python", "javascript"],
                "run_verification": True,
                "enable_feedback_loop": True,
                "output_formats": ["json", "sarif"],
            }
        }


class BaselineRequest(BaseModel):
    """Request to create or update a baseline."""

    name: str = Field(..., description="Baseline name")
    scan_id: str = Field(..., description="Scan ID to baseline")


# Response Models


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "healthy"
    version: str = ""
    joern_available: bool = False
    llm_available: bool = False
    timestamp: datetime = Field(default_factory=datetime.now)


class ProgressResponse(BaseModel):
    """Scan progress response."""

    phase: str
    phase_progress: float = Field(ge=0.0, le=1.0)
    overall_progress: float = Field(ge=0.0, le=1.0)
    message: Optional[str] = None
    current_file: Optional[str] = None
    files_processed: int = 0
    files_total: int = 0
    findings_count: int = 0
    elapsed_seconds: float = 0.0


class VerificationResponse(BaseModel):
    """Verification result for a finding."""

    verdict: VerdictType
    confidence: float = Field(ge=0.0, le=1.0)
    attacker_exploitable: bool
    attacker_reasoning: str
    defender_safe: bool
    defender_reasoning: str
    judge_reasoning: str


class TaintNodeResponse(BaseModel):
    """Taint source or sink node."""

    method: str
    file_path: str
    line: int
    code_snippet: Optional[str] = None


class FindingResponse(BaseModel):
    """Single vulnerability finding."""

    id: str
    vulnerability_type: str
    severity: SeverityLevel
    confidence: float = Field(ge=0.0, le=1.0)

    title: str = ""
    description: str = ""
    remediation: str = ""

    source: Optional[TaintNodeResponse] = None
    sink: Optional[TaintNodeResponse] = None

    verification: Optional[VerificationResponse] = None

    cwe_id: Optional[str] = None
    tags: list[str] = Field(default_factory=list)


class ScanSummary(BaseModel):
    """Scan summary statistics."""

    files_scanned: int = 0
    lines_scanned: int = 0
    total_findings: int = 0
    true_positives: int = 0
    false_positives: int = 0
    uncertain: int = 0
    unverified: int = 0

    # By severity
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    # Spec inference
    sources_found: int = 0
    sinks_found: int = 0
    sanitizers_found: int = 0


class ScanResponse(BaseModel):
    """Response for a scan request."""

    scan_id: str
    status: ScanStatus
    message: str = ""

    class Config:
        json_schema_extra = {
            "example": {
                "scan_id": "abc123-def456",
                "status": "pending",
                "message": "Scan queued",
            }
        }


class ScanStatusResponse(BaseModel):
    """Detailed scan status response."""

    scan_id: str
    status: ScanStatus
    repository: str = ""

    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Progress
    progress: Optional[ProgressResponse] = None

    # Results (when complete)
    summary: Optional[ScanSummary] = None
    findings: Optional[list[FindingResponse]] = None
    errors: list[dict[str, Any]] = Field(default_factory=list)

    # Feedback loop info
    iterations_run: int = 1
    spec_updates_applied: int = 0
    converged: bool = True

    class Config:
        json_schema_extra = {
            "example": {
                "scan_id": "abc123-def456",
                "status": "completed",
                "repository": "my-project",
                "duration_seconds": 45.2,
                "summary": {
                    "files_scanned": 150,
                    "total_findings": 5,
                    "true_positives": 3,
                },
            }
        }


class ScanListResponse(BaseModel):
    """List of scans response."""

    scans: list[ScanStatusResponse]
    total: int
    page: int = 1
    page_size: int = 20


class BaselineResponse(BaseModel):
    """Baseline information response."""

    name: str
    repository: str
    created_at: datetime
    updated_at: datetime
    entry_count: int
    active_count: int


class BaselineDiffResponse(BaseModel):
    """Baseline comparison response."""

    new_count: int
    existing_count: int
    resolved_count: int
    new_findings: list[FindingResponse]


class ErrorResponse(BaseModel):
    """Error response."""

    error: str
    detail: Optional[str] = None
    code: Optional[str] = None
