"""Tests for API models."""

from __future__ import annotations

from datetime import datetime

import pytest

from cerberus.api.models import (
    BaselineDiffResponse,
    BaselineRequest,
    BaselineResponse,
    ErrorResponse,
    FindingResponse,
    HealthResponse,
    ProgressResponse,
    ScanListResponse,
    ScanRequest,
    ScanResponse,
    ScanStatus,
    ScanStatusResponse,
    ScanSummary,
    SeverityLevel,
    TaintNodeResponse,
    VerdictType,
    VerificationResponse,
)


class TestScanStatus:
    """Test ScanStatus enum."""

    def test_status_values(self):
        """Should have expected values."""
        assert ScanStatus.PENDING == "pending"
        assert ScanStatus.RUNNING == "running"
        assert ScanStatus.COMPLETED == "completed"
        assert ScanStatus.FAILED == "failed"
        assert ScanStatus.CANCELLED == "cancelled"


class TestSeverityLevel:
    """Test SeverityLevel enum."""

    def test_severity_values(self):
        """Should have expected values."""
        assert SeverityLevel.CRITICAL == "critical"
        assert SeverityLevel.HIGH == "high"
        assert SeverityLevel.MEDIUM == "medium"
        assert SeverityLevel.LOW == "low"
        assert SeverityLevel.INFO == "info"


class TestVerdictType:
    """Test VerdictType enum."""

    def test_verdict_values(self):
        """Should have expected values."""
        assert VerdictType.TRUE_POSITIVE == "true_positive"
        assert VerdictType.FALSE_POSITIVE == "false_positive"
        assert VerdictType.UNCERTAIN == "uncertain"


class TestScanRequest:
    """Test ScanRequest model."""

    def test_minimal_request(self):
        """Should create with minimal fields."""
        request = ScanRequest(repository_path="/path/to/repo")

        assert request.repository_path == "/path/to/repo"
        assert request.repository_name is None
        assert request.run_inference is True
        assert request.run_detection is True
        assert request.run_verification is True
        assert request.enable_feedback_loop is True
        assert request.max_iterations == 3

    def test_full_request(self):
        """Should accept all fields."""
        request = ScanRequest(
            repository_path="/path/to/repo",
            repository_name="my-repo",
            languages=["python", "javascript"],
            exclude_patterns=["**/test/**"],
            run_inference=True,
            run_detection=True,
            run_verification=False,
            enable_feedback_loop=False,
            max_iterations=2,
            output_formats=["json", "sarif"],
            min_severity="high",
        )

        assert request.repository_name == "my-repo"
        assert request.languages == ["python", "javascript"]
        assert request.exclude_patterns == ["**/test/**"]
        assert request.run_verification is False
        assert request.enable_feedback_loop is False
        assert request.max_iterations == 2
        assert request.output_formats == ["json", "sarif"]
        assert request.min_severity == "high"

    def test_max_iterations_constraint(self):
        """Should enforce max iterations constraint."""
        # Value within range should work
        request = ScanRequest(repository_path="/path", max_iterations=3)
        assert request.max_iterations == 3

        # Values at boundaries
        request = ScanRequest(repository_path="/path", max_iterations=1)
        assert request.max_iterations == 1

    def test_json_serialization(self):
        """Should serialize to JSON."""
        request = ScanRequest(
            repository_path="/path/to/repo",
            repository_name="test",
        )

        json_data = request.model_dump()
        assert json_data["repository_path"] == "/path/to/repo"
        assert json_data["repository_name"] == "test"


class TestScanResponse:
    """Test ScanResponse model."""

    def test_create_response(self):
        """Should create response."""
        response = ScanResponse(
            scan_id="abc123",
            status=ScanStatus.PENDING,
            message="Scan queued",
        )

        assert response.scan_id == "abc123"
        assert response.status == ScanStatus.PENDING
        assert response.message == "Scan queued"


class TestHealthResponse:
    """Test HealthResponse model."""

    def test_default_response(self):
        """Should have default values."""
        response = HealthResponse()

        assert response.status == "healthy"
        assert response.joern_available is False
        assert response.llm_available is False

    def test_custom_response(self):
        """Should accept custom values."""
        response = HealthResponse(
            status="healthy",
            version="1.0.0",
            joern_available=True,
            llm_available=True,
        )

        assert response.version == "1.0.0"
        assert response.joern_available is True
        assert response.llm_available is True


class TestProgressResponse:
    """Test ProgressResponse model."""

    def test_create_progress(self):
        """Should create progress response."""
        response = ProgressResponse(
            phase="detection",
            phase_progress=0.5,
            overall_progress=0.6,
            message="Analyzing files",
            files_processed=50,
            files_total=100,
            findings_count=3,
        )

        assert response.phase == "detection"
        assert response.phase_progress == 0.5
        assert response.overall_progress == 0.6
        assert response.message == "Analyzing files"
        assert response.files_processed == 50
        assert response.files_total == 100
        assert response.findings_count == 3


class TestTaintNodeResponse:
    """Test TaintNodeResponse model."""

    def test_create_node(self):
        """Should create taint node response."""
        node = TaintNodeResponse(
            method="get_input",
            file_path="src/input.py",
            line=10,
            code_snippet="user_input = request.get('input')",
        )

        assert node.method == "get_input"
        assert node.file_path == "src/input.py"
        assert node.line == 10
        assert node.code_snippet == "user_input = request.get('input')"


class TestVerificationResponse:
    """Test VerificationResponse model."""

    def test_create_verification(self):
        """Should create verification response."""
        response = VerificationResponse(
            verdict=VerdictType.TRUE_POSITIVE,
            confidence=0.9,
            attacker_exploitable=True,
            attacker_reasoning="Input flows to sink without sanitization",
            defender_safe=False,
            defender_reasoning="No sanitization found",
            judge_reasoning="Clear vulnerability",
        )

        assert response.verdict == VerdictType.TRUE_POSITIVE
        assert response.confidence == 0.9
        assert response.attacker_exploitable is True


class TestFindingResponse:
    """Test FindingResponse model."""

    def test_create_finding(self):
        """Should create finding response."""
        finding = FindingResponse(
            id="finding-123",
            vulnerability_type="SQL_INJECTION",
            severity=SeverityLevel.HIGH,
            confidence=0.85,
            title="SQL Injection",
            description="Unsanitized input in SQL query",
            source=TaintNodeResponse(
                method="get_input",
                file_path="src/api.py",
                line=10,
            ),
            sink=TaintNodeResponse(
                method="execute_query",
                file_path="src/db.py",
                line=50,
            ),
        )

        assert finding.id == "finding-123"
        assert finding.vulnerability_type == "SQL_INJECTION"
        assert finding.severity == SeverityLevel.HIGH
        assert finding.source.method == "get_input"
        assert finding.sink.method == "execute_query"


class TestScanSummary:
    """Test ScanSummary model."""

    def test_default_summary(self):
        """Should have zero defaults."""
        summary = ScanSummary()

        assert summary.files_scanned == 0
        assert summary.lines_scanned == 0
        assert summary.total_findings == 0
        assert summary.true_positives == 0
        assert summary.false_positives == 0

    def test_custom_summary(self):
        """Should accept custom values."""
        summary = ScanSummary(
            files_scanned=100,
            lines_scanned=5000,
            total_findings=10,
            true_positives=5,
            false_positives=2,
            uncertain=3,
            critical=1,
            high=4,
            medium=3,
            low=2,
        )

        assert summary.files_scanned == 100
        assert summary.total_findings == 10
        assert summary.true_positives == 5


class TestScanStatusResponse:
    """Test ScanStatusResponse model."""

    def test_minimal_status(self):
        """Should create with minimal fields."""
        response = ScanStatusResponse(
            scan_id="abc123",
            status=ScanStatus.RUNNING,
        )

        assert response.scan_id == "abc123"
        assert response.status == ScanStatus.RUNNING
        assert response.findings is None

    def test_completed_status(self):
        """Should include results when completed."""
        response = ScanStatusResponse(
            scan_id="abc123",
            status=ScanStatus.COMPLETED,
            repository="my-repo",
            duration_seconds=45.2,
            summary=ScanSummary(
                files_scanned=100,
                total_findings=5,
            ),
            findings=[
                FindingResponse(
                    id="f1",
                    vulnerability_type="XSS",
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.8,
                ),
            ],
            iterations_run=2,
            converged=True,
        )

        assert response.status == ScanStatus.COMPLETED
        assert response.duration_seconds == 45.2
        assert response.summary.files_scanned == 100
        assert len(response.findings) == 1


class TestScanListResponse:
    """Test ScanListResponse model."""

    def test_create_list(self):
        """Should create list response."""
        response = ScanListResponse(
            scans=[
                ScanStatusResponse(scan_id="1", status=ScanStatus.COMPLETED),
                ScanStatusResponse(scan_id="2", status=ScanStatus.RUNNING),
            ],
            total=2,
            page=1,
            page_size=20,
        )

        assert len(response.scans) == 2
        assert response.total == 2
        assert response.page == 1


class TestBaselineRequest:
    """Test BaselineRequest model."""

    def test_create_request(self):
        """Should create baseline request."""
        request = BaselineRequest(
            name="baseline-v1",
            scan_id="scan-123",
        )

        assert request.name == "baseline-v1"
        assert request.scan_id == "scan-123"


class TestBaselineResponse:
    """Test BaselineResponse model."""

    def test_create_response(self):
        """Should create baseline response."""
        response = BaselineResponse(
            name="baseline-v1",
            repository="my-repo",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            entry_count=50,
            active_count=45,
        )

        assert response.name == "baseline-v1"
        assert response.entry_count == 50
        assert response.active_count == 45


class TestBaselineDiffResponse:
    """Test BaselineDiffResponse model."""

    def test_create_diff(self):
        """Should create diff response."""
        response = BaselineDiffResponse(
            new_count=3,
            existing_count=10,
            resolved_count=2,
            new_findings=[
                FindingResponse(
                    id="new-1",
                    vulnerability_type="XSS",
                    severity=SeverityLevel.HIGH,
                    confidence=0.9,
                ),
            ],
        )

        assert response.new_count == 3
        assert response.existing_count == 10
        assert response.resolved_count == 2
        assert len(response.new_findings) == 1


class TestErrorResponse:
    """Test ErrorResponse model."""

    def test_create_error(self):
        """Should create error response."""
        response = ErrorResponse(
            error="Not found",
            detail="Scan with ID 'xyz' not found",
            code="SCAN_NOT_FOUND",
        )

        assert response.error == "Not found"
        assert response.detail == "Scan with ID 'xyz' not found"
        assert response.code == "SCAN_NOT_FOUND"
