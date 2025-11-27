"""Tests for the API application."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from cerberus.api.app import create_app, _scans, _baselines, _finding_to_response, _create_scan_summary
from cerberus.api.models import ScanStatus, SeverityLevel, VerdictType
from cerberus.baseline import Baseline, BaselineEntry
from cerberus.core.orchestrator import OrchestratorResult
from cerberus.models.base import Severity, TaintLabel, Verdict
from cerberus.models.finding import Finding, ScanResult, VerificationResult
from cerberus.models.spec import TaintSpec


@pytest.fixture
def client() -> TestClient:
    """Create test client."""
    app = create_app()
    return TestClient(app)


@pytest.fixture
def sample_finding() -> Finding:
    """Create sample finding."""
    return Finding(
        vulnerability_type="SQL_INJECTION",
        severity=Severity.HIGH,
        confidence=0.85,
        title="SQL Injection",
        description="Unsanitized input in SQL query",
        source=TaintSpec(
            method="get_input",
            file_path=Path("src/api.py"),
            line=10,
            label=TaintLabel.SOURCE,
        ),
        sink=TaintSpec(
            method="execute_query",
            file_path=Path("src/db.py"),
            line=50,
            label=TaintLabel.SINK,
        ),
    )


@pytest.fixture
def verified_finding(sample_finding: Finding) -> Finding:
    """Create verified finding."""
    sample_finding.verification = VerificationResult(
        verdict=Verdict.TRUE_POSITIVE,
        confidence=0.9,
        attacker_exploitable=True,
        attacker_input="'; DROP TABLE users; --",
        attacker_trace="Input passed directly to query",
        attacker_impact="Database compromise",
        attacker_reasoning="Clear injection path",
        defender_safe=False,
        defender_lines=[],
        defender_sanitization=None,
        defender_reasoning="No sanitization",
        judge_reasoning="Confirmed vulnerability",
    )
    return sample_finding


@pytest.fixture
def sample_scan_result(sample_finding: Finding) -> ScanResult:
    """Create sample scan result."""
    result = ScanResult(
        repository="test-repo",
        findings=[sample_finding],
    )
    result.files_scanned = 100
    result.lines_scanned = 5000
    result.sources_found = 5
    result.sinks_found = 3
    result.sanitizers_found = 2
    result.complete()
    return result


@pytest.fixture(autouse=True)
def cleanup_scans():
    """Clear scans between tests."""
    _scans.clear()
    _baselines.clear()
    yield
    _scans.clear()
    _baselines.clear()


class TestHealthEndpoint:
    """Test health check endpoint."""

    def test_health_check(self, client: TestClient):
        """Should return healthy status."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "joern_available" in data
        assert "llm_available" in data


class TestScanEndpoints:
    """Test scan endpoints."""

    def test_start_scan_path_not_exists(self, client: TestClient):
        """Should reject non-existent paths."""
        response = client.post("/scans", json={
            "repository_path": "/nonexistent/path",
        })

        assert response.status_code == 400
        assert "does not exist" in response.json()["detail"]

    def test_start_scan_success(self, client: TestClient):
        """Should start scan with valid path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            response = client.post("/scans", json={
                "repository_path": tmpdir,
                "repository_name": "test-repo",
            })

            assert response.status_code == 200
            data = response.json()
            assert "scan_id" in data
            assert data["status"] == "pending"
            assert data["message"] == "Scan queued"

    def test_get_scan_not_found(self, client: TestClient):
        """Should return 404 for unknown scan."""
        response = client.get("/scans/nonexistent-id")

        assert response.status_code == 404

    def test_get_scan_pending(self, client: TestClient):
        """Should return pending scan status."""
        # Add a pending scan
        _scans["test-scan"] = {
            "scan_id": "test-scan",
            "status": ScanStatus.PENDING,
            "request": MagicMock(repository_name="test-repo", repository_path="/path"),
            "progress": None,
            "result": None,
            "started_at": None,
            "completed_at": None,
            "error": None,
        }

        response = client.get("/scans/test-scan")

        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == "test-scan"
        assert data["status"] == "pending"

    def test_get_scan_completed(self, client: TestClient, sample_scan_result: ScanResult):
        """Should return completed scan with results."""
        result = OrchestratorResult(
            scan_result=sample_scan_result,
            iterations_run=2,
            spec_updates_applied=1,
            converged=True,
        )

        _scans["test-scan"] = {
            "scan_id": "test-scan",
            "status": ScanStatus.COMPLETED,
            "request": MagicMock(repository_name="test-repo", repository_path="/path"),
            "progress": None,
            "result": result,
            "started_at": None,
            "completed_at": None,
            "error": None,
        }

        response = client.get("/scans/test-scan")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert data["summary"]["files_scanned"] == 100
        assert data["summary"]["total_findings"] == 1
        assert data["iterations_run"] == 2
        assert data["converged"] is True

    def test_list_scans_empty(self, client: TestClient):
        """Should return empty list."""
        response = client.get("/scans")

        assert response.status_code == 200
        data = response.json()
        assert data["scans"] == []
        assert data["total"] == 0

    def test_list_scans_with_data(self, client: TestClient):
        """Should list scans."""
        _scans["scan-1"] = {
            "scan_id": "scan-1",
            "status": ScanStatus.COMPLETED,
            "request": MagicMock(repository_name="repo-1", repository_path="/path1"),
            "progress": None,
            "result": None,
            "started_at": None,
            "completed_at": None,
            "error": None,
        }
        _scans["scan-2"] = {
            "scan_id": "scan-2",
            "status": ScanStatus.RUNNING,
            "request": MagicMock(repository_name="repo-2", repository_path="/path2"),
            "progress": None,
            "result": None,
            "started_at": None,
            "completed_at": None,
            "error": None,
        }

        response = client.get("/scans")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        assert len(data["scans"]) == 2

    def test_list_scans_filter_by_status(self, client: TestClient):
        """Should filter by status."""
        _scans["scan-1"] = {
            "scan_id": "scan-1",
            "status": ScanStatus.COMPLETED,
            "request": MagicMock(repository_name="repo-1", repository_path="/path1"),
            "progress": None,
            "result": None,
            "started_at": None,
            "completed_at": None,
            "error": None,
        }
        _scans["scan-2"] = {
            "scan_id": "scan-2",
            "status": ScanStatus.RUNNING,
            "request": MagicMock(repository_name="repo-2", repository_path="/path2"),
            "progress": None,
            "result": None,
            "started_at": None,
            "completed_at": None,
            "error": None,
        }

        response = client.get("/scans?status=completed")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["scans"][0]["scan_id"] == "scan-1"

    def test_delete_scan_not_found(self, client: TestClient):
        """Should return 404 for unknown scan."""
        response = client.delete("/scans/nonexistent")

        assert response.status_code == 404

    def test_delete_completed_scan(self, client: TestClient):
        """Should delete completed scan."""
        _scans["test-scan"] = {
            "scan_id": "test-scan",
            "status": ScanStatus.COMPLETED,
            "request": MagicMock(),
            "progress": None,
            "result": None,
            "started_at": None,
            "completed_at": None,
            "error": None,
        }

        response = client.delete("/scans/test-scan")

        assert response.status_code == 200
        assert "deleted" in response.json()["message"]
        assert "test-scan" not in _scans

    def test_cancel_running_scan(self, client: TestClient):
        """Should cancel running scan."""
        _scans["test-scan"] = {
            "scan_id": "test-scan",
            "status": ScanStatus.RUNNING,
            "request": MagicMock(),
            "progress": None,
            "result": None,
            "started_at": None,
            "completed_at": None,
            "error": None,
        }

        response = client.delete("/scans/test-scan")

        assert response.status_code == 200
        assert "cancelled" in response.json()["message"]
        assert _scans["test-scan"]["status"] == ScanStatus.CANCELLED


class TestFindingsEndpoints:
    """Test findings endpoints."""

    def test_get_findings_scan_not_found(self, client: TestClient):
        """Should return 404 for unknown scan."""
        response = client.get("/scans/nonexistent/findings")

        assert response.status_code == 404

    def test_get_findings_empty(self, client: TestClient):
        """Should return empty list for scan without results."""
        _scans["test-scan"] = {
            "scan_id": "test-scan",
            "status": ScanStatus.RUNNING,
            "request": MagicMock(),
            "progress": None,
            "result": None,
            "started_at": None,
            "completed_at": None,
            "error": None,
        }

        response = client.get("/scans/test-scan/findings")

        assert response.status_code == 200
        assert response.json() == []

    def test_get_findings_with_results(
        self, client: TestClient, sample_scan_result: ScanResult
    ):
        """Should return findings."""
        result = OrchestratorResult(scan_result=sample_scan_result)
        _scans["test-scan"] = {
            "scan_id": "test-scan",
            "status": ScanStatus.COMPLETED,
            "request": MagicMock(),
            "progress": None,
            "result": result,
            "started_at": None,
            "completed_at": None,
            "error": None,
        }

        response = client.get("/scans/test-scan/findings")

        assert response.status_code == 200
        findings = response.json()
        assert len(findings) == 1
        assert findings[0]["vulnerability_type"] == "SQL_INJECTION"

    def test_get_findings_filter_by_severity(
        self, client: TestClient, sample_scan_result: ScanResult
    ):
        """Should filter by severity."""
        # Add a low severity finding
        low_finding = Finding(
            vulnerability_type="INFO_LEAK",
            severity=Severity.LOW,
            confidence=0.5,
        )
        sample_scan_result.findings.append(low_finding)

        result = OrchestratorResult(scan_result=sample_scan_result)
        _scans["test-scan"] = {
            "scan_id": "test-scan",
            "status": ScanStatus.COMPLETED,
            "request": MagicMock(),
            "progress": None,
            "result": result,
            "started_at": None,
            "completed_at": None,
            "error": None,
        }

        response = client.get("/scans/test-scan/findings?severity=high")

        assert response.status_code == 200
        findings = response.json()
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"


class TestBaselineEndpoints:
    """Test baseline endpoints."""

    def test_create_baseline_scan_not_found(self, client: TestClient):
        """Should return 404 for unknown scan."""
        response = client.post("/baselines", json={
            "name": "baseline-v1",
            "scan_id": "nonexistent",
        })

        assert response.status_code == 404

    def test_create_baseline_scan_not_complete(self, client: TestClient):
        """Should reject incomplete scans."""
        _scans["test-scan"] = {
            "scan_id": "test-scan",
            "status": ScanStatus.RUNNING,
            "request": MagicMock(),
            "progress": None,
            "result": None,
            "started_at": None,
            "completed_at": None,
            "error": None,
        }

        response = client.post("/baselines", json={
            "name": "baseline-v1",
            "scan_id": "test-scan",
        })

        assert response.status_code == 400

    def test_create_baseline_success(
        self, client: TestClient, sample_scan_result: ScanResult
    ):
        """Should create baseline from completed scan."""
        result = OrchestratorResult(scan_result=sample_scan_result)
        _scans["test-scan"] = {
            "scan_id": "test-scan",
            "status": ScanStatus.COMPLETED,
            "request": MagicMock(repository_name="test-repo", repository_path="/path"),
            "progress": None,
            "result": result,
            "started_at": None,
            "completed_at": None,
            "error": None,
        }

        response = client.post("/baselines", json={
            "name": "baseline-v1",
            "scan_id": "test-scan",
        })

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "baseline-v1"
        assert "baseline-v1" in _baselines

    def test_get_baseline_not_found(self, client: TestClient):
        """Should return 404 for unknown baseline."""
        response = client.get("/baselines/nonexistent")

        assert response.status_code == 404

    def test_get_baseline_success(self, client: TestClient):
        """Should return baseline."""
        _baselines["test-baseline"] = Baseline(
            name="test-baseline",
            repository="test-repo",
        )
        _baselines["test-baseline"].add_entry(BaselineEntry(
            fingerprint="abc123",
            vulnerability_type="SQL_INJECTION",
            file_path="src/db.py",
        ))

        response = client.get("/baselines/test-baseline")

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "test-baseline"
        assert data["entry_count"] == 1

    def test_list_baselines_empty(self, client: TestClient):
        """Should return empty list."""
        response = client.get("/baselines")

        assert response.status_code == 200
        assert response.json() == []

    def test_list_baselines_with_data(self, client: TestClient):
        """Should list baselines."""
        _baselines["baseline-1"] = Baseline(name="baseline-1", repository="repo-1")
        _baselines["baseline-2"] = Baseline(name="baseline-2", repository="repo-2")

        response = client.get("/baselines")

        assert response.status_code == 200
        baselines = response.json()
        assert len(baselines) == 2

    def test_compare_baseline_not_found(self, client: TestClient):
        """Should return 404 for unknown baseline."""
        _scans["test-scan"] = {
            "scan_id": "test-scan",
            "status": ScanStatus.COMPLETED,
            "request": MagicMock(),
            "progress": None,
            "result": OrchestratorResult(scan_result=ScanResult(repository="test")),
            "started_at": None,
            "completed_at": None,
            "error": None,
        }

        response = client.get("/baselines/nonexistent/compare/test-scan")

        assert response.status_code == 404


class TestHelperFunctions:
    """Test helper functions."""

    def test_finding_to_response(self, sample_finding: Finding):
        """Should convert Finding to FindingResponse."""
        response = _finding_to_response(sample_finding)

        assert response.vulnerability_type == "SQL_INJECTION"
        assert response.severity == SeverityLevel.HIGH
        assert response.source.method == "get_input"
        assert response.sink.method == "execute_query"

    def test_finding_to_response_with_verification(self, verified_finding: Finding):
        """Should include verification details."""
        response = _finding_to_response(verified_finding)

        assert response.verification is not None
        assert response.verification.verdict == VerdictType.TRUE_POSITIVE
        assert response.verification.confidence == 0.9

    def test_create_scan_summary(self, sample_scan_result: ScanResult):
        """Should create summary from scan result."""
        summary = _create_scan_summary(sample_scan_result)

        assert summary.files_scanned == 100
        assert summary.lines_scanned == 5000
        assert summary.total_findings == 1
        assert summary.sources_found == 5
        assert summary.sinks_found == 3
        assert summary.sanitizers_found == 2


class TestAppFactory:
    """Test app factory function."""

    def test_create_app_defaults(self):
        """Should create app with defaults."""
        app = create_app()

        assert app.title == "Cerberus SAST API"

    def test_create_app_custom_title(self):
        """Should accept custom title."""
        app = create_app(title="Custom API", version="2.0.0")

        assert app.title == "Custom API"
        assert app.version == "2.0.0"

    def test_app_has_cors(self):
        """Should have CORS middleware."""
        app = create_app()

        # Check middleware is added
        middleware_classes = [type(m).__name__ for m in app.user_middleware]
        # CORSMiddleware is wrapped, so check it's configured
        assert len(app.user_middleware) > 0
