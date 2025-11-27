"""
Cerberus API Application.

FastAPI application factory and configuration.
"""

from __future__ import annotations

import asyncio
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware

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
from cerberus.baseline import Baseline, BaselineManager
from cerberus.core.orchestrator import OrchestratorConfig, OrchestratorResult, ScanOrchestrator
from cerberus.core.progress import ScanProgress
from cerberus.detection.joern_client import JoernClient, JoernConfig
from cerberus.models.base import Verdict
from cerberus.models.finding import Finding, ScanResult
from cerberus.utils.logging import ComponentLogger


# In-memory storage for scans (in production, use a database)
_scans: dict[str, dict[str, Any]] = {}
_baselines: dict[str, Baseline] = {}
_logger = ComponentLogger("api")


def _finding_to_response(finding: Finding) -> FindingResponse:
    """Convert Finding model to FindingResponse."""
    source_response = None
    if finding.source:
        source_response = TaintNodeResponse(
            method=finding.source.method,
            file_path=str(finding.source.file_path),
            line=finding.source.line,
        )

    sink_response = None
    if finding.sink:
        sink_response = TaintNodeResponse(
            method=finding.sink.method,
            file_path=str(finding.sink.file_path),
            line=finding.sink.line,
        )

    verification_response = None
    if finding.verification:
        v = finding.verification
        verification_response = VerificationResponse(
            verdict=VerdictType(v.verdict.value),
            confidence=v.confidence,
            attacker_exploitable=v.attacker_exploitable,
            attacker_reasoning=v.attacker_reasoning,
            defender_safe=v.defender_safe,
            defender_reasoning=v.defender_reasoning,
            judge_reasoning=v.judge_reasoning,
        )

    severity_str = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)

    return FindingResponse(
        id=finding.id,
        vulnerability_type=finding.vulnerability_type,
        severity=SeverityLevel(severity_str.lower()),
        confidence=finding.confidence,
        title=finding.title,
        description=finding.description,
        remediation=finding.remediation,
        source=source_response,
        sink=sink_response,
        verification=verification_response,
        cwe_id=finding.vulnerability_type if finding.vulnerability_type.startswith("CWE-") else None,
        tags=finding.tags,
    )


def _create_scan_summary(result: ScanResult) -> ScanSummary:
    """Create scan summary from ScanResult."""
    summary = ScanSummary(
        files_scanned=result.files_scanned,
        lines_scanned=result.lines_scanned,
        total_findings=len(result.findings),
        sources_found=result.sources_found,
        sinks_found=result.sinks_found,
        sanitizers_found=result.sanitizers_found,
    )

    for finding in result.findings:
        # Count by severity
        severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        severity_lower = severity.lower()
        if severity_lower == "critical":
            summary.critical += 1
        elif severity_lower == "high":
            summary.high += 1
        elif severity_lower == "medium":
            summary.medium += 1
        elif severity_lower == "low":
            summary.low += 1

        # Count by verdict
        if finding.verification:
            if finding.verification.verdict == Verdict.TRUE_POSITIVE:
                summary.true_positives += 1
            elif finding.verification.verdict == Verdict.FALSE_POSITIVE:
                summary.false_positives += 1
            else:
                summary.uncertain += 1
        else:
            summary.unverified += 1

    return summary


async def _run_scan_task(
    scan_id: str,
    request: ScanRequest,
    orchestrator: ScanOrchestrator,
) -> None:
    """Background task to run a scan."""
    try:
        _scans[scan_id]["status"] = ScanStatus.RUNNING
        _scans[scan_id]["started_at"] = datetime.now(timezone.utc)

        # Run the scan
        result = await orchestrator.scan(
            path=Path(request.repository_path),
            repository_name=request.repository_name,
        )

        # Store results
        _scans[scan_id]["status"] = ScanStatus.COMPLETED if result.error is None else ScanStatus.FAILED
        _scans[scan_id]["completed_at"] = datetime.now(timezone.utc)
        _scans[scan_id]["result"] = result
        _scans[scan_id]["error"] = result.error

        _logger.info(f"Scan {scan_id} completed: {len(result.scan_result.findings)} findings")

    except Exception as e:
        _scans[scan_id]["status"] = ScanStatus.FAILED
        _scans[scan_id]["completed_at"] = datetime.now(timezone.utc)
        _scans[scan_id]["error"] = str(e)
        _logger.error(f"Scan {scan_id} failed: {e}")


def create_app(
    title: str = "Cerberus SAST API",
    version: str = "1.0.0",
    llm_gateway: Optional[Any] = None,
    joern_config: Optional[JoernConfig] = None,
) -> FastAPI:
    """
    Create the FastAPI application.

    Args:
        title: API title.
        version: API version.
        llm_gateway: Optional LLM gateway instance.
        joern_config: Optional Joern configuration.

    Returns:
        FastAPI application instance.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Application lifespan handler."""
        _logger.info("Starting Cerberus API server")
        yield
        _logger.info("Shutting down Cerberus API server")

    app = FastAPI(
        title=title,
        version=version,
        description="Neuro-Symbolic Self-Configuring Security Scanner API",
        lifespan=lifespan,
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Store configuration
    app.state.llm_gateway = llm_gateway
    app.state.joern_config = joern_config or JoernConfig()

    # Health endpoint
    @app.get("/health", response_model=HealthResponse, tags=["System"])
    async def health_check() -> HealthResponse:
        """Check API health and dependency status."""
        joern_available = False
        try:
            client = JoernClient(config=app.state.joern_config)
            joern_available = await client.is_available()
        except Exception:
            pass

        return HealthResponse(
            status="healthy",
            version=version,
            joern_available=joern_available,
            llm_available=app.state.llm_gateway is not None,
        )

    # Scan endpoints
    @app.post(
        "/scans",
        response_model=ScanResponse,
        tags=["Scans"],
        responses={400: {"model": ErrorResponse}},
    )
    async def start_scan(
        request: ScanRequest,
        background_tasks: BackgroundTasks,
    ) -> ScanResponse:
        """
        Start a new security scan.

        The scan runs asynchronously. Use GET /scans/{scan_id} to check status.
        """
        # Validate path exists
        path = Path(request.repository_path)
        if not path.exists():
            raise HTTPException(
                status_code=400,
                detail=f"Repository path does not exist: {request.repository_path}",
            )

        # Create scan ID
        scan_id = str(uuid.uuid4())

        # Create orchestrator config
        config = OrchestratorConfig(
            run_inference=request.run_inference,
            run_detection=request.run_detection,
            run_verification=request.run_verification,
            enable_feedback_loop=request.enable_feedback_loop,
            max_feedback_iterations=min(request.max_iterations, 3),  # Hard limit
            languages=request.languages,
            exclude_patterns=request.exclude_patterns,
        )

        # Progress callback
        def progress_callback(progress: ScanProgress) -> None:
            _scans[scan_id]["progress"] = progress

        # Create orchestrator
        orchestrator = ScanOrchestrator(
            config=config,
            llm_gateway=app.state.llm_gateway,
            joern_client=JoernClient(config=app.state.joern_config),
            progress_callback=progress_callback,
        )

        # Initialize scan record
        _scans[scan_id] = {
            "scan_id": scan_id,
            "status": ScanStatus.PENDING,
            "request": request,
            "progress": None,
            "result": None,
            "started_at": None,
            "completed_at": None,
            "error": None,
        }

        # Start background task
        background_tasks.add_task(_run_scan_task, scan_id, request, orchestrator)

        return ScanResponse(
            scan_id=scan_id,
            status=ScanStatus.PENDING,
            message="Scan queued",
        )

    @app.get(
        "/scans/{scan_id}",
        response_model=ScanStatusResponse,
        tags=["Scans"],
        responses={404: {"model": ErrorResponse}},
    )
    async def get_scan_status(scan_id: str) -> ScanStatusResponse:
        """Get the status and results of a scan."""
        if scan_id not in _scans:
            raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

        scan = _scans[scan_id]
        result: Optional[OrchestratorResult] = scan.get("result")
        progress = scan.get("progress")

        # Build progress response
        progress_response = None
        if progress:
            progress_response = ProgressResponse(
                phase=progress.phase,
                phase_progress=progress.phase_progress,
                overall_progress=progress.overall_progress,
                message=progress.message,
                current_file=progress.current_file,
                files_processed=progress.files_processed,
                files_total=progress.files_total,
                findings_count=progress.findings_count,
                elapsed_seconds=progress.elapsed_seconds,
            )

        # Build response
        response = ScanStatusResponse(
            scan_id=scan_id,
            status=scan["status"],
            repository=scan["request"].repository_name or scan["request"].repository_path,
            started_at=scan["started_at"],
            completed_at=scan["completed_at"],
            progress=progress_response,
            errors=[{"error": scan["error"]}] if scan["error"] else [],
        )

        # Add results if complete
        if result and result.scan_result:
            sr = result.scan_result
            response.duration_seconds = sr.duration_seconds
            response.summary = _create_scan_summary(sr)
            response.findings = [_finding_to_response(f) for f in sr.findings]
            response.iterations_run = result.iterations_run
            response.spec_updates_applied = result.spec_updates_applied
            response.converged = result.converged

        return response

    @app.get(
        "/scans",
        response_model=ScanListResponse,
        tags=["Scans"],
    )
    async def list_scans(
        page: int = Query(1, ge=1),
        page_size: int = Query(20, ge=1, le=100),
        status: Optional[ScanStatus] = None,
    ) -> ScanListResponse:
        """List all scans with optional filtering."""
        all_scans = list(_scans.values())

        # Filter by status
        if status:
            all_scans = [s for s in all_scans if s["status"] == status]

        # Paginate
        total = len(all_scans)
        start = (page - 1) * page_size
        end = start + page_size
        page_scans = all_scans[start:end]

        # Convert to responses
        responses = []
        for scan in page_scans:
            result = scan.get("result")
            responses.append(ScanStatusResponse(
                scan_id=scan["scan_id"],
                status=scan["status"],
                repository=scan["request"].repository_name or scan["request"].repository_path,
                started_at=scan["started_at"],
                completed_at=scan["completed_at"],
                duration_seconds=result.scan_result.duration_seconds if result else None,
                iterations_run=result.iterations_run if result else 1,
            ))

        return ScanListResponse(
            scans=responses,
            total=total,
            page=page,
            page_size=page_size,
        )

    @app.delete(
        "/scans/{scan_id}",
        tags=["Scans"],
        responses={404: {"model": ErrorResponse}},
    )
    async def cancel_scan(scan_id: str) -> dict[str, str]:
        """Cancel a running scan or delete a completed scan."""
        if scan_id not in _scans:
            raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

        scan = _scans[scan_id]
        if scan["status"] == ScanStatus.RUNNING:
            scan["status"] = ScanStatus.CANCELLED
            return {"message": f"Scan {scan_id} cancelled"}
        else:
            del _scans[scan_id]
            return {"message": f"Scan {scan_id} deleted"}

    # Findings endpoints
    @app.get(
        "/scans/{scan_id}/findings",
        response_model=list[FindingResponse],
        tags=["Findings"],
        responses={404: {"model": ErrorResponse}},
    )
    async def get_findings(
        scan_id: str,
        severity: Optional[SeverityLevel] = None,
        verdict: Optional[VerdictType] = None,
        verified_only: bool = False,
    ) -> list[FindingResponse]:
        """Get findings from a scan with optional filtering."""
        if scan_id not in _scans:
            raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

        scan = _scans[scan_id]
        result = scan.get("result")

        if not result or not result.scan_result:
            return []

        findings = result.scan_result.findings

        # Filter by severity
        if severity:
            findings = [
                f for f in findings
                if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).lower() == severity.value
            ]

        # Filter by verdict
        if verdict:
            findings = [
                f for f in findings
                if f.verification and f.verification.verdict.value == verdict.value
            ]

        # Filter verified only
        if verified_only:
            findings = [f for f in findings if f.verification is not None]

        return [_finding_to_response(f) for f in findings]

    # Baseline endpoints
    @app.post(
        "/baselines",
        response_model=BaselineResponse,
        tags=["Baselines"],
        responses={400: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
    )
    async def create_baseline(request: BaselineRequest) -> BaselineResponse:
        """Create a baseline from a completed scan."""
        if request.scan_id not in _scans:
            raise HTTPException(status_code=404, detail=f"Scan not found: {request.scan_id}")

        scan = _scans[request.scan_id]
        result = scan.get("result")

        if not result or scan["status"] != ScanStatus.COMPLETED:
            raise HTTPException(status_code=400, detail="Scan must be completed to create baseline")

        # Create baseline
        manager = BaselineManager()
        baseline = manager.create_baseline(
            name=request.name,
            repository=scan["request"].repository_name or scan["request"].repository_path,
            findings=result.scan_result.findings,
        )

        _baselines[request.name] = baseline

        return BaselineResponse(
            name=baseline.name,
            repository=baseline.repository,
            created_at=baseline.created_at,
            updated_at=baseline.updated_at,
            entry_count=baseline.count,
            active_count=baseline.active_count,
        )

    @app.get(
        "/baselines/{name}",
        response_model=BaselineResponse,
        tags=["Baselines"],
        responses={404: {"model": ErrorResponse}},
    )
    async def get_baseline(name: str) -> BaselineResponse:
        """Get baseline information."""
        if name not in _baselines:
            raise HTTPException(status_code=404, detail=f"Baseline not found: {name}")

        baseline = _baselines[name]
        return BaselineResponse(
            name=baseline.name,
            repository=baseline.repository,
            created_at=baseline.created_at,
            updated_at=baseline.updated_at,
            entry_count=baseline.count,
            active_count=baseline.active_count,
        )

    @app.get(
        "/baselines/{name}/compare/{scan_id}",
        response_model=BaselineDiffResponse,
        tags=["Baselines"],
        responses={404: {"model": ErrorResponse}},
    )
    async def compare_to_baseline(name: str, scan_id: str) -> BaselineDiffResponse:
        """Compare a scan's findings against a baseline."""
        if name not in _baselines:
            raise HTTPException(status_code=404, detail=f"Baseline not found: {name}")

        if scan_id not in _scans:
            raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

        scan = _scans[scan_id]
        result = scan.get("result")

        if not result:
            raise HTTPException(status_code=400, detail="Scan has no results")

        # Compare
        manager = BaselineManager()
        diff = manager.compare(result.scan_result.findings, _baselines[name])

        return BaselineDiffResponse(
            new_count=diff.new_count,
            existing_count=diff.existing_count,
            resolved_count=diff.resolved_count,
            new_findings=[_finding_to_response(f) for f in diff.new_findings],
        )

    @app.get("/baselines", response_model=list[BaselineResponse], tags=["Baselines"])
    async def list_baselines() -> list[BaselineResponse]:
        """List all baselines."""
        return [
            BaselineResponse(
                name=b.name,
                repository=b.repository,
                created_at=b.created_at,
                updated_at=b.updated_at,
                entry_count=b.count,
                active_count=b.active_count,
            )
            for b in _baselines.values()
        ]

    return app


# Default app instance
app = create_app()
