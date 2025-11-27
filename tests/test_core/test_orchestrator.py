"""Tests for the scan orchestrator."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cerberus.core.orchestrator import (
    DependencyError,
    OrchestratorConfig,
    OrchestratorResult,
    ScanOrchestrator,
)
from cerberus.core.progress import ScanProgress
from cerberus.models.base import TaintLabel, Verdict
from cerberus.models.finding import Finding, ScanResult
from cerberus.models.repo_map import FileInfo, RepoMap
from cerberus.models.spec import DynamicSpec, TaintSpec
from cerberus.verification.feedback import SpecUpdate


@pytest.fixture
def mock_repo_map() -> RepoMap:
    """Create a mock repository map."""
    return RepoMap(
        root_path=Path("/test/repo"),
        files=[
            FileInfo(
                path=Path("/test/repo/src/app.py"),
                language="python",
                lines=100,
                size_bytes=5000,
            ),
            FileInfo(
                path=Path("/test/repo/src/utils.py"),
                language="python",
                lines=50,
                size_bytes=2500,
            ),
        ],
        symbols=[],
        dependencies={},
        rankings={},
    )


@pytest.fixture
def mock_dynamic_spec() -> DynamicSpec:
    """Create a mock dynamic spec."""
    return DynamicSpec(
        sources=[
            TaintSpec(
                method="get_user_input",
                file_path=Path("src/app.py"),
                line=10,
                label=TaintLabel.SOURCE,
            ),
        ],
        sinks=[
            TaintSpec(
                method="execute_query",
                file_path=Path("src/db.py"),
                line=50,
                label=TaintLabel.SINK,
            ),
        ],
        sanitizers=[],
    )


@pytest.fixture
def mock_finding() -> Finding:
    """Create a mock finding."""
    return Finding(
        id="finding-1",
        vulnerability_type="sql_injection",
        severity="high",
        description="SQL injection vulnerability",
        source=TaintSpec(
            method="get_input",
            file_path=Path("src/app.py"),
            line=10,
            label=TaintLabel.SOURCE,
        ),
        sink=TaintSpec(
            method="query",
            file_path=Path("src/db.py"),
            line=20,
            label=TaintLabel.SINK,
        ),
    )


class TestOrchestratorConfig:
    """Test OrchestratorConfig."""

    def test_default_config(self):
        """Should have sensible defaults."""
        config = OrchestratorConfig()

        assert config.run_inference is True
        assert config.run_detection is True
        assert config.run_verification is True
        assert config.enable_feedback_loop is True
        assert config.max_feedback_iterations == 3
        assert config.min_confidence >= 0.0
        assert config.min_confidence <= 1.0

    def test_custom_config(self):
        """Should accept custom configuration."""
        config = OrchestratorConfig(
            run_verification=False,
            max_feedback_iterations=2,
            languages=["python"],
        )

        assert config.run_verification is False
        assert config.max_feedback_iterations == 2
        assert config.languages == ["python"]


class TestOrchestratorResult:
    """Test OrchestratorResult."""

    def test_create_result(self):
        """Should create result with scan result."""
        scan_result = ScanResult()
        result = OrchestratorResult(scan_result=scan_result)

        assert result.scan_result == scan_result
        assert result.iterations_run == 1
        assert result.converged is True
        assert result.error is None

    def test_result_with_metadata(self):
        """Should include metadata."""
        scan_result = ScanResult()
        result = OrchestratorResult(
            scan_result=scan_result,
            iterations_run=2,
            spec_updates_applied=3,
            metadata={"key": "value"},
        )

        assert result.iterations_run == 2
        assert result.spec_updates_applied == 3
        assert result.metadata["key"] == "value"


class TestScanOrchestrator:
    """Test ScanOrchestrator creation."""

    def test_create_orchestrator(self):
        """Should create orchestrator with defaults."""
        orchestrator = ScanOrchestrator()

        assert orchestrator.config is not None
        assert orchestrator.llm_gateway is None

    def test_create_with_config(self):
        """Should accept custom config."""
        config = OrchestratorConfig(max_feedback_iterations=2)
        orchestrator = ScanOrchestrator(config=config)

        assert orchestrator.config.max_feedback_iterations == 2

    def test_enforce_max_iterations_hard_limit(self):
        """Should cap iterations to hard limit."""
        config = OrchestratorConfig(max_feedback_iterations=10)
        orchestrator = ScanOrchestrator(config=config)

        assert orchestrator.config.max_feedback_iterations <= ScanOrchestrator.MAX_FEEDBACK_ITERATIONS

    def test_create_with_progress_callback(self):
        """Should accept progress callback."""
        callback = MagicMock()
        orchestrator = ScanOrchestrator(progress_callback=callback)

        assert orchestrator.progress_tracker._callbacks[0] == callback


class TestOrchestratorDependencyCheck:
    """Test dependency checking."""

    @pytest.mark.asyncio
    async def test_check_joern_available(self):
        """Should pass when Joern is available."""
        orchestrator = ScanOrchestrator()
        orchestrator.joern_client = AsyncMock()
        orchestrator.joern_client.is_available = AsyncMock(return_value=True)

        # Should not raise
        await orchestrator._check_dependencies()

    @pytest.mark.asyncio
    async def test_check_joern_unavailable(self):
        """Should raise when Joern is unavailable."""
        orchestrator = ScanOrchestrator()
        orchestrator.joern_client = AsyncMock()
        orchestrator.joern_client.is_available = AsyncMock(return_value=False)

        with pytest.raises(DependencyError):
            await orchestrator._check_dependencies()


class TestOrchestratorScan:
    """Test main scan flow."""

    @pytest.mark.asyncio
    async def test_scan_returns_result(
        self,
        mock_repo_map: RepoMap,
        mock_dynamic_spec: DynamicSpec,
        mock_finding: Finding,
    ):
        """Should return OrchestratorResult."""
        orchestrator = ScanOrchestrator()

        # Mock all phase components
        orchestrator._repo_mapper = MagicMock()
        orchestrator._repo_mapper.map_repository = AsyncMock(return_value=mock_repo_map)

        inference_result = MagicMock()
        inference_result.spec = mock_dynamic_spec
        orchestrator._inference_engine = MagicMock()
        orchestrator._inference_engine.infer = AsyncMock(return_value=inference_result)

        orchestrator._detection_engine = MagicMock()
        orchestrator._detection_engine.detect = AsyncMock(
            return_value=MagicMock(
                success=True,
                findings=[mock_finding],
                error=None,
            )
        )

        orchestrator._verification_engine = MagicMock()
        orchestrator._verification_engine.verify = AsyncMock(
            return_value=MagicMock(
                findings=[mock_finding],
                spec_updates=None,
            )
        )

        orchestrator.joern_client = AsyncMock()
        orchestrator.joern_client.is_available = AsyncMock(return_value=True)

        result = await orchestrator.scan(Path("/test/repo"))

        assert isinstance(result, OrchestratorResult)
        assert result.scan_result is not None
        assert len(result.scan_result.findings) == 1

    @pytest.mark.asyncio
    async def test_scan_tracks_files_scanned(
        self,
        mock_repo_map: RepoMap,
        mock_dynamic_spec: DynamicSpec,
    ):
        """Should track files scanned from repo map."""
        config = OrchestratorConfig(
            run_detection=False,  # Skip detection
        )
        orchestrator = ScanOrchestrator(config=config)

        orchestrator._repo_mapper = MagicMock()
        orchestrator._repo_mapper.map_repository = AsyncMock(return_value=mock_repo_map)

        inference_result = MagicMock()
        inference_result.spec = mock_dynamic_spec
        orchestrator._inference_engine = MagicMock()
        orchestrator._inference_engine.infer = AsyncMock(return_value=inference_result)

        result = await orchestrator.scan(Path("/test/repo"))

        assert result.scan_result.files_scanned == 2
        assert result.scan_result.lines_scanned == 150  # 100 + 50

    @pytest.mark.asyncio
    async def test_scan_handles_dependency_error(self):
        """Should handle dependency errors gracefully."""
        orchestrator = ScanOrchestrator()
        orchestrator.joern_client = AsyncMock()
        orchestrator.joern_client.is_available = AsyncMock(return_value=False)

        result = await orchestrator.scan(Path("/test/repo"))

        assert result.error is not None
        assert "Joern" in result.error
        assert result.scan_result.status == "failed"

    @pytest.mark.asyncio
    async def test_scan_skips_inference_when_disabled(
        self,
        mock_repo_map: RepoMap,
    ):
        """Should skip inference when disabled."""
        config = OrchestratorConfig(run_inference=False)
        orchestrator = ScanOrchestrator(config=config)

        orchestrator._repo_mapper = MagicMock()
        orchestrator._repo_mapper.map_repository = AsyncMock(return_value=mock_repo_map)

        # Should not be called
        orchestrator._inference_engine = MagicMock()
        orchestrator._inference_engine.infer = AsyncMock()

        await orchestrator.scan(Path("/test/repo"))

        orchestrator._inference_engine.infer.assert_not_called()


class TestOrchestratorFeedbackLoop:
    """Test feedback loop iteration."""

    @pytest.mark.asyncio
    async def test_feedback_loop_runs_multiple_iterations(
        self,
        mock_repo_map: RepoMap,
        mock_dynamic_spec: DynamicSpec,
    ):
        """Should run multiple iterations when feedback produces updates."""
        config = OrchestratorConfig(max_feedback_iterations=3)
        orchestrator = ScanOrchestrator(config=config)

        orchestrator.joern_client = AsyncMock()
        orchestrator.joern_client.is_available = AsyncMock(return_value=True)

        orchestrator._repo_mapper = MagicMock()
        orchestrator._repo_mapper.map_repository = AsyncMock(return_value=mock_repo_map)

        inference_result = MagicMock()
        inference_result.spec = mock_dynamic_spec
        orchestrator._inference_engine = MagicMock()
        orchestrator._inference_engine.infer = AsyncMock(return_value=inference_result)

        # Create different findings for each iteration
        iteration_count = [0]

        def create_finding(i: int) -> Finding:
            return Finding(
                id=f"finding-{i}",
                vulnerability_type="sql_injection",
                severity="high",
                description=f"Finding {i}",
                source=mock_dynamic_spec.sources[0],
                sink=mock_dynamic_spec.sinks[0],
            )

        async def mock_detect(spec: DynamicSpec) -> MagicMock:
            iteration_count[0] += 1
            return MagicMock(
                success=True,
                findings=[create_finding(iteration_count[0])],
                error=None,
            )

        orchestrator._detection_engine = MagicMock()
        orchestrator._detection_engine.detect = mock_detect

        # Return spec updates for first iteration, none for second
        call_count = [0]

        async def mock_verify(findings: list[Finding]) -> MagicMock:
            call_count[0] += 1
            if call_count[0] == 1:
                return MagicMock(
                    findings=findings,
                    spec_updates=SpecUpdate(
                        sanitizers=[
                            TaintSpec(
                                method="sanitize",
                                file_path=Path("src/utils.py"),
                                line=25,
                                label=TaintLabel.SANITIZER,
                            )
                        ]
                    ),
                )
            else:
                return MagicMock(
                    findings=findings,
                    spec_updates=SpecUpdate(),  # No more updates
                )

        orchestrator._verification_engine = MagicMock()
        orchestrator._verification_engine.verify = mock_verify

        result = await orchestrator.scan(Path("/test/repo"))

        # Should run 2 iterations (first with updates, second converges)
        assert result.iterations_run == 2
        assert result.spec_updates_applied == 1
        assert result.converged is True

    @pytest.mark.asyncio
    async def test_feedback_loop_respects_max_iterations(
        self,
        mock_repo_map: RepoMap,
        mock_dynamic_spec: DynamicSpec,
    ):
        """Should stop at max iterations even with updates."""
        config = OrchestratorConfig(max_feedback_iterations=2)
        orchestrator = ScanOrchestrator(config=config)

        orchestrator.joern_client = AsyncMock()
        orchestrator.joern_client.is_available = AsyncMock(return_value=True)

        orchestrator._repo_mapper = MagicMock()
        orchestrator._repo_mapper.map_repository = AsyncMock(return_value=mock_repo_map)

        inference_result = MagicMock()
        inference_result.spec = mock_dynamic_spec
        orchestrator._inference_engine = MagicMock()
        orchestrator._inference_engine.infer = AsyncMock(return_value=inference_result)

        # Always return new findings
        finding_id = [0]

        async def mock_detect(spec: DynamicSpec) -> MagicMock:
            finding_id[0] += 1
            return MagicMock(
                success=True,
                findings=[
                    Finding(
                        id=f"finding-{finding_id[0]}",
                        vulnerability_type="sql_injection",
                        severity="high",
                        description="Test",
                        source=mock_dynamic_spec.sources[0],
                        sink=mock_dynamic_spec.sinks[0],
                    )
                ],
                error=None,
            )

        orchestrator._detection_engine = MagicMock()
        orchestrator._detection_engine.detect = mock_detect

        # Always return spec updates
        async def mock_verify(findings: list[Finding]) -> MagicMock:
            return MagicMock(
                findings=findings,
                spec_updates=SpecUpdate(
                    sanitizers=[
                        TaintSpec(
                            method=f"sanitize_{finding_id[0]}",
                            file_path=Path("src/utils.py"),
                            line=25,
                            label=TaintLabel.SANITIZER,
                        )
                    ]
                ),
            )

        orchestrator._verification_engine = MagicMock()
        orchestrator._verification_engine.verify = mock_verify

        result = await orchestrator.scan(Path("/test/repo"))

        # Should stop at max iterations (2)
        assert result.iterations_run == 2
        assert result.converged is False  # Didn't naturally converge

    @pytest.mark.asyncio
    async def test_feedback_loop_deduplicates_findings(
        self,
        mock_repo_map: RepoMap,
        mock_dynamic_spec: DynamicSpec,
        mock_finding: Finding,
    ):
        """Should not add duplicate findings."""
        config = OrchestratorConfig(max_feedback_iterations=2)
        orchestrator = ScanOrchestrator(config=config)

        orchestrator.joern_client = AsyncMock()
        orchestrator.joern_client.is_available = AsyncMock(return_value=True)

        orchestrator._repo_mapper = MagicMock()
        orchestrator._repo_mapper.map_repository = AsyncMock(return_value=mock_repo_map)

        inference_result = MagicMock()
        inference_result.spec = mock_dynamic_spec
        orchestrator._inference_engine = MagicMock()
        orchestrator._inference_engine.infer = AsyncMock(return_value=inference_result)

        # Return same finding both times
        orchestrator._detection_engine = MagicMock()
        orchestrator._detection_engine.detect = AsyncMock(
            return_value=MagicMock(
                success=True,
                findings=[mock_finding],  # Same finding each time
                error=None,
            )
        )

        orchestrator._verification_engine = MagicMock()
        orchestrator._verification_engine.verify = AsyncMock(
            return_value=MagicMock(
                findings=[mock_finding],
                spec_updates=SpecUpdate(),
            )
        )

        result = await orchestrator.scan(Path("/test/repo"))

        # Should only have 1 finding (deduplicated)
        assert len(result.scan_result.findings) == 1


class TestOrchestratorSpecMerge:
    """Test spec merging for feedback loop."""

    def test_merge_adds_new_sanitizers(self):
        """Should add new sanitizers to spec."""
        orchestrator = ScanOrchestrator()

        base_spec = DynamicSpec(
            sources=[],
            sinks=[],
            sanitizers=[
                TaintSpec(
                    method="existing_sanitizer",
                    file_path=Path("src/utils.py"),
                    line=10,
                    label=TaintLabel.SANITIZER,
                )
            ],
        )

        updates = SpecUpdate(
            sanitizers=[
                TaintSpec(
                    method="new_sanitizer",
                    file_path=Path("src/utils.py"),
                    line=20,
                    label=TaintLabel.SANITIZER,
                )
            ]
        )

        merged = orchestrator._merge_specs(base_spec, updates)

        assert len(merged.sanitizers) == 2
        assert any(s.method == "existing_sanitizer" for s in merged.sanitizers)
        assert any(s.method == "new_sanitizer" for s in merged.sanitizers)

    def test_merge_skips_duplicate_sanitizers(self):
        """Should not add duplicate sanitizers."""
        orchestrator = ScanOrchestrator()

        base_spec = DynamicSpec(
            sources=[],
            sinks=[],
            sanitizers=[
                TaintSpec(
                    method="sanitize",
                    file_path=Path("src/utils.py"),
                    line=10,
                    label=TaintLabel.SANITIZER,
                )
            ],
        )

        updates = SpecUpdate(
            sanitizers=[
                TaintSpec(
                    method="sanitize",  # Same method
                    file_path=Path("src/utils.py"),
                    line=10,
                    label=TaintLabel.SANITIZER,
                )
            ]
        )

        merged = orchestrator._merge_specs(base_spec, updates)

        assert len(merged.sanitizers) == 1


class TestOrchestratorProgress:
    """Test progress tracking during scan."""

    @pytest.mark.asyncio
    async def test_scan_updates_progress(
        self,
        mock_repo_map: RepoMap,
    ):
        """Should update progress during scan."""
        progress_updates: list[ScanProgress] = []

        def track_progress(p: ScanProgress) -> None:
            progress_updates.append(p)

        config = OrchestratorConfig(run_inference=False)
        orchestrator = ScanOrchestrator(config=config, progress_callback=track_progress)

        orchestrator._repo_mapper = MagicMock()
        orchestrator._repo_mapper.map_repository = AsyncMock(return_value=mock_repo_map)

        orchestrator.joern_client = AsyncMock()
        orchestrator.joern_client.is_available = AsyncMock(return_value=True)

        await orchestrator.scan(Path("/test/repo"))

        # Should have progress updates
        assert len(progress_updates) >= 2  # At least start and complete
        assert progress_updates[0].phase == "context"
        assert progress_updates[-1].phase == "complete"


class TestOrchestratorVerdictCounting:
    """Test verdict counting helper."""

    def test_count_by_verdict_empty(self):
        """Should handle empty findings."""
        orchestrator = ScanOrchestrator()

        counts = orchestrator._count_by_verdict([])

        assert counts["true_positive"] == 0
        assert counts["false_positive"] == 0
        assert counts["uncertain"] == 0
        assert counts["unverified"] == 0

    def test_count_by_verdict_unverified(self, mock_finding: Finding):
        """Should count unverified findings."""
        orchestrator = ScanOrchestrator()
        mock_finding.verification = None

        counts = orchestrator._count_by_verdict([mock_finding])

        assert counts["unverified"] == 1

    def test_count_by_verdict_mixed(self, mock_finding: Finding):
        """Should count different verdicts correctly."""
        from cerberus.models.finding import VerificationResult

        orchestrator = ScanOrchestrator()

        # Create findings with different verdicts
        f1 = Finding(
            id="f1",
            vulnerability_type="xss",
            severity="medium",
            description="Test 1",
            source=mock_finding.source,
            sink=mock_finding.sink,
            verification=VerificationResult(
                verdict=Verdict.TRUE_POSITIVE,
                confidence=0.9,
                attacker_exploitable=True,
                attacker_input="<script>alert(1)</script>",
                attacker_trace="XSS trace",
                attacker_impact="Session hijacking",
                attacker_reasoning="Input reflected without encoding",
                defender_safe=False,
                defender_lines=[],
                defender_sanitization=None,
                defender_reasoning="No sanitization found",
                judge_reasoning="Clear XSS vulnerability",
            ),
        )

        f2 = Finding(
            id="f2",
            vulnerability_type="xss",
            severity="medium",
            description="Test 2",
            source=mock_finding.source,
            sink=mock_finding.sink,
            verification=VerificationResult(
                verdict=Verdict.FALSE_POSITIVE,
                confidence=0.8,
                attacker_exploitable=False,
                attacker_input=None,
                attacker_trace=None,
                attacker_impact=None,
                attacker_reasoning="Cannot exploit",
                defender_safe=True,
                defender_lines=[15],
                defender_sanitization="escape_html()",
                defender_reasoning="Input properly sanitized",
                judge_reasoning="Sanitizer blocks attack",
            ),
        )

        f3 = Finding(
            id="f3",
            vulnerability_type="xss",
            severity="medium",
            description="Test 3",
            source=mock_finding.source,
            sink=mock_finding.sink,
        )  # Unverified

        counts = orchestrator._count_by_verdict([f1, f2, f3])

        assert counts["true_positive"] == 1
        assert counts["false_positive"] == 1
        assert counts["unverified"] == 1
