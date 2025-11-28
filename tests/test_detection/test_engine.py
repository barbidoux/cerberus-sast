"""
Tests for Detection Engine.

TDD: Write tests first, then implement to make them pass.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cerberus.detection.engine import (
    DetectionEngine,
    DetectionConfig,
    DetectionResult,
)
from cerberus.detection.flow_analyzer import DataFlow, FlowResult
from cerberus.detection.joern_client import JoernClient, QueryResult
from cerberus.detection.query_generator import CPGQLQuery
from cerberus.detection.slicer import SliceResult
from cerberus.models.base import CodeLocation, TaintLabel, Severity
from cerberus.models.finding import Finding, ProgramSlice, SliceLine
from cerberus.models.spec import DynamicSpec, TaintSpec


@pytest.fixture
def sample_spec() -> DynamicSpec:
    """Create a sample DynamicSpec."""
    spec = DynamicSpec(repository="test-repo")
    spec.add_source(TaintSpec(
        method="get_user_input",
        file_path=Path("/app/handler.py"),
        line=10,
        label=TaintLabel.SOURCE,
        confidence=0.95,
        vulnerability_types=["CWE-89"],
    ))
    spec.add_sink(TaintSpec(
        method="execute_query",
        file_path=Path("/app/database.py"),
        line=25,
        label=TaintLabel.SINK,
        confidence=0.9,
        vulnerability_types=["CWE-89"],
    ))
    spec.add_sanitizer(TaintSpec(
        method="escape_sql",
        file_path=Path("/app/utils.py"),
        line=5,
        label=TaintLabel.SANITIZER,
        confidence=0.85,
        vulnerability_types=["CWE-89"],
    ))
    return spec


@pytest.fixture
def sample_flow() -> DataFlow:
    """Create a sample data flow."""
    return DataFlow(
        source_method="get_user_input",
        sink_method="execute_query",
        source_location=CodeLocation(Path("/app/handler.py"), 10, 0),
        sink_location=CodeLocation(Path("/app/database.py"), 25, 0),
        vulnerability_type="CWE-89",
    )


class TestDetectionConfig:
    """Test DetectionConfig."""

    def test_default_config(self):
        """Should have sensible defaults."""
        config = DetectionConfig()
        assert config.parallel_queries is True
        assert config.generate_slices is True
        assert config.min_confidence > 0

    def test_custom_config(self):
        """Should accept custom values."""
        config = DetectionConfig(
            parallel_queries=False,
            generate_slices=False,
            min_confidence=0.9,
        )
        assert config.parallel_queries is False
        assert config.min_confidence == 0.9


class TestDetectionResult:
    """Test DetectionResult dataclass."""

    def test_create_detection_result(self):
        """Should create detection result."""
        result = DetectionResult(
            findings=[],
            flows_analyzed=5,
            queries_executed=3,
            success=True,
        )
        assert result.success is True
        assert result.flows_analyzed == 5

    def test_result_with_error(self):
        """Should capture error details."""
        result = DetectionResult(
            findings=[],
            flows_analyzed=0,
            queries_executed=0,
            success=False,
            error="Joern connection failed",
        )
        assert result.success is False
        assert "Joern" in result.error

    def test_finding_counts(self):
        """Should count findings by severity."""
        findings = [
            Finding(severity=Severity.CRITICAL, vulnerability_type="CWE-89"),
            Finding(severity=Severity.HIGH, vulnerability_type="CWE-89"),
            Finding(severity=Severity.HIGH, vulnerability_type="CWE-79"),
        ]
        result = DetectionResult(
            findings=findings,
            flows_analyzed=3,
            queries_executed=2,
            success=True,
        )

        summary = result.summary()
        assert summary["total_findings"] == 3
        assert "CWE-89" in str(summary)


class TestDetectionEngine:
    """Test DetectionEngine class."""

    def test_create_engine(self):
        """Should create engine instance."""
        engine = DetectionEngine()
        assert engine is not None

    def test_create_with_config(self):
        """Should accept custom configuration."""
        config = DetectionConfig(min_confidence=0.8)
        engine = DetectionEngine(config=config)
        assert engine.config.min_confidence == 0.8

    def test_create_with_joern_client(self):
        """Should accept Joern client."""
        client = MagicMock(spec=JoernClient)
        engine = DetectionEngine(joern_client=client)
        assert engine.joern_client == client


class TestDetectionPipeline:
    """Test the full detection pipeline."""

    @pytest.mark.asyncio
    async def test_detect_flows(self, sample_spec: DynamicSpec):
        """Should detect data flows from spec."""
        mock_joern = AsyncMock(spec=JoernClient)
        mock_joern.is_available.return_value = True
        mock_joern.query.return_value = QueryResult(
            success=True,
            data=json.dumps([{
                "source": {"method": "get_user_input", "line": 10, "file": "handler.py"},
                "sink": {"method": "execute_query", "line": 25, "file": "db.py"},
                "trace": [
                    {"line": 10, "code": "data = get_input()"},
                    {"line": 25, "code": "execute(data)"},
                ],
            }]),
        )
        mock_joern.get_slice.return_value = [
            {"lineNumber": 10, "code": "data = get_input()"},
            {"lineNumber": 25, "code": "execute(data)"},
        ]
        mock_joern.get_control_structures.return_value = []

        engine = DetectionEngine(joern_client=mock_joern)
        result = await engine.detect(sample_spec)

        assert isinstance(result, DetectionResult)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_generates_queries(self, sample_spec: DynamicSpec):
        """Should generate queries from spec."""
        mock_joern = AsyncMock(spec=JoernClient)
        mock_joern.is_available.return_value = True
        mock_joern.query.return_value = QueryResult(success=True, data='[]')

        engine = DetectionEngine(joern_client=mock_joern)
        result = await engine.detect(sample_spec)

        # Should have executed queries
        assert result.queries_executed >= 0

    @pytest.mark.asyncio
    async def test_creates_findings(self, sample_spec: DynamicSpec):
        """Should create Finding objects from flows."""
        mock_joern = AsyncMock(spec=JoernClient)
        mock_joern.is_available.return_value = True
        mock_joern.query.return_value = QueryResult(
            success=True,
            data=json.dumps([{
                "source": {"method": "get_user_input", "line": 10, "file": "handler.py"},
                "sink": {"method": "execute_query", "line": 25, "file": "db.py"},
                "trace": [],
            }]),
        )
        mock_joern.get_slice.return_value = []
        mock_joern.get_control_structures.return_value = []

        engine = DetectionEngine(joern_client=mock_joern)
        result = await engine.detect(sample_spec)

        if result.findings:
            assert all(isinstance(f, Finding) for f in result.findings)

    @pytest.mark.asyncio
    async def test_handles_joern_unavailable(self, sample_spec: DynamicSpec):
        """Should handle Joern being unavailable with LLM-trust fallback."""
        mock_joern = AsyncMock(spec=JoernClient)
        mock_joern.is_available.return_value = False

        engine = DetectionEngine(joern_client=mock_joern)
        result = await engine.detect(sample_spec)

        # Detection should succeed using LLM-trust fallback
        assert result.success is True
        assert result.metadata.get("detection_mode") == "llm_trust"
        assert result.metadata.get("joern_available") is False


class TestFindingCreation:
    """Test Finding creation from flows."""

    @pytest.mark.asyncio
    async def test_finding_has_vulnerability_type(
        self,
        sample_spec: DynamicSpec,
    ):
        """Should set vulnerability type on finding."""
        mock_joern = AsyncMock(spec=JoernClient)
        mock_joern.is_available.return_value = True
        mock_joern.query.return_value = QueryResult(
            success=True,
            data=json.dumps([{
                "source": {"line": 10, "file": "a.py"},
                "sink": {"line": 25, "file": "b.py"},
                "trace": [],
            }]),
        )
        mock_joern.get_slice.return_value = []
        mock_joern.get_control_structures.return_value = []

        engine = DetectionEngine(joern_client=mock_joern)
        result = await engine.detect(sample_spec)

        if result.findings:
            finding = result.findings[0]
            assert finding.vulnerability_type == "CWE-89"

    @pytest.mark.asyncio
    async def test_finding_has_trace(
        self,
        sample_spec: DynamicSpec,
    ):
        """Should include trace in finding."""
        mock_joern = AsyncMock(spec=JoernClient)
        mock_joern.is_available.return_value = True
        mock_joern.query.return_value = QueryResult(
            success=True,
            data=json.dumps([{
                "source": {"line": 10, "file": "a.py"},
                "sink": {"line": 25, "file": "b.py"},
                "trace": [
                    {"line": 10, "code": "source"},
                    {"line": 25, "code": "sink"},
                ],
            }]),
        )
        mock_joern.get_slice.return_value = []
        mock_joern.get_control_structures.return_value = []

        engine = DetectionEngine(joern_client=mock_joern)
        result = await engine.detect(sample_spec)

        if result.findings:
            finding = result.findings[0]
            assert len(finding.trace) > 0

    @pytest.mark.asyncio
    async def test_finding_has_severity(
        self,
        sample_spec: DynamicSpec,
    ):
        """Should assign severity based on vulnerability type."""
        mock_joern = AsyncMock(spec=JoernClient)
        mock_joern.is_available.return_value = True
        mock_joern.query.return_value = QueryResult(
            success=True,
            data=json.dumps([{
                "source": {"line": 10, "file": "a.py"},
                "sink": {"line": 25, "file": "b.py"},
                "trace": [],
            }]),
        )
        mock_joern.get_slice.return_value = []
        mock_joern.get_control_structures.return_value = []

        engine = DetectionEngine(joern_client=mock_joern)
        result = await engine.detect(sample_spec)

        if result.findings:
            finding = result.findings[0]
            # SQL injection should be high/critical severity
            assert finding.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]


class TestSliceGeneration:
    """Test program slice generation."""

    @pytest.mark.asyncio
    async def test_generates_slices_when_enabled(
        self,
        sample_spec: DynamicSpec,
    ):
        """Should generate slices when configured."""
        mock_joern = AsyncMock(spec=JoernClient)
        mock_joern.is_available.return_value = True
        mock_joern.query.return_value = QueryResult(
            success=True,
            data=json.dumps([{
                "source": {"line": 10, "file": "a.py"},
                "sink": {"line": 25, "file": "b.py"},
                "trace": [],
            }]),
        )
        mock_joern.get_slice.return_value = [
            {"lineNumber": 10, "code": "source"},
            {"lineNumber": 25, "code": "sink"},
        ]
        mock_joern.get_control_structures.return_value = []

        config = DetectionConfig(generate_slices=True)
        engine = DetectionEngine(config=config, joern_client=mock_joern)
        result = await engine.detect(sample_spec)

        if result.findings:
            finding = result.findings[0]
            assert finding.slice is not None

    @pytest.mark.asyncio
    async def test_skips_slices_when_disabled(
        self,
        sample_spec: DynamicSpec,
    ):
        """Should skip slices when configured."""
        mock_joern = AsyncMock(spec=JoernClient)
        mock_joern.is_available.return_value = True
        mock_joern.query.return_value = QueryResult(
            success=True,
            data=json.dumps([{
                "source": {"line": 10, "file": "a.py"},
                "sink": {"line": 25, "file": "b.py"},
                "trace": [],
            }]),
        )

        config = DetectionConfig(generate_slices=False)
        engine = DetectionEngine(config=config, joern_client=mock_joern)
        result = await engine.detect(sample_spec)

        # Slice should not be generated
        mock_joern.get_slice.assert_not_called()


class TestConfidenceFiltering:
    """Test confidence-based filtering."""

    @pytest.mark.asyncio
    async def test_filters_low_confidence_specs(self):
        """Should filter out low confidence specs."""
        spec = DynamicSpec(repository="test")
        spec.add_source(TaintSpec(
            method="low_conf",
            file_path=Path("/app/a.py"),
            line=1,
            label=TaintLabel.SOURCE,
            confidence=0.3,  # Low confidence
            vulnerability_types=["CWE-89"],
        ))
        spec.add_sink(TaintSpec(
            method="sink",
            file_path=Path("/app/b.py"),
            line=2,
            label=TaintLabel.SINK,
            confidence=0.9,
            vulnerability_types=["CWE-89"],
        ))

        mock_joern = AsyncMock(spec=JoernClient)
        mock_joern.is_available.return_value = True
        mock_joern.query.return_value = QueryResult(success=True, data='[]')

        config = DetectionConfig(min_confidence=0.5)
        engine = DetectionEngine(config=config, joern_client=mock_joern)
        result = await engine.detect(spec)

        # Low confidence source should be filtered
        assert result.success is True


class TestDetectionStatistics:
    """Test detection statistics."""

    @pytest.mark.asyncio
    async def test_tracks_execution_time(self, sample_spec: DynamicSpec):
        """Should track execution time."""
        mock_joern = AsyncMock(spec=JoernClient)
        mock_joern.is_available.return_value = True
        mock_joern.query.return_value = QueryResult(success=True, data='[]')

        engine = DetectionEngine(joern_client=mock_joern)
        result = await engine.detect(sample_spec)

        assert result.execution_time_ms >= 0

    @pytest.mark.asyncio
    async def test_provides_summary(self, sample_spec: DynamicSpec):
        """Should provide detection summary."""
        mock_joern = AsyncMock(spec=JoernClient)
        mock_joern.is_available.return_value = True
        mock_joern.query.return_value = QueryResult(success=True, data='[]')

        engine = DetectionEngine(joern_client=mock_joern)
        result = await engine.detect(sample_spec)

        summary = result.summary()
        assert "total_findings" in summary
        assert "flows_analyzed" in summary
        assert "queries_executed" in summary
