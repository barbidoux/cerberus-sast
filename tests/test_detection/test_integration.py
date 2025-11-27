"""
Integration tests for Phase III Detection Engine.

These tests verify the complete detection pipeline works correctly.
Some tests require Joern to be running and are skipped if unavailable.
"""

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from cerberus.detection import (
    CPGQLQuery,
    DataFlow,
    DetectionConfig,
    DetectionEngine,
    DetectionResult,
    FlowAnalyzer,
    JoernClient,
    JoernConfig,
    ProgramSlicer,
    QueryGenerator,
    QueryResult,
)
from cerberus.models.base import CodeLocation, Severity, TaintLabel
from cerberus.models.finding import Finding, TraceStep
from cerberus.models.spec import DynamicSpec, TaintSpec


# Check if Joern is available
async def is_joern_available() -> bool:
    """Check if Joern server is running."""
    try:
        client = JoernClient(JoernConfig(endpoint="localhost:8080", timeout=5))
        return await client.is_available()
    except Exception:
        return False


# Skip marker for tests requiring Joern
joern_required = pytest.mark.skipif(
    os.environ.get("SKIP_JOERN_TESTS", "1") == "1",
    reason="Joern server not available or SKIP_JOERN_TESTS=1"
)


@pytest.fixture
def sample_spec() -> DynamicSpec:
    """Create a sample DynamicSpec for testing."""
    spec = DynamicSpec(
        repository="test-repo",
        generated_at=datetime.now(timezone.utc),
    )
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


class TestQueryGeneration:
    """Test query generation without Joern."""

    def test_generates_queries_for_sql_injection(self, sample_spec: DynamicSpec):
        """Should generate SQL injection queries."""
        generator = QueryGenerator()
        queries = generator.generate_queries(sample_spec)

        assert len(queries) > 0
        assert all(isinstance(q, CPGQLQuery) for q in queries)
        assert any(q.vulnerability_type == "CWE-89" for q in queries)

    def test_queries_include_sanitizers(self, sample_spec: DynamicSpec):
        """Should include sanitizer references in queries."""
        generator = QueryGenerator()
        queries = generator.generate_queries(sample_spec)

        sql_queries = [q for q in queries if q.vulnerability_type == "CWE-89"]
        assert len(sql_queries) > 0
        assert any("escape_sql" in q.sanitizers for q in sql_queries)

    def test_handles_empty_spec(self):
        """Should handle empty specification."""
        spec = DynamicSpec(repository="empty")
        generator = QueryGenerator()
        queries = generator.generate_queries(spec)

        assert queries == []


class TestMockedDetection:
    """Test detection with mocked Joern client."""

    @pytest.mark.asyncio
    async def test_full_pipeline_with_mock(self, sample_spec: DynamicSpec):
        """Should run full detection pipeline with mocked Joern."""
        mock_joern = AsyncMock(spec=JoernClient)
        mock_joern.is_available.return_value = True
        mock_joern.query.return_value = QueryResult(
            success=True,
            data=json.dumps([{
                "source": {
                    "method": "get_user_input",
                    "line": 10,
                    "file": "handler.py"
                },
                "sink": {
                    "method": "execute_query",
                    "line": 25,
                    "file": "database.py"
                },
                "trace": [
                    {"line": 10, "code": "data = request.params['q']", "file": "handler.py"},
                    {"line": 15, "code": "query = 'SELECT * FROM users WHERE id=' + data", "file": "handler.py"},
                    {"line": 25, "code": "cursor.execute(query)", "file": "database.py"},
                ],
            }]),
        )
        mock_joern.get_slice.return_value = [
            {"lineNumber": 10, "code": "data = request.params['q']"},
            {"lineNumber": 15, "code": "query = 'SELECT * FROM users WHERE id=' + data"},
            {"lineNumber": 25, "code": "cursor.execute(query)"},
        ]
        mock_joern.get_control_structures.return_value = []

        config = DetectionConfig(generate_slices=True)
        engine = DetectionEngine(config=config, joern_client=mock_joern)
        result = await engine.detect(sample_spec)

        assert result.success is True
        assert len(result.findings) > 0

        finding = result.findings[0]
        assert finding.vulnerability_type == "CWE-89"
        assert finding.severity in [Severity.HIGH, Severity.CRITICAL]
        assert len(finding.trace) > 0
        assert finding.slice is not None

    @pytest.mark.asyncio
    async def test_finding_has_complete_trace(self, sample_spec: DynamicSpec):
        """Should create findings with complete traces."""
        mock_joern = AsyncMock(spec=JoernClient)
        mock_joern.is_available.return_value = True
        mock_joern.query.return_value = QueryResult(
            success=True,
            data=json.dumps([{
                "source": {"line": 10, "file": "a.py"},
                "sink": {"line": 25, "file": "b.py"},
                "trace": [
                    {"line": 10, "code": "source_code", "file": "a.py"},
                    {"line": 25, "code": "sink_code", "file": "b.py"},
                ],
            }]),
        )
        mock_joern.get_slice.return_value = []
        mock_joern.get_control_structures.return_value = []

        config = DetectionConfig(generate_slices=False)
        engine = DetectionEngine(config=config, joern_client=mock_joern)
        result = await engine.detect(sample_spec)

        assert result.success is True
        if result.findings:
            finding = result.findings[0]
            # Should have source and sink in trace
            source_steps = [t for t in finding.trace if t.step_type == "source"]
            sink_steps = [t for t in finding.trace if t.step_type == "sink"]
            assert len(source_steps) > 0 or len(sink_steps) > 0

    @pytest.mark.asyncio
    async def test_handles_no_flows_found(self, sample_spec: DynamicSpec):
        """Should handle case where no flows are found."""
        mock_joern = AsyncMock(spec=JoernClient)
        mock_joern.is_available.return_value = True
        mock_joern.query.return_value = QueryResult(success=True, data='[]')

        engine = DetectionEngine(joern_client=mock_joern)
        result = await engine.detect(sample_spec)

        assert result.success is True
        assert result.findings == []


class TestFlowAnalyzerIntegration:
    """Test flow analyzer integration."""

    @pytest.mark.asyncio
    async def test_analyzes_multiple_queries(self, sample_spec: DynamicSpec):
        """Should analyze multiple queries in parallel."""
        mock_joern = AsyncMock(spec=JoernClient)
        mock_joern.query.return_value = QueryResult(
            success=True,
            data=json.dumps([{"source": {"line": 1}, "sink": {"line": 2}, "trace": []}]),
        )

        analyzer = FlowAnalyzer(joern_client=mock_joern)
        queries = [
            CPGQLQuery("query1", "src1", "sink1", "CWE-89"),
            CPGQLQuery("query2", "src2", "sink2", "CWE-79"),
            CPGQLQuery("query3", "src3", "sink3", "CWE-78"),
        ]

        results = await analyzer.analyze_queries(queries)

        assert len(results) == 3
        assert all(r.success for r in results)


class TestSlicerIntegration:
    """Test slicer integration."""

    @pytest.mark.asyncio
    async def test_generates_prompt_context(self):
        """Should generate usable prompt context."""
        flow = DataFlow(
            source_method="get_input",
            sink_method="execute",
            source_location=CodeLocation(Path("/app/a.py"), 10, 0),
            sink_location=CodeLocation(Path("/app/a.py"), 25, 0),
            trace_steps=[
                TraceStep(
                    location=CodeLocation(Path("/app/a.py"), 10, 0),
                    code_snippet="data = get_input()",
                    description="Source",
                    step_type="source",
                ),
            ],
            vulnerability_type="CWE-89",
        )

        mock_joern = AsyncMock(spec=JoernClient)
        mock_joern.get_slice.return_value = [
            {"lineNumber": 10, "code": "data = get_input()"},
            {"lineNumber": 15, "code": "query = build_query(data)"},
            {"lineNumber": 25, "code": "cursor.execute(query)"},
        ]
        mock_joern.get_control_structures.return_value = []
        mock_joern.query.return_value = QueryResult(success=True, data='[]')

        slicer = ProgramSlicer(joern_client=mock_joern)
        result = await slicer.extract_slice(flow)

        assert result.success is True
        assert result.slice is not None

        context = result.slice.to_prompt_context()
        assert "File:" in context
        assert "Source:" in context or "source" in context.lower()


class TestEndToEndMocked:
    """End-to-end tests with mocked dependencies."""

    @pytest.mark.asyncio
    async def test_complete_detection_workflow(self, sample_spec: DynamicSpec):
        """Should complete full detection workflow."""
        mock_joern = AsyncMock(spec=JoernClient)
        mock_joern.is_available.return_value = True

        # Simulate finding a SQL injection vulnerability
        mock_joern.query.return_value = QueryResult(
            success=True,
            data=json.dumps([{
                "source": {
                    "method": "get_user_input",
                    "line": 10,
                    "file": "handler.py"
                },
                "sink": {
                    "method": "execute_query",
                    "line": 25,
                    "file": "database.py"
                },
                "trace": [
                    {"line": 10, "code": "user_input = request.form['q']", "file": "handler.py"},
                    {"line": 18, "code": "sql = f'SELECT * FROM table WHERE col={user_input}'", "file": "handler.py"},
                    {"line": 25, "code": "db.execute_query(sql)", "file": "database.py"},
                ],
            }]),
        )
        mock_joern.get_slice.return_value = [
            {"lineNumber": 10, "code": "user_input = request.form['q']"},
            {"lineNumber": 18, "code": "sql = f'SELECT * FROM table WHERE col={user_input}'"},
            {"lineNumber": 25, "code": "db.execute_query(sql)"},
        ]
        mock_joern.get_control_structures.return_value = []

        # Run detection
        engine = DetectionEngine(joern_client=mock_joern)
        result = await engine.detect(sample_spec)

        # Verify results
        assert result.success is True
        assert result.queries_executed > 0
        assert len(result.findings) > 0

        finding = result.findings[0]
        assert finding.vulnerability_type == "CWE-89"
        assert "SQL" in finding.title or "sql" in finding.title.lower()
        assert finding.severity in [Severity.HIGH, Severity.CRITICAL]

        # Should have trace
        assert len(finding.trace) >= 2  # At least source and sink

        # Should have program slice
        assert finding.slice is not None
        assert len(finding.slice.trace_lines) > 0

    @pytest.mark.asyncio
    async def test_multiple_vulnerability_types(self):
        """Should detect multiple vulnerability types."""
        spec = DynamicSpec(repository="multi-vuln-test")

        # Add SQL injection source/sink
        spec.add_source(TaintSpec(
            method="get_query_param",
            file_path=Path("/app/api.py"),
            line=10,
            label=TaintLabel.SOURCE,
            confidence=0.9,
            vulnerability_types=["CWE-89"],
        ))
        spec.add_sink(TaintSpec(
            method="run_query",
            file_path=Path("/app/db.py"),
            line=20,
            label=TaintLabel.SINK,
            confidence=0.9,
            vulnerability_types=["CWE-89"],
        ))

        # Add XSS source/sink
        spec.add_source(TaintSpec(
            method="get_html_input",
            file_path=Path("/app/views.py"),
            line=30,
            label=TaintLabel.SOURCE,
            confidence=0.85,
            vulnerability_types=["CWE-79"],
        ))
        spec.add_sink(TaintSpec(
            method="render_template",
            file_path=Path("/app/templates.py"),
            line=40,
            label=TaintLabel.SINK,
            confidence=0.85,
            vulnerability_types=["CWE-79"],
        ))

        mock_joern = AsyncMock(spec=JoernClient)
        mock_joern.is_available.return_value = True
        mock_joern.query.return_value = QueryResult(
            success=True,
            data=json.dumps([{"source": {"line": 10}, "sink": {"line": 20}, "trace": []}]),
        )
        mock_joern.get_slice.return_value = []
        mock_joern.get_control_structures.return_value = []

        engine = DetectionEngine(joern_client=mock_joern)
        result = await engine.detect(spec)

        assert result.success is True
        # Should have generated queries for both CWE-89 and CWE-79
        assert result.queries_executed >= 2


@joern_required
class TestLiveJoern:
    """Tests requiring a live Joern server."""

    @pytest.mark.asyncio
    async def test_joern_connectivity(self):
        """Should connect to Joern server."""
        client = JoernClient()
        available = await client.is_available()
        assert available is True

    @pytest.mark.asyncio
    async def test_execute_simple_query(self):
        """Should execute a simple CPGQL query."""
        client = JoernClient()
        result = await client.query('cpg.method.name.l.take(5)')

        # Query should succeed (even if no CPG loaded)
        assert isinstance(result, QueryResult)
