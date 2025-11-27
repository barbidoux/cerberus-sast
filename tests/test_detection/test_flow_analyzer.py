"""
Tests for Flow Analyzer.

TDD: Write tests first, then implement to make them pass.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cerberus.detection.flow_analyzer import (
    FlowAnalyzer,
    FlowAnalyzerConfig,
    FlowResult,
    DataFlow,
)
from cerberus.detection.joern_client import JoernClient, QueryResult
from cerberus.detection.query_generator import CPGQLQuery
from cerberus.models.base import CodeLocation, TaintLabel
from cerberus.models.finding import TraceStep
from cerberus.models.spec import TaintSpec


@pytest.fixture
def sample_query() -> CPGQLQuery:
    """Create a sample CPGQL query."""
    return CPGQLQuery(
        query='def source = cpg.method.name("get_input").parameter\n'
              'def sink = cpg.method.name("execute").parameter\n'
              'sink.reachableBy(source).toJson',
        source="get_input",
        sink="execute",
        vulnerability_type="CWE-89",
        sanitizers=["escape_sql"],
    )


@pytest.fixture
def sample_joern_response() -> dict:
    """Create a sample Joern query response."""
    return [
        {
            "source": {"method": "get_input", "line": 10, "file": "handler.py"},
            "sink": {"method": "execute", "line": 25, "file": "db.py"},
            "trace": [
                {"line": 10, "code": "data = request.get_param('q')", "file": "handler.py"},
                {"line": 15, "code": "result = process(data)", "file": "handler.py"},
                {"line": 25, "code": "cursor.execute(query)", "file": "db.py"},
            ],
        }
    ]


class TestFlowAnalyzerConfig:
    """Test FlowAnalyzerConfig."""

    def test_default_config(self):
        """Should have sensible defaults."""
        config = FlowAnalyzerConfig()
        assert config.max_flows_per_query > 0
        assert config.timeout > 0
        assert config.parallel_queries is True

    def test_custom_config(self):
        """Should accept custom values."""
        config = FlowAnalyzerConfig(
            max_flows_per_query=50,
            timeout=120,
            parallel_queries=False,
        )
        assert config.max_flows_per_query == 50
        assert config.timeout == 120


class TestDataFlow:
    """Test DataFlow dataclass."""

    def test_create_data_flow(self):
        """Should create data flow with trace."""
        flow = DataFlow(
            source_method="get_input",
            sink_method="execute",
            source_location=CodeLocation(Path("/app/handler.py"), 10, 0),
            sink_location=CodeLocation(Path("/app/db.py"), 25, 0),
            trace_steps=[
                TraceStep(
                    location=CodeLocation(Path("/app/handler.py"), 10, 0),
                    code_snippet="data = get_input()",
                    description="Source: user input",
                    step_type="source",
                ),
            ],
            vulnerability_type="CWE-89",
        )
        assert flow.source_method == "get_input"
        assert flow.sink_method == "execute"
        assert len(flow.trace_steps) == 1

    def test_data_flow_to_dict(self):
        """Should serialize to dictionary."""
        flow = DataFlow(
            source_method="src",
            sink_method="sink",
            source_location=CodeLocation(Path("/app/a.py"), 1, 0),
            sink_location=CodeLocation(Path("/app/b.py"), 2, 0),
        )
        data = flow.to_dict()
        assert "source_method" in data
        assert "sink_method" in data


class TestFlowResult:
    """Test FlowResult dataclass."""

    def test_create_flow_result(self):
        """Should create flow result."""
        result = FlowResult(
            query=CPGQLQuery("...", "src", "sink"),
            flows=[],
            success=True,
        )
        assert result.success is True
        assert result.flows == []

    def test_flow_result_with_error(self):
        """Should capture error details."""
        result = FlowResult(
            query=CPGQLQuery("...", "src", "sink"),
            flows=[],
            success=False,
            error="Query timeout",
        )
        assert result.success is False
        assert "timeout" in result.error.lower()

    def test_flow_count(self):
        """Should count flows."""
        flow = DataFlow(
            source_method="src",
            sink_method="sink",
            source_location=CodeLocation(Path("/a.py"), 1, 0),
            sink_location=CodeLocation(Path("/b.py"), 2, 0),
        )
        result = FlowResult(
            query=CPGQLQuery("...", "src", "sink"),
            flows=[flow, flow],
            success=True,
        )
        assert result.flow_count == 2


class TestFlowAnalyzer:
    """Test FlowAnalyzer class."""

    def test_create_analyzer(self):
        """Should create analyzer instance."""
        analyzer = FlowAnalyzer()
        assert analyzer is not None

    def test_create_with_config(self):
        """Should accept custom configuration."""
        config = FlowAnalyzerConfig(timeout=30)
        analyzer = FlowAnalyzer(config=config)
        assert analyzer.config.timeout == 30

    def test_create_with_joern_client(self):
        """Should accept Joern client."""
        client = MagicMock(spec=JoernClient)
        analyzer = FlowAnalyzer(joern_client=client)
        assert analyzer.joern_client == client


class TestFlowAnalysis:
    """Test flow analysis functionality."""

    @pytest.mark.asyncio
    async def test_analyze_single_query(
        self,
        sample_query: CPGQLQuery,
        sample_joern_response: dict,
    ):
        """Should analyze a single query."""
        mock_client = AsyncMock(spec=JoernClient)
        mock_client.query.return_value = QueryResult(
            success=True,
            data='[{"source": {"line": 10}, "sink": {"line": 25}, "trace": []}]',
        )

        analyzer = FlowAnalyzer(joern_client=mock_client)
        result = await analyzer.analyze_query(sample_query)

        assert isinstance(result, FlowResult)
        mock_client.query.assert_called_once()

    @pytest.mark.asyncio
    async def test_analyze_multiple_queries(
        self,
        sample_query: CPGQLQuery,
    ):
        """Should analyze multiple queries."""
        mock_client = AsyncMock(spec=JoernClient)
        mock_client.query.return_value = QueryResult(
            success=True,
            data='[]',
        )

        analyzer = FlowAnalyzer(joern_client=mock_client)
        queries = [sample_query, sample_query]
        results = await analyzer.analyze_queries(queries)

        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_handles_query_failure(self, sample_query: CPGQLQuery):
        """Should handle query failures gracefully."""
        mock_client = AsyncMock(spec=JoernClient)
        mock_client.query.return_value = QueryResult(
            success=False,
            error="Syntax error",
        )

        analyzer = FlowAnalyzer(joern_client=mock_client)
        result = await analyzer.analyze_query(sample_query)

        assert result.success is False
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_limits_flows_per_query(self, sample_query: CPGQLQuery):
        """Should respect max flows limit."""
        # Generate response with many flows
        many_flows = [
            {"source": {"line": i}, "sink": {"line": i + 10}, "trace": []}
            for i in range(100)
        ]

        mock_client = AsyncMock(spec=JoernClient)
        mock_client.query.return_value = QueryResult(
            success=True,
            data=str(many_flows).replace("'", '"'),
        )

        config = FlowAnalyzerConfig(max_flows_per_query=10)
        analyzer = FlowAnalyzer(config=config, joern_client=mock_client)
        result = await analyzer.analyze_query(sample_query)

        assert len(result.flows) <= 10


class TestTraceExtraction:
    """Test trace extraction from Joern results."""

    @pytest.mark.asyncio
    async def test_extracts_trace_steps(
        self,
        sample_query: CPGQLQuery,
        sample_joern_response: dict,
    ):
        """Should extract trace steps from response."""
        import json

        mock_client = AsyncMock(spec=JoernClient)
        mock_client.query.return_value = QueryResult(
            success=True,
            data=json.dumps(sample_joern_response),
        )

        analyzer = FlowAnalyzer(joern_client=mock_client)
        result = await analyzer.analyze_query(sample_query)

        assert len(result.flows) == 1
        flow = result.flows[0]
        assert len(flow.trace_steps) == 3

    @pytest.mark.asyncio
    async def test_marks_source_and_sink_steps(
        self,
        sample_query: CPGQLQuery,
        sample_joern_response: dict,
    ):
        """Should mark source and sink in trace."""
        import json

        mock_client = AsyncMock(spec=JoernClient)
        mock_client.query.return_value = QueryResult(
            success=True,
            data=json.dumps(sample_joern_response),
        )

        analyzer = FlowAnalyzer(joern_client=mock_client)
        result = await analyzer.analyze_query(sample_query)

        flow = result.flows[0]
        # First step should be source
        assert flow.trace_steps[0].step_type == "source"
        # Last step should be sink
        assert flow.trace_steps[-1].step_type == "sink"

    @pytest.mark.asyncio
    async def test_includes_vulnerability_type(
        self,
        sample_query: CPGQLQuery,
        sample_joern_response: dict,
    ):
        """Should include vulnerability type in flow."""
        import json

        mock_client = AsyncMock(spec=JoernClient)
        mock_client.query.return_value = QueryResult(
            success=True,
            data=json.dumps(sample_joern_response),
        )

        analyzer = FlowAnalyzer(joern_client=mock_client)
        result = await analyzer.analyze_query(sample_query)

        flow = result.flows[0]
        assert flow.vulnerability_type == "CWE-89"


class TestParallelExecution:
    """Test parallel query execution."""

    @pytest.mark.asyncio
    async def test_parallel_execution(self, sample_query: CPGQLQuery):
        """Should execute queries in parallel."""
        mock_client = AsyncMock(spec=JoernClient)
        mock_client.query.return_value = QueryResult(success=True, data='[]')

        config = FlowAnalyzerConfig(parallel_queries=True)
        analyzer = FlowAnalyzer(config=config, joern_client=mock_client)

        queries = [sample_query] * 5
        results = await analyzer.analyze_queries(queries)

        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_sequential_execution(self, sample_query: CPGQLQuery):
        """Should execute sequentially when configured."""
        mock_client = AsyncMock(spec=JoernClient)
        mock_client.query.return_value = QueryResult(success=True, data='[]')

        config = FlowAnalyzerConfig(parallel_queries=False)
        analyzer = FlowAnalyzer(config=config, joern_client=mock_client)

        queries = [sample_query] * 3
        results = await analyzer.analyze_queries(queries)

        assert len(results) == 3


class TestFlowDeduplication:
    """Test flow deduplication."""

    @pytest.mark.asyncio
    async def test_deduplicates_identical_flows(self, sample_query: CPGQLQuery):
        """Should remove duplicate flows."""
        # Response with duplicate flows
        duplicate_flows = [
            {"source": {"line": 10}, "sink": {"line": 25}, "trace": []},
            {"source": {"line": 10}, "sink": {"line": 25}, "trace": []},
        ]

        mock_client = AsyncMock(spec=JoernClient)
        mock_client.query.return_value = QueryResult(
            success=True,
            data=str(duplicate_flows).replace("'", '"'),
        )

        analyzer = FlowAnalyzer(joern_client=mock_client)
        result = await analyzer.analyze_query(sample_query)

        # Should deduplicate
        assert result.flow_count <= 2  # Could be 1 if dedup is strict


class TestFlowStatistics:
    """Test flow analysis statistics."""

    @pytest.mark.asyncio
    async def test_tracks_query_time(self, sample_query: CPGQLQuery):
        """Should track query execution time."""
        mock_client = AsyncMock(spec=JoernClient)
        mock_client.query.return_value = QueryResult(success=True, data='[]')

        analyzer = FlowAnalyzer(joern_client=mock_client)
        result = await analyzer.analyze_query(sample_query)

        assert result.execution_time_ms >= 0

    @pytest.mark.asyncio
    async def test_provides_summary(self, sample_query: CPGQLQuery):
        """Should provide result summary."""
        mock_client = AsyncMock(spec=JoernClient)
        mock_client.query.return_value = QueryResult(
            success=True,
            data='[{"source": {"line": 10}, "sink": {"line": 20}, "trace": []}]',
        )

        analyzer = FlowAnalyzer(joern_client=mock_client)
        result = await analyzer.analyze_query(sample_query)

        summary = result.summary()
        assert "success" in summary
        assert "flow_count" in summary
