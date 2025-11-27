"""
Tests for Program Slicer.

TDD: Write tests first, then implement to make them pass.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from cerberus.detection.slicer import (
    ProgramSlicer,
    SlicerConfig,
    SliceResult,
)
from cerberus.detection.flow_analyzer import DataFlow
from cerberus.detection.joern_client import JoernClient, QueryResult
from cerberus.models.base import CodeLocation
from cerberus.models.finding import TraceStep, ProgramSlice, SliceLine


@pytest.fixture
def sample_data_flow() -> DataFlow:
    """Create a sample data flow."""
    return DataFlow(
        source_method="get_user_input",
        sink_method="execute_query",
        source_location=CodeLocation(Path("/app/handler.py"), 10, 0),
        sink_location=CodeLocation(Path("/app/handler.py"), 25, 0),
        trace_steps=[
            TraceStep(
                location=CodeLocation(Path("/app/handler.py"), 10, 0),
                code_snippet="data = request.get_param('query')",
                description="Source",
                step_type="source",
            ),
            TraceStep(
                location=CodeLocation(Path("/app/handler.py"), 15, 0),
                code_snippet="processed = process_input(data)",
                description="Propagation",
                step_type="propagation",
            ),
            TraceStep(
                location=CodeLocation(Path("/app/handler.py"), 25, 0),
                code_snippet="cursor.execute(processed)",
                description="Sink",
                step_type="sink",
            ),
        ],
        vulnerability_type="CWE-89",
    )


@pytest.fixture
def sample_source_code() -> str:
    """Sample source code for slicing."""
    return '''
def handler(request):
    # This is a handler function
    user_id = request.get_header('X-User-ID')

    # Get query from user input
    data = request.get_param('query')  # SOURCE

    # Some validation
    if not data:
        return error_response("Missing query")

    # Process the data
    processed = process_input(data)

    # Additional processing
    result_count = len(processed)
    log.info(f"Processing {result_count} items")

    # Execute the query
    cursor.execute(processed)  # SINK

    results = cursor.fetchall()
    return json_response(results)

def other_function():
    # This should not be in the slice
    pass
'''


class TestSlicerConfig:
    """Test SlicerConfig."""

    def test_default_config(self):
        """Should have sensible defaults."""
        config = SlicerConfig()
        assert config.include_control_structures is True
        assert config.include_variable_definitions is True
        assert config.context_lines >= 0
        assert config.max_slice_lines > 0

    def test_custom_config(self):
        """Should accept custom values."""
        config = SlicerConfig(
            include_control_structures=False,
            context_lines=5,
            max_slice_lines=50,
        )
        assert config.include_control_structures is False
        assert config.context_lines == 5


class TestSliceResult:
    """Test SliceResult dataclass."""

    def test_create_slice_result(self, sample_data_flow: DataFlow):
        """Should create slice result."""
        result = SliceResult(
            flow=sample_data_flow,
            slice=ProgramSlice(
                source_location=sample_data_flow.source_location,
                sink_location=sample_data_flow.sink_location,
                file_path=Path("/app/handler.py"),
                trace_lines=[],
            ),
            success=True,
        )
        assert result.success is True

    def test_slice_result_with_error(self, sample_data_flow: DataFlow):
        """Should capture error details."""
        result = SliceResult(
            flow=sample_data_flow,
            slice=None,
            success=False,
            error="Failed to read file",
        )
        assert result.success is False
        assert result.error is not None


class TestProgramSlicer:
    """Test ProgramSlicer class."""

    def test_create_slicer(self):
        """Should create slicer instance."""
        slicer = ProgramSlicer()
        assert slicer is not None

    def test_create_with_config(self):
        """Should accept custom configuration."""
        config = SlicerConfig(context_lines=10)
        slicer = ProgramSlicer(config=config)
        assert slicer.config.context_lines == 10

    def test_create_with_joern_client(self):
        """Should accept Joern client."""
        client = MagicMock(spec=JoernClient)
        slicer = ProgramSlicer(joern_client=client)
        assert slicer.joern_client == client


class TestSliceExtraction:
    """Test slice extraction functionality."""

    @pytest.mark.asyncio
    async def test_extract_slice(
        self,
        sample_data_flow: DataFlow,
        sample_source_code: str,
    ):
        """Should extract slice from data flow."""
        mock_client = AsyncMock(spec=JoernClient)
        mock_client.get_slice.return_value = [
            {"lineNumber": 10, "code": "data = request.get_param('query')"},
            {"lineNumber": 15, "code": "processed = process_input(data)"},
            {"lineNumber": 25, "code": "cursor.execute(processed)"},
        ]

        slicer = ProgramSlicer(joern_client=mock_client)
        result = await slicer.extract_slice(sample_data_flow)

        assert isinstance(result, SliceResult)
        assert result.success is True
        assert result.slice is not None

    @pytest.mark.asyncio
    async def test_includes_trace_lines(
        self,
        sample_data_flow: DataFlow,
    ):
        """Should include all trace lines in slice."""
        mock_client = AsyncMock(spec=JoernClient)
        mock_client.get_slice.return_value = [
            {"lineNumber": 10, "code": "data = request.get_param('query')"},
            {"lineNumber": 15, "code": "processed = process_input(data)"},
            {"lineNumber": 25, "code": "cursor.execute(processed)"},
        ]

        slicer = ProgramSlicer(joern_client=mock_client)
        result = await slicer.extract_slice(sample_data_flow)

        slice_lines = [l.line_number for l in result.slice.trace_lines]
        assert 10 in slice_lines  # Source
        assert 25 in slice_lines  # Sink

    @pytest.mark.asyncio
    async def test_marks_trace_lines(
        self,
        sample_data_flow: DataFlow,
    ):
        """Should mark which lines are part of trace."""
        mock_client = AsyncMock(spec=JoernClient)
        mock_client.get_slice.return_value = [
            {"lineNumber": 10, "code": "data = request.get_param('query')"},
            {"lineNumber": 15, "code": "processed = process_input(data)"},
            {"lineNumber": 25, "code": "cursor.execute(processed)"},
        ]

        slicer = ProgramSlicer(joern_client=mock_client)
        result = await slicer.extract_slice(sample_data_flow)

        # Lines from the trace should be marked
        trace_marked = [l for l in result.slice.trace_lines if l.is_trace]
        assert len(trace_marked) >= 2  # At least source and sink


class TestControlStructures:
    """Test control structure inclusion."""

    @pytest.mark.asyncio
    async def test_includes_control_structures(
        self,
        sample_data_flow: DataFlow,
    ):
        """Should include relevant control structures."""
        mock_client = AsyncMock(spec=JoernClient)
        mock_client.get_slice.return_value = [
            {"lineNumber": 10, "code": "data = request.get_param('query')"},
        ]
        mock_client.get_control_structures.return_value = [
            {"type": "if", "lineNumber": 12, "code": "if not data:"},
        ]

        config = SlicerConfig(include_control_structures=True)
        slicer = ProgramSlicer(config=config, joern_client=mock_client)
        result = await slicer.extract_slice(sample_data_flow)

        # Should have control structure info
        assert len(result.slice.control_structures) > 0

    @pytest.mark.asyncio
    async def test_excludes_control_structures_when_disabled(
        self,
        sample_data_flow: DataFlow,
    ):
        """Should exclude control structures when configured."""
        mock_client = AsyncMock(spec=JoernClient)
        mock_client.get_slice.return_value = []

        config = SlicerConfig(include_control_structures=False)
        slicer = ProgramSlicer(config=config, joern_client=mock_client)
        result = await slicer.extract_slice(sample_data_flow)

        # Should not call get_control_structures
        mock_client.get_control_structures.assert_not_called()


class TestVariableDefinitions:
    """Test variable definition inclusion."""

    @pytest.mark.asyncio
    async def test_includes_variable_definitions(
        self,
        sample_data_flow: DataFlow,
    ):
        """Should include variable definitions."""
        mock_client = AsyncMock(spec=JoernClient)
        mock_client.get_slice.return_value = [
            {"lineNumber": 10, "code": "data = request.get_param('query')"},
        ]
        mock_client.query.return_value = QueryResult(
            success=True,
            data='[{"name": "data", "line": 10, "value": "request.get_param"}]',
        )

        config = SlicerConfig(include_variable_definitions=True)
        slicer = ProgramSlicer(config=config, joern_client=mock_client)
        result = await slicer.extract_slice(sample_data_flow)

        assert result.slice is not None


class TestSliceReduction:
    """Test code reduction capabilities."""

    @pytest.mark.asyncio
    async def test_reduces_code_size(
        self,
        sample_data_flow: DataFlow,
    ):
        """Should achieve significant code reduction."""
        mock_client = AsyncMock(spec=JoernClient)
        # Only return trace-relevant lines, simulating ~90% reduction
        mock_client.get_slice.return_value = [
            {"lineNumber": 10, "code": "data = request.get_param('query')"},
            {"lineNumber": 15, "code": "processed = process_input(data)"},
            {"lineNumber": 25, "code": "cursor.execute(processed)"},
        ]

        slicer = ProgramSlicer(joern_client=mock_client)
        result = await slicer.extract_slice(sample_data_flow)

        # Set original lines to simulate reduction
        result.slice.original_lines = 50

        # Should achieve reduction
        assert result.slice.reduction_ratio > 0

    @pytest.mark.asyncio
    async def test_respects_max_slice_lines(
        self,
        sample_data_flow: DataFlow,
    ):
        """Should respect maximum slice lines limit."""
        mock_client = AsyncMock(spec=JoernClient)
        # Return many lines
        mock_client.get_slice.return_value = [
            {"lineNumber": i, "code": f"line {i}"}
            for i in range(100)
        ]

        config = SlicerConfig(max_slice_lines=20)
        slicer = ProgramSlicer(config=config, joern_client=mock_client)
        result = await slicer.extract_slice(sample_data_flow)

        assert len(result.slice.trace_lines) <= 20


class TestSliceAnnotations:
    """Test slice line annotations."""

    @pytest.mark.asyncio
    async def test_annotates_source_line(
        self,
        sample_data_flow: DataFlow,
    ):
        """Should annotate source line."""
        mock_client = AsyncMock(spec=JoernClient)
        mock_client.get_slice.return_value = [
            {"lineNumber": 10, "code": "data = request.get_param('query')"},
        ]

        slicer = ProgramSlicer(joern_client=mock_client)
        result = await slicer.extract_slice(sample_data_flow)

        source_line = next(
            (l for l in result.slice.trace_lines if l.line_number == 10),
            None
        )
        assert source_line is not None
        assert source_line.annotation == "SOURCE"

    @pytest.mark.asyncio
    async def test_annotates_sink_line(
        self,
        sample_data_flow: DataFlow,
    ):
        """Should annotate sink line."""
        mock_client = AsyncMock(spec=JoernClient)
        mock_client.get_slice.return_value = [
            {"lineNumber": 25, "code": "cursor.execute(processed)"},
        ]

        slicer = ProgramSlicer(joern_client=mock_client)
        result = await slicer.extract_slice(sample_data_flow)

        sink_line = next(
            (l for l in result.slice.trace_lines if l.line_number == 25),
            None
        )
        assert sink_line is not None
        assert sink_line.annotation == "SINK"


class TestPromptContext:
    """Test prompt context generation."""

    @pytest.mark.asyncio
    async def test_generates_prompt_context(
        self,
        sample_data_flow: DataFlow,
    ):
        """Should generate context for LLM verification."""
        mock_client = AsyncMock(spec=JoernClient)
        mock_client.get_slice.return_value = [
            {"lineNumber": 10, "code": "data = request.get_param('query')"},
            {"lineNumber": 25, "code": "cursor.execute(processed)"},
        ]
        mock_client.get_control_structures.return_value = []
        mock_client.query.return_value = QueryResult(success=True, data='[]')

        slicer = ProgramSlicer(joern_client=mock_client)
        result = await slicer.extract_slice(sample_data_flow)

        context = result.slice.to_prompt_context()

        assert isinstance(context, str)
        assert "Source" in context or "source" in context.lower()
        assert "Sink" in context or "sink" in context.lower()

    @pytest.mark.asyncio
    async def test_context_includes_code(
        self,
        sample_data_flow: DataFlow,
    ):
        """Should include code in prompt context."""
        mock_client = AsyncMock(spec=JoernClient)
        mock_client.get_slice.return_value = [
            {"lineNumber": 10, "code": "data = request.get_param('query')"},
        ]
        mock_client.get_control_structures.return_value = []
        mock_client.query.return_value = QueryResult(success=True, data='[]')

        slicer = ProgramSlicer(joern_client=mock_client)
        result = await slicer.extract_slice(sample_data_flow)

        context = result.slice.to_prompt_context()

        # Should contain the code or line reference
        assert "10" in context or "request.get_param" in context


class TestBatchSlicing:
    """Test batch slicing functionality."""

    @pytest.mark.asyncio
    async def test_extract_multiple_slices(
        self,
        sample_data_flow: DataFlow,
    ):
        """Should extract slices for multiple flows."""
        mock_client = AsyncMock(spec=JoernClient)
        mock_client.get_slice.return_value = [
            {"lineNumber": 10, "code": "test"},
        ]

        slicer = ProgramSlicer(joern_client=mock_client)
        flows = [sample_data_flow, sample_data_flow]
        results = await slicer.extract_slices(flows)

        assert len(results) == 2
        assert all(r.success for r in results)

    @pytest.mark.asyncio
    async def test_handles_individual_failures(
        self,
        sample_data_flow: DataFlow,
    ):
        """Should handle failures for individual flows."""
        mock_client = AsyncMock(spec=JoernClient)
        mock_client.get_slice.side_effect = [
            [{"lineNumber": 10, "code": "test"}],
            Exception("Failed"),
            [{"lineNumber": 20, "code": "test2"}],
        ]

        slicer = ProgramSlicer(joern_client=mock_client)
        flows = [sample_data_flow, sample_data_flow, sample_data_flow]
        results = await slicer.extract_slices(flows)

        assert len(results) == 3
        # First and third should succeed, second should fail
        assert results[0].success is True
        assert results[1].success is False
        assert results[2].success is True
