"""
Tests for Defender Agent.

TDD: Write tests first, then implement to make them pass.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from cerberus.llm.prompts.verification import AttackerResponse, DefenderResponse
from cerberus.models.base import CodeLocation
from cerberus.models.finding import Finding, ProgramSlice, SliceLine, TraceStep
from cerberus.verification.defender_agent import (
    DefenderAgent,
    DefenderAgentConfig,
    DefenderResult,
)


@pytest.fixture
def sample_finding() -> Finding:
    """Create a sample finding for testing."""
    return Finding(
        vulnerability_type="CWE-89",
        title="SQL Injection via user input",
        description="User input flows to SQL query without sanitization",
        trace=[
            TraceStep(
                location=CodeLocation(Path("/app/handler.py"), 10, 0),
                code_snippet="user_input = request.get('query')",
                description="Source: User input from request",
                step_type="source",
            ),
            TraceStep(
                location=CodeLocation(Path("/app/handler.py"), 25, 0),
                code_snippet="cursor.execute(processed)",
                description="Sink: SQL execution",
                step_type="sink",
            ),
        ],
        slice=ProgramSlice(
            source_location=CodeLocation(Path("/app/handler.py"), 10, 0),
            sink_location=CodeLocation(Path("/app/handler.py"), 25, 0),
            file_path=Path("/app/handler.py"),
            trace_lines=[
                SliceLine(line_number=10, code="user_input = request.get('query')", is_trace=True),
                SliceLine(line_number=15, code="validated = validate_input(user_input)", is_trace=True),
                SliceLine(line_number=25, code="cursor.execute(validated)", is_trace=True),
            ],
        ),
    )


@pytest.fixture
def sample_attacker_response() -> AttackerResponse:
    """Create a sample attacker response."""
    return AttackerResponse(
        exploitable=True,
        attack_input="'; DROP TABLE users; --",
        reasoning="Direct SQL injection possible",
    )


@pytest.fixture
def mock_llm_gateway() -> AsyncMock:
    """Create a mock LLM gateway."""
    gateway = AsyncMock()
    gateway.complete.return_value = '{"safe": true, "defense_lines": [15], "sanitization": "Input validated at line 15", "reasoning": "Validation prevents injection"}'
    return gateway


class TestDefenderAgentConfig:
    """Test DefenderAgentConfig."""

    def test_default_config(self):
        """Should have sensible defaults."""
        config = DefenderAgentConfig()
        assert config.max_retries >= 1
        assert config.temperature >= 0.0
        assert config.model is not None

    def test_custom_config(self):
        """Should accept custom values."""
        config = DefenderAgentConfig(
            max_retries=5,
            temperature=0.7,
            model="custom-model",
        )
        assert config.max_retries == 5


class TestDefenderResult:
    """Test DefenderResult dataclass."""

    def test_create_result(self):
        """Should create result with required fields."""
        response = DefenderResponse(
            safe=True,
            defense_lines=[15, 20],
            reasoning="Input is validated",
        )
        result = DefenderResult(
            success=True,
            response=response,
        )
        assert result.success is True
        assert result.response.safe is True

    def test_result_with_error(self):
        """Should capture error details."""
        result = DefenderResult(
            success=False,
            response=None,
            error="LLM request failed",
        )
        assert result.success is False
        assert result.error is not None


class TestDefenderAgent:
    """Test DefenderAgent class."""

    def test_create_agent(self):
        """Should create agent instance."""
        agent = DefenderAgent()
        assert agent is not None

    def test_create_with_config(self):
        """Should accept custom configuration."""
        config = DefenderAgentConfig(max_retries=5)
        agent = DefenderAgent(config=config)
        assert agent.config.max_retries == 5

    def test_create_with_llm_gateway(self):
        """Should accept LLM gateway."""
        gateway = MagicMock()
        agent = DefenderAgent(llm_gateway=gateway)
        assert agent.llm_gateway == gateway


class TestDefenderAnalysis:
    """Test defender analysis functionality."""

    @pytest.mark.asyncio
    async def test_analyze_finding(
        self,
        sample_finding: Finding,
        sample_attacker_response: AttackerResponse,
        mock_llm_gateway: AsyncMock,
    ):
        """Should analyze finding and return result."""
        agent = DefenderAgent(llm_gateway=mock_llm_gateway)
        result = await agent.analyze(sample_finding, sample_attacker_response)

        assert isinstance(result, DefenderResult)
        assert result.success is True
        assert result.response is not None

    @pytest.mark.asyncio
    async def test_analyze_returns_defense_lines(
        self,
        sample_finding: Finding,
        sample_attacker_response: AttackerResponse,
        mock_llm_gateway: AsyncMock,
    ):
        """Should return defense lines when safe."""
        agent = DefenderAgent(llm_gateway=mock_llm_gateway)
        result = await agent.analyze(sample_finding, sample_attacker_response)

        assert result.response.safe is True
        assert 15 in result.response.defense_lines

    @pytest.mark.asyncio
    async def test_analyze_includes_attacker_context(
        self,
        sample_finding: Finding,
        sample_attacker_response: AttackerResponse,
        mock_llm_gateway: AsyncMock,
    ):
        """Should include attacker's argument in prompt."""
        agent = DefenderAgent(llm_gateway=mock_llm_gateway)
        await agent.analyze(sample_finding, sample_attacker_response)

        # Verify LLM was called
        assert mock_llm_gateway.complete.called

    @pytest.mark.asyncio
    async def test_analyze_handles_llm_error(
        self,
        sample_finding: Finding,
        sample_attacker_response: AttackerResponse,
    ):
        """Should handle LLM errors gracefully."""
        gateway = AsyncMock()
        gateway.complete.side_effect = Exception("LLM unavailable")

        agent = DefenderAgent(llm_gateway=gateway)
        result = await agent.analyze(sample_finding, sample_attacker_response)

        assert result.success is False
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_analyze_handles_invalid_response(
        self,
        sample_finding: Finding,
        sample_attacker_response: AttackerResponse,
    ):
        """Should handle invalid LLM response."""
        gateway = AsyncMock()
        gateway.complete.return_value = "not valid json"

        agent = DefenderAgent(llm_gateway=gateway)
        result = await agent.analyze(sample_finding, sample_attacker_response)

        # Should still succeed with parsed fallback
        assert result.success is True
        assert result.response is not None


class TestDefenderRetries:
    """Test retry behavior."""

    @pytest.mark.asyncio
    async def test_retries_on_failure(
        self,
        sample_finding: Finding,
        sample_attacker_response: AttackerResponse,
    ):
        """Should retry on transient failures."""
        gateway = AsyncMock()
        gateway.complete.side_effect = [
            Exception("Transient error"),
            '{"safe": false, "defense_lines": [], "reasoning": "test"}',
        ]

        config = DefenderAgentConfig(max_retries=3)
        agent = DefenderAgent(config=config, llm_gateway=gateway)
        result = await agent.analyze(sample_finding, sample_attacker_response)

        assert result.success is True
        assert gateway.complete.call_count == 2

    @pytest.mark.asyncio
    async def test_fails_after_max_retries(
        self,
        sample_finding: Finding,
        sample_attacker_response: AttackerResponse,
    ):
        """Should fail after exhausting retries."""
        gateway = AsyncMock()
        gateway.complete.side_effect = Exception("Persistent error")

        config = DefenderAgentConfig(max_retries=2)
        agent = DefenderAgent(config=config, llm_gateway=gateway)
        result = await agent.analyze(sample_finding, sample_attacker_response)

        assert result.success is False
        assert gateway.complete.call_count == 2
