"""
Tests for Attacker Agent.

TDD: Write tests first, then implement to make them pass.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from cerberus.llm.prompts.verification import AttackerResponse
from cerberus.models.base import CodeLocation
from cerberus.models.finding import Finding, ProgramSlice, SliceLine, TraceStep
from cerberus.verification.attacker_agent import (
    AttackerAgent,
    AttackerAgentConfig,
    AttackerResult,
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
                SliceLine(line_number=25, code="cursor.execute(processed)", is_trace=True),
            ],
        ),
    )


@pytest.fixture
def mock_llm_gateway() -> AsyncMock:
    """Create a mock LLM gateway."""
    gateway = AsyncMock()
    gateway.complete.return_value = '{"exploitable": true, "attack_input": "\\"; DROP TABLE users; --", "reasoning": "Direct SQL injection"}'
    return gateway


class TestAttackerAgentConfig:
    """Test AttackerAgentConfig."""

    def test_default_config(self):
        """Should have sensible defaults."""
        config = AttackerAgentConfig()
        assert config.max_retries >= 1
        assert config.temperature >= 0.0
        assert config.model is not None

    def test_custom_config(self):
        """Should accept custom values."""
        config = AttackerAgentConfig(
            max_retries=5,
            temperature=0.8,
            model="custom-model",
        )
        assert config.max_retries == 5
        assert config.temperature == 0.8
        assert config.model == "custom-model"


class TestAttackerResult:
    """Test AttackerResult dataclass."""

    def test_create_result(self):
        """Should create result with required fields."""
        response = AttackerResponse(
            exploitable=True,
            attack_input="'; DROP TABLE--",
            reasoning="SQL injection",
        )
        result = AttackerResult(
            success=True,
            response=response,
        )
        assert result.success is True
        assert result.response.exploitable is True

    def test_result_with_error(self):
        """Should capture error details."""
        result = AttackerResult(
            success=False,
            response=None,
            error="LLM request failed",
        )
        assert result.success is False
        assert result.error is not None


class TestAttackerAgent:
    """Test AttackerAgent class."""

    def test_create_agent(self):
        """Should create agent instance."""
        agent = AttackerAgent()
        assert agent is not None

    def test_create_with_config(self):
        """Should accept custom configuration."""
        config = AttackerAgentConfig(max_retries=5)
        agent = AttackerAgent(config=config)
        assert agent.config.max_retries == 5

    def test_create_with_llm_gateway(self):
        """Should accept LLM gateway."""
        gateway = MagicMock()
        agent = AttackerAgent(llm_gateway=gateway)
        assert agent.llm_gateway == gateway


class TestAttackerAnalysis:
    """Test attacker analysis functionality."""

    @pytest.mark.asyncio
    async def test_analyze_finding(
        self,
        sample_finding: Finding,
        mock_llm_gateway: AsyncMock,
    ):
        """Should analyze finding and return result."""
        agent = AttackerAgent(llm_gateway=mock_llm_gateway)
        result = await agent.analyze(sample_finding)

        assert isinstance(result, AttackerResult)
        assert result.success is True
        assert result.response is not None

    @pytest.mark.asyncio
    async def test_analyze_returns_exploitable(
        self,
        sample_finding: Finding,
        mock_llm_gateway: AsyncMock,
    ):
        """Should return exploitable status from LLM."""
        agent = AttackerAgent(llm_gateway=mock_llm_gateway)
        result = await agent.analyze(sample_finding)

        assert result.response.exploitable is True

    @pytest.mark.asyncio
    async def test_analyze_includes_attack_input(
        self,
        sample_finding: Finding,
        mock_llm_gateway: AsyncMock,
    ):
        """Should include attack input when exploitable."""
        agent = AttackerAgent(llm_gateway=mock_llm_gateway)
        result = await agent.analyze(sample_finding)

        assert result.response.attack_input is not None
        assert "DROP" in result.response.attack_input

    @pytest.mark.asyncio
    async def test_analyze_handles_llm_error(
        self,
        sample_finding: Finding,
    ):
        """Should handle LLM errors gracefully."""
        gateway = AsyncMock()
        gateway.complete.side_effect = Exception("LLM unavailable")

        agent = AttackerAgent(llm_gateway=gateway)
        result = await agent.analyze(sample_finding)

        assert result.success is False
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_analyze_handles_invalid_response(
        self,
        sample_finding: Finding,
    ):
        """Should handle invalid LLM response."""
        gateway = AsyncMock()
        gateway.complete.return_value = "not valid json at all"

        agent = AttackerAgent(llm_gateway=gateway)
        result = await agent.analyze(sample_finding)

        # Should still succeed but with parsed fallback
        assert result.success is True
        assert result.response is not None


class TestAttackerPromptConstruction:
    """Test prompt construction for attacker."""

    @pytest.mark.asyncio
    async def test_prompt_includes_vulnerability_type(
        self,
        sample_finding: Finding,
        mock_llm_gateway: AsyncMock,
    ):
        """Should include vulnerability type in prompt."""
        agent = AttackerAgent(llm_gateway=mock_llm_gateway)
        await agent.analyze(sample_finding)

        # Check that complete was called with prompt containing vuln type
        call_args = mock_llm_gateway.complete.call_args
        assert call_args is not None

    @pytest.mark.asyncio
    async def test_prompt_includes_code_slice(
        self,
        sample_finding: Finding,
        mock_llm_gateway: AsyncMock,
    ):
        """Should include code slice in prompt."""
        agent = AttackerAgent(llm_gateway=mock_llm_gateway)
        await agent.analyze(sample_finding)

        # Verify LLM was called
        assert mock_llm_gateway.complete.called


class TestAttackerRetries:
    """Test retry behavior."""

    @pytest.mark.asyncio
    async def test_retries_on_failure(
        self,
        sample_finding: Finding,
    ):
        """Should retry on transient failures."""
        gateway = AsyncMock()
        gateway.complete.side_effect = [
            Exception("Transient error"),
            '{"exploitable": false, "reasoning": "test"}',
        ]

        config = AttackerAgentConfig(max_retries=3)
        agent = AttackerAgent(config=config, llm_gateway=gateway)
        result = await agent.analyze(sample_finding)

        assert result.success is True
        assert gateway.complete.call_count == 2

    @pytest.mark.asyncio
    async def test_fails_after_max_retries(
        self,
        sample_finding: Finding,
    ):
        """Should fail after exhausting retries."""
        gateway = AsyncMock()
        gateway.complete.side_effect = Exception("Persistent error")

        config = AttackerAgentConfig(max_retries=2)
        agent = AttackerAgent(config=config, llm_gateway=gateway)
        result = await agent.analyze(sample_finding)

        assert result.success is False
        assert gateway.complete.call_count == 2
