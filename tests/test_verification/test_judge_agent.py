"""
Tests for Judge Agent.

TDD: Write tests first, then implement to make them pass.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from cerberus.llm.prompts.verification import (
    AttackerResponse,
    DefenderResponse,
    JudgeResponse,
)
from cerberus.models.base import CodeLocation, Verdict
from cerberus.models.finding import Finding, ProgramSlice, SliceLine, TraceStep
from cerberus.verification.judge_agent import (
    JudgeAgent,
    JudgeAgentConfig,
    JudgeResult,
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
def sample_attacker_response() -> AttackerResponse:
    """Create a sample attacker response."""
    return AttackerResponse(
        exploitable=True,
        attack_input="'; DROP TABLE users; --",
        reasoning="Direct SQL injection possible",
    )


@pytest.fixture
def sample_defender_response() -> DefenderResponse:
    """Create a sample defender response."""
    return DefenderResponse(
        safe=False,
        defense_lines=[],
        reasoning="No sanitization found",
    )


@pytest.fixture
def mock_llm_gateway() -> AsyncMock:
    """Create a mock LLM gateway."""
    gateway = AsyncMock()
    gateway.complete.return_value = '{"verdict": "TRUE_POSITIVE", "confidence": 0.85, "reasoning": "Attacker argument convincing, no defenses found"}'
    return gateway


class TestJudgeAgentConfig:
    """Test JudgeAgentConfig."""

    def test_default_config(self):
        """Should have sensible defaults."""
        config = JudgeAgentConfig()
        assert config.max_retries >= 1
        assert config.temperature >= 0.0
        assert config.model is not None

    def test_custom_config(self):
        """Should accept custom values."""
        config = JudgeAgentConfig(
            max_retries=5,
            temperature=0.5,
            model="custom-model",
        )
        assert config.max_retries == 5


class TestJudgeResult:
    """Test JudgeResult dataclass."""

    def test_create_result(self):
        """Should create result with required fields."""
        response = JudgeResponse(
            verdict=Verdict.TRUE_POSITIVE,
            confidence=0.9,
            reasoning="Vulnerability confirmed",
        )
        result = JudgeResult(
            success=True,
            response=response,
        )
        assert result.success is True
        assert result.response.verdict == Verdict.TRUE_POSITIVE

    def test_result_with_error(self):
        """Should capture error details."""
        result = JudgeResult(
            success=False,
            response=None,
            error="LLM request failed",
        )
        assert result.success is False
        assert result.error is not None


class TestJudgeAgent:
    """Test JudgeAgent class."""

    def test_create_agent(self):
        """Should create agent instance."""
        agent = JudgeAgent()
        assert agent is not None

    def test_create_with_config(self):
        """Should accept custom configuration."""
        config = JudgeAgentConfig(max_retries=5)
        agent = JudgeAgent(config=config)
        assert agent.config.max_retries == 5

    def test_create_with_llm_gateway(self):
        """Should accept LLM gateway."""
        gateway = MagicMock()
        agent = JudgeAgent(llm_gateway=gateway)
        assert agent.llm_gateway == gateway


class TestJudgeAnalysis:
    """Test judge analysis functionality."""

    @pytest.mark.asyncio
    async def test_analyze_finding(
        self,
        sample_finding: Finding,
        sample_attacker_response: AttackerResponse,
        sample_defender_response: DefenderResponse,
        mock_llm_gateway: AsyncMock,
    ):
        """Should analyze finding and return result."""
        agent = JudgeAgent(llm_gateway=mock_llm_gateway)
        result = await agent.analyze(
            sample_finding,
            sample_attacker_response,
            sample_defender_response,
        )

        assert isinstance(result, JudgeResult)
        assert result.success is True
        assert result.response is not None

    @pytest.mark.asyncio
    async def test_analyze_returns_true_positive(
        self,
        sample_finding: Finding,
        sample_attacker_response: AttackerResponse,
        sample_defender_response: DefenderResponse,
        mock_llm_gateway: AsyncMock,
    ):
        """Should return TRUE_POSITIVE verdict."""
        agent = JudgeAgent(llm_gateway=mock_llm_gateway)
        result = await agent.analyze(
            sample_finding,
            sample_attacker_response,
            sample_defender_response,
        )

        assert result.response.verdict == Verdict.TRUE_POSITIVE

    @pytest.mark.asyncio
    async def test_analyze_returns_false_positive(
        self,
        sample_finding: Finding,
        sample_attacker_response: AttackerResponse,
    ):
        """Should return FALSE_POSITIVE when defender wins."""
        gateway = AsyncMock()
        gateway.complete.return_value = '{"verdict": "FALSE_POSITIVE", "confidence": 0.8, "reasoning": "Defender identified valid sanitization"}'

        defender_response = DefenderResponse(
            safe=True,
            defense_lines=[15],
            reasoning="Parameterized query at line 15",
        )

        agent = JudgeAgent(llm_gateway=gateway)
        result = await agent.analyze(
            sample_finding,
            sample_attacker_response,
            defender_response,
        )

        assert result.response.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_analyze_returns_uncertain(
        self,
        sample_finding: Finding,
        sample_attacker_response: AttackerResponse,
        sample_defender_response: DefenderResponse,
    ):
        """Should return UNCERTAIN when evidence is ambiguous."""
        gateway = AsyncMock()
        gateway.complete.return_value = '{"verdict": "UNCERTAIN", "confidence": 0.5, "reasoning": "Need more context"}'

        agent = JudgeAgent(llm_gateway=gateway)
        result = await agent.analyze(
            sample_finding,
            sample_attacker_response,
            sample_defender_response,
        )

        assert result.response.verdict == Verdict.UNCERTAIN

    @pytest.mark.asyncio
    async def test_analyze_includes_confidence(
        self,
        sample_finding: Finding,
        sample_attacker_response: AttackerResponse,
        sample_defender_response: DefenderResponse,
        mock_llm_gateway: AsyncMock,
    ):
        """Should include confidence score."""
        agent = JudgeAgent(llm_gateway=mock_llm_gateway)
        result = await agent.analyze(
            sample_finding,
            sample_attacker_response,
            sample_defender_response,
        )

        assert result.response.confidence == 0.85

    @pytest.mark.asyncio
    async def test_analyze_handles_llm_error(
        self,
        sample_finding: Finding,
        sample_attacker_response: AttackerResponse,
        sample_defender_response: DefenderResponse,
    ):
        """Should handle LLM errors gracefully."""
        gateway = AsyncMock()
        gateway.complete.side_effect = Exception("LLM unavailable")

        agent = JudgeAgent(llm_gateway=gateway)
        result = await agent.analyze(
            sample_finding,
            sample_attacker_response,
            sample_defender_response,
        )

        assert result.success is False
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_analyze_handles_invalid_response(
        self,
        sample_finding: Finding,
        sample_attacker_response: AttackerResponse,
        sample_defender_response: DefenderResponse,
    ):
        """Should handle invalid LLM response."""
        gateway = AsyncMock()
        gateway.complete.return_value = "not valid json"

        agent = JudgeAgent(llm_gateway=gateway)
        result = await agent.analyze(
            sample_finding,
            sample_attacker_response,
            sample_defender_response,
        )

        # Should still succeed with fallback UNCERTAIN
        assert result.success is True
        assert result.response is not None
        assert result.response.verdict == Verdict.UNCERTAIN


class TestJudgeMissedConsiderations:
    """Test missed considerations extraction."""

    @pytest.mark.asyncio
    async def test_extracts_missed_considerations(
        self,
        sample_finding: Finding,
        sample_attacker_response: AttackerResponse,
        sample_defender_response: DefenderResponse,
    ):
        """Should extract missed considerations for feedback."""
        gateway = AsyncMock()
        gateway.complete.return_value = '{"verdict": "FALSE_POSITIVE", "confidence": 0.8, "reasoning": "test", "missed_considerations": "Sanitizer at line 15 was not in spec"}'

        agent = JudgeAgent(llm_gateway=gateway)
        result = await agent.analyze(
            sample_finding,
            sample_attacker_response,
            sample_defender_response,
        )

        assert result.response.missed_considerations is not None
        assert "Sanitizer" in result.response.missed_considerations


class TestJudgeRetries:
    """Test retry behavior."""

    @pytest.mark.asyncio
    async def test_retries_on_failure(
        self,
        sample_finding: Finding,
        sample_attacker_response: AttackerResponse,
        sample_defender_response: DefenderResponse,
    ):
        """Should retry on transient failures."""
        gateway = AsyncMock()
        gateway.complete.side_effect = [
            Exception("Transient error"),
            '{"verdict": "TRUE_POSITIVE", "confidence": 0.7, "reasoning": "test"}',
        ]

        config = JudgeAgentConfig(max_retries=3)
        agent = JudgeAgent(config=config, llm_gateway=gateway)
        result = await agent.analyze(
            sample_finding,
            sample_attacker_response,
            sample_defender_response,
        )

        assert result.success is True
        assert gateway.complete.call_count == 2

    @pytest.mark.asyncio
    async def test_fails_after_max_retries(
        self,
        sample_finding: Finding,
        sample_attacker_response: AttackerResponse,
        sample_defender_response: DefenderResponse,
    ):
        """Should fail after exhausting retries."""
        gateway = AsyncMock()
        gateway.complete.side_effect = Exception("Persistent error")

        config = JudgeAgentConfig(max_retries=2)
        agent = JudgeAgent(config=config, llm_gateway=gateway)
        result = await agent.analyze(
            sample_finding,
            sample_attacker_response,
            sample_defender_response,
        )

        assert result.success is False
        assert gateway.complete.call_count == 2
