"""
Tests for Multi-Agent Council.

TDD: Write tests first, then implement to make them pass.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cerberus.llm.prompts.verification import (
    AttackerResponse,
    DefenderResponse,
    JudgeResponse,
)
from cerberus.models.base import CodeLocation, Verdict
from cerberus.models.finding import Finding, ProgramSlice, SliceLine, TraceStep, VerificationResult
from cerberus.verification.attacker_agent import AttackerResult
from cerberus.verification.defender_agent import DefenderResult
from cerberus.verification.judge_agent import JudgeResult
from cerberus.verification.council import (
    Council,
    CouncilConfig,
    CouncilResult,
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
    # Attacker response
    gateway.complete.side_effect = [
        '{"exploitable": true, "attack_input": "\\"; DROP TABLE users;--", "reasoning": "SQL injection"}',
        '{"safe": false, "defense_lines": [], "reasoning": "No defenses found"}',
        '{"verdict": "TRUE_POSITIVE", "confidence": 0.9, "reasoning": "Attacker wins"}',
    ]
    return gateway


class TestCouncilConfig:
    """Test CouncilConfig."""

    def test_default_config(self):
        """Should have sensible defaults."""
        config = CouncilConfig()
        assert config.max_iterations >= 1
        assert config.min_confidence >= 0.0

    def test_custom_config(self):
        """Should accept custom values."""
        config = CouncilConfig(
            max_iterations=3,
            min_confidence=0.8,
        )
        assert config.max_iterations == 3
        assert config.min_confidence == 0.8


class TestCouncilResult:
    """Test CouncilResult dataclass."""

    def test_create_result(self):
        """Should create result with required fields."""
        verification = VerificationResult(
            verdict=Verdict.TRUE_POSITIVE,
            confidence=0.9,
            attacker_exploitable=True,
            attacker_input="test",
            attacker_trace=None,
            attacker_impact=None,
            attacker_reasoning="test",
            defender_safe=False,
            defender_lines=[],
            defender_sanitization=None,
            defender_reasoning="test",
            judge_reasoning="test",
        )
        result = CouncilResult(
            success=True,
            verification=verification,
        )
        assert result.success is True
        assert result.verification.verdict == Verdict.TRUE_POSITIVE

    def test_result_with_error(self):
        """Should capture error details."""
        result = CouncilResult(
            success=False,
            verification=None,
            error="Council failed",
        )
        assert result.success is False
        assert result.error is not None


class TestCouncil:
    """Test Council class."""

    def test_create_council(self):
        """Should create council instance."""
        council = Council()
        assert council is not None

    def test_create_with_config(self):
        """Should accept custom configuration."""
        config = CouncilConfig(max_iterations=5)
        council = Council(config=config)
        assert council.config.max_iterations == 5

    def test_create_with_llm_gateway(self):
        """Should accept LLM gateway."""
        gateway = MagicMock()
        council = Council(llm_gateway=gateway)
        assert council.llm_gateway == gateway


class TestCouncilVerification:
    """Test council verification pipeline."""

    @pytest.mark.asyncio
    async def test_verify_finding(
        self,
        sample_finding: Finding,
        mock_llm_gateway: AsyncMock,
    ):
        """Should verify finding through all agents."""
        council = Council(llm_gateway=mock_llm_gateway)
        result = await council.verify(sample_finding)

        assert isinstance(result, CouncilResult)
        assert result.success is True
        assert result.verification is not None

    @pytest.mark.asyncio
    async def test_verify_returns_true_positive(
        self,
        sample_finding: Finding,
        mock_llm_gateway: AsyncMock,
    ):
        """Should return TRUE_POSITIVE when attacker wins."""
        council = Council(llm_gateway=mock_llm_gateway)
        result = await council.verify(sample_finding)

        assert result.verification.verdict == Verdict.TRUE_POSITIVE

    @pytest.mark.asyncio
    async def test_verify_returns_false_positive(
        self,
        sample_finding: Finding,
    ):
        """Should return FALSE_POSITIVE when defender wins."""
        gateway = AsyncMock()
        gateway.complete.side_effect = [
            '{"exploitable": true, "reasoning": "test"}',
            '{"safe": true, "defense_lines": [15], "sanitization": "Parameterized", "reasoning": "test"}',
            '{"verdict": "FALSE_POSITIVE", "confidence": 0.85, "reasoning": "Defender wins"}',
        ]

        council = Council(llm_gateway=gateway)
        result = await council.verify(sample_finding)

        assert result.verification.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_verify_calls_agents_in_order(
        self,
        sample_finding: Finding,
    ):
        """Should call agents in order: Attacker -> Defender -> Judge."""
        call_order = []

        async def track_calls(messages, **kwargs):
            system_content = messages[0]["content"]
            # Use unique role markers from prompts (uppercase)
            if "You are the ATTACKER" in system_content:
                call_order.append("attacker")
                return '{"exploitable": true, "reasoning": "test"}'
            elif "You are the DEFENDER" in system_content:
                call_order.append("defender")
                return '{"safe": false, "defense_lines": [], "reasoning": "test"}'
            elif "You are the JUDGE" in system_content:
                call_order.append("judge")
                return '{"verdict": "TRUE_POSITIVE", "confidence": 0.8, "reasoning": "test"}'
            else:
                call_order.append("unknown")
                return '{}'

        gateway = AsyncMock()
        gateway.complete = track_calls

        council = Council(llm_gateway=gateway)
        await council.verify(sample_finding)

        assert call_order == ["attacker", "defender", "judge"]


class TestCouncilVerificationResult:
    """Test VerificationResult creation from council."""

    @pytest.mark.asyncio
    async def test_verification_has_attacker_fields(
        self,
        sample_finding: Finding,
        mock_llm_gateway: AsyncMock,
    ):
        """Should include attacker fields in result."""
        council = Council(llm_gateway=mock_llm_gateway)
        result = await council.verify(sample_finding)

        assert result.verification.attacker_exploitable is True
        assert result.verification.attacker_reasoning != ""

    @pytest.mark.asyncio
    async def test_verification_has_defender_fields(
        self,
        sample_finding: Finding,
        mock_llm_gateway: AsyncMock,
    ):
        """Should include defender fields in result."""
        council = Council(llm_gateway=mock_llm_gateway)
        result = await council.verify(sample_finding)

        assert result.verification.defender_safe is False
        assert result.verification.defender_reasoning != ""

    @pytest.mark.asyncio
    async def test_verification_has_judge_fields(
        self,
        sample_finding: Finding,
        mock_llm_gateway: AsyncMock,
    ):
        """Should include judge fields in result."""
        council = Council(llm_gateway=mock_llm_gateway)
        result = await council.verify(sample_finding)

        assert result.verification.judge_reasoning != ""
        assert result.verification.confidence > 0


class TestCouncilErrorHandling:
    """Test error handling in council."""

    @pytest.mark.asyncio
    async def test_handles_attacker_failure(
        self,
        sample_finding: Finding,
    ):
        """Should handle attacker agent failure."""
        gateway = AsyncMock()
        gateway.complete.side_effect = Exception("Attacker failed")

        council = Council(llm_gateway=gateway)
        result = await council.verify(sample_finding)

        assert result.success is False
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_handles_defender_failure(
        self,
        sample_finding: Finding,
    ):
        """Should handle defender agent failure."""
        gateway = AsyncMock()
        gateway.complete.side_effect = [
            '{"exploitable": true, "reasoning": "test"}',
            Exception("Defender failed"),
        ]

        council = Council(llm_gateway=gateway)
        result = await council.verify(sample_finding)

        assert result.success is False

    @pytest.mark.asyncio
    async def test_handles_judge_failure(
        self,
        sample_finding: Finding,
    ):
        """Should handle judge agent failure."""
        gateway = AsyncMock()
        gateway.complete.side_effect = [
            '{"exploitable": true, "reasoning": "test"}',
            '{"safe": false, "defense_lines": [], "reasoning": "test"}',
            Exception("Judge failed"),
        ]

        council = Council(llm_gateway=gateway)
        result = await council.verify(sample_finding)

        assert result.success is False


class TestCouncilBatchVerification:
    """Test batch verification of multiple findings."""

    @pytest.mark.asyncio
    async def test_verify_multiple_findings(
        self,
        sample_finding: Finding,
    ):
        """Should verify multiple findings."""
        gateway = AsyncMock()
        # Responses for two findings
        gateway.complete.side_effect = [
            '{"exploitable": true, "reasoning": "test"}',
            '{"safe": false, "defense_lines": [], "reasoning": "test"}',
            '{"verdict": "TRUE_POSITIVE", "confidence": 0.9, "reasoning": "test"}',
            '{"exploitable": false, "reasoning": "test"}',
            '{"safe": true, "defense_lines": [10], "reasoning": "test"}',
            '{"verdict": "FALSE_POSITIVE", "confidence": 0.8, "reasoning": "test"}',
        ]

        council = Council(llm_gateway=gateway)
        findings = [sample_finding, sample_finding]
        results = await council.verify_batch(findings)

        assert len(results) == 2
        assert results[0].verification.verdict == Verdict.TRUE_POSITIVE
        assert results[1].verification.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_batch_handles_individual_failures(
        self,
        sample_finding: Finding,
    ):
        """Should handle failures for individual findings."""
        gateway = AsyncMock()
        gateway.complete.side_effect = [
            '{"exploitable": true, "reasoning": "test"}',
            '{"safe": false, "defense_lines": [], "reasoning": "test"}',
            '{"verdict": "TRUE_POSITIVE", "confidence": 0.9, "reasoning": "test"}',
            Exception("Failed for second finding"),
        ]

        council = Council(llm_gateway=gateway)
        findings = [sample_finding, sample_finding]
        results = await council.verify_batch(findings)

        assert len(results) == 2
        assert results[0].success is True
        assert results[1].success is False
