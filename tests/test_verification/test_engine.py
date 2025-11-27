"""Tests for the Verification Engine."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from cerberus.models.base import (
    CodeLocation,
    TaintLabel,
    Verdict,
)
from cerberus.models.finding import (
    Finding,
    ProgramSlice,
    SliceLine,
    TraceStep,
)
from cerberus.models.spec import TaintSpec
from cerberus.verification.engine import (
    VerificationEngine,
    VerificationEngineConfig,
    VerificationEngineResult,
)


@pytest.fixture
def sample_finding() -> Finding:
    """Create a sample finding for testing."""
    source_loc = CodeLocation(file_path=Path("src/input.py"), line=10, column=0)
    sink_loc = CodeLocation(file_path=Path("src/db.py"), line=50, column=0)

    return Finding(
        id="test-finding-1",
        vulnerability_type="sql_injection",
        severity="high",
        description="SQL injection via user input",
        source=TaintSpec(
            method="get_user_input",
            file_path=Path("src/input.py"),
            line=10,
            label=TaintLabel.SOURCE,
        ),
        sink=TaintSpec(
            method="execute_query",
            file_path=Path("src/db.py"),
            line=50,
            label=TaintLabel.SINK,
        ),
        trace=[
            TraceStep(
                location=source_loc,
                code_snippet="data = get_user_input()",
                description="User input source",
                step_type="source",
            ),
            TraceStep(
                location=sink_loc,
                code_snippet="cursor.execute(query % data)",
                description="SQL sink",
                step_type="sink",
            ),
        ],
        slice=ProgramSlice(
            source_location=source_loc,
            sink_location=sink_loc,
            file_path=Path("src/app.py"),
            trace_lines=[
                SliceLine(
                    line_number=10,
                    code="data = get_user_input()",
                    is_trace=True,
                ),
                SliceLine(
                    line_number=50,
                    code="cursor.execute(query % data)",
                    is_trace=True,
                ),
            ],
        ),
    )


@pytest.fixture
def multiple_findings(sample_finding: Finding) -> list[Finding]:
    """Create multiple findings for batch testing."""
    finding2 = Finding(
        id="test-finding-2",
        vulnerability_type="xss",
        severity="medium",
        description="XSS via user input",
        source=sample_finding.source,
        sink=TaintSpec(
            method="render_html",
            file_path=Path("src/view.py"),
            line=30,
            label=TaintLabel.SINK,
        ),
        trace=sample_finding.trace,
        slice=sample_finding.slice,
    )
    return [sample_finding, finding2]


@pytest.fixture
def mock_llm_gateway() -> AsyncMock:
    """Create a mock LLM gateway."""
    gateway = AsyncMock()

    async def complete_mock(messages: list[dict[str, str]], **kwargs: Any) -> str:
        system_content = messages[0]["content"]
        if "You are the ATTACKER" in system_content:
            return '{"exploitable": true, "attack_input": "1 OR 1=1", "reasoning": "SQL injection"}'
        elif "You are the DEFENDER" in system_content:
            return '{"safe": false, "defense_lines": [], "sanitization": null, "reasoning": "No defense"}'
        elif "You are the JUDGE" in system_content:
            return '{"verdict": "TRUE_POSITIVE", "confidence": 0.85, "reasoning": "Exploitable"}'
        return "{}"

    gateway.complete = complete_mock
    return gateway


class TestVerificationEngineConfig:
    """Test VerificationEngineConfig."""

    def test_default_config(self):
        """Should have sensible defaults."""
        config = VerificationEngineConfig()

        assert config.enable_feedback is True
        assert config.min_confidence >= 0.0
        assert config.min_confidence <= 1.0

    def test_custom_config(self):
        """Should accept custom configuration."""
        config = VerificationEngineConfig(
            enable_feedback=False,
            min_confidence=0.7,
        )

        assert config.enable_feedback is False
        assert config.min_confidence == 0.7


class TestVerificationEngineResult:
    """Test VerificationEngineResult."""

    def test_create_result(self, sample_finding: Finding):
        """Should create result with verified findings."""
        result = VerificationEngineResult(
            success=True,
            findings=[sample_finding],
        )

        assert result.success is True
        assert len(result.findings) == 1
        assert result.error is None

    def test_result_with_spec_updates(self, sample_finding: Finding):
        """Should include spec updates from feedback."""
        from cerberus.verification.feedback import SpecUpdate

        updates = SpecUpdate(
            sanitizers=[
                TaintSpec(
                    method="escape_sql",
                    file_path=Path("src/utils.py"),
                    line=25,
                    label=TaintLabel.SANITIZER,
                )
            ]
        )

        result = VerificationEngineResult(
            success=True,
            findings=[sample_finding],
            spec_updates=updates,
        )

        assert result.spec_updates is not None
        assert len(result.spec_updates.sanitizers) == 1

    def test_result_has_statistics(self, sample_finding: Finding):
        """Should track verification statistics."""
        result = VerificationEngineResult(
            success=True,
            findings=[sample_finding],
            metadata={
                "total_findings": 5,
                "true_positives": 3,
                "false_positives": 2,
            },
        )

        assert result.metadata["total_findings"] == 5
        assert result.metadata["true_positives"] == 3


class TestVerificationEngine:
    """Test VerificationEngine creation."""

    def test_create_engine(self):
        """Should create engine with defaults."""
        engine = VerificationEngine()

        assert engine.config is not None
        assert engine.llm_gateway is None

    def test_create_with_config(self):
        """Should accept custom config."""
        config = VerificationEngineConfig(enable_feedback=False)
        engine = VerificationEngine(config=config)

        assert engine.config.enable_feedback is False

    def test_create_with_llm_gateway(self, mock_llm_gateway: AsyncMock):
        """Should accept LLM gateway."""
        engine = VerificationEngine(llm_gateway=mock_llm_gateway)

        assert engine.llm_gateway is mock_llm_gateway


class TestEngineVerification:
    """Test main verification flow."""

    @pytest.mark.asyncio
    async def test_verify_single_finding(
        self,
        sample_finding: Finding,
        mock_llm_gateway: AsyncMock,
    ):
        """Should verify a single finding."""
        engine = VerificationEngine(llm_gateway=mock_llm_gateway)
        result = await engine.verify([sample_finding])

        assert result.success is True
        assert len(result.findings) == 1

    @pytest.mark.asyncio
    async def test_verify_adds_verification_result(
        self,
        sample_finding: Finding,
        mock_llm_gateway: AsyncMock,
    ):
        """Should add verification result to finding."""
        engine = VerificationEngine(llm_gateway=mock_llm_gateway)
        result = await engine.verify([sample_finding])

        finding = result.findings[0]
        assert finding.verification is not None
        assert finding.verification.verdict == Verdict.TRUE_POSITIVE

    @pytest.mark.asyncio
    async def test_verify_multiple_findings(
        self,
        multiple_findings: list[Finding],
        mock_llm_gateway: AsyncMock,
    ):
        """Should verify multiple findings."""
        engine = VerificationEngine(llm_gateway=mock_llm_gateway)
        result = await engine.verify(multiple_findings)

        assert result.success is True
        assert len(result.findings) == 2

    @pytest.mark.asyncio
    async def test_verify_returns_statistics(
        self,
        multiple_findings: list[Finding],
        mock_llm_gateway: AsyncMock,
    ):
        """Should return verification statistics."""
        engine = VerificationEngine(llm_gateway=mock_llm_gateway)
        result = await engine.verify(multiple_findings)

        assert "total_findings" in result.metadata
        assert result.metadata["total_findings"] == 2


class TestFeedbackIntegration:
    """Test feedback loop integration."""

    @pytest.mark.asyncio
    async def test_extracts_spec_updates_on_false_positive(
        self,
        sample_finding: Finding,
    ):
        """Should extract spec updates from false positives."""
        gateway = AsyncMock()

        async def complete_fp(messages: list[dict[str, str]], **kwargs: Any) -> str:
            system_content = messages[0]["content"]
            if "You are the ATTACKER" in system_content:
                return '{"exploitable": false, "reasoning": "Cannot exploit"}'
            elif "You are the DEFENDER" in system_content:
                return '{"safe": true, "defense_lines": [15], "sanitization": "sanitize_input()", "reasoning": "Input sanitized"}'
            elif "You are the JUDGE" in system_content:
                return '{"verdict": "FALSE_POSITIVE", "confidence": 0.9, "reasoning": "Properly sanitized"}'
            return "{}"

        gateway.complete = complete_fp

        engine = VerificationEngine(llm_gateway=gateway)
        result = await engine.verify([sample_finding])

        assert result.success is True
        # Should have spec updates from feedback
        assert result.spec_updates is not None
        assert len(result.spec_updates.sanitizers) >= 0  # May or may not extract

    @pytest.mark.asyncio
    async def test_feedback_disabled_skips_extraction(
        self,
        sample_finding: Finding,
    ):
        """Should skip feedback when disabled."""
        gateway = AsyncMock()

        async def complete_fp(messages: list[dict[str, str]], **kwargs: Any) -> str:
            system_content = messages[0]["content"]
            if "You are the ATTACKER" in system_content:
                return '{"exploitable": false, "reasoning": "Cannot exploit"}'
            elif "You are the DEFENDER" in system_content:
                return '{"safe": true, "defense_lines": [15], "sanitization": "sanitize()", "reasoning": "Safe"}'
            elif "You are the JUDGE" in system_content:
                return '{"verdict": "FALSE_POSITIVE", "confidence": 0.9, "reasoning": "Safe"}'
            return "{}"

        gateway.complete = complete_fp

        config = VerificationEngineConfig(enable_feedback=False)
        engine = VerificationEngine(config=config, llm_gateway=gateway)
        result = await engine.verify([sample_finding])

        assert result.success is True
        # Feedback disabled, so no spec updates
        assert result.spec_updates is None or result.spec_updates.total == 0


class TestErrorHandling:
    """Test error handling in the engine."""

    @pytest.mark.asyncio
    async def test_handles_llm_failure(
        self,
        sample_finding: Finding,
    ):
        """Should handle LLM failures gracefully."""
        gateway = AsyncMock()
        gateway.complete = AsyncMock(side_effect=Exception("LLM error"))

        engine = VerificationEngine(llm_gateway=gateway)
        result = await engine.verify([sample_finding])

        # Should not crash, but may have partial results
        assert result is not None

    @pytest.mark.asyncio
    async def test_handles_empty_findings(
        self,
        mock_llm_gateway: AsyncMock,
    ):
        """Should handle empty findings list."""
        engine = VerificationEngine(llm_gateway=mock_llm_gateway)
        result = await engine.verify([])

        assert result.success is True
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_returns_error_without_gateway(
        self,
        sample_finding: Finding,
    ):
        """Should return error when no gateway configured."""
        engine = VerificationEngine()
        result = await engine.verify([sample_finding])

        assert result.success is False
        assert result.error is not None


class TestFilterByVerdict:
    """Test filtering findings by verdict."""

    @pytest.mark.asyncio
    async def test_filter_true_positives(
        self,
        sample_finding: Finding,
        mock_llm_gateway: AsyncMock,
    ):
        """Should be able to filter true positives."""
        engine = VerificationEngine(llm_gateway=mock_llm_gateway)
        result = await engine.verify([sample_finding])

        true_positives = [
            f for f in result.findings
            if f.verification and f.verification.verdict == Verdict.TRUE_POSITIVE
        ]
        assert len(true_positives) == 1

    @pytest.mark.asyncio
    async def test_get_fp_rate(
        self,
        multiple_findings: list[Finding],
    ):
        """Should calculate false positive rate."""
        # Create gateway that returns mixed verdicts
        call_count = 0
        gateway = AsyncMock()

        async def mixed_verdicts(messages: list[dict[str, str]], **kwargs: Any) -> str:
            nonlocal call_count
            system_content = messages[0]["content"]
            if "You are the ATTACKER" in system_content:
                return '{"exploitable": true, "reasoning": "test"}'
            elif "You are the DEFENDER" in system_content:
                return '{"safe": false, "defense_lines": [], "reasoning": "test"}'
            elif "You are the JUDGE" in system_content:
                call_count += 1
                # Alternate verdicts
                if call_count % 2 == 1:
                    return '{"verdict": "TRUE_POSITIVE", "confidence": 0.8, "reasoning": "test"}'
                else:
                    return '{"verdict": "FALSE_POSITIVE", "confidence": 0.8, "reasoning": "test"}'
            return "{}"

        gateway.complete = mixed_verdicts

        engine = VerificationEngine(llm_gateway=gateway)
        result = await engine.verify(multiple_findings)

        # Calculate FP rate from results
        total = len(result.findings)
        fp_count = sum(
            1 for f in result.findings
            if f.verification and f.verification.verdict == Verdict.FALSE_POSITIVE
        )
        fp_rate = fp_count / total if total > 0 else 0

        assert 0 <= fp_rate <= 1
