"""
Tests for Feedback Loop.

TDD: Write tests first, then implement to make them pass.
"""

from pathlib import Path

import pytest

from cerberus.models.base import CodeLocation, TaintLabel, Verdict
from cerberus.models.finding import Finding, ProgramSlice, SliceLine, TraceStep, VerificationResult
from cerberus.models.spec import TaintSpec
from cerberus.verification.feedback import (
    FeedbackLoop,
    FeedbackConfig,
    FeedbackResult,
    SpecUpdate,
)


@pytest.fixture
def false_positive_verification() -> VerificationResult:
    """Create a FALSE_POSITIVE verification result."""
    return VerificationResult(
        verdict=Verdict.FALSE_POSITIVE,
        confidence=0.85,
        attacker_exploitable=True,
        attacker_input="'; DROP TABLE--",
        attacker_trace=None,
        attacker_impact="SQL injection",
        attacker_reasoning="Direct injection possible",
        defender_safe=True,
        defender_lines=[15, 20],
        defender_sanitization="Input is sanitized using escape_sql at line 15",
        defender_reasoning="The escape_sql function at line 15 properly escapes all SQL metacharacters",
        judge_reasoning="Defender wins - escape_sql sanitizer blocks the attack",
        missed_considerations="escape_sql was not in the original sanitizer spec",
    )


@pytest.fixture
def sample_finding(false_positive_verification: VerificationResult) -> Finding:
    """Create a sample finding with FALSE_POSITIVE verification."""
    return Finding(
        vulnerability_type="CWE-89",
        title="SQL Injection via user input",
        description="User input flows to SQL query without sanitization",
        trace=[
            TraceStep(
                location=CodeLocation(Path("/app/handler.py"), 10, 0),
                code_snippet="user_input = request.get('query')",
                description="Source",
                step_type="source",
            ),
            TraceStep(
                location=CodeLocation(Path("/app/handler.py"), 15, 0),
                code_snippet="sanitized = escape_sql(user_input)",
                description="Sanitization",
                step_type="propagation",
            ),
            TraceStep(
                location=CodeLocation(Path("/app/handler.py"), 25, 0),
                code_snippet="cursor.execute(sanitized)",
                description="Sink",
                step_type="sink",
            ),
        ],
        slice=ProgramSlice(
            source_location=CodeLocation(Path("/app/handler.py"), 10, 0),
            sink_location=CodeLocation(Path("/app/handler.py"), 25, 0),
            file_path=Path("/app/handler.py"),
            trace_lines=[
                SliceLine(line_number=10, code="user_input = request.get('query')", is_trace=True),
                SliceLine(line_number=15, code="sanitized = escape_sql(user_input)", is_trace=True),
                SliceLine(line_number=25, code="cursor.execute(sanitized)", is_trace=True),
            ],
        ),
        verification=false_positive_verification,
    )


class TestFeedbackConfig:
    """Test FeedbackConfig."""

    def test_default_config(self):
        """Should have sensible defaults."""
        config = FeedbackConfig()
        assert config.min_confidence >= 0.0
        assert config.extract_sanitizers is True

    def test_custom_config(self):
        """Should accept custom values."""
        config = FeedbackConfig(
            min_confidence=0.9,
            extract_sanitizers=False,
        )
        assert config.min_confidence == 0.9
        assert config.extract_sanitizers is False


class TestSpecUpdate:
    """Test SpecUpdate dataclass."""

    def test_create_spec_update(self):
        """Should create spec update with required fields."""
        sanitizer = TaintSpec(
            method="escape_sql",
            file_path=Path("/app/utils.py"),
            line=15,
            label=TaintLabel.SANITIZER,
            confidence=0.8,
        )
        update = SpecUpdate(
            sanitizers=[sanitizer],
            sources=[],
            sinks=[],
        )
        assert len(update.sanitizers) == 1
        assert update.sanitizers[0].method == "escape_sql"

    def test_spec_update_has_total(self):
        """Should report total updates."""
        update = SpecUpdate(
            sanitizers=[
                TaintSpec(method="a", file_path=Path("/a.py"), line=1, label=TaintLabel.SANITIZER),
                TaintSpec(method="b", file_path=Path("/b.py"), line=2, label=TaintLabel.SANITIZER),
            ],
            sources=[],
            sinks=[],
        )
        assert update.total == 2


class TestFeedbackResult:
    """Test FeedbackResult dataclass."""

    def test_create_result(self):
        """Should create result with required fields."""
        update = SpecUpdate(sanitizers=[], sources=[], sinks=[])
        result = FeedbackResult(
            success=True,
            updates=update,
        )
        assert result.success is True

    def test_result_has_update_count(self):
        """Should expose update count."""
        update = SpecUpdate(
            sanitizers=[
                TaintSpec(method="a", file_path=Path("/a.py"), line=1, label=TaintLabel.SANITIZER),
            ],
            sources=[],
            sinks=[],
        )
        result = FeedbackResult(
            success=True,
            updates=update,
        )
        assert result.update_count == 1


class TestFeedbackLoop:
    """Test FeedbackLoop class."""

    def test_create_feedback_loop(self):
        """Should create feedback loop instance."""
        feedback = FeedbackLoop()
        assert feedback is not None

    def test_create_with_config(self):
        """Should accept custom configuration."""
        config = FeedbackConfig(min_confidence=0.9)
        feedback = FeedbackLoop(config=config)
        assert feedback.config.min_confidence == 0.9


class TestSanitizerExtraction:
    """Test sanitizer extraction from FALSE_POSITIVE verdicts."""

    def test_extract_from_false_positive(
        self,
        sample_finding: Finding,
    ):
        """Should extract sanitizers from FALSE_POSITIVE findings."""
        feedback = FeedbackLoop()
        result = feedback.analyze(sample_finding)

        assert result.success is True
        assert len(result.updates.sanitizers) > 0

    def test_extracts_sanitizer_from_defender_lines(
        self,
        sample_finding: Finding,
    ):
        """Should extract sanitizer from defender's cited lines."""
        feedback = FeedbackLoop()
        result = feedback.analyze(sample_finding)

        # Should have found escape_sql at line 15
        sanitizer_lines = [s.line for s in result.updates.sanitizers]
        assert 15 in sanitizer_lines

    def test_extracts_sanitizer_method_name(
        self,
        sample_finding: Finding,
    ):
        """Should extract method name from defender reasoning."""
        feedback = FeedbackLoop()
        result = feedback.analyze(sample_finding)

        # Should have extracted escape_sql
        sanitizer_names = [s.method for s in result.updates.sanitizers]
        assert "escape_sql" in sanitizer_names

    def test_skips_true_positive(self):
        """Should skip TRUE_POSITIVE findings."""
        finding = Finding(
            vulnerability_type="CWE-89",
            verification=VerificationResult(
                verdict=Verdict.TRUE_POSITIVE,
                confidence=0.9,
                attacker_exploitable=True,
                attacker_input=None,
                attacker_trace=None,
                attacker_impact=None,
                attacker_reasoning="test",
                defender_safe=False,
                defender_lines=[],
                defender_sanitization=None,
                defender_reasoning="test",
                judge_reasoning="test",
            ),
        )

        feedback = FeedbackLoop()
        result = feedback.analyze(finding)

        assert result.success is True
        assert result.updates.total == 0

    def test_skips_uncertain_verdict(self):
        """Should skip UNCERTAIN findings."""
        finding = Finding(
            vulnerability_type="CWE-89",
            verification=VerificationResult(
                verdict=Verdict.UNCERTAIN,
                confidence=0.5,
                attacker_exploitable=True,
                attacker_input=None,
                attacker_trace=None,
                attacker_impact=None,
                attacker_reasoning="test",
                defender_safe=False,
                defender_lines=[],
                defender_sanitization=None,
                defender_reasoning="test",
                judge_reasoning="test",
            ),
        )

        feedback = FeedbackLoop()
        result = feedback.analyze(finding)

        assert result.success is True
        assert result.updates.total == 0

    def test_skips_low_confidence(
        self,
        sample_finding: Finding,
    ):
        """Should skip low confidence FALSE_POSITIVE."""
        sample_finding.verification.confidence = 0.3

        config = FeedbackConfig(min_confidence=0.5)
        feedback = FeedbackLoop(config=config)
        result = feedback.analyze(sample_finding)

        assert result.success is True
        assert result.updates.total == 0


class TestMissedConsiderations:
    """Test extraction from missed_considerations field."""

    def test_extracts_from_missed_considerations(
        self,
        sample_finding: Finding,
    ):
        """Should extract info from judge's missed_considerations."""
        feedback = FeedbackLoop()
        result = feedback.analyze(sample_finding)

        # Should extract escape_sql from missed_considerations
        assert result.success is True


class TestBatchAnalysis:
    """Test batch analysis of multiple findings."""

    def test_analyze_batch(
        self,
        sample_finding: Finding,
    ):
        """Should analyze multiple findings."""
        feedback = FeedbackLoop()
        findings = [sample_finding, sample_finding]
        result = feedback.analyze_batch(findings)

        assert result.success is True
        # Should have combined updates from both findings
        assert result.updates.total >= 1

    def test_batch_deduplicates_sanitizers(
        self,
        sample_finding: Finding,
    ):
        """Should deduplicate sanitizers across findings."""
        feedback = FeedbackLoop()
        findings = [sample_finding, sample_finding]
        result = feedback.analyze_batch(findings)

        # Should not have duplicates
        sanitizer_keys = [
            (s.method, s.line) for s in result.updates.sanitizers
        ]
        assert len(sanitizer_keys) == len(set(sanitizer_keys))


class TestUnverifiedFindings:
    """Test handling of unverified findings."""

    def test_skips_unverified_finding(self):
        """Should skip findings without verification."""
        finding = Finding(
            vulnerability_type="CWE-89",
            verification=None,
        )

        feedback = FeedbackLoop()
        result = feedback.analyze(finding)

        assert result.success is True
        assert result.updates.total == 0
