"""
Tests for Verification Prompts.

TDD: Write tests first, then implement to make them pass.
"""

import json
from pathlib import Path

import pytest

from cerberus.llm.prompts.verification import (
    AttackerPrompt,
    AttackerResponse,
    DefenderPrompt,
    DefenderResponse,
    JudgePrompt,
    JudgeResponse,
    VerificationPromptBuilder,
)
from cerberus.models.base import CodeLocation, Verdict
from cerberus.models.finding import Finding, ProgramSlice, SliceLine, TraceStep


@pytest.fixture
def sample_slice() -> ProgramSlice:
    """Create a sample program slice for testing."""
    return ProgramSlice(
        source_location=CodeLocation(Path("/app/handler.py"), 10, 0),
        sink_location=CodeLocation(Path("/app/handler.py"), 25, 0),
        file_path=Path("/app/handler.py"),
        trace_lines=[
            SliceLine(
                line_number=10,
                code="user_input = request.get('query')",
                is_trace=True,
                annotation="SOURCE",
            ),
            SliceLine(
                line_number=15,
                code="processed = user_input.strip()",
                is_trace=True,
            ),
            SliceLine(
                line_number=25,
                code="cursor.execute(processed)",
                is_trace=True,
                annotation="SINK",
            ),
        ],
    )


@pytest.fixture
def sample_finding(sample_slice: ProgramSlice) -> Finding:
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
        slice=sample_slice,
    )


class TestAttackerPrompt:
    """Test AttackerPrompt class."""

    def test_create_prompt(self):
        """Should create attacker prompt instance."""
        prompt = AttackerPrompt()
        assert prompt is not None

    def test_build_system_prompt(self):
        """Should build system prompt for attacker role."""
        prompt = AttackerPrompt()
        system = prompt.build_system_prompt()

        assert "security researcher" in system.lower() or "attacker" in system.lower()
        assert "exploit" in system.lower()

    def test_build_user_prompt(self, sample_finding: Finding):
        """Should build user prompt with finding context."""
        prompt = AttackerPrompt()
        user = prompt.build_user_prompt(sample_finding)

        assert "CWE-89" in user or "SQL" in user
        assert sample_finding.slice.to_prompt_context() in user or "handler.py" in user

    def test_response_format_instruction(self):
        """Should include response format instructions."""
        prompt = AttackerPrompt()
        system = prompt.build_system_prompt()

        assert "JSON" in system or "json" in system
        assert "exploitable" in system.lower()


class TestAttackerResponse:
    """Test AttackerResponse parsing."""

    def test_create_response(self):
        """Should create response with required fields."""
        response = AttackerResponse(
            exploitable=True,
            reasoning="The input flows directly to execute without sanitization.",
        )
        assert response.exploitable is True
        assert "input" in response.reasoning.lower()

    def test_parse_from_json(self):
        """Should parse response from JSON string."""
        json_str = json.dumps({
            "exploitable": True,
            "attack_input": "'; DROP TABLE users; --",
            "attack_trace": "Input flows to execute()",
            "impact": "Full database compromise",
            "reasoning": "Direct SQL injection possible",
        })

        response = AttackerResponse.from_json(json_str)

        assert response.exploitable is True
        assert response.attack_input is not None
        assert "DROP" in response.attack_input

    def test_parse_invalid_json(self):
        """Should handle invalid JSON gracefully."""
        response = AttackerResponse.from_json("not valid json")

        assert response.exploitable is False
        assert response.reasoning != ""

    def test_to_dict(self):
        """Should serialize to dictionary."""
        response = AttackerResponse(
            exploitable=True,
            attack_input="malicious",
            reasoning="test",
        )
        data = response.to_dict()

        assert data["exploitable"] is True
        assert data["attack_input"] == "malicious"


class TestDefenderPrompt:
    """Test DefenderPrompt class."""

    def test_create_prompt(self):
        """Should create defender prompt instance."""
        prompt = DefenderPrompt()
        assert prompt is not None

    def test_build_system_prompt(self):
        """Should build system prompt for defender role."""
        prompt = DefenderPrompt()
        system = prompt.build_system_prompt()

        assert "security engineer" in system.lower() or "defender" in system.lower()
        assert "defense" in system.lower() or "safe" in system.lower()

    def test_build_user_prompt_includes_attacker_result(self, sample_finding: Finding):
        """Should include attacker result in user prompt."""
        prompt = DefenderPrompt()
        attacker_result = AttackerResponse(
            exploitable=True,
            attack_input="'; DROP TABLE users; --",
            reasoning="SQL injection possible",
        )
        user = prompt.build_user_prompt(sample_finding, attacker_result)

        assert "DROP TABLE" in user or "attacker" in user.lower()

    def test_requires_line_number_citations(self):
        """Should require citing specific line numbers."""
        prompt = DefenderPrompt()
        system = prompt.build_system_prompt()

        assert "line" in system.lower()


class TestDefenderResponse:
    """Test DefenderResponse parsing."""

    def test_create_response(self):
        """Should create response with required fields."""
        response = DefenderResponse(
            safe=True,
            defense_lines=[15, 20],
            reasoning="Input is validated at line 15",
        )
        assert response.safe is True
        assert 15 in response.defense_lines

    def test_parse_from_json(self):
        """Should parse response from JSON string."""
        json_str = json.dumps({
            "safe": True,
            "defense_lines": [12, 18],
            "sanitization": "Input is parameterized at line 12",
            "reasoning": "Prepared statements prevent injection",
        })

        response = DefenderResponse.from_json(json_str)

        assert response.safe is True
        assert 12 in response.defense_lines

    def test_parse_invalid_json(self):
        """Should handle invalid JSON gracefully."""
        response = DefenderResponse.from_json("invalid")

        assert response.safe is False
        assert response.defense_lines == []


class TestJudgePrompt:
    """Test JudgePrompt class."""

    def test_create_prompt(self):
        """Should create judge prompt instance."""
        prompt = JudgePrompt()
        assert prompt is not None

    def test_build_system_prompt(self):
        """Should build system prompt for judge role."""
        prompt = JudgePrompt()
        system = prompt.build_system_prompt()

        assert "judge" in system.lower() or "arbiter" in system.lower()
        assert "verdict" in system.lower()

    def test_build_user_prompt_includes_both_arguments(self, sample_finding: Finding):
        """Should include both attacker and defender arguments."""
        prompt = JudgePrompt()
        attacker_result = AttackerResponse(
            exploitable=True,
            reasoning="SQL injection possible",
        )
        defender_result = DefenderResponse(
            safe=True,
            defense_lines=[15],
            reasoning="Input is validated",
        )

        user = prompt.build_user_prompt(sample_finding, attacker_result, defender_result)

        assert "attacker" in user.lower() or "exploit" in user.lower()
        assert "defender" in user.lower() or "safe" in user.lower()

    def test_verdict_options(self):
        """Should specify verdict options in system prompt."""
        prompt = JudgePrompt()
        system = prompt.build_system_prompt()

        assert "TRUE_POSITIVE" in system or "true_positive" in system.lower()
        assert "FALSE_POSITIVE" in system or "false_positive" in system.lower()
        assert "UNCERTAIN" in system or "uncertain" in system.lower()


class TestJudgeResponse:
    """Test JudgeResponse parsing."""

    def test_create_response(self):
        """Should create response with required fields."""
        response = JudgeResponse(
            verdict=Verdict.TRUE_POSITIVE,
            confidence=0.85,
            reasoning="Attacker argument is more convincing",
        )
        assert response.verdict == Verdict.TRUE_POSITIVE
        assert response.confidence == 0.85

    def test_parse_from_json_true_positive(self):
        """Should parse TRUE_POSITIVE verdict."""
        json_str = json.dumps({
            "verdict": "TRUE_POSITIVE",
            "confidence": 0.9,
            "reasoning": "No sanitization observed",
            "missed_considerations": None,
        })

        response = JudgeResponse.from_json(json_str)

        assert response.verdict == Verdict.TRUE_POSITIVE
        assert response.confidence == 0.9

    def test_parse_from_json_false_positive(self):
        """Should parse FALSE_POSITIVE verdict."""
        json_str = json.dumps({
            "verdict": "FALSE_POSITIVE",
            "confidence": 0.8,
            "reasoning": "Input is properly sanitized at line 15",
            "missed_considerations": "Sanitizer at line 15 was not in the original spec",
        })

        response = JudgeResponse.from_json(json_str)

        assert response.verdict == Verdict.FALSE_POSITIVE
        assert response.missed_considerations is not None

    def test_parse_from_json_uncertain(self):
        """Should parse UNCERTAIN verdict."""
        json_str = json.dumps({
            "verdict": "UNCERTAIN",
            "confidence": 0.5,
            "reasoning": "Need more context to determine",
        })

        response = JudgeResponse.from_json(json_str)

        assert response.verdict == Verdict.UNCERTAIN

    def test_parse_invalid_json(self):
        """Should handle invalid JSON gracefully."""
        response = JudgeResponse.from_json("not json")

        assert response.verdict == Verdict.UNCERTAIN
        assert response.confidence < 0.5


class TestVerificationPromptBuilder:
    """Test VerificationPromptBuilder."""

    def test_create_builder(self):
        """Should create builder instance."""
        builder = VerificationPromptBuilder()
        assert builder is not None

    def test_build_attacker_prompt(self, sample_finding: Finding):
        """Should build complete attacker prompt."""
        builder = VerificationPromptBuilder()
        prompt = builder.build_attacker_prompt(sample_finding)

        assert prompt.system_message is not None
        assert prompt.user_message is not None
        assert len(prompt.system_message) > 0

    def test_build_defender_prompt(self, sample_finding: Finding):
        """Should build complete defender prompt."""
        builder = VerificationPromptBuilder()
        attacker_result = AttackerResponse(
            exploitable=True,
            reasoning="test",
        )
        prompt = builder.build_defender_prompt(sample_finding, attacker_result)

        assert prompt.system_message is not None
        assert prompt.user_message is not None

    def test_build_judge_prompt(self, sample_finding: Finding):
        """Should build complete judge prompt."""
        builder = VerificationPromptBuilder()
        attacker_result = AttackerResponse(exploitable=True, reasoning="test")
        defender_result = DefenderResponse(safe=True, defense_lines=[], reasoning="test")

        prompt = builder.build_judge_prompt(sample_finding, attacker_result, defender_result)

        assert prompt.system_message is not None
        assert prompt.user_message is not None

    def test_prompts_have_to_messages(self, sample_finding: Finding):
        """Should convert prompts to message format."""
        builder = VerificationPromptBuilder()
        prompt = builder.build_attacker_prompt(sample_finding)

        messages = prompt.to_messages()

        assert isinstance(messages, list)
        assert len(messages) >= 2
        assert messages[0]["role"] == "system"
        assert messages[-1]["role"] == "user"


class TestResponseParsing:
    """Test edge cases in response parsing."""

    def test_attacker_response_embedded_json(self):
        """Should extract JSON from text with surrounding content."""
        text = 'Here is my analysis:\n{"exploitable": true, "reasoning": "test"}\nEnd of analysis.'
        response = AttackerResponse.from_json(text)
        assert response.exploitable is True

    def test_defender_response_lowercase_keys(self):
        """Should handle lowercase keys."""
        json_str = '{"safe": false, "defense_lines": [], "reasoning": "no defense"}'
        response = DefenderResponse.from_json(json_str)
        assert response.safe is False

    def test_judge_response_lowercase_verdict(self):
        """Should handle lowercase verdict."""
        json_str = '{"verdict": "true_positive", "confidence": 0.7, "reasoning": "test"}'
        response = JudgeResponse.from_json(json_str)
        assert response.verdict == Verdict.TRUE_POSITIVE
