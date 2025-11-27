"""
Tests for LLM Classification Prompts.

TDD: Write tests first, then implement to make them pass.
"""

import pytest

from cerberus.llm.prompts.classification import (
    ClassificationPrompt,
    ClassificationResponse,
    FewShotExample,
    PromptBuilder,
    SOURCE_EXAMPLES,
    SINK_EXAMPLES,
    SANITIZER_EXAMPLES,
)
from cerberus.models.base import TaintLabel


class TestClassificationResponse:
    """Test ClassificationResponse dataclass."""

    def test_create_response(self):
        """Should create a classification response."""
        response = ClassificationResponse(
            label=TaintLabel.SOURCE,
            confidence=0.95,
            reason="This function reads user input from HTTP request",
            vulnerability_types=["CWE-89", "CWE-79"],
        )
        assert response.label == TaintLabel.SOURCE
        assert response.confidence == 0.95
        assert "HTTP request" in response.reason
        assert "CWE-89" in response.vulnerability_types

    def test_from_json_string(self):
        """Should parse from JSON string."""
        json_str = '''
        {
            "label": "SOURCE",
            "confidence": 0.9,
            "reason": "Reads from user input",
            "vulnerability_types": ["CWE-79"]
        }
        '''
        response = ClassificationResponse.from_json(json_str)
        assert response.label == TaintLabel.SOURCE
        assert response.confidence == 0.9
        assert "user input" in response.reason

    def test_from_json_with_lowercase_label(self):
        """Should handle lowercase labels."""
        json_str = '{"label": "sink", "confidence": 0.8, "reason": "Executes SQL", "vulnerability_types": ["CWE-89"]}'
        response = ClassificationResponse.from_json(json_str)
        assert response.label == TaintLabel.SINK

    def test_from_json_with_none_label(self):
        """Should handle NONE label."""
        json_str = '{"label": "NONE", "confidence": 0.7, "reason": "Just a helper", "vulnerability_types": []}'
        response = ClassificationResponse.from_json(json_str)
        assert response.label == TaintLabel.NONE

    def test_from_json_invalid_returns_none(self):
        """Should return NONE label for invalid JSON."""
        response = ClassificationResponse.from_json("not valid json")
        assert response.label == TaintLabel.NONE
        assert response.confidence < 0.5

    def test_to_dict(self):
        """Should serialize to dictionary."""
        response = ClassificationResponse(
            label=TaintLabel.SANITIZER,
            confidence=0.85,
            reason="Validates and escapes HTML",
            vulnerability_types=["CWE-79"],
        )
        data = response.to_dict()
        assert data["label"] == "sanitizer"
        assert data["confidence"] == 0.85
        assert data["vulnerability_types"] == ["CWE-79"]


class TestFewShotExample:
    """Test FewShotExample dataclass."""

    def test_create_example(self):
        """Should create a few-shot example."""
        example = FewShotExample(
            code="def get_user_input(): return request.args.get('id')",
            language="python",
            label=TaintLabel.SOURCE,
            reason="Reads from HTTP request parameters",
        )
        assert example.code is not None
        assert example.language == "python"
        assert example.label == TaintLabel.SOURCE

    def test_format_for_prompt(self):
        """Should format example for inclusion in prompt."""
        example = FewShotExample(
            code="def execute_query(sql): cursor.execute(sql)",
            language="python",
            label=TaintLabel.SINK,
            reason="Executes SQL query which could allow injection",
            vulnerability_types=["CWE-89"],
        )
        formatted = example.format_for_prompt()
        assert "execute_query" in formatted
        assert "SINK" in formatted
        assert "CWE-89" in formatted


class TestSourceExamples:
    """Test that SOURCE_EXAMPLES are properly defined."""

    def test_source_examples_exist(self):
        """Should have source examples for common patterns."""
        assert len(SOURCE_EXAMPLES) >= 3

    def test_source_examples_have_correct_label(self):
        """All source examples should have SOURCE label."""
        for example in SOURCE_EXAMPLES:
            assert example.label == TaintLabel.SOURCE

    def test_source_examples_cover_web_input(self):
        """Should have examples for web input sources."""
        has_request = any("request" in e.code.lower() for e in SOURCE_EXAMPLES)
        assert has_request, "Missing web request source examples"


class TestSinkExamples:
    """Test that SINK_EXAMPLES are properly defined."""

    def test_sink_examples_exist(self):
        """Should have sink examples for common patterns."""
        assert len(SINK_EXAMPLES) >= 4

    def test_sink_examples_have_correct_label(self):
        """All sink examples should have SINK label."""
        for example in SINK_EXAMPLES:
            assert example.label == TaintLabel.SINK

    def test_sink_examples_cover_sql(self):
        """Should have examples for SQL injection sinks."""
        has_sql = any("CWE-89" in e.vulnerability_types for e in SINK_EXAMPLES)
        assert has_sql, "Missing SQL injection sink examples"

    def test_sink_examples_cover_command(self):
        """Should have examples for command injection sinks."""
        has_cmd = any("CWE-78" in e.vulnerability_types for e in SINK_EXAMPLES)
        assert has_cmd, "Missing command injection sink examples"


class TestSanitizerExamples:
    """Test that SANITIZER_EXAMPLES are properly defined."""

    def test_sanitizer_examples_exist(self):
        """Should have sanitizer examples."""
        assert len(SANITIZER_EXAMPLES) >= 2

    def test_sanitizer_examples_have_correct_label(self):
        """All sanitizer examples should have SANITIZER label."""
        for example in SANITIZER_EXAMPLES:
            assert example.label == TaintLabel.SANITIZER


class TestClassificationPrompt:
    """Test ClassificationPrompt class."""

    def test_create_prompt(self):
        """Should create a classification prompt."""
        prompt = ClassificationPrompt(
            target_label=TaintLabel.SOURCE,
            few_shot_count=3,
        )
        assert prompt.target_label == TaintLabel.SOURCE
        assert prompt.few_shot_count == 3

    def test_default_few_shot_count(self):
        """Should default to 3 few-shot examples."""
        prompt = ClassificationPrompt(target_label=TaintLabel.SINK)
        assert prompt.few_shot_count == 3

    def test_build_system_prompt(self):
        """Should build a system prompt with instructions."""
        prompt = ClassificationPrompt(target_label=TaintLabel.SOURCE)
        system_prompt = prompt.build_system_prompt()

        assert "security analyst" in system_prompt.lower()
        assert "source" in system_prompt.lower()
        assert "json" in system_prompt.lower()

    def test_build_user_prompt(self):
        """Should build user prompt with code to analyze."""
        prompt = ClassificationPrompt(target_label=TaintLabel.SINK)
        code = "def run_query(sql): db.execute(sql)"
        user_prompt = prompt.build_user_prompt(code, language="python")

        assert "run_query" in user_prompt
        assert "python" in user_prompt.lower()

    def test_get_examples_for_source(self):
        """Should get relevant examples for SOURCE classification."""
        prompt = ClassificationPrompt(
            target_label=TaintLabel.SOURCE,
            few_shot_count=2,
        )
        examples = prompt.get_examples()
        assert len(examples) == 2
        # Should include both positive and negative examples
        labels = [e.label for e in examples]
        assert TaintLabel.SOURCE in labels

    def test_get_examples_for_sink(self):
        """Should get relevant examples for SINK classification."""
        prompt = ClassificationPrompt(
            target_label=TaintLabel.SINK,
            few_shot_count=3,
        )
        examples = prompt.get_examples()
        assert len(examples) == 3


class TestPromptBuilder:
    """Test PromptBuilder for assembling complete prompts."""

    def test_build_source_classification_prompt(self):
        """Should build complete prompt for source classification."""
        builder = PromptBuilder()
        prompt = builder.build_classification_prompt(
            code="def get_param(): return request.args.get('id')",
            language="python",
            target_label=TaintLabel.SOURCE,
        )

        assert prompt.system_message is not None
        assert prompt.user_message is not None
        assert "get_param" in prompt.user_message

    def test_build_sink_classification_prompt(self):
        """Should build complete prompt for sink classification."""
        builder = PromptBuilder()
        prompt = builder.build_classification_prompt(
            code="def exec_cmd(cmd): os.system(cmd)",
            language="python",
            target_label=TaintLabel.SINK,
        )

        assert "sink" in prompt.system_message.lower()
        assert "exec_cmd" in prompt.user_message

    def test_build_with_context(self):
        """Should include additional context in prompt."""
        builder = PromptBuilder()
        prompt = builder.build_classification_prompt(
            code="def process(data): return data.strip()",
            language="python",
            target_label=TaintLabel.SANITIZER,
            context={"imports": ["from django.utils.html import escape"]},
        )

        assert "sanitizer" in prompt.system_message.lower()

    def test_build_multi_label_prompt(self):
        """Should build prompt for classifying any taint label."""
        builder = PromptBuilder()
        prompt = builder.build_multi_label_prompt(
            code="def fetch_data(): return db.query('SELECT * FROM users')",
            language="python",
        )

        # Should mention all possible labels
        combined = prompt.system_message + prompt.user_message
        assert "source" in combined.lower()
        assert "sink" in combined.lower()
        assert "sanitizer" in combined.lower()

    def test_response_format_included(self):
        """Should include expected JSON response format."""
        builder = PromptBuilder()
        prompt = builder.build_classification_prompt(
            code="def test(): pass",
            language="python",
            target_label=TaintLabel.SOURCE,
        )

        # Should specify response format
        assert "label" in prompt.system_message
        assert "confidence" in prompt.system_message
        assert "reason" in prompt.system_message


class TestPromptWithChainOfThought:
    """Test Chain-of-Thought reasoning in prompts."""

    def test_cot_instruction_in_system_prompt(self):
        """Should include chain-of-thought instruction."""
        prompt = ClassificationPrompt(target_label=TaintLabel.SINK)
        system_prompt = prompt.build_system_prompt()

        # Should ask for step-by-step reasoning
        assert "step" in system_prompt.lower() or "reason" in system_prompt.lower()

    def test_cot_examples_show_reasoning(self):
        """Few-shot examples should demonstrate reasoning."""
        for example in SOURCE_EXAMPLES[:2]:
            formatted = example.format_for_prompt()
            # Examples should include reasoning
            assert len(example.reason) > 10, "Examples should have detailed reasoning"


class TestLanguageSupport:
    """Test multi-language support in prompts."""

    def test_python_code_formatting(self):
        """Should properly format Python code in prompts."""
        builder = PromptBuilder()
        prompt = builder.build_classification_prompt(
            code="def fetch(): return request.get('/api')",
            language="python",
            target_label=TaintLabel.SOURCE,
        )
        assert "python" in prompt.user_message.lower()

    def test_javascript_code_formatting(self):
        """Should properly format JavaScript code in prompts."""
        builder = PromptBuilder()
        prompt = builder.build_classification_prompt(
            code="function fetch() { return req.query.id; }",
            language="javascript",
            target_label=TaintLabel.SOURCE,
        )
        assert "javascript" in prompt.user_message.lower()

    def test_java_code_formatting(self):
        """Should properly format Java code in prompts."""
        builder = PromptBuilder()
        prompt = builder.build_classification_prompt(
            code="public String getInput() { return request.getParameter(\"id\"); }",
            language="java",
            target_label=TaintLabel.SOURCE,
        )
        assert "java" in prompt.user_message.lower()


class TestBuiltPromptStructure:
    """Test the structure of built prompts."""

    def test_built_prompt_has_system_and_user(self):
        """Built prompt should have system and user messages."""
        builder = PromptBuilder()
        prompt = builder.build_classification_prompt(
            code="def test(): pass",
            language="python",
            target_label=TaintLabel.SOURCE,
        )

        assert hasattr(prompt, "system_message")
        assert hasattr(prompt, "user_message")
        assert len(prompt.system_message) > 100
        assert len(prompt.user_message) > 10

    def test_to_messages_format(self):
        """Should convert to LLM messages format."""
        builder = PromptBuilder()
        prompt = builder.build_classification_prompt(
            code="def test(): pass",
            language="python",
            target_label=TaintLabel.SOURCE,
        )

        messages = prompt.to_messages()
        assert len(messages) >= 2
        # First message should be system
        assert messages[0]["role"] == "system"
        # Last message should be user
        assert messages[-1]["role"] == "user"
