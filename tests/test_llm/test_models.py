"""
Tests for LLM request/response data models.

TDD: Write tests first, then implement to make them pass.
"""

import pytest
from cerberus.llm.providers.models import LLMRequest, LLMResponse, Message, Role


class TestRole:
    """Test the Role enum."""

    def test_role_values(self):
        """Role should have system, user, and assistant values."""
        assert Role.SYSTEM.value == "system"
        assert Role.USER.value == "user"
        assert Role.ASSISTANT.value == "assistant"


class TestMessage:
    """Test the Message dataclass."""

    def test_message_creation(self):
        """Messages should have role and content."""
        msg = Message(role=Role.USER, content="Hello")
        assert msg.role == Role.USER
        assert msg.content == "Hello"

    def test_message_system_role(self):
        """Should create system message."""
        msg = Message(role=Role.SYSTEM, content="You are helpful")
        assert msg.role == Role.SYSTEM
        assert msg.content == "You are helpful"

    def test_message_assistant_role(self):
        """Should create assistant message."""
        msg = Message(role=Role.ASSISTANT, content="I can help")
        assert msg.role == Role.ASSISTANT

    def test_message_to_dict(self):
        """Message should serialize to dict."""
        msg = Message(role=Role.USER, content="Hello")
        data = msg.to_dict()
        assert data["role"] == "user"
        assert data["content"] == "Hello"


class TestLLMRequest:
    """Test the LLMRequest dataclass."""

    def test_llm_request_with_defaults(self):
        """LLMRequest should have sensible defaults."""
        request = LLMRequest(messages=[Message(role=Role.USER, content="test")])
        assert request.temperature == 0.0
        assert request.max_tokens == 4096
        assert request.model is None  # Provider decides

    def test_llm_request_custom_values(self):
        """LLMRequest should accept custom values."""
        request = LLMRequest(
            messages=[Message(role=Role.USER, content="test")],
            model="custom-model",
            temperature=0.7,
            max_tokens=1024,
            stop=["END"],
        )
        assert request.model == "custom-model"
        assert request.temperature == 0.7
        assert request.max_tokens == 1024
        assert request.stop == ["END"]

    def test_llm_request_serialization(self):
        """LLMRequest should serialize to dict for API calls."""
        request = LLMRequest(
            messages=[Message(role=Role.USER, content="test")],
            temperature=0.7,
            max_tokens=1024,
        )
        data = request.to_dict()
        assert "messages" in data
        assert len(data["messages"]) == 1
        assert data["messages"][0]["role"] == "user"
        assert data["messages"][0]["content"] == "test"
        assert data["temperature"] == 0.7
        assert data["max_tokens"] == 1024

    def test_llm_request_with_multiple_messages(self):
        """LLMRequest should handle multi-turn conversations."""
        request = LLMRequest(
            messages=[
                Message(role=Role.SYSTEM, content="You are helpful"),
                Message(role=Role.USER, content="Hi"),
                Message(role=Role.ASSISTANT, content="Hello!"),
                Message(role=Role.USER, content="Bye"),
            ]
        )
        assert len(request.messages) == 4
        data = request.to_dict()
        assert len(data["messages"]) == 4


class TestLLMResponse:
    """Test the LLMResponse dataclass."""

    def test_llm_response_creation(self):
        """LLMResponse should store all required fields."""
        response = LLMResponse(
            content="Hello!",
            model="test-model",
            provider="test",
            input_tokens=10,
            output_tokens=5,
            finish_reason="stop",
        )
        assert response.content == "Hello!"
        assert response.model == "test-model"
        assert response.provider == "test"
        assert response.input_tokens == 10
        assert response.output_tokens == 5
        assert response.finish_reason == "stop"

    def test_llm_response_total_tokens(self):
        """LLMResponse should calculate total tokens."""
        response = LLMResponse(
            content="Hello!",
            model="test-model",
            provider="test",
            input_tokens=10,
            output_tokens=5,
            finish_reason="stop",
        )
        assert response.total_tokens == 15

    def test_llm_response_latency(self):
        """LLMResponse should track latency."""
        response = LLMResponse(
            content="Hello!",
            model="test-model",
            provider="test",
            input_tokens=10,
            output_tokens=5,
            finish_reason="stop",
            latency_ms=150.5,
        )
        assert response.latency_ms == 150.5

    def test_llm_response_raw_response(self):
        """LLMResponse should optionally store raw response."""
        raw = {"id": "123", "object": "completion"}
        response = LLMResponse(
            content="Hello!",
            model="test-model",
            provider="test",
            input_tokens=10,
            output_tokens=5,
            finish_reason="stop",
            raw_response=raw,
        )
        assert response.raw_response == raw

    def test_llm_response_from_ollama(self):
        """LLMResponse should parse Ollama format."""
        raw_ollama = {
            "response": "Hello, world!",
            "model": "qwen2.5-coder:7b",
            "eval_count": 10,
            "prompt_eval_count": 5,
            "total_duration": 1500000000,  # nanoseconds
        }
        response = LLMResponse.from_ollama(raw_ollama)
        assert response.content == "Hello, world!"
        assert response.model == "qwen2.5-coder:7b"
        assert response.provider == "ollama"
        assert response.output_tokens == 10
        assert response.input_tokens == 5

    def test_llm_response_from_anthropic(self):
        """LLMResponse should parse Anthropic format."""
        raw_anthropic = {
            "content": [{"type": "text", "text": "Hello!"}],
            "model": "claude-sonnet-4-20250514",
            "usage": {"input_tokens": 10, "output_tokens": 5},
            "stop_reason": "end_turn",
        }
        response = LLMResponse.from_anthropic(raw_anthropic)
        assert response.content == "Hello!"
        assert response.model == "claude-sonnet-4-20250514"
        assert response.provider == "anthropic"
        assert response.input_tokens == 10
        assert response.output_tokens == 5
        assert response.finish_reason == "end_turn"

    def test_llm_response_from_openai(self):
        """LLMResponse should parse OpenAI format."""
        raw_openai = {
            "choices": [
                {
                    "message": {"role": "assistant", "content": "Hello!"},
                    "finish_reason": "stop",
                }
            ],
            "model": "gpt-4-turbo",
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15,
            },
        }
        response = LLMResponse.from_openai(raw_openai)
        assert response.content == "Hello!"
        assert response.model == "gpt-4-turbo"
        assert response.provider == "openai"
        assert response.input_tokens == 10
        assert response.output_tokens == 5
        assert response.finish_reason == "stop"

    def test_llm_response_to_dict(self):
        """LLMResponse should serialize to dict."""
        response = LLMResponse(
            content="Hello!",
            model="test-model",
            provider="test",
            input_tokens=10,
            output_tokens=5,
            finish_reason="stop",
        )
        data = response.to_dict()
        assert data["content"] == "Hello!"
        assert data["model"] == "test-model"
        assert data["provider"] == "test"
        assert data["input_tokens"] == 10
        assert data["output_tokens"] == 5
        assert data["total_tokens"] == 15
        assert data["finish_reason"] == "stop"
