"""
LLM request/response data models.

Provides unified data structures for interacting with different LLM providers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Role(Enum):
    """Message roles for chat-based LLM interactions."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


@dataclass
class Message:
    """A single message in a conversation."""

    role: Role
    content: str

    def to_dict(self) -> dict[str, str]:
        """Serialize to dict for API calls."""
        return {
            "role": self.role.value,
            "content": self.content,
        }


@dataclass
class LLMRequest:
    """Request to an LLM provider."""

    messages: list[Message]
    model: Optional[str] = None
    temperature: float = 0.0
    max_tokens: int = 4096
    stop: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for API calls."""
        return {
            "messages": [m.to_dict() for m in self.messages],
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "stop": self.stop,
        }


@dataclass
class LLMResponse:
    """Response from an LLM provider."""

    content: str
    model: str
    provider: str
    input_tokens: int
    output_tokens: int
    finish_reason: str
    latency_ms: float = 0.0
    raw_response: Optional[dict[str, Any]] = None

    @property
    def total_tokens(self) -> int:
        """Get total tokens used (input + output)."""
        return self.input_tokens + self.output_tokens

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "content": self.content,
            "model": self.model,
            "provider": self.provider,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "finish_reason": self.finish_reason,
            "latency_ms": self.latency_ms,
        }

    @classmethod
    def from_ollama(cls, raw: dict[str, Any]) -> LLMResponse:
        """Parse response from Ollama API format."""
        return cls(
            content=raw.get("response", ""),
            model=raw.get("model", "unknown"),
            provider="ollama",
            input_tokens=raw.get("prompt_eval_count", 0),
            output_tokens=raw.get("eval_count", 0),
            finish_reason="stop",
            latency_ms=raw.get("total_duration", 0) / 1_000_000,  # ns to ms
            raw_response=raw,
        )

    @classmethod
    def from_anthropic(cls, raw: dict[str, Any]) -> LLMResponse:
        """Parse response from Anthropic API format."""
        content = ""
        if raw.get("content"):
            for block in raw["content"]:
                if block.get("type") == "text":
                    content = block.get("text", "")
                    break

        usage = raw.get("usage", {})
        return cls(
            content=content,
            model=raw.get("model", "unknown"),
            provider="anthropic",
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            finish_reason=raw.get("stop_reason", "unknown"),
            raw_response=raw,
        )

    @classmethod
    def from_openai(cls, raw: dict[str, Any]) -> LLMResponse:
        """Parse response from OpenAI API format."""
        content = ""
        finish_reason = "unknown"

        choices = raw.get("choices", [])
        if choices:
            choice = choices[0]
            message = choice.get("message", {})
            content = message.get("content", "")
            finish_reason = choice.get("finish_reason", "unknown")

        usage = raw.get("usage", {})
        return cls(
            content=content,
            model=raw.get("model", "unknown"),
            provider="openai",
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            finish_reason=finish_reason,
            raw_response=raw,
        )
