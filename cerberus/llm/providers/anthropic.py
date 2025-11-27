"""
Anthropic Claude LLM provider.

Provides integration with Anthropic's Claude API.
"""

from __future__ import annotations

from typing import Any, Optional

import anthropic

from cerberus.core.config import AnthropicConfig
from cerberus.llm.providers.base import LLMProvider
from cerberus.llm.providers.models import LLMRequest, LLMResponse, Message, Role


class AnthropicProvider(LLMProvider):
    """Anthropic Claude API provider.

    Uses the Anthropic Python SDK for communication with Claude models.
    """

    name = "anthropic"

    def __init__(self, config: AnthropicConfig) -> None:
        """Initialize the Anthropic provider.

        Args:
            config: Anthropic configuration with api_key, model, timeout.
        """
        self.api_key = config.api_key
        self.default_model = config.model
        self.timeout = config.timeout
        self.max_tokens = config.max_tokens

        # Initialize client if API key is provided
        self._client: Optional[anthropic.AsyncAnthropic] = None
        if self.api_key:
            self._client = anthropic.AsyncAnthropic(
                api_key=self.api_key,
                timeout=self.timeout,
            )

    async def is_available(self) -> bool:
        """Check if Anthropic API is available.

        Returns:
            True if API key is configured, False otherwise.
        """
        return bool(self.api_key) and self._client is not None

    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Generate completion using Anthropic API.

        Args:
            request: LLM request with messages and parameters.

        Returns:
            LLMResponse with generated content.

        Raises:
            Exception: If client not configured or API error occurs.
        """
        if self._client is None:
            raise Exception("Anthropic client not configured - missing API key")

        model = request.model or self.default_model
        messages, system = self._format_messages(request.messages)

        kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": request.max_tokens or self.max_tokens,
            "messages": messages,
        }

        if system:
            kwargs["system"] = system

        if request.temperature is not None:
            kwargs["temperature"] = request.temperature

        if request.stop:
            kwargs["stop_sequences"] = request.stop

        response = await self._client.messages.create(**kwargs)

        # Extract content from response
        content = ""
        if response.content:
            content = response.content[0].text

        return LLMResponse(
            content=content,
            model=response.model,
            provider=self.name,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            finish_reason=response.stop_reason or "unknown",
            raw_response=None,  # Don't store raw Anthropic objects
        )

    def _format_messages(
        self, messages: list[Message]
    ) -> tuple[list[dict[str, str]], Optional[str]]:
        """Format messages for Anthropic API.

        Anthropic API requires system message to be passed separately.

        Args:
            messages: List of Message objects.

        Returns:
            Tuple of (formatted messages, system message or None).
        """
        system: Optional[str] = None
        formatted: list[dict[str, str]] = []

        for msg in messages:
            if msg.role == Role.SYSTEM:
                system = msg.content
            else:
                formatted.append(
                    {
                        "role": msg.role.value,
                        "content": msg.content,
                    }
                )

        return formatted, system
