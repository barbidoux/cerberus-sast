"""
OpenAI GPT LLM provider.

Provides integration with OpenAI's GPT API.
"""

from __future__ import annotations

from typing import Any, Optional

import openai

from cerberus.core.config import OpenAIConfig
from cerberus.llm.providers.base import LLMProvider
from cerberus.llm.providers.models import LLMRequest, LLMResponse, Message


class OpenAIProvider(LLMProvider):
    """OpenAI GPT API provider.

    Uses the OpenAI Python SDK for communication with GPT models.
    """

    name = "openai"

    def __init__(self, config: OpenAIConfig) -> None:
        """Initialize the OpenAI provider.

        Args:
            config: OpenAI configuration with api_key, model, timeout.
        """
        self.api_key = config.api_key
        self.default_model = config.model
        self.timeout = config.timeout
        self.max_tokens = config.max_tokens

        # Initialize client if API key is provided
        self._client: Optional[openai.AsyncOpenAI] = None
        if self.api_key:
            self._client = openai.AsyncOpenAI(
                api_key=self.api_key,
                timeout=self.timeout,
            )

    async def is_available(self) -> bool:
        """Check if OpenAI API is available.

        Returns:
            True if API key is configured, False otherwise.
        """
        return bool(self.api_key) and self._client is not None

    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Generate completion using OpenAI API.

        Args:
            request: LLM request with messages and parameters.

        Returns:
            LLMResponse with generated content.

        Raises:
            Exception: If client not configured or API error occurs.
        """
        if self._client is None:
            raise Exception("OpenAI client not configured - missing API key")

        model = request.model or self.default_model
        messages = self._format_messages(request.messages)

        kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": request.max_tokens or self.max_tokens,
            "messages": messages,
        }

        if request.temperature is not None:
            kwargs["temperature"] = request.temperature

        if request.stop:
            kwargs["stop"] = request.stop

        response = await self._client.chat.completions.create(**kwargs)

        # Extract content from response
        content = ""
        finish_reason = "unknown"
        if response.choices:
            choice = response.choices[0]
            content = choice.message.content or ""
            finish_reason = choice.finish_reason or "unknown"

        return LLMResponse(
            content=content,
            model=response.model,
            provider=self.name,
            input_tokens=response.usage.prompt_tokens,
            output_tokens=response.usage.completion_tokens,
            finish_reason=finish_reason,
            raw_response=None,  # Don't store raw OpenAI objects
        )

    def _format_messages(self, messages: list[Message]) -> list[dict[str, str]]:
        """Format messages for OpenAI chat API.

        OpenAI chat API accepts system messages in the messages array.

        Args:
            messages: List of Message objects.

        Returns:
            List of dicts in OpenAI message format.
        """
        return [
            {
                "role": msg.role.value,
                "content": msg.content,
            }
            for msg in messages
        ]
