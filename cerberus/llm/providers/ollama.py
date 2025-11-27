"""
Ollama LLM provider.

Provides integration with local Ollama server for LLM inference.
"""

from __future__ import annotations

import asyncio
from typing import Any

import aiohttp

from cerberus.core.config import OllamaConfig
from cerberus.llm.providers.base import LLMProvider
from cerberus.llm.providers.models import LLMRequest, LLMResponse, Message


class OllamaProvider(LLMProvider):
    """Ollama local LLM provider.

    Connects to a local Ollama server for inference using models
    like Qwen, Llama, CodeLlama, etc.
    """

    name = "ollama"

    def __init__(self, config: OllamaConfig) -> None:
        """Initialize the Ollama provider.

        Args:
            config: Ollama configuration with base_url, model, timeout.
        """
        self.base_url = config.base_url.rstrip("/")
        self.default_model = config.model
        self.timeout = config.timeout
        self.context_length = config.context_length

    async def is_available(self) -> bool:
        """Check if Ollama server is running and model is available.

        Returns:
            True if server responds and requested model is installed.
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/api/tags",
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status != 200:
                        return False

                    data = await resp.json()
                    models = data.get("models", [])

                    # Check if our model is available
                    model_base = self.default_model.split(":")[0]
                    for model in models:
                        model_name = model.get("name", "")
                        # Match exact or by base name
                        if model_name == self.default_model:
                            return True
                        if model_name.startswith(model_base):
                            return True

                    return False

        except (aiohttp.ClientError, asyncio.TimeoutError, ConnectionError):
            return False
        except Exception:
            return False

    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Generate completion using Ollama API.

        Args:
            request: LLM request with messages and parameters.

        Returns:
            LLMResponse with generated content.

        Raises:
            ConnectionError: If cannot connect to Ollama server.
            TimeoutError: If request times out.
            Exception: On API errors.
        """
        model = request.model or self.default_model
        messages = self._format_messages(request.messages)

        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": request.temperature,
                "num_predict": request.max_tokens,
            },
        }

        if request.stop:
            payload["options"]["stop"] = request.stop

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/api/chat",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if resp.status != 200:
                        error_text = await resp.text()
                        raise Exception(
                            f"Ollama API error (status {resp.status}): {error_text}"
                        )

                    data = await resp.json()

                    # Extract response content - handle both chat and generate API formats
                    content = ""
                    message = data.get("message", {})
                    if isinstance(message, dict) and message.get("content"):
                        content = message["content"]
                    elif data.get("response"):
                        # Fallback for generate API format
                        content = data["response"]

                    return LLMResponse(
                        content=content,
                        model=data.get("model", model),
                        provider=self.name,
                        input_tokens=data.get("prompt_eval_count", 0),
                        output_tokens=data.get("eval_count", 0),
                        finish_reason="stop",
                        latency_ms=data.get("total_duration", 0) / 1_000_000,
                        raw_response=data,
                    )

        except asyncio.TimeoutError as e:
            raise TimeoutError(f"Ollama request timed out after {self.timeout}s") from e
        except aiohttp.ClientError as e:
            raise ConnectionError(f"Failed to connect to Ollama: {e}") from e

    def _format_messages(self, messages: list[Message]) -> list[dict[str, str]]:
        """Format messages for Ollama chat API.

        Args:
            messages: List of Message objects.

        Returns:
            List of dicts in Ollama message format.
        """
        return [
            {
                "role": msg.role.value,
                "content": msg.content,
            }
            for msg in messages
        ]
