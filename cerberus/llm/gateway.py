"""
LLM Gateway with provider failover, caching, and usage tracking.

Provides a unified interface to multiple LLM providers with automatic
failover when providers fail.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from cerberus.core.config import LLMConfig
from cerberus.llm.providers.anthropic import AnthropicProvider
from cerberus.llm.providers.base import LLMProvider
from cerberus.llm.providers.models import LLMRequest, LLMResponse, Message, Role
from cerberus.llm.providers.ollama import OllamaProvider
from cerberus.llm.providers.openai import OpenAIProvider


@dataclass
class Classification:
    """Result from classify() method."""

    label: str
    confidence: float = 0.8
    reasoning: str = ""


class ResponseCache:
    """Simple in-memory cache for LLM responses."""

    def __init__(self, ttl: int = 3600) -> None:
        """Initialize cache with TTL in seconds."""
        self.ttl = ttl
        self._cache: dict[str, tuple[LLMResponse, datetime]] = {}

    def _hash_key(self, prompt: str, model: str) -> str:
        """Generate cache key from prompt and model."""
        key_str = f"{model}:{prompt}"
        return hashlib.sha256(key_str.encode()).hexdigest()

    def get(self, prompt: str, model: str) -> Optional[LLMResponse]:
        """Get cached response if exists and not expired."""
        key = self._hash_key(prompt, model)
        if key in self._cache:
            response, timestamp = self._cache[key]
            if datetime.now(timezone.utc) - timestamp < timedelta(seconds=self.ttl):
                return response
            # Expired, remove from cache
            del self._cache[key]
        return None

    def set(self, prompt: str, model: str, response: LLMResponse) -> None:
        """Cache a response."""
        key = self._hash_key(prompt, model)
        self._cache[key] = (response, datetime.now(timezone.utc))

    def clear(self) -> None:
        """Clear all cached entries."""
        self._cache.clear()


@dataclass
class ProviderUsage:
    """Usage statistics for a provider."""

    total_tokens: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    request_count: int = 0


class LLMGateway:
    """Unified LLM interface with provider failover, caching, and usage tracking.

    Manages multiple LLM providers and automatically fails over to the next
    provider if one fails. Also provides response caching and usage tracking.
    """

    def __init__(self, config: LLMConfig) -> None:
        """Initialize the gateway with configuration.

        Args:
            config: LLM configuration specifying providers and settings.
        """
        self.config = config

        # Initialize providers in priority order
        self.providers: list[LLMProvider] = [
            OllamaProvider(config.ollama),
            AnthropicProvider(config.anthropic),
            OpenAIProvider(config.openai),
        ]

        # Initialize cache if enabled
        self.cache: Optional[ResponseCache] = None
        if config.cache_enabled:
            self.cache = ResponseCache(ttl=config.cache_ttl)

        # Usage tracking per provider
        self._usage: dict[str, ProviderUsage] = {}

    async def complete(
        self,
        request: LLMRequest,
        use_cache: bool = True,
    ) -> LLMResponse:
        """Generate completion with automatic failover.

        Tries providers in order until one succeeds. Results are cached
        by default.

        Args:
            request: The LLM request.
            use_cache: Whether to use/store cached responses.

        Returns:
            LLMResponse from the first successful provider.

        Raises:
            Exception: If all providers fail.
        """
        # Generate cache key from request
        cache_key = self._get_cache_key(request)
        model = request.model or "default"

        # Check cache
        if use_cache and self.cache:
            cached = self.cache.get(cache_key, model)
            if cached:
                return cached

        # Try providers in order
        last_exception: Optional[Exception] = None
        for provider in self.providers:
            if not await provider.is_available():
                continue

            try:
                response = await provider.complete(request)

                # Cache successful response
                if use_cache and self.cache:
                    self.cache.set(cache_key, model, response)

                # Track usage
                self._track_usage(provider.name, response)

                return response

            except Exception as e:
                last_exception = e
                continue

        # All providers failed
        if last_exception:
            raise Exception(f"All LLM providers failed. Last error: {last_exception}")
        else:
            raise Exception("No LLM providers available")

    async def classify(
        self,
        prompt: str,
        options: list[str],
        model: Optional[str] = None,
    ) -> Classification:
        """Classify input into one of the predefined options.

        Args:
            prompt: The classification prompt.
            options: List of possible classification labels.
            model: Optional model override.

        Returns:
            Classification with extracted label.
        """
        # Build classification prompt
        options_str = ", ".join(options)
        full_prompt = (
            f"{prompt}\n\n"
            f"Respond with one of: {options_str}\n"
            f"Your classification:"
        )

        request = LLMRequest(
            messages=[Message(role=Role.USER, content=full_prompt)],
            model=model,
            temperature=0.0,
        )

        response = await self.complete(request)

        # Extract label from response
        content = response.content.upper()
        for option in options:
            if option.upper() in content:
                return Classification(
                    label=option,
                    confidence=0.8,
                    reasoning=response.content,
                )

        # Default to first option if none found
        return Classification(
            label=options[0],
            confidence=0.5,
            reasoning=f"Could not parse response: {response.content}",
        )

    def get_usage_stats(self) -> dict[str, dict[str, int]]:
        """Get usage statistics by provider.

        Returns:
            Dict mapping provider name to usage stats.
        """
        return {
            name: {
                "total_tokens": usage.total_tokens,
                "input_tokens": usage.input_tokens,
                "output_tokens": usage.output_tokens,
                "request_count": usage.request_count,
            }
            for name, usage in self._usage.items()
        }

    def clear_cache(self) -> None:
        """Clear the response cache."""
        if self.cache:
            self.cache.clear()

    def _get_cache_key(self, request: LLMRequest) -> str:
        """Generate cache key from request."""
        # Serialize messages to string
        messages_str = "|".join(
            f"{m.role.value}:{m.content}" for m in request.messages
        )
        return messages_str

    def _track_usage(self, provider_name: str, response: LLMResponse) -> None:
        """Track token usage for a provider."""
        if provider_name not in self._usage:
            self._usage[provider_name] = ProviderUsage()

        usage = self._usage[provider_name]
        usage.input_tokens += response.input_tokens
        usage.output_tokens += response.output_tokens
        usage.total_tokens += response.total_tokens
        usage.request_count += 1
