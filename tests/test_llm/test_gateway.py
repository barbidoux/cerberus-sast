"""
Tests for the LLM Gateway with failover and caching.

TDD: Write tests first, then implement to make them pass.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import hashlib

from cerberus.llm.gateway import LLMGateway, ResponseCache
from cerberus.llm.providers.models import LLMRequest, LLMResponse, Message, Role
from cerberus.core.config import LLMConfig, OllamaConfig, AnthropicConfig, OpenAIConfig


class TestResponseCache:
    """Test the response cache."""

    @pytest.fixture
    def cache(self):
        return ResponseCache(ttl=3600)

    def test_cache_miss_returns_none(self, cache):
        """Should return None on cache miss."""
        result = cache.get("prompt", "model")
        assert result is None

    def test_cache_hit_returns_response(self, cache):
        """Should return response on cache hit."""
        response = LLMResponse(
            content="cached",
            model="test",
            provider="test",
            input_tokens=1,
            output_tokens=1,
            finish_reason="stop",
        )
        cache.set("prompt", "model", response)
        result = cache.get("prompt", "model")
        assert result is not None
        assert result.content == "cached"

    def test_cache_key_includes_model(self, cache):
        """Different models should have different cache keys."""
        response1 = LLMResponse(
            content="model1",
            model="model1",
            provider="test",
            input_tokens=1,
            output_tokens=1,
            finish_reason="stop",
        )
        response2 = LLMResponse(
            content="model2",
            model="model2",
            provider="test",
            input_tokens=1,
            output_tokens=1,
            finish_reason="stop",
        )
        cache.set("prompt", "model1", response1)
        cache.set("prompt", "model2", response2)

        result1 = cache.get("prompt", "model1")
        result2 = cache.get("prompt", "model2")

        assert result1.content == "model1"
        assert result2.content == "model2"

    def test_clear_removes_all_entries(self, cache):
        """Should remove all entries on clear."""
        response = LLMResponse(
            content="cached",
            model="test",
            provider="test",
            input_tokens=1,
            output_tokens=1,
            finish_reason="stop",
        )
        cache.set("prompt1", "model", response)
        cache.set("prompt2", "model", response)

        cache.clear()

        assert cache.get("prompt1", "model") is None
        assert cache.get("prompt2", "model") is None


class TestLLMGatewayInit:
    """Test LLM Gateway initialization."""

    @pytest.fixture
    def config(self):
        return LLMConfig(
            default_provider="ollama",
            cache_enabled=True,
            cache_ttl=3600,
            retry_max_attempts=3,
            retry_backoff_factor=2.0,
        )

    def test_creates_with_config(self, config):
        """Should initialize with LLMConfig."""
        gateway = LLMGateway(config)
        assert gateway.config == config
        assert len(gateway.providers) == 3  # Ollama, Anthropic, OpenAI

    def test_creates_cache_when_enabled(self, config):
        """Should create cache when enabled."""
        gateway = LLMGateway(config)
        assert gateway.cache is not None

    def test_no_cache_when_disabled(self):
        """Should not create cache when disabled."""
        config = LLMConfig(cache_enabled=False)
        gateway = LLMGateway(config)
        assert gateway.cache is None

    def test_initializes_usage_tracking(self, config):
        """Should initialize usage tracking."""
        gateway = LLMGateway(config)
        usage = gateway.get_usage_stats()
        assert isinstance(usage, dict)


class TestLLMGatewayProviderSelection:
    """Test provider selection and failover."""

    @pytest.fixture
    def config(self):
        return LLMConfig(
            default_provider="ollama",
            cache_enabled=False,
        )

    @pytest.fixture
    def gateway(self, config):
        gateway = LLMGateway(config)
        # Replace providers with mocks
        gateway.providers = [
            MagicMock(name="ollama"),
            MagicMock(name="anthropic"),
            MagicMock(name="openai"),
        ]
        for p in gateway.providers:
            p.name = p._mock_name
        return gateway

    @pytest.mark.asyncio
    async def test_uses_first_available_provider(self, gateway):
        """Should use first provider that is available."""
        gateway.providers[0].is_available = AsyncMock(return_value=True)
        gateway.providers[0].complete = AsyncMock(
            return_value=LLMResponse(
                content="from ollama",
                model="test",
                provider="ollama",
                input_tokens=1,
                output_tokens=1,
                finish_reason="stop",
            )
        )

        request = LLMRequest(messages=[Message(role=Role.USER, content="test")])
        response = await gateway.complete(request)

        assert response.content == "from ollama"
        assert response.provider == "ollama"

    @pytest.mark.asyncio
    async def test_failover_to_next_provider(self, gateway):
        """Should try next provider when first fails."""
        # First provider fails
        gateway.providers[0].is_available = AsyncMock(return_value=True)
        gateway.providers[0].complete = AsyncMock(side_effect=Exception("fail"))

        # Second provider succeeds
        gateway.providers[1].is_available = AsyncMock(return_value=True)
        gateway.providers[1].complete = AsyncMock(
            return_value=LLMResponse(
                content="from anthropic",
                model="test",
                provider="anthropic",
                input_tokens=1,
                output_tokens=1,
                finish_reason="stop",
            )
        )

        request = LLMRequest(messages=[Message(role=Role.USER, content="test")])
        response = await gateway.complete(request)

        assert response.provider == "anthropic"

    @pytest.mark.asyncio
    async def test_skips_unavailable_providers(self, gateway):
        """Should skip providers that report unavailable."""
        gateway.providers[0].is_available = AsyncMock(return_value=False)
        gateway.providers[1].is_available = AsyncMock(return_value=True)
        gateway.providers[1].complete = AsyncMock(
            return_value=LLMResponse(
                content="ok",
                model="test",
                provider="anthropic",
                input_tokens=1,
                output_tokens=1,
                finish_reason="stop",
            )
        )

        request = LLMRequest(messages=[Message(role=Role.USER, content="test")])
        response = await gateway.complete(request)

        gateway.providers[0].complete.assert_not_called()
        assert response.provider == "anthropic"

    @pytest.mark.asyncio
    async def test_raises_when_all_providers_fail(self, gateway):
        """Should raise when all providers fail."""
        for provider in gateway.providers:
            provider.is_available = AsyncMock(return_value=True)
            provider.complete = AsyncMock(side_effect=Exception("fail"))

        request = LLMRequest(messages=[Message(role=Role.USER, content="test")])
        with pytest.raises(Exception, match="All LLM providers failed"):
            await gateway.complete(request)

    @pytest.mark.asyncio
    async def test_raises_when_no_providers_available(self, gateway):
        """Should raise when no providers are available."""
        for provider in gateway.providers:
            provider.is_available = AsyncMock(return_value=False)

        request = LLMRequest(messages=[Message(role=Role.USER, content="test")])
        with pytest.raises(Exception):
            await gateway.complete(request)


class TestLLMGatewayCaching:
    """Test response caching."""

    @pytest.fixture
    def config(self):
        return LLMConfig(
            default_provider="ollama",
            cache_enabled=True,
            cache_ttl=3600,
        )

    @pytest.fixture
    def gateway(self, config):
        gateway = LLMGateway(config)
        # Replace provider with mock
        mock_provider = MagicMock(name="ollama")
        mock_provider.name = "ollama"
        mock_provider.is_available = AsyncMock(return_value=True)
        gateway.providers = [mock_provider]
        return gateway

    @pytest.mark.asyncio
    async def test_cache_hit_returns_cached_response(self, gateway):
        """Should return cached response on cache hit."""
        call_count = 0

        async def mock_complete(req):
            nonlocal call_count
            call_count += 1
            return LLMResponse(
                content=f"response-{call_count}",
                model="test",
                provider="ollama",
                input_tokens=1,
                output_tokens=1,
                finish_reason="stop",
            )

        gateway.providers[0].complete = mock_complete

        request = LLMRequest(messages=[Message(role=Role.USER, content="test")])

        # First call - cache miss
        response1 = await gateway.complete(request)
        assert response1.content == "response-1"

        # Second call - should be cached
        response2 = await gateway.complete(request)
        assert response2.content == "response-1"  # Same as first
        assert call_count == 1  # Provider called only once

    @pytest.mark.asyncio
    async def test_cache_bypass_with_flag(self, gateway):
        """Should bypass cache when use_cache=False."""
        call_count = 0

        async def mock_complete(req):
            nonlocal call_count
            call_count += 1
            return LLMResponse(
                content=f"response-{call_count}",
                model="test",
                provider="ollama",
                input_tokens=1,
                output_tokens=1,
                finish_reason="stop",
            )

        gateway.providers[0].complete = mock_complete

        request = LLMRequest(messages=[Message(role=Role.USER, content="test")])

        response1 = await gateway.complete(request)
        response2 = await gateway.complete(request, use_cache=False)

        assert response1.content == "response-1"
        assert response2.content == "response-2"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_different_prompts_not_cached_together(self, gateway):
        """Different prompts should have separate cache entries."""
        call_count = 0

        async def mock_complete(req):
            nonlocal call_count
            call_count += 1
            return LLMResponse(
                content=f"response-{call_count}",
                model="test",
                provider="ollama",
                input_tokens=1,
                output_tokens=1,
                finish_reason="stop",
            )

        gateway.providers[0].complete = mock_complete

        request1 = LLMRequest(messages=[Message(role=Role.USER, content="test1")])
        request2 = LLMRequest(messages=[Message(role=Role.USER, content="test2")])

        response1 = await gateway.complete(request1)
        response2 = await gateway.complete(request2)

        assert response1.content == "response-1"
        assert response2.content == "response-2"
        assert call_count == 2


class TestLLMGatewayUsageTracking:
    """Test usage statistics tracking."""

    @pytest.fixture
    def config(self):
        return LLMConfig(cache_enabled=False)

    @pytest.fixture
    def gateway(self, config):
        gateway = LLMGateway(config)
        mock_provider = MagicMock(name="ollama")
        mock_provider.name = "ollama"
        mock_provider.is_available = AsyncMock(return_value=True)
        gateway.providers = [mock_provider]
        return gateway

    @pytest.mark.asyncio
    async def test_tracks_token_usage(self, gateway):
        """Should track token usage by provider."""
        gateway.providers[0].complete = AsyncMock(
            return_value=LLMResponse(
                content="test",
                model="test",
                provider="ollama",
                input_tokens=100,
                output_tokens=50,
                finish_reason="stop",
            )
        )

        request = LLMRequest(messages=[Message(role=Role.USER, content="test")])
        await gateway.complete(request, use_cache=False)
        await gateway.complete(request, use_cache=False)

        usage = gateway.get_usage_stats()
        assert "ollama" in usage
        assert usage["ollama"]["total_tokens"] == 300
        assert usage["ollama"]["request_count"] == 2

    @pytest.mark.asyncio
    async def test_tracks_usage_per_provider(self, gateway):
        """Should track usage separately per provider."""
        # First provider fails, second succeeds
        mock_provider2 = MagicMock(name="anthropic")
        mock_provider2.name = "anthropic"
        mock_provider2.is_available = AsyncMock(return_value=True)
        mock_provider2.complete = AsyncMock(
            return_value=LLMResponse(
                content="test",
                model="test",
                provider="anthropic",
                input_tokens=50,
                output_tokens=25,
                finish_reason="stop",
            )
        )
        gateway.providers.append(mock_provider2)

        gateway.providers[0].is_available = AsyncMock(return_value=False)

        request = LLMRequest(messages=[Message(role=Role.USER, content="test")])
        await gateway.complete(request, use_cache=False)

        usage = gateway.get_usage_stats()
        assert "anthropic" in usage
        assert usage["anthropic"]["total_tokens"] == 75


class TestLLMGatewayClassify:
    """Test classification helper."""

    @pytest.fixture
    def config(self):
        return LLMConfig(cache_enabled=False)

    @pytest.fixture
    def gateway(self, config):
        gateway = LLMGateway(config)
        mock_provider = MagicMock(name="ollama")
        mock_provider.name = "ollama"
        mock_provider.is_available = AsyncMock(return_value=True)
        gateway.providers = [mock_provider]
        return gateway

    @pytest.mark.asyncio
    async def test_classify_extracts_option(self, gateway):
        """Should extract classification from response."""
        gateway.providers[0].complete = AsyncMock(
            return_value=LLMResponse(
                content="Based on analysis, this is a SOURCE",
                model="test",
                provider="ollama",
                input_tokens=10,
                output_tokens=5,
                finish_reason="stop",
            )
        )

        result = await gateway.classify(
            "Is this a source or sink?",
            options=["SOURCE", "SINK", "SANITIZER"],
        )

        assert result.label == "SOURCE"

    @pytest.mark.asyncio
    async def test_classify_case_insensitive(self, gateway):
        """Should match options case-insensitively."""
        gateway.providers[0].complete = AsyncMock(
            return_value=LLMResponse(
                content="This is clearly a sink function",
                model="test",
                provider="ollama",
                input_tokens=10,
                output_tokens=5,
                finish_reason="stop",
            )
        )

        result = await gateway.classify(
            "Classify this function",
            options=["SOURCE", "SINK"],
        )

        assert result.label == "SINK"
