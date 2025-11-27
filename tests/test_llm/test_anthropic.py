"""
Tests for the Anthropic Claude provider.

TDD: Write tests first, then implement to make them pass.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from cerberus.llm.providers.anthropic import AnthropicProvider
from cerberus.llm.providers.models import LLMRequest, LLMResponse, Message, Role
from cerberus.llm.providers.base import LLMProvider
from cerberus.core.config import AnthropicConfig


class TestAnthropicProviderInit:
    """Test Anthropic provider initialization."""

    def test_creates_with_config(self):
        """Should initialize with AnthropicConfig."""
        config = AnthropicConfig(
            api_key="test-key",
            model="claude-sonnet-4-20250514",
            timeout=60,
            max_tokens=4096,
        )
        provider = AnthropicProvider(config)
        assert provider.api_key == "test-key"
        assert provider.default_model == "claude-sonnet-4-20250514"
        assert provider.timeout == 60
        assert provider.max_tokens == 4096

    def test_creates_without_api_key(self):
        """Should initialize without API key (will be unavailable)."""
        config = AnthropicConfig(api_key=None)
        provider = AnthropicProvider(config)
        assert provider.api_key is None

    def test_inherits_from_base_provider(self):
        """Should inherit from LLMProvider."""
        config = AnthropicConfig(api_key="test")
        provider = AnthropicProvider(config)
        assert isinstance(provider, LLMProvider)

    def test_has_correct_name(self):
        """Should have name 'anthropic'."""
        config = AnthropicConfig(api_key="test")
        provider = AnthropicProvider(config)
        assert provider.name == "anthropic"


class TestAnthropicAvailability:
    """Test Anthropic provider availability checks."""

    @pytest.fixture
    def config_with_key(self):
        return AnthropicConfig(api_key="test-api-key")

    @pytest.fixture
    def config_without_key(self):
        return AnthropicConfig(api_key=None)

    @pytest.mark.asyncio
    async def test_is_available_with_api_key(self, config_with_key):
        """Should return True when API key is configured."""
        provider = AnthropicProvider(config_with_key)
        result = await provider.is_available()
        assert result is True

    @pytest.mark.asyncio
    async def test_is_available_without_api_key(self, config_without_key):
        """Should return False when no API key."""
        provider = AnthropicProvider(config_without_key)
        result = await provider.is_available()
        assert result is False

    @pytest.mark.asyncio
    async def test_is_available_with_empty_api_key(self):
        """Should return False when API key is empty string."""
        config = AnthropicConfig(api_key="")
        provider = AnthropicProvider(config)
        result = await provider.is_available()
        assert result is False


class TestAnthropicCompletion:
    """Test Anthropic provider completion."""

    @pytest.fixture
    def config(self):
        return AnthropicConfig(
            api_key="test-api-key",
            model="claude-sonnet-4-20250514",
            timeout=60,
            max_tokens=4096,
        )

    @pytest.fixture
    def provider(self, config):
        return AnthropicProvider(config)

    @pytest.mark.asyncio
    async def test_complete_success(self, provider):
        """Should return LLMResponse on successful completion."""
        mock_message = MagicMock()
        mock_message.content = [MagicMock(text="Hello from Claude!")]
        mock_message.model = "claude-sonnet-4-20250514"
        mock_message.usage = MagicMock(input_tokens=10, output_tokens=5)
        mock_message.stop_reason = "end_turn"

        mock_client = MagicMock()
        mock_client.messages = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_message)

        provider._client = mock_client

        request = LLMRequest(
            messages=[Message(role=Role.USER, content="Hello")]
        )
        response = await provider.complete(request)

        assert isinstance(response, LLMResponse)
        assert response.content == "Hello from Claude!"
        assert response.provider == "anthropic"
        assert response.model == "claude-sonnet-4-20250514"
        assert response.input_tokens == 10
        assert response.output_tokens == 5
        assert response.finish_reason == "end_turn"

    @pytest.mark.asyncio
    async def test_complete_with_system_message(self, provider):
        """Should extract system message for Anthropic API format."""
        mock_message = MagicMock()
        mock_message.content = [MagicMock(text="response")]
        mock_message.model = "claude-sonnet-4-20250514"
        mock_message.usage = MagicMock(input_tokens=5, output_tokens=3)
        mock_message.stop_reason = "end_turn"

        mock_client = MagicMock()
        mock_client.messages = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_message)

        provider._client = mock_client

        request = LLMRequest(
            messages=[
                Message(role=Role.SYSTEM, content="You are helpful"),
                Message(role=Role.USER, content="Hi"),
            ]
        )
        await provider.complete(request)

        # Verify system message was passed separately
        call_kwargs = mock_client.messages.create.call_args.kwargs
        assert "system" in call_kwargs
        assert call_kwargs["system"] == "You are helpful"
        # User messages should not include system message
        messages = call_kwargs["messages"]
        assert len(messages) == 1
        assert messages[0]["role"] == "user"

    @pytest.mark.asyncio
    async def test_complete_with_custom_model(self, provider):
        """Should use custom model if specified in request."""
        mock_message = MagicMock()
        mock_message.content = [MagicMock(text="response")]
        mock_message.model = "claude-3-opus-20240229"
        mock_message.usage = MagicMock(input_tokens=5, output_tokens=3)
        mock_message.stop_reason = "end_turn"

        mock_client = MagicMock()
        mock_client.messages = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_message)

        provider._client = mock_client

        request = LLMRequest(
            messages=[Message(role=Role.USER, content="test")],
            model="claude-3-opus-20240229",
        )
        response = await provider.complete(request)

        call_kwargs = mock_client.messages.create.call_args.kwargs
        assert call_kwargs["model"] == "claude-3-opus-20240229"

    @pytest.mark.asyncio
    async def test_complete_with_temperature(self, provider):
        """Should pass temperature to API."""
        mock_message = MagicMock()
        mock_message.content = [MagicMock(text="response")]
        mock_message.model = "claude-sonnet-4-20250514"
        mock_message.usage = MagicMock(input_tokens=5, output_tokens=3)
        mock_message.stop_reason = "end_turn"

        mock_client = MagicMock()
        mock_client.messages = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_message)

        provider._client = mock_client

        request = LLMRequest(
            messages=[Message(role=Role.USER, content="test")],
            temperature=0.7,
        )
        await provider.complete(request)

        call_kwargs = mock_client.messages.create.call_args.kwargs
        assert call_kwargs["temperature"] == 0.7

    @pytest.mark.asyncio
    async def test_complete_multi_turn_conversation(self, provider):
        """Should format multi-turn conversation correctly."""
        mock_message = MagicMock()
        mock_message.content = [MagicMock(text="response")]
        mock_message.model = "claude-sonnet-4-20250514"
        mock_message.usage = MagicMock(input_tokens=10, output_tokens=5)
        mock_message.stop_reason = "end_turn"

        mock_client = MagicMock()
        mock_client.messages = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_message)

        provider._client = mock_client

        request = LLMRequest(
            messages=[
                Message(role=Role.USER, content="Hi"),
                Message(role=Role.ASSISTANT, content="Hello!"),
                Message(role=Role.USER, content="How are you?"),
            ]
        )
        await provider.complete(request)

        call_kwargs = mock_client.messages.create.call_args.kwargs
        messages = call_kwargs["messages"]
        assert len(messages) == 3
        assert messages[0]["role"] == "user"
        assert messages[1]["role"] == "assistant"
        assert messages[2]["role"] == "user"

    @pytest.mark.asyncio
    async def test_complete_api_error(self, provider):
        """Should raise exception on API error."""
        mock_client = MagicMock()
        mock_client.messages = MagicMock()
        mock_client.messages.create = AsyncMock(side_effect=Exception("API Error"))

        provider._client = mock_client

        request = LLMRequest(messages=[Message(role=Role.USER, content="test")])
        with pytest.raises(Exception, match="API Error"):
            await provider.complete(request)

    @pytest.mark.asyncio
    async def test_complete_without_client(self, config):
        """Should raise exception when no client configured."""
        config = AnthropicConfig(api_key=None)
        provider = AnthropicProvider(config)

        request = LLMRequest(messages=[Message(role=Role.USER, content="test")])
        with pytest.raises(Exception):
            await provider.complete(request)


class TestAnthropicMessageFormatting:
    """Test Anthropic message formatting."""

    @pytest.fixture
    def provider(self):
        config = AnthropicConfig(api_key="test")
        return AnthropicProvider(config)

    def test_format_user_message(self, provider):
        """Should format user message correctly."""
        messages = [Message(role=Role.USER, content="Hello")]
        formatted, system = provider._format_messages(messages)
        assert len(formatted) == 1
        assert formatted[0]["role"] == "user"
        assert formatted[0]["content"] == "Hello"
        assert system is None

    def test_format_extracts_system_message(self, provider):
        """Should extract system message separately."""
        messages = [
            Message(role=Role.SYSTEM, content="Be helpful"),
            Message(role=Role.USER, content="Hi"),
        ]
        formatted, system = provider._format_messages(messages)
        assert system == "Be helpful"
        assert len(formatted) == 1
        assert formatted[0]["role"] == "user"

    def test_format_multi_turn(self, provider):
        """Should format multi-turn conversation."""
        messages = [
            Message(role=Role.USER, content="Hi"),
            Message(role=Role.ASSISTANT, content="Hello!"),
            Message(role=Role.USER, content="Bye"),
        ]
        formatted, system = provider._format_messages(messages)
        assert len(formatted) == 3
        assert formatted[0]["role"] == "user"
        assert formatted[1]["role"] == "assistant"
        assert formatted[2]["role"] == "user"
        assert system is None


class TestAnthropicIntegration:
    """Integration tests - require valid Anthropic API key."""

    @pytest.fixture
    def config(self):
        import os
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        return AnthropicConfig(
            api_key=api_key,
            model="claude-sonnet-4-20250514",
        )

    @pytest.fixture
    def provider(self, config):
        return AnthropicProvider(config)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_real_availability_check(self, provider):
        """Integration test: Check real Anthropic availability."""
        result = await provider.is_available()
        assert isinstance(result, bool)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_real_completion(self, provider):
        """Integration test: Real completion with Anthropic."""
        if not await provider.is_available():
            pytest.skip("Anthropic API not available")

        request = LLMRequest(
            messages=[
                Message(role=Role.USER, content="Say 'test' and nothing else")
            ],
            max_tokens=10,
        )
        response = await provider.complete(request)

        assert isinstance(response, LLMResponse)
        assert response.provider == "anthropic"
        assert len(response.content) > 0
