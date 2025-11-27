"""
Tests for the OpenAI GPT provider.

TDD: Write tests first, then implement to make them pass.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from cerberus.llm.providers.openai import OpenAIProvider
from cerberus.llm.providers.models import LLMRequest, LLMResponse, Message, Role
from cerberus.llm.providers.base import LLMProvider
from cerberus.core.config import OpenAIConfig


class TestOpenAIProviderInit:
    """Test OpenAI provider initialization."""

    def test_creates_with_config(self):
        """Should initialize with OpenAIConfig."""
        config = OpenAIConfig(
            api_key="test-key",
            model="gpt-4-turbo",
            timeout=60,
            max_tokens=4096,
        )
        provider = OpenAIProvider(config)
        assert provider.api_key == "test-key"
        assert provider.default_model == "gpt-4-turbo"
        assert provider.timeout == 60
        assert provider.max_tokens == 4096

    def test_creates_without_api_key(self):
        """Should initialize without API key (will be unavailable)."""
        config = OpenAIConfig(api_key=None)
        provider = OpenAIProvider(config)
        assert provider.api_key is None

    def test_inherits_from_base_provider(self):
        """Should inherit from LLMProvider."""
        config = OpenAIConfig(api_key="test")
        provider = OpenAIProvider(config)
        assert isinstance(provider, LLMProvider)

    def test_has_correct_name(self):
        """Should have name 'openai'."""
        config = OpenAIConfig(api_key="test")
        provider = OpenAIProvider(config)
        assert provider.name == "openai"


class TestOpenAIAvailability:
    """Test OpenAI provider availability checks."""

    @pytest.fixture
    def config_with_key(self):
        return OpenAIConfig(api_key="test-api-key")

    @pytest.fixture
    def config_without_key(self):
        return OpenAIConfig(api_key=None)

    @pytest.mark.asyncio
    async def test_is_available_with_api_key(self, config_with_key):
        """Should return True when API key is configured."""
        provider = OpenAIProvider(config_with_key)
        result = await provider.is_available()
        assert result is True

    @pytest.mark.asyncio
    async def test_is_available_without_api_key(self, config_without_key):
        """Should return False when no API key."""
        provider = OpenAIProvider(config_without_key)
        result = await provider.is_available()
        assert result is False

    @pytest.mark.asyncio
    async def test_is_available_with_empty_api_key(self):
        """Should return False when API key is empty string."""
        config = OpenAIConfig(api_key="")
        provider = OpenAIProvider(config)
        result = await provider.is_available()
        assert result is False


class TestOpenAICompletion:
    """Test OpenAI provider completion."""

    @pytest.fixture
    def config(self):
        return OpenAIConfig(
            api_key="test-api-key",
            model="gpt-4-turbo",
            timeout=60,
            max_tokens=4096,
        )

    @pytest.fixture
    def provider(self, config):
        return OpenAIProvider(config)

    def _create_mock_response(
        self,
        content: str = "Hello!",
        model: str = "gpt-4-turbo",
        finish_reason: str = "stop",
        prompt_tokens: int = 10,
        completion_tokens: int = 5,
    ):
        """Helper to create mock OpenAI response."""
        mock_choice = MagicMock()
        mock_choice.message = MagicMock(content=content)
        mock_choice.finish_reason = finish_reason

        mock_usage = MagicMock(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        )

        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_response.model = model
        mock_response.usage = mock_usage

        return mock_response

    @pytest.mark.asyncio
    async def test_complete_success(self, provider):
        """Should return LLMResponse on successful completion."""
        mock_response = self._create_mock_response(
            content="Hello from GPT!",
            model="gpt-4-turbo",
            prompt_tokens=10,
            completion_tokens=5,
        )

        mock_client = MagicMock()
        mock_client.chat = MagicMock()
        mock_client.chat.completions = MagicMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        provider._client = mock_client

        request = LLMRequest(messages=[Message(role=Role.USER, content="Hello")])
        response = await provider.complete(request)

        assert isinstance(response, LLMResponse)
        assert response.content == "Hello from GPT!"
        assert response.provider == "openai"
        assert response.model == "gpt-4-turbo"
        assert response.input_tokens == 10
        assert response.output_tokens == 5
        assert response.finish_reason == "stop"

    @pytest.mark.asyncio
    async def test_complete_with_system_message(self, provider):
        """Should include system message in messages array."""
        mock_response = self._create_mock_response()

        mock_client = MagicMock()
        mock_client.chat = MagicMock()
        mock_client.chat.completions = MagicMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        provider._client = mock_client

        request = LLMRequest(
            messages=[
                Message(role=Role.SYSTEM, content="You are helpful"),
                Message(role=Role.USER, content="Hi"),
            ]
        )
        await provider.complete(request)

        call_kwargs = mock_client.chat.completions.create.call_args.kwargs
        messages = call_kwargs["messages"]
        assert len(messages) == 2
        assert messages[0]["role"] == "system"
        assert messages[0]["content"] == "You are helpful"

    @pytest.mark.asyncio
    async def test_complete_with_custom_model(self, provider):
        """Should use custom model if specified in request."""
        mock_response = self._create_mock_response(model="gpt-4")

        mock_client = MagicMock()
        mock_client.chat = MagicMock()
        mock_client.chat.completions = MagicMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        provider._client = mock_client

        request = LLMRequest(
            messages=[Message(role=Role.USER, content="test")],
            model="gpt-4",
        )
        await provider.complete(request)

        call_kwargs = mock_client.chat.completions.create.call_args.kwargs
        assert call_kwargs["model"] == "gpt-4"

    @pytest.mark.asyncio
    async def test_complete_with_temperature(self, provider):
        """Should pass temperature to API."""
        mock_response = self._create_mock_response()

        mock_client = MagicMock()
        mock_client.chat = MagicMock()
        mock_client.chat.completions = MagicMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        provider._client = mock_client

        request = LLMRequest(
            messages=[Message(role=Role.USER, content="test")],
            temperature=0.7,
        )
        await provider.complete(request)

        call_kwargs = mock_client.chat.completions.create.call_args.kwargs
        assert call_kwargs["temperature"] == 0.7

    @pytest.mark.asyncio
    async def test_complete_with_stop_sequences(self, provider):
        """Should pass stop sequences to API."""
        mock_response = self._create_mock_response()

        mock_client = MagicMock()
        mock_client.chat = MagicMock()
        mock_client.chat.completions = MagicMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        provider._client = mock_client

        request = LLMRequest(
            messages=[Message(role=Role.USER, content="test")],
            stop=["END", "STOP"],
        )
        await provider.complete(request)

        call_kwargs = mock_client.chat.completions.create.call_args.kwargs
        assert call_kwargs["stop"] == ["END", "STOP"]

    @pytest.mark.asyncio
    async def test_complete_multi_turn_conversation(self, provider):
        """Should format multi-turn conversation correctly."""
        mock_response = self._create_mock_response()

        mock_client = MagicMock()
        mock_client.chat = MagicMock()
        mock_client.chat.completions = MagicMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        provider._client = mock_client

        request = LLMRequest(
            messages=[
                Message(role=Role.USER, content="Hi"),
                Message(role=Role.ASSISTANT, content="Hello!"),
                Message(role=Role.USER, content="How are you?"),
            ]
        )
        await provider.complete(request)

        call_kwargs = mock_client.chat.completions.create.call_args.kwargs
        messages = call_kwargs["messages"]
        assert len(messages) == 3
        assert messages[0]["role"] == "user"
        assert messages[1]["role"] == "assistant"
        assert messages[2]["role"] == "user"

    @pytest.mark.asyncio
    async def test_complete_api_error(self, provider):
        """Should raise exception on API error."""
        mock_client = MagicMock()
        mock_client.chat = MagicMock()
        mock_client.chat.completions = MagicMock()
        mock_client.chat.completions.create = AsyncMock(
            side_effect=Exception("API Error")
        )

        provider._client = mock_client

        request = LLMRequest(messages=[Message(role=Role.USER, content="test")])
        with pytest.raises(Exception, match="API Error"):
            await provider.complete(request)

    @pytest.mark.asyncio
    async def test_complete_without_client(self):
        """Should raise exception when no client configured."""
        config = OpenAIConfig(api_key=None)
        provider = OpenAIProvider(config)

        request = LLMRequest(messages=[Message(role=Role.USER, content="test")])
        with pytest.raises(Exception):
            await provider.complete(request)


class TestOpenAIMessageFormatting:
    """Test OpenAI message formatting."""

    @pytest.fixture
    def provider(self):
        config = OpenAIConfig(api_key="test")
        return OpenAIProvider(config)

    def test_format_user_message(self, provider):
        """Should format user message correctly."""
        messages = [Message(role=Role.USER, content="Hello")]
        formatted = provider._format_messages(messages)
        assert len(formatted) == 1
        assert formatted[0]["role"] == "user"
        assert formatted[0]["content"] == "Hello"

    def test_format_system_message(self, provider):
        """Should include system message in array."""
        messages = [
            Message(role=Role.SYSTEM, content="Be helpful"),
            Message(role=Role.USER, content="Hi"),
        ]
        formatted = provider._format_messages(messages)
        assert len(formatted) == 2
        assert formatted[0]["role"] == "system"
        assert formatted[0]["content"] == "Be helpful"

    def test_format_multi_turn(self, provider):
        """Should format multi-turn conversation."""
        messages = [
            Message(role=Role.USER, content="Hi"),
            Message(role=Role.ASSISTANT, content="Hello!"),
            Message(role=Role.USER, content="Bye"),
        ]
        formatted = provider._format_messages(messages)
        assert len(formatted) == 3
        assert formatted[0]["role"] == "user"
        assert formatted[1]["role"] == "assistant"
        assert formatted[2]["role"] == "user"


class TestOpenAIIntegration:
    """Integration tests - require valid OpenAI API key."""

    @pytest.fixture
    def config(self):
        import os
        api_key = os.environ.get("OPENAI_API_KEY", "")
        return OpenAIConfig(
            api_key=api_key,
            model="gpt-4-turbo",
        )

    @pytest.fixture
    def provider(self, config):
        return OpenAIProvider(config)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_real_availability_check(self, provider):
        """Integration test: Check real OpenAI availability."""
        result = await provider.is_available()
        assert isinstance(result, bool)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_real_completion(self, provider):
        """Integration test: Real completion with OpenAI."""
        if not await provider.is_available():
            pytest.skip("OpenAI API not available")

        request = LLMRequest(
            messages=[
                Message(role=Role.USER, content="Say 'test' and nothing else")
            ],
            max_tokens=10,
        )
        response = await provider.complete(request)

        assert isinstance(response, LLMResponse)
        assert response.provider == "openai"
        assert len(response.content) > 0
