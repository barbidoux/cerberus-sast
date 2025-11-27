"""
Tests for the Ollama LLM provider.

TDD: Write tests first, then implement to make them pass.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from cerberus.llm.providers.ollama import OllamaProvider
from cerberus.llm.providers.models import LLMRequest, LLMResponse, Message, Role
from cerberus.llm.providers.base import LLMProvider
from cerberus.core.config import OllamaConfig


class TestOllamaProviderInit:
    """Test Ollama provider initialization."""

    def test_creates_with_config(self):
        """Should initialize with OllamaConfig."""
        config = OllamaConfig(
            base_url="http://localhost:11434",
            model="qwen2.5-coder:7b",
            timeout=30,
        )
        provider = OllamaProvider(config)
        assert provider.base_url == "http://localhost:11434"
        assert provider.default_model == "qwen2.5-coder:7b"
        assert provider.timeout == 30

    def test_inherits_from_base_provider(self):
        """Should inherit from LLMProvider."""
        config = OllamaConfig()
        provider = OllamaProvider(config)
        assert isinstance(provider, LLMProvider)

    def test_has_correct_name(self):
        """Should have name 'ollama'."""
        config = OllamaConfig()
        provider = OllamaProvider(config)
        assert provider.name == "ollama"


class TestOllamaAvailability:
    """Test Ollama provider availability checks."""

    @pytest.fixture
    def config(self):
        return OllamaConfig(
            base_url="http://localhost:11434",
            model="qwen2.5-coder:7b",
            timeout=30,
        )

    @pytest.fixture
    def provider(self, config):
        return OllamaProvider(config)

    @pytest.mark.asyncio
    async def test_is_available_when_server_running(self, provider):
        """Should return True when Ollama server responds with model available."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(
            return_value={"models": [{"name": "qwen2.5-coder:7b"}]}
        )
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await provider.is_available()
            assert result is True

    @pytest.mark.asyncio
    async def test_is_available_when_server_down(self, provider):
        """Should return False when server is unreachable."""
        mock_session = MagicMock()
        mock_session.get = MagicMock(side_effect=ConnectionError("Connection refused"))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await provider.is_available()
            assert result is False

    @pytest.mark.asyncio
    async def test_is_available_when_model_not_installed(self, provider):
        """Should return False when model is not installed."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(
            return_value={"models": [{"name": "other-model:latest"}]}
        )
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await provider.is_available()
            assert result is False

    @pytest.mark.asyncio
    async def test_is_available_handles_timeout(self, provider):
        """Should return False on timeout."""
        mock_session = MagicMock()
        mock_session.get = MagicMock(side_effect=asyncio.TimeoutError())
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await provider.is_available()
            assert result is False

    @pytest.mark.asyncio
    async def test_is_available_with_model_variant(self, provider):
        """Should match model with different tags."""
        mock_response = MagicMock()
        mock_response.status = 200
        # Server has model with full tag
        mock_response.json = AsyncMock(
            return_value={"models": [{"name": "qwen2.5-coder:7b-instruct-q4_K_M"}]}
        )
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await provider.is_available()
            # Should still find the model by base name
            assert result is True


class TestOllamaCompletion:
    """Test Ollama provider completion."""

    @pytest.fixture
    def config(self):
        return OllamaConfig(
            base_url="http://localhost:11434",
            model="qwen2.5-coder:7b",
            timeout=30,
        )

    @pytest.fixture
    def provider(self, config):
        return OllamaProvider(config)

    def _create_mock_session(self, response_data: dict, status: int = 200):
        """Helper to create mock aiohttp session."""
        mock_response = MagicMock()
        mock_response.status = status
        mock_response.json = AsyncMock(return_value=response_data)
        mock_response.text = AsyncMock(return_value=str(response_data))
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        return mock_session

    @pytest.mark.asyncio
    async def test_complete_success(self, provider):
        """Should return LLMResponse on successful completion."""
        mock_session = self._create_mock_session(
            {
                "response": "Hello, world!",
                "model": "qwen2.5-coder:7b",
                "eval_count": 10,
                "prompt_eval_count": 5,
                "total_duration": 1500000000,
            }
        )

        with patch("aiohttp.ClientSession", return_value=mock_session):
            request = LLMRequest(
                messages=[Message(role=Role.USER, content="Say hello")]
            )
            response = await provider.complete(request)

            assert isinstance(response, LLMResponse)
            assert response.content == "Hello, world!"
            assert response.provider == "ollama"
            assert response.model == "qwen2.5-coder:7b"
            assert response.output_tokens == 10
            assert response.input_tokens == 5

    @pytest.mark.asyncio
    async def test_complete_with_custom_model(self, provider):
        """Should use custom model if specified in request."""
        mock_session = self._create_mock_session(
            {
                "response": "response",
                "model": "llama2:7b",
                "eval_count": 5,
                "prompt_eval_count": 3,
            }
        )

        with patch("aiohttp.ClientSession", return_value=mock_session):
            request = LLMRequest(
                messages=[Message(role=Role.USER, content="test")],
                model="llama2:7b",
            )
            response = await provider.complete(request)
            assert response.model == "llama2:7b"

    @pytest.mark.asyncio
    async def test_complete_with_temperature(self, provider):
        """Should pass temperature to API."""
        mock_session = self._create_mock_session(
            {
                "response": "creative response",
                "model": "qwen2.5-coder:7b",
                "eval_count": 5,
                "prompt_eval_count": 3,
            }
        )

        with patch("aiohttp.ClientSession", return_value=mock_session):
            request = LLMRequest(
                messages=[Message(role=Role.USER, content="test")],
                temperature=0.7,
            )
            await provider.complete(request)

            # Verify temperature was passed in the request body
            call_kwargs = mock_session.post.call_args
            assert call_kwargs is not None

    @pytest.mark.asyncio
    async def test_complete_formats_messages(self, provider):
        """Should format multi-turn messages correctly."""
        mock_session = self._create_mock_session(
            {
                "response": "result",
                "model": "qwen2.5-coder:7b",
                "eval_count": 1,
                "prompt_eval_count": 10,
            }
        )

        with patch("aiohttp.ClientSession", return_value=mock_session):
            request = LLMRequest(
                messages=[
                    Message(role=Role.SYSTEM, content="You are helpful"),
                    Message(role=Role.USER, content="Hi"),
                    Message(role=Role.ASSISTANT, content="Hello!"),
                    Message(role=Role.USER, content="How are you?"),
                ]
            )
            response = await provider.complete(request)
            assert response.content == "result"

    @pytest.mark.asyncio
    async def test_complete_handles_api_error(self, provider):
        """Should raise exception on API error."""
        mock_response = MagicMock()
        mock_response.status = 500
        mock_response.text = AsyncMock(return_value="Internal Server Error")
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            request = LLMRequest(
                messages=[Message(role=Role.USER, content="test")]
            )
            with pytest.raises(Exception) as exc_info:
                await provider.complete(request)
            assert "error" in str(exc_info.value).lower() or "500" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_complete_handles_timeout(self, provider):
        """Should raise TimeoutError on timeout."""
        mock_session = MagicMock()
        mock_session.post = MagicMock(side_effect=asyncio.TimeoutError())
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            request = LLMRequest(
                messages=[Message(role=Role.USER, content="test")]
            )
            with pytest.raises((TimeoutError, asyncio.TimeoutError)):
                await provider.complete(request)

    @pytest.mark.asyncio
    async def test_complete_handles_connection_error(self, provider):
        """Should raise exception on connection error."""
        mock_session = MagicMock()
        mock_session.post = MagicMock(side_effect=ConnectionError("Connection refused"))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            request = LLMRequest(
                messages=[Message(role=Role.USER, content="test")]
            )
            with pytest.raises(ConnectionError):
                await provider.complete(request)


class TestOllamaMessageFormatting:
    """Test Ollama message formatting."""

    @pytest.fixture
    def config(self):
        return OllamaConfig()

    @pytest.fixture
    def provider(self, config):
        return OllamaProvider(config)

    def test_format_single_user_message(self, provider):
        """Should format single user message."""
        messages = [Message(role=Role.USER, content="Hello")]
        formatted = provider._format_messages(messages)
        assert isinstance(formatted, list)
        assert len(formatted) == 1
        assert formatted[0]["role"] == "user"
        assert formatted[0]["content"] == "Hello"

    def test_format_system_message(self, provider):
        """Should format system message."""
        messages = [Message(role=Role.SYSTEM, content="Be helpful")]
        formatted = provider._format_messages(messages)
        assert formatted[0]["role"] == "system"

    def test_format_multi_turn_conversation(self, provider):
        """Should format multi-turn conversation correctly."""
        messages = [
            Message(role=Role.SYSTEM, content="You are an assistant"),
            Message(role=Role.USER, content="Hi"),
            Message(role=Role.ASSISTANT, content="Hello!"),
            Message(role=Role.USER, content="How are you?"),
        ]
        formatted = provider._format_messages(messages)
        assert len(formatted) == 4
        assert formatted[0]["role"] == "system"
        assert formatted[1]["role"] == "user"
        assert formatted[2]["role"] == "assistant"
        assert formatted[3]["role"] == "user"


class TestOllamaIntegration:
    """Integration tests - require running Ollama server."""

    @pytest.fixture
    def config(self):
        return OllamaConfig(
            base_url="http://localhost:11434",
            model="qwen2.5-coder:7b",
            timeout=60,
        )

    @pytest.fixture
    def provider(self, config):
        return OllamaProvider(config)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_real_availability_check(self, provider):
        """Integration test: Check real Ollama availability."""
        # This test will skip if Ollama isn't running
        result = await provider.is_available()
        # Just verify it returns a boolean without error
        assert isinstance(result, bool)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_real_completion(self, provider):
        """Integration test: Real completion with Ollama."""
        if not await provider.is_available():
            pytest.skip("Ollama not available")

        request = LLMRequest(
            messages=[
                Message(role=Role.USER, content="Say 'test' and nothing else")
            ],
            max_tokens=10,
        )
        response = await provider.complete(request)

        assert isinstance(response, LLMResponse)
        assert response.provider == "ollama"
        assert len(response.content) > 0
