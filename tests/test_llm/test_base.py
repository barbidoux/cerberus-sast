"""
Tests for the base LLM provider interface.

TDD: Write tests first, then implement to make them pass.
"""

import pytest
from cerberus.llm.providers.base import LLMProvider
from cerberus.llm.providers.models import LLMRequest, LLMResponse, Message, Role


class TestLLMProviderInterface:
    """Test the abstract LLMProvider interface."""

    def test_provider_is_abstract(self):
        """LLMProvider cannot be instantiated directly."""
        with pytest.raises(TypeError):
            LLMProvider()

    def test_provider_requires_complete_method(self):
        """Subclasses must implement complete()."""

        class IncompleteProvider(LLMProvider):
            name = "incomplete"

            async def is_available(self) -> bool:
                return True

        with pytest.raises(TypeError):
            IncompleteProvider()

    def test_provider_requires_is_available_method(self):
        """Subclasses must implement is_available()."""

        class IncompleteProvider(LLMProvider):
            name = "incomplete"

            async def complete(self, request: LLMRequest) -> LLMResponse:
                return LLMResponse(
                    content="",
                    model="",
                    provider="",
                    input_tokens=0,
                    output_tokens=0,
                    finish_reason="",
                )

        with pytest.raises(TypeError):
            IncompleteProvider()

    def test_provider_has_name_attribute(self):
        """Provider should have a name class attribute."""

        class CompleteProvider(LLMProvider):
            name = "test-provider"

            async def complete(self, request: LLMRequest) -> LLMResponse:
                return LLMResponse(
                    content="",
                    model="",
                    provider=self.name,
                    input_tokens=0,
                    output_tokens=0,
                    finish_reason="",
                )

            async def is_available(self) -> bool:
                return True

        provider = CompleteProvider()
        assert provider.name == "test-provider"


class TestMockProvider:
    """Test with a complete mock implementation."""

    @pytest.fixture
    def mock_provider(self):
        """Create a mock provider for testing."""

        class MockProvider(LLMProvider):
            name = "mock"

            async def complete(self, request: LLMRequest) -> LLMResponse:
                return LLMResponse(
                    content="mock response",
                    model="mock-model",
                    provider="mock",
                    input_tokens=10,
                    output_tokens=5,
                    finish_reason="stop",
                )

            async def is_available(self) -> bool:
                return True

        return MockProvider()

    @pytest.mark.asyncio
    async def test_complete_returns_response(self, mock_provider):
        """complete() should return LLMResponse."""
        request = LLMRequest(messages=[Message(role=Role.USER, content="test")])
        response = await mock_provider.complete(request)
        assert isinstance(response, LLMResponse)
        assert response.provider == "mock"
        assert response.content == "mock response"

    @pytest.mark.asyncio
    async def test_is_available_returns_bool(self, mock_provider):
        """is_available() should return boolean."""
        result = await mock_provider.is_available()
        assert isinstance(result, bool)
        assert result is True


class TestCompleteText:
    """Test the convenience complete_text method."""

    @pytest.fixture
    def echo_provider(self):
        """Create a provider that echoes the prompt."""

        class EchoProvider(LLMProvider):
            name = "echo"

            async def complete(self, request: LLMRequest) -> LLMResponse:
                # Echo back the content of the first user message
                content = ""
                for msg in request.messages:
                    if msg.role == Role.USER:
                        content = f"Echo: {msg.content}"
                        break
                return LLMResponse(
                    content=content,
                    model=request.model or "echo-model",
                    provider="echo",
                    input_tokens=len(content) // 4,
                    output_tokens=len(content) // 4,
                    finish_reason="stop",
                )

            async def is_available(self) -> bool:
                return True

        return EchoProvider()

    @pytest.mark.asyncio
    async def test_complete_text_simple(self, echo_provider):
        """complete_text() should provide simple text completion."""
        result = await echo_provider.complete_text("Hello world")
        assert isinstance(result, str)
        assert "Hello world" in result

    @pytest.mark.asyncio
    async def test_complete_text_with_model(self, echo_provider):
        """complete_text() should accept model parameter."""
        result = await echo_provider.complete_text("Test", model="custom-model")
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_complete_text_with_temperature(self, echo_provider):
        """complete_text() should accept temperature parameter."""
        result = await echo_provider.complete_text("Test", temperature=0.7)
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_complete_text_with_max_tokens(self, echo_provider):
        """complete_text() should accept max_tokens parameter."""
        result = await echo_provider.complete_text("Test", max_tokens=100)
        assert isinstance(result, str)


class TestUnavailableProvider:
    """Test provider unavailability handling."""

    @pytest.fixture
    def unavailable_provider(self):
        """Create a provider that is not available."""

        class UnavailableProvider(LLMProvider):
            name = "unavailable"

            async def complete(self, request: LLMRequest) -> LLMResponse:
                raise RuntimeError("Provider not available")

            async def is_available(self) -> bool:
                return False

        return UnavailableProvider()

    @pytest.mark.asyncio
    async def test_is_available_returns_false(self, unavailable_provider):
        """Unavailable provider should return False for is_available()."""
        result = await unavailable_provider.is_available()
        assert result is False
