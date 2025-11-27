"""
Base LLM provider interface.

Defines the abstract base class that all LLM providers must implement.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from cerberus.llm.providers.models import LLMRequest, LLMResponse, Message, Role


class LLMProvider(ABC):
    """Abstract base class for LLM providers.

    All LLM providers (Ollama, Anthropic, OpenAI) must inherit from this class
    and implement the abstract methods.
    """

    name: str = "base"

    @abstractmethod
    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Generate completion from request.

        Args:
            request: The LLM request containing messages and parameters.

        Returns:
            LLMResponse with the generated content and metadata.

        Raises:
            Exception: If the provider fails to generate a completion.
        """
        pass

    @abstractmethod
    async def is_available(self) -> bool:
        """Check if provider is available and configured.

        Returns:
            True if the provider can accept requests, False otherwise.
        """
        pass

    async def complete_text(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> str:
        """Convenience method for simple text completion.

        Creates a single-message request with the given prompt and returns
        just the response content as a string.

        Args:
            prompt: The text prompt to send to the model.
            model: Optional model override.
            temperature: Sampling temperature (0.0 = deterministic).
            max_tokens: Maximum tokens to generate.

        Returns:
            The generated text content.
        """
        request = LLMRequest(
            messages=[Message(role=Role.USER, content=prompt)],
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        response = await self.complete(request)
        return response.content
