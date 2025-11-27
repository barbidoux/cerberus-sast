"""
Defender Agent for the Multi-Agent Council.

The defender acts as a security engineer defending the code,
identifying sanitization and validation that prevents exploitation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from cerberus.llm.prompts.verification import (
    AttackerResponse,
    DefenderResponse,
    VerificationPromptBuilder,
)
from cerberus.models.finding import Finding


@dataclass
class DefenderAgentConfig:
    """Configuration for the Defender Agent."""

    max_retries: int = 3
    temperature: float = 0.7
    model: str = "default"
    timeout: int = 60


@dataclass
class DefenderResult:
    """Result from the Defender Agent analysis."""

    success: bool
    response: Optional[DefenderResponse] = None
    error: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


class DefenderAgent:
    """
    Defender Agent for vulnerability verification.

    Acts as a security engineer defending the code by identifying
    sanitization, validation, and other protective measures.
    Must cite specific line numbers for any defenses.
    """

    def __init__(
        self,
        config: Optional[DefenderAgentConfig] = None,
        llm_gateway: Optional[Any] = None,
    ) -> None:
        """
        Initialize the Defender Agent.

        Args:
            config: Agent configuration.
            llm_gateway: LLM gateway for completions.
        """
        self.config = config or DefenderAgentConfig()
        self.llm_gateway = llm_gateway
        self._prompt_builder = VerificationPromptBuilder()

    async def analyze(
        self,
        finding: Finding,
        attacker_result: AttackerResponse,
    ) -> DefenderResult:
        """
        Analyze a finding to identify defenses against the attack.

        Args:
            finding: The finding to analyze.
            attacker_result: The attacker's assessment to respond to.

        Returns:
            DefenderResult with defense assessment.
        """
        if self.llm_gateway is None:
            return DefenderResult(
                success=False,
                error="LLM gateway not configured",
            )

        prompt = self._prompt_builder.build_defender_prompt(finding, attacker_result)
        messages = prompt.to_messages()

        last_error: Optional[str] = None

        for attempt in range(self.config.max_retries):
            try:
                response_text = await self.llm_gateway.complete(
                    messages=messages,
                    temperature=self.config.temperature,
                )

                response = DefenderResponse.from_json(response_text)

                return DefenderResult(
                    success=True,
                    response=response,
                    metadata={"attempts": attempt + 1},
                )

            except Exception as e:
                last_error = str(e)
                continue

        return DefenderResult(
            success=False,
            error=last_error or "Unknown error",
            metadata={"attempts": self.config.max_retries},
        )
