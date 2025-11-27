"""
Attacker Agent for the Multi-Agent Council.

The attacker acts as a security researcher attempting to prove
that the detected vulnerability is exploitable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from cerberus.llm.prompts.verification import (
    AttackerResponse,
    VerificationPromptBuilder,
)
from cerberus.models.finding import Finding


@dataclass
class AttackerAgentConfig:
    """Configuration for the Attacker Agent."""

    max_retries: int = 3
    temperature: float = 0.7
    model: str = "default"
    timeout: int = 60


@dataclass
class AttackerResult:
    """Result from the Attacker Agent analysis."""

    success: bool
    response: Optional[AttackerResponse] = None
    error: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


class AttackerAgent:
    """
    Attacker Agent for vulnerability verification.

    Acts as a security researcher attempting to prove exploitability
    by crafting attack inputs and tracing data flow.
    """

    def __init__(
        self,
        config: Optional[AttackerAgentConfig] = None,
        llm_gateway: Optional[Any] = None,
    ) -> None:
        """
        Initialize the Attacker Agent.

        Args:
            config: Agent configuration.
            llm_gateway: LLM gateway for completions.
        """
        self.config = config or AttackerAgentConfig()
        self.llm_gateway = llm_gateway
        self._prompt_builder = VerificationPromptBuilder()

    async def analyze(self, finding: Finding) -> AttackerResult:
        """
        Analyze a finding to determine if it's exploitable.

        Args:
            finding: The finding to analyze.

        Returns:
            AttackerResult with exploitability assessment.
        """
        if self.llm_gateway is None:
            return AttackerResult(
                success=False,
                error="LLM gateway not configured",
            )

        prompt = self._prompt_builder.build_attacker_prompt(finding)
        messages = prompt.to_messages()

        last_error: Optional[str] = None

        for attempt in range(self.config.max_retries):
            try:
                response_text = await self.llm_gateway.complete(
                    messages=messages,
                    temperature=self.config.temperature,
                )

                response = AttackerResponse.from_json(response_text)

                return AttackerResult(
                    success=True,
                    response=response,
                    metadata={"attempts": attempt + 1},
                )

            except Exception as e:
                last_error = str(e)
                continue

        return AttackerResult(
            success=False,
            error=last_error or "Unknown error",
            metadata={"attempts": self.config.max_retries},
        )
