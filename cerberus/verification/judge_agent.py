"""
Judge Agent for the Multi-Agent Council.

The judge reviews both attacker and defender arguments and
renders a final verdict with confidence score.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from cerberus.llm.prompts.verification import (
    AttackerResponse,
    DefenderResponse,
    JudgeResponse,
    VerificationPromptBuilder,
)
from cerberus.models.finding import Finding


@dataclass
class JudgeAgentConfig:
    """Configuration for the Judge Agent."""

    max_retries: int = 3
    temperature: float = 0.5  # Lower for more consistent verdicts
    model: str = "default"
    timeout: int = 60


@dataclass
class JudgeResult:
    """Result from the Judge Agent analysis."""

    success: bool
    response: Optional[JudgeResponse] = None
    error: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


class JudgeAgent:
    """
    Judge Agent for vulnerability verification.

    Acts as an impartial arbiter reviewing both the attacker's
    and defender's arguments to render a final verdict.
    """

    def __init__(
        self,
        config: Optional[JudgeAgentConfig] = None,
        llm_gateway: Optional[Any] = None,
    ) -> None:
        """
        Initialize the Judge Agent.

        Args:
            config: Agent configuration.
            llm_gateway: LLM gateway for completions.
        """
        self.config = config or JudgeAgentConfig()
        self.llm_gateway = llm_gateway
        self._prompt_builder = VerificationPromptBuilder()

    async def analyze(
        self,
        finding: Finding,
        attacker_result: AttackerResponse,
        defender_result: DefenderResponse,
    ) -> JudgeResult:
        """
        Review both arguments and render a verdict.

        Args:
            finding: The finding under review.
            attacker_result: The attacker's assessment.
            defender_result: The defender's assessment.

        Returns:
            JudgeResult with final verdict.
        """
        if self.llm_gateway is None:
            return JudgeResult(
                success=False,
                error="LLM gateway not configured",
            )

        prompt = self._prompt_builder.build_judge_prompt(
            finding, attacker_result, defender_result
        )
        messages = prompt.to_messages()

        last_error: Optional[str] = None

        for attempt in range(self.config.max_retries):
            try:
                response_text = await self.llm_gateway.complete(
                    messages=messages,
                    temperature=self.config.temperature,
                )

                response = JudgeResponse.from_json(response_text)

                return JudgeResult(
                    success=True,
                    response=response,
                    metadata={"attempts": attempt + 1},
                )

            except Exception as e:
                last_error = str(e)
                continue

        return JudgeResult(
            success=False,
            error=last_error or "Unknown error",
            metadata={"attempts": self.config.max_retries},
        )
