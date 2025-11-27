"""
Multi-Agent Council for vulnerability verification.

Orchestrates the three-agent debate system:
Attacker → Defender → Judge

Creates VerificationResult from the combined agent outputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from cerberus.llm.prompts.verification import (
    AttackerResponse,
    DefenderResponse,
    JudgeResponse,
)
from cerberus.models.base import Verdict
from cerberus.models.finding import Finding, VerificationResult
from cerberus.verification.attacker_agent import AttackerAgent, AttackerAgentConfig
from cerberus.verification.defender_agent import DefenderAgent, DefenderAgentConfig
from cerberus.verification.judge_agent import JudgeAgent, JudgeAgentConfig


@dataclass
class CouncilConfig:
    """Configuration for the Multi-Agent Council."""

    max_iterations: int = 1  # For future iterative verification
    min_confidence: float = 0.5  # Minimum confidence for conclusive verdict
    parallel_batch: bool = True  # Whether to run batch verifications in parallel
    attacker_config: Optional[AttackerAgentConfig] = None
    defender_config: Optional[DefenderAgentConfig] = None
    judge_config: Optional[JudgeAgentConfig] = None


@dataclass
class CouncilResult:
    """Result from Council verification."""

    success: bool
    verification: Optional[VerificationResult] = None
    error: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


class Council:
    """
    Multi-Agent Council for vulnerability verification.

    Orchestrates the debate between Attacker, Defender, and Judge agents
    to determine if a finding is a true positive or false positive.
    """

    def __init__(
        self,
        config: Optional[CouncilConfig] = None,
        llm_gateway: Optional[Any] = None,
    ) -> None:
        """
        Initialize the Council.

        Args:
            config: Council configuration.
            llm_gateway: LLM gateway for all agents.
        """
        self.config = config or CouncilConfig()
        self.llm_gateway = llm_gateway

        # Initialize agents
        self._attacker = AttackerAgent(
            config=self.config.attacker_config,
            llm_gateway=llm_gateway,
        )
        self._defender = DefenderAgent(
            config=self.config.defender_config,
            llm_gateway=llm_gateway,
        )
        self._judge = JudgeAgent(
            config=self.config.judge_config,
            llm_gateway=llm_gateway,
        )

    async def verify(self, finding: Finding) -> CouncilResult:
        """
        Verify a single finding through the council debate.

        Args:
            finding: The finding to verify.

        Returns:
            CouncilResult with verification outcome.
        """
        try:
            # Step 1: Attacker analyzes the finding
            attacker_result = await self._attacker.analyze(finding)
            if not attacker_result.success:
                return CouncilResult(
                    success=False,
                    error=f"Attacker agent failed: {attacker_result.error}",
                )

            attacker_response = attacker_result.response

            # Step 2: Defender responds to attacker's argument
            defender_result = await self._defender.analyze(finding, attacker_response)
            if not defender_result.success:
                return CouncilResult(
                    success=False,
                    error=f"Defender agent failed: {defender_result.error}",
                )

            defender_response = defender_result.response

            # Step 3: Judge renders verdict
            judge_result = await self._judge.analyze(
                finding, attacker_response, defender_response
            )
            if not judge_result.success:
                return CouncilResult(
                    success=False,
                    error=f"Judge agent failed: {judge_result.error}",
                )

            judge_response = judge_result.response

            # Create VerificationResult from agent outputs
            verification = self._create_verification_result(
                attacker_response, defender_response, judge_response
            )

            return CouncilResult(
                success=True,
                verification=verification,
                metadata={
                    "attacker_attempts": attacker_result.metadata.get("attempts", 1),
                    "defender_attempts": defender_result.metadata.get("attempts", 1),
                    "judge_attempts": judge_result.metadata.get("attempts", 1),
                },
            )

        except Exception as e:
            return CouncilResult(
                success=False,
                error=str(e),
            )

    async def verify_batch(self, findings: list[Finding]) -> list[CouncilResult]:
        """
        Verify multiple findings.

        Args:
            findings: List of findings to verify.

        Returns:
            List of CouncilResult, one per finding.
        """
        results: list[CouncilResult] = []

        for finding in findings:
            result = await self.verify(finding)
            results.append(result)

        return results

    def _create_verification_result(
        self,
        attacker: AttackerResponse,
        defender: DefenderResponse,
        judge: JudgeResponse,
    ) -> VerificationResult:
        """
        Create a VerificationResult from agent responses.

        Args:
            attacker: Attacker agent response.
            defender: Defender agent response.
            judge: Judge agent response.

        Returns:
            Unified VerificationResult.
        """
        return VerificationResult(
            verdict=judge.verdict,
            confidence=judge.confidence,
            attacker_exploitable=attacker.exploitable,
            attacker_input=attacker.attack_input,
            attacker_trace=attacker.attack_trace,
            attacker_impact=attacker.impact,
            attacker_reasoning=attacker.reasoning,
            defender_safe=defender.safe,
            defender_lines=defender.defense_lines,
            defender_sanitization=defender.sanitization,
            defender_reasoning=defender.reasoning,
            judge_reasoning=judge.reasoning,
            missed_considerations=judge.missed_considerations,
        )
