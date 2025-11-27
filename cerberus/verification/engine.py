"""
Verification Engine for Phase IV.

Main orchestrator that coordinates the Multi-Agent Council and Feedback Loop
to verify findings and reduce false positives.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from cerberus.models.finding import Finding
from cerberus.verification.council import Council, CouncilConfig
from cerberus.verification.feedback import (
    FeedbackConfig,
    FeedbackLoop,
    SpecUpdate,
)


@dataclass
class VerificationEngineConfig:
    """Configuration for the Verification Engine."""

    enable_feedback: bool = True
    min_confidence: float = 0.5
    council_config: Optional[CouncilConfig] = None
    feedback_config: Optional[FeedbackConfig] = None


@dataclass
class VerificationEngineResult:
    """Result from the Verification Engine."""

    success: bool
    findings: list[Finding] = field(default_factory=list)
    spec_updates: Optional[SpecUpdate] = None
    error: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


class VerificationEngine:
    """
    Verification Engine - Main orchestrator for Phase IV.

    Coordinates:
    - Council: Multi-agent verification (Attacker → Defender → Judge)
    - Feedback Loop: Extract spec updates from FALSE_POSITIVEs
    """

    def __init__(
        self,
        config: Optional[VerificationEngineConfig] = None,
        llm_gateway: Optional[Any] = None,
    ) -> None:
        """
        Initialize the Verification Engine.

        Args:
            config: Engine configuration.
            llm_gateway: LLM gateway for agent completions.
        """
        self.config = config or VerificationEngineConfig()
        self.llm_gateway = llm_gateway

        # Initialize sub-components
        self._council = Council(
            config=self.config.council_config,
            llm_gateway=llm_gateway,
        )
        self._feedback = FeedbackLoop(
            config=self.config.feedback_config,
        )

    async def verify(self, findings: list[Finding]) -> VerificationEngineResult:
        """
        Verify a list of findings using the Multi-Agent Council.

        Args:
            findings: List of findings to verify.

        Returns:
            VerificationEngineResult with verified findings and spec updates.
        """
        if not findings:
            return VerificationEngineResult(
                success=True,
                findings=[],
                metadata={"total_findings": 0},
            )

        if self.llm_gateway is None:
            return VerificationEngineResult(
                success=False,
                error="LLM gateway not configured",
            )

        verified_findings: list[Finding] = []
        errors: list[str] = []

        # Verify each finding through the Council
        for finding in findings:
            try:
                result = await self._council.verify(finding)

                if result.success and result.verification:
                    # Update finding with verification result
                    finding.verification = result.verification
                    verified_findings.append(finding)
                else:
                    # Include finding even if verification failed
                    verified_findings.append(finding)
                    if result.error:
                        errors.append(f"Finding {finding.id}: {result.error}")

            except Exception as e:
                errors.append(f"Finding {finding.id}: {str(e)}")
                verified_findings.append(finding)

        # Process feedback if enabled
        spec_updates: Optional[SpecUpdate] = None
        if self.config.enable_feedback:
            feedback_result = self._feedback.analyze_batch(verified_findings)
            if feedback_result.success and feedback_result.updates.total > 0:
                spec_updates = feedback_result.updates

        # Calculate statistics
        stats = self._calculate_statistics(verified_findings)

        return VerificationEngineResult(
            success=len(errors) == 0,
            findings=verified_findings,
            spec_updates=spec_updates,
            error="; ".join(errors) if errors else None,
            metadata=stats,
        )

    def _calculate_statistics(self, findings: list[Finding]) -> dict[str, Any]:
        """Calculate verification statistics."""
        from cerberus.models.base import Verdict

        total = len(findings)
        verified = sum(1 for f in findings if f.verification is not None)

        # Count by verdict
        true_positives = sum(
            1 for f in findings
            if f.verification and f.verification.verdict == Verdict.TRUE_POSITIVE
        )
        false_positives = sum(
            1 for f in findings
            if f.verification and f.verification.verdict == Verdict.FALSE_POSITIVE
        )
        uncertain = sum(
            1 for f in findings
            if f.verification and f.verification.verdict == Verdict.UNCERTAIN
        )

        # Calculate rates
        fp_rate = false_positives / verified if verified > 0 else 0.0

        return {
            "total_findings": total,
            "verified": verified,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "uncertain": uncertain,
            "fp_rate": fp_rate,
        }
