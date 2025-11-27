"""
Verification prompts for the Multi-Agent Council.

Implements prompts for the three-agent verification system:
- AttackerPrompt: Security researcher attempting to prove exploitability
- DefenderPrompt: Security engineer defending the code, citing line numbers
- JudgePrompt: Final arbiter rendering verdict with confidence score
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from cerberus.models.base import Verdict
from cerberus.models.finding import Finding


@dataclass
class AttackerResponse:
    """
    Response from the Attacker agent.

    The attacker attempts to prove the vulnerability is exploitable
    by providing attack vectors and impact assessment.
    """

    exploitable: bool
    reasoning: str
    attack_input: Optional[str] = None
    attack_trace: Optional[str] = None
    impact: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "exploitable": self.exploitable,
            "attack_input": self.attack_input,
            "attack_trace": self.attack_trace,
            "impact": self.impact,
            "reasoning": self.reasoning,
        }

    @classmethod
    def from_json(cls, json_str: str) -> "AttackerResponse":
        """
        Parse attacker response from JSON string.

        Args:
            json_str: JSON string from LLM response

        Returns:
            AttackerResponse instance
        """
        try:
            # Try to extract JSON from the response
            json_match = re.search(r'\{[^{}]*\}', json_str, re.DOTALL)
            if json_match:
                json_str = json_match.group()

            data = json.loads(json_str)

            return cls(
                exploitable=bool(data.get("exploitable", False)),
                attack_input=data.get("attack_input"),
                attack_trace=data.get("attack_trace"),
                impact=data.get("impact"),
                reasoning=data.get("reasoning", ""),
            )
        except (json.JSONDecodeError, AttributeError, TypeError):
            return cls(
                exploitable=False,
                reasoning=f"Failed to parse response: {json_str[:200]}",
            )


@dataclass
class DefenderResponse:
    """
    Response from the Defender agent.

    The defender attempts to prove the vulnerability is not exploitable
    by citing specific line numbers with defenses.
    """

    safe: bool
    defense_lines: list[int]
    reasoning: str
    sanitization: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "safe": self.safe,
            "defense_lines": self.defense_lines,
            "sanitization": self.sanitization,
            "reasoning": self.reasoning,
        }

    @classmethod
    def from_json(cls, json_str: str) -> "DefenderResponse":
        """
        Parse defender response from JSON string.

        Args:
            json_str: JSON string from LLM response

        Returns:
            DefenderResponse instance
        """
        try:
            json_match = re.search(r'\{[^{}]*\}', json_str, re.DOTALL)
            if json_match:
                json_str = json_match.group()

            data = json.loads(json_str)

            return cls(
                safe=bool(data.get("safe", False)),
                defense_lines=data.get("defense_lines", []),
                sanitization=data.get("sanitization"),
                reasoning=data.get("reasoning", ""),
            )
        except (json.JSONDecodeError, AttributeError, TypeError):
            return cls(
                safe=False,
                defense_lines=[],
                reasoning=f"Failed to parse response: {json_str[:200]}",
            )


@dataclass
class JudgeResponse:
    """
    Response from the Judge agent.

    The judge renders final verdict after reviewing both arguments.
    """

    verdict: Verdict
    confidence: float
    reasoning: str
    missed_considerations: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "missed_considerations": self.missed_considerations,
        }

    @classmethod
    def from_json(cls, json_str: str) -> "JudgeResponse":
        """
        Parse judge response from JSON string.

        Args:
            json_str: JSON string from LLM response

        Returns:
            JudgeResponse instance
        """
        try:
            json_match = re.search(r'\{[^{}]*\}', json_str, re.DOTALL)
            if json_match:
                json_str = json_match.group()

            data = json.loads(json_str)

            # Parse verdict (handle both upper and lower case)
            verdict_str = data.get("verdict", "UNCERTAIN").upper()
            try:
                verdict = Verdict.from_string(verdict_str.lower())
            except (ValueError, KeyError):
                verdict = Verdict.UNCERTAIN

            return cls(
                verdict=verdict,
                confidence=float(data.get("confidence", 0.5)),
                reasoning=data.get("reasoning", ""),
                missed_considerations=data.get("missed_considerations"),
            )
        except (json.JSONDecodeError, AttributeError, TypeError):
            return cls(
                verdict=Verdict.UNCERTAIN,
                confidence=0.3,
                reasoning=f"Failed to parse response: {json_str[:200]}",
            )


class AttackerPrompt:
    """
    Prompt builder for the Attacker agent.

    The attacker acts as a security researcher attempting to
    prove the vulnerability is exploitable.
    """

    def build_system_prompt(self) -> str:
        """Build the system prompt for the attacker role."""
        return """You are an expert security researcher specializing in vulnerability exploitation. Your task is to analyze a potential vulnerability and determine if it is exploitable.

## Your Role

You are the ATTACKER in a security debate. Your goal is to prove that the detected vulnerability IS EXPLOITABLE.

## Analysis Process

Think step by step:
1. Examine the code slice and data flow trace
2. Identify the source of tainted data
3. Trace how data reaches the sink
4. Determine if any sanitization blocks exploitation
5. Craft a proof-of-concept attack input if exploitable

## What to Look For

- Direct data flow from source to sink without sanitization
- Incomplete or bypassable sanitization
- Type coercion or encoding issues
- Context-specific attack vectors

## Response Format

Respond with a JSON object:
{
    "exploitable": true/false,
    "attack_input": "Example malicious input that would exploit this (if exploitable)",
    "attack_trace": "How the attack input would flow through the code",
    "impact": "What damage could be caused (data theft, RCE, etc.)",
    "reasoning": "Step-by-step explanation of your analysis"
}

Be specific and cite line numbers when discussing code behavior."""

    def build_user_prompt(self, finding: Finding) -> str:
        """Build the user prompt with finding context."""
        context = ""
        if finding.slice:
            context = finding.slice.to_prompt_context()

        trace_str = ""
        if finding.trace:
            trace_str = "\n".join(
                f"  {i+1}. Line {step.location.line}: {step.code_snippet} ({step.step_type})"
                for i, step in enumerate(finding.trace)
            )

        return f"""Analyze this potential {finding.vulnerability_type} vulnerability and determine if it is exploitable.

## Vulnerability Details

Type: {finding.vulnerability_type}
Title: {finding.title}
Description: {finding.description}

## Data Flow Trace

{trace_str}

## Code Context

{context}

## Your Task

As the ATTACKER, prove this vulnerability IS exploitable:
1. Can you craft a malicious input that reaches the sink?
2. What sanitization (if any) exists, and can it be bypassed?
3. What is the potential impact if exploited?

Provide your analysis as JSON."""


class DefenderPrompt:
    """
    Prompt builder for the Defender agent.

    The defender acts as a security engineer defending the code,
    MUST cite specific line numbers for any defenses.
    """

    def build_system_prompt(self) -> str:
        """Build the system prompt for the defender role."""
        return """You are an expert security engineer defending code against vulnerability claims. Your task is to analyze a potential vulnerability and determine if the code is actually safe.

## Your Role

You are the DEFENDER in a security debate. Your goal is to prove that the detected vulnerability is NOT exploitable or is a FALSE POSITIVE.

## Critical Requirement

You MUST cite specific line numbers for any defenses you identify. Vague claims without line number evidence will be dismissed.

## Analysis Process

Think step by step:
1. Examine the code slice and data flow trace
2. Look for sanitization, validation, or encoding at each step
3. Check for defensive coding patterns
4. Consider framework-provided protections
5. Identify any conditions that prevent exploitation

## What to Look For

- Input validation (regex, type checking, allowlists)
- Output encoding or escaping
- Parameterized queries or prepared statements
- Framework security features (CSRF tokens, auto-escaping)
- Conditional logic that blocks malicious inputs
- Sanitization functions in the data flow

## Response Format

Respond with a JSON object:
{
    "safe": true/false,
    "defense_lines": [list of line numbers where defenses exist],
    "sanitization": "Description of how the data is sanitized",
    "reasoning": "Step-by-step explanation citing specific line numbers"
}

IMPORTANT: If you claim the code is safe, you MUST provide defense_lines with actual line numbers from the code."""

    def build_user_prompt(
        self,
        finding: Finding,
        attacker_result: AttackerResponse,
    ) -> str:
        """Build the user prompt including attacker's argument."""
        context = ""
        if finding.slice:
            context = finding.slice.to_prompt_context()

        trace_str = ""
        if finding.trace:
            trace_str = "\n".join(
                f"  {i+1}. Line {step.location.line}: {step.code_snippet} ({step.step_type})"
                for i, step in enumerate(finding.trace)
            )

        attacker_summary = f"""## Attacker's Argument

The attacker claims this vulnerability IS exploitable:
- Exploitable: {attacker_result.exploitable}
- Attack Input: {attacker_result.attack_input or 'Not provided'}
- Impact: {attacker_result.impact or 'Not specified'}
- Reasoning: {attacker_result.reasoning}"""

        return f"""Review this potential {finding.vulnerability_type} vulnerability and the attacker's argument.

## Vulnerability Details

Type: {finding.vulnerability_type}
Title: {finding.title}
Description: {finding.description}

## Data Flow Trace

{trace_str}

## Code Context

{context}

{attacker_summary}

## Your Task

As the DEFENDER, prove this vulnerability is NOT exploitable:
1. What sanitization or validation exists in the code?
2. Are there framework protections not shown in the slice?
3. What conditions prevent the attacker's exploit from working?

IMPORTANT: Cite specific line numbers for any defenses you identify.

Provide your analysis as JSON."""


class JudgePrompt:
    """
    Prompt builder for the Judge agent.

    The judge reviews both arguments and renders final verdict.
    """

    def build_system_prompt(self) -> str:
        """Build the system prompt for the judge role."""
        return """You are an impartial security judge reviewing a debate about a potential vulnerability. Your task is to render a final verdict based on the arguments presented.

## Your Role

You are the JUDGE in a security debate between an ATTACKER (proving exploitability) and a DEFENDER (proving safety). You must:
1. Evaluate both arguments objectively
2. Check if the defender's line citations are accurate
3. Consider whether the attacker's exploit is realistic
4. Render a final verdict with confidence

## Verdict Options

- **TRUE_POSITIVE**: The vulnerability is real and exploitable. The attacker's argument is convincing and the defender failed to identify adequate defenses.

- **FALSE_POSITIVE**: The vulnerability is not exploitable. The defender identified legitimate defenses with accurate line citations that block the attack.

- **UNCERTAIN**: Neither argument is fully convincing. More context is needed or the evidence is ambiguous.

## Evaluation Criteria

For TRUE_POSITIVE:
- Attacker provided realistic attack input
- Data flows to sink without adequate sanitization
- Defender's defenses are invalid or non-existent

For FALSE_POSITIVE:
- Defender cited specific line numbers with real defenses
- Sanitization adequately blocks the attack vector
- Attacker's exploit is unrealistic or blocked

For UNCERTAIN:
- Defenses exist but may be incomplete
- Attack is possible but impact is unclear
- Missing context prevents conclusive judgment

## Response Format

Respond with a JSON object:
{
    "verdict": "TRUE_POSITIVE" | "FALSE_POSITIVE" | "UNCERTAIN",
    "confidence": 0.0 to 1.0,
    "reasoning": "Explanation of your verdict, addressing both arguments",
    "missed_considerations": "Any defenses or attack vectors not discussed (for feedback loop)"
}"""

    def build_user_prompt(
        self,
        finding: Finding,
        attacker_result: AttackerResponse,
        defender_result: DefenderResponse,
    ) -> str:
        """Build the user prompt with both arguments."""
        context = ""
        if finding.slice:
            context = finding.slice.to_prompt_context()

        return f"""Review this security debate and render your verdict.

## Vulnerability Under Review

Type: {finding.vulnerability_type}
Title: {finding.title}
Description: {finding.description}

## Code Context

{context}

## ATTACKER'S ARGUMENT

The attacker claims this vulnerability IS exploitable:
- Exploitable: {attacker_result.exploitable}
- Attack Input: {attacker_result.attack_input or 'Not provided'}
- Attack Trace: {attacker_result.attack_trace or 'Not provided'}
- Impact: {attacker_result.impact or 'Not specified'}
- Reasoning: {attacker_result.reasoning}

## DEFENDER'S ARGUMENT

The defender claims this vulnerability is NOT exploitable:
- Safe: {defender_result.safe}
- Defense Lines: {defender_result.defense_lines}
- Sanitization: {defender_result.sanitization or 'Not specified'}
- Reasoning: {defender_result.reasoning}

## Your Task

As the JUDGE, evaluate both arguments and render your verdict:
1. Is the attacker's exploit realistic and impactful?
2. Did the defender cite valid defenses with accurate line numbers?
3. Which argument is more convincing?

Provide your verdict as JSON."""


@dataclass
class VerificationBuiltPrompt:
    """A fully constructed verification prompt ready for LLM invocation."""

    system_message: str
    user_message: str

    def to_messages(self) -> list[dict[str, str]]:
        """Convert to LLM message format."""
        return [
            {"role": "system", "content": self.system_message},
            {"role": "user", "content": self.user_message},
        ]


class VerificationPromptBuilder:
    """Builder for assembling complete verification prompts."""

    def __init__(self) -> None:
        """Initialize prompt builders for each agent."""
        self._attacker = AttackerPrompt()
        self._defender = DefenderPrompt()
        self._judge = JudgePrompt()

    def build_attacker_prompt(self, finding: Finding) -> VerificationBuiltPrompt:
        """
        Build a complete prompt for the attacker agent.

        Args:
            finding: The finding to analyze

        Returns:
            VerificationBuiltPrompt ready for LLM invocation
        """
        return VerificationBuiltPrompt(
            system_message=self._attacker.build_system_prompt(),
            user_message=self._attacker.build_user_prompt(finding),
        )

    def build_defender_prompt(
        self,
        finding: Finding,
        attacker_result: AttackerResponse,
    ) -> VerificationBuiltPrompt:
        """
        Build a complete prompt for the defender agent.

        Args:
            finding: The finding to analyze
            attacker_result: The attacker's response

        Returns:
            VerificationBuiltPrompt ready for LLM invocation
        """
        return VerificationBuiltPrompt(
            system_message=self._defender.build_system_prompt(),
            user_message=self._defender.build_user_prompt(finding, attacker_result),
        )

    def build_judge_prompt(
        self,
        finding: Finding,
        attacker_result: AttackerResponse,
        defender_result: DefenderResponse,
    ) -> VerificationBuiltPrompt:
        """
        Build a complete prompt for the judge agent.

        Args:
            finding: The finding to analyze
            attacker_result: The attacker's response
            defender_result: The defender's response

        Returns:
            VerificationBuiltPrompt ready for LLM invocation
        """
        return VerificationBuiltPrompt(
            system_message=self._judge.build_system_prompt(),
            user_message=self._judge.build_user_prompt(
                finding, attacker_result, defender_result
            ),
        )
