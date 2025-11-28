"""
Tier 1: Fast Pattern-Based Pre-Filter.

This is the first tier of the ML-enhanced pipeline. It uses precompiled
regex patterns to quickly filter out safe code (70% of candidates) before
passing uncertain cases to Tier 2 (CodeBERT).

Performance:
- Speed: ~0.1s per file
- Filters: ~70% of candidates (safe code)
- VRAM: 0 (CPU only)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

from cerberus.models.taint_flow import TaintFlowCandidate
from cerberus.rules.loader import RuleLoader, RuleSet

logger = logging.getLogger(__name__)


@dataclass
class FilterResult:
    """Result from Tier 1 filtering."""

    high_confidence: list[TaintFlowCandidate]  # Confident vulnerabilities
    needs_ml_review: list[TaintFlowCandidate]  # Send to Tier 2 (CodeBERT)
    filtered_out: list[TaintFlowCandidate]     # Safe, no further analysis

    # Metrics
    total_candidates: int = 0
    high_confidence_count: int = 0
    needs_ml_count: int = 0
    filtered_count: int = 0


class Tier1Filter:
    """
    Fast pattern-based pre-filter for vulnerability candidates.

    This is Tier 1 of the ML-enhanced pipeline. It uses precompiled regex
    patterns to:
    1. Identify high-confidence vulnerabilities (confidence >= 0.85)
    2. Filter out safe code (confidence < 0.45)
    3. Pass uncertain cases to Tier 2 CodeBERT classifier (0.45-0.85)

    High-risk indicators that boost confidence:
    - Template literals in SQL/command: +0.3
    - Same function scope: +0.2
    - Direct parameter to sink: +0.15
    - No sanitizer in path: +0.1

    Sanitizer patterns reduce confidence:
    - Known sanitizer in path: sets confidence to 0 (filtered)
    """

    # Confidence thresholds (aligned with Tier 2 CodeBERT classifier)
    HIGH_CONFIDENCE_THRESHOLD = 0.85  # Direct to findings (above Tier 2's 0.75)
    ML_REVIEW_THRESHOLD = 0.45        # Send to CodeBERT (aligned with Tier 2 safe)
    # Below ML_REVIEW_THRESHOLD = filtered out

    # Confidence boosts for high-risk patterns
    TEMPLATE_LITERAL_BOOST = 0.3
    SAME_FUNCTION_BOOST = 0.2
    DIRECT_PARAM_BOOST = 0.15
    NO_SANITIZER_BOOST = 0.1
    STRING_CONCAT_BOOST = 0.25

    def __init__(
        self,
        rules: Optional[RuleSet] = None,
        languages: Optional[list[str]] = None,
        high_confidence_threshold: float = 0.85,
        ml_review_threshold: float = 0.45,
    ):
        """
        Initialize Tier 1 filter.

        Args:
            rules: Rule set from RuleLoader (uses this directly if provided)
            languages: Languages to load rules for (e.g., ["javascript", "python"])
            high_confidence_threshold: Threshold for direct vulnerability detection
            ml_review_threshold: Threshold for sending to ML review
        """
        if rules is not None:
            self.rules = rules
        elif languages:
            # Load and merge rules for all specified languages
            loader = RuleLoader()
            merged_rules = RuleSet(language="multi")
            for lang in languages:
                try:
                    lang_rules = loader.load_rules(lang)
                    merged_rules.sources.extend(lang_rules.sources)
                    merged_rules.sinks.extend(lang_rules.sinks)
                    merged_rules.sanitizers.extend(lang_rules.sanitizers)
                except Exception as e:
                    logger.warning(f"Failed to load rules for {lang}: {e}")
            self.rules = merged_rules
        else:
            # Default: load JavaScript rules (most common)
            loader = RuleLoader()
            self.rules = loader.load_rules("javascript")

        self.rules = self.rules if self.rules else RuleSet(language="default")
        self.HIGH_CONFIDENCE_THRESHOLD = high_confidence_threshold
        self.ML_REVIEW_THRESHOLD = ml_review_threshold

        # Precompile sanitizer patterns for speed
        self._compiled_sanitizers: dict[str, re.Pattern] = {}
        for rule in self.rules.sanitizers:
            try:
                self._compiled_sanitizers[rule.name] = re.compile(rule.pattern, re.IGNORECASE)
            except re.error as e:
                logger.warning(f"Invalid sanitizer pattern '{rule.name}': {e}")

    def filter_candidates(
        self,
        candidates: list[TaintFlowCandidate],
    ) -> FilterResult:
        """
        Filter candidates into three buckets.

        Args:
            candidates: List of taint flow candidates from AST extraction

        Returns:
            FilterResult with three lists:
            - high_confidence: Ready for finding generation
            - needs_ml_review: Send to Tier 2 CodeBERT
            - filtered_out: Safe code, no further analysis
        """
        high_confidence: list[TaintFlowCandidate] = []
        needs_ml_review: list[TaintFlowCandidate] = []
        filtered_out: list[TaintFlowCandidate] = []

        for candidate in candidates:
            # Check for sanitizers first - if present, filter out
            if self._has_sanitizer_in_path(candidate):
                candidate.confidence = 0.0
                filtered_out.append(candidate)
                continue

            # Calculate boosted confidence
            boosted_confidence = self._calculate_boosted_confidence(candidate)
            candidate.confidence = boosted_confidence

            # Route based on confidence
            if boosted_confidence >= self.HIGH_CONFIDENCE_THRESHOLD:
                high_confidence.append(candidate)
            elif boosted_confidence >= self.ML_REVIEW_THRESHOLD:
                needs_ml_review.append(candidate)
            else:
                filtered_out.append(candidate)

        result = FilterResult(
            high_confidence=high_confidence,
            needs_ml_review=needs_ml_review,
            filtered_out=filtered_out,
            total_candidates=len(candidates),
            high_confidence_count=len(high_confidence),
            needs_ml_count=len(needs_ml_review),
            filtered_count=len(filtered_out),
        )

        logger.info(
            f"Tier 1 filter: {len(candidates)} candidates -> "
            f"{len(high_confidence)} high conf, "
            f"{len(needs_ml_review)} need ML, "
            f"{len(filtered_out)} filtered"
        )

        return result

    def _has_sanitizer_in_path(self, candidate: TaintFlowCandidate) -> bool:
        """
        Check if candidate has a sanitizer in the data flow path.

        This is a heuristic check based on:
        1. Sanitizer patterns in the code context
        2. Known safe functions called on the source
        """
        # Check code context for sanitizer patterns
        if candidate.code_context:
            for name, pattern in self._compiled_sanitizers.items():
                if pattern.search(candidate.code_context):
                    logger.debug(f"Sanitizer '{name}' found in code context")
                    return True

        # Check if source is wrapped in a sanitizer
        source_expr = candidate.source.expression
        for name, pattern in self._compiled_sanitizers.items():
            if pattern.search(source_expr):
                return True

        return False

    def _calculate_boosted_confidence(self, candidate: TaintFlowCandidate) -> float:
        """
        Calculate confidence with high-risk indicator boosts.

        Starting from the base confidence, apply boosts for:
        - Template literals (SQL injection, command injection)
        - Same function scope
        - Direct parameter passing
        - String concatenation
        """
        confidence = candidate.confidence

        # Template literal boost (very high risk for SQLi, CMDi)
        if candidate.sink.uses_template_literal:
            confidence += self.TEMPLATE_LITERAL_BOOST
            logger.debug(f"Template literal boost: +{self.TEMPLATE_LITERAL_BOOST}")

        # Same function scope boost
        if candidate.in_same_function:
            confidence += self.SAME_FUNCTION_BOOST
            logger.debug(f"Same function boost: +{self.SAME_FUNCTION_BOOST}")

        # String concatenation in code context
        if candidate.code_context and self._has_string_concat(candidate.code_context):
            confidence += self.STRING_CONCAT_BOOST
            logger.debug(f"String concat boost: +{self.STRING_CONCAT_BOOST}")

        # Direct parameter to sink (source variable used directly in sink args)
        if self._is_direct_param(candidate):
            confidence += self.DIRECT_PARAM_BOOST
            logger.debug(f"Direct param boost: +{self.DIRECT_PARAM_BOOST}")

        # Cap at 1.0
        return min(confidence, 1.0)

    def _has_string_concat(self, code: str) -> bool:
        """Check for string concatenation patterns."""
        # JavaScript/Python string concat patterns
        concat_patterns = [
            r'\+\s*["\']',      # + "..." or + '...'
            r'["\']\s*\+',      # "..." + or '...' +
            r'\+\s*\w+\s*\+',   # + var +
            r'\.concat\(',      # .concat(
            r'%\s',             # Python % formatting
            r'\.format\(',      # Python .format()
        ]
        for pattern in concat_patterns:
            if re.search(pattern, code):
                return True
        return False

    def _is_direct_param(self, candidate: TaintFlowCandidate) -> bool:
        """
        Check if source is used directly as sink parameter.

        Examples of direct param:
        - exec(req.body.cmd)
        - sequelize.query(`SELECT * FROM users WHERE id = ${id}`)
        """
        source_var = candidate.source.expression.split('.')[-1]
        sink_expr = candidate.sink.expression

        # Check if source variable appears in sink expression
        if source_var and source_var in sink_expr:
            return True

        # Check if source appears in template literal within sink
        if '${' in sink_expr and source_var and source_var in sink_expr:
            return True

        return False

    def get_metrics(self) -> dict:
        """Get filter configuration metrics."""
        return {
            "high_confidence_threshold": self.HIGH_CONFIDENCE_THRESHOLD,
            "ml_review_threshold": self.ML_REVIEW_THRESHOLD,
            "sanitizer_patterns_count": len(self._compiled_sanitizers),
            "boost_factors": {
                "template_literal": self.TEMPLATE_LITERAL_BOOST,
                "same_function": self.SAME_FUNCTION_BOOST,
                "direct_param": self.DIRECT_PARAM_BOOST,
                "string_concat": self.STRING_CONCAT_BOOST,
            },
        }
