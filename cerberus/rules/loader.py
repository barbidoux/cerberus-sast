"""
YAML-based Rule Loader for Taint Analysis.

Loads source, sink, and sanitizer rules from external YAML files,
enabling customization without code changes.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)


@dataclass
class TaintRule:
    """A single taint analysis rule (source, sink, or sanitizer)."""

    name: str
    pattern: str
    type: str
    confidence: float = 0.85
    cwe_types: list[str] = field(default_factory=list)
    description: str = ""
    callee_pattern: Optional[str] = None  # For sinks only
    high_risk_indicators: dict[str, bool] = field(default_factory=dict)
    language: str = "javascript"
    enabled: bool = True

    def matches(self, expression: str) -> bool:
        """Check if expression matches this rule's pattern."""
        import re
        try:
            return bool(re.match(self.pattern, expression))
        except re.error:
            logger.warning(f"Invalid regex pattern in rule {self.name}: {self.pattern}")
            return False

    def matches_callee(self, callee: str) -> bool:
        """Check if callee matches this rule's callee pattern (for sinks)."""
        if not self.callee_pattern:
            return self.pattern in callee or callee.endswith(self.pattern)
        import re
        try:
            return bool(re.match(self.callee_pattern, callee))
        except re.error:
            return callee == self.callee_pattern

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TaintRule":
        """Create TaintRule from dictionary."""
        return cls(
            name=data.get("name", "unnamed"),
            pattern=data.get("pattern", ""),
            type=data.get("type", "user_input"),
            confidence=float(data.get("confidence", 0.85)),
            cwe_types=data.get("cwe_types", []),
            description=data.get("description", ""),
            callee_pattern=data.get("callee_pattern"),
            high_risk_indicators=data.get("high_risk_indicators", {}),
            language=data.get("language", "javascript"),
            enabled=data.get("enabled", True),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "name": self.name,
            "pattern": self.pattern,
            "type": self.type,
            "confidence": self.confidence,
            "cwe_types": self.cwe_types,
            "description": self.description,
            "callee_pattern": self.callee_pattern,
            "high_risk_indicators": self.high_risk_indicators,
            "language": self.language,
            "enabled": self.enabled,
        }


@dataclass
class RuleSet:
    """Collection of rules for a specific language."""

    language: str = "javascript"
    sources: list[TaintRule] = field(default_factory=list)
    sinks: list[TaintRule] = field(default_factory=list)
    sanitizers: list[TaintRule] = field(default_factory=list)

    @property
    def enabled_sources(self) -> list[TaintRule]:
        """Get only enabled source rules."""
        return [r for r in self.sources if r.enabled]

    @property
    def enabled_sinks(self) -> list[TaintRule]:
        """Get only enabled sink rules."""
        return [r for r in self.sinks if r.enabled]

    @property
    def enabled_sanitizers(self) -> list[TaintRule]:
        """Get only enabled sanitizer rules."""
        return [r for r in self.sanitizers if r.enabled]

    def merge(self, other: "RuleSet") -> "RuleSet":
        """Merge another RuleSet into this one (other takes precedence)."""
        merged = RuleSet(language=self.language)

        # Build name -> rule maps
        source_map = {r.name: r for r in self.sources}
        sink_map = {r.name: r for r in self.sinks}
        sanitizer_map = {r.name: r for r in self.sanitizers}

        # Override with other's rules
        for r in other.sources:
            source_map[r.name] = r
        for r in other.sinks:
            sink_map[r.name] = r
        for r in other.sanitizers:
            sanitizer_map[r.name] = r

        merged.sources = list(source_map.values())
        merged.sinks = list(sink_map.values())
        merged.sanitizers = list(sanitizer_map.values())

        return merged


class RuleLoader:
    """Load taint analysis rules from YAML files."""

    def __init__(self, rules_dir: Optional[Path] = None) -> None:
        """
        Initialize the rule loader.

        Args:
            rules_dir: Directory containing rule files. Defaults to built-in rules.
        """
        self.default_rules_dir = Path(__file__).parent / "defaults"
        self.custom_rules_dir = rules_dir
        self._cache: dict[str, RuleSet] = {}

    def load_rules(self, language: str) -> RuleSet:
        """
        Load rules for a specific language.

        Loads from default rules first, then overlays custom rules.

        Args:
            language: Programming language (e.g., "javascript", "python")

        Returns:
            RuleSet for the specified language.
        """
        cache_key = f"{language}_{self.custom_rules_dir}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Load default rules
        rules = self._load_from_directory(self.default_rules_dir, language)

        # Overlay custom rules if specified
        if self.custom_rules_dir and self.custom_rules_dir.exists():
            custom_rules = self._load_from_directory(self.custom_rules_dir, language)
            rules = rules.merge(custom_rules)

        self._cache[cache_key] = rules
        return rules

    def _load_from_directory(self, directory: Path, language: str) -> RuleSet:
        """Load rules from a directory."""
        rules = RuleSet(language=language)

        # Load language-specific source rules
        sources_file = directory / f"{language}_sources.yaml"
        if sources_file.exists():
            rules.sources.extend(self._load_rules_from_file(sources_file, "sources"))

        # Load generic sources (fallback)
        generic_sources = directory / "sources.yaml"
        if generic_sources.exists():
            rules.sources.extend(self._load_rules_from_file(generic_sources, "sources"))

        # Load language-specific sink rules
        sinks_file = directory / f"{language}_sinks.yaml"
        if sinks_file.exists():
            rules.sinks.extend(self._load_rules_from_file(sinks_file, "sinks"))

        # Load generic sinks (fallback)
        generic_sinks = directory / "sinks.yaml"
        if generic_sinks.exists():
            rules.sinks.extend(self._load_rules_from_file(generic_sinks, "sinks"))

        # Load sanitizer rules
        sanitizers_file = directory / f"{language}_sanitizers.yaml"
        if sanitizers_file.exists():
            rules.sanitizers.extend(self._load_rules_from_file(sanitizers_file, "sanitizers"))

        generic_sanitizers = directory / "sanitizers.yaml"
        if generic_sanitizers.exists():
            rules.sanitizers.extend(self._load_rules_from_file(generic_sanitizers, "sanitizers"))

        return rules

    def _load_rules_from_file(self, file_path: Path, rule_type: str) -> list[TaintRule]:
        """Load rules from a YAML file."""
        try:
            with open(file_path, "r") as f:
                data = yaml.safe_load(f)

            if not data:
                return []

            rules = []
            for item in data.get(rule_type, []):
                try:
                    rule = TaintRule.from_dict(item)
                    rules.append(rule)
                except Exception as e:
                    logger.warning(f"Failed to parse rule in {file_path}: {e}")

            logger.debug(f"Loaded {len(rules)} {rule_type} rules from {file_path}")
            return rules

        except yaml.YAMLError as e:
            logger.error(f"YAML error in {file_path}: {e}")
            return []
        except OSError as e:
            logger.error(f"Failed to read {file_path}: {e}")
            return []

    def load_project_rules(self, project_path: Path) -> Optional[RuleSet]:
        """
        Load project-specific rules from .cerberus/rules/ directory.

        Args:
            project_path: Path to the project root.

        Returns:
            RuleSet from project rules, or None if not found.
        """
        project_rules_dir = project_path / ".cerberus" / "rules"
        if project_rules_dir.exists():
            loader = RuleLoader(rules_dir=project_rules_dir)
            # Load all common languages
            rules = RuleSet()
            for lang in ["javascript", "typescript", "python", "java", "go", "php"]:
                lang_rules = loader.load_rules(lang)
                rules = rules.merge(lang_rules)
            return rules
        return None

    def clear_cache(self) -> None:
        """Clear the rule cache."""
        self._cache.clear()

    def validate_rules(self, rules: RuleSet) -> list[str]:
        """
        Validate a RuleSet and return any errors found.

        Args:
            rules: RuleSet to validate.

        Returns:
            List of error messages (empty if valid).
        """
        errors = []
        import re

        for rule in rules.sources + rules.sinks + rules.sanitizers:
            # Check required fields
            if not rule.name:
                errors.append("Rule missing 'name' field")
            if not rule.pattern:
                errors.append(f"Rule '{rule.name}' missing 'pattern' field")
            if not rule.type:
                errors.append(f"Rule '{rule.name}' missing 'type' field")

            # Validate regex pattern
            try:
                re.compile(rule.pattern)
            except re.error as e:
                errors.append(f"Rule '{rule.name}' has invalid regex: {e}")

            # Validate confidence range
            if not 0.0 <= rule.confidence <= 1.0:
                errors.append(f"Rule '{rule.name}' has invalid confidence: {rule.confidence}")

            # Validate CWE format
            for cwe in rule.cwe_types:
                if not cwe.startswith("CWE-"):
                    errors.append(f"Rule '{rule.name}' has invalid CWE format: {cwe}")

        return errors
