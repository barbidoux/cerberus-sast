"""
Candidate Extractor for Phase II Spec Inference.

Uses heuristics and Phase I data (RepoMap, PageRank) to identify
function candidates for LLM classification as sources, sinks, or sanitizers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from cerberus.models.base import SymbolType, TaintLabel
from cerberus.models.repo_map import RepoMap, Symbol


class CandidateType(Enum):
    """Type of candidate based on suspected taint role."""

    SOURCE = "source"
    SINK = "sink"
    SANITIZER = "sanitizer"
    PROPAGATOR = "propagator"

    def to_taint_label(self) -> TaintLabel:
        """Convert to TaintLabel enum."""
        return TaintLabel(self.value)


@dataclass
class Candidate:
    """
    A function/method candidate for taint classification.

    Represents a code symbol that might be a source, sink, or sanitizer,
    along with the heuristic score and reasoning for why it was selected.
    """

    symbol: Symbol
    candidate_type: CandidateType
    score: float
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def file_path(self) -> Path:
        """Get the file path from the symbol."""
        return self.symbol.file_path

    @property
    def name(self) -> str:
        """Get the symbol name."""
        return self.symbol.name

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "name": self.symbol.name,
            "type": self.candidate_type.value,
            "file_path": str(self.symbol.file_path),
            "line": self.symbol.line,
            "score": self.score,
            "reason": self.reason,
            "signature": self.symbol.signature,
            "metadata": self.metadata,
        }


@dataclass
class ExtractionConfig:
    """Configuration for candidate extraction."""

    max_candidates: int = 100
    min_score: float = 0.1
    include_methods: bool = True
    pagerank_weight: float = 0.3
    pattern_weight: float = 0.5
    import_weight: float = 0.2


class HeuristicMatcher:
    """
    Pattern-based heuristic matching for candidate identification.

    Uses naming conventions, import patterns, and other heuristics
    to score potential sources, sinks, and sanitizers.
    """

    # Source patterns - functions that introduce tainted data
    SOURCE_PATTERNS: list[tuple[str, float]] = [
        (r"get_.*input", 0.9),
        (r"read_.*request", 0.9),
        (r"fetch_.*param", 0.8),
        (r"get_.*param", 0.8),
        (r"request\.", 0.7),
        (r"get_.*user", 0.7),
        (r"read_.*file", 0.6),
        (r"read_.*data", 0.6),
        (r"input", 0.5),
        (r"getenv", 0.5),
        (r"environ", 0.5),
        (r"argv", 0.5),
        (r"stdin", 0.5),
        (r"fetch", 0.4),
        (r"recv", 0.4),
        (r"receive", 0.4),
    ]

    # Sink patterns - dangerous operations
    SINK_PATTERNS: list[tuple[str, float]] = [
        (r"execute.*query", 0.95),
        (r"exec.*sql", 0.95),
        (r"run.*sql", 0.9),
        (r"execute", 0.7),
        (r"query", 0.6),
        (r"system.*exec", 0.95),
        (r"run.*command", 0.9),
        (r"run.*cmd", 0.9),
        (r"os\.system", 0.95),
        (r"popen", 0.9),
        (r"subprocess", 0.8),
        (r"spawn", 0.7),
        (r"eval", 0.8),
        (r"innerHTML", 0.9),
        (r"dangerously.*html", 0.95),
        (r"write.*file", 0.6),
        (r"open", 0.4),
        (r"render.*template", 0.5),
    ]

    # Sanitizer patterns - validation and cleaning
    SANITIZER_PATTERNS: list[tuple[str, float]] = [
        (r"sanitize", 0.95),
        (r"escape", 0.9),
        (r"clean", 0.7),
        (r"validate", 0.8),
        (r"filter", 0.5),
        (r"encode", 0.6),
        (r"normalize", 0.5),
        (r"strip", 0.4),
        (r"check", 0.3),
        (r"verify", 0.4),
        (r"safe", 0.5),
        (r"whitelist", 0.7),
    ]

    # Import patterns that suggest specific candidate types
    SOURCE_IMPORTS: list[str] = [
        "flask", "django", "request", "fastapi",
        "tornado", "bottle", "aiohttp",
        "sys.argv", "argparse", "click",
        "os.environ", "dotenv",
    ]

    SINK_IMPORTS: list[str] = [
        "sqlite3", "mysql", "psycopg", "pymongo",
        "sqlalchemy", "peewee",
        "subprocess", "os.system", "shlex",
        "eval", "exec",
        "jinja2", "mako", "template",
    ]

    SANITIZER_IMPORTS: list[str] = [
        "html.escape", "markupsafe", "bleach",
        "validators", "cerberus", "pydantic",
        "re", "regex",
    ]

    def match_source_pattern(self, name: str) -> float:
        """
        Match function name against source patterns.

        Returns score between 0 and 1, or 0 if no match.
        """
        name_lower = name.lower()
        max_score = 0.0

        for pattern, score in self.SOURCE_PATTERNS:
            if re.search(pattern, name_lower):
                max_score = max(max_score, score)

        return max_score

    def match_sink_pattern(self, name: str) -> float:
        """
        Match function name against sink patterns.

        Returns score between 0 and 1, or 0 if no match.
        """
        name_lower = name.lower()
        max_score = 0.0

        for pattern, score in self.SINK_PATTERNS:
            if re.search(pattern, name_lower):
                max_score = max(max_score, score)

        return max_score

    def match_sanitizer_pattern(self, name: str) -> float:
        """
        Match function name against sanitizer patterns.

        Returns score between 0 and 1, or 0 if no match.
        """
        name_lower = name.lower()
        max_score = 0.0

        for pattern, score in self.SANITIZER_PATTERNS:
            if re.search(pattern, name_lower):
                max_score = max(max_score, score)

        return max_score

    def score_from_imports(
        self,
        imports: list[str],
        candidate_type: CandidateType,
    ) -> float:
        """
        Score based on file imports.

        Returns a boost score based on relevant imports.
        """
        if not imports:
            return 0.0

        imports_lower = " ".join(imports).lower()

        if candidate_type == CandidateType.SOURCE:
            patterns = self.SOURCE_IMPORTS
        elif candidate_type == CandidateType.SINK:
            patterns = self.SINK_IMPORTS
        elif candidate_type == CandidateType.SANITIZER:
            patterns = self.SANITIZER_IMPORTS
        else:
            return 0.0

        score = 0.0
        for pattern in patterns:
            if pattern.lower() in imports_lower:
                score += 0.2

        return min(score, 0.5)  # Cap at 0.5


class CandidateExtractor:
    """
    Extracts candidate functions for taint classification.

    Uses heuristics, import analysis, and PageRank scores to
    identify and prioritize functions that are likely to be
    sources, sinks, or sanitizers.
    """

    def __init__(self, config: Optional[ExtractionConfig] = None) -> None:
        """Initialize extractor with optional configuration."""
        self.config = config or ExtractionConfig()
        self.matcher = HeuristicMatcher()

    def extract(self, repo_map: RepoMap) -> list[Candidate]:
        """
        Extract all candidate types from repository.

        Args:
            repo_map: Repository structural map from Phase I

        Returns:
            List of candidates sorted by score descending
        """
        candidates: list[Candidate] = []

        # Extract candidates of each type
        candidates.extend(self._extract_type(repo_map, CandidateType.SOURCE))
        candidates.extend(self._extract_type(repo_map, CandidateType.SINK))
        candidates.extend(self._extract_type(repo_map, CandidateType.SANITIZER))

        # Sort by score descending
        candidates.sort(key=lambda c: c.score, reverse=True)

        # Apply filters
        candidates = [c for c in candidates if c.score >= self.config.min_score]
        candidates = candidates[:self.config.max_candidates]

        return candidates

    def extract_sources(self, repo_map: RepoMap) -> list[Candidate]:
        """Extract only source candidates."""
        candidates = self._extract_type(repo_map, CandidateType.SOURCE)
        candidates.sort(key=lambda c: c.score, reverse=True)
        candidates = [c for c in candidates if c.score >= self.config.min_score]
        return candidates[:self.config.max_candidates]

    def extract_sinks(self, repo_map: RepoMap) -> list[Candidate]:
        """Extract only sink candidates."""
        candidates = self._extract_type(repo_map, CandidateType.SINK)
        candidates.sort(key=lambda c: c.score, reverse=True)
        candidates = [c for c in candidates if c.score >= self.config.min_score]
        return candidates[:self.config.max_candidates]

    def extract_sanitizers(self, repo_map: RepoMap) -> list[Candidate]:
        """Extract only sanitizer candidates."""
        candidates = self._extract_type(repo_map, CandidateType.SANITIZER)
        candidates.sort(key=lambda c: c.score, reverse=True)
        candidates = [c for c in candidates if c.score >= self.config.min_score]
        return candidates[:self.config.max_candidates]

    def _extract_type(
        self,
        repo_map: RepoMap,
        candidate_type: CandidateType,
    ) -> list[Candidate]:
        """Extract candidates of a specific type."""
        candidates: list[Candidate] = []

        for file_info in repo_map.files:
            # Get PageRank score for this file
            pagerank = repo_map.rankings.get(str(file_info.path), 0.0)

            for symbol in file_info.symbols:
                # Only consider functions and methods
                if symbol.type == SymbolType.FUNCTION:
                    pass  # Always include functions
                elif symbol.type == SymbolType.METHOD:
                    if not self.config.include_methods:
                        continue
                else:
                    continue

                # Calculate score for this candidate type
                candidate = self._score_symbol(
                    symbol=symbol,
                    candidate_type=candidate_type,
                    imports=file_info.imports,
                    pagerank=pagerank,
                )

                if candidate and candidate.score > 0:
                    candidates.append(candidate)

        return candidates

    def _score_symbol(
        self,
        symbol: Symbol,
        candidate_type: CandidateType,
        imports: list[str],
        pagerank: float,
    ) -> Optional[Candidate]:
        """
        Score a symbol as a candidate of the given type.

        Combines pattern matching, import analysis, and PageRank.
        """
        # Get pattern match score
        if candidate_type == CandidateType.SOURCE:
            pattern_score = self.matcher.match_source_pattern(symbol.name)
        elif candidate_type == CandidateType.SINK:
            pattern_score = self.matcher.match_sink_pattern(symbol.name)
        elif candidate_type == CandidateType.SANITIZER:
            pattern_score = self.matcher.match_sanitizer_pattern(symbol.name)
        else:
            pattern_score = 0.0

        # No match - skip
        if pattern_score == 0:
            return None

        # Get import boost
        import_score = self.matcher.score_from_imports(imports, candidate_type)

        # Calculate weighted score
        weighted_score = (
            self.config.pattern_weight * pattern_score +
            self.config.import_weight * import_score +
            self.config.pagerank_weight * pagerank
        )

        # Build reason string
        reasons = []
        if pattern_score > 0:
            reasons.append(f"name pattern ({pattern_score:.2f})")
        if import_score > 0:
            reasons.append(f"imports ({import_score:.2f})")
        if pagerank > 0:
            reasons.append(f"PageRank ({pagerank:.2f})")

        return Candidate(
            symbol=symbol,
            candidate_type=candidate_type,
            score=weighted_score,
            reason=f"Matched: {', '.join(reasons)}",
            metadata={
                "pattern_score": pattern_score,
                "import_score": import_score,
                "pagerank": pagerank,
            },
        )
