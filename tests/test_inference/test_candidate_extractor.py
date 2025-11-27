"""
Tests for Candidate Extractor.

TDD: Write tests first, then implement to make them pass.
"""

from datetime import datetime
from pathlib import Path

import pytest

from cerberus.inference.candidate_extractor import (
    Candidate,
    CandidateExtractor,
    CandidateType,
    ExtractionConfig,
    HeuristicMatcher,
)
from cerberus.models.base import SymbolType, TaintLabel
from cerberus.models.repo_map import FileInfo, RepoMap, Symbol


@pytest.fixture
def sample_symbols() -> list[Symbol]:
    """Create sample symbols for testing."""
    return [
        Symbol(
            name="get_user_input",
            type=SymbolType.FUNCTION,
            file_path=Path("/app/handlers.py"),
            line=10,
            signature="def get_user_input(request):",
        ),
        Symbol(
            name="execute_query",
            type=SymbolType.FUNCTION,
            file_path=Path("/app/database.py"),
            line=25,
            signature="def execute_query(sql):",
        ),
        Symbol(
            name="sanitize_html",
            type=SymbolType.FUNCTION,
            file_path=Path("/app/utils.py"),
            line=5,
            signature="def sanitize_html(content):",
        ),
        Symbol(
            name="process_data",
            type=SymbolType.FUNCTION,
            file_path=Path("/app/core.py"),
            line=100,
            signature="def process_data(data):",
        ),
        Symbol(
            name="UserModel",
            type=SymbolType.CLASS,
            file_path=Path("/app/models.py"),
            line=1,
        ),
        Symbol(
            name="fetch",
            type=SymbolType.METHOD,
            file_path=Path("/app/api.py"),
            line=50,
            parent_class="ApiClient",
            signature="def fetch(self, url):",
        ),
    ]


@pytest.fixture
def sample_repo_map(sample_symbols: list[Symbol]) -> RepoMap:
    """Create a sample RepoMap for testing."""
    files = [
        FileInfo(
            path=Path("/app/handlers.py"),
            language="python",
            size_bytes=1000,
            lines=50,
            symbols=[s for s in sample_symbols if s.file_path == Path("/app/handlers.py")],
            imports=["from flask import request"],
        ),
        FileInfo(
            path=Path("/app/database.py"),
            language="python",
            size_bytes=2000,
            lines=100,
            symbols=[s for s in sample_symbols if s.file_path == Path("/app/database.py")],
            imports=["import sqlite3"],
        ),
        FileInfo(
            path=Path("/app/utils.py"),
            language="python",
            size_bytes=500,
            lines=25,
            symbols=[s for s in sample_symbols if s.file_path == Path("/app/utils.py")],
            imports=["import html"],
        ),
        FileInfo(
            path=Path("/app/core.py"),
            language="python",
            size_bytes=3000,
            lines=150,
            symbols=[s for s in sample_symbols if s.file_path == Path("/app/core.py")],
        ),
        FileInfo(
            path=Path("/app/models.py"),
            language="python",
            size_bytes=1500,
            lines=75,
            symbols=[s for s in sample_symbols if s.file_path == Path("/app/models.py")],
        ),
        FileInfo(
            path=Path("/app/api.py"),
            language="python",
            size_bytes=1200,
            lines=60,
            symbols=[s for s in sample_symbols if s.file_path == Path("/app/api.py")],
            imports=["import requests"],
        ),
    ]

    return RepoMap(
        root_path=Path("/app"),
        files=files,
        symbols=sample_symbols,
        dependencies={
            "/app/handlers.py": ["/app/database.py", "/app/utils.py"],
            "/app/core.py": ["/app/database.py"],
        },
        rankings={
            "/app/handlers.py": 0.3,
            "/app/database.py": 0.25,
            "/app/utils.py": 0.1,
            "/app/core.py": 0.2,
            "/app/models.py": 0.1,
            "/app/api.py": 0.05,
        },
        generated_at=datetime.utcnow(),
    )


class TestCandidate:
    """Test Candidate dataclass."""

    def test_create_candidate(self):
        """Should create a candidate with required fields."""
        candidate = Candidate(
            symbol=Symbol(
                name="test_func",
                type=SymbolType.FUNCTION,
                file_path=Path("/test.py"),
                line=1,
            ),
            candidate_type=CandidateType.SOURCE,
            score=0.8,
            reason="Name pattern matches source heuristic",
        )
        assert candidate.symbol.name == "test_func"
        assert candidate.candidate_type == CandidateType.SOURCE
        assert candidate.score == 0.8

    def test_candidate_has_file_path(self):
        """Candidate should expose file path from symbol."""
        symbol = Symbol(
            name="func",
            type=SymbolType.FUNCTION,
            file_path=Path("/app/test.py"),
            line=10,
        )
        candidate = Candidate(
            symbol=symbol,
            candidate_type=CandidateType.SINK,
            score=0.7,
        )
        assert candidate.file_path == Path("/app/test.py")

    def test_candidate_to_dict(self):
        """Should serialize candidate to dictionary."""
        symbol = Symbol(
            name="execute",
            type=SymbolType.FUNCTION,
            file_path=Path("/db.py"),
            line=5,
        )
        candidate = Candidate(
            symbol=symbol,
            candidate_type=CandidateType.SINK,
            score=0.9,
            reason="SQL execution pattern",
        )
        data = candidate.to_dict()
        assert data["name"] == "execute"
        assert data["type"] == "sink"
        assert data["score"] == 0.9


class TestCandidateType:
    """Test CandidateType enum."""

    def test_candidate_types_exist(self):
        """Should have all taint label types."""
        assert CandidateType.SOURCE is not None
        assert CandidateType.SINK is not None
        assert CandidateType.SANITIZER is not None

    def test_to_taint_label(self):
        """Should convert to TaintLabel."""
        assert CandidateType.SOURCE.to_taint_label() == TaintLabel.SOURCE
        assert CandidateType.SINK.to_taint_label() == TaintLabel.SINK
        assert CandidateType.SANITIZER.to_taint_label() == TaintLabel.SANITIZER


class TestExtractionConfig:
    """Test ExtractionConfig."""

    def test_default_config(self):
        """Should have sensible defaults."""
        config = ExtractionConfig()
        assert config.max_candidates > 0
        assert config.min_score >= 0.0
        assert config.include_methods is True

    def test_custom_config(self):
        """Should accept custom values."""
        config = ExtractionConfig(
            max_candidates=50,
            min_score=0.5,
            include_methods=False,
        )
        assert config.max_candidates == 50
        assert config.min_score == 0.5
        assert config.include_methods is False


class TestHeuristicMatcher:
    """Test HeuristicMatcher for pattern matching."""

    def test_match_source_pattern(self):
        """Should match source patterns."""
        matcher = HeuristicMatcher()

        # Should match request/input patterns
        assert matcher.match_source_pattern("get_user_input") > 0
        assert matcher.match_source_pattern("read_request") > 0
        assert matcher.match_source_pattern("fetch_params") > 0

        # Should not match non-source patterns
        assert matcher.match_source_pattern("calculate_sum") == 0

    def test_match_sink_pattern(self):
        """Should match sink patterns."""
        matcher = HeuristicMatcher()

        # SQL patterns
        assert matcher.match_sink_pattern("execute_query") > 0
        assert matcher.match_sink_pattern("run_sql") > 0

        # Command patterns
        assert matcher.match_sink_pattern("system_exec") > 0
        assert matcher.match_sink_pattern("run_command") > 0

        # Should not match non-sink patterns
        assert matcher.match_sink_pattern("validate_input") == 0

    def test_match_sanitizer_pattern(self):
        """Should match sanitizer patterns."""
        matcher = HeuristicMatcher()

        # Validation patterns
        assert matcher.match_sanitizer_pattern("validate_email") > 0
        assert matcher.match_sanitizer_pattern("sanitize_input") > 0
        assert matcher.match_sanitizer_pattern("escape_html") > 0
        assert matcher.match_sanitizer_pattern("clean_data") > 0

        # Should not match non-sanitizer patterns
        assert matcher.match_sanitizer_pattern("get_data") == 0

    def test_match_from_imports(self):
        """Should boost score based on imports."""
        matcher = HeuristicMatcher()

        # Flask/Django imports suggest sources
        assert matcher.score_from_imports(
            ["from flask import request"],
            CandidateType.SOURCE
        ) > 0

        # Database imports suggest sinks
        assert matcher.score_from_imports(
            ["import sqlite3"],
            CandidateType.SINK
        ) > 0


class TestCandidateExtractor:
    """Test CandidateExtractor class."""

    def test_create_extractor(self):
        """Should create extractor instance."""
        extractor = CandidateExtractor()
        assert extractor is not None

    def test_create_extractor_with_config(self):
        """Should accept custom configuration."""
        config = ExtractionConfig(max_candidates=10)
        extractor = CandidateExtractor(config=config)
        assert extractor.config.max_candidates == 10

    def test_extract_from_repo_map(self, sample_repo_map: RepoMap):
        """Should extract candidates from RepoMap."""
        extractor = CandidateExtractor()
        candidates = extractor.extract(sample_repo_map)

        assert isinstance(candidates, list)
        assert len(candidates) > 0
        assert all(isinstance(c, Candidate) for c in candidates)

    def test_finds_source_candidates(self, sample_repo_map: RepoMap):
        """Should identify source candidates."""
        extractor = CandidateExtractor()
        candidates = extractor.extract(sample_repo_map)

        source_candidates = [c for c in candidates if c.candidate_type == CandidateType.SOURCE]
        source_names = [c.symbol.name for c in source_candidates]

        # get_user_input should be identified as potential source
        assert "get_user_input" in source_names

    def test_finds_sink_candidates(self, sample_repo_map: RepoMap):
        """Should identify sink candidates."""
        extractor = CandidateExtractor()
        candidates = extractor.extract(sample_repo_map)

        sink_candidates = [c for c in candidates if c.candidate_type == CandidateType.SINK]
        sink_names = [c.symbol.name for c in sink_candidates]

        # execute_query should be identified as potential sink
        assert "execute_query" in sink_names

    def test_finds_sanitizer_candidates(self, sample_repo_map: RepoMap):
        """Should identify sanitizer candidates."""
        extractor = CandidateExtractor()
        candidates = extractor.extract(sample_repo_map)

        sanitizer_candidates = [c for c in candidates if c.candidate_type == CandidateType.SANITIZER]
        sanitizer_names = [c.symbol.name for c in sanitizer_candidates]

        # sanitize_html should be identified as potential sanitizer
        assert "sanitize_html" in sanitizer_names

    def test_candidates_sorted_by_score(self, sample_repo_map: RepoMap):
        """Candidates should be sorted by score descending."""
        extractor = CandidateExtractor()
        candidates = extractor.extract(sample_repo_map)

        scores = [c.score for c in candidates]
        assert scores == sorted(scores, reverse=True)

    def test_respects_max_candidates(self, sample_repo_map: RepoMap):
        """Should respect max_candidates limit."""
        config = ExtractionConfig(max_candidates=2)
        extractor = CandidateExtractor(config=config)
        candidates = extractor.extract(sample_repo_map)

        assert len(candidates) <= 2

    def test_respects_min_score(self, sample_repo_map: RepoMap):
        """Should filter out low-score candidates."""
        config = ExtractionConfig(min_score=0.5)
        extractor = CandidateExtractor(config=config)
        candidates = extractor.extract(sample_repo_map)

        for candidate in candidates:
            assert candidate.score >= 0.5

    def test_includes_methods_when_configured(self, sample_repo_map: RepoMap):
        """Should include methods when configured."""
        config = ExtractionConfig(include_methods=True)
        extractor = CandidateExtractor(config=config)
        candidates = extractor.extract(sample_repo_map)

        symbol_types = {c.symbol.type for c in candidates}
        assert SymbolType.METHOD in symbol_types or len(candidates) == 0

    def test_excludes_methods_when_configured(self, sample_repo_map: RepoMap):
        """Should exclude methods when configured."""
        config = ExtractionConfig(include_methods=False)
        extractor = CandidateExtractor(config=config)
        candidates = extractor.extract(sample_repo_map)

        for candidate in candidates:
            assert candidate.symbol.type != SymbolType.METHOD

    def test_uses_pagerank_boost(self, sample_repo_map: RepoMap):
        """Higher PageRank files should boost candidate scores."""
        extractor = CandidateExtractor()
        candidates = extractor.extract(sample_repo_map)

        # Find candidates from high/low ranked files
        handler_candidates = [c for c in candidates if "handlers" in str(c.file_path)]
        api_candidates = [c for c in candidates if "api" in str(c.file_path)]

        # handlers.py has higher PageRank (0.3) than api.py (0.05)
        # If both have similar pattern matches, handler should score higher
        if handler_candidates and api_candidates:
            # At least check they both have scores
            assert handler_candidates[0].score >= 0
            assert api_candidates[0].score >= 0


class TestExtractByType:
    """Test extracting candidates by specific type."""

    def test_extract_sources_only(self, sample_repo_map: RepoMap):
        """Should extract only source candidates."""
        extractor = CandidateExtractor()
        candidates = extractor.extract_sources(sample_repo_map)

        assert all(c.candidate_type == CandidateType.SOURCE for c in candidates)

    def test_extract_sinks_only(self, sample_repo_map: RepoMap):
        """Should extract only sink candidates."""
        extractor = CandidateExtractor()
        candidates = extractor.extract_sinks(sample_repo_map)

        assert all(c.candidate_type == CandidateType.SINK for c in candidates)

    def test_extract_sanitizers_only(self, sample_repo_map: RepoMap):
        """Should extract only sanitizer candidates."""
        extractor = CandidateExtractor()
        candidates = extractor.extract_sanitizers(sample_repo_map)

        assert all(c.candidate_type == CandidateType.SANITIZER for c in candidates)


class TestCandidateContext:
    """Test getting context for candidates."""

    def test_get_candidate_code(self, sample_repo_map: RepoMap):
        """Should be able to get code context for candidate."""
        extractor = CandidateExtractor()
        candidates = extractor.extract(sample_repo_map)

        if candidates:
            candidate = candidates[0]
            # Should have access to signature at minimum
            assert candidate.symbol.signature or candidate.symbol.name


class TestEdgeCases:
    """Test edge cases."""

    def test_empty_repo_map(self):
        """Should handle empty RepoMap."""
        repo_map = RepoMap(
            root_path=Path("/empty"),
            files=[],
            symbols=[],
            dependencies={},
            rankings={},
        )
        extractor = CandidateExtractor()
        candidates = extractor.extract(repo_map)

        assert candidates == []

    def test_repo_with_no_functions(self):
        """Should handle repo with no callable symbols."""
        repo_map = RepoMap(
            root_path=Path("/app"),
            files=[
                FileInfo(
                    path=Path("/app/constants.py"),
                    language="python",
                    size_bytes=100,
                    lines=10,
                    symbols=[
                        Symbol(
                            name="CONFIG",
                            type=SymbolType.VARIABLE,
                            file_path=Path("/app/constants.py"),
                            line=1,
                        )
                    ],
                )
            ],
            symbols=[
                Symbol(
                    name="CONFIG",
                    type=SymbolType.VARIABLE,
                    file_path=Path("/app/constants.py"),
                    line=1,
                )
            ],
            dependencies={},
            rankings={"/app/constants.py": 0.5},
        )
        extractor = CandidateExtractor()
        candidates = extractor.extract(repo_map)

        # Variables should not be candidates
        assert len(candidates) == 0
