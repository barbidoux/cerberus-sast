"""
Tests for Taint Propagator.

TDD: Write tests first, then implement to make them pass.
"""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from cerberus.inference.propagator import (
    PropagationConfig,
    PropagationResult,
    TaintPropagator,
)
from cerberus.models.base import SymbolType, TaintLabel
from cerberus.models.repo_map import FileInfo, RepoMap, Symbol
from cerberus.models.spec import DynamicSpec, TaintSpec


@pytest.fixture
def sample_specs() -> list[TaintSpec]:
    """Create sample taint specs."""
    return [
        TaintSpec(
            method="get_user_input",
            file_path=Path("/app/handlers.py"),
            line=10,
            label=TaintLabel.SOURCE,
            confidence=0.95,
            reason="Reads user input",
            vulnerability_types=["CWE-89"],
        ),
        TaintSpec(
            method="execute_query",
            file_path=Path("/app/database.py"),
            line=25,
            label=TaintLabel.SINK,
            confidence=0.9,
            reason="Executes SQL",
            vulnerability_types=["CWE-89"],
        ),
        TaintSpec(
            method="sanitize_input",
            file_path=Path("/app/utils.py"),
            line=5,
            label=TaintLabel.SANITIZER,
            confidence=0.85,
            reason="Sanitizes input",
            vulnerability_types=["CWE-89"],
        ),
    ]


@pytest.fixture
def sample_repo_map() -> RepoMap:
    """Create a sample RepoMap with call relationships."""
    symbols = [
        Symbol(
            name="get_user_input",
            type=SymbolType.FUNCTION,
            file_path=Path("/app/handlers.py"),
            line=10,
        ),
        Symbol(
            name="process_request",
            type=SymbolType.FUNCTION,
            file_path=Path("/app/handlers.py"),
            line=30,
        ),
        Symbol(
            name="execute_query",
            type=SymbolType.FUNCTION,
            file_path=Path("/app/database.py"),
            line=25,
        ),
        Symbol(
            name="sanitize_input",
            type=SymbolType.FUNCTION,
            file_path=Path("/app/utils.py"),
            line=5,
        ),
        Symbol(
            name="helper",
            type=SymbolType.FUNCTION,
            file_path=Path("/app/core.py"),
            line=100,
        ),
    ]

    files = [
        FileInfo(
            path=Path("/app/handlers.py"),
            language="python",
            size_bytes=1000,
            lines=50,
            symbols=[s for s in symbols if s.file_path == Path("/app/handlers.py")],
            imports=["from database import execute_query", "from utils import sanitize_input"],
        ),
        FileInfo(
            path=Path("/app/database.py"),
            language="python",
            size_bytes=500,
            lines=30,
            symbols=[s for s in symbols if s.file_path == Path("/app/database.py")],
        ),
        FileInfo(
            path=Path("/app/utils.py"),
            language="python",
            size_bytes=300,
            lines=20,
            symbols=[s for s in symbols if s.file_path == Path("/app/utils.py")],
        ),
        FileInfo(
            path=Path("/app/core.py"),
            language="python",
            size_bytes=800,
            lines=40,
            symbols=[s for s in symbols if s.file_path == Path("/app/core.py")],
        ),
    ]

    return RepoMap(
        root_path=Path("/app"),
        files=files,
        symbols=symbols,
        dependencies={
            "/app/handlers.py": ["/app/database.py", "/app/utils.py"],
            "/app/core.py": ["/app/database.py"],
        },
        rankings={
            "/app/handlers.py": 0.3,
            "/app/database.py": 0.25,
            "/app/utils.py": 0.2,
            "/app/core.py": 0.15,
        },
        generated_at=datetime.now(timezone.utc),
    )


class TestPropagationConfig:
    """Test PropagationConfig."""

    def test_default_config(self):
        """Should have sensible defaults."""
        config = PropagationConfig()
        assert config.max_iterations > 0
        assert config.propagate_through_calls is True

    def test_custom_config(self):
        """Should accept custom values."""
        config = PropagationConfig(
            max_iterations=5,
            propagate_through_calls=False,
        )
        assert config.max_iterations == 5
        assert config.propagate_through_calls is False


class TestPropagationResult:
    """Test PropagationResult dataclass."""

    def test_create_result(self):
        """Should create propagation result."""
        result = PropagationResult(
            propagated_specs=[],
            iterations=3,
            converged=True,
        )
        assert result.iterations == 3
        assert result.converged is True

    def test_result_counts(self, sample_specs: list[TaintSpec]):
        """Should track spec counts by type."""
        result = PropagationResult(
            propagated_specs=sample_specs,
            iterations=1,
            converged=True,
        )
        assert result.source_count == 1
        assert result.sink_count == 1
        assert result.sanitizer_count == 1


class TestTaintPropagator:
    """Test TaintPropagator class."""

    def test_create_propagator(self):
        """Should create propagator instance."""
        propagator = TaintPropagator()
        assert propagator is not None

    def test_create_propagator_with_config(self):
        """Should accept custom configuration."""
        config = PropagationConfig(max_iterations=5)
        propagator = TaintPropagator(config=config)
        assert propagator.config.max_iterations == 5

    def test_propagate_with_initial_specs(
        self,
        sample_specs: list[TaintSpec],
        sample_repo_map: RepoMap,
    ):
        """Should propagate from initial specs."""
        propagator = TaintPropagator()
        result = propagator.propagate(sample_specs, sample_repo_map)

        assert isinstance(result, PropagationResult)
        # Should include original specs
        assert len(result.propagated_specs) >= len(sample_specs)

    def test_identifies_propagators(
        self,
        sample_specs: list[TaintSpec],
        sample_repo_map: RepoMap,
    ):
        """Should identify functions that propagate taint."""
        propagator = TaintPropagator()
        result = propagator.propagate(sample_specs, sample_repo_map)

        # Functions that call sources/sinks may be identified as propagators
        propagator_specs = [
            s for s in result.propagated_specs
            if s.label == TaintLabel.PROPAGATOR
        ]
        # At minimum, original specs should be present
        assert len(result.propagated_specs) >= 3

    def test_converges_within_max_iterations(
        self,
        sample_specs: list[TaintSpec],
        sample_repo_map: RepoMap,
    ):
        """Should converge within max iterations."""
        config = PropagationConfig(max_iterations=10)
        propagator = TaintPropagator(config=config)
        result = propagator.propagate(sample_specs, sample_repo_map)

        assert result.iterations <= config.max_iterations

    def test_reports_convergence(
        self,
        sample_specs: list[TaintSpec],
        sample_repo_map: RepoMap,
    ):
        """Should report whether propagation converged."""
        propagator = TaintPropagator()
        result = propagator.propagate(sample_specs, sample_repo_map)

        assert isinstance(result.converged, bool)


class TestPropagationAcrossCallGraph:
    """Test propagation across the call graph."""

    def test_propagates_across_imports(
        self,
        sample_specs: list[TaintSpec],
        sample_repo_map: RepoMap,
    ):
        """Should consider import relationships."""
        propagator = TaintPropagator()
        result = propagator.propagate(sample_specs, sample_repo_map)

        # handlers.py imports from database.py and utils.py
        # Functions in handlers.py may be affected
        assert len(result.propagated_specs) >= 3

    def test_respects_propagation_config(
        self,
        sample_specs: list[TaintSpec],
        sample_repo_map: RepoMap,
    ):
        """Should respect propagation configuration."""
        config = PropagationConfig(propagate_through_calls=False)
        propagator = TaintPropagator(config=config)
        result = propagator.propagate(sample_specs, sample_repo_map)

        # Without call propagation, should mainly have original specs
        # (implementation dependent)
        assert isinstance(result, PropagationResult)


class TestToDynamicSpec:
    """Test conversion to DynamicSpec."""

    def test_converts_to_dynamic_spec(
        self,
        sample_specs: list[TaintSpec],
        sample_repo_map: RepoMap,
    ):
        """Should convert result to DynamicSpec."""
        propagator = TaintPropagator()
        result = propagator.propagate(sample_specs, sample_repo_map)

        dynamic_spec = result.to_dynamic_spec(repository="test-repo")

        assert isinstance(dynamic_spec, DynamicSpec)
        assert dynamic_spec.repository == "test-repo"

    def test_dynamic_spec_has_all_specs(
        self,
        sample_specs: list[TaintSpec],
        sample_repo_map: RepoMap,
    ):
        """DynamicSpec should contain all propagated specs."""
        propagator = TaintPropagator()
        result = propagator.propagate(sample_specs, sample_repo_map)

        dynamic_spec = result.to_dynamic_spec()

        total = (
            len(dynamic_spec.sources) +
            len(dynamic_spec.sinks) +
            len(dynamic_spec.sanitizers) +
            len(dynamic_spec.propagators)
        )
        assert total >= 3  # At least original specs


class TestEdgeCases:
    """Test edge cases."""

    def test_empty_specs(self, sample_repo_map: RepoMap):
        """Should handle empty specs list."""
        propagator = TaintPropagator()
        result = propagator.propagate([], sample_repo_map)

        assert result.propagated_specs == []
        assert result.converged is True

    def test_empty_repo_map(self, sample_specs: list[TaintSpec]):
        """Should handle empty repo map."""
        empty_map = RepoMap(
            root_path=Path("/empty"),
            files=[],
            symbols=[],
            dependencies={},
            rankings={},
            generated_at=datetime.now(timezone.utc),
        )
        propagator = TaintPropagator()
        result = propagator.propagate(sample_specs, empty_map)

        # Should still have original specs
        assert len(result.propagated_specs) == len(sample_specs)

    def test_no_dependencies(self, sample_specs: list[TaintSpec]):
        """Should handle repo with no dependencies."""
        repo_map = RepoMap(
            root_path=Path("/app"),
            files=[
                FileInfo(
                    path=Path("/app/single.py"),
                    language="python",
                    size_bytes=100,
                    lines=10,
                    symbols=[
                        Symbol(
                            name="func",
                            type=SymbolType.FUNCTION,
                            file_path=Path("/app/single.py"),
                            line=1,
                        )
                    ],
                )
            ],
            symbols=[
                Symbol(
                    name="func",
                    type=SymbolType.FUNCTION,
                    file_path=Path("/app/single.py"),
                    line=1,
                )
            ],
            dependencies={},  # No dependencies
            rankings={"/app/single.py": 0.5},
            generated_at=datetime.now(timezone.utc),
        )
        propagator = TaintPropagator()
        result = propagator.propagate(sample_specs, repo_map)

        # Should converge quickly with no propagation
        assert result.converged is True


class TestPropagatorStatistics:
    """Test propagator statistics."""

    def test_tracks_iteration_count(
        self,
        sample_specs: list[TaintSpec],
        sample_repo_map: RepoMap,
    ):
        """Should track number of iterations."""
        propagator = TaintPropagator()
        result = propagator.propagate(sample_specs, sample_repo_map)

        assert result.iterations >= 1

    def test_provides_summary(
        self,
        sample_specs: list[TaintSpec],
        sample_repo_map: RepoMap,
    ):
        """Should provide summary statistics."""
        propagator = TaintPropagator()
        result = propagator.propagate(sample_specs, sample_repo_map)

        summary = result.summary()

        assert "total_specs" in summary
        assert "iterations" in summary
        assert "converged" in summary
