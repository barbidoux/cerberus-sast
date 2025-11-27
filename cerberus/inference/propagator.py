"""
Taint Propagator for Phase II Spec Inference.

Propagates taint labels across the call graph using fixpoint iteration.
Identifies propagator functions that pass tainted data through.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cerberus.models.base import TaintLabel
from cerberus.models.repo_map import RepoMap
from cerberus.models.spec import DynamicSpec, TaintSpec


@dataclass
class PropagationConfig:
    """Configuration for taint propagation."""

    max_iterations: int = 10
    propagate_through_calls: bool = True
    min_confidence_for_propagation: float = 0.5


@dataclass
class PropagationResult:
    """
    Result of taint propagation.

    Contains all propagated specs and metadata about the propagation process.
    """

    propagated_specs: list[TaintSpec]
    iterations: int
    converged: bool
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def source_count(self) -> int:
        """Count of SOURCE specs."""
        return len([s for s in self.propagated_specs if s.label == TaintLabel.SOURCE])

    @property
    def sink_count(self) -> int:
        """Count of SINK specs."""
        return len([s for s in self.propagated_specs if s.label == TaintLabel.SINK])

    @property
    def sanitizer_count(self) -> int:
        """Count of SANITIZER specs."""
        return len([s for s in self.propagated_specs if s.label == TaintLabel.SANITIZER])

    @property
    def propagator_count(self) -> int:
        """Count of PROPAGATOR specs."""
        return len([s for s in self.propagated_specs if s.label == TaintLabel.PROPAGATOR])

    def to_dynamic_spec(self, repository: str = "") -> DynamicSpec:
        """
        Convert to DynamicSpec.

        Args:
            repository: Repository name

        Returns:
            DynamicSpec containing all propagated specs
        """
        spec = DynamicSpec(
            repository=repository,
            generated_at=datetime.now(timezone.utc),
            metadata={
                "propagation_iterations": self.iterations,
                "converged": self.converged,
            },
        )

        for taint_spec in self.propagated_specs:
            if taint_spec.label == TaintLabel.SOURCE:
                spec.add_source(taint_spec)
            elif taint_spec.label == TaintLabel.SINK:
                spec.add_sink(taint_spec)
            elif taint_spec.label == TaintLabel.SANITIZER:
                spec.add_sanitizer(taint_spec)
            elif taint_spec.label == TaintLabel.PROPAGATOR:
                spec.add_propagator(taint_spec)

        return spec

    def summary(self) -> dict[str, Any]:
        """Generate summary statistics."""
        return {
            "total_specs": len(self.propagated_specs),
            "sources": self.source_count,
            "sinks": self.sink_count,
            "sanitizers": self.sanitizer_count,
            "propagators": self.propagator_count,
            "iterations": self.iterations,
            "converged": self.converged,
        }


class TaintPropagator:
    """
    Propagates taint labels across the dependency graph.

    Uses fixpoint iteration to identify functions that propagate
    tainted data from sources to sinks.
    """

    def __init__(self, config: Optional[PropagationConfig] = None) -> None:
        """Initialize propagator with optional configuration."""
        self.config = config or PropagationConfig()

    def propagate(
        self,
        initial_specs: list[TaintSpec],
        repo_map: RepoMap,
    ) -> PropagationResult:
        """
        Propagate taint labels across the call graph.

        Uses fixpoint iteration to identify propagator functions
        that pass tainted data through.

        Args:
            initial_specs: Initial taint specs from classification
            repo_map: Repository map with dependency information

        Returns:
            PropagationResult with all propagated specs
        """
        if not initial_specs:
            return PropagationResult(
                propagated_specs=[],
                iterations=0,
                converged=True,
            )

        # Initialize spec set with copies of initial specs
        current_specs: dict[str, TaintSpec] = {}
        for spec in initial_specs:
            key = self._spec_key(spec)
            current_specs[key] = spec

        # Build lookup maps
        file_to_specs = self._build_file_lookup(initial_specs)
        symbol_to_file = self._build_symbol_lookup(repo_map)

        # Fixpoint iteration
        iteration = 0
        converged = False

        while iteration < self.config.max_iterations and not converged:
            iteration += 1
            prev_count = len(current_specs)

            if self.config.propagate_through_calls:
                # Propagate through call relationships
                new_specs = self._propagate_through_dependencies(
                    current_specs=current_specs,
                    repo_map=repo_map,
                    file_to_specs=file_to_specs,
                    symbol_to_file=symbol_to_file,
                )

                # Add new specs
                for key, spec in new_specs.items():
                    if key not in current_specs:
                        current_specs[key] = spec
                        # Update file lookup
                        file_key = str(spec.file_path)
                        if file_key not in file_to_specs:
                            file_to_specs[file_key] = []
                        file_to_specs[file_key].append(spec)

            # Check for convergence
            if len(current_specs) == prev_count:
                converged = True

        return PropagationResult(
            propagated_specs=list(current_specs.values()),
            iterations=iteration,
            converged=converged,
            metadata={
                "initial_count": len(initial_specs),
                "final_count": len(current_specs),
            },
        )

    def _propagate_through_dependencies(
        self,
        current_specs: dict[str, TaintSpec],
        repo_map: RepoMap,
        file_to_specs: dict[str, list[TaintSpec]],
        symbol_to_file: dict[str, Path],
    ) -> dict[str, TaintSpec]:
        """
        Propagate specs through file dependencies.

        If a file imports another file with taint specs, functions
        in the importing file may be propagators.
        """
        new_specs: dict[str, TaintSpec] = {}

        for file_path, deps in repo_map.dependencies.items():
            # Check if this file imports files with taint specs
            has_source_dep = False
            has_sink_dep = False

            for dep in deps:
                if dep in file_to_specs:
                    for spec in file_to_specs[dep]:
                        if spec.label == TaintLabel.SOURCE:
                            has_source_dep = True
                        elif spec.label == TaintLabel.SINK:
                            has_sink_dep = True

            # If file imports both source and sink, its functions may be propagators
            if has_source_dep or has_sink_dep:
                file_info = repo_map.get_file(file_path)
                if file_info:
                    for symbol in file_info.symbols:
                        # Only consider functions and methods
                        if symbol.type.value not in ("function", "method"):
                            continue

                        # Don't re-classify existing specs
                        key = f"{symbol.file_path}:{symbol.line}:{symbol.name}"
                        if key in current_specs:
                            continue

                        # Create propagator spec for functions in files with taint dependencies
                        new_spec = TaintSpec(
                            method=symbol.name,
                            file_path=symbol.file_path,
                            line=symbol.line,
                            label=TaintLabel.PROPAGATOR,
                            class_name=symbol.parent_class,
                            confidence=self.config.min_confidence_for_propagation,
                            reason="Function in file that imports tainted sources/sinks",
                            metadata={"propagated": True},
                        )
                        new_specs[key] = new_spec

        return new_specs

    def _build_file_lookup(
        self,
        specs: list[TaintSpec],
    ) -> dict[str, list[TaintSpec]]:
        """Build lookup from file path to specs in that file."""
        lookup: dict[str, list[TaintSpec]] = {}
        for spec in specs:
            key = str(spec.file_path)
            if key not in lookup:
                lookup[key] = []
            lookup[key].append(spec)
        return lookup

    def _build_symbol_lookup(
        self,
        repo_map: RepoMap,
    ) -> dict[str, Path]:
        """Build lookup from symbol name to file path."""
        lookup: dict[str, Path] = {}
        for symbol in repo_map.symbols:
            lookup[symbol.name] = symbol.file_path
            if symbol.parent_class:
                lookup[f"{symbol.parent_class}.{symbol.name}"] = symbol.file_path
        return lookup

    def _spec_key(self, spec: TaintSpec) -> str:
        """Generate unique key for a spec."""
        return f"{spec.file_path}:{spec.line}:{spec.method}"
