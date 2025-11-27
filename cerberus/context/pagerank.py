"""
PageRank Scorer for file importance ranking.

Uses the PageRank algorithm on the dependency graph to rank files
by their structural importance in the codebase.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import networkx as nx

from cerberus.context.dependency_graph import DependencyGraph
from cerberus.utils.logging import ComponentLogger


class PageRankScorer:
    """Compute PageRank scores for files based on dependency graph."""

    def __init__(self, damping_factor: float = 0.85) -> None:
        """
        Initialize PageRank scorer.

        Args:
            damping_factor: PageRank damping factor (default 0.85)
        """
        self.logger = ComponentLogger("pagerank")
        self.damping_factor = damping_factor
        self._scores: dict[Path, float] = {}

    def compute(
        self,
        graph: DependencyGraph,
        personalization: Optional[dict[Path, float]] = None,
        max_iter: int = 100,
        tol: float = 1e-6,
    ) -> dict[Path, float]:
        """
        Compute PageRank scores for all files in the graph.

        Note: PageRank naturally ranks nodes that receive more links higher.
        In our dependency graph, an edge from A to B means "A imports B".
        Files that are imported more (receive more edges) will rank higher.

        Args:
            graph: DependencyGraph to analyze
            personalization: Optional personalization vector for biased PageRank
            max_iter: Maximum iterations for convergence
            tol: Tolerance for convergence

        Returns:
            Dictionary mapping file paths to their PageRank scores
        """
        # Get the underlying networkx graph
        nx_graph = graph._graph

        if nx_graph.number_of_nodes() == 0:
            self._scores = {}
            return {}

        # Handle single node case
        if nx_graph.number_of_nodes() == 1:
            node = list(nx_graph.nodes())[0]
            data = nx_graph.nodes[node]
            path = data.get("path", Path(node))
            self._scores = {path: 1.0}
            return self._scores

        # Prepare personalization vector if provided
        pers = None
        if personalization:
            pers = {}
            for path, weight in personalization.items():
                pers[str(path)] = weight

        try:
            # Compute PageRank
            # Note: NetworkX PageRank computes higher scores for nodes with more
            # incoming edges, which is what we want.
            raw_scores = nx.pagerank(
                nx_graph,
                alpha=self.damping_factor,
                personalization=pers,
                max_iter=max_iter,
                tol=tol,
            )
        except nx.PowerIterationFailedConvergence:
            self.logger.warning("PageRank did not converge, using partial results")
            raw_scores = nx.pagerank(
                nx_graph,
                alpha=self.damping_factor,
                personalization=pers,
                max_iter=max_iter * 2,
                tol=tol * 10,
            )

        # Convert node IDs to Path objects
        self._scores = {}
        for node, score in raw_scores.items():
            data = nx_graph.nodes[node]
            path = data.get("path", Path(node))
            self._scores[path] = score

        self.logger.debug(
            f"Computed PageRank for {len(self._scores)} files",
            top_file=self.get_top_files(1)[0][0].name if self._scores else None,
        )

        return self._scores

    def get_score(self, file_path: Path) -> float:
        """
        Get PageRank score for a specific file.

        Args:
            file_path: Path to the file

        Returns:
            PageRank score or 0.0 if file not found
        """
        return self._scores.get(file_path, 0.0)

    def get_top_files(self, n: int = 10) -> list[tuple[Path, float]]:
        """
        Get top N files by PageRank score.

        Args:
            n: Number of files to return

        Returns:
            List of (file_path, score) tuples in descending order
        """
        sorted_scores = sorted(
            self._scores.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        return sorted_scores[:n]

    def get_rankings(self) -> dict[Path, float]:
        """
        Get all computed rankings.

        Returns:
            Dictionary mapping file paths to scores
        """
        return dict(self._scores)

    def normalize_scores(self) -> dict[Path, float]:
        """
        Get scores normalized to 0-1 range.

        Returns:
            Dictionary with normalized scores
        """
        if not self._scores:
            return {}

        min_score = min(self._scores.values())
        max_score = max(self._scores.values())

        if max_score == min_score:
            return {path: 1.0 for path in self._scores}

        return {
            path: (score - min_score) / (max_score - min_score)
            for path, score in self._scores.items()
        }
