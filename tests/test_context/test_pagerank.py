"""
Tests for PageRank Scorer.

TDD: Write tests first, then implement to make them pass.
"""

from pathlib import Path

import pytest

from cerberus.context.dependency_graph import DependencyGraph
from cerberus.context.pagerank import PageRankScorer


class TestPageRankScorerInit:
    """Test PageRankScorer initialization."""

    def test_creates_scorer_instance(self):
        """Scorer should initialize without errors."""
        scorer = PageRankScorer()
        assert scorer is not None

    def test_default_damping_factor(self):
        """Should have default damping factor of 0.85."""
        scorer = PageRankScorer()
        assert scorer.damping_factor == 0.85

    def test_custom_damping_factor(self):
        """Should accept custom damping factor."""
        scorer = PageRankScorer(damping_factor=0.9)
        assert scorer.damping_factor == 0.9


class TestBasicPageRank:
    """Test basic PageRank computation."""

    @pytest.fixture
    def simple_graph(self):
        """Create a simple graph: A -> B -> C"""
        g = DependencyGraph()
        g.add_file(Path("a.py"), "python")
        g.add_file(Path("b.py"), "python")
        g.add_file(Path("c.py"), "python")
        g.add_dependency(Path("a.py"), Path("b.py"))
        g.add_dependency(Path("b.py"), Path("c.py"))
        return g

    def test_compute_scores(self, simple_graph):
        """Should compute scores for all nodes."""
        scorer = PageRankScorer()
        scores = scorer.compute(simple_graph)

        assert len(scores) == 3
        assert Path("a.py") in scores
        assert Path("b.py") in scores
        assert Path("c.py") in scores

    def test_scores_sum_to_one(self, simple_graph):
        """Scores should approximately sum to 1."""
        scorer = PageRankScorer()
        scores = scorer.compute(simple_graph)

        total = sum(scores.values())
        assert abs(total - 1.0) < 0.01  # Allow small floating point error

    def test_all_scores_positive(self, simple_graph):
        """All scores should be positive."""
        scorer = PageRankScorer()
        scores = scorer.compute(simple_graph)

        for score in scores.values():
            assert score > 0

    def test_imported_files_rank_higher(self, simple_graph):
        """Files that are imported should rank higher than importers."""
        scorer = PageRankScorer()
        scores = scorer.compute(simple_graph)

        # C is imported by B, B is imported by A
        # In PageRank, files that receive links rank higher
        # So C should rank highest, then B, then A
        assert scores[Path("c.py")] > scores[Path("a.py")]


class TestComplexGraph:
    """Test PageRank on more complex graphs."""

    @pytest.fixture
    def hub_graph(self):
        """Create graph where utils.py is imported by everything.

        main.py -> utils.py
        app.py -> utils.py
        api.py -> utils.py
        """
        g = DependencyGraph()
        files = ["main.py", "app.py", "api.py", "utils.py"]
        for f in files:
            g.add_file(Path(f), "python")

        g.add_dependency(Path("main.py"), Path("utils.py"))
        g.add_dependency(Path("app.py"), Path("utils.py"))
        g.add_dependency(Path("api.py"), Path("utils.py"))
        return g

    def test_hub_file_ranks_highest(self, hub_graph):
        """File imported by many should have highest rank."""
        scorer = PageRankScorer()
        scores = scorer.compute(hub_graph)

        # utils.py is imported by 3 files, should rank highest
        highest = max(scores.items(), key=lambda x: x[1])
        assert highest[0].name == "utils.py"

    @pytest.fixture
    def chain_graph(self):
        """Create a long chain: a -> b -> c -> d -> e"""
        g = DependencyGraph()
        files = ["a.py", "b.py", "c.py", "d.py", "e.py"]
        for f in files:
            g.add_file(Path(f), "python")

        g.add_dependency(Path("a.py"), Path("b.py"))
        g.add_dependency(Path("b.py"), Path("c.py"))
        g.add_dependency(Path("c.py"), Path("d.py"))
        g.add_dependency(Path("d.py"), Path("e.py"))
        return g

    def test_chain_end_ranks_highest(self, chain_graph):
        """End of chain should rank highest."""
        scorer = PageRankScorer()
        scores = scorer.compute(chain_graph)

        # e.py is at the end, should rank highest
        highest = max(scores.items(), key=lambda x: x[1])
        assert highest[0].name == "e.py"


class TestCyclicGraph:
    """Test PageRank on graphs with cycles."""

    @pytest.fixture
    def cyclic_graph(self):
        """Create graph with cycle: a -> b -> c -> a"""
        g = DependencyGraph()
        g.add_file(Path("a.py"), "python")
        g.add_file(Path("b.py"), "python")
        g.add_file(Path("c.py"), "python")

        g.add_dependency(Path("a.py"), Path("b.py"))
        g.add_dependency(Path("b.py"), Path("c.py"))
        g.add_dependency(Path("c.py"), Path("a.py"))
        return g

    def test_handles_cycles(self, cyclic_graph):
        """Should handle cyclic graphs without hanging."""
        scorer = PageRankScorer()
        scores = scorer.compute(cyclic_graph)

        # Should complete and return scores
        assert len(scores) == 3

    def test_cyclic_scores_balanced(self, cyclic_graph):
        """Nodes in a cycle should have similar scores."""
        scorer = PageRankScorer()
        scores = scorer.compute(cyclic_graph)

        values = list(scores.values())
        # In a perfect cycle, all scores should be nearly equal
        assert max(values) - min(values) < 0.1


class TestEmptyGraph:
    """Test PageRank on edge cases."""

    def test_empty_graph(self):
        """Should handle empty graph."""
        scorer = PageRankScorer()
        g = DependencyGraph()
        scores = scorer.compute(g)
        assert scores == {}

    def test_single_node(self):
        """Should handle single node graph."""
        scorer = PageRankScorer()
        g = DependencyGraph()
        g.add_file(Path("single.py"), "python")
        scores = scorer.compute(g)

        assert len(scores) == 1
        assert scores[Path("single.py")] == 1.0

    def test_disconnected_nodes(self):
        """Should handle disconnected nodes."""
        scorer = PageRankScorer()
        g = DependencyGraph()
        g.add_file(Path("a.py"), "python")
        g.add_file(Path("b.py"), "python")
        g.add_file(Path("c.py"), "python")
        # No edges

        scores = scorer.compute(g)
        assert len(scores) == 3
        # All should have equal scores
        values = list(scores.values())
        assert abs(max(values) - min(values)) < 0.01


class TestRankingMethods:
    """Test ranking utility methods."""

    @pytest.fixture
    def scorer_with_graph(self):
        """Create scorer with computed scores."""
        g = DependencyGraph()
        files = ["main.py", "utils.py", "config.py", "helpers.py"]
        for f in files:
            g.add_file(Path(f), "python")

        # utils is imported by main and config
        g.add_dependency(Path("main.py"), Path("utils.py"))
        g.add_dependency(Path("config.py"), Path("utils.py"))
        g.add_dependency(Path("utils.py"), Path("helpers.py"))

        scorer = PageRankScorer()
        scorer.compute(g)
        return scorer

    def test_get_top_files(self, scorer_with_graph):
        """Should return top N files by score."""
        top = scorer_with_graph.get_top_files(2)
        assert len(top) == 2

        # Should be in descending order
        assert top[0][1] >= top[1][1]

    def test_get_file_score(self, scorer_with_graph):
        """Should return score for specific file."""
        score = scorer_with_graph.get_score(Path("utils.py"))
        assert score is not None
        assert score > 0

    def test_get_score_missing_file(self, scorer_with_graph):
        """Should return 0 for missing file."""
        score = scorer_with_graph.get_score(Path("nonexistent.py"))
        assert score == 0.0


class TestPersonalization:
    """Test personalized PageRank."""

    @pytest.fixture
    def graph(self):
        """Create graph for personalization tests."""
        g = DependencyGraph()
        files = ["main.py", "utils.py", "config.py", "helpers.py"]
        for f in files:
            g.add_file(Path(f), "python")

        g.add_dependency(Path("main.py"), Path("utils.py"))
        g.add_dependency(Path("main.py"), Path("config.py"))
        g.add_dependency(Path("utils.py"), Path("helpers.py"))
        return g

    def test_personalized_pagerank(self, graph):
        """Should support personalized PageRank with seed files."""
        scorer = PageRankScorer()

        # Give more weight to main.py as starting point
        scores = scorer.compute(
            graph,
            personalization={Path("main.py"): 1.0}
        )

        assert len(scores) == 4
        # All scores should still be positive
        for score in scores.values():
            assert score > 0
