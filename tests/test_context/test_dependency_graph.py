"""
Tests for Dependency Graph.

TDD: Write tests first, then implement to make them pass.
"""

import tempfile
import shutil
from pathlib import Path

import pytest

from cerberus.context.dependency_graph import DependencyGraph


class TestDependencyGraphInit:
    """Test DependencyGraph initialization."""

    def test_creates_graph_instance(self):
        """Graph should initialize without errors."""
        graph = DependencyGraph()
        assert graph is not None

    def test_starts_empty(self):
        """Graph should start with no nodes or edges."""
        graph = DependencyGraph()
        assert graph.node_count == 0
        assert graph.edge_count == 0


class TestAddingNodes:
    """Test adding nodes to the graph."""

    @pytest.fixture
    def graph(self):
        return DependencyGraph()

    def test_add_file(self, graph):
        """Should add a file node."""
        graph.add_file(Path("src/main.py"), "python")
        assert graph.node_count == 1

    def test_add_multiple_files(self, graph):
        """Should add multiple file nodes."""
        graph.add_file(Path("src/main.py"), "python")
        graph.add_file(Path("src/utils.py"), "python")
        graph.add_file(Path("src/config.py"), "python")
        assert graph.node_count == 3

    def test_add_duplicate_file(self, graph):
        """Adding same file twice should not duplicate."""
        graph.add_file(Path("src/main.py"), "python")
        graph.add_file(Path("src/main.py"), "python")
        assert graph.node_count == 1

    def test_file_metadata(self, graph):
        """Should store file metadata."""
        graph.add_file(Path("src/main.py"), "python")
        metadata = graph.get_file_metadata(Path("src/main.py"))
        assert metadata is not None
        assert metadata["language"] == "python"


class TestAddingEdges:
    """Test adding dependency edges."""

    @pytest.fixture
    def graph(self):
        g = DependencyGraph()
        g.add_file(Path("src/main.py"), "python")
        g.add_file(Path("src/utils.py"), "python")
        g.add_file(Path("src/config.py"), "python")
        return g

    def test_add_dependency(self, graph):
        """Should add dependency edge."""
        graph.add_dependency(Path("src/main.py"), Path("src/utils.py"))
        assert graph.edge_count == 1

    def test_add_multiple_dependencies(self, graph):
        """Should add multiple dependency edges."""
        graph.add_dependency(Path("src/main.py"), Path("src/utils.py"))
        graph.add_dependency(Path("src/main.py"), Path("src/config.py"))
        assert graph.edge_count == 2

    def test_add_duplicate_dependency(self, graph):
        """Adding same dependency twice should not duplicate."""
        graph.add_dependency(Path("src/main.py"), Path("src/utils.py"))
        graph.add_dependency(Path("src/main.py"), Path("src/utils.py"))
        assert graph.edge_count == 1


class TestQueryingDependencies:
    """Test querying dependency relationships."""

    @pytest.fixture
    def graph(self):
        """Create graph with known dependencies.

        main.py -> utils.py -> helpers.py
                -> config.py
        """
        g = DependencyGraph()
        g.add_file(Path("main.py"), "python")
        g.add_file(Path("utils.py"), "python")
        g.add_file(Path("config.py"), "python")
        g.add_file(Path("helpers.py"), "python")

        g.add_dependency(Path("main.py"), Path("utils.py"))
        g.add_dependency(Path("main.py"), Path("config.py"))
        g.add_dependency(Path("utils.py"), Path("helpers.py"))
        return g

    def test_get_dependencies(self, graph):
        """Should get direct dependencies of a file."""
        deps = graph.get_dependencies(Path("main.py"))
        assert len(deps) == 2
        assert Path("utils.py") in deps
        assert Path("config.py") in deps

    def test_get_dependents(self, graph):
        """Should get files that depend on a file."""
        dependents = graph.get_dependents(Path("utils.py"))
        assert len(dependents) == 1
        assert Path("main.py") in dependents

    def test_get_dependencies_empty(self, graph):
        """Should return empty list for file with no dependencies."""
        deps = graph.get_dependencies(Path("helpers.py"))
        assert deps == []

    def test_get_dependents_empty(self, graph):
        """Should return empty list for file with no dependents."""
        dependents = graph.get_dependents(Path("main.py"))
        assert dependents == []

    def test_get_all_dependencies(self, graph):
        """Should get transitive dependencies."""
        all_deps = graph.get_all_dependencies(Path("main.py"))
        assert len(all_deps) == 3
        assert Path("utils.py") in all_deps
        assert Path("config.py") in all_deps
        assert Path("helpers.py") in all_deps

    def test_get_all_dependents(self, graph):
        """Should get transitive dependents."""
        all_deps = graph.get_all_dependents(Path("helpers.py"))
        assert len(all_deps) == 2
        assert Path("utils.py") in all_deps
        assert Path("main.py") in all_deps


class TestBuildFromRepository:
    """Test building dependency graph from a repository."""

    @pytest.fixture
    def temp_repo(self):
        """Create a temporary repository with imports."""
        repo_dir = Path(tempfile.mkdtemp())

        # Create Python files with imports
        (repo_dir / "main.py").write_text("""
from utils import helper
from config import CONFIG
import os

def main():
    pass
""")
        (repo_dir / "utils.py").write_text("""
from helpers import do_something

def helper():
    pass
""")
        (repo_dir / "config.py").write_text("""
CONFIG = {}
""")
        (repo_dir / "helpers.py").write_text("""
def do_something():
    pass
""")

        yield repo_dir
        shutil.rmtree(repo_dir)

    def test_build_from_repository(self, temp_repo):
        """Should build graph from repository files."""
        graph = DependencyGraph()
        graph.build_from_repository(temp_repo)

        # Should have all Python files
        assert graph.node_count == 4

    def test_resolves_local_imports(self, temp_repo):
        """Should resolve local imports to file paths."""
        graph = DependencyGraph()
        graph.build_from_repository(temp_repo)

        # main.py imports utils and config
        deps = graph.get_dependencies(temp_repo / "main.py")
        dep_names = {d.name for d in deps}
        assert "utils.py" in dep_names
        assert "config.py" in dep_names


class TestCyclicDependencies:
    """Test handling of cyclic dependencies."""

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

    def test_detect_cycle(self, cyclic_graph):
        """Should detect cyclic dependencies."""
        assert cyclic_graph.has_cycles()

    def test_get_cycles(self, cyclic_graph):
        """Should return cycle nodes."""
        cycles = cyclic_graph.find_cycles()
        assert len(cycles) > 0

    def test_no_infinite_loop(self, cyclic_graph):
        """Should not infinite loop on transitive queries."""
        # This should complete, not hang
        all_deps = cyclic_graph.get_all_dependencies(Path("a.py"))
        # Should have b and c (and possibly a if we include cycles)
        assert len(all_deps) >= 2


class TestGraphSerialization:
    """Test graph serialization."""

    @pytest.fixture
    def graph(self):
        g = DependencyGraph()
        g.add_file(Path("main.py"), "python")
        g.add_file(Path("utils.py"), "python")
        g.add_dependency(Path("main.py"), Path("utils.py"))
        return g

    def test_to_dict(self, graph):
        """Should serialize to dictionary."""
        data = graph.to_dict()
        assert "nodes" in data
        assert "edges" in data

    def test_from_dict(self, graph):
        """Should deserialize from dictionary."""
        data = graph.to_dict()
        new_graph = DependencyGraph.from_dict(data)
        assert new_graph.node_count == graph.node_count
        assert new_graph.edge_count == graph.edge_count


class TestGraphStatistics:
    """Test graph statistics and analysis."""

    @pytest.fixture
    def graph(self):
        """Create a more complex graph for analysis."""
        g = DependencyGraph()
        files = ["main.py", "app.py", "utils.py", "config.py", "helpers.py"]
        for f in files:
            g.add_file(Path(f), "python")

        # main.py imports everything
        g.add_dependency(Path("main.py"), Path("app.py"))
        g.add_dependency(Path("main.py"), Path("utils.py"))
        g.add_dependency(Path("main.py"), Path("config.py"))

        # app.py imports utils and config
        g.add_dependency(Path("app.py"), Path("utils.py"))
        g.add_dependency(Path("app.py"), Path("config.py"))

        # utils imports helpers
        g.add_dependency(Path("utils.py"), Path("helpers.py"))

        return g

    def test_get_most_imported(self, graph):
        """Should identify most imported files."""
        most_imported = graph.get_most_imported(n=3)
        assert len(most_imported) == 3
        # utils.py and config.py are imported the most (2 each)
        names = [p.name for p, _ in most_imported]
        assert "utils.py" in names or "config.py" in names

    def test_get_most_importing(self, graph):
        """Should identify files with most imports."""
        most_importing = graph.get_most_importing(n=2)
        assert len(most_importing) == 2
        # main.py has the most imports (3)
        assert most_importing[0][0].name == "main.py"

    def test_get_orphan_files(self, graph):
        """Should identify files with no dependents or dependencies."""
        # helpers.py has no imports and is only imported by utils
        # It's not an orphan because it IS imported
        # Let's add a true orphan
        graph.add_file(Path("orphan.py"), "python")
        orphans = graph.get_orphan_files()
        assert len(orphans) == 1
        assert orphans[0].name == "orphan.py"
