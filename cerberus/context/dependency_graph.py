"""
Dependency Graph for tracking file imports and relationships.

Builds and analyzes a directed graph of file dependencies based on
import/require statements across multiple programming languages.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import networkx as nx

from cerberus.context.symbol_extractor import SymbolExtractor
from cerberus.context.tree_sitter_parser import TreeSitterParser
from cerberus.utils.logging import ComponentLogger


class DependencyGraph:
    """Directed graph of file dependencies."""

    def __init__(self) -> None:
        """Initialize an empty dependency graph."""
        self.logger = ComponentLogger("dependency_graph")
        self._graph: nx.DiGraph = nx.DiGraph()
        self._parser = TreeSitterParser()
        self._extractor = SymbolExtractor()

    @property
    def node_count(self) -> int:
        """Get number of files in the graph."""
        return self._graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        """Get number of dependency edges."""
        return self._graph.number_of_edges()

    def add_file(self, file_path: Path, language: str) -> None:
        """
        Add a file node to the graph.

        Args:
            file_path: Path to the file
            language: Programming language of the file
        """
        node_id = str(file_path)
        if node_id not in self._graph:
            self._graph.add_node(node_id, path=file_path, language=language)

    def add_dependency(self, source: Path, target: Path) -> None:
        """
        Add a dependency edge (source imports target).

        Args:
            source: File that contains the import
            target: File being imported
        """
        source_id = str(source)
        target_id = str(target)

        # Ensure both nodes exist
        if source_id not in self._graph:
            self.add_file(source, "unknown")
        if target_id not in self._graph:
            self.add_file(target, "unknown")

        # Add edge if not already present
        if not self._graph.has_edge(source_id, target_id):
            self._graph.add_edge(source_id, target_id)

    def get_file_metadata(self, file_path: Path) -> Optional[dict[str, Any]]:
        """
        Get metadata for a file node.

        Args:
            file_path: Path to the file

        Returns:
            Dictionary of metadata or None if file not in graph
        """
        node_id = str(file_path)
        if node_id in self._graph:
            return dict(self._graph.nodes[node_id])
        return None

    def get_dependencies(self, file_path: Path) -> list[Path]:
        """
        Get direct dependencies of a file (files it imports).

        Args:
            file_path: Path to the file

        Returns:
            List of files that this file imports
        """
        node_id = str(file_path)
        if node_id not in self._graph:
            return []

        deps = []
        for target in self._graph.successors(node_id):
            data = self._graph.nodes[target]
            deps.append(data.get("path", Path(target)))
        return deps

    def get_dependents(self, file_path: Path) -> list[Path]:
        """
        Get direct dependents of a file (files that import it).

        Args:
            file_path: Path to the file

        Returns:
            List of files that import this file
        """
        node_id = str(file_path)
        if node_id not in self._graph:
            return []

        deps = []
        for source in self._graph.predecessors(node_id):
            data = self._graph.nodes[source]
            deps.append(data.get("path", Path(source)))
        return deps

    def get_all_dependencies(self, file_path: Path) -> list[Path]:
        """
        Get all transitive dependencies of a file.

        Args:
            file_path: Path to the file

        Returns:
            List of all files this file depends on (directly or indirectly)
        """
        node_id = str(file_path)
        if node_id not in self._graph:
            return []

        # Use BFS to avoid infinite loops in cyclic graphs
        visited: set[str] = set()
        to_visit = list(self._graph.successors(node_id))

        while to_visit:
            current = to_visit.pop(0)
            if current in visited or current == node_id:
                continue
            visited.add(current)
            to_visit.extend(self._graph.successors(current))

        deps = []
        for node in visited:
            data = self._graph.nodes[node]
            deps.append(data.get("path", Path(node)))
        return deps

    def get_all_dependents(self, file_path: Path) -> list[Path]:
        """
        Get all transitive dependents of a file.

        Args:
            file_path: Path to the file

        Returns:
            List of all files that depend on this file (directly or indirectly)
        """
        node_id = str(file_path)
        if node_id not in self._graph:
            return []

        # Use BFS to avoid infinite loops in cyclic graphs
        visited: set[str] = set()
        to_visit = list(self._graph.predecessors(node_id))

        while to_visit:
            current = to_visit.pop(0)
            if current in visited or current == node_id:
                continue
            visited.add(current)
            to_visit.extend(self._graph.predecessors(current))

        deps = []
        for node in visited:
            data = self._graph.nodes[node]
            deps.append(data.get("path", Path(node)))
        return deps

    def has_cycles(self) -> bool:
        """
        Check if the graph has cyclic dependencies.

        Returns:
            True if there are cycles, False otherwise
        """
        try:
            nx.find_cycle(self._graph)
            return True
        except nx.NetworkXNoCycle:
            return False

    def find_cycles(self) -> list[list[Path]]:
        """
        Find all cyclic dependency paths.

        Returns:
            List of cycles, where each cycle is a list of file paths
        """
        cycles = []
        try:
            # simple_cycles returns generator of cycles
            for cycle in nx.simple_cycles(self._graph):
                cycle_paths = []
                for node in cycle:
                    data = self._graph.nodes[node]
                    cycle_paths.append(data.get("path", Path(node)))
                cycles.append(cycle_paths)
        except Exception:
            pass
        return cycles

    def build_from_repository(
        self,
        repo_path: Path,
        languages: Optional[list[str]] = None,
    ) -> None:
        """
        Build dependency graph from a repository.

        Args:
            repo_path: Path to repository root
            languages: Optional list of languages to include
        """
        # First, parse all files
        trees = self._parser.parse_repository(repo_path, languages=languages)

        # Add all files as nodes
        for file_path in trees.keys():
            language = self._parser.detect_language(file_path) or "unknown"
            self.add_file(file_path, language)

        # Build file lookup by module name
        file_lookup = self._build_file_lookup(repo_path, trees.keys())

        # Extract imports and add edges
        for file_path in trees.keys():
            language = self._parser.detect_language(file_path)
            if not language:
                continue

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception:
                continue

            imports = self._extractor.extract_imports(content, language)
            for imp in imports:
                # Try to resolve import to a file
                target = self._resolve_import(imp, file_path, file_lookup, repo_path)
                if target and target != file_path:
                    self.add_dependency(file_path, target)

    def _build_file_lookup(
        self,
        repo_path: Path,
        files: list[Path],
    ) -> dict[str, Path]:
        """Build lookup from module names to file paths."""
        lookup: dict[str, Path] = {}

        for file_path in files:
            # Get relative path without extension
            try:
                rel_path = file_path.relative_to(repo_path)
            except ValueError:
                rel_path = file_path

            # Create module-style name (e.g., src/utils.py -> src.utils)
            module_name = str(rel_path.with_suffix("")).replace("/", ".").replace("\\", ".")
            lookup[module_name] = file_path

            # Also store just the filename without extension
            stem = file_path.stem
            if stem not in lookup:
                lookup[stem] = file_path

        return lookup

    def _resolve_import(
        self,
        import_name: str,
        source_file: Path,
        file_lookup: dict[str, Path],
        repo_path: Path,
    ) -> Optional[Path]:
        """
        Resolve an import name to a file path.

        Args:
            import_name: The imported module name
            source_file: The file containing the import
            file_lookup: Mapping from module names to file paths
            repo_path: Repository root path

        Returns:
            Resolved file path or None if not found
        """
        # Direct lookup
        if import_name in file_lookup:
            return file_lookup[import_name]

        # Try relative to source file directory
        source_dir = source_file.parent
        possible_names = [
            import_name,
            import_name.replace(".", "/"),
            import_name.split(".")[0],  # Just the first part
        ]

        for name in possible_names:
            # Try as Python file
            candidate = source_dir / f"{name}.py"
            if candidate.exists():
                return candidate

            # Try as package
            candidate = source_dir / name / "__init__.py"
            if candidate.exists():
                return candidate

            # Try from repo root
            candidate = repo_path / f"{name}.py"
            if candidate.exists():
                return candidate

        return None

    def get_most_imported(self, n: int = 10) -> list[tuple[Path, int]]:
        """
        Get files with the most incoming dependencies.

        Args:
            n: Number of results to return

        Returns:
            List of (file_path, import_count) tuples, sorted by count
        """
        results = []
        for node in self._graph.nodes():
            in_degree = self._graph.in_degree(node)
            data = self._graph.nodes[node]
            results.append((data.get("path", Path(node)), in_degree))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:n]

    def get_most_importing(self, n: int = 10) -> list[tuple[Path, int]]:
        """
        Get files with the most outgoing dependencies.

        Args:
            n: Number of results to return

        Returns:
            List of (file_path, dependency_count) tuples, sorted by count
        """
        results = []
        for node in self._graph.nodes():
            out_degree = self._graph.out_degree(node)
            data = self._graph.nodes[node]
            results.append((data.get("path", Path(node)), out_degree))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:n]

    def get_orphan_files(self) -> list[Path]:
        """
        Get files with no incoming or outgoing dependencies.

        Returns:
            List of orphan file paths
        """
        orphans = []
        for node in self._graph.nodes():
            if self._graph.degree(node) == 0:
                data = self._graph.nodes[node]
                orphans.append(data.get("path", Path(node)))
        return orphans

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize graph to dictionary.

        Returns:
            Dictionary representation of the graph
        """
        nodes = []
        for node in self._graph.nodes():
            data = dict(self._graph.nodes[node])
            data["id"] = node
            if "path" in data:
                data["path"] = str(data["path"])
            nodes.append(data)

        edges = []
        for source, target in self._graph.edges():
            edges.append({"source": source, "target": target})

        return {"nodes": nodes, "edges": edges}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DependencyGraph":
        """
        Deserialize graph from dictionary.

        Args:
            data: Dictionary representation of the graph

        Returns:
            DependencyGraph instance
        """
        graph = cls()

        for node_data in data.get("nodes", []):
            node_id = node_data.get("id", "")
            path = Path(node_data.get("path", node_id))
            language = node_data.get("language", "unknown")
            graph.add_file(path, language)

        for edge in data.get("edges", []):
            source = Path(edge["source"])
            target = Path(edge["target"])
            graph.add_dependency(source, target)

        return graph
