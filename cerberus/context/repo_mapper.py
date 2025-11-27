"""
Repository Mapper - Phase I main orchestrator.

Combines tree-sitter parsing, symbol extraction, dependency graph building,
and PageRank scoring to create a complete structural map of a codebase.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cerberus.context.dependency_graph import DependencyGraph
from cerberus.context.pagerank import PageRankScorer
from cerberus.context.symbol_extractor import SymbolExtractor
from cerberus.context.tree_sitter_parser import TreeSitterParser
from cerberus.models.repo_map import FileInfo, RepoMap, Symbol
from cerberus.utils.logging import ComponentLogger


class RepositoryMapper:
    """
    Map a repository's structure using static analysis.

    This is the main entry point for Phase I of the NSSCP pipeline.
    It coordinates:
    - Tree-sitter parsing for all source files
    - Symbol extraction (functions, classes, methods)
    - Dependency graph construction
    - PageRank scoring for file importance
    """

    def __init__(self) -> None:
        """Initialize the repository mapper."""
        self.logger = ComponentLogger("repo_mapper")
        self.parser = TreeSitterParser()
        self.extractor = SymbolExtractor()
        self.graph = DependencyGraph()
        self.ranker = PageRankScorer()

    async def map_repository(
        self,
        repo_path: Path,
        languages: Optional[list[str]] = None,
        exclude_patterns: Optional[list[str]] = None,
        max_file_size_mb: int = 10,
    ) -> RepoMap:
        """
        Create a complete structural map of a repository.

        Args:
            repo_path: Path to repository root
            languages: Optional list of languages to include (None = all)
            exclude_patterns: Glob patterns to exclude (e.g., ["tests/*", "*.test.py"])
            max_file_size_mb: Maximum file size in MB to process

        Returns:
            RepoMap containing files, symbols, dependencies, and rankings
        """
        self.logger.info(f"Mapping repository: {repo_path}")

        # Reset graph for new mapping
        self.graph = DependencyGraph()

        # Step 1: Parse all files
        trees = self.parser.parse_repository(
            repo_path,
            exclude_patterns=exclude_patterns,
            max_file_size_mb=max_file_size_mb,
            languages=languages,
        )

        self.logger.info(f"Parsed {len(trees)} files")

        # Step 2: Extract symbols and build FileInfo objects
        files: list[FileInfo] = []
        all_symbols: list[Symbol] = []

        for file_path, tree in trees.items():
            file_info = await self._process_file(file_path, repo_path)
            if file_info:
                files.append(file_info)
                all_symbols.extend(file_info.symbols)

        self.logger.info(f"Extracted {len(all_symbols)} symbols from {len(files)} files")

        # Step 3: Build dependency graph
        self.graph.build_from_repository(repo_path, languages=languages)

        # Convert graph dependencies to dict format
        dependencies: dict[str, list[str]] = {}
        for file_info in files:
            file_deps = self.graph.get_dependencies(file_info.path)
            if file_deps:
                dependencies[str(file_info.path)] = [str(d) for d in file_deps]

        self.logger.info(f"Built dependency graph with {self.graph.edge_count} edges")

        # Step 4: Compute PageRank scores
        scores = self.ranker.compute(self.graph)
        rankings = {str(path): score for path, score in scores.items()}

        self.logger.info("Computed PageRank scores")

        # Step 5: Build RepoMap
        repo_map = RepoMap(
            root_path=repo_path,
            files=files,
            symbols=all_symbols,
            dependencies=dependencies,
            rankings=rankings,
            generated_at=datetime.now(timezone.utc),
            metadata={
                "languages": list(self.parser.get_supported_languages()),
                "exclude_patterns": exclude_patterns or [],
                "max_file_size_mb": max_file_size_mb,
            },
        )

        self.logger.info(
            f"Repository mapping complete",
            files=repo_map.file_count,
            symbols=repo_map.symbol_count,
            lines=repo_map.total_lines,
        )

        return repo_map

    async def _process_file(
        self,
        file_path: Path,
        repo_root: Path,
    ) -> Optional[FileInfo]:
        """
        Process a single file to extract its information.

        Args:
            file_path: Path to the source file
            repo_root: Repository root path

        Returns:
            FileInfo object or None if processing fails
        """
        try:
            # Read file content
            with open(file_path, "rb") as f:
                content = f.read()

            # Calculate file hash for change detection
            file_hash = hashlib.sha256(content).hexdigest()[:16]

            # Get file stats
            stat = file_path.stat()
            size_bytes = stat.st_size

            # Count lines
            try:
                text_content = content.decode("utf-8")
                lines = text_content.count("\n") + 1
            except UnicodeDecodeError:
                lines = 0
                text_content = ""

            # Detect language
            language = self.parser.detect_language(file_path) or "unknown"

            # Extract symbols
            symbols = self.extractor.extract_from_file(file_path)

            # Extract imports and exports
            imports = self.extractor.extract_imports(text_content, language)
            exports = self.extractor.extract_exports(text_content, language)

            return FileInfo(
                path=file_path,
                language=language,
                size_bytes=size_bytes,
                lines=lines,
                symbols=symbols,
                imports=imports,
                exports=exports,
                hash=file_hash,
                metadata={
                    "relative_path": str(file_path.relative_to(repo_root)),
                },
            )

        except Exception as e:
            self.logger.warning(f"Failed to process {file_path}: {e}")
            return None

    async def update_file(
        self,
        repo_map: RepoMap,
        file_path: Path,
    ) -> RepoMap:
        """
        Update the RepoMap for a changed file.

        This provides incremental updates without re-mapping the entire repository.

        Args:
            repo_map: Existing RepoMap to update
            file_path: Path to the changed file

        Returns:
            Updated RepoMap
        """
        # Process the changed file
        new_file_info = await self._process_file(file_path, repo_map.root_path)
        if not new_file_info:
            return repo_map

        # Update files list
        new_files = [f for f in repo_map.files if f.path != file_path]
        new_files.append(new_file_info)

        # Update symbols list
        old_symbols = [s for s in repo_map.symbols if s.file_path != file_path]
        new_symbols = old_symbols + new_file_info.symbols

        # Rebuild dependency graph and rankings
        self.graph = DependencyGraph()
        self.graph.build_from_repository(repo_map.root_path)

        # Recompute rankings
        scores = self.ranker.compute(self.graph)
        rankings = {str(path): score for path, score in scores.items()}

        # Build updated dependencies
        dependencies: dict[str, list[str]] = {}
        for file_info in new_files:
            file_deps = self.graph.get_dependencies(file_info.path)
            if file_deps:
                dependencies[str(file_info.path)] = [str(d) for d in file_deps]

        return RepoMap(
            root_path=repo_map.root_path,
            files=new_files,
            symbols=new_symbols,
            dependencies=dependencies,
            rankings=rankings,
            generated_at=datetime.now(timezone.utc),
            metadata=repo_map.metadata,
        )

    async def get_context_for_symbol(
        self,
        repo_map: RepoMap,
        symbol_name: str,
        include_dependents: bool = True,
        include_dependencies: bool = True,
    ) -> dict:
        """
        Get relevant context for a symbol for LLM analysis.

        Args:
            repo_map: Repository map
            symbol_name: Name of the symbol to get context for
            include_dependents: Include files that depend on the symbol's file
            include_dependencies: Include files that the symbol's file depends on

        Returns:
            Dictionary with symbol info and related files
        """
        symbol = repo_map.get_symbol(symbol_name)
        if not symbol:
            return {"error": f"Symbol '{symbol_name}' not found"}

        file_path = symbol.file_path
        context = {
            "symbol": symbol.to_dict(),
            "file": str(file_path),
            "related_files": [],
        }

        if include_dependencies:
            deps = self.graph.get_dependencies(file_path)
            context["dependencies"] = [str(d) for d in deps]

        if include_dependents:
            dependents = self.graph.get_dependents(file_path)
            context["dependents"] = [str(d) for d in dependents]

        return context
