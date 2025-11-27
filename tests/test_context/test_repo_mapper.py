"""
Tests for Repository Mapper.

TDD: Write tests first, then implement to make them pass.
"""

import shutil
import tempfile
from pathlib import Path

import pytest

from cerberus.context.repo_mapper import RepositoryMapper
from cerberus.models.base import SymbolType
from cerberus.models.repo_map import FileInfo, RepoMap, Symbol


class TestRepositoryMapperInit:
    """Test RepositoryMapper initialization."""

    def test_creates_mapper_instance(self):
        """Mapper should initialize without errors."""
        mapper = RepositoryMapper()
        assert mapper is not None

    def test_has_required_components(self):
        """Mapper should have parser, extractor, and graph."""
        mapper = RepositoryMapper()
        assert hasattr(mapper, "parser")
        assert hasattr(mapper, "extractor")
        assert hasattr(mapper, "graph")


class TestMapRepository:
    """Test repository mapping functionality."""

    @pytest.fixture
    def temp_repo(self):
        """Create a temporary Python repository."""
        repo_dir = Path(tempfile.mkdtemp())

        # Create source files
        (repo_dir / "src").mkdir()
        (repo_dir / "src" / "main.py").write_text('''
"""Main application entry point."""

from utils import helper
from config import CONFIG

def main():
    """Run the application."""
    result = helper()
    return result

class Application:
    """Main application class."""

    def __init__(self):
        self.config = CONFIG

    def run(self):
        """Start the application."""
        pass

if __name__ == "__main__":
    main()
''')

        (repo_dir / "src" / "utils.py").write_text('''
"""Utility functions."""

def helper():
    """A helper function."""
    return "help"

def another_helper(name: str) -> str:
    """Another helper with args."""
    return f"Hello {name}"

class UtilClass:
    """Utility class."""

    def method(self):
        pass
''')

        (repo_dir / "src" / "config.py").write_text('''
"""Configuration module."""

CONFIG = {
    "debug": True,
    "name": "test"
}

class Config:
    """Configuration class."""
    pass
''')

        yield repo_dir
        shutil.rmtree(repo_dir)

    @pytest.mark.asyncio
    async def test_map_repository(self, temp_repo):
        """Should create a complete RepoMap."""
        mapper = RepositoryMapper()
        repo_map = await mapper.map_repository(temp_repo)

        assert isinstance(repo_map, RepoMap)
        assert repo_map.root_path == temp_repo

    @pytest.mark.asyncio
    async def test_map_finds_all_files(self, temp_repo):
        """Should find all source files."""
        mapper = RepositoryMapper()
        repo_map = await mapper.map_repository(temp_repo)

        assert repo_map.file_count == 3
        file_names = {f.path.name for f in repo_map.files}
        assert "main.py" in file_names
        assert "utils.py" in file_names
        assert "config.py" in file_names

    @pytest.mark.asyncio
    async def test_map_extracts_symbols(self, temp_repo):
        """Should extract all symbols."""
        mapper = RepositoryMapper()
        repo_map = await mapper.map_repository(temp_repo)

        # Should have functions, classes, and methods
        functions = repo_map.get_symbols_by_type(SymbolType.FUNCTION)
        classes = repo_map.get_symbols_by_type(SymbolType.CLASS)
        methods = repo_map.get_symbols_by_type(SymbolType.METHOD)

        assert len(functions) >= 3  # main, helper, another_helper
        assert len(classes) >= 3  # Application, UtilClass, Config
        assert len(methods) >= 2  # run, method

    @pytest.mark.asyncio
    async def test_map_builds_dependencies(self, temp_repo):
        """Should build dependency graph."""
        mapper = RepositoryMapper()
        repo_map = await mapper.map_repository(temp_repo)

        # main.py imports utils and config
        assert len(repo_map.dependencies) > 0

    @pytest.mark.asyncio
    async def test_map_computes_rankings(self, temp_repo):
        """Should compute PageRank scores."""
        mapper = RepositoryMapper()
        repo_map = await mapper.map_repository(temp_repo)

        assert len(repo_map.rankings) == 3
        # All scores should be positive
        for score in repo_map.rankings.values():
            assert score > 0

    @pytest.mark.asyncio
    async def test_map_stores_file_info(self, temp_repo):
        """Should store complete file info."""
        mapper = RepositoryMapper()
        repo_map = await mapper.map_repository(temp_repo)

        main_file = repo_map.get_file(temp_repo / "src" / "main.py")
        assert main_file is not None
        assert main_file.language == "python"
        assert main_file.lines > 0
        assert main_file.size_bytes > 0


class TestMapperConfiguration:
    """Test mapper configuration options."""

    @pytest.fixture
    def multi_lang_repo(self):
        """Create repo with multiple languages."""
        repo_dir = Path(tempfile.mkdtemp())

        (repo_dir / "main.py").write_text("def main(): pass")
        (repo_dir / "app.js").write_text("function app() {}")
        (repo_dir / "style.css").write_text("body { color: red; }")

        yield repo_dir
        shutil.rmtree(repo_dir)

    @pytest.mark.asyncio
    async def test_filter_by_language(self, multi_lang_repo):
        """Should filter by language."""
        mapper = RepositoryMapper()
        repo_map = await mapper.map_repository(
            multi_lang_repo,
            languages=["python"]
        )

        assert repo_map.file_count == 1
        assert repo_map.files[0].language == "python"

    @pytest.fixture
    def repo_with_tests(self):
        """Create repo with test files."""
        repo_dir = Path(tempfile.mkdtemp())

        (repo_dir / "src").mkdir()
        (repo_dir / "src" / "main.py").write_text("def main(): pass")

        (repo_dir / "tests").mkdir()
        (repo_dir / "tests" / "test_main.py").write_text("def test_main(): pass")

        (repo_dir / "node_modules").mkdir()
        (repo_dir / "node_modules" / "pkg.js").write_text("function pkg() {}")

        yield repo_dir
        shutil.rmtree(repo_dir)

    @pytest.mark.asyncio
    async def test_exclude_patterns(self, repo_with_tests):
        """Should exclude files matching patterns."""
        mapper = RepositoryMapper()
        repo_map = await mapper.map_repository(
            repo_with_tests,
            exclude_patterns=["tests/*", "node_modules/*"]
        )

        assert repo_map.file_count == 1
        assert repo_map.files[0].path.name == "main.py"


class TestIncrementalMapping:
    """Test incremental repository mapping."""

    @pytest.fixture
    def temp_repo(self):
        """Create a temporary repository."""
        repo_dir = Path(tempfile.mkdtemp())
        (repo_dir / "main.py").write_text("def main(): pass")
        (repo_dir / "utils.py").write_text("def helper(): pass")
        yield repo_dir
        shutil.rmtree(repo_dir)

    @pytest.mark.asyncio
    async def test_update_single_file(self, temp_repo):
        """Should update mapping for changed file."""
        mapper = RepositoryMapper()
        repo_map = await mapper.map_repository(temp_repo)

        initial_symbols = repo_map.symbol_count

        # Modify a file
        (temp_repo / "utils.py").write_text("""
def helper(): pass
def new_function(): pass
class NewClass: pass
""")

        # Update the mapping
        updated_map = await mapper.update_file(
            repo_map,
            temp_repo / "utils.py"
        )

        assert updated_map.symbol_count > initial_symbols


class TestRepoMapSerialization:
    """Test RepoMap serialization."""

    @pytest.fixture
    def temp_repo(self):
        """Create a temporary repository."""
        repo_dir = Path(tempfile.mkdtemp())
        (repo_dir / "main.py").write_text("def main(): pass")
        yield repo_dir
        shutil.rmtree(repo_dir)

    @pytest.mark.asyncio
    async def test_save_and_load(self, temp_repo):
        """Should save and load RepoMap."""
        mapper = RepositoryMapper()
        repo_map = await mapper.map_repository(temp_repo)

        # Save to file
        save_path = temp_repo / "repo_map.json"
        repo_map.to_json(save_path)

        # Load from file
        loaded_map = RepoMap.from_json(save_path)

        assert loaded_map.file_count == repo_map.file_count
        assert loaded_map.symbol_count == repo_map.symbol_count


class TestStatistics:
    """Test repository statistics."""

    @pytest.fixture
    def temp_repo(self):
        """Create a repository for statistics."""
        repo_dir = Path(tempfile.mkdtemp())
        (repo_dir / "main.py").write_text("""
def main(): pass
def helper(): pass
class MyClass:
    def method(self): pass
""")
        yield repo_dir
        shutil.rmtree(repo_dir)

    @pytest.mark.asyncio
    async def test_summary_statistics(self, temp_repo):
        """Should generate summary statistics."""
        mapper = RepositoryMapper()
        repo_map = await mapper.map_repository(temp_repo)

        summary = repo_map.summary()

        assert "file_count" in summary
        assert "symbol_count" in summary
        assert "total_lines" in summary
        assert "languages" in summary
        assert "symbols_by_type" in summary
