"""
Tests for the ChromaDB vector store for semantic code search.

TDD: Write tests first, then implement to make them pass.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from cerberus.context.vector_store import VectorStoreManager, SearchResult
from cerberus.models.repo_map import Symbol, FileInfo
from cerberus.models.base import SymbolType


class TestVectorStoreInit:
    """Test vector store initialization."""

    def test_creates_with_persist_dir(self, tmp_path):
        """Should initialize with persist directory."""
        persist_dir = tmp_path / "vectors"
        store = VectorStoreManager(persist_dir)
        assert store.persist_dir == persist_dir

    def test_creates_persist_dir_if_not_exists(self, tmp_path):
        """Should create persist directory if it doesn't exist."""
        persist_dir = tmp_path / "new_vectors"
        assert not persist_dir.exists()
        store = VectorStoreManager(persist_dir)
        assert persist_dir.exists()


class TestVectorStoreIndexing:
    """Test vector store indexing operations."""

    @pytest.fixture
    def store(self, tmp_path):
        return VectorStoreManager(tmp_path / "vectors")

    @pytest.fixture
    def sample_symbols(self):
        return [
            Symbol(
                name="process_user_input",
                type=SymbolType.FUNCTION,
                file_path=Path("src/handler.py"),
                line=10,
                signature="def process_user_input(data: str) -> dict",
                docstring="Process and validate user input from request",
            ),
            Symbol(
                name="execute_query",
                type=SymbolType.FUNCTION,
                file_path=Path("src/db.py"),
                line=25,
                signature="def execute_query(sql: str) -> list",
                docstring="Execute SQL query against database",
            ),
            Symbol(
                name="sanitize_html",
                type=SymbolType.FUNCTION,
                file_path=Path("src/utils.py"),
                line=5,
                signature="def sanitize_html(text: str) -> str",
                docstring="Sanitize HTML content to prevent XSS",
            ),
        ]

    @pytest.fixture
    def sample_files(self):
        return [
            FileInfo(
                path=Path("src/main.py"),
                language="python",
                size_bytes=1000,
                lines=50,
                symbols=[],
                imports=["os", "sys"],
            ),
            FileInfo(
                path=Path("src/handler.py"),
                language="python",
                size_bytes=2000,
                lines=100,
                symbols=[],
                imports=["flask", "json"],
            ),
        ]

    @pytest.mark.asyncio
    async def test_index_symbols(self, store, sample_symbols):
        """Should index symbols for search."""
        await store.index_symbols(sample_symbols)
        stats = store.get_stats()
        assert stats["functions"] >= 3

    @pytest.mark.asyncio
    async def test_index_files(self, store, sample_files):
        """Should index file summaries."""
        await store.index_files(sample_files)
        stats = store.get_stats()
        assert stats["files"] >= 2

    @pytest.mark.asyncio
    async def test_index_empty_list(self, store):
        """Should handle empty symbol list."""
        await store.index_symbols([])
        stats = store.get_stats()
        assert stats["functions"] == 0


class TestVectorStoreSearch:
    """Test vector store search operations."""

    @pytest.fixture
    def store(self, tmp_path):
        return VectorStoreManager(tmp_path / "vectors")

    @pytest.fixture
    def sample_symbols(self):
        return [
            Symbol(
                name="process_user_input",
                type=SymbolType.FUNCTION,
                file_path=Path("src/handler.py"),
                line=10,
                signature="def process_user_input(data: str) -> dict",
                docstring="Process and validate user input from request",
            ),
            Symbol(
                name="execute_query",
                type=SymbolType.FUNCTION,
                file_path=Path("src/db.py"),
                line=25,
                signature="def execute_query(sql: str) -> list",
                docstring="Execute SQL query against database",
            ),
            Symbol(
                name="sanitize_html",
                type=SymbolType.FUNCTION,
                file_path=Path("src/utils.py"),
                line=5,
                signature="def sanitize_html(text: str) -> str",
                docstring="Sanitize HTML content to prevent XSS",
            ),
        ]

    @pytest.mark.asyncio
    async def test_search_by_semantic_similarity(self, store, sample_symbols):
        """Should find semantically similar functions."""
        await store.index_symbols(sample_symbols)

        results = await store.search(
            query="handle user data from request",
            collection="functions",
            top_k=5,
        )

        assert len(results) > 0
        # Should find process_user_input as most relevant
        result_names = [r.id for r in results]
        assert any("process_user_input" in name for name in result_names)

    @pytest.mark.asyncio
    async def test_search_returns_metadata(self, store, sample_symbols):
        """Search results should include symbol metadata."""
        await store.index_symbols(sample_symbols)

        results = await store.search(
            query="database query",
            collection="functions",
            top_k=1,
        )

        assert len(results) >= 1
        result = results[0]
        assert "file_path" in result.metadata
        assert "line" in result.metadata

    @pytest.mark.asyncio
    async def test_search_respects_top_k(self, store, sample_symbols):
        """Should return at most top_k results."""
        await store.index_symbols(sample_symbols)

        results = await store.search(
            query="function",
            collection="functions",
            top_k=2,
        )

        assert len(results) <= 2

    @pytest.mark.asyncio
    async def test_search_empty_collection(self, store):
        """Should return empty list for empty collection."""
        results = await store.search(
            query="anything",
            collection="functions",
            top_k=10,
        )
        assert results == []


class TestVectorStoreCollectionManagement:
    """Test collection management operations."""

    @pytest.fixture
    def store(self, tmp_path):
        return VectorStoreManager(tmp_path / "vectors")

    @pytest.fixture
    def sample_symbols(self):
        return [
            Symbol(
                name="test_func",
                type=SymbolType.FUNCTION,
                file_path=Path("src/test.py"),
                line=1,
            ),
        ]

    @pytest.mark.asyncio
    async def test_clear_collection(self, store, sample_symbols):
        """Should clear all items from collection."""
        await store.index_symbols(sample_symbols)
        stats_before = store.get_stats()
        assert stats_before["functions"] > 0

        store.clear("functions")

        stats_after = store.get_stats()
        assert stats_after["functions"] == 0

    def test_get_stats_returns_counts(self, store):
        """Should return collection counts."""
        stats = store.get_stats()
        assert "functions" in stats
        assert "classes" in stats
        assert "files" in stats


class TestSearchResult:
    """Test SearchResult dataclass."""

    def test_search_result_creation(self):
        """Should create SearchResult with all fields."""
        result = SearchResult(
            id="test_id",
            content="test content",
            metadata={"file": "test.py", "line": 10},
            distance=0.5,
        )
        assert result.id == "test_id"
        assert result.content == "test content"
        assert result.metadata["file"] == "test.py"
        assert result.distance == 0.5
