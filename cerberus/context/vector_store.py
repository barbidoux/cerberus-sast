"""
Vector Store Manager for semantic code search.

Uses ChromaDB for storing and searching code embeddings.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import chromadb
from chromadb.config import Settings

from cerberus.models.base import SymbolType
from cerberus.models.repo_map import FileInfo, Symbol


@dataclass
class SearchResult:
    """Result from vector search."""

    id: str
    content: str
    metadata: dict[str, Any]
    distance: float


class VectorStoreManager:
    """Manages ChromaDB collections for semantic code search.

    Provides collections for:
    - functions: Function and method embeddings
    - classes: Class-level embeddings
    - files: File summary embeddings
    """

    COLLECTIONS = {
        "functions": "Function and method embeddings",
        "classes": "Class-level embeddings",
        "files": "File summary embeddings",
    }

    def __init__(self, persist_dir: Path) -> None:
        """Initialize the vector store.

        Args:
            persist_dir: Directory for ChromaDB persistence.
        """
        self.persist_dir = persist_dir

        # Ensure directory exists
        self.persist_dir.mkdir(parents=True, exist_ok=True)

        # Initialize ChromaDB client with persistence
        self._client = chromadb.PersistentClient(
            path=str(self.persist_dir),
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True,
            ),
        )

        # Initialize or get collections
        self._collections: dict[str, Any] = {}
        for name, description in self.COLLECTIONS.items():
            self._collections[name] = self._client.get_or_create_collection(
                name=name,
                metadata={"description": description},
            )

    async def index_symbols(self, symbols: list[Symbol]) -> None:
        """Index symbols for semantic search.

        Args:
            symbols: List of Symbol objects to index.
        """
        if not symbols:
            return

        # Separate functions/methods and classes
        functions = [
            s
            for s in symbols
            if s.type in (SymbolType.FUNCTION, SymbolType.METHOD)
        ]
        classes = [s for s in symbols if s.type == SymbolType.CLASS]

        # Index functions
        if functions:
            ids = [f"{s.file_path}:{s.line}:{s.name}" for s in functions]
            documents = [
                f"{s.name}: {s.signature or ''} {s.docstring or ''}"
                for s in functions
            ]
            metadatas = [
                {
                    "name": s.name,
                    "file_path": str(s.file_path),
                    "line": s.line,
                    "type": s.type.value,
                    "signature": s.signature or "",
                }
                for s in functions
            ]
            self._collections["functions"].add(
                ids=ids,
                documents=documents,
                metadatas=metadatas,
            )

        # Index classes
        if classes:
            ids = [f"{s.file_path}:{s.line}:{s.name}" for s in classes]
            documents = [f"{s.name}: {s.docstring or ''}" for s in classes]
            metadatas = [
                {
                    "name": s.name,
                    "file_path": str(s.file_path),
                    "line": s.line,
                    "type": "class",
                }
                for s in classes
            ]
            self._collections["classes"].add(
                ids=ids,
                documents=documents,
                metadatas=metadatas,
            )

    async def index_files(self, files: list[FileInfo]) -> None:
        """Index file summaries for semantic search.

        Args:
            files: List of FileInfo objects to index.
        """
        if not files:
            return

        ids = [str(f.path) for f in files]
        documents = [
            f"{f.path.name} ({f.language}): {', '.join(s.name for s in f.symbols[:10])}"
            for f in files
        ]
        metadatas = [
            {
                "path": str(f.path),
                "language": f.language,
                "lines": f.lines,
                "size_bytes": f.size_bytes,
            }
            for f in files
        ]

        self._collections["files"].add(
            ids=ids,
            documents=documents,
            metadatas=metadatas,
        )

    async def search(
        self,
        query: str,
        collection: str = "functions",
        top_k: int = 10,
    ) -> list[SearchResult]:
        """Search for semantically similar code elements.

        Args:
            query: Natural language search query.
            collection: Which collection to search (functions, classes, files).
            top_k: Maximum number of results to return.

        Returns:
            List of SearchResult objects sorted by relevance.
        """
        if collection not in self._collections:
            raise ValueError(f"Unknown collection: {collection}")

        coll = self._collections[collection]

        # Check if collection is empty
        if coll.count() == 0:
            return []

        # Query the collection
        results = coll.query(
            query_texts=[query],
            n_results=min(top_k, coll.count()),
        )

        # Convert to SearchResult objects
        search_results = []
        if results["ids"] and results["ids"][0]:
            for i, id_ in enumerate(results["ids"][0]):
                search_results.append(
                    SearchResult(
                        id=id_,
                        content=results["documents"][0][i] if results["documents"] else "",
                        metadata=results["metadatas"][0][i] if results["metadatas"] else {},
                        distance=results["distances"][0][i] if results["distances"] else 0.0,
                    )
                )

        return search_results

    def clear(self, collection: str) -> None:
        """Clear all items from a collection.

        Args:
            collection: Name of the collection to clear.
        """
        if collection not in self._collections:
            raise ValueError(f"Unknown collection: {collection}")

        # Delete and recreate collection
        self._client.delete_collection(collection)
        self._collections[collection] = self._client.create_collection(
            name=collection,
            metadata={"description": self.COLLECTIONS[collection]},
        )

    def get_stats(self) -> dict[str, int]:
        """Get counts for each collection.

        Returns:
            Dict mapping collection name to item count.
        """
        return {name: coll.count() for name, coll in self._collections.items()}
