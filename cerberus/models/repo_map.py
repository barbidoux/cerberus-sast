"""
Repository Map models for Phase I output.

These models represent the structural understanding of a codebase:
- FileInfo: Information about individual source files
- Symbol: Code symbols (functions, classes, variables)
- RepoMap: Complete repository structural map
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cerberus.models.base import CodeLocation, SymbolType


@dataclass
class Symbol:
    """
    Code symbol (function, class, variable, etc.).

    Represents a named code element extracted from source.
    """

    name: str
    type: SymbolType
    file_path: Path
    line: int
    signature: Optional[str] = None
    docstring: Optional[str] = None
    parent_class: Optional[str] = None
    visibility: str = "public"  # public, private, protected
    references: list[CodeLocation] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Ensure file_path is a Path object."""
        if isinstance(self.file_path, str):
            self.file_path = Path(self.file_path)
        if isinstance(self.type, str):
            self.type = SymbolType.from_string(self.type)

    @property
    def qualified_name(self) -> str:
        """Get fully qualified name including parent class."""
        if self.parent_class:
            return f"{self.parent_class}.{self.name}"
        return self.name

    @property
    def location(self) -> CodeLocation:
        """Get CodeLocation for this symbol."""
        return CodeLocation(file_path=self.file_path, line=self.line, column=0)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "name": self.name,
            "type": self.type.value,
            "file_path": str(self.file_path),
            "line": self.line,
            "signature": self.signature,
            "docstring": self.docstring,
            "parent_class": self.parent_class,
            "visibility": self.visibility,
            "references": [r.to_dict() for r in self.references],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Symbol":
        """Deserialize from dictionary."""
        return cls(
            name=data["name"],
            type=SymbolType(data["type"]),
            file_path=Path(data["file_path"]),
            line=data["line"],
            signature=data.get("signature"),
            docstring=data.get("docstring"),
            parent_class=data.get("parent_class"),
            visibility=data.get("visibility", "public"),
            references=[CodeLocation.from_dict(r) for r in data.get("references", [])],
            metadata=data.get("metadata", {}),
        )

    def __hash__(self) -> int:
        """Make Symbol hashable."""
        return hash((str(self.file_path), self.line, self.name))

    def __eq__(self, other: object) -> bool:
        """Check equality."""
        if not isinstance(other, Symbol):
            return False
        return (
            self.file_path == other.file_path
            and self.line == other.line
            and self.name == other.name
        )


@dataclass
class FileInfo:
    """
    Information about a source file.

    Contains metadata and extracted symbols from a single file.
    """

    path: Path
    language: str
    size_bytes: int
    lines: int
    symbols: list[Symbol] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    hash: Optional[str] = None  # For caching/change detection
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Ensure path is a Path object."""
        if isinstance(self.path, str):
            self.path = Path(self.path)

    @property
    def functions(self) -> list[Symbol]:
        """Get all function symbols."""
        return [s for s in self.symbols if s.type == SymbolType.FUNCTION]

    @property
    def methods(self) -> list[Symbol]:
        """Get all method symbols."""
        return [s for s in self.symbols if s.type == SymbolType.METHOD]

    @property
    def classes(self) -> list[Symbol]:
        """Get all class symbols."""
        return [s for s in self.symbols if s.type == SymbolType.CLASS]

    @property
    def variables(self) -> list[Symbol]:
        """Get all variable symbols."""
        return [s for s in self.symbols if s.type == SymbolType.VARIABLE]

    def get_symbol_by_name(self, name: str) -> Optional[Symbol]:
        """Find a symbol by name."""
        for symbol in self.symbols:
            if symbol.name == name or symbol.qualified_name == name:
                return symbol
        return None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "path": str(self.path),
            "language": self.language,
            "size_bytes": self.size_bytes,
            "lines": self.lines,
            "symbols": [s.to_dict() for s in self.symbols],
            "imports": self.imports,
            "exports": self.exports,
            "hash": self.hash,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FileInfo":
        """Deserialize from dictionary."""
        return cls(
            path=Path(data["path"]),
            language=data["language"],
            size_bytes=data["size_bytes"],
            lines=data["lines"],
            symbols=[Symbol.from_dict(s) for s in data.get("symbols", [])],
            imports=data.get("imports", []),
            exports=data.get("exports", []),
            hash=data.get("hash"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class RepoMap:
    """
    Repository structural map - output of Phase I.

    Contains the complete structural understanding of a codebase:
    - All parsed files and their symbols
    - Dependency graph (which files import which)
    - PageRank scores for file importance
    """

    root_path: Path
    files: list[FileInfo]
    symbols: list[Symbol]
    dependencies: dict[str, list[str]]  # file -> [imported files]
    rankings: dict[str, float]  # file -> PageRank score
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    version: str = "1.0"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Ensure root_path is a Path object."""
        if isinstance(self.root_path, str):
            self.root_path = Path(self.root_path)

    @property
    def file_count(self) -> int:
        """Get total number of files."""
        return len(self.files)

    @property
    def symbol_count(self) -> int:
        """Get total number of symbols."""
        return len(self.symbols)

    @property
    def total_lines(self) -> int:
        """Get total lines of code."""
        return sum(f.lines for f in self.files)

    @property
    def languages(self) -> set[str]:
        """Get set of languages in the repository."""
        return {f.language for f in self.files}

    def get_file(self, path: Path | str) -> Optional[FileInfo]:
        """Get FileInfo by path."""
        if isinstance(path, str):
            path = Path(path)
        for f in self.files:
            if f.path == path:
                return f
        return None

    def get_symbol(self, name: str) -> Optional[Symbol]:
        """Find a symbol by name across all files."""
        for symbol in self.symbols:
            if symbol.name == name or symbol.qualified_name == name:
                return symbol
        return None

    def get_symbols_by_type(self, symbol_type: SymbolType) -> list[Symbol]:
        """Get all symbols of a specific type."""
        return [s for s in self.symbols if s.type == symbol_type]

    def get_top_files(self, n: int = 10) -> list[FileInfo]:
        """Get top N files by PageRank score."""
        sorted_files = sorted(
            self.files,
            key=lambda f: self.rankings.get(str(f.path), 0),
            reverse=True,
        )
        return sorted_files[:n]

    def get_dependents(self, file_path: str) -> list[str]:
        """Get files that import the given file."""
        dependents = []
        for f, deps in self.dependencies.items():
            if file_path in deps:
                dependents.append(f)
        return dependents

    def to_json(self, path: Path) -> None:
        """Serialize to JSON file."""
        data = {
            "version": self.version,
            "root_path": str(self.root_path),
            "files": [f.to_dict() for f in self.files],
            "symbols": [s.to_dict() for s in self.symbols],
            "dependencies": self.dependencies,
            "rankings": self.rankings,
            "generated_at": self.generated_at.isoformat(),
            "metadata": self.metadata,
            "statistics": {
                "file_count": self.file_count,
                "symbol_count": self.symbol_count,
                "total_lines": self.total_lines,
                "languages": list(self.languages),
            },
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def from_json(cls, path: Path) -> "RepoMap":
        """Deserialize from JSON file."""
        with open(path) as f:
            data = json.load(f)

        return cls(
            root_path=Path(data["root_path"]),
            files=[FileInfo.from_dict(f) for f in data["files"]],
            symbols=[Symbol.from_dict(s) for s in data["symbols"]],
            dependencies=data["dependencies"],
            rankings=data["rankings"],
            generated_at=datetime.fromisoformat(data["generated_at"]),
            version=data.get("version", "1.0"),
            metadata=data.get("metadata", {}),
        )

    def summary(self) -> dict[str, Any]:
        """Generate summary statistics."""
        return {
            "root_path": str(self.root_path),
            "file_count": self.file_count,
            "symbol_count": self.symbol_count,
            "total_lines": self.total_lines,
            "languages": list(self.languages),
            "generated_at": self.generated_at.isoformat(),
            "symbols_by_type": {
                st.value: len(self.get_symbols_by_type(st))
                for st in SymbolType
            },
        }
