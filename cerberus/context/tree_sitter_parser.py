"""
Universal AST generation using Tree-sitter.

Provides parsing for all Joern-supported languages.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from cerberus.utils.logging import ComponentLogger

# Language extension mappings (all 12 Joern-supported languages)
LANGUAGE_EXTENSIONS: dict[str, str] = {
    # C/C++
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".c++": "cpp",
    ".h++": "cpp",
    # Java
    ".java": "java",
    # JavaScript/TypeScript
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    # Python
    ".py": "python",
    ".pyi": "python",
    # Kotlin
    ".kt": "kotlin",
    ".kts": "kotlin",
    # PHP
    ".php": "php",
    ".phtml": "php",
    ".php3": "php",
    ".php4": "php",
    ".php5": "php",
    ".php7": "php",
    ".phps": "php",
    # Go
    ".go": "go",
    # Swift
    ".swift": "swift",
    # Ruby
    ".rb": "ruby",
    ".rake": "ruby",
    ".gemspec": "ruby",
    # C#
    ".cs": "csharp",
    # Scala (Joern's native language)
    ".scala": "scala",
    ".sc": "scala",
}

# Tree-sitter language name mappings
TREE_SITTER_LANGUAGES: dict[str, str] = {
    "c": "c",
    "cpp": "cpp",
    "java": "java",
    "javascript": "javascript",
    "typescript": "typescript",
    "python": "python",
    "kotlin": "kotlin",
    "php": "php",
    "go": "go",
    "swift": "swift",
    "ruby": "ruby",
    "csharp": "c_sharp",
    "scala": "scala",
}


class TreeSitterParser:
    """Universal AST generation using Tree-sitter."""

    def __init__(self) -> None:
        """Initialize the parser."""
        self.logger = ComponentLogger("tree_sitter")
        self._parsers: dict[str, Any] = {}

    def _get_parser(self, language: str) -> Optional[Any]:
        """
        Get or create parser for a language.

        Args:
            language: Language name (e.g., "python", "javascript")

        Returns:
            Tree-sitter parser for the language, or None if not available
        """
        if language not in self._parsers:
            try:
                import tree_sitter_languages

                ts_lang = TREE_SITTER_LANGUAGES.get(language, language)
                self._parsers[language] = tree_sitter_languages.get_parser(ts_lang)
                self.logger.debug(f"Loaded parser for {language}")
            except Exception as e:
                self.logger.warning(f"No parser available for {language}: {e}")
                return None
        return self._parsers.get(language)

    def detect_language(self, file_path: Path) -> Optional[str]:
        """
        Detect language from file extension.

        Args:
            file_path: Path to the source file

        Returns:
            Language name or None if not recognized
        """
        return LANGUAGE_EXTENSIONS.get(file_path.suffix.lower())

    def parse_file(self, file_path: Path, language: Optional[str] = None) -> Optional[Any]:
        """
        Parse a single file into an AST.

        Args:
            file_path: Path to the source file
            language: Optional language override

        Returns:
            Tree-sitter tree or None if parsing failed
        """
        if language is None:
            language = self.detect_language(file_path)
        if not language:
            self.logger.debug(f"Unknown language for {file_path}")
            return None

        parser = self._get_parser(language)
        if not parser:
            return None

        try:
            with open(file_path, "rb") as f:
                content = f.read()
            tree = parser.parse(content)
            self.logger.debug(f"Parsed {file_path}", language=language)
            return tree
        except Exception as e:
            self.logger.warning(f"Failed to parse {file_path}: {e}")
            return None

    def parse_bytes(self, content: bytes, language: str) -> Optional[Any]:
        """
        Parse source code bytes into an AST.

        Args:
            content: Source code as bytes
            language: Language name

        Returns:
            Tree-sitter tree or None if parsing failed
        """
        parser = self._get_parser(language)
        if not parser:
            return None

        try:
            return parser.parse(content)
        except Exception as e:
            self.logger.warning(f"Failed to parse content: {e}")
            return None

    def parse_string(self, content: str, language: str) -> Optional[Any]:
        """
        Parse source code string into an AST.

        Args:
            content: Source code as string
            language: Language name

        Returns:
            Tree-sitter tree or None if parsing failed
        """
        return self.parse_bytes(content.encode("utf-8"), language)

    def parse_repository(
        self,
        repo_path: Path,
        exclude_patterns: Optional[list[str]] = None,
        max_file_size_mb: int = 10,
        languages: Optional[list[str]] = None,
    ) -> dict[Path, Any]:
        """
        Parse all supported files in a repository.

        Args:
            repo_path: Path to repository root
            exclude_patterns: Glob patterns to exclude
            max_file_size_mb: Maximum file size in MB
            languages: List of languages to include (None = all)

        Returns:
            Dictionary mapping file paths to AST trees
        """
        import fnmatch

        trees: dict[Path, Any] = {}
        exclude_patterns = exclude_patterns or []
        max_size = max_file_size_mb * 1024 * 1024

        # Discover files
        for file_path in self._discover_files(repo_path, languages):
            # Check size
            try:
                if file_path.stat().st_size > max_size:
                    self.logger.debug(f"Skipping large file: {file_path}")
                    continue
            except OSError:
                continue

            # Check exclusions
            rel_path = str(file_path.relative_to(repo_path))
            excluded = any(
                fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(file_path.name, pattern)
                for pattern in exclude_patterns
            )
            if excluded:
                continue

            # Parse file
            tree = self.parse_file(file_path)
            if tree:
                trees[file_path] = tree

        self.logger.info(f"Parsed {len(trees)} files from {repo_path}")
        return trees

    def _discover_files(
        self,
        repo_path: Path,
        languages: Optional[list[str]] = None,
    ) -> list[Path]:
        """
        Discover all parseable files in a repository.

        Args:
            repo_path: Repository root path
            languages: List of languages to include (None = all)

        Returns:
            List of file paths
        """
        files: list[Path] = []

        # Determine which extensions to look for
        if languages and "auto" not in languages:
            extensions = {
                ext
                for ext, lang in LANGUAGE_EXTENSIONS.items()
                if lang in languages
            }
        else:
            extensions = set(LANGUAGE_EXTENSIONS.keys())

        # Walk repository
        for ext in extensions:
            for file_path in repo_path.rglob(f"*{ext}"):
                if file_path.is_file():
                    files.append(file_path)

        return sorted(files)

    def get_supported_languages(self) -> set[str]:
        """Get set of supported languages."""
        return set(LANGUAGE_EXTENSIONS.values())

    def get_extensions_for_language(self, language: str) -> list[str]:
        """Get file extensions for a language."""
        return [ext for ext, lang in LANGUAGE_EXTENSIONS.items() if lang == language]
