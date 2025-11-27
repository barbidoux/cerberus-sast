"""
Joern Client for CPG operations.

Provides interface to Joern server for:
- Code import and CPG generation
- CPGQL query execution
- Data flow analysis
- Program slicing
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


class JoernError(Exception):
    """Base exception for Joern errors."""

    def __init__(self, message: str, query: Optional[str] = None) -> None:
        self.query = query
        if query:
            message = f"{message}\nQuery: {query}"
        super().__init__(message)


class JoernImportError(JoernError):
    """Error during code import."""

    def __init__(
        self,
        message: str,
        path: Optional[Path] = None,
        query: Optional[str] = None,
    ) -> None:
        self.path = path
        if path:
            message = f"{message}\nPath: {path}"
        super().__init__(message, query)


@dataclass
class JoernConfig:
    """Configuration for Joern client."""

    endpoint: str = "localhost:8080"
    workspace: Path = field(default_factory=lambda: Path("/tmp/joern-workspace"))
    timeout: int = 60
    username: Optional[str] = None
    password: Optional[str] = None

    def __post_init__(self) -> None:
        """Ensure workspace is a Path."""
        if isinstance(self.workspace, str):
            self.workspace = Path(self.workspace)

    @property
    def url(self) -> str:
        """Get full HTTP URL for the endpoint."""
        if self.endpoint.startswith(("http://", "https://")):
            return self.endpoint
        return f"http://{self.endpoint}"


@dataclass
class QueryResult:
    """Result from a CPGQL query."""

    success: bool
    data: Optional[str] = None
    error: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> list[Any]:
        """Parse data as JSON array."""
        if not self.data:
            return []
        try:
            result = json.loads(self.data)
            if isinstance(result, list):
                return result
            return [result]
        except json.JSONDecodeError:
            return []

    def to_dict(self) -> dict[str, Any]:
        """Parse data as JSON object."""
        if not self.data:
            return {}
        try:
            result = json.loads(self.data)
            if isinstance(result, dict):
                return result
            return {}
        except json.JSONDecodeError:
            return {}


@dataclass
class Flow:
    """Represents a data flow from source to sink."""

    source: dict[str, Any]
    sink: dict[str, Any]
    trace: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Flow":
        """Create Flow from dictionary."""
        return cls(
            source=data.get("source", {}),
            sink=data.get("sink", {}),
            trace=data.get("trace", []),
            metadata=data.get("metadata", {}),
        )


class JoernClient:
    """Client for interacting with Joern server.

    Provides methods for:
    - Importing code and generating CPGs
    - Executing CPGQL queries
    - Finding data flows
    - Extracting program slices
    """

    def __init__(self, config: Optional[JoernConfig] = None) -> None:
        """Initialize Joern client.

        Args:
            config: Joern configuration. Uses defaults if not provided.
        """
        self.config = config or JoernConfig()
        self._session: Optional[Any] = None

    async def is_available(self) -> bool:
        """Check if Joern server is available.

        Returns:
            True if server is reachable and ready.
        """
        try:
            await self._http_get("/")
            return True
        except Exception:
            return False

    async def import_code(
        self,
        path: Path,
        project_name: str,
        language: Optional[str] = None,
    ) -> None:
        """Import code and generate CPG.

        Args:
            path: Path to source code directory.
            project_name: Name for the project/CPG.
            language: Optional language hint (python, java, javascript, etc.).

        Raises:
            JoernImportError: If import fails.
        """
        # Build import query based on language
        if language:
            query = self._build_import_query(path, project_name, language)
        else:
            query = f'importCode("{path}", "{project_name}")'

        result = await self._execute_query(query)

        if not result.success:
            raise JoernImportError(
                result.error or "Failed to import code",
                path=path,
                query=query,
            )

    async def query(self, cpgql: str) -> QueryResult:
        """Execute CPGQL query.

        Args:
            cpgql: The CPGQL query string.

        Returns:
            QueryResult with data or error.

        Raises:
            JoernError: On connection or timeout errors.
        """
        try:
            response = await self._http_post("/query", {"query": cpgql})

            if response.get("success", False):
                return QueryResult(
                    success=True,
                    data=response.get("stdout", ""),
                    metadata={"query": cpgql},
                )
            else:
                return QueryResult(
                    success=False,
                    error=response.get("stderr", "Query failed"),
                    metadata={"query": cpgql},
                )

        except TimeoutError as e:
            raise JoernError(f"Query timeout: {e}", query=cpgql)
        except Exception as e:
            raise JoernError(f"Query failed: {e}", query=cpgql)

    async def find_flows(
        self,
        source: str,
        sink: str,
        exclude_sanitizers: Optional[list[str]] = None,
    ) -> list[Flow]:
        """Find data flows from source to sink.

        Args:
            source: Source method name.
            sink: Sink method name.
            exclude_sanitizers: Methods to exclude from paths.

        Returns:
            List of Flow objects representing data flow paths.
        """
        # Build the flow query
        sanitizer_filter = ""
        if exclude_sanitizers:
            sanitizer_names = "|".join(exclude_sanitizers)
            sanitizer_filter = (
                f'.whereNot(_.reachableBy(cpg.method.name("{sanitizer_names}")))'
            )

        query = f"""
        def source = cpg.method.name("{source}").parameter
        def sink = cpg.method.name("{sink}").parameter
        sink.reachableBy(source){sanitizer_filter}.map {{ path =>
            Map(
                "source" -> Map("method" -> "{source}", "line" -> path.head.lineNumber.getOrElse(-1)),
                "sink" -> Map("method" -> "{sink}", "line" -> path.last.lineNumber.getOrElse(-1)),
                "trace" -> path.map(n => Map("line" -> n.lineNumber.getOrElse(-1), "code" -> n.code))
            )
        }}.toJson
        """

        result = await self.query(query)

        if not result.success:
            return []

        flows_data = result.to_json()
        return [Flow.from_dict(f) for f in flows_data]

    async def get_methods(self) -> list[dict[str, Any]]:
        """Get all methods in the CPG.

        Returns:
            List of method information dictionaries.
        """
        query = """
        cpg.method.map(m => Map(
            "name" -> m.name,
            "fullName" -> m.fullName,
            "lineNumber" -> m.lineNumber.getOrElse(-1),
            "file" -> m.filename
        )).toJson
        """

        result = await self.query(query)
        return result.to_json() if result.success else []

    async def get_method(self, name: str) -> Optional[dict[str, Any]]:
        """Get method by name.

        Args:
            name: Method name to find.

        Returns:
            Method information or None if not found.
        """
        query = f"""
        cpg.method.name("{name}").map(m => Map(
            "name" -> m.name,
            "fullName" -> m.fullName,
            "lineNumber" -> m.lineNumber.getOrElse(-1),
            "code" -> m.code,
            "file" -> m.filename
        )).headOption.map(_.toJson).getOrElse("null")
        """

        result = await self.query(query)
        if result.success and result.data and result.data != "null":
            data = result.to_json()
            return data[0] if data else None
        return None

    async def get_calls_to(self, method_name: str) -> list[dict[str, Any]]:
        """Get all call sites for a method.

        Args:
            method_name: Name of the called method.

        Returns:
            List of call site information.
        """
        query = f"""
        cpg.call.name("{method_name}").map(c => Map(
            "lineNumber" -> c.lineNumber.getOrElse(-1),
            "file" -> c.file.name.headOption.getOrElse("unknown"),
            "code" -> c.code
        )).toJson
        """

        result = await self.query(query)
        return result.to_json() if result.success else []

    async def get_slice(
        self,
        source_line: int,
        sink_line: int,
        file_path: str,
    ) -> list[dict[str, Any]]:
        """Get program slice between source and sink.

        Args:
            source_line: Source line number.
            sink_line: Sink line number.
            file_path: Path to the file.

        Returns:
            List of slice lines with code.
        """
        query = f"""
        cpg.method.filename("{file_path}").ast
            .filter(n => n.lineNumber.exists(l => l >= {source_line} && l <= {sink_line}))
            .map(n => Map(
                "lineNumber" -> n.lineNumber.getOrElse(-1),
                "code" -> n.code
            ))
            .dedup
            .toJson
        """

        result = await self.query(query)
        return result.to_json() if result.success else []

    async def get_control_structures(
        self,
        file_path: str,
        start_line: int,
        end_line: int,
    ) -> list[dict[str, Any]]:
        """Get control structures in a line range.

        Args:
            file_path: Path to the file.
            start_line: Start line number.
            end_line: End line number.

        Returns:
            List of control structure information.
        """
        query = f"""
        cpg.method.filename("{file_path}")
            .controlStructure
            .filter(cs => cs.lineNumber.exists(l => l >= {start_line} && l <= {end_line}))
            .map(cs => Map(
                "type" -> cs.controlStructureType,
                "lineNumber" -> cs.lineNumber.getOrElse(-1),
                "code" -> cs.code
            ))
            .toJson
        """

        result = await self.query(query)
        return result.to_json() if result.success else []

    async def close(self) -> None:
        """Close the client connection."""
        if self._session:
            await self._session.close()
            self._session = None

    def _build_import_query(
        self,
        path: Path,
        project_name: str,
        language: str,
    ) -> str:
        """Build language-specific import query."""
        language_map = {
            "python": "py2cpg",
            "java": "java2cpg",
            "javascript": "jssrc2cpg",
            "typescript": "jssrc2cpg",
            "c": "c2cpg",
            "cpp": "c2cpg",
            "go": "go2cpg",
        }

        generator = language_map.get(language.lower(), "importCode")

        if generator == "importCode":
            return f'importCode("{path}", "{project_name}")'
        else:
            return f'{generator}("{path}", "{project_name}")'

    async def _execute_query(self, query: str) -> QueryResult:
        """Execute a query and return result."""
        return await self.query(query)

    async def _http_get(self, path: str) -> dict[str, Any]:
        """Make HTTP GET request to Joern server."""
        # This would use aiohttp in production
        # For now, return mock response for testing
        import aiohttp

        url = f"{self.config.url}{path}"

        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout),
            ) as response:
                return await response.json()

    async def _http_post(
        self,
        path: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Make HTTP POST request to Joern server."""
        import aiohttp

        url = f"{self.config.url}{path}"

        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=data,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout),
            ) as response:
                return await response.json()
