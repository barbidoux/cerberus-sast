"""
AST-Level Taint Flow Models for Milestone 7.

These models represent extracted sources, sinks, and flow candidates
from Tree-sitter AST traversal:
- SourceType: Type of user input source (request body, params, etc.)
- SinkType: Type of dangerous operation (SQL, command exec, etc.)
- TaintSource: Location where untrusted data enters the application
- TaintSink: Location where data reaches a dangerous operation
- TaintFlowCandidate: Potential taint flow between source and sink
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class SourceType(Enum):
    """Types of user input sources across languages."""

    # JavaScript/TypeScript (Express.js)
    REQUEST_BODY = "request_body"          # req.body
    REQUEST_PARAMS = "request_params"      # req.params
    REQUEST_QUERY = "request_query"        # req.query
    REQUEST_HEADERS = "request_headers"    # req.headers
    REQUEST_COOKIES = "request_cookies"    # req.cookies

    # Python (Flask/Django)
    FLASK_REQUEST = "flask_request"        # request.form, request.args
    DJANGO_REQUEST = "django_request"      # request.GET, request.POST

    # Java (Spring/Servlet)
    SERVLET_PARAM = "servlet_param"        # request.getParameter()
    SPRING_PARAM = "spring_param"          # @RequestParam, @PathVariable

    # PHP
    PHP_SUPERGLOBAL = "php_superglobal"    # $_GET, $_POST, $_REQUEST

    # Go
    GO_REQUEST = "go_request"              # r.URL.Query(), r.FormValue()

    # Environment/Config
    ENVIRONMENT = "environment"            # process.env, os.environ

    # Generic
    USER_INPUT = "user_input"              # Generic user input
    FILE_INPUT = "file_input"              # File read operations
    DATABASE_INPUT = "database_input"      # Data from database

    @classmethod
    def from_string(cls, value: str) -> "SourceType":
        """Create SourceType from string, case-insensitive."""
        try:
            return cls(value.lower())
        except ValueError:
            return cls.USER_INPUT


class SinkType(Enum):
    """Types of dangerous sink operations across languages."""

    # Injection vulnerabilities
    SQL_QUERY = "sql_query"               # query(), execute(), raw SQL
    COMMAND_EXEC = "command_exec"         # exec(), system(), spawn()
    CODE_EXEC = "code_exec"               # eval(), Function(), exec()
    LDAP_QUERY = "ldap_query"             # LDAP operations
    XPATH_QUERY = "xpath_query"           # XPath operations

    # XSS vulnerabilities
    DOM_WRITE = "dom_write"               # innerHTML, document.write
    TEMPLATE_RENDER = "template_render"   # Template rendering
    RESPONSE_WRITE = "response_write"     # res.send(), response.write()

    # File system
    FILE_READ = "file_read"               # readFile(), open()
    FILE_WRITE = "file_write"             # writeFile(), save()
    PATH_ACCESS = "path_access"           # path.join(), file paths

    # Network
    URL_FETCH = "url_fetch"               # fetch(), HTTP requests (SSRF)
    REDIRECT = "redirect"                 # response.redirect()

    # Deserialization
    DESERIALIZE = "deserialize"           # JSON.parse (unsafe), pickle.loads

    # Generic
    DANGEROUS_CALL = "dangerous_call"     # Generic dangerous operation

    @classmethod
    def from_string(cls, value: str) -> "SinkType":
        """Create SinkType from string, case-insensitive."""
        try:
            return cls(value.lower())
        except ValueError:
            return cls.DANGEROUS_CALL


@dataclass
class TaintSource:
    """
    Location where untrusted user data enters the application.

    Extracted from AST member_expression nodes like req.body.username.
    """

    expression: str               # Full expression: "req.body.username"
    source_type: SourceType
    file_path: Path
    line: int
    column: int = 0
    containing_function: Optional[str] = None  # Enclosing function name
    variable_name: Optional[str] = None        # Variable it's assigned to
    cwe_types: list[str] = field(default_factory=list)  # Potential CWEs
    confidence: float = 0.8
    language: str = "javascript"
    metadata: dict[str, Any] = field(default_factory=dict)
    # Milestone 8: LLM Integration
    llm_reasoning: Optional[str] = None        # LLM Chain-of-Thought explanation
    llm_validated: bool = False                # Whether LLM has validated this source

    def __post_init__(self) -> None:
        """Ensure proper types."""
        if isinstance(self.file_path, str):
            self.file_path = Path(self.file_path)
        if isinstance(self.source_type, str):
            self.source_type = SourceType.from_string(self.source_type)

    @property
    def location_key(self) -> str:
        """Unique key for this source location."""
        return f"{self.file_path}:{self.line}:{self.column}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "expression": self.expression,
            "source_type": self.source_type.value,
            "file_path": str(self.file_path),
            "line": self.line,
            "column": self.column,
            "containing_function": self.containing_function,
            "variable_name": self.variable_name,
            "cwe_types": self.cwe_types,
            "confidence": self.confidence,
            "language": self.language,
            "metadata": self.metadata,
            "llm_reasoning": self.llm_reasoning,
            "llm_validated": self.llm_validated,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TaintSource":
        """Deserialize from dictionary."""
        return cls(
            expression=data["expression"],
            source_type=SourceType.from_string(data["source_type"]),
            file_path=Path(data["file_path"]),
            line=data["line"],
            column=data.get("column", 0),
            containing_function=data.get("containing_function"),
            variable_name=data.get("variable_name"),
            cwe_types=data.get("cwe_types", []),
            confidence=data.get("confidence", 0.8),
            language=data.get("language", "javascript"),
            metadata=data.get("metadata", {}),
            llm_reasoning=data.get("llm_reasoning"),
            llm_validated=data.get("llm_validated", False),
        )

    def __hash__(self) -> int:
        """Make hashable."""
        return hash((str(self.file_path), self.line, self.expression))

    def __eq__(self, other: object) -> bool:
        """Check equality."""
        if not isinstance(other, TaintSource):
            return False
        return (
            self.file_path == other.file_path
            and self.line == other.line
            and self.expression == other.expression
        )


@dataclass
class TaintSink:
    """
    Location where data reaches a dangerous operation.

    Extracted from AST call_expression nodes like exec(), query().
    """

    callee: str                   # Function/method name: "query", "exec"
    expression: str               # Full call expression
    sink_type: SinkType
    file_path: Path
    line: int
    column: int = 0
    containing_function: Optional[str] = None
    uses_template_literal: bool = False  # HIGH RISK indicator
    argument_indices: list[int] = field(default_factory=list)  # Which args are tainted
    cwe_types: list[str] = field(default_factory=list)
    confidence: float = 0.85
    language: str = "javascript"
    metadata: dict[str, Any] = field(default_factory=dict)
    # Milestone 8: LLM Integration
    llm_reasoning: Optional[str] = None        # LLM Chain-of-Thought explanation
    llm_validated: bool = False                # Whether LLM has validated this sink

    def __post_init__(self) -> None:
        """Ensure proper types."""
        if isinstance(self.file_path, str):
            self.file_path = Path(self.file_path)
        if isinstance(self.sink_type, str):
            self.sink_type = SinkType.from_string(self.sink_type)

    @property
    def location_key(self) -> str:
        """Unique key for this sink location."""
        return f"{self.file_path}:{self.line}:{self.column}"

    @property
    def is_high_risk(self) -> bool:
        """Check if this is a high-risk sink (template literal with user data)."""
        return self.uses_template_literal

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "callee": self.callee,
            "expression": self.expression,
            "sink_type": self.sink_type.value,
            "file_path": str(self.file_path),
            "line": self.line,
            "column": self.column,
            "containing_function": self.containing_function,
            "uses_template_literal": self.uses_template_literal,
            "argument_indices": self.argument_indices,
            "cwe_types": self.cwe_types,
            "confidence": self.confidence,
            "language": self.language,
            "metadata": self.metadata,
            "llm_reasoning": self.llm_reasoning,
            "llm_validated": self.llm_validated,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TaintSink":
        """Deserialize from dictionary."""
        return cls(
            callee=data["callee"],
            expression=data["expression"],
            sink_type=SinkType.from_string(data["sink_type"]),
            file_path=Path(data["file_path"]),
            line=data["line"],
            column=data.get("column", 0),
            containing_function=data.get("containing_function"),
            uses_template_literal=data.get("uses_template_literal", False),
            argument_indices=data.get("argument_indices", []),
            cwe_types=data.get("cwe_types", []),
            confidence=data.get("confidence", 0.85),
            language=data.get("language", "javascript"),
            metadata=data.get("metadata", {}),
            llm_reasoning=data.get("llm_reasoning"),
            llm_validated=data.get("llm_validated", False),
        )

    def __hash__(self) -> int:
        """Make hashable."""
        return hash((str(self.file_path), self.line, self.callee))

    def __eq__(self, other: object) -> bool:
        """Check equality."""
        if not isinstance(other, TaintSink):
            return False
        return (
            self.file_path == other.file_path
            and self.line == other.line
            and self.callee == other.callee
        )


@dataclass
class FlowTraceStep:
    """Single step in a taint flow trace (lightweight version for AST extraction)."""

    line: int
    column: int = 0
    code: str = ""
    file_path: Optional[Path] = None
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "line": self.line,
            "column": self.column,
            "code": self.code,
            "file_path": str(self.file_path) if self.file_path else None,
            "description": self.description,
        }


@dataclass
class TaintFlowCandidate:
    """
    Potential taint flow between a source and sink.

    Created by matching sources and sinks by CWE type and location.
    Validated by Joern CPG or heuristic analysis.
    """

    source: TaintSource
    sink: TaintSink
    in_same_function: bool = False
    in_same_file: bool = True
    distance_lines: int = 0
    shared_cwe_types: list[str] = field(default_factory=list)

    # Validation results
    joern_validated: bool = False
    heuristic_validated: bool = False
    joern_trace: list[FlowTraceStep] = field(default_factory=list)

    # Confidence scoring
    base_confidence: float = 0.5
    confidence: float = 0.5  # Updated after validation
    confidence_factors: dict[str, float] = field(default_factory=dict)

    # Metadata
    detection_mode: str = "pending"  # "cpg", "heuristic", "pending", "hybrid_ml"
    metadata: dict[str, Any] = field(default_factory=dict)

    # ML-enhanced detection (Milestone 11)
    ml_reasoning: Optional[str] = None  # Reasoning from CodeBERT/LLM
    code_context: Optional[str] = None  # Code context for ML classification

    def __post_init__(self) -> None:
        """Calculate initial values."""
        self.in_same_file = self.source.file_path == self.sink.file_path
        self.distance_lines = abs(self.sink.line - self.source.line)
        self._calculate_shared_cwes()

    def _calculate_shared_cwes(self) -> None:
        """Find CWE types shared between source and sink."""
        source_cwes = set(self.source.cwe_types)
        sink_cwes = set(self.sink.cwe_types)
        self.shared_cwe_types = list(source_cwes & sink_cwes)

    @property
    def is_valid_candidate(self) -> bool:
        """Check if this is a valid candidate (shared CWE types)."""
        return len(self.shared_cwe_types) > 0

    @property
    def primary_cwe(self) -> Optional[str]:
        """Get the primary (most severe) CWE type."""
        # Severity order: CWE-78 > CWE-89 > CWE-94 > CWE-22 > CWE-79
        severity_order = ["CWE-78", "CWE-89", "CWE-94", "CWE-22", "CWE-79", "CWE-918"]
        for cwe in severity_order:
            if cwe in self.shared_cwe_types:
                return cwe
        return self.shared_cwe_types[0] if self.shared_cwe_types else None

    def apply_heuristic_scoring(self) -> None:
        """
        Apply heuristic confidence scoring.

        Scoring factors:
        - Same function: +0.3
        - Template literal: +0.4
        - Line proximity (<10): +0.2
        - Same file: +0.1
        """
        self.confidence = self.base_confidence
        self.confidence_factors = {}

        # Same function bonus
        if self.in_same_function:
            self.confidence += 0.3
            self.confidence_factors["same_function"] = 0.3

        # Template literal is HIGH RISK
        if self.sink.uses_template_literal:
            self.confidence += 0.4
            self.confidence_factors["template_literal"] = 0.4

        # Line proximity bonus
        if self.distance_lines < 10:
            self.confidence += 0.2
            self.confidence_factors["line_proximity"] = 0.2
        elif self.distance_lines < 20:
            self.confidence += 0.1
            self.confidence_factors["line_proximity"] = 0.1

        # Same file bonus (already expected for most cases)
        if self.in_same_file:
            self.confidence += 0.1
            self.confidence_factors["same_file"] = 0.1

        # Cap at 0.95 for heuristic-only (reserve 0.95+ for CPG-validated)
        self.confidence = min(self.confidence, 0.94)
        self.heuristic_validated = True
        self.detection_mode = "heuristic"

    def apply_cpg_validation(self, trace: list[FlowTraceStep]) -> None:
        """
        Apply CPG-validated confidence.

        CPG validation gives high confidence (0.95+).
        """
        self.joern_validated = True
        self.joern_trace = trace
        self.confidence = 0.95
        self.confidence_factors["cpg_validated"] = 0.95
        self.detection_mode = "cpg"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "source": self.source.to_dict(),
            "sink": self.sink.to_dict(),
            "in_same_function": self.in_same_function,
            "in_same_file": self.in_same_file,
            "distance_lines": self.distance_lines,
            "shared_cwe_types": self.shared_cwe_types,
            "joern_validated": self.joern_validated,
            "heuristic_validated": self.heuristic_validated,
            "joern_trace": [step.to_dict() for step in self.joern_trace],
            "base_confidence": self.base_confidence,
            "confidence": self.confidence,
            "confidence_factors": self.confidence_factors,
            "detection_mode": self.detection_mode,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TaintFlowCandidate":
        """Deserialize from dictionary."""
        candidate = cls(
            source=TaintSource.from_dict(data["source"]),
            sink=TaintSink.from_dict(data["sink"]),
            in_same_function=data.get("in_same_function", False),
        )
        candidate.joern_validated = data.get("joern_validated", False)
        candidate.heuristic_validated = data.get("heuristic_validated", False)
        candidate.confidence = data.get("confidence", 0.5)
        candidate.confidence_factors = data.get("confidence_factors", {})
        candidate.detection_mode = data.get("detection_mode", "pending")
        candidate.metadata = data.get("metadata", {})
        return candidate

    def __hash__(self) -> int:
        """Make hashable."""
        return hash((self.source.location_key, self.sink.location_key))

    def __eq__(self, other: object) -> bool:
        """Check equality."""
        if not isinstance(other, TaintFlowCandidate):
            return False
        return self.source == other.source and self.sink == other.sink


# Language-specific source patterns for multi-language support
LANGUAGE_SOURCE_PATTERNS: dict[str, dict[str, tuple[SourceType, list[str]]]] = {
    "javascript": {
        "req.body": (SourceType.REQUEST_BODY, ["CWE-89", "CWE-78", "CWE-79", "CWE-22"]),
        "req.params": (SourceType.REQUEST_PARAMS, ["CWE-89", "CWE-78", "CWE-22"]),
        "req.query": (SourceType.REQUEST_QUERY, ["CWE-89", "CWE-78", "CWE-918", "CWE-22"]),
        "req.headers": (SourceType.REQUEST_HEADERS, ["CWE-79"]),
        "req.cookies": (SourceType.REQUEST_COOKIES, ["CWE-79"]),
        "process.env": (SourceType.ENVIRONMENT, ["CWE-78"]),
    },
    "typescript": {
        "req.body": (SourceType.REQUEST_BODY, ["CWE-89", "CWE-78", "CWE-79", "CWE-22"]),
        "req.params": (SourceType.REQUEST_PARAMS, ["CWE-89", "CWE-78", "CWE-22"]),
        "req.query": (SourceType.REQUEST_QUERY, ["CWE-89", "CWE-78", "CWE-918", "CWE-22"]),
        "req.headers": (SourceType.REQUEST_HEADERS, ["CWE-79"]),
        "req.cookies": (SourceType.REQUEST_COOKIES, ["CWE-79"]),
        "process.env": (SourceType.ENVIRONMENT, ["CWE-78"]),
    },
    "python": {
        "request.form": (SourceType.FLASK_REQUEST, ["CWE-89", "CWE-78", "CWE-79", "CWE-22"]),
        "request.args": (SourceType.FLASK_REQUEST, ["CWE-89", "CWE-78", "CWE-918", "CWE-22"]),
        "request.json": (SourceType.FLASK_REQUEST, ["CWE-89", "CWE-78", "CWE-22"]),
        "request.GET": (SourceType.DJANGO_REQUEST, ["CWE-89", "CWE-78", "CWE-918", "CWE-22"]),
        "request.POST": (SourceType.DJANGO_REQUEST, ["CWE-89", "CWE-78", "CWE-79", "CWE-22"]),
        "os.environ": (SourceType.ENVIRONMENT, ["CWE-78"]),
        "sys.argv": (SourceType.USER_INPUT, ["CWE-78", "CWE-22"]),
    },
    "java": {
        "request.getParameter": (SourceType.SERVLET_PARAM, ["CWE-89", "CWE-78", "CWE-79", "CWE-22"]),
        "request.getHeader": (SourceType.REQUEST_HEADERS, ["CWE-79"]),
        "@RequestParam": (SourceType.SPRING_PARAM, ["CWE-89", "CWE-78", "CWE-22"]),
        "@PathVariable": (SourceType.SPRING_PARAM, ["CWE-89", "CWE-22"]),
        "System.getenv": (SourceType.ENVIRONMENT, ["CWE-78"]),
    },
    "php": {
        "$_GET": (SourceType.PHP_SUPERGLOBAL, ["CWE-89", "CWE-78", "CWE-918", "CWE-22"]),
        "$_POST": (SourceType.PHP_SUPERGLOBAL, ["CWE-89", "CWE-78", "CWE-79", "CWE-22"]),
        "$_REQUEST": (SourceType.PHP_SUPERGLOBAL, ["CWE-89", "CWE-78", "CWE-79", "CWE-22"]),
        "$_COOKIE": (SourceType.PHP_SUPERGLOBAL, ["CWE-79"]),
        "$_SERVER": (SourceType.PHP_SUPERGLOBAL, ["CWE-79"]),
        "getenv": (SourceType.ENVIRONMENT, ["CWE-78"]),
    },
    "go": {
        "r.URL.Query": (SourceType.GO_REQUEST, ["CWE-89", "CWE-78", "CWE-918", "CWE-22"]),
        "r.FormValue": (SourceType.GO_REQUEST, ["CWE-89", "CWE-78", "CWE-79", "CWE-22"]),
        "r.PostFormValue": (SourceType.GO_REQUEST, ["CWE-89", "CWE-78", "CWE-22"]),
        "r.Header.Get": (SourceType.REQUEST_HEADERS, ["CWE-79"]),
        "os.Getenv": (SourceType.ENVIRONMENT, ["CWE-78"]),
    },
    "kotlin": {
        "request.getParameter": (SourceType.SERVLET_PARAM, ["CWE-89", "CWE-78", "CWE-22"]),
        "@RequestParam": (SourceType.SPRING_PARAM, ["CWE-89", "CWE-78", "CWE-22"]),
        "@PathVariable": (SourceType.SPRING_PARAM, ["CWE-89", "CWE-22"]),
        "System.getenv": (SourceType.ENVIRONMENT, ["CWE-78"]),
    },
    "c": {
        "getenv": (SourceType.ENVIRONMENT, ["CWE-78"]),
        "fgets": (SourceType.USER_INPUT, ["CWE-120", "CWE-78"]),
        "scanf": (SourceType.USER_INPUT, ["CWE-120", "CWE-78"]),
        "gets": (SourceType.USER_INPUT, ["CWE-120", "CWE-78"]),
        "argv": (SourceType.USER_INPUT, ["CWE-78", "CWE-22"]),
    },
    "cpp": {
        "getenv": (SourceType.ENVIRONMENT, ["CWE-78"]),
        "std::cin": (SourceType.USER_INPUT, ["CWE-120", "CWE-78"]),
        "argv": (SourceType.USER_INPUT, ["CWE-78", "CWE-22"]),
    },
}

# Language-specific sink patterns
LANGUAGE_SINK_PATTERNS: dict[str, dict[str, tuple[SinkType, list[str]]]] = {
    "javascript": {
        # Command Execution (CWE-78)
        "exec": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "execSync": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "spawn": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "spawnSync": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        # SQL Injection (CWE-89)
        "query": (SinkType.SQL_QUERY, ["CWE-89"]),
        "execute": (SinkType.SQL_QUERY, ["CWE-89"]),
        "raw": (SinkType.SQL_QUERY, ["CWE-89"]),
        # Code Execution (CWE-94)
        "eval": (SinkType.CODE_EXEC, ["CWE-94"]),
        "Function": (SinkType.CODE_EXEC, ["CWE-94"]),
        # XSS - DOM Write (CWE-79)
        "innerHTML": (SinkType.DOM_WRITE, ["CWE-79"]),
        "outerHTML": (SinkType.DOM_WRITE, ["CWE-79"]),
        "document.write": (SinkType.DOM_WRITE, ["CWE-79"]),
        "insertAdjacentHTML": (SinkType.DOM_WRITE, ["CWE-79"]),
        # XSS - Response Write (CWE-79)
        "send": (SinkType.RESPONSE_WRITE, ["CWE-79"]),
        "render": (SinkType.TEMPLATE_RENDER, ["CWE-79"]),
        # File System (CWE-22)
        "readFileSync": (SinkType.FILE_READ, ["CWE-22"]),
        "readFile": (SinkType.FILE_READ, ["CWE-22"]),
        "writeFileSync": (SinkType.FILE_WRITE, ["CWE-22"]),
        "writeFile": (SinkType.FILE_WRITE, ["CWE-22"]),
        "readdirSync": (SinkType.FILE_READ, ["CWE-22"]),
        "readdir": (SinkType.FILE_READ, ["CWE-22"]),
        "download": (SinkType.FILE_READ, ["CWE-22"]),
        # SSRF (CWE-918)
        "fetch": (SinkType.URL_FETCH, ["CWE-918"]),
        "axios": (SinkType.URL_FETCH, ["CWE-918"]),
        "get": (SinkType.URL_FETCH, ["CWE-918"]),
        "post": (SinkType.URL_FETCH, ["CWE-918"]),
        # Redirect (CWE-601)
        "redirect": (SinkType.REDIRECT, ["CWE-601"]),
    },
    "typescript": {
        # Command Execution (CWE-78)
        "exec": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "execSync": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "spawn": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        # SQL Injection (CWE-89)
        "query": (SinkType.SQL_QUERY, ["CWE-89"]),
        "execute": (SinkType.SQL_QUERY, ["CWE-89"]),
        # Code Execution (CWE-94)
        "eval": (SinkType.CODE_EXEC, ["CWE-94"]),
        "Function": (SinkType.CODE_EXEC, ["CWE-94"]),
        # XSS - DOM Write (CWE-79)
        "innerHTML": (SinkType.DOM_WRITE, ["CWE-79"]),
        "insertAdjacentHTML": (SinkType.DOM_WRITE, ["CWE-79"]),
        "bypassSecurityTrustHtml": (SinkType.DOM_WRITE, ["CWE-79"]),
        "bypassSecurityTrustScript": (SinkType.CODE_EXEC, ["CWE-94"]),
        "bypassSecurityTrustUrl": (SinkType.REDIRECT, ["CWE-601"]),
        "bypassSecurityTrustResourceUrl": (SinkType.URL_FETCH, ["CWE-918"]),
        # File System (CWE-22)
        "readFileSync": (SinkType.FILE_READ, ["CWE-22"]),
        "writeFileSync": (SinkType.FILE_WRITE, ["CWE-22"]),
        # SSRF (CWE-918)
        "fetch": (SinkType.URL_FETCH, ["CWE-918"]),
        "get": (SinkType.URL_FETCH, ["CWE-918"]),
        "post": (SinkType.URL_FETCH, ["CWE-918"]),
    },
    "python": {
        "execute": (SinkType.SQL_QUERY, ["CWE-89"]),
        "executemany": (SinkType.SQL_QUERY, ["CWE-89"]),
        "raw": (SinkType.SQL_QUERY, ["CWE-89"]),
        "os.system": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "subprocess.run": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "subprocess.call": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "subprocess.Popen": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "eval": (SinkType.CODE_EXEC, ["CWE-94"]),
        "exec": (SinkType.CODE_EXEC, ["CWE-94"]),
        "open": (SinkType.FILE_READ, ["CWE-22"]),
        "requests.get": (SinkType.URL_FETCH, ["CWE-918"]),
        "requests.post": (SinkType.URL_FETCH, ["CWE-918"]),
        "urllib.request.urlopen": (SinkType.URL_FETCH, ["CWE-918"]),
        "pickle.loads": (SinkType.DESERIALIZE, ["CWE-502"]),
        "yaml.load": (SinkType.DESERIALIZE, ["CWE-502"]),
    },
    "java": {
        "executeQuery": (SinkType.SQL_QUERY, ["CWE-89"]),
        "executeUpdate": (SinkType.SQL_QUERY, ["CWE-89"]),
        "execute": (SinkType.SQL_QUERY, ["CWE-89"]),
        "Runtime.exec": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "ProcessBuilder": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "ScriptEngine.eval": (SinkType.CODE_EXEC, ["CWE-94"]),
        "FileInputStream": (SinkType.FILE_READ, ["CWE-22"]),
        "FileOutputStream": (SinkType.FILE_WRITE, ["CWE-22"]),
        "URL.openConnection": (SinkType.URL_FETCH, ["CWE-918"]),
        "HttpURLConnection": (SinkType.URL_FETCH, ["CWE-918"]),
        "ObjectInputStream.readObject": (SinkType.DESERIALIZE, ["CWE-502"]),
        "response.sendRedirect": (SinkType.REDIRECT, ["CWE-601"]),
    },
    "php": {
        "mysqli_query": (SinkType.SQL_QUERY, ["CWE-89"]),
        "mysql_query": (SinkType.SQL_QUERY, ["CWE-89"]),
        "pg_query": (SinkType.SQL_QUERY, ["CWE-89"]),
        "exec": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "system": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "passthru": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "shell_exec": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "eval": (SinkType.CODE_EXEC, ["CWE-94"]),
        "include": (SinkType.FILE_READ, ["CWE-22", "CWE-98"]),
        "require": (SinkType.FILE_READ, ["CWE-22", "CWE-98"]),
        "file_get_contents": (SinkType.FILE_READ, ["CWE-22", "CWE-918"]),
        "file_put_contents": (SinkType.FILE_WRITE, ["CWE-22"]),
        "unserialize": (SinkType.DESERIALIZE, ["CWE-502"]),
        "header": (SinkType.REDIRECT, ["CWE-601"]),
    },
    "go": {
        "db.Query": (SinkType.SQL_QUERY, ["CWE-89"]),
        "db.Exec": (SinkType.SQL_QUERY, ["CWE-89"]),
        "exec.Command": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "os.Open": (SinkType.FILE_READ, ["CWE-22"]),
        "os.Create": (SinkType.FILE_WRITE, ["CWE-22"]),
        "ioutil.ReadFile": (SinkType.FILE_READ, ["CWE-22"]),
        "http.Get": (SinkType.URL_FETCH, ["CWE-918"]),
        "http.Post": (SinkType.URL_FETCH, ["CWE-918"]),
        "http.Redirect": (SinkType.REDIRECT, ["CWE-601"]),
    },
    "kotlin": {
        "executeQuery": (SinkType.SQL_QUERY, ["CWE-89"]),
        "execute": (SinkType.SQL_QUERY, ["CWE-89"]),
        "Runtime.getRuntime().exec": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "ProcessBuilder": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "File": (SinkType.FILE_READ, ["CWE-22"]),
        "URL": (SinkType.URL_FETCH, ["CWE-918"]),
    },
    "c": {
        "system": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "popen": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "execve": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "execl": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "fopen": (SinkType.FILE_READ, ["CWE-22"]),
        "sprintf": (SinkType.DANGEROUS_CALL, ["CWE-120"]),
        "strcpy": (SinkType.DANGEROUS_CALL, ["CWE-120"]),
        "strcat": (SinkType.DANGEROUS_CALL, ["CWE-120"]),
        "gets": (SinkType.DANGEROUS_CALL, ["CWE-120"]),
    },
    "cpp": {
        "system": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "popen": (SinkType.COMMAND_EXEC, ["CWE-78"]),
        "std::ifstream": (SinkType.FILE_READ, ["CWE-22"]),
        "std::ofstream": (SinkType.FILE_WRITE, ["CWE-22"]),
    },
}
