"""
Specification models for Phase II output.

These models represent the dynamic taint specifications:
- TaintSpec: Individual source/sink/sanitizer specification
- DynamicSpec: Complete specification for a repository (context_rules.json)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cerberus.models.base import TaintLabel, VulnerabilityType


@dataclass
class TaintSpec:
    """
    Single taint specification entry.

    Represents a method/function that has been classified as a
    source, sink, sanitizer, or propagator.
    """

    method: str
    file_path: Path
    line: int
    label: TaintLabel
    class_name: Optional[str] = None
    parameter_index: Optional[int] = None  # Which parameter is tainted
    return_tainted: bool = False  # Whether return value is tainted
    confidence: float = 0.0
    reason: str = ""
    vulnerability_types: list[str] = field(default_factory=list)  # CWE IDs
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Ensure proper types."""
        if isinstance(self.file_path, str):
            self.file_path = Path(self.file_path)
        if isinstance(self.label, str):
            self.label = TaintLabel.from_string(self.label)

    @property
    def qualified_name(self) -> str:
        """Get fully qualified method name."""
        if self.class_name:
            return f"{self.class_name}.{self.method}"
        return self.method

    @property
    def is_source(self) -> bool:
        """Check if this is a source."""
        return self.label == TaintLabel.SOURCE

    @property
    def is_sink(self) -> bool:
        """Check if this is a sink."""
        return self.label == TaintLabel.SINK

    @property
    def is_sanitizer(self) -> bool:
        """Check if this is a sanitizer."""
        return self.label == TaintLabel.SANITIZER

    @property
    def is_propagator(self) -> bool:
        """Check if this is a propagator."""
        return self.label == TaintLabel.PROPAGATOR

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "method": self.method,
            "class": self.class_name,
            "file": str(self.file_path),
            "line": self.line,
            "label": self.label.value,
            "parameter_index": self.parameter_index,
            "return_tainted": self.return_tainted,
            "confidence": self.confidence,
            "reason": self.reason,
            "vulnerability_types": self.vulnerability_types,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TaintSpec":
        """Deserialize from dictionary."""
        return cls(
            method=data["method"],
            class_name=data.get("class"),
            file_path=Path(data["file"]),
            line=data["line"],
            label=TaintLabel(data["label"]),
            parameter_index=data.get("parameter_index"),
            return_tainted=data.get("return_tainted", False),
            confidence=data.get("confidence", 0.0),
            reason=data.get("reason", ""),
            vulnerability_types=data.get("vulnerability_types", []),
            metadata=data.get("metadata", {}),
        )

    def matches(self, method_name: str, class_name: Optional[str] = None) -> bool:
        """Check if this spec matches a given method."""
        if class_name and self.class_name:
            return self.method == method_name and self.class_name == class_name
        return self.method == method_name

    def __hash__(self) -> int:
        """Make TaintSpec hashable."""
        return hash((str(self.file_path), self.line, self.method, self.label.value))

    def __eq__(self, other: object) -> bool:
        """Check equality."""
        if not isinstance(other, TaintSpec):
            return False
        return (
            self.file_path == other.file_path
            and self.line == other.line
            and self.method == other.method
            and self.label == other.label
        )


@dataclass
class DynamicSpec:
    """
    Complete dynamic specification for a repository - output of Phase II.

    This is the context_rules.json that contains all inferred
    sources, sinks, sanitizers, and propagators.
    """

    repository: str = ""
    version: str = "1.0"
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sources: list[TaintSpec] = field(default_factory=list)
    sinks: list[TaintSpec] = field(default_factory=list)
    sanitizers: list[TaintSpec] = field(default_factory=list)
    propagators: list[TaintSpec] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def total_specs(self) -> int:
        """Get total number of specifications."""
        return len(self.sources) + len(self.sinks) + len(self.sanitizers) + len(self.propagators)

    def add_source(self, spec: TaintSpec) -> bool:
        """
        Add a source specification.

        Returns:
            True if added, False if already exists
        """
        spec.label = TaintLabel.SOURCE
        if spec not in self.sources:
            self.sources.append(spec)
            return True
        return False

    def add_sink(self, spec: TaintSpec) -> bool:
        """
        Add a sink specification.

        Returns:
            True if added, False if already exists
        """
        spec.label = TaintLabel.SINK
        if spec not in self.sinks:
            self.sinks.append(spec)
            return True
        return False

    def add_sanitizer(self, spec: TaintSpec) -> bool:
        """
        Add a sanitizer specification.

        Used by the feedback loop when a false positive is caused
        by a missed sanitizer.

        Returns:
            True if added, False if already exists
        """
        spec.label = TaintLabel.SANITIZER
        if spec not in self.sanitizers:
            self.sanitizers.append(spec)
            return True
        return False

    def add_propagator(self, spec: TaintSpec) -> bool:
        """
        Add a propagator specification.

        Returns:
            True if added, False if already exists
        """
        spec.label = TaintLabel.PROPAGATOR
        if spec not in self.propagators:
            self.propagators.append(spec)
            return True
        return False

    def get_source_methods(self) -> list[str]:
        """Get list of source method names for CPGQL queries."""
        return [s.method for s in self.sources]

    def get_sink_methods(self) -> list[str]:
        """Get list of sink method names for CPGQL queries."""
        return [s.method for s in self.sinks]

    def get_sanitizer_methods(self) -> list[str]:
        """Get list of sanitizer method names for CPGQL queries."""
        return [s.method for s in self.sanitizers]

    def get_propagator_methods(self) -> list[str]:
        """Get list of propagator method names for CPGQL queries."""
        return [s.method for s in self.propagators]

    def get_sinks_for_vuln_type(self, vuln_type: str) -> list[TaintSpec]:
        """Get sinks that can lead to a specific vulnerability type."""
        return [s for s in self.sinks if vuln_type in s.vulnerability_types]

    def is_source(self, method_name: str, class_name: Optional[str] = None) -> bool:
        """Check if a method is a source."""
        return any(s.matches(method_name, class_name) for s in self.sources)

    def is_sink(self, method_name: str, class_name: Optional[str] = None) -> bool:
        """Check if a method is a sink."""
        return any(s.matches(method_name, class_name) for s in self.sinks)

    def is_sanitizer(self, method_name: str, class_name: Optional[str] = None) -> bool:
        """Check if a method is a sanitizer."""
        return any(s.matches(method_name, class_name) for s in self.sanitizers)

    def get_by_method(self, method_name: str) -> Optional[TaintSpec]:
        """Get spec for a method name."""
        all_specs = self.sources + self.sinks + self.sanitizers + self.propagators
        for spec in all_specs:
            if spec.method == method_name or spec.qualified_name == method_name:
                return spec
        return None

    def to_json(self, path: Path) -> None:
        """Serialize to context_rules.json."""
        data = {
            "version": self.version,
            "repository": self.repository,
            "generated_at": self.generated_at.isoformat(),
            "sources": [s.to_dict() for s in self.sources],
            "sinks": [s.to_dict() for s in self.sinks],
            "sanitizers": [s.to_dict() for s in self.sanitizers],
            "propagators": [s.to_dict() for s in self.propagators],
            "metadata": self.metadata,
            "statistics": {
                "total_specs": self.total_specs,
                "sources": len(self.sources),
                "sinks": len(self.sinks),
                "sanitizers": len(self.sanitizers),
                "propagators": len(self.propagators),
            },
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def from_json(cls, path: Path) -> "DynamicSpec":
        """Load from context_rules.json."""
        with open(path) as f:
            data = json.load(f)

        return cls(
            repository=data.get("repository", ""),
            version=data.get("version", "1.0"),
            generated_at=datetime.fromisoformat(data["generated_at"]),
            sources=[TaintSpec.from_dict(s) for s in data.get("sources", [])],
            sinks=[TaintSpec.from_dict(s) for s in data.get("sinks", [])],
            sanitizers=[TaintSpec.from_dict(s) for s in data.get("sanitizers", [])],
            propagators=[TaintSpec.from_dict(s) for s in data.get("propagators", [])],
            metadata=data.get("metadata", {}),
        )

    def merge(self, other: "DynamicSpec") -> None:
        """Merge another spec into this one."""
        for spec in other.sources:
            self.add_source(spec)
        for spec in other.sinks:
            self.add_sink(spec)
        for spec in other.sanitizers:
            self.add_sanitizer(spec)
        for spec in other.propagators:
            self.add_propagator(spec)

    def summary(self) -> dict[str, Any]:
        """Generate summary statistics."""
        # Group sinks by vulnerability type
        vuln_types: dict[str, int] = {}
        for sink in self.sinks:
            for vt in sink.vulnerability_types:
                vuln_types[vt] = vuln_types.get(vt, 0) + 1

        return {
            "repository": self.repository,
            "generated_at": self.generated_at.isoformat(),
            "total_specs": self.total_specs,
            "sources": len(self.sources),
            "sinks": len(self.sinks),
            "sanitizers": len(self.sanitizers),
            "propagators": len(self.propagators),
            "vulnerability_types": vuln_types,
            "high_confidence_specs": len(
                [s for s in (self.sources + self.sinks) if s.confidence >= 0.8]
            ),
        }


# Common source/sink patterns for different vulnerability types
COMMON_SOURCE_PATTERNS: dict[str, list[str]] = {
    "web_input": [
        "request.get", "request.post", "request.params",
        "request.query", "request.body", "request.headers",
        "req.query", "req.body", "req.params",
        "getParameter", "getQueryString", "getHeader",
        "input", "stdin", "argv",
    ],
    "database": [
        "query", "execute", "fetch", "find", "findOne",
        "select", "insert", "update", "delete",
    ],
    "file": [
        "read", "readFile", "open", "fopen",
        "readlines", "readline",
    ],
    "environment": [
        "getenv", "os.environ", "process.env",
        "System.getenv",
    ],
}

COMMON_SINK_PATTERNS: dict[str, list[str]] = {
    VulnerabilityType.SQL_INJECTION.value: [
        "execute", "query", "raw", "rawQuery",
        "executeQuery", "executeUpdate",
        "cursor.execute", "db.query",
    ],
    VulnerabilityType.COMMAND_INJECTION.value: [
        "system", "exec", "popen", "spawn",
        "Runtime.exec", "ProcessBuilder",
        "subprocess.run", "os.system",
        "child_process.exec",
    ],
    VulnerabilityType.XSS.value: [
        "innerHTML", "outerHTML", "document.write",
        "render", "template", "dangerouslySetInnerHTML",
    ],
    VulnerabilityType.PATH_TRAVERSAL.value: [
        "open", "readFile", "writeFile",
        "fopen", "include", "require",
        "FileInputStream", "FileOutputStream",
    ],
}
