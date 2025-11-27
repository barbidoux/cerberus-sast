"""
Finding and Slice models for Phase III/IV output.

These models represent:
- TraceStep: Single step in a vulnerability trace
- ProgramSlice: Minimal code context for verification (90% reduction)
- VerificationResult: Output from Multi-Agent Council
- Finding: Complete vulnerability finding
- ScanResult: Complete scan output
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cerberus.models.base import (
    CodeLocation,
    Severity,
    Verdict,
    severity_to_sarif,
    get_cwe_description,
)
from cerberus.models.spec import TaintSpec


@dataclass
class TraceStep:
    """
    Single step in a vulnerability trace.

    Represents one point in the data flow from source to sink.
    """

    location: CodeLocation
    code_snippet: str
    description: str
    step_type: str  # "source", "propagation", "sanitizer", "sink"
    variable: Optional[str] = None  # The tainted variable at this step
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_source(self) -> bool:
        return self.step_type == "source"

    @property
    def is_sink(self) -> bool:
        return self.step_type == "sink"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "location": self.location.to_dict(),
            "code_snippet": self.code_snippet,
            "description": self.description,
            "step_type": self.step_type,
            "variable": self.variable,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TraceStep":
        """Deserialize from dictionary."""
        return cls(
            location=CodeLocation.from_dict(data["location"]),
            code_snippet=data["code_snippet"],
            description=data["description"],
            step_type=data["step_type"],
            variable=data.get("variable"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class SliceLine:
    """
    Single line in a program slice.

    Represents one line of code in the minimal context.
    """

    line_number: int
    code: str
    is_trace: bool  # Part of the direct trace
    annotation: Optional[str] = None  # e.g., "// SOURCE", "// SINK"
    tainted_variables: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "line_number": self.line_number,
            "code": self.code,
            "is_trace": self.is_trace,
            "annotation": self.annotation,
            "tainted_variables": self.tainted_variables,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SliceLine":
        """Deserialize from dictionary."""
        return cls(
            line_number=data["line_number"],
            code=data["code"],
            is_trace=data["is_trace"],
            annotation=data.get("annotation"),
            tainted_variables=data.get("tainted_variables", []),
        )


@dataclass
class ProgramSlice:
    """
    Minimal code context for verification - 90% reduction.

    Contains only the code necessary to understand the vulnerability:
    - The direct trace lines
    - Variable definitions
    - Control structures affecting the flow
    """

    source_location: CodeLocation
    sink_location: CodeLocation
    file_path: Path
    trace_lines: list[SliceLine]
    variable_definitions: list[dict[str, Any]] = field(default_factory=list)
    control_structures: list[dict[str, Any]] = field(default_factory=list)
    original_lines: int = 0  # Original file line count
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Ensure file_path is a Path object."""
        if isinstance(self.file_path, str):
            self.file_path = Path(self.file_path)

    @property
    def slice_lines(self) -> int:
        """Get number of lines in slice."""
        return len(self.trace_lines)

    @property
    def reduction_ratio(self) -> float:
        """Calculate code reduction percentage."""
        if self.original_lines == 0:
            return 0.0
        return (1 - (self.slice_lines / self.original_lines)) * 100

    def to_code_string(self) -> str:
        """
        Render as readable code with line numbers and markers.

        Returns:
            Formatted string representation of the slice
        """
        lines = []
        for sl in sorted(self.trace_lines, key=lambda x: x.line_number):
            marker = ">>>" if sl.is_trace else "   "
            annotation = f"  // {sl.annotation}" if sl.annotation else ""
            lines.append(f"{marker} {sl.line_number:4d}: {sl.code}{annotation}")
        return "\n".join(lines)

    def to_prompt_context(self) -> str:
        """
        Generate context for LLM verification prompt.

        Returns:
            Formatted string suitable for LLM analysis
        """
        output = []
        output.append(f"File: {self.file_path}")
        output.append(f"Source: Line {self.source_location.line}")
        output.append(f"Sink: Line {self.sink_location.line}")
        output.append("")
        output.append("Code Slice:")
        output.append("-" * 60)
        output.append(self.to_code_string())
        output.append("-" * 60)

        if self.variable_definitions:
            output.append("\nVariable Definitions:")
            for vd in self.variable_definitions:
                output.append(f"  {vd.get('name')}: {vd.get('value')}")

        if self.control_structures:
            output.append("\nControl Structures:")
            for cs in self.control_structures:
                output.append(f"  Line {cs.get('line')}: {cs.get('type')}")

        return "\n".join(output)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "source_location": self.source_location.to_dict(),
            "sink_location": self.sink_location.to_dict(),
            "file_path": str(self.file_path),
            "trace_lines": [t.to_dict() for t in self.trace_lines],
            "variable_definitions": self.variable_definitions,
            "control_structures": self.control_structures,
            "original_lines": self.original_lines,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProgramSlice":
        """Deserialize from dictionary."""
        return cls(
            source_location=CodeLocation.from_dict(data["source_location"]),
            sink_location=CodeLocation.from_dict(data["sink_location"]),
            file_path=Path(data["file_path"]),
            trace_lines=[SliceLine.from_dict(t) for t in data["trace_lines"]],
            variable_definitions=data.get("variable_definitions", []),
            control_structures=data.get("control_structures", []),
            original_lines=data.get("original_lines", 0),
            metadata=data.get("metadata", {}),
        )


@dataclass
class VerificationResult:
    """
    Result from the Multi-Agent Council.

    Contains the outputs from all three agents:
    - Attacker: Attempts to prove exploitability
    - Defender: Attempts to prove safety
    - Judge: Renders final verdict
    """

    verdict: Verdict
    confidence: float

    # Attacker agent output
    attacker_exploitable: bool
    attacker_input: Optional[str]  # Example malicious input
    attacker_trace: Optional[str]  # Attack trace description
    attacker_impact: Optional[str]  # Potential impact
    attacker_reasoning: str

    # Defender agent output
    defender_safe: bool
    defender_lines: list[int]  # Lines with defenses
    defender_sanitization: Optional[str]  # Sanitization description
    defender_reasoning: str

    # Judge agent output
    judge_reasoning: str
    missed_considerations: Optional[str] = None
    iteration: int = 1  # Which iteration of verification

    @property
    def is_true_positive(self) -> bool:
        """Check if verdict is true positive."""
        return self.verdict == Verdict.TRUE_POSITIVE

    @property
    def is_false_positive(self) -> bool:
        """Check if verdict is false positive."""
        return self.verdict == Verdict.FALSE_POSITIVE

    @property
    def is_uncertain(self) -> bool:
        """Check if verdict is uncertain."""
        return self.verdict == Verdict.UNCERTAIN

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "iteration": self.iteration,
            "attacker": {
                "exploitable": self.attacker_exploitable,
                "input": self.attacker_input,
                "trace": self.attacker_trace,
                "impact": self.attacker_impact,
                "reasoning": self.attacker_reasoning,
            },
            "defender": {
                "safe": self.defender_safe,
                "lines": self.defender_lines,
                "sanitization": self.defender_sanitization,
                "reasoning": self.defender_reasoning,
            },
            "judge": {
                "reasoning": self.judge_reasoning,
                "missed_considerations": self.missed_considerations,
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VerificationResult":
        """Deserialize from dictionary."""
        attacker = data.get("attacker", {})
        defender = data.get("defender", {})
        judge = data.get("judge", {})

        return cls(
            verdict=Verdict(data["verdict"]),
            confidence=data["confidence"],
            iteration=data.get("iteration", 1),
            attacker_exploitable=attacker.get("exploitable", False),
            attacker_input=attacker.get("input"),
            attacker_trace=attacker.get("trace"),
            attacker_impact=attacker.get("impact"),
            attacker_reasoning=attacker.get("reasoning", ""),
            defender_safe=defender.get("safe", False),
            defender_lines=defender.get("lines", []),
            defender_sanitization=defender.get("sanitization"),
            defender_reasoning=defender.get("reasoning", ""),
            judge_reasoning=judge.get("reasoning", ""),
            missed_considerations=judge.get("missed_considerations"),
        )


@dataclass
class Finding:
    """
    Complete vulnerability finding.

    Represents a potential security issue detected by the pipeline,
    including the trace, verification results, and metadata.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    vulnerability_type: str = ""  # CWE-XXX
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.0

    source: Optional[TaintSpec] = None
    sink: Optional[TaintSpec] = None
    trace: list[TraceStep] = field(default_factory=list)

    slice: Optional[ProgramSlice] = None

    verification: Optional[VerificationResult] = None

    # Metadata
    title: str = ""
    description: str = ""
    remediation: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scan_id: str = ""
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Ensure proper types."""
        if isinstance(self.severity, str):
            self.severity = Severity.from_string(self.severity)

    @property
    def cwe_description(self) -> str:
        """Get human-readable CWE description."""
        return get_cwe_description(self.vulnerability_type)

    @property
    def is_verified(self) -> bool:
        """Check if finding has been verified."""
        return self.verification is not None

    @property
    def is_verified_positive(self) -> bool:
        """Check if finding is a verified true positive."""
        return (
            self.verification is not None
            and self.verification.verdict == Verdict.TRUE_POSITIVE
        )

    @property
    def is_verified_negative(self) -> bool:
        """Check if finding is a verified false positive."""
        return (
            self.verification is not None
            and self.verification.verdict == Verdict.FALSE_POSITIVE
        )

    @property
    def source_location(self) -> Optional[CodeLocation]:
        """Get source code location."""
        if self.trace:
            source_step = next((t for t in self.trace if t.is_source), None)
            if source_step:
                return source_step.location
        return None

    @property
    def sink_location(self) -> Optional[CodeLocation]:
        """Get sink code location."""
        if self.trace:
            sink_step = next((t for t in self.trace if t.is_sink), None)
            if sink_step:
                return sink_step.location
        return None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "id": self.id,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "source": self.source.to_dict() if self.source else None,
            "sink": self.sink.to_dict() if self.sink else None,
            "trace": [t.to_dict() for t in self.trace],
            "slice": self.slice.to_dict() if self.slice else None,
            "verification": self.verification.to_dict() if self.verification else None,
            "created_at": self.created_at.isoformat(),
            "scan_id": self.scan_id,
            "tags": self.tags,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Deserialize from dictionary."""
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            vulnerability_type=data.get("vulnerability_type", ""),
            severity=Severity(data.get("severity", "medium")),
            confidence=data.get("confidence", 0.0),
            title=data.get("title", ""),
            description=data.get("description", ""),
            remediation=data.get("remediation", ""),
            source=TaintSpec.from_dict(data["source"]) if data.get("source") else None,
            sink=TaintSpec.from_dict(data["sink"]) if data.get("sink") else None,
            trace=[TraceStep.from_dict(t) for t in data.get("trace", [])],
            slice=ProgramSlice.from_dict(data["slice"]) if data.get("slice") else None,
            verification=(
                VerificationResult.from_dict(data["verification"])
                if data.get("verification")
                else None
            ),
            created_at=datetime.fromisoformat(data["created_at"]),
            scan_id=data.get("scan_id", ""),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )

    def to_sarif_result(self) -> dict[str, Any]:
        """Convert to SARIF result format."""
        result: dict[str, Any] = {
            "ruleId": self.vulnerability_type,
            "level": severity_to_sarif(self.severity),
            "message": {
                "text": self.description or f"{self.cwe_description} vulnerability detected",
            },
            "locations": [],
        }

        if self.sink_location:
            result["locations"].append({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(self.sink_location.file_path),
                    },
                    "region": {
                        "startLine": self.sink_location.line,
                        "startColumn": self.sink_location.column,
                    },
                },
            })

        if self.trace:
            result["codeFlows"] = [{
                "threadFlows": [{
                    "locations": [
                        {
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": str(step.location.file_path),
                                    },
                                    "region": {
                                        "startLine": step.location.line,
                                        "snippet": {"text": step.code_snippet},
                                    },
                                },
                                "message": {"text": step.description},
                            },
                        }
                        for step in self.trace
                    ],
                }],
            }]

        return result


@dataclass
class ScanResult:
    """
    Complete scan result.

    Contains all findings and statistics from a scan.
    """

    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    repository: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    status: str = "running"  # running, completed, failed

    findings: list[Finding] = field(default_factory=list)

    # Statistics
    files_scanned: int = 0
    lines_scanned: int = 0
    sources_found: int = 0
    sinks_found: int = 0
    sanitizers_found: int = 0

    # Timing
    phase_timings: dict[str, float] = field(default_factory=dict)

    # Error tracking
    errors: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    metadata: dict[str, Any] = field(default_factory=dict)

    def complete(self, status: str = "completed") -> None:
        """Mark scan as complete."""
        self.completed_at = datetime.now(timezone.utc)
        self.status = status

    @property
    def duration_seconds(self) -> Optional[float]:
        """Get total scan duration in seconds."""
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()

    @property
    def verified_findings(self) -> list[Finding]:
        """Get findings that passed verification."""
        return [f for f in self.findings if f.is_verified_positive]

    @property
    def unverified_findings(self) -> list[Finding]:
        """Get findings that haven't been verified."""
        return [f for f in self.findings if not f.is_verified]

    @property
    def false_positives(self) -> list[Finding]:
        """Get findings marked as false positives."""
        return [f for f in self.findings if f.is_verified_negative]

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the scan results."""
        finding.scan_id = self.scan_id
        self.findings.append(finding)

    def get_findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Get findings filtered by severity."""
        return [f for f in self.verified_findings if f.severity == severity]

    def get_findings_by_type(self, vuln_type: str) -> list[Finding]:
        """Get findings filtered by vulnerability type."""
        return [f for f in self.verified_findings if f.vulnerability_type == vuln_type]

    def summary(self) -> dict[str, Any]:
        """Generate summary statistics."""
        verified = self.verified_findings
        return {
            "scan_id": self.scan_id,
            "repository": self.repository,
            "status": self.status,
            "duration_seconds": self.duration_seconds,
            "files_scanned": self.files_scanned,
            "lines_scanned": self.lines_scanned,
            "total_findings": len(self.findings),
            "verified_positives": len(verified),
            "false_positives": len(self.false_positives),
            "unverified": len(self.unverified_findings),
            "by_severity": {
                s.value: len([f for f in verified if f.severity == s])
                for s in Severity
            },
            "by_type": self._group_by_type(verified),
            "phase_timings": self.phase_timings,
        }

    def _group_by_type(self, findings: list[Finding]) -> dict[str, int]:
        """Group findings by vulnerability type."""
        result: dict[str, int] = {}
        for f in findings:
            result[f.vulnerability_type] = result.get(f.vulnerability_type, 0) + 1
        return result

    def to_json(self, path: Path) -> None:
        """Serialize to JSON file."""
        data = {
            "scan_id": self.scan_id,
            "repository": self.repository,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status,
            "findings": [f.to_dict() for f in self.findings],
            "statistics": {
                "files_scanned": self.files_scanned,
                "lines_scanned": self.lines_scanned,
                "sources_found": self.sources_found,
                "sinks_found": self.sinks_found,
                "sanitizers_found": self.sanitizers_found,
            },
            "phase_timings": self.phase_timings,
            "errors": self.errors,
            "warnings": self.warnings,
            "summary": self.summary(),
            "metadata": self.metadata,
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def from_json(cls, path: Path) -> "ScanResult":
        """Deserialize from JSON file."""
        with open(path) as f:
            data = json.load(f)

        return cls(
            scan_id=data["scan_id"],
            repository=data.get("repository", ""),
            started_at=datetime.fromisoformat(data["started_at"]),
            completed_at=(
                datetime.fromisoformat(data["completed_at"])
                if data.get("completed_at")
                else None
            ),
            status=data.get("status", "completed"),
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            files_scanned=data.get("statistics", {}).get("files_scanned", 0),
            lines_scanned=data.get("statistics", {}).get("lines_scanned", 0),
            sources_found=data.get("statistics", {}).get("sources_found", 0),
            sinks_found=data.get("statistics", {}).get("sinks_found", 0),
            sanitizers_found=data.get("statistics", {}).get("sanitizers_found", 0),
            phase_timings=data.get("phase_timings", {}),
            errors=data.get("errors", []),
            warnings=data.get("warnings", []),
            metadata=data.get("metadata", {}),
        )

    def to_sarif(self) -> dict[str, Any]:
        """Convert to SARIF format."""
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Cerberus SAST",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/cerberus-sast/cerberus",
                        "rules": self._generate_sarif_rules(),
                    },
                },
                "results": [f.to_sarif_result() for f in self.verified_findings],
                "invocations": [{
                    "executionSuccessful": self.status == "completed",
                    "startTimeUtc": self.started_at.isoformat() + "Z",
                    "endTimeUtc": (
                        self.completed_at.isoformat() + "Z"
                        if self.completed_at
                        else None
                    ),
                }],
            }],
        }

    def _generate_sarif_rules(self) -> list[dict[str, Any]]:
        """Generate SARIF rule definitions."""
        vuln_types = set(f.vulnerability_type for f in self.findings)
        return [
            {
                "id": vt,
                "name": get_cwe_description(vt),
                "shortDescription": {"text": get_cwe_description(vt)},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{vt.replace('CWE-', '')}.html",
            }
            for vt in vuln_types
        ]
