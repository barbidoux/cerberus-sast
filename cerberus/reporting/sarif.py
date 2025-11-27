"""
SARIF 2.1.0 Reporter for Cerberus SAST.

Generates Static Analysis Results Interchange Format (SARIF)
for integration with GitHub, Azure DevOps, VS Code, and other tools.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cerberus.models.base import Verdict, severity_to_sarif, get_cwe_description
from cerberus.models.finding import Finding, ScanResult
from cerberus.reporting.base import BaseReporter, ReportConfig, ReportMetadata, ReporterRegistry


@ReporterRegistry.register("sarif")
class SARIFReporter(BaseReporter):
    """
    SARIF 2.1.0 format reporter.

    Produces reports compliant with the SARIF 2.1.0 specification
    for integration with security tools and CI/CD pipelines.
    """

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    @property
    def format_name(self) -> str:
        return "sarif"

    @property
    def file_extension(self) -> str:
        return ".sarif"

    def generate(self, scan_result: ScanResult) -> str:
        """Generate SARIF report."""
        sarif = {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [self._create_run(scan_result)],
        }

        return json.dumps(sarif, indent=2, default=str)

    def _create_run(self, scan_result: ScanResult) -> dict[str, Any]:
        """Create a SARIF run object."""
        findings = self.filter_findings(scan_result.findings)

        run: dict[str, Any] = {
            "tool": self._create_tool(),
            "results": [self._create_result(f, idx) for idx, f in enumerate(findings)],
            "invocations": [self._create_invocation(scan_result)],
        }

        # Add artifacts (files scanned)
        if scan_result.files_scanned > 0:
            run["artifacts"] = self._create_artifacts(findings)

        return run

    def _create_tool(self) -> dict[str, Any]:
        """Create SARIF tool object."""
        return {
            "driver": {
                "name": self.metadata.tool_name,
                "version": self.metadata.tool_version,
                "informationUri": "https://github.com/cerberus-sast/cerberus",
                "rules": self._create_rules(),
                "properties": {
                    "tags": ["security", "sast", "neuro-symbolic", "ai-powered"],
                },
            }
        }

    def _create_rules(self) -> list[dict[str, Any]]:
        """Create SARIF rules (vulnerability types)."""
        rules = [
            {
                "id": "sql_injection",
                "name": "SQL Injection",
                "shortDescription": {"text": "SQL injection vulnerability detected"},
                "fullDescription": {"text": "User-controlled data reaches a SQL query without proper sanitization."},
                "defaultConfiguration": {"level": "error"},
                "properties": {"cwe": ["CWE-89"], "owasp": ["A03:2021"]},
            },
            {
                "id": "xss",
                "name": "Cross-Site Scripting",
                "shortDescription": {"text": "XSS vulnerability detected"},
                "fullDescription": {"text": "User-controlled data is rendered in HTML without proper encoding."},
                "defaultConfiguration": {"level": "error"},
                "properties": {"cwe": ["CWE-79"], "owasp": ["A03:2021"]},
            },
            {
                "id": "command_injection",
                "name": "Command Injection",
                "shortDescription": {"text": "Command injection vulnerability detected"},
                "fullDescription": {"text": "User-controlled data reaches a shell command without proper sanitization."},
                "defaultConfiguration": {"level": "error"},
                "properties": {"cwe": ["CWE-78"], "owasp": ["A03:2021"]},
            },
            {
                "id": "path_traversal",
                "name": "Path Traversal",
                "shortDescription": {"text": "Path traversal vulnerability detected"},
                "fullDescription": {"text": "User-controlled data used in file path without validation."},
                "defaultConfiguration": {"level": "error"},
                "properties": {"cwe": ["CWE-22"], "owasp": ["A01:2021"]},
            },
            {
                "id": "ssrf",
                "name": "Server-Side Request Forgery",
                "shortDescription": {"text": "SSRF vulnerability detected"},
                "fullDescription": {"text": "User-controlled URL used in server-side HTTP request."},
                "defaultConfiguration": {"level": "error"},
                "properties": {"cwe": ["CWE-918"], "owasp": ["A10:2021"]},
            },
            {
                "id": "sensitive_data_exposure",
                "name": "Sensitive Data Exposure",
                "shortDescription": {"text": "Sensitive data exposure detected"},
                "fullDescription": {"text": "Sensitive data may be logged, displayed, or transmitted insecurely."},
                "defaultConfiguration": {"level": "warning"},
                "properties": {"cwe": ["CWE-200"], "owasp": ["A02:2021"]},
            },
        ]
        return rules

    def _create_result(self, finding: Finding, idx: int) -> dict[str, Any]:
        """Create a SARIF result from a finding."""
        result: dict[str, Any] = {
            "ruleId": finding.vulnerability_type,
            "level": self._severity_to_level(finding.severity),
            "message": {
                "text": finding.description,
            },
            "locations": [self._create_location(finding)],
        }

        # Add fingerprint
        result["fingerprints"] = {
            "primaryLocationLineHash": finding.id,
        }

        # Add code flows (trace)
        if self.config.include_trace and finding.trace:
            result["codeFlows"] = [self._create_code_flow(finding)]

        # Add verification info as properties
        if self.config.include_verification and finding.verification:
            result["properties"] = self._create_verification_properties(finding)

        # Add related locations
        if finding.source and finding.sink:
            result["relatedLocations"] = [
                self._create_related_location(finding.source, "source"),
                self._create_related_location(finding.sink, "sink"),
            ]

        return result

    def _create_location(self, finding: Finding) -> dict[str, Any]:
        """Create primary location for a finding."""
        # Use sink as primary location
        if finding.sink:
            return {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(finding.sink.file_path),
                    },
                    "region": {
                        "startLine": finding.sink.line,
                        "startColumn": 1,
                    },
                },
                "message": {"text": f"Sink: {finding.sink.method}"},
            }

        # Fallback to trace
        if finding.trace:
            return {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(finding.trace[-1].location.file_path),
                    },
                    "region": {
                        "startLine": finding.trace[-1].location.line,
                        "startColumn": finding.trace[-1].location.column or 1,
                    },
                },
            }

        return {"physicalLocation": {"artifactLocation": {"uri": "unknown"}}}

    def _create_related_location(self, spec: Any, label: str) -> dict[str, Any]:
        """Create a related location."""
        return {
            "id": 0,
            "physicalLocation": {
                "artifactLocation": {
                    "uri": str(spec.file_path),
                },
                "region": {
                    "startLine": spec.line,
                    "startColumn": 1,
                },
            },
            "message": {"text": f"{label}: {spec.method}"},
        }

    def _create_code_flow(self, finding: Finding) -> dict[str, Any]:
        """Create a code flow from the trace."""
        thread_flows = []

        for step in finding.trace:
            thread_flows.append({
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": str(step.location.file_path),
                        },
                        "region": {
                            "startLine": step.location.line,
                            "startColumn": step.location.column or 1,
                            "snippet": {"text": step.code_snippet} if self.config.include_code_snippets else None,
                        },
                    },
                    "message": {"text": step.description},
                },
            })

        return {
            "threadFlows": [{
                "locations": thread_flows,
            }],
        }

    def _create_verification_properties(self, finding: Finding) -> dict[str, Any]:
        """Create properties from verification result."""
        v = finding.verification
        return {
            "cerberus:verification": {
                "verdict": v.verdict.value,
                "confidence": v.confidence,
                "attackerExploitable": v.attacker_exploitable,
                "defenderSafe": v.defender_safe,
                "judgeReasoning": v.judge_reasoning,
            },
        }

    def _create_invocation(self, scan_result: ScanResult) -> dict[str, Any]:
        """Create SARIF invocation object."""
        return {
            "executionSuccessful": scan_result.status == "completed",
            "startTimeUtc": scan_result.started_at.isoformat() if scan_result.started_at else None,
            "endTimeUtc": scan_result.completed_at.isoformat() if scan_result.completed_at else None,
            "properties": {
                "filesScanned": scan_result.files_scanned,
                "linesScanned": scan_result.lines_scanned,
                "sourcesFound": scan_result.sources_found,
                "sinksFound": scan_result.sinks_found,
                "sanitizersFound": scan_result.sanitizers_found,
            },
        }

    def _create_artifacts(self, findings: list[Finding]) -> list[dict[str, Any]]:
        """Create artifacts list from findings."""
        seen_files: set[str] = set()
        artifacts = []

        for finding in findings:
            if finding.sink:
                path = str(finding.sink.file_path)
                if path not in seen_files:
                    seen_files.add(path)
                    artifacts.append({"location": {"uri": path}})

            if finding.source:
                path = str(finding.source.file_path)
                if path not in seen_files:
                    seen_files.add(path)
                    artifacts.append({"location": {"uri": path}})

        return artifacts

    def _severity_to_level(self, severity: Any) -> str:
        """Convert severity to SARIF level."""
        sev = severity.lower() if isinstance(severity, str) else severity.value.lower()
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }
        return mapping.get(sev, "warning")
