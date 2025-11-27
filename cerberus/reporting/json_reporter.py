"""
JSON Reporter for Cerberus SAST.

Generates structured JSON output for programmatic consumption.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from cerberus.models.finding import Finding, ScanResult
from cerberus.reporting.base import BaseReporter, ReportConfig, ReportMetadata, ReporterRegistry


@ReporterRegistry.register("json")
class JSONReporter(BaseReporter):
    """
    JSON format reporter.

    Produces detailed JSON reports for programmatic processing
    and integration with other tools.
    """

    @property
    def format_name(self) -> str:
        return "json"

    @property
    def file_extension(self) -> str:
        return ".json"

    def generate(self, scan_result: ScanResult) -> str:
        """Generate JSON report."""
        findings = self.filter_findings(scan_result.findings)

        report = {
            "metadata": self._create_metadata(scan_result),
            "summary": self._create_summary(scan_result, findings),
            "findings": [self._finding_to_dict(f) for f in findings],
        }

        if scan_result.errors:
            report["errors"] = scan_result.errors

        if scan_result.warnings:
            report["warnings"] = scan_result.warnings

        return json.dumps(report, indent=2, default=str)

    def _create_metadata(self, scan_result: ScanResult) -> dict[str, Any]:
        """Create metadata section."""
        return {
            "tool": {
                "name": self.metadata.tool_name,
                "version": self.metadata.tool_version,
            },
            "scan": {
                "id": scan_result.scan_id,
                "repository": scan_result.repository,
                "status": scan_result.status,
                "started_at": scan_result.started_at.isoformat() if scan_result.started_at else None,
                "completed_at": scan_result.completed_at.isoformat() if scan_result.completed_at else None,
                "duration_seconds": scan_result.duration_seconds,
            },
            "generated_at": self.metadata.generated_at.isoformat(),
        }

    def _create_summary(self, scan_result: ScanResult, findings: list[Finding]) -> dict[str, Any]:
        """Create summary section."""
        # Count by severity
        severity_counts: dict[str, int] = {}
        verdict_counts: dict[str, int] = {
            "true_positive": 0,
            "false_positive": 0,
            "uncertain": 0,
            "unverified": 0,
        }

        for finding in findings:
            sev = finding.severity.lower() if isinstance(finding.severity, str) else finding.severity.value.lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            if finding.verification:
                verdict = finding.verification.verdict.value.lower()
                verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
            else:
                verdict_counts["unverified"] += 1

        return {
            "files_scanned": scan_result.files_scanned,
            "lines_scanned": scan_result.lines_scanned,
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "by_verdict": verdict_counts,
            "spec_inference": {
                "sources": scan_result.sources_found,
                "sinks": scan_result.sinks_found,
                "sanitizers": scan_result.sanitizers_found,
            },
        }

    def _finding_to_dict(self, finding: Finding) -> dict[str, Any]:
        """Convert a finding to a dictionary."""
        result: dict[str, Any] = {
            "id": finding.id,
            "vulnerability_type": finding.vulnerability_type,
            "severity": finding.severity if isinstance(finding.severity, str) else finding.severity.value,
            "description": finding.description,
        }

        # Source/sink
        if finding.source:
            result["source"] = {
                "method": finding.source.method,
                "file": str(finding.source.file_path),
                "line": finding.source.line,
            }

        if finding.sink:
            result["sink"] = {
                "method": finding.sink.method,
                "file": str(finding.sink.file_path),
                "line": finding.sink.line,
            }

        # Trace
        if self.config.include_trace and finding.trace:
            result["trace"] = [
                {
                    "step_type": step.step_type,
                    "file": str(step.location.file_path),
                    "line": step.location.line,
                    "column": step.location.column,
                    "code": step.code_snippet if self.config.include_code_snippets else None,
                    "description": step.description,
                }
                for step in finding.trace
            ]

        # Slice
        if self.config.include_code_snippets and finding.slice:
            result["slice"] = {
                "file": str(finding.slice.file_path),
                "lines": [
                    {
                        "line_number": line.line_number,
                        "code": line.code,
                        "is_trace": line.is_trace,
                        "annotation": line.annotation,
                    }
                    for line in finding.slice.trace_lines
                ],
            }

        # Verification
        if self.config.include_verification and finding.verification:
            v = finding.verification
            result["verification"] = {
                "verdict": v.verdict.value,
                "confidence": v.confidence,
                "attacker": {
                    "exploitable": v.attacker_exploitable,
                    "input": v.attacker_input,
                    "reasoning": v.attacker_reasoning,
                },
                "defender": {
                    "safe": v.defender_safe,
                    "defense_lines": v.defender_lines,
                    "sanitization": v.defender_sanitization,
                    "reasoning": v.defender_reasoning,
                },
                "judge": {
                    "reasoning": v.judge_reasoning,
                    "missed_considerations": v.missed_considerations,
                },
            }

        # CWE
        if hasattr(finding, 'cwe_ids') and finding.cwe_ids:
            result["cwe_ids"] = finding.cwe_ids

        return result
