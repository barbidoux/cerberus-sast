"""
Markdown Reporter for Cerberus SAST.

Generates Markdown reports for GitHub, GitLab, and documentation.
"""

from __future__ import annotations

from typing import Any, Optional

from cerberus.models.base import Verdict
from cerberus.models.finding import Finding, ScanResult
from cerberus.reporting.base import BaseReporter, ReportConfig, ReportMetadata, ReporterRegistry


@ReporterRegistry.register("markdown")
class MarkdownReporter(BaseReporter):
    """
    Markdown format reporter.

    Produces GitHub-flavored Markdown reports suitable for
    PR comments, wiki pages, and documentation.
    """

    @property
    def format_name(self) -> str:
        return "markdown"

    @property
    def file_extension(self) -> str:
        return ".md"

    def generate(self, scan_result: ScanResult) -> str:
        """Generate Markdown report."""
        findings = self.filter_findings(scan_result.findings)

        parts = [
            self._render_header(scan_result),
            self._render_summary(scan_result, findings),
            self._render_spec_inference(scan_result),
            self._render_findings(findings),
            self._render_footer(),
        ]

        return "\n\n".join(filter(None, parts))

    def _render_header(self, scan_result: ScanResult) -> str:
        """Render report header."""
        status_emoji = {
            "completed": "\u2705",  # Check mark
            "failed": "\u274c",  # X mark
            "running": "\u23f3",  # Hourglass
        }.get(scan_result.status, "\u2754")  # Question mark

        return f"""# {self.metadata.tool_name} Scan Report

{status_emoji} **Status:** {scan_result.status.upper()}

| Property | Value |
|----------|-------|
| Repository | `{scan_result.repository}` |
| Scan ID | `{scan_result.scan_id}` |
| Duration | {scan_result.duration_seconds:.2f}s |
| Generated | {self.metadata.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')} |"""

    def _render_summary(self, scan_result: ScanResult, findings: list[Finding]) -> str:
        """Render summary section."""
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
                v = finding.verification.verdict.value.lower()
                verdict_counts[v] = verdict_counts.get(v, 0) + 1
            else:
                verdict_counts["unverified"] += 1

        # Severity badges
        severity_badges = []
        for sev, emoji in [("critical", "\U0001f534"), ("high", "\U0001f7e0"), ("medium", "\U0001f7e1"), ("low", "\U0001f7e2")]:
            if sev in severity_counts:
                severity_badges.append(f"{emoji} **{sev.upper()}:** {severity_counts[sev]}")

        return f"""## Summary

| Metric | Value |
|--------|-------|
| Files Scanned | {scan_result.files_scanned} |
| Lines Analyzed | {scan_result.lines_scanned:,} |
| Total Findings | {len(findings)} |

### Findings by Severity

{' | '.join(severity_badges) if severity_badges else 'No findings'}

### Verification Results

| Verdict | Count |
|---------|-------|
| True Positive | {verdict_counts['true_positive']} |
| False Positive | {verdict_counts['false_positive']} |
| Uncertain | {verdict_counts['uncertain']} |
| Unverified | {verdict_counts['unverified']} |"""

    def _render_spec_inference(self, scan_result: ScanResult) -> str:
        """Render spec inference section."""
        if not (scan_result.sources_found or scan_result.sinks_found or scan_result.sanitizers_found):
            return ""

        return f"""## Spec Inference

| Type | Count |
|------|-------|
| Sources | {scan_result.sources_found} |
| Sinks | {scan_result.sinks_found} |
| Sanitizers | {scan_result.sanitizers_found} |"""

    def _render_findings(self, findings: list[Finding]) -> str:
        """Render findings section."""
        if not findings:
            return "## Findings\n\n\u2705 **No vulnerabilities found!**"

        parts = ["## Findings"]

        for i, finding in enumerate(findings, 1):
            parts.append(self._render_finding(finding, i))

        return "\n\n".join(parts)

    def _render_finding(self, finding: Finding, index: int) -> str:
        """Render a single finding."""
        sev = finding.severity.upper() if isinstance(finding.severity, str) else finding.severity.value.upper()
        sev_emoji = {
            "CRITICAL": "\U0001f534",
            "HIGH": "\U0001f7e0",
            "MEDIUM": "\U0001f7e1",
            "LOW": "\U0001f7e2",
        }.get(sev, "\u26aa")

        verdict_str = ""
        if finding.verification:
            v = finding.verification.verdict.value.replace("_", " ").title()
            verdict_emoji = {
                "True Positive": "\U0001f534",
                "False Positive": "\U0001f7e2",
                "Uncertain": "\U0001f7e1",
            }.get(v, "\u26aa")
            verdict_str = f" {verdict_emoji} `{v}`"

        # Build finding block
        parts = [
            f"### {index}. {sev_emoji} [{sev}] {finding.vulnerability_type}{verdict_str}",
            f"> {finding.description}",
        ]

        # Source/Sink
        if finding.source:
            parts.append(f"**Source:** `{finding.source.method}` at `{finding.source.file_path}:{finding.source.line}`")
        if finding.sink:
            parts.append(f"**Sink:** `{finding.sink.method}` at `{finding.sink.file_path}:{finding.sink.line}`")

        # Trace
        if self.config.include_trace and finding.trace:
            trace_lines = ["<details>", "<summary>Trace</summary>", ""]
            for step in finding.trace:
                trace_lines.append(f"- **{step.step_type}**: `{step.location.file_path}:{step.location.line}`")
                if self.config.include_code_snippets and step.code_snippet:
                    trace_lines.append(f"  ```\n  {step.code_snippet}\n  ```")
            trace_lines.extend(["", "</details>"])
            parts.append("\n".join(trace_lines))

        # Verification
        if self.config.include_verification and finding.verification:
            v = finding.verification
            parts.append(f"""
<details>
<summary>Verification Details</summary>

**Confidence:** {v.confidence:.0%}

**Judge Reasoning:** {v.judge_reasoning}

**Attacker Analysis:**
- Exploitable: {'Yes' if v.attacker_exploitable else 'No'}
- {v.attacker_reasoning}

**Defender Analysis:**
- Safe: {'Yes' if v.defender_safe else 'No'}
- {v.defender_reasoning}

</details>""")

        return "\n\n".join(parts)

    def _render_footer(self) -> str:
        """Render report footer."""
        return f"""---

*Generated by {self.metadata.tool_name} v{self.metadata.tool_version}*
*Neuro-Symbolic Self-Configuring Security Scanner*"""
