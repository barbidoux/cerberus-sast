"""
Console Reporter for Cerberus SAST.

Generates rich text output for terminal display using Rich library.
"""

from __future__ import annotations

from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from cerberus.models.base import Verdict
from cerberus.models.finding import Finding, ScanResult
from cerberus.reporting.base import BaseReporter, ReportConfig, ReportMetadata, ReporterRegistry


@ReporterRegistry.register("console")
class ConsoleReporter(BaseReporter):
    """
    Console format reporter.

    Produces rich terminal output with colors, tables, and formatting.
    """

    def __init__(
        self,
        config: Optional[ReportConfig] = None,
        metadata: Optional[ReportMetadata] = None,
        console: Optional[Console] = None,
    ) -> None:
        super().__init__(config, metadata)
        self.console = console or Console()

    @property
    def format_name(self) -> str:
        return "console"

    @property
    def file_extension(self) -> str:
        return ".txt"

    def generate(self, scan_result: ScanResult) -> str:
        """Generate console report as plain text."""
        # For console, we return the Rich-formatted string
        # In practice, you'd call display() directly for terminal output
        with self.console.capture() as capture:
            self.display(scan_result)
        return capture.get()

    def display(self, scan_result: ScanResult) -> None:
        """Display the report to the console."""
        findings = self.filter_findings(scan_result.findings)

        # Header
        self._display_header(scan_result)

        # Summary
        self._display_summary(scan_result, findings)

        # Spec inference
        self._display_spec_inference(scan_result)

        # Findings
        self._display_findings(findings)

        # Errors/Warnings
        if scan_result.errors:
            self._display_errors(scan_result.errors)

    def _display_header(self, scan_result: ScanResult) -> None:
        """Display report header."""
        status_style = self._status_to_style(scan_result.status)

        self.console.print(Panel.fit(
            f"[bold]{self.metadata.tool_name}[/] Scan Report\n\n"
            f"Repository: {scan_result.repository}\n"
            f"Scan ID: {scan_result.scan_id}\n"
            f"Status: [{status_style}]{scan_result.status.upper()}[/{status_style}]\n"
            f"Duration: {scan_result.duration_seconds:.2f}s",
            title="Scan Summary",
            border_style=status_style,
        ))

    def _display_summary(self, scan_result: ScanResult, findings: list[Finding]) -> None:
        """Display findings summary."""
        table = Table(title="Scan Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right")

        table.add_row("Files Scanned", str(scan_result.files_scanned))
        table.add_row("Lines Analyzed", f"{scan_result.lines_scanned:,}")
        table.add_row("Total Findings", str(len(findings)))

        self.console.print(table)
        self.console.print()

    def _display_spec_inference(self, scan_result: ScanResult) -> None:
        """Display spec inference results."""
        if not (scan_result.sources_found or scan_result.sinks_found or scan_result.sanitizers_found):
            return

        table = Table(title="Spec Inference Results")
        table.add_column("Type", style="cyan")
        table.add_column("Count", justify="right")

        table.add_row("Sources", str(scan_result.sources_found))
        table.add_row("Sinks", str(scan_result.sinks_found))
        table.add_row("Sanitizers", str(scan_result.sanitizers_found))

        self.console.print(table)
        self.console.print()

    def _display_findings(self, findings: list[Finding]) -> None:
        """Display findings list."""
        if not findings:
            self.console.print("[bold green]No vulnerabilities found![/]")
            return

        # Severity breakdown
        severity_table = Table(title="Findings by Severity")
        severity_table.add_column("Severity", style="cyan")
        severity_table.add_column("Count", justify="right")

        severity_counts: dict[str, int] = {}
        for finding in findings:
            sev = finding.severity.lower() if isinstance(finding.severity, str) else finding.severity.value.lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in severity_counts:
                style = self._severity_to_style(sev)
                severity_table.add_row(sev.upper(), str(severity_counts[sev]), style=style)

        self.console.print(severity_table)
        self.console.print()

        # Verdict breakdown (if verification was run)
        verified_findings = [f for f in findings if f.verification]
        if verified_findings:
            verdict_table = Table(title="Verification Results")
            verdict_table.add_column("Verdict", style="cyan")
            verdict_table.add_column("Count", justify="right")

            verdict_counts: dict[str, int] = {}
            for finding in findings:
                if finding.verification:
                    v = finding.verification.verdict.value
                else:
                    v = "unverified"
                verdict_counts[v] = verdict_counts.get(v, 0) + 1

            for verdict, count in verdict_counts.items():
                style = self._verdict_to_style(verdict)
                verdict_table.add_row(verdict.replace("_", " ").title(), str(count), style=style)

            self.console.print(verdict_table)
            self.console.print()

        # Individual findings
        self.console.print("[bold]Findings:[/]")
        self.console.print()

        for i, finding in enumerate(findings, 1):
            self._display_finding(finding, i)

    def _display_finding(self, finding: Finding, index: int) -> None:
        """Display a single finding."""
        sev = finding.severity.upper() if isinstance(finding.severity, str) else finding.severity.value.upper()
        sev_style = self._severity_to_style(sev.lower())

        # Title line
        verdict_str = ""
        if finding.verification:
            v = finding.verification.verdict.value.replace("_", " ").title()
            v_style = self._verdict_to_style(finding.verification.verdict.value)
            verdict_str = f" [{v_style}][{v}][/{v_style}]"

        self.console.print(
            f"[bold]{index}. [{sev_style}][{sev}][/{sev_style}] "
            f"{finding.vulnerability_type}{verdict_str}[/]"
        )

        # Description
        self.console.print(f"   {finding.description}")

        # Source/Sink
        if finding.source:
            self.console.print(
                f"   [dim]Source:[/] {finding.source.method} "
                f"({finding.source.file_path}:{finding.source.line})"
            )
        if finding.sink:
            self.console.print(
                f"   [dim]Sink:[/] {finding.sink.method} "
                f"({finding.sink.file_path}:{finding.sink.line})"
            )

        # Verification reasoning
        if self.config.include_verification and finding.verification:
            self.console.print(f"   [dim]Reasoning:[/] {finding.verification.judge_reasoning}")
            self.console.print(f"   [dim]Confidence:[/] {finding.verification.confidence:.0%}")

        # Trace
        if self.config.include_trace and finding.trace:
            tree = Tree("[dim]Trace:[/]")
            for step in finding.trace:
                tree.add(f"{step.step_type}: {step.location.file_path}:{step.location.line}")
            self.console.print(tree)

        self.console.print()

    def _display_errors(self, errors: list[dict[str, Any]]) -> None:
        """Display errors and warnings."""
        self.console.print("[bold yellow]Errors/Warnings:[/]")
        for err in errors:
            phase = err.get("phase", "unknown")
            error = err.get("error", "Unknown error")
            self.console.print(f"  [yellow]- {phase}:[/] {error}")
        self.console.print()

    def _status_to_style(self, status: str) -> str:
        """Convert status to Rich style."""
        return {
            "completed": "green",
            "failed": "red",
            "running": "yellow",
        }.get(status, "white")

    def _severity_to_style(self, severity: str) -> str:
        """Convert severity to Rich style."""
        return {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "dim",
            "info": "dim",
        }.get(severity.lower(), "white")

    def _verdict_to_style(self, verdict: str) -> str:
        """Convert verdict to Rich style."""
        return {
            "true_positive": "red",
            "false_positive": "green",
            "uncertain": "yellow",
            "unverified": "dim",
        }.get(verdict.lower(), "white")
