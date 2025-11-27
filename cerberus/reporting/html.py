"""
HTML Reporter for Cerberus SAST.

Generates styled HTML reports for web viewing and sharing.
"""

from __future__ import annotations

from html import escape
from typing import Any, Optional

from cerberus.models.base import Verdict
from cerberus.models.finding import Finding, ScanResult
from cerberus.reporting.base import BaseReporter, ReportConfig, ReportMetadata, ReporterRegistry


@ReporterRegistry.register("html")
class HTMLReporter(BaseReporter):
    """
    HTML format reporter.

    Produces standalone HTML reports with embedded CSS.
    """

    @property
    def format_name(self) -> str:
        return "html"

    @property
    def file_extension(self) -> str:
        return ".html"

    def generate(self, scan_result: ScanResult) -> str:
        """Generate HTML report."""
        findings = self.filter_findings(scan_result.findings)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cerberus SAST Report - {escape(scan_result.repository)}</title>
    {self._get_styles()}
</head>
<body>
    <div class="container">
        {self._render_header(scan_result)}
        {self._render_summary(scan_result, findings)}
        {self._render_findings(findings)}
        {self._render_footer()}
    </div>
</body>
</html>"""

    def _get_styles(self) -> str:
        """Get embedded CSS styles."""
        return """<style>
:root {
    --bg-primary: #1a1a2e;
    --bg-secondary: #16213e;
    --text-primary: #eaeaea;
    --text-secondary: #a8a8a8;
    --accent: #0f3460;
    --critical: #ff4757;
    --high: #ff6b6b;
    --medium: #ffa502;
    --low: #7bed9f;
    --success: #2ed573;
    --border: #2a2a4a;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
}
.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
.header {
    background: var(--bg-secondary);
    padding: 30px;
    border-radius: 10px;
    margin-bottom: 20px;
    border-left: 4px solid var(--accent);
}
.header h1 { font-size: 2em; margin-bottom: 10px; }
.header .meta { color: var(--text-secondary); }
.summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
    margin-bottom: 20px;
}
.stat-card {
    background: var(--bg-secondary);
    padding: 20px;
    border-radius: 10px;
    text-align: center;
}
.stat-card .value { font-size: 2em; font-weight: bold; }
.stat-card .label { color: var(--text-secondary); }
.severity-critical { color: var(--critical); }
.severity-high { color: var(--high); }
.severity-medium { color: var(--medium); }
.severity-low { color: var(--low); }
.verdict-true_positive { color: var(--critical); }
.verdict-false_positive { color: var(--success); }
.verdict-uncertain { color: var(--medium); }
.finding {
    background: var(--bg-secondary);
    padding: 20px;
    border-radius: 10px;
    margin-bottom: 15px;
    border-left: 4px solid var(--accent);
}
.finding.critical { border-left-color: var(--critical); }
.finding.high { border-left-color: var(--high); }
.finding.medium { border-left-color: var(--medium); }
.finding.low { border-left-color: var(--low); }
.finding-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
}
.finding-header h3 { font-size: 1.1em; }
.badge {
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 0.8em;
    font-weight: bold;
}
.badge.critical { background: var(--critical); }
.badge.high { background: var(--high); }
.badge.medium { background: var(--medium); color: var(--bg-primary); }
.badge.low { background: var(--low); color: var(--bg-primary); }
.trace { margin-top: 15px; }
.trace-step {
    padding: 10px;
    background: var(--bg-primary);
    margin: 5px 0;
    border-radius: 5px;
    font-family: monospace;
    font-size: 0.9em;
}
.trace-step .type { color: var(--text-secondary); }
code {
    background: var(--bg-primary);
    padding: 2px 6px;
    border-radius: 3px;
    font-family: monospace;
}
.footer {
    text-align: center;
    padding: 20px;
    color: var(--text-secondary);
    font-size: 0.9em;
}
</style>"""

    def _render_header(self, scan_result: ScanResult) -> str:
        """Render report header."""
        status_class = "success" if scan_result.status == "completed" else "critical"
        return f"""
<div class="header">
    <h1>{escape(self.metadata.tool_name)} Scan Report</h1>
    <div class="meta">
        <p><strong>Repository:</strong> {escape(scan_result.repository)}</p>
        <p><strong>Scan ID:</strong> {escape(scan_result.scan_id)}</p>
        <p><strong>Status:</strong> <span class="severity-{status_class}">{escape(scan_result.status.upper())}</span></p>
        <p><strong>Duration:</strong> {scan_result.duration_seconds:.2f}s</p>
        <p><strong>Generated:</strong> {self.metadata.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    </div>
</div>"""

    def _render_summary(self, scan_result: ScanResult, findings: list[Finding]) -> str:
        """Render summary cards."""
        # Count by severity
        severity_counts: dict[str, int] = {}
        for finding in findings:
            sev = finding.severity.lower() if isinstance(finding.severity, str) else finding.severity.value.lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return f"""
<div class="summary">
    <div class="stat-card">
        <div class="value">{scan_result.files_scanned}</div>
        <div class="label">Files Scanned</div>
    </div>
    <div class="stat-card">
        <div class="value">{scan_result.lines_scanned:,}</div>
        <div class="label">Lines Analyzed</div>
    </div>
    <div class="stat-card">
        <div class="value severity-critical">{severity_counts.get('critical', 0) + severity_counts.get('high', 0)}</div>
        <div class="label">Critical/High</div>
    </div>
    <div class="stat-card">
        <div class="value severity-medium">{severity_counts.get('medium', 0)}</div>
        <div class="label">Medium</div>
    </div>
    <div class="stat-card">
        <div class="value severity-low">{severity_counts.get('low', 0)}</div>
        <div class="label">Low</div>
    </div>
    <div class="stat-card">
        <div class="value">{len(findings)}</div>
        <div class="label">Total Findings</div>
    </div>
</div>"""

    def _render_findings(self, findings: list[Finding]) -> str:
        """Render findings list."""
        if not findings:
            return '<div class="finding"><p style="color: var(--success);">No vulnerabilities found!</p></div>'

        html_parts = ['<h2>Findings</h2>']
        for i, finding in enumerate(findings, 1):
            html_parts.append(self._render_finding(finding, i))

        return "\n".join(html_parts)

    def _render_finding(self, finding: Finding, index: int) -> str:
        """Render a single finding."""
        sev = finding.severity.lower() if isinstance(finding.severity, str) else finding.severity.value.lower()

        verdict_html = ""
        if finding.verification:
            v = finding.verification.verdict.value
            verdict_html = f'<span class="badge verdict-{v}">{v.replace("_", " ").title()}</span>'

        trace_html = ""
        if self.config.include_trace and finding.trace:
            steps = "\n".join([
                f'<div class="trace-step"><span class="type">{escape(s.step_type)}:</span> '
                f'{escape(str(s.location.file_path))}:{s.location.line}</div>'
                for s in finding.trace
            ])
            trace_html = f'<div class="trace"><strong>Trace:</strong>{steps}</div>'

        verification_html = ""
        if self.config.include_verification and finding.verification:
            v = finding.verification
            verification_html = f"""
<div style="margin-top: 15px; padding: 10px; background: var(--bg-primary); border-radius: 5px;">
    <strong>Verification:</strong>
    <p><em>Confidence:</em> {v.confidence:.0%}</p>
    <p><em>Judge Reasoning:</em> {escape(v.judge_reasoning)}</p>
</div>"""

        return f"""
<div class="finding {sev}">
    <div class="finding-header">
        <h3>{index}. {escape(finding.vulnerability_type)}</h3>
        <div>
            <span class="badge {sev}">{sev.upper()}</span>
            {verdict_html}
        </div>
    </div>
    <p>{escape(finding.description)}</p>
    <p style="margin-top: 10px;">
        <strong>Source:</strong> <code>{escape(finding.source.method if finding.source else 'N/A')}</code>
        ({escape(str(finding.source.file_path) if finding.source else 'N/A')}:{finding.source.line if finding.source else 0})
    </p>
    <p>
        <strong>Sink:</strong> <code>{escape(finding.sink.method if finding.sink else 'N/A')}</code>
        ({escape(str(finding.sink.file_path) if finding.sink else 'N/A')}:{finding.sink.line if finding.sink else 0})
    </p>
    {trace_html}
    {verification_html}
</div>"""

    def _render_footer(self) -> str:
        """Render report footer."""
        return f"""
<div class="footer">
    <p>Generated by {escape(self.metadata.tool_name)} v{escape(self.metadata.tool_version)}</p>
    <p>Neuro-Symbolic Self-Configuring Security Scanner</p>
</div>"""
