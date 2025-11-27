"""Tests for the reporters."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from cerberus.models.base import TaintLabel, Verdict
from cerberus.models.finding import Finding, ScanResult, VerificationResult
from cerberus.models.spec import TaintSpec
from cerberus.reporting import (
    BaseReporter,
    ConsoleReporter,
    HTMLReporter,
    JSONReporter,
    MarkdownReporter,
    ReportConfig,
    ReporterRegistry,
    ReportMetadata,
    SARIFReporter,
)


@pytest.fixture
def sample_scan_result() -> ScanResult:
    """Create a sample scan result."""
    result = ScanResult(
        repository="test-repo",
        files_scanned=10,
        lines_scanned=1000,
        sources_found=5,
        sinks_found=3,
        sanitizers_found=2,
    )
    result.complete()
    return result


@pytest.fixture
def sample_finding() -> Finding:
    """Create a sample finding."""
    return Finding(
        id="finding-1",
        vulnerability_type="sql_injection",
        severity="high",
        description="SQL injection vulnerability detected",
        source=TaintSpec(
            method="get_user_input",
            file_path=Path("src/input.py"),
            line=10,
            label=TaintLabel.SOURCE,
        ),
        sink=TaintSpec(
            method="execute_query",
            file_path=Path("src/db.py"),
            line=50,
            label=TaintLabel.SINK,
        ),
    )


@pytest.fixture
def verified_finding(sample_finding: Finding) -> Finding:
    """Create a verified finding."""
    sample_finding.verification = VerificationResult(
        verdict=Verdict.TRUE_POSITIVE,
        confidence=0.85,
        attacker_exploitable=True,
        attacker_input="' OR 1=1 --",
        attacker_trace="Input flows to query",
        attacker_impact="Database compromise",
        attacker_reasoning="User input not sanitized",
        defender_safe=False,
        defender_lines=[],
        defender_sanitization=None,
        defender_reasoning="No sanitization found",
        judge_reasoning="Clear SQL injection vulnerability",
    )
    return sample_finding


@pytest.fixture
def scan_with_findings(sample_scan_result: ScanResult, sample_finding: Finding) -> ScanResult:
    """Create a scan result with findings."""
    sample_scan_result.findings = [sample_finding]
    sample_scan_result.complete()
    return sample_scan_result


class TestReporterRegistry:
    """Test ReporterRegistry."""

    def test_list_formats(self):
        """Should list all registered formats."""
        formats = ReporterRegistry.list_formats()
        assert "sarif" in formats
        assert "json" in formats
        assert "html" in formats
        assert "markdown" in formats
        assert "console" in formats

    def test_get_registered_reporter(self):
        """Should get registered reporter class."""
        sarif_class = ReporterRegistry.get("sarif")
        assert sarif_class is SARIFReporter

    def test_get_unregistered_format(self):
        """Should return None for unregistered format."""
        result = ReporterRegistry.get("unknown_format")
        assert result is None

    def test_create_reporter(self):
        """Should create reporter instance."""
        reporter = ReporterRegistry.create("json")
        assert isinstance(reporter, JSONReporter)

    def test_create_with_config(self):
        """Should create reporter with config."""
        config = ReportConfig(include_code_snippets=False)
        reporter = ReporterRegistry.create("sarif", config=config)
        assert reporter.config.include_code_snippets is False


class TestReportConfig:
    """Test ReportConfig."""

    def test_default_config(self):
        """Should have sensible defaults."""
        config = ReportConfig()
        assert config.include_code_snippets is True
        assert config.include_verification is True
        assert config.include_trace is True
        assert config.max_findings is None
        assert config.min_confidence == 0.0

    def test_custom_config(self):
        """Should accept custom values."""
        config = ReportConfig(
            include_code_snippets=False,
            max_findings=10,
            min_severity="high",
        )
        assert config.include_code_snippets is False
        assert config.max_findings == 10
        assert config.min_severity == "high"


class TestBaseReporter:
    """Test BaseReporter functionality."""

    def test_filter_by_severity(self, sample_finding: Finding):
        """Should filter by minimum severity."""
        reporter = JSONReporter(config=ReportConfig(min_severity="high"))

        # High severity should pass
        high = sample_finding
        filtered = reporter.filter_findings([high])
        assert len(filtered) == 1

        # Low severity should be filtered
        low = Finding(
            id="finding-2",
            vulnerability_type="info_leak",
            severity="low",
            description="Info leak",
            source=high.source,
            sink=high.sink,
        )
        filtered = reporter.filter_findings([low])
        assert len(filtered) == 0

    def test_filter_by_confidence(self, verified_finding: Finding):
        """Should filter by minimum confidence."""
        reporter = JSONReporter(config=ReportConfig(min_confidence=0.9))

        # 0.85 confidence should be filtered
        filtered = reporter.filter_findings([verified_finding])
        assert len(filtered) == 0

        # Lower threshold should pass
        reporter = JSONReporter(config=ReportConfig(min_confidence=0.8))
        filtered = reporter.filter_findings([verified_finding])
        assert len(filtered) == 1

    def test_filter_max_findings(self, sample_finding: Finding):
        """Should limit number of findings."""
        reporter = JSONReporter(config=ReportConfig(max_findings=2))

        findings = [sample_finding] * 5
        filtered = reporter.filter_findings(findings)
        assert len(filtered) == 2


class TestSARIFReporter:
    """Test SARIF reporter."""

    def test_format_name(self):
        """Should return 'sarif'."""
        reporter = SARIFReporter()
        assert reporter.format_name == "sarif"

    def test_file_extension(self):
        """Should return '.sarif'."""
        reporter = SARIFReporter()
        assert reporter.file_extension == ".sarif"

    def test_generate_empty_scan(self, sample_scan_result: ScanResult):
        """Should generate valid SARIF for empty scan."""
        reporter = SARIFReporter()
        output = reporter.generate(sample_scan_result)

        sarif = json.loads(output)
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["results"] == []

    def test_generate_with_findings(self, scan_with_findings: ScanResult):
        """Should generate SARIF with findings."""
        reporter = SARIFReporter()
        output = reporter.generate(scan_with_findings)

        sarif = json.loads(output)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "sql_injection"
        assert results[0]["level"] == "error"

    def test_sarif_has_tool_info(self, sample_scan_result: ScanResult):
        """Should include tool information."""
        reporter = SARIFReporter()
        output = reporter.generate(sample_scan_result)

        sarif = json.loads(output)
        tool = sarif["runs"][0]["tool"]["driver"]
        assert tool["name"] == "Cerberus SAST"
        assert "rules" in tool

    def test_sarif_has_invocation(self, sample_scan_result: ScanResult):
        """Should include invocation info."""
        reporter = SARIFReporter()
        output = reporter.generate(sample_scan_result)

        sarif = json.loads(output)
        invocation = sarif["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is True


class TestJSONReporter:
    """Test JSON reporter."""

    def test_format_name(self):
        """Should return 'json'."""
        reporter = JSONReporter()
        assert reporter.format_name == "json"

    def test_file_extension(self):
        """Should return '.json'."""
        reporter = JSONReporter()
        assert reporter.file_extension == ".json"

    def test_generate_empty_scan(self, sample_scan_result: ScanResult):
        """Should generate valid JSON for empty scan."""
        reporter = JSONReporter()
        output = reporter.generate(sample_scan_result)

        data = json.loads(output)
        assert "metadata" in data
        assert "summary" in data
        assert "findings" in data
        assert data["findings"] == []

    def test_generate_with_findings(self, scan_with_findings: ScanResult):
        """Should generate JSON with findings."""
        reporter = JSONReporter()
        output = reporter.generate(scan_with_findings)

        data = json.loads(output)
        assert len(data["findings"]) == 1
        assert data["findings"][0]["vulnerability_type"] == "sql_injection"

    def test_json_has_summary(self, scan_with_findings: ScanResult):
        """Should include summary section."""
        reporter = JSONReporter()
        output = reporter.generate(scan_with_findings)

        data = json.loads(output)
        summary = data["summary"]
        assert summary["files_scanned"] == 10
        assert summary["lines_scanned"] == 1000
        assert summary["total_findings"] == 1


class TestHTMLReporter:
    """Test HTML reporter."""

    def test_format_name(self):
        """Should return 'html'."""
        reporter = HTMLReporter()
        assert reporter.format_name == "html"

    def test_file_extension(self):
        """Should return '.html'."""
        reporter = HTMLReporter()
        assert reporter.file_extension == ".html"

    def test_generate_empty_scan(self, sample_scan_result: ScanResult):
        """Should generate valid HTML for empty scan."""
        reporter = HTMLReporter()
        output = reporter.generate(sample_scan_result)

        assert "<!DOCTYPE html>" in output
        assert "Cerberus SAST" in output
        assert "test-repo" in output

    def test_generate_with_findings(self, scan_with_findings: ScanResult):
        """Should generate HTML with findings."""
        reporter = HTMLReporter()
        output = reporter.generate(scan_with_findings)

        assert "sql_injection" in output
        assert "HIGH" in output

    def test_html_has_styles(self, sample_scan_result: ScanResult):
        """Should include embedded CSS."""
        reporter = HTMLReporter()
        output = reporter.generate(sample_scan_result)

        assert "<style>" in output
        assert "</style>" in output


class TestMarkdownReporter:
    """Test Markdown reporter."""

    def test_format_name(self):
        """Should return 'markdown'."""
        reporter = MarkdownReporter()
        assert reporter.format_name == "markdown"

    def test_file_extension(self):
        """Should return '.md'."""
        reporter = MarkdownReporter()
        assert reporter.file_extension == ".md"

    def test_generate_empty_scan(self, sample_scan_result: ScanResult):
        """Should generate valid Markdown for empty scan."""
        reporter = MarkdownReporter()
        output = reporter.generate(sample_scan_result)

        assert "# Cerberus SAST" in output
        assert "test-repo" in output
        assert "No vulnerabilities found" in output

    def test_generate_with_findings(self, scan_with_findings: ScanResult):
        """Should generate Markdown with findings."""
        reporter = MarkdownReporter()
        output = reporter.generate(scan_with_findings)

        assert "sql_injection" in output
        assert "[HIGH]" in output

    def test_markdown_has_tables(self, sample_scan_result: ScanResult):
        """Should include Markdown tables."""
        reporter = MarkdownReporter()
        output = reporter.generate(sample_scan_result)

        assert "|" in output
        assert "---" in output


class TestConsoleReporter:
    """Test Console reporter."""

    def test_format_name(self):
        """Should return 'console'."""
        reporter = ConsoleReporter()
        assert reporter.format_name == "console"

    def test_file_extension(self):
        """Should return '.txt'."""
        reporter = ConsoleReporter()
        assert reporter.file_extension == ".txt"

    def test_generate_returns_string(self, sample_scan_result: ScanResult):
        """Should generate string output."""
        reporter = ConsoleReporter()
        output = reporter.generate(sample_scan_result)

        assert isinstance(output, str)
        assert len(output) > 0


class TestReporterWriteFile:
    """Test file writing functionality."""

    def test_write_json(self, sample_scan_result: ScanResult, tmp_path: Path):
        """Should write JSON to file."""
        reporter = JSONReporter()
        output_path = tmp_path / "report.json"

        result_path = reporter.write(sample_scan_result, output_path)

        assert result_path == output_path
        assert output_path.exists()
        data = json.loads(output_path.read_text())
        assert "metadata" in data

    def test_write_sarif(self, sample_scan_result: ScanResult, tmp_path: Path):
        """Should write SARIF to file."""
        reporter = SARIFReporter()
        output_path = tmp_path / "report.sarif"

        result_path = reporter.write(sample_scan_result, output_path)

        assert result_path == output_path
        assert output_path.exists()
        sarif = json.loads(output_path.read_text())
        assert sarif["version"] == "2.1.0"

    def test_write_html(self, sample_scan_result: ScanResult, tmp_path: Path):
        """Should write HTML to file."""
        reporter = HTMLReporter()
        output_path = tmp_path / "report.html"

        result_path = reporter.write(sample_scan_result, output_path)

        assert result_path == output_path
        assert output_path.exists()
        content = output_path.read_text()
        assert "<!DOCTYPE html>" in content

    def test_write_generates_default_name(self, sample_scan_result: ScanResult, tmp_path: Path):
        """Should generate default filename if not provided."""
        import os
        os.chdir(tmp_path)

        reporter = JSONReporter()
        result_path = reporter.write(sample_scan_result)

        assert result_path.suffix == ".json"
        assert result_path.exists()
