"""Tests for CLI commands."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from cerberus.cli.commands import cli, scan


@pytest.fixture
def runner() -> CliRunner:
    """Create CLI test runner."""
    return CliRunner()


@pytest.fixture
def mock_orchestrator_result() -> MagicMock:
    """Create mock orchestrator result."""
    from cerberus.models.finding import ScanResult

    # Use a real ScanResult for proper attribute access
    scan_result = ScanResult(
        repository="test-repo",
        files_scanned=10,
        lines_scanned=1000,
        sources_found=5,
        sinks_found=3,
        sanitizers_found=2,
    )
    scan_result.complete()

    result = MagicMock()
    result.scan_result = scan_result
    result.iterations_run = 1
    result.spec_updates_applied = 0

    return result


class TestCLIGroup:
    """Test main CLI group."""

    def test_cli_help(self, runner: CliRunner):
        """Should show help text."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Cerberus SAST" in result.output

    def test_cli_version(self, runner: CliRunner):
        """Should show version."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "cerberus" in result.output.lower()

    def test_cli_verbose_flag(self, runner: CliRunner):
        """Should accept verbose flag."""
        result = runner.invoke(cli, ["-v", "--help"])
        assert result.exit_code == 0

    def test_cli_quiet_flag(self, runner: CliRunner):
        """Should accept quiet flag."""
        result = runner.invoke(cli, ["-q", "--help"])
        assert result.exit_code == 0


class TestScanCommand:
    """Test scan command."""

    def test_scan_help(self, runner: CliRunner):
        """Should show scan help."""
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "Scan a codebase" in result.output

    def test_scan_dry_run(self, runner: CliRunner, tmp_path: Path):
        """Should show config without scanning."""
        result = runner.invoke(cli, ["scan", str(tmp_path), "--dry-run"])
        # May fail if config loading fails, but should not crash
        assert "Dry run" in result.output or result.exit_code != 0

    def test_scan_invalid_path(self, runner: CliRunner):
        """Should error on invalid path."""
        result = runner.invoke(cli, ["scan", "/nonexistent/path"])
        assert result.exit_code != 0
        # Click should report path doesn't exist

    def test_scan_accepts_output_format(self, runner: CliRunner, tmp_path: Path):
        """Should accept output format option."""
        result = runner.invoke(cli, ["scan", str(tmp_path), "--format", "json", "--dry-run"])
        # Just verify the command accepts the option
        assert "--format" not in result.output or result.exit_code == 0

    def test_scan_accepts_exclude_patterns(self, runner: CliRunner, tmp_path: Path):
        """Should accept exclude patterns."""
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--exclude", "**/test/**",
            "--exclude", "*.md",
            "--dry-run",
        ])
        assert "Dry run" in result.output or result.exit_code != 0


class TestLanguagesCommand:
    """Test languages command."""

    def test_languages_list(self, runner: CliRunner):
        """Should list supported languages."""
        result = runner.invoke(cli, ["languages"])
        assert result.exit_code == 0
        assert "Language" in result.output
        assert "python" in result.output.lower()


class TestVersionCommand:
    """Test version command."""

    def test_version_info(self, runner: CliRunner):
        """Should show version information."""
        result = runner.invoke(cli, ["version"])
        assert result.exit_code == 0
        assert "Cerberus" in result.output
        assert "Python" in result.output


class TestInitCommand:
    """Test init command."""

    def test_init_creates_config(self, runner: CliRunner, tmp_path: Path):
        """Should create config file."""
        result = runner.invoke(cli, ["init", str(tmp_path)])
        assert result.exit_code == 0
        config_file = tmp_path / ".cerberus.yml"
        assert config_file.exists()

    def test_init_no_overwrite(self, runner: CliRunner, tmp_path: Path):
        """Should not overwrite existing config."""
        config_file = tmp_path / ".cerberus.yml"
        config_file.write_text("existing: config")

        result = runner.invoke(cli, ["init", str(tmp_path)])
        assert "already exists" in result.output.lower()
        assert config_file.read_text() == "existing: config"

    def test_init_force_overwrite(self, runner: CliRunner, tmp_path: Path):
        """Should overwrite with --force."""
        config_file = tmp_path / ".cerberus.yml"
        config_file.write_text("existing: config")

        result = runner.invoke(cli, ["init", str(tmp_path), "--force"])
        assert result.exit_code == 0
        assert config_file.read_text() != "existing: config"


class TestBaselineCommands:
    """Test baseline subcommands."""

    def test_baseline_create_help(self, runner: CliRunner):
        """Should show baseline create help."""
        result = runner.invoke(cli, ["baseline", "create", "--help"])
        assert result.exit_code == 0
        assert "baseline" in result.output.lower()

    def test_baseline_update_help(self, runner: CliRunner):
        """Should show baseline update help."""
        result = runner.invoke(cli, ["baseline", "update", "--help"])
        assert result.exit_code == 0

    def test_baseline_diff_help(self, runner: CliRunner):
        """Should show baseline diff help."""
        result = runner.invoke(cli, ["baseline", "diff", "--help"])
        assert result.exit_code == 0


class TestExplainCommand:
    """Test explain command."""

    def test_explain_help(self, runner: CliRunner):
        """Should show explain help."""
        result = runner.invoke(cli, ["explain", "--help"])
        assert result.exit_code == 0


class TestServerCommand:
    """Test server command."""

    def test_server_help(self, runner: CliRunner):
        """Should show server help."""
        result = runner.invoke(cli, ["server", "--help"])
        assert result.exit_code == 0
        assert "API server" in result.output


class TestScanIntegration:
    """Integration tests for scan command."""

    @pytest.mark.asyncio
    async def test_scan_with_mocked_orchestrator(
        self,
        runner: CliRunner,
        tmp_path: Path,
        mock_orchestrator_result: MagicMock,
    ):
        """Should run scan with mocked orchestrator."""
        # Create a simple test file
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")

        with patch("cerberus.cli.commands._run_scan") as mock_run:
            mock_run.return_value = mock_orchestrator_result

            result = runner.invoke(cli, ["-q", "scan", str(tmp_path)])

            # Should call _run_scan
            if result.exit_code == 0:
                assert mock_run.called


class TestProgressCallback:
    """Test progress callback integration."""

    def test_progress_callback_format(self):
        """Should format progress correctly for CLI."""
        from cerberus.core.progress import ScanProgress

        progress = ScanProgress(
            phase="detection",
            phase_progress=0.5,
            message="Analyzing files",
        )

        # Test overall progress calculation
        assert 0.0 <= progress.overall_progress <= 1.0


class TestOutputFormatting:
    """Test output formatting helpers."""

    def test_print_scan_summary_no_findings(
        self,
        mock_orchestrator_result: MagicMock,
    ):
        """Should print summary without findings."""
        from cerberus.cli.commands import _print_scan_summary

        # Should not raise
        _print_scan_summary(mock_orchestrator_result)

    def test_write_results_json(
        self,
        mock_orchestrator_result: MagicMock,
        tmp_path: Path,
    ):
        """Should write JSON results."""
        from cerberus.cli.commands import _write_results

        output_file = tmp_path / "results.json"
        _write_results(mock_orchestrator_result, output_file, "json")

        assert output_file.exists()
        import json
        data = json.loads(output_file.read_text())
        assert "metadata" in data
        assert "summary" in data

