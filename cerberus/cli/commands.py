"""
CLI commands for Cerberus SAST.

Provides the main command-line interface using Click.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from cerberus import __version__
from cerberus.core.config import CerberusConfig, validate_config
from cerberus.core.orchestrator import OrchestratorConfig, ScanOrchestrator, DependencyError
from cerberus.core.progress import ScanProgress, create_cli_progress_callback
from cerberus.utils.logging import setup_logging

console = Console()

# Exit codes
EXIT_SUCCESS = 0
EXIT_FINDINGS = 1
EXIT_CONFIG_ERROR = 2
EXIT_RUNTIME_ERROR = 3


def print_banner() -> None:
    """Print the Cerberus banner."""
    banner = """
╔═════════════════════════════════════════════════════════════════════╗
║   ██████╗███████╗██████╗ ██████╗ ███████╗██████╗ ██╗   ██╗███████╗  ║
║  ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██║   ██║██╔════╝  ║
║  ██║     █████╗  ██████╔╝██████╔╝█████╗  ██████╔╝██║   ██║███████╗  ║
║  ██║     ██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██╗██║   ██║╚════██║  ║
║  ╚██████╗███████╗██║  ██║██████╔╝███████╗██║  ██║╚██████╔╝███████║  ║
║   ╚═════╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝  ║
║                                                                     ║
║  Neuro-Symbolic Self-Configuring Security Scanner                   ║
╚═════════════════════════════════════════════════════════════════════╝
"""
    console.print(banner, style="bold blue")


@click.group()
@click.version_option(version=__version__, prog_name="cerberus")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output (DEBUG level)")
@click.option("-q", "--quiet", is_flag=True, help="Suppress non-error output (ERROR level)")
@click.option(
    "--log-file",
    type=click.Path(path_type=Path),
    help="Write logs to file",
)
@click.option("--json-logs", is_flag=True, help="Output logs in JSON format")
@click.pass_context
def cli(
    ctx: click.Context,
    verbose: bool,
    quiet: bool,
    log_file: Optional[Path],
    json_logs: bool,
) -> None:
    """Cerberus SAST - AI-Driven Static Application Security Testing.

    A Neuro-Symbolic Self-Configuring Pipeline that combines
    LLM semantic reasoning with Code Property Graph precision.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet

    # Determine log level
    if verbose:
        level = "DEBUG"
    elif quiet:
        level = "ERROR"
    else:
        level = "INFO"

    # Setup logging
    setup_logging(
        level=level,
        log_file=log_file,
        json_format=json_logs,
    )


@cli.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    help="Output directory for results",
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["sarif", "json", "html", "console", "markdown"]),
    default="console",
    help="Output format",
)
@click.option(
    "-c",
    "--config",
    type=click.Path(exists=True, path_type=Path),
    help="Configuration file path",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low"]),
    help="Exit with error if findings >= severity",
)
@click.option(
    "--exclude",
    multiple=True,
    help="Glob patterns to exclude (can be specified multiple times)",
)
@click.option(
    "--languages",
    help="Comma-separated list of languages to analyze",
)
@click.option(
    "--no-verify",
    is_flag=True,
    help="Skip verification phase (Multi-Agent Council)",
)
@click.option(
    "--council/--no-council",
    default=True,
    help="Enable/disable multi-agent council verification",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be analyzed without running",
)
@click.pass_context
def scan(
    ctx: click.Context,
    path: Path,
    output: Optional[Path],
    output_format: str,
    config: Optional[Path],
    fail_on: Optional[str],
    exclude: tuple[str, ...],
    languages: Optional[str],
    no_verify: bool,
    council: bool,
    dry_run: bool,
) -> None:
    """Scan a codebase for security vulnerabilities.

    PATH is the directory or file to scan.

    Examples:

        cerberus scan ./my-project

        cerberus scan ./src --format sarif -o results.sarif

        cerberus scan . --exclude "**/test/**" --languages python,javascript
    """
    if not ctx.obj.get("quiet"):
        print_banner()

    console.print(f"[bold blue]Target:[/] {path.absolute()}")

    # Build CLI args for config loading
    cli_args = {
        "output": output,
        "output_format": output_format,
        "exclude": list(exclude) if exclude else None,
        "languages": languages,
        "no_verify": no_verify,
        "council": council,
    }

    # Load configuration
    try:
        cfg = CerberusConfig.load(cli_args=cli_args, project_path=path)

        # Validate configuration
        warnings = validate_config(cfg)
        for warning in warnings:
            console.print(f"[yellow]Warning:[/] {warning}")

    except Exception as e:
        console.print(f"[red]Configuration error:[/] {e}")
        sys.exit(EXIT_CONFIG_ERROR)

    if dry_run:
        console.print("\n[bold]Dry run - configuration:[/]")
        _print_config_summary(cfg)
        console.print("\n[green]Dry run complete. No analysis performed.[/]")
        return

    # Run the scan
    try:
        result = asyncio.run(_run_scan(
            path=path,
            cfg=cfg,
            no_verify=no_verify,
            council=council,
            output=output,
            output_format=output_format,
            quiet=ctx.obj.get("quiet", False),
        ))

        # Print summary
        if not ctx.obj.get("quiet"):
            _print_scan_summary(result)

        # Output results
        if output:
            _write_results(result, output, output_format)
        elif output_format != "console":
            _write_results(result, Path(f"cerberus-results.{output_format}"), output_format)

        # Determine exit code
        exit_code = EXIT_SUCCESS
        if fail_on and result.scan_result.findings:
            severity_order = ["critical", "high", "medium", "low"]
            fail_threshold = severity_order.index(fail_on)
            for finding in result.scan_result.findings:
                finding_severity = finding.severity.lower() if isinstance(finding.severity, str) else finding.severity.value.lower()
                if finding_severity in severity_order:
                    if severity_order.index(finding_severity) <= fail_threshold:
                        exit_code = EXIT_FINDINGS
                        break

        sys.exit(exit_code)

    except DependencyError as e:
        console.print(f"\n[red]Dependency error:[/] {e}")
        console.print("[yellow]Ensure Joern is running (docker run --rm -p 9000:9000 joernio/joern)[/]")
        sys.exit(EXIT_RUNTIME_ERROR)

    except Exception as e:
        console.print(f"\n[red]Scan failed:[/] {e}")
        if ctx.obj.get("verbose"):
            import traceback
            console.print(traceback.format_exc())
        sys.exit(EXIT_RUNTIME_ERROR)


@cli.command()
@click.option("--host", default="127.0.0.1", help="Bind host address")
@click.option("--port", default=8080, type=int, help="Bind port")
@click.option("--workers", default=1, type=int, help="Number of worker processes")
@click.option("--reload", is_flag=True, help="Enable auto-reload for development")
@click.pass_context
def server(
    ctx: click.Context,
    host: str,
    port: int,
    workers: int,
    reload: bool,
) -> None:
    """Start the Cerberus API server.

    Provides REST API and WebSocket endpoints for scanning.

    Examples:

        cerberus server

        cerberus server --host 0.0.0.0 --port 9000

        cerberus server --workers 4
    """
    console.print(f"[bold green]Starting Cerberus API server on {host}:{port}[/]")
    console.print(f"Workers: {workers}, Reload: {reload}")

    # TODO: Implement FastAPI server
    console.print("\n[yellow]API server not yet implemented[/]")
    console.print("Endpoints to be implemented:")
    console.print("  POST   /api/v1/scans         - Start new scan")
    console.print("  GET    /api/v1/scans/{id}    - Get scan status")
    console.print("  GET    /api/v1/scans/{id}/results - Get scan results")
    console.print("  WS     /api/v1/scans/{id}/stream  - Stream progress")

    raise NotImplementedError("Server command not yet implemented")


@cli.command()
def languages() -> None:
    """List supported programming languages.

    Shows all languages supported by Cerberus for analysis.
    """
    # Import here to avoid circular imports
    from cerberus.context.tree_sitter_parser import LANGUAGE_EXTENSIONS

    table = Table(title="Supported Languages")
    table.add_column("Language", style="cyan")
    table.add_column("Extensions", style="green")

    # Group extensions by language
    lang_to_exts: dict[str, list[str]] = {}
    for ext, lang in LANGUAGE_EXTENSIONS.items():
        lang_to_exts.setdefault(lang, []).append(ext)

    for lang in sorted(lang_to_exts.keys()):
        exts = ", ".join(sorted(lang_to_exts[lang]))
        table.add_row(lang, exts)

    console.print(table)


@cli.command()
def version() -> None:
    """Show version and system information."""
    console.print(Panel.fit(
        f"[bold]Cerberus SAST[/] v{__version__}\n\n"
        "Neuro-Symbolic Self-Configuring Pipeline\n"
        "AI-Driven Static Application Security Testing",
        title="Version Info",
    ))

    import platform
    import sys

    table = Table(title="System Information")
    table.add_column("Component", style="cyan")
    table.add_column("Version", style="green")

    table.add_row("Python", platform.python_version())
    table.add_row("Platform", platform.platform())
    table.add_row("Architecture", platform.machine())

    console.print(table)


@cli.command()
@click.argument("path", type=click.Path(path_type=Path), default=".")
@click.option("--force", is_flag=True, help="Overwrite existing configuration")
def init(path: Path, force: bool) -> None:
    """Initialize .cerberus.yml configuration in a directory.

    Creates a default configuration file with all options documented.

    Examples:

        cerberus init

        cerberus init ./my-project

        cerberus init --force
    """
    config_path = path / ".cerberus.yml"

    if config_path.exists() and not force:
        console.print(f"[yellow]Configuration already exists:[/] {config_path}")
        console.print("Use --force to overwrite")
        return

    # Create default config
    default_config = CerberusConfig()
    default_config.to_yaml(config_path)

    console.print(f"[green]Created configuration:[/] {config_path}")
    console.print("\nEdit this file to customize your scan settings.")
    console.print("Run 'cerberus scan .' to analyze your codebase.")


@cli.group()
def baseline() -> None:
    """Manage finding baselines.

    Baselines allow you to track new findings vs. existing ones.
    """
    pass


@baseline.command("create")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    default=".cerberus-baseline.json",
    help="Output baseline file path",
)
def baseline_create(path: Path, output: Path) -> None:
    """Create baseline of existing findings.

    Scans the codebase and saves all findings as a baseline.
    Future scans can compare against this baseline to show only new issues.

    Examples:

        cerberus baseline create ./my-project

        cerberus baseline create . -o baseline.json
    """
    console.print(f"[blue]Creating baseline for:[/] {path}")
    console.print(f"[blue]Output:[/] {output}")

    # TODO: Implement baseline creation
    raise NotImplementedError("Baseline create not yet implemented")


@baseline.command("update")
@click.argument("baseline_file", type=click.Path(exists=True, path_type=Path))
@click.argument("path", type=click.Path(exists=True, path_type=Path))
def baseline_update(baseline_file: Path, path: Path) -> None:
    """Update baseline with current findings.

    Re-scans the codebase and updates the baseline file.

    Examples:

        cerberus baseline update .cerberus-baseline.json ./my-project
    """
    console.print(f"[blue]Updating baseline:[/] {baseline_file}")
    console.print(f"[blue]Target:[/] {path}")

    # TODO: Implement baseline update
    raise NotImplementedError("Baseline update not yet implemented")


@baseline.command("diff")
@click.argument("baseline_file", type=click.Path(exists=True, path_type=Path))
@click.argument("path", type=click.Path(exists=True, path_type=Path))
def baseline_diff(baseline_file: Path, path: Path) -> None:
    """Show findings not in baseline.

    Scans the codebase and shows only findings that are not in the baseline.

    Examples:

        cerberus baseline diff .cerberus-baseline.json ./my-project
    """
    console.print(f"[blue]Comparing against baseline:[/] {baseline_file}")
    console.print(f"[blue]Target:[/] {path}")

    # TODO: Implement baseline diff
    raise NotImplementedError("Baseline diff not yet implemented")


@cli.command()
@click.argument("finding_id", type=str)
@click.option(
    "--scan-results",
    type=click.Path(exists=True, path_type=Path),
    help="Path to scan results file",
)
def explain(finding_id: str, scan_results: Optional[Path]) -> None:
    """Get detailed explanation of a finding.

    Shows the full trace, verification reasoning, and remediation advice.

    Examples:

        cerberus explain abc123

        cerberus explain abc123 --scan-results results.json
    """
    console.print(f"[blue]Explaining finding:[/] {finding_id}")

    # TODO: Implement finding explanation
    raise NotImplementedError("Explain command not yet implemented")


def _print_config_summary(cfg: CerberusConfig) -> None:
    """Print a summary of the configuration."""
    table = Table(title="Configuration Summary")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Project Name", cfg.project_name)
    table.add_row("Output Directory", str(cfg.output_dir))
    table.add_row("Languages", ", ".join(cfg.analysis.languages))
    table.add_row("Exclude Patterns", str(len(cfg.analysis.exclude_patterns)) + " patterns")
    table.add_row("LLM Provider", cfg.llm.default_provider)
    table.add_row("Verification", "Enabled" if cfg.verification.enabled else "Disabled")
    table.add_row("Council Mode", "Enabled" if cfg.verification.council_mode else "Disabled")
    table.add_row("Report Formats", ", ".join(cfg.reporting.formats))

    console.print(table)


async def _run_scan(
    path: Path,
    cfg: CerberusConfig,
    no_verify: bool,
    council: bool,
    output: Optional[Path],
    output_format: str,
    quiet: bool,
) -> Any:
    """Run the scan pipeline with progress tracking."""
    from cerberus.core.orchestrator import OrchestratorResult
    from cerberus.llm.gateway import LLMGateway

    # Configure orchestrator
    orchestrator_config = OrchestratorConfig(
        run_inference=True,
        run_detection=True,
        run_verification=not no_verify and council,
        max_feedback_iterations=cfg.verification.max_iterations if hasattr(cfg, 'verification') else 3,
        min_confidence=cfg.verification.confidence_threshold if hasattr(cfg, 'verification') else 0.5,
        joern_endpoint=f"http://{cfg.joern.endpoint}" if hasattr(cfg, 'joern') and cfg.joern else "http://localhost:8080",
    )

    # Create LLM gateway from configuration
    llm_gateway = LLMGateway(cfg.llm)

    # Create progress display
    if not quiet:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task_id = progress.add_task("[cyan]Scanning...", total=100)

            def progress_callback(p: ScanProgress) -> None:
                description = f"[{p.phase}]"
                if p.message:
                    description = f"{description} {p.message}"
                elif p.current_file:
                    description = f"{description} {p.current_file}"
                progress.update(task_id, description=description, completed=p.overall_progress * 100)

            orchestrator = ScanOrchestrator(
                config=orchestrator_config,
                llm_gateway=llm_gateway,
                progress_callback=progress_callback,
            )

            result = await orchestrator.scan(path, repository_name=cfg.project_name)
    else:
        orchestrator = ScanOrchestrator(config=orchestrator_config, llm_gateway=llm_gateway)
        result = await orchestrator.scan(path, repository_name=cfg.project_name)

    return result


def _print_scan_summary(result: Any) -> None:
    """Print scan results summary."""
    from cerberus.core.orchestrator import OrchestratorResult
    from cerberus.models.base import Verdict

    sr = result.scan_result

    # Summary panel
    status_color = "green" if sr.status == "completed" else "red" if sr.status == "failed" else "yellow"
    console.print(Panel.fit(
        f"[bold]Scan {sr.status.upper()}[/]\n\n"
        f"Files scanned: {sr.files_scanned}\n"
        f"Lines analyzed: {sr.lines_scanned:,}\n"
        f"Duration: {sr.duration_seconds:.2f}s",
        title="Scan Summary",
        border_style=status_color,
    ))

    # Spec inference results
    if sr.sources_found or sr.sinks_found or sr.sanitizers_found:
        console.print(f"\n[bold]Spec Inference:[/]")
        console.print(f"  Sources:    {sr.sources_found}")
        console.print(f"  Sinks:      {sr.sinks_found}")
        console.print(f"  Sanitizers: {sr.sanitizers_found}")

    # Findings summary
    if sr.findings:
        console.print(f"\n[bold red]Findings: {len(sr.findings)}[/]")

        # Count by severity
        severity_counts: dict[str, int] = {}
        verdict_counts: dict[str, int] = {"true_positive": 0, "false_positive": 0, "uncertain": 0, "unverified": 0}

        for finding in sr.findings:
            sev = finding.severity.lower() if isinstance(finding.severity, str) else finding.severity.value.lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            if finding.verification:
                if finding.verification.verdict == Verdict.TRUE_POSITIVE:
                    verdict_counts["true_positive"] += 1
                elif finding.verification.verdict == Verdict.FALSE_POSITIVE:
                    verdict_counts["false_positive"] += 1
                else:
                    verdict_counts["uncertain"] += 1
            else:
                verdict_counts["unverified"] += 1

        # Severity table
        table = Table(title="Findings by Severity")
        table.add_column("Severity", style="cyan")
        table.add_column("Count", style="red")

        for sev in ["critical", "high", "medium", "low"]:
            if sev in severity_counts:
                style = "bold red" if sev in ["critical", "high"] else "yellow" if sev == "medium" else "dim"
                table.add_row(sev.upper(), str(severity_counts[sev]), style=style)

        console.print(table)

        # Verdict table (if verification was run)
        if verdict_counts["true_positive"] + verdict_counts["false_positive"] + verdict_counts["uncertain"] > 0:
            table = Table(title="Verification Results")
            table.add_column("Verdict", style="cyan")
            table.add_column("Count")

            table.add_row("True Positive", str(verdict_counts["true_positive"]), style="red")
            table.add_row("False Positive", str(verdict_counts["false_positive"]), style="green")
            table.add_row("Uncertain", str(verdict_counts["uncertain"]), style="yellow")
            table.add_row("Unverified", str(verdict_counts["unverified"]), style="dim")

            console.print(table)

        # List findings
        console.print("\n[bold]Findings:[/]")
        for i, finding in enumerate(sr.findings[:10], 1):  # Show first 10
            sev = finding.severity.upper() if isinstance(finding.severity, str) else finding.severity.value.upper()
            sev_style = "red" if sev in ["CRITICAL", "HIGH"] else "yellow" if sev == "MEDIUM" else "dim"
            verdict = ""
            if finding.verification:
                v = finding.verification.verdict.value
                verdict = f" [{v}]"

            console.print(f"  {i}. [{sev_style}][{sev}][/{sev_style}] {finding.vulnerability_type}{verdict}")
            if finding.source:
                console.print(f"     Source: {finding.source.method} ({finding.source.file_path}:{finding.source.line})")
            if finding.sink:
                console.print(f"     Sink: {finding.sink.method} ({finding.sink.file_path}:{finding.sink.line})")

        if len(sr.findings) > 10:
            console.print(f"\n  ... and {len(sr.findings) - 10} more findings")
    else:
        console.print("\n[bold green]No vulnerabilities found![/]")

    # Errors
    if sr.errors:
        console.print(f"\n[yellow]Warnings/Errors: {len(sr.errors)}[/]")
        for err in sr.errors[:5]:
            console.print(f"  - {err.get('phase', 'unknown')}: {err.get('error', 'Unknown error')}")

    # Feedback loop info
    if hasattr(result, 'iterations_run') and result.iterations_run > 1:
        console.print(f"\n[dim]Feedback iterations: {result.iterations_run}[/]")
        console.print(f"[dim]Spec updates applied: {result.spec_updates_applied}[/]")


def _write_results(result: Any, output: Path, output_format: str) -> None:
    """Write scan results to file using the reporting module."""
    from cerberus.reporting import ReporterRegistry

    sr = result.scan_result

    # Get reporter from registry
    reporter = ReporterRegistry.create(output_format)
    if reporter is None:
        console.print(f"[yellow]Unknown output format: {output_format}[/]")
        return

    try:
        # Write the report
        output_path = reporter.write(sr, output)
        console.print(f"[green]Results written to:[/] {output_path}")
    except Exception as e:
        console.print(f"[red]Failed to write report:[/] {e}")


if __name__ == "__main__":
    cli()
