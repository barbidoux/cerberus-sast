"""
CLI commands for Cerberus SAST.

Provides the main command-line interface using Click.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cerberus import __version__
from cerberus.core.config import CerberusConfig, validate_config
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
╔═══════════════════════════════════════════════════════════╗
║   ██████╗███████╗██████╗ ██████╗ ███████╗██████╗ ██╗   ██╗███████╗  ║
║  ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██║   ██║██╔════╝  ║
║  ██║     █████╗  ██████╔╝██████╔╝█████╗  ██████╔╝██║   ██║███████╗  ║
║  ██║     ██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██╗██║   ██║╚════██║  ║
║  ╚██████╗███████╗██║  ██║██████╔╝███████╗██║  ██║╚██████╔╝███████║  ║
║   ╚═════╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝  ║
║                                                                      ║
║  Neuro-Symbolic Self-Configuring Security Scanner                   ║
╚═══════════════════════════════════════════════════════════╝
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

    # TODO: Implement scan pipeline
    console.print("\n[yellow]Scan pipeline not yet implemented[/]")
    console.print("This will execute the four-phase NSSCP pipeline:")
    console.print("  I.   Context Engine - Repository mapping")
    console.print("  II.  Spec Inference - Source/Sink/Sanitizer identification")
    console.print("  III. Detection - CPG-based taint analysis")
    console.print("  IV.  Verification - Multi-Agent Council")

    raise NotImplementedError("Scan command not yet implemented")


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


if __name__ == "__main__":
    cli()
