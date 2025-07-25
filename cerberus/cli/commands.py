"""
Interface en ligne de commande pour Cerberus-SAST.
"""

import sys
from pathlib import Path
from typing import Optional
import click
from rich.console import Console
from rich.table import Table

from cerberus import __version__
from cerberus.core.config import CerberusConfig
from cerberus.core.engine import CerberusEngine
from cerberus.utils.logging import setup_logging


console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="cerberus")
@click.option("--verbose", "-v", is_flag=True, help="Active les logs détaillés")
@click.option("--quiet", "-q", is_flag=True, help="Supprime la sortie sauf les erreurs")
@click.pass_context
def cli(ctx, verbose: bool, quiet: bool):
    """
    Cerberus-SAST : Moteur d'analyse de sécurité statique modulaire.
    """
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    ctx.obj['quiet'] = quiet
    
    # Configuration du logging
    if quiet:
        level = "ERROR"
    elif verbose:
        level = "DEBUG"
    else:
        level = "INFO"
    
    setup_logging(level)


@cli.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--output", "-o", type=click.Path(), help="Fichier de sortie")
@click.option(
    "--format", "-f",
    type=click.Choice(["sarif", "json", "html", "console"]),
    default="console",
    help="Format du rapport"
)
@click.option(
    "--fail-on",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE"]),
    help="Seuil de sévérité pour l'échec"
)
@click.option("--config", "-c", type=click.Path(exists=True), help="Fichier de configuration")
@click.option("--no-cache", is_flag=True, help="Désactive le cache")
@click.option("--diff-aware", is_flag=True, help="Analyse seulement les fichiers modifiés")
@click.pass_context
def scan(
    ctx,
    path: str,
    output: Optional[str],
    format: str,
    fail_on: Optional[str],
    config: Optional[str],
    no_cache: bool,
    diff_aware: bool
):
    """
    Lance une analyse de sécurité sur le chemin spécifié.
    """
    scan_path = Path(path).resolve()
    
    if not ctx.obj['quiet']:
        console.print(f"[bold blue]Cerberus-SAST v{__version__}[/bold blue]")
        console.print(f"Analyse de: {scan_path}")
    
    # Chargement de la configuration
    if config:
        config_path = Path(config)
        cerberus_config = CerberusConfig.from_file(config_path)
    else:
        cerberus_config = CerberusConfig.discover(scan_path)
        if not cerberus_config:
            if not ctx.obj['quiet']:
                console.print("[yellow]Aucun .cerberus.yml trouvé, utilisation de la configuration par défaut[/yellow]")
            cerberus_config = CerberusConfig.default()
    
    # Override des options CLI
    if fail_on:
        cerberus_config.scan.fail_on_severity = fail_on
    if no_cache:
        cerberus_config.scan.cache_enabled = False
    
    # Création et exécution du moteur
    try:
        engine = CerberusEngine(cerberus_config)
        results = engine.scan(scan_path, diff_aware=diff_aware)
        
        # Génération du rapport
        if format == "console" and not output:
            _print_console_report(results)
        else:
            report_path = Path(output) if output else None
            engine.generate_report(results, format, report_path)
            if not ctx.obj['quiet'] and report_path:
                console.print(f"[green]Rapport généré: {report_path}[/green]")
        
        # Détermination du code de sortie
        exit_code = _calculate_exit_code(results, cerberus_config.scan.fail_on_severity)
        
        if not ctx.obj['quiet']:
            if exit_code == 0:
                console.print("[green]✓ Scan terminé avec succès[/green]")
            else:
                console.print("[red]✗ Des vulnérabilités ont été détectées[/red]")
        
        sys.exit(exit_code)
        
    except Exception as e:
        console.print(f"[red]Erreur: {e}[/red]")
        sys.exit(3)


@cli.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--update", is_flag=True, help="Met à jour la baseline existante")
@click.pass_context
def baseline(ctx, path: str, update: bool):
    """
    Crée ou met à jour une baseline des vulnérabilités existantes.
    """
    console.print("[yellow]La fonctionnalité baseline sera implémentée dans la v1.1[/yellow]")


@cli.command()
@click.option("--plugin", "-p", help="Filtre par plugin")
@click.pass_context
def rules(ctx, plugin: Optional[str]):
    """
    Liste les règles disponibles.
    """
    config = CerberusConfig.default()
    engine = CerberusEngine(config)
    
    table = Table(title="Règles disponibles")
    table.add_column("ID", style="cyan")
    table.add_column("Plugin", style="magenta")
    table.add_column("Sévérité", style="yellow")
    table.add_column("Description")
    
    # TODO: Implémenter la récupération des règles depuis les plugins
    console.print("[yellow]Liste des règles en cours d'implémentation[/yellow]")
    console.print(table)


def _print_console_report(results: dict):
    """Affiche le rapport dans la console."""
    findings = results.get("findings", [])
    
    if not findings:
        console.print("[green]✓ Aucune vulnérabilité détectée[/green]")
        return
    
    # Grouper par sévérité
    by_severity = {}
    for finding in findings:
        severity = finding.get("severity", "INFO")
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(finding)
    
    # Afficher le résumé
    console.print("\n[bold]Résumé des vulnérabilités:[/bold]")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if severity in by_severity:
            count = len(by_severity[severity])
            color = {
                "CRITICAL": "red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "blue",
                "INFO": "cyan"
            }.get(severity, "white")
            console.print(f"  {severity}: [{color}]{count}[/{color}]")
    
    # Afficher les détails
    console.print("\n[bold]Détails:[/bold]")
    for finding in findings:
        severity_color = {
            "CRITICAL": "red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "cyan"
        }.get(finding.get("severity", "INFO"), "white")
        
        console.print(f"\n[{severity_color}][{finding.get('severity', 'INFO')}][/{severity_color}] {finding.get('rule_id', 'unknown')}")
        console.print(f"  Fichier: {finding.get('file_path', 'unknown')}:{finding.get('line', '?')}")
        console.print(f"  Message: {finding.get('message', 'Pas de description')}")


def _calculate_exit_code(results: dict, fail_on_severity: str) -> int:
    """Calcule le code de sortie basé sur les résultats."""
    if fail_on_severity == "NONE":
        return 0
    
    severity_levels = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1
    }
    
    threshold = severity_levels.get(fail_on_severity, 4)
    
    for finding in results.get("findings", []):
        finding_level = severity_levels.get(finding.get("severity", "INFO"), 1)
        if finding_level >= threshold:
            return 1
    
    return 0


def main():
    """Point d'entrée principal."""
    cli(obj={})