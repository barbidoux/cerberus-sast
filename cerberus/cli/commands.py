"""
Interface en ligne de commande pour Cerberus-SAST.
"""

import sys
import logging
from pathlib import Path
from typing import Optional, Dict, Any
import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from cerberus import __version__
from cerberus.core.config import CerberusConfig
from cerberus.core.engine import CerberusEngine
from cerberus.core.baseline import BaselineManager
from cerberus.utils.logging import setup_logging


console = Console()
logger = logging.getLogger(__name__)


# Codes de retour standardisés
class ExitCode:
    """Codes de retour standardisés pour Cerberus-SAST."""
    SUCCESS = 0           # Aucune vulnérabilité bloquante trouvée
    FINDINGS_DETECTED = 1 # Vulnérabilités détectées selon le seuil fail_on_severity
    CONFIG_ERROR = 2      # Erreur de configuration ou de plugin
    INTERNAL_ERROR = 3    # Crash interne ou erreur inattendue


def handle_exception(e: Exception, verbose: bool = False) -> int:
    """
    Gère les exceptions de manière uniforme et retourne le code de sortie approprié.
    
    Args:
        e: Exception à traiter
        verbose: Si True, affiche la stack trace complète
        
    Returns:
        Code de sortie approprié
    """
    from cerberus.plugins.manager import PluginLoadingError
    
    if isinstance(e, (FileNotFoundError, ValueError, PluginLoadingError)):
        # Erreurs de configuration ou de setup
        console.print(f"[red]Erreur de configuration: {e}[/red]")
        if verbose:
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
        return ExitCode.CONFIG_ERROR
    else:
        # Erreurs internes
        console.print(f"[red]Erreur interne: {e}[/red]")
        if verbose:
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
        return ExitCode.INTERNAL_ERROR


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
@click.option("--compare-to-baseline", type=click.Path(exists=True), help="Compare les résultats à une baseline")
@click.pass_context
def scan(
    ctx,
    path: str,
    output: Optional[str],
    format: str,
    fail_on: Optional[str],
    config: Optional[str],
    no_cache: bool,
    diff_aware: bool,
    compare_to_baseline: Optional[str]
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
        if not ctx.obj['quiet']:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True
            ) as progress:
                progress.add_task(description="Initialisation du moteur...", total=None)
                engine = CerberusEngine(cerberus_config)
                
                progress.update(progress.task_ids[0], description="Scan en cours...")
                results = engine.scan(scan_path, diff_aware=diff_aware)
        else:
            engine = CerberusEngine(cerberus_config)
            results = engine.scan(scan_path, diff_aware=diff_aware)
        
        # Filtrage par baseline si demandé
        original_findings_count = len(results.get('findings', []))
        if compare_to_baseline:
            baseline_manager = BaselineManager(Path(compare_to_baseline))
            baseline_data = baseline_manager.load_baseline()
            
            if baseline_data:
                # Convertir les findings dict en objets Finding pour le filtrage
                from cerberus.models.finding import Finding, Severity
                findings_objects = []
                for finding_dict in results.get('findings', []):
                    # Reconstruction basique d'un Finding depuis le dict
                    finding = Finding(
                        rule_id=finding_dict['rule_id'],
                        message=finding_dict['message'],
                        severity=Severity(finding_dict['severity']),
                        location={
                            'file_path': finding_dict['file_path'],
                            'line': finding_dict['line'],
                            'column': finding_dict['column']
                        },
                        metadata=finding_dict.get('metadata', {}),
                        variables=finding_dict.get('variables', {})
                    )
                    findings_objects.append(finding)
                
                # Filtrer les nouveaux findings
                new_findings = baseline_manager.filter_new_findings(findings_objects)
                
                # Reconvertir en dictionnaires
                filtered_findings = []
                for finding in new_findings:
                    filtered_findings.append({
                        'rule_id': finding.rule_id,
                        'message': finding.message,
                        'severity': finding.severity.value,
                        'file_path': finding.location.file_path,
                        'line': finding.location.line,
                        'column': finding.location.column,
                        'metadata': finding.metadata,
                        'variables': finding.variables
                    })
                
                results['findings'] = filtered_findings
                results['stats']['total_findings'] = len(filtered_findings)
                
                # Recalculer les stats par sévérité
                severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
                for finding in filtered_findings:
                    severity = finding.get("severity", "INFO")
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                results['stats']['findings_by_severity'] = severity_counts
                
                if not ctx.obj['quiet']:
                    console.print(f"[blue]Filtrage baseline: {original_findings_count} → {len(filtered_findings)} nouveaux findings[/blue]")
            else:
                console.print("[yellow]Impossible de charger la baseline, tous les findings sont affichés[/yellow]")
        
        # Génération du rapport
        if format == "console" and not output:
            _print_console_report(results, compare_to_baseline is not None)
        else:
            report_path = Path(output) if output else None
            engine.generate_report(results, format, report_path)
            if not ctx.obj['quiet'] and report_path:
                console.print(f"[green]Rapport généré: {report_path}[/green]")
        
        # Détermination du code de sortie
        exit_code = _calculate_exit_code(results, cerberus_config.scan.fail_on_severity)
        
        if not ctx.obj['quiet']:
            if exit_code == ExitCode.SUCCESS:
                console.print("[green]✓ Scan terminé avec succès[/green]")
            elif exit_code == ExitCode.FINDINGS_DETECTED:
                console.print("[red]✗ Des vulnérabilités bloquantes ont été détectées[/red]")
                
        # Logging des statistiques pour debug
        stats = results.get('stats', {})
        logger.info(f"Scan terminé: {stats.get('files_scanned', 0)} fichiers, "
                   f"{stats.get('total_findings', 0)} findings")
        
        sys.exit(exit_code)
        
    except Exception as e:
        exit_code = handle_exception(e, ctx.obj.get('verbose', False))
        sys.exit(exit_code)


@cli.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--output", "-o", type=click.Path(), help="Fichier de baseline (défaut: baseline.json)")
@click.option("--update", is_flag=True, help="Met à jour la baseline existante")
@click.option("--config", "-c", type=click.Path(exists=True), help="Fichier de configuration")
@click.option("--show-stats", is_flag=True, help="Affiche les statistiques de la baseline")
@click.pass_context
def baseline(ctx, path: str, output: Optional[str], update: bool, config: Optional[str], show_stats: bool):
    """
    Crée ou met à jour une baseline des vulnérabilités existantes.
    
    Une baseline capture l'état actuel des vulnérabilités pour permettre
    de filtrer les findings connus lors de scans ultérieurs.
    """
    scan_path = Path(path).resolve()
    baseline_path = Path(output) if output else Path("baseline.json")
    
    if not ctx.obj['quiet']:
        console.print(f"[bold blue]Cerberus-SAST v{__version__} - Gestion des baselines[/bold blue]")
    
    try:
        # Chargement de la configuration
        if config:
            config_path = Path(config)
            cerberus_config = CerberusConfig.from_file(config_path)
        else:
            cerberus_config = CerberusConfig.discover(scan_path)
            if not cerberus_config:
                cerberus_config = CerberusConfig.default()
        
        baseline_manager = BaselineManager(baseline_path)
        
        # Mode affichage des statistiques
        if show_stats:
            baseline_data = baseline_manager.load_baseline()
            if not baseline_data:
                console.print(f"[red]Aucune baseline trouvée: {baseline_path}[/red]")
                sys.exit(1)
            
            stats = baseline_manager.get_baseline_stats(baseline_data)
            _print_baseline_stats(stats)
            return
        
        # Lancer un scan pour obtenir les findings actuels
        if not ctx.obj['quiet']:
            console.print(f"Scan en cours de: {scan_path}")
        
        engine = CerberusEngine(cerberus_config)
        results = engine.scan(scan_path)
        
        # Convertir les findings dict en objets Finding
        from cerberus.models.finding import Finding, Severity
        findings_objects = []
        for finding_dict in results.get('findings', []):
            try:
                finding = Finding(
                    rule_id=finding_dict['rule_id'],
                    message=finding_dict['message'],
                    severity=Severity(finding_dict['severity']),
                    location={
                        'file_path': finding_dict['file_path'],
                        'line': finding_dict['line'],
                        'column': finding_dict['column']
                    },
                    metadata=finding_dict.get('metadata', {}),
                    variables=finding_dict.get('variables', {})
                )
                findings_objects.append(finding)
            except Exception as e:
                logger.warning(f"Impossible de convertir le finding: {e}")
                continue
        
        # Créer ou mettre à jour la baseline
        if update:
            baseline_data = baseline_manager.update_baseline(findings_objects, scan_path)
            action = "mise à jour"
        else:
            baseline_data = baseline_manager.create_baseline(findings_objects, scan_path)
            action = "création"
        
        # Sauvegarder la baseline
        saved_path = baseline_manager.save_baseline(baseline_data, baseline_path)
        
        if not ctx.obj['quiet']:
            console.print(f"[green]✓ Baseline {action} réussie: {saved_path}[/green]")
            console.print(f"  Findings capturés: {baseline_data['total_findings']}")
            
            # Afficher un résumé
            stats = baseline_manager.get_baseline_stats(baseline_data)
            console.print(f"  Par sévérité: {dict(stats['by_severity'])}")
            console.print(f"  Fichiers uniques: {stats['unique_files']}")
            console.print(f"  Règles uniques: {stats['unique_rules']}")
        
    except Exception as e:
        exit_code = handle_exception(e, ctx.obj.get('verbose', False))
        sys.exit(exit_code)


@cli.command()
@click.option("--plugin", "-p", help="Diagnostic pour un plugin spécifique")
@click.pass_context
def doctor(ctx, plugin: Optional[str]):
    """
    Effectue un diagnostic du système Cerberus-SAST.
    
    Vérifie l'état des plugins, des dépendances et de la configuration.
    """
    try:
        if not ctx.obj['quiet']:
            console.print(f"[bold blue]Cerberus-SAST v{__version__} - Diagnostic[/bold blue]")
        
        config = CerberusConfig.default()
        engine = CerberusEngine(config)
        
        # Diagnostic général
        diagnostic_info = engine.plugin_manager.get_diagnostic_info()
        
        if plugin:
            # Diagnostic spécifique à un plugin
            validation = engine.plugin_manager.validate_plugin_dependencies(plugin)
            _print_plugin_diagnostic(validation)
        else:
            # Diagnostic général
            _print_general_diagnostic(diagnostic_info)
        
        # Déterminer le code de sortie
        if diagnostic_info["summary"]["error_count"] > 0:
            exit_code = ExitCode.CONFIG_ERROR
        else:
            exit_code = ExitCode.SUCCESS
            
        sys.exit(exit_code)
        
    except Exception as e:
        exit_code = handle_exception(e, ctx.obj.get('verbose', False))
        sys.exit(exit_code)


def _print_general_diagnostic(diagnostic_info: Dict[str, Any]):
    """Affiche le diagnostic général du système."""
    summary = diagnostic_info["summary"]
    
    # Résumé
    console.print(f"\n[bold]Résumé du système:[/bold]")
    console.print(f"  Plugins chargés: [green]{summary['loaded_count']}[/green]")
    console.print(f"  Plugins en erreur: [red]{summary['error_count']}[/red]")
    console.print(f"  Extensions supportées: [blue]{summary['total_extensions']}[/blue]")
    
    # Plugins chargés avec succès
    if diagnostic_info["loaded_plugins"]:
        console.print(f"\n[bold green]✓ Plugins fonctionnels:[/bold green]")
        for name, info in diagnostic_info["loaded_plugins"].items():
            console.print(f"  • {name} v{info['version']} ({', '.join(info['extensions'])})")
            console.print(f"    Règles: {info['rules_count']}")
    
    # Erreurs de plugins
    if diagnostic_info["plugin_errors"]:
        console.print(f"\n[bold red]✗ Plugins en erreur:[/bold red]")
        for plugin_name, error in diagnostic_info["plugin_errors"].items():
            console.print(f"  • {plugin_name}:")
            # Afficher seulement la première ligne de l'erreur pour le résumé
            error_summary = error.split('\n')[0]
            console.print(f"    [red]{error_summary}[/red]")
            console.print(f"    Utilisez [cyan]cerberus doctor --plugin {plugin_name}[/cyan] pour plus de détails")
    
    # Mapping des extensions
    if diagnostic_info["extension_mapping"]:
        console.print(f"\n[bold]Extensions supportées:[/bold]")
        ext_by_plugin = {}
        for ext, plugin in diagnostic_info["extension_mapping"].items():
            if plugin not in ext_by_plugin:
                ext_by_plugin[plugin] = []
            ext_by_plugin[plugin].append(ext)
        
        for plugin, extensions in ext_by_plugin.items():
            console.print(f"  {plugin}: {', '.join(sorted(extensions))}")


def _print_plugin_diagnostic(validation: Dict[str, Any]):
    """Affiche le diagnostic détaillé d'un plugin."""
    plugin_name = validation["plugin_name"]
    
    console.print(f"\n[bold]Diagnostic détaillé: {plugin_name}[/bold]")
    
    # État général
    if validation["exists"]:
        console.print(f"  État: [green]✓ Chargé[/green]")
    else:
        console.print(f"  État: [red]✗ Non chargé[/red]")
        if "error" in validation:
            console.print(f"  Erreur: [red]{validation['error']}[/red]")
        return
    
    # Méthodes requises
    console.print(f"\n[bold]Méthodes requises:[/bold]")
    for method_name, method_info in validation.get("methods", {}).items():
        if method_info["exists"] and method_info["callable"]:
            console.print(f"  ✓ {method_name}")
        else:
            console.print(f"  ✗ {method_name} [red](manquante ou non callable)[/red]")
    
    # Dépendances
    console.print(f"\n[bold]Dépendances:[/bold]")
    deps = validation.get("dependencies", {})
    if "tree_sitter" in deps:
        ts_info = deps["tree_sitter"]
        if ts_info["available"]:
            console.print(f"  ✓ Tree-sitter: [green]Disponible[/green] ({ts_info.get('type', 'Unknown')})")
        else:
            console.print(f"  ✗ Tree-sitter: [red]Non disponible[/red]")
            if "error" in ts_info:
                console.print(f"    Erreur: {ts_info['error']}")
    
    # Règles
    console.print(f"\n[bold]Règles:[/bold]")
    rules_info = validation.get("rules", {})
    if "error" in rules_info:
        console.print(f"  ✗ Erreur: [red]{rules_info['error']}[/red]")
    else:
        total_rules = rules_info.get("count", 0)
        existing_rules = len(rules_info.get("existing", []))
        console.print(f"  Total: {total_rules}")
        console.print(f"  Disponibles: [green]{existing_rules}[/green]")
        
        if existing_rules < total_rules:
            missing = total_rules - existing_rules
            console.print(f"  Manquantes: [red]{missing}[/red]")
    
    # Recommandations
    recommendations = validation.get("recommendations", [])
    if recommendations:
        console.print(f"\n[bold yellow]Recommandations:[/bold yellow]")
        for rec in recommendations:
            console.print(f"  • {rec}")


def _print_baseline_stats(stats: Dict[str, Any]):
    """Affiche les statistiques d'une baseline."""
    console.print("\n[bold]Statistiques de la baseline:[/bold]")
    
    if 'error' in stats:
        console.print(f"[red]{stats['error']}[/red]")
        return
    
    console.print(f"  Créée le: {stats.get('created_at', 'Inconnue')}")
    console.print(f"  Chemin scanné: {stats.get('scan_path', 'Inconnu')}")
    console.print(f"  Total findings: {stats.get('total_findings', 0)}")
    console.print(f"  Fichiers uniques: {stats.get('unique_files', 0)}")
    console.print(f"  Règles uniques: {stats.get('unique_rules', 0)}")
    
    # Par sévérité
    severity_stats = stats.get('by_severity', {})
    if severity_stats:
        console.print("\n[bold]Répartition par sévérité:[/bold]")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if severity in severity_stats:
                count = severity_stats[severity]
                color = {
                    "CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
                    "LOW": "blue", "INFO": "cyan"
                }.get(severity, "white")
                console.print(f"  {severity}: [{color}]{count}[/{color}]")
    
    # Top fichiers
    top_files = stats.get('by_file', {})
    if top_files:
        console.print("\n[bold]Top 10 fichiers:[/bold]")
        for file_path, count in list(top_files.items())[:10]:
            console.print(f"  {file_path}: {count}")
    
    # Top règles
    top_rules = stats.get('by_rule', {})
    if top_rules:
        console.print("\n[bold]Top 10 règles:[/bold]")
        for rule_id, count in list(top_rules.items())[:10]:
            console.print(f"  {rule_id}: {count}")


@cli.command()
@click.option("--plugin", "-p", help="Filtre par plugin")
@click.option("--severity", "-s", help="Filtre par sévérité")
@click.pass_context
def rules(ctx, plugin: Optional[str], severity: Optional[str]):
    """
    Liste les règles disponibles.
    """
    try:
        config = CerberusConfig.default()
        engine = CerberusEngine(config)
        
        # Récupérer toutes les règles depuis le moteur de règles
        all_rules = engine.rule_engine.get_all_rules()
        
        if not all_rules:
            console.print("[yellow]Aucune règle trouvée. Vérifiez que les plugins sont correctement installés.[/yellow]")
            return
        
        # Filtrage des règles
        filtered_rules = {}
        for rule_id, rule in all_rules.items():
            # Filtre par plugin
            if plugin:
                rule_languages = [lang.lower() for lang in rule.languages]
                if plugin.lower() not in rule_languages:
                    continue
            
            # Filtre par sévérité
            if severity:
                if rule.severity != severity.upper():
                    continue
            
            filtered_rules[rule_id] = rule
        
        # Affichage du tableau
        table = Table(title=f"Règles disponibles ({len(filtered_rules)} règles)")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Langages", style="magenta")
        table.add_column("Sévérité", style="yellow", justify="center")
        table.add_column("Description", min_width=40)
        table.add_column("CWE", style="dim", justify="center")
        
        # Trier les règles par sévérité puis par ID
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_rules = sorted(
            filtered_rules.items(),
            key=lambda x: (severity_order.get(x[1].severity, 5), x[0])
        )
        
        for rule_id, rule in sorted_rules:
            # Couleur de la sévérité
            severity_color = {
                "CRITICAL": "red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "blue",
                "INFO": "cyan"
            }.get(rule.severity, "white")
            
            # Formatage de la description (limiter à 80 caractères)
            description = rule.message.replace('\n', ' ').strip()
            if len(description) > 80:
                description = description[:77] + "..."
            
            # Extraction du CWE des métadonnées
            cwe = rule.metadata.get("cwe", "N/A")
            
            table.add_row(
                rule_id,
                ", ".join(rule.languages),
                f"[{severity_color}]{rule.severity}[/{severity_color}]",
                description,
                cwe
            )
        
        console.print(table)
        
        # Statistiques
        if not ctx.obj.get('quiet', False):
            stats_by_severity = {}
            stats_by_language = {}
            
            for rule in filtered_rules.values():
                # Par sévérité
                severity = rule.severity
                stats_by_severity[severity] = stats_by_severity.get(severity, 0) + 1
                
                # Par langage
                for lang in rule.languages:
                    stats_by_language[lang] = stats_by_language.get(lang, 0) + 1
            
            console.print(f"\n[bold]Statistiques:[/bold]")
            console.print(f"  Total: {len(filtered_rules)} règles")
            
            if stats_by_severity:
                console.print("  Par sévérité:")
                for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                    if sev in stats_by_severity:
                        color = {
                            "CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
                            "LOW": "blue", "INFO": "cyan"
                        }.get(sev, "white")
                        console.print(f"    {sev}: [{color}]{stats_by_severity[sev]}[/{color}]")
            
            if stats_by_language:
                console.print("  Par langage:")
                for lang, count in sorted(stats_by_language.items()):
                    console.print(f"    {lang}: {count}")
        
    except Exception as e:
        exit_code = handle_exception(e, ctx.obj.get('verbose', False))
        sys.exit(exit_code)


def _print_console_report(results: dict, baseline_filtered: bool = False):
    """Affiche le rapport dans la console."""
    findings = results.get("findings", [])
    
    if not findings:
        if baseline_filtered:
            console.print("[green]✓ Aucune nouvelle vulnérabilité détectée par rapport à la baseline[/green]")
        else:
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
    """
    Calcule le code de sortie basé sur les résultats et le seuil de sévérité.
    
    Args:
        results: Résultats du scan
        fail_on_severity: Seuil de sévérité pour échec
        
    Returns:
        Code de sortie approprié (ExitCode.SUCCESS ou ExitCode.FINDINGS_DETECTED)
    """
    if fail_on_severity == "NONE":
        return ExitCode.SUCCESS
    
    severity_levels = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1
    }
    
    threshold = severity_levels.get(fail_on_severity, 4)
    findings = results.get("findings", [])
    
    # Compter les findings bloquants
    blocking_findings = 0
    for finding in findings:
        finding_level = severity_levels.get(finding.get("severity", "INFO"), 1)
        if finding_level >= threshold:
            blocking_findings += 1
    
    logger.debug(f"Seuil: {fail_on_severity} ({threshold}), "
                f"Findings bloquants: {blocking_findings}/{len(findings)}")
    
    return ExitCode.FINDINGS_DETECTED if blocking_findings > 0 else ExitCode.SUCCESS


def main():
    """Point d'entrée principal."""
    cli(obj={})