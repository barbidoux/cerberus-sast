"""
Moteur principal de Cerberus-SAST.

Ce module orchestre l'ensemble du processus d'analyse.
"""

import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor, as_completed

from cerberus.core.config import CerberusConfig
from cerberus.plugins.manager import PluginManager
from cerberus.analysis.rule_engine import RuleEngine
from cerberus.core.scanner import FileScanner
from cerberus.reporting.formats import ReportGenerator
from cerberus.ast.cerberus_node import CerberusNode
from cerberus.models.finding import Finding

try:
    import tree_sitter
except ImportError:
    tree_sitter = None


logger = logging.getLogger(__name__)


class CerberusEngine:
    """
    Moteur principal qui orchestre l'analyse de sécurité.
    """
    
    def __init__(self, config: CerberusConfig):
        """
        Initialise le moteur avec la configuration donnée.
        
        Args:
            config: Configuration Cerberus
        """
        self.config = config
        self.plugin_manager = PluginManager()
        self.rule_engine = RuleEngine()
        self.file_scanner = FileScanner(config)
        self.report_generator = ReportGenerator()
        
        # Déterminer le nombre de workers
        self.num_workers = config.scan.parallel_workers or mp.cpu_count()
        
        # Initialiser les plugins
        self._initialize_plugins()
    
    def _initialize_plugins(self):
        """Initialise tous les plugins activés."""
        logger.info("Initialisation des plugins...")
        
        for plugin_name, plugin_config in self.config.plugins.items():
            if not plugin_config.enabled:
                continue
                
            try:
                plugin = self.plugin_manager.load_plugin(plugin_name)
                plugin.initialize(plugin_config.options)
                
                # Charger les règles du plugin
                for rule_path in plugin.get_rule_paths():
                    self.rule_engine.load_rules_from_file(rule_path)
                
                logger.info(f"Plugin '{plugin_name}' chargé avec succès")
                
            except Exception as e:
                logger.error(f"Erreur lors du chargement du plugin '{plugin_name}': {e}")
    
    def scan(self, target_path: Path, diff_aware: bool = False) -> Dict[str, Any]:
        """
        Lance une analyse de sécurité sur le chemin cible.
        
        Args:
            target_path: Chemin à analyser
            diff_aware: Si True, analyse seulement les fichiers modifiés
            
        Returns:
            Dict contenant les résultats de l'analyse
        """
        logger.info(f"Démarrage du scan sur: {target_path}")
        
        # Phase 1: Découverte des fichiers
        files_to_scan = self.file_scanner.discover_files(target_path, diff_aware)
        logger.info(f"Fichiers à analyser: {len(files_to_scan)}")
        
        if not files_to_scan:
            return {"findings": [], "stats": {"files_scanned": 0}}
        
        # Phase 2: Analyse parallèle
        all_findings = []
        
        with ProcessPoolExecutor(max_workers=self.num_workers) as executor:
            # Soumettre les tâches d'analyse
            future_to_file = {
                executor.submit(self._analyze_file, file_path): file_path
                for file_path in files_to_scan
            }
            
            # Collecter les résultats
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except Exception as e:
                    logger.error(f"Erreur lors de l'analyse de {file_path}: {e}")
        
        # Phase 3: Post-traitement et agrégation
        results = self._aggregate_results(all_findings, len(files_to_scan))
        
        logger.info(f"Scan terminé. {len(all_findings)} vulnérabilités trouvées.")
        
        return results
    
    def _analyze_file(self, file_path: Path) -> List[Finding]:
        """
        Analyse un fichier individuel.
        
        Args:
            file_path: Chemin du fichier à analyser
            
        Returns:
            Liste des vulnérabilités trouvées
        """
        findings = []
        
        try:
            # Déterminer le plugin à utiliser
            plugin = self.plugin_manager.get_plugin_for_file(file_path)
            if not plugin:
                logger.debug(f"Aucun plugin pour: {file_path}")
                return findings
            
            # Parser le fichier avec tree-sitter
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Générer l'AST avec Tree-sitter
            ast = self._parse_file(content, file_path, plugin)
            if not ast:
                logger.warning(f"Impossible de parser le fichier: {file_path}")
                return findings
            
            # Appliquer les règles
            findings = self.rule_engine.check_file(ast, file_path, plugin.name)
            
            logger.debug(f"Fichier analysé: {file_path} - {len(findings)} findings")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse de {file_path}: {e}")
        
        return findings
    
    def _parse_file(self, content: str, file_path: Path, plugin) -> Optional[CerberusNode]:
        """
        Parse un fichier avec Tree-sitter et retourne un CerberusNode.
        
        Args:
            content: Contenu du fichier
            file_path: Chemin du fichier
            plugin: Plugin responsable du langage
            
        Returns:
            CerberusNode racine de l'AST ou None en cas d'erreur
        """
        if not tree_sitter:
            logger.error("Tree-sitter n'est pas disponible")
            return None
        
        try:
            # Récupérer le langage Tree-sitter du plugin
            language = plugin.get_tree_sitter_language()
            if not language:
                logger.error(f"Langage Tree-sitter non disponible pour {plugin.name}")
                return None
            
            # Créer le parser
            parser = tree_sitter.Parser()
            parser.set_language(language)
            
            # Parser le contenu
            tree = parser.parse(bytes(content, 'utf-8'))
            
            if tree.root_node.has_error:
                logger.warning(f"Erreurs de parsing détectées dans {file_path}")
            
            # Créer le CerberusNode racine
            root_node = CerberusNode(
                tree_sitter_node=tree.root_node,
                source_code=content,
                file_path=file_path
            )
            
            logger.debug(f"AST généré pour {file_path}: {tree.root_node.type} "
                        f"({len(tree.root_node.children)} enfants)")
            
            return root_node
            
        except Exception as e:
            logger.error(f"Erreur lors du parsing de {file_path}: {e}")
            return None
    
    def _aggregate_results(self, findings: List[Finding], files_count: int) -> Dict[str, Any]:
        """
        Agrège les résultats de l'analyse.
        
        Args:
            findings: Liste de toutes les vulnérabilités trouvées
            files_count: Nombre de fichiers analysés
            
        Returns:
            Dict avec les résultats agrégés
        """
        # Calculer les statistiques
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        for finding in findings:
            severity = finding.severity.value
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Convertir les findings en dictionnaires pour la compatibilité
        findings_dicts = []
        for finding in findings:
            finding_dict = {
                "rule_id": finding.rule_id,
                "message": finding.message,
                "severity": finding.severity.value,
                "file_path": finding.location.file_path,
                "line": finding.location.line,
                "column": finding.location.column,
                "metadata": finding.metadata,
                "variables": finding.variables
            }
            
            if finding.code_snippet:
                finding_dict["code_snippet"] = finding.code_snippet.content
            
            if finding.fix:
                finding_dict["fix"] = {
                    "pattern": finding.fix.pattern,
                    "description": finding.fix.description
                }
            
            findings_dicts.append(finding_dict)
        
        return {
            "findings": findings_dicts,
            "stats": {
                "files_scanned": files_count,
                "total_findings": len(findings),
                "findings_by_severity": severity_counts
            },
            "metadata": {
                "engine_version": "1.0.0",
                "scan_config": {
                    "fail_on_severity": self.config.scan.fail_on_severity,
                    "cache_enabled": self.config.scan.cache_enabled
                }
            }
        }
    
    def generate_report(self, results: Dict[str, Any], format: str, output_path: Optional[Path] = None):
        """
        Génère un rapport dans le format demandé.
        
        Args:
            results: Résultats de l'analyse
            format: Format de sortie (sarif, json, html, console)
            output_path: Chemin de sortie (optionnel)
        """
        self.report_generator.generate(results, format, output_path)