"""
Module de génération de rapports pour Cerberus-SAST.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

from cerberus import __version__


logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Générateur de rapports multi-formats.
    """
    
    def generate(self, results: Dict[str, Any], format: str, output_path: Optional[Path] = None):
        """
        Génère un rapport dans le format demandé.
        
        Args:
            results: Résultats de l'analyse
            format: Format de sortie (sarif, json, html, console)
            output_path: Chemin de sortie optionnel
        """
        generators = {
            "json": self._generate_json,
            "sarif": self._generate_sarif,
            "html": self._generate_html,
            "console": self._generate_console
        }
        
        if format not in generators:
            raise ValueError(f"Format non supporté: {format}")
        
        content = generators[format](results)
        
        if output_path and format != "console":
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            if format == "html":
                output_path.write_text(content, encoding='utf-8')
            else:
                output_path.write_text(json.dumps(content, indent=2), encoding='utf-8')
            
            logger.info(f"Rapport généré: {output_path}")
    
    def _generate_json(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Génère un rapport JSON simple.
        
        Args:
            results: Résultats de l'analyse
            
        Returns:
            Dict: Rapport au format JSON
        """
        return {
            "cerberus_version": __version__,
            "scan_date": datetime.utcnow().isoformat() + "Z",
            "findings": results.get("findings", []),
            "statistics": results.get("stats", {}),
            "metadata": results.get("metadata", {})
        }
    
    def _generate_sarif(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Génère un rapport au format SARIF 2.1.0.
        
        Args:
            results: Résultats de l'analyse
            
        Returns:
            Dict: Rapport au format SARIF
        """
        # Créer la structure SARIF de base
        sarif = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Cerberus-SAST",
                        "version": __version__,
                        "informationUri": "https://github.com/cerberus-sast",
                        "rules": []
                    }
                },
                "results": [],
                "columnKind": "utf16CodeUnits"
            }]
        }
        
        # Collecter les règles uniques
        rules_map = {}
        
        for finding in results.get("findings", []):
            rule_id = finding.get("rule_id", "unknown")
            
            # Ajouter la règle si pas déjà présente
            if rule_id not in rules_map:
                rule = {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {
                        "text": finding.get("message", "")[:100]
                    },
                    "fullDescription": {
                        "text": finding.get("message", "")
                    },
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(finding.get("severity", "INFO"))
                    }
                }
                
                # Ajouter les métadonnées
                metadata = finding.get("metadata", {})
                if metadata:
                    rule["properties"] = {
                        "tags": []
                    }
                    if "cwe" in metadata:
                        rule["properties"]["tags"].append(metadata["cwe"].lower())
                    if "category" in metadata:
                        rule["properties"]["tags"].append(metadata["category"])
                
                rules_map[rule_id] = rule
            
            # Créer le résultat SARIF
            result = {
                "ruleId": rule_id,
                "level": self._severity_to_sarif_level(finding.get("severity", "INFO")),
                "message": {
                    "text": finding.get("message", "")
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f"file:///{finding.get('file_path', 'unknown')}"
                        },
                        "region": {
                            "startLine": finding.get("line", 1),
                            "startColumn": finding.get("column", 1)
                        }
                    }
                }],
                "partialFingerprints": {
                    "primaryLocationLineHash": self._generate_fingerprint(finding)
                }
            }
            
            # Ajouter le fix si disponible
            if "fix" in finding:
                result["fixes"] = [{
                    "description": {
                        "text": "Correction automatique suggérée"
                    },
                    "artifactChanges": [{
                        "artifactLocation": {
                            "uri": f"file:///{finding.get('file_path', 'unknown')}"
                        },
                        "replacements": [{
                            "deletedRegion": {
                                "startLine": finding.get("line", 1),
                                "startColumn": finding.get("column", 1)
                            },
                            "insertedContent": {
                                "text": finding["fix"].get("pattern", "")
                            }
                        }]
                    }]
                }]
            
            sarif["runs"][0]["results"].append(result)
        
        # Ajouter toutes les règles collectées
        sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules_map.values())
        
        return sarif
    
    def _generate_html(self, results: Dict[str, Any]) -> str:
        """
        Génère un rapport HTML.
        
        Args:
            results: Résultats de l'analyse
            
        Returns:
            str: Rapport HTML
        """
        findings = results.get("findings", [])
        stats = results.get("stats", {})
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Rapport Cerberus-SAST</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .finding {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .severity-CRITICAL {{ border-left: 5px solid #d32f2f; }}
        .severity-HIGH {{ border-left: 5px solid #f44336; }}
        .severity-MEDIUM {{ border-left: 5px solid #ff9800; }}
        .severity-LOW {{ border-left: 5px solid #2196f3; }}
        .severity-INFO {{ border-left: 5px solid #4caf50; }}
        .code {{ background: #f5f5f5; padding: 10px; font-family: monospace; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>Rapport d'Analyse Cerberus-SAST</h1>
    
    <div class="summary">
        <h2>Résumé</h2>
        <p>Date du scan: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
        <p>Fichiers analysés: {stats.get('files_scanned', 0)}</p>
        <p>Vulnérabilités trouvées: {stats.get('total_findings', 0)}</p>
        <ul>
"""
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = stats.get('findings_by_severity', {}).get(severity, 0)
            if count > 0:
                html += f"            <li>{severity}: {count}</li>\n"
        
        html += """        </ul>
    </div>
    
    <h2>Détails des Vulnérabilités</h2>
"""
        
        for finding in findings:
            severity = finding.get('severity', 'INFO')
            html += f"""
    <div class="finding severity-{severity}">
        <h3>[{severity}] {finding.get('rule_id', 'unknown')}</h3>
        <p><strong>Fichier:</strong> {finding.get('file_path', 'unknown')}:{finding.get('line', '?')}</p>
        <p>{finding.get('message', 'Pas de description')}</p>
"""
            
            if finding.get('code_snippet'):
                html += f"""        <div class="code">{finding['code_snippet']}</div>"""
            
            html += """    </div>
"""
        
        html += """</body>
</html>"""
        
        return html
    
    def _generate_console(self, results: Dict[str, Any]) -> None:
        """
        Génère un rapport console (ne retourne rien).
        
        Args:
            results: Résultats de l'analyse
        """
        # Le rapport console est géré directement par la CLI
        pass
    
    def _severity_to_sarif_level(self, severity: str) -> str:
        """
        Convertit la sévérité Cerberus en niveau SARIF.
        
        Args:
            severity: Sévérité Cerberus
            
        Returns:
            str: Niveau SARIF
        """
        mapping = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note"
        }
        return mapping.get(severity, "note")
    
    def _generate_fingerprint(self, finding: Dict[str, Any]) -> str:
        """
        Génère une empreinte unique pour un finding.
        
        Args:
            finding: Résultat trouvé
            
        Returns:
            str: Empreinte unique
        """
        # Simple hash basé sur le rule_id et le fichier
        import hashlib
        
        data = f"{finding.get('rule_id', '')}:{finding.get('file_path', '')}:{finding.get('line', '')}"
        return hashlib.md5(data.encode()).hexdigest()[:16]