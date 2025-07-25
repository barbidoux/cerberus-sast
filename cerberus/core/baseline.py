"""
Gestion des baselines pour Cerberus-SAST.

Ce module gère la création, le chargement et la comparaison des baselines
pour filtrer les findings déjà connus et ne remonter que les nouveaux.
"""

import json
import logging
import hashlib
from pathlib import Path
from typing import Dict, List, Set, Optional, Any
from datetime import datetime

from cerberus.models.finding import Finding


logger = logging.getLogger(__name__)


class BaselineManager:
    """
    Gestionnaire des baselines pour filtrer les findings connus.
    
    Une baseline est un snapshot des findings existants à un moment donné.
    Elle permet de ne remonter que les nouveaux findings lors des scans ultérieurs.
    """
    
    def __init__(self, baseline_path: Optional[Path] = None):
        """
        Initialise le gestionnaire de baseline.
        
        Args:
            baseline_path: Chemin vers le fichier de baseline (défaut: baseline.json)
        """
        self.baseline_path = baseline_path or Path("baseline.json")
        self._baseline_data: Optional[Dict[str, Any]] = None
    
    def create_baseline(self, findings: List[Finding], scan_path: Path) -> Dict[str, Any]:
        """
        Crée une nouvelle baseline à partir d'une liste de findings.
        
        Args:
            findings: Liste des findings actuels
            scan_path: Chemin scanné
            
        Returns:
            Dictionnaire contenant les données de la baseline
        """
        logger.info(f"Création d'une baseline avec {len(findings)} findings")
        
        # Convertir les findings en signatures pour comparaison
        finding_signatures = []
        for finding in findings:
            signature = self._create_finding_signature(finding)
            finding_signatures.append(signature)
        
        baseline_data = {
            "version": "1.0",
            "created_at": datetime.now().isoformat(),
            "scan_path": str(scan_path.resolve()),
            "total_findings": len(findings),
            "findings": finding_signatures,
            "metadata": {
                "generator": "cerberus-sast",
                "description": "Baseline des vulnérabilités existantes"
            }
        }
        
        self._baseline_data = baseline_data
        return baseline_data
    
    def save_baseline(self, baseline_data: Dict[str, Any], output_path: Optional[Path] = None) -> Path:
        """
        Sauvegarde une baseline sur disque.
        
        Args:
            baseline_data: Données de la baseline
            output_path: Chemin de sortie (optionnel)
            
        Returns:
            Chemin du fichier créé
        """
        output_file = output_path or self.baseline_path
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(baseline_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Baseline sauvegardée: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde de la baseline: {e}")
            raise
    
    def load_baseline(self, baseline_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
        """
        Charge une baseline depuis le disque.
        
        Args:
            baseline_path: Chemin vers le fichier de baseline
            
        Returns:
            Données de la baseline ou None si non trouvée
        """
        file_path = baseline_path or self.baseline_path
        
        if not file_path.exists():
            logger.warning(f"Fichier de baseline non trouvé: {file_path}")
            return None
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                baseline_data = json.load(f)
            
            # Validation basique
            if not isinstance(baseline_data, dict) or 'findings' not in baseline_data:
                logger.error(f"Format de baseline invalide: {file_path}")
                return None
            
            logger.info(f"Baseline chargée: {file_path} ({baseline_data.get('total_findings', 0)} findings)")
            self._baseline_data = baseline_data
            return baseline_data
            
        except json.JSONDecodeError as e:
            logger.error(f"Erreur de parsing JSON de la baseline: {e}")
            return None
        except Exception as e:
            logger.error(f"Erreur lors du chargement de la baseline: {e}")
            return None
    
    def filter_new_findings(self, findings: List[Finding], baseline_data: Optional[Dict[str, Any]] = None) -> List[Finding]:
        """
        Filtre les findings pour ne garder que les nouveaux (non présents dans la baseline).
        
        Args:
            findings: Liste des findings actuels
            baseline_data: Données de baseline (utilise celle chargée si None)
            
        Returns:
            Liste des findings nouveaux uniquement
        """
        if baseline_data is None:
            baseline_data = self._baseline_data
        
        if not baseline_data:
            logger.warning("Aucune baseline disponible, tous les findings sont considérés comme nouveaux")
            return findings
        
        # Créer un set des signatures de baseline pour recherche rapide
        baseline_signatures = set()
        for baseline_finding in baseline_data.get('findings', []):
            baseline_signatures.add(baseline_finding.get('signature', ''))
        
        logger.debug(f"Baseline contient {len(baseline_signatures)} signatures")
        
        # Filtrer les findings nouveaux
        new_findings = []
        for finding in findings:
            signature = self._create_finding_signature(finding)['signature']
            if signature not in baseline_signatures:
                new_findings.append(finding)
                logger.debug(f"Nouveau finding détecté: {finding.rule_id} @ {finding.location.file_path}:{finding.location.line}")
        
        logger.info(f"Filtrage baseline: {len(findings)} findings → {len(new_findings)} nouveaux")
        return new_findings
    
    def _create_finding_signature(self, finding: Finding) -> Dict[str, Any]:
        """
        Crée une signature unique pour un finding.
        
        La signature permet d'identifier de manière unique un finding
        même si d'autres détails changent (message, métadonnées, etc.).
        
        Args:
            finding: Finding à signer
            
        Returns:
            Dictionnaire avec la signature et les métadonnées essentielles
        """
        # Éléments stables pour la signature
        signature_elements = [
            finding.rule_id,
            finding.location.file_path,
            str(finding.location.line),
            str(finding.location.column),
            finding.severity.value
        ]
        
        # Ajouter les variables capturées si disponibles (pour distinguer les instances)
        if finding.variables:
            # Trier les variables pour une signature déterministe
            sorted_vars = sorted(finding.variables.items())
            signature_elements.extend([f"{k}={v}" for k, v in sorted_vars])
        
        # Créer un hash de la signature
        signature_string = "|".join(signature_elements)
        signature_hash = hashlib.sha256(signature_string.encode('utf-8')).hexdigest()[:16]
        
        return {
            "signature": signature_hash,
            "rule_id": finding.rule_id,
            "file_path": finding.location.file_path,
            "line": finding.location.line,
            "column": finding.location.column,
            "severity": finding.severity.value,
            "variables": finding.variables,
            "message": finding.message[:100],  # Truncated pour économiser l'espace
            "created_at": datetime.now().isoformat()
        }
    
    def get_baseline_stats(self, baseline_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Retourne les statistiques d'une baseline.
        
        Args:
            baseline_data: Données de baseline (utilise celle chargée si None)
            
        Returns:
            Dictionnaire avec les statistiques
        """
        if baseline_data is None:
            baseline_data = self._baseline_data
        
        if not baseline_data:
            return {"error": "Aucune baseline disponible"}
        
        findings = baseline_data.get('findings', [])
        
        # Statistiques par sévérité
        severity_counts = {}
        for finding in findings:
            severity = finding.get('severity', 'INFO')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Statistiques par fichier
        file_counts = {}
        for finding in findings:
            file_path = finding.get('file_path', 'unknown')
            file_counts[file_path] = file_counts.get(file_path, 0) + 1
        
        # Statistiques par règle
        rule_counts = {}
        for finding in findings:
            rule_id = finding.get('rule_id', 'unknown')
            rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
        
        return {
            "created_at": baseline_data.get('created_at'),
            "scan_path": baseline_data.get('scan_path'),
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "by_file": dict(sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:10]),  # Top 10
            "by_rule": dict(sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10]),   # Top 10
            "unique_files": len(file_counts),
            "unique_rules": len(rule_counts)
        }
    
    def update_baseline(self, new_findings: List[Finding], scan_path: Path) -> Dict[str, Any]:
        """
        Met à jour une baseline existante avec de nouveaux findings.
        
        Args:
            new_findings: Nouveaux findings à ajouter
            scan_path: Chemin scanné
            
        Returns:
            Nouvelle baseline mise à jour
        """
        # Charger la baseline existante si elle existe
        existing_baseline = self.load_baseline()
        
        if existing_baseline:
            logger.info("Mise à jour de la baseline existante")
            # Fusionner avec les nouveaux findings
            existing_signatures = {f.get('signature') for f in existing_baseline.get('findings', [])}
            
            new_signature_findings = []
            added_count = 0
            
            for finding in new_findings:
                signature_data = self._create_finding_signature(finding)
                if signature_data['signature'] not in existing_signatures:
                    new_signature_findings.append(signature_data)
                    added_count += 1
            
            # Combiner les findings
            all_findings = existing_baseline.get('findings', []) + new_signature_findings
            
            updated_baseline = {
                **existing_baseline,
                "updated_at": datetime.now().isoformat(),
                "total_findings": len(all_findings),
                "findings": all_findings
            }
            
            logger.info(f"Baseline mise à jour: +{added_count} nouveaux findings")
            
        else:
            logger.info("Création d'une nouvelle baseline")
            updated_baseline = self.create_baseline(new_findings, scan_path)
        
        self._baseline_data = updated_baseline
        return updated_baseline