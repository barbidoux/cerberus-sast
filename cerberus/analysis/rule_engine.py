"""
Moteur de règles pour Cerberus-SAST.

Ce module gère le chargement et l'application des règles de détection.
"""

import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
import yaml
from pydantic import BaseModel, Field, validator


logger = logging.getLogger(__name__)


class Rule(BaseModel):
    """Modèle d'une règle de détection."""
    id: str
    message: str
    severity: str
    languages: List[str]
    pattern: Optional[str] = None
    patterns: Optional[List[Dict[str, Any]]] = None
    pattern_either: Optional[List[Dict[str, Any]]] = Field(None, alias="pattern-either")
    metadata: Dict[str, Any] = Field(default_factory=dict)
    autofix: Optional[Dict[str, str]] = None
    
    @validator('severity')
    def validate_severity(cls, v):
        valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        if v not in valid_severities:
            raise ValueError(f"Sévérité invalide: {v}. Doit être l'une de: {valid_severities}")
        return v
    
    @validator('pattern', 'patterns', 'pattern_either')
    def validate_pattern_presence(cls, v, values):
        # Au moins un type de pattern doit être présent
        if not any([v, values.get('pattern'), values.get('patterns'), values.get('pattern_either')]):
            raise ValueError("Une règle doit avoir au moins un pattern défini")
        return v


class RuleSet(BaseModel):
    """Collection de règles."""
    rules: List[Rule]
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RuleEngine:
    """
    Moteur responsable du chargement et de l'application des règles.
    """
    
    def __init__(self):
        """Initialise le moteur de règles."""
        self.rules: Dict[str, Rule] = {}  # rule_id -> Rule
        self.rules_by_language: Dict[str, List[Rule]] = {}  # language -> [Rule]
    
    def load_rules_from_file(self, rule_file: Path):
        """
        Charge des règles depuis un fichier YAML.
        
        Args:
            rule_file: Chemin vers le fichier de règles
            
        Raises:
            ValueError: Si le fichier est invalide
        """
        logger.info(f"Chargement des règles depuis: {rule_file}")
        
        try:
            with open(rule_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            if not data:
                logger.warning(f"Fichier de règles vide: {rule_file}")
                return
            
            # Gérer les différents formats possibles
            if 'rules' in data:
                # Format avec une liste de règles
                ruleset = RuleSet(**data)
                for rule in ruleset.rules:
                    self._register_rule(rule)
            elif 'id' in data:
                # Fichier contenant une seule règle
                rule = Rule(**data)
                self._register_rule(rule)
            else:
                raise ValueError(f"Format de règle non reconnu dans: {rule_file}")
                
        except Exception as e:
            logger.error(f"Erreur lors du chargement des règles depuis {rule_file}: {e}")
            raise
    
    def _register_rule(self, rule: Rule):
        """
        Enregistre une règle dans le moteur.
        
        Args:
            rule: Règle à enregistrer
        """
        if rule.id in self.rules:
            logger.warning(f"Règle '{rule.id}' déjà enregistrée, écrasement")
        
        self.rules[rule.id] = rule
        
        # Indexer par langage
        for language in rule.languages:
            if language not in self.rules_by_language:
                self.rules_by_language[language] = []
            self.rules_by_language[language].append(rule)
        
        logger.debug(f"Règle '{rule.id}' enregistrée pour les langages: {rule.languages}")
    
    def get_rules_for_language(self, language: str) -> List[Rule]:
        """
        Retourne toutes les règles applicables à un langage.
        
        Args:
            language: Nom du langage
            
        Returns:
            List[Rule]: Règles applicables
        """
        return self.rules_by_language.get(language, [])
    
    def check_file(self, ast: Any, file_path: Path, language: str) -> List[Dict[str, Any]]:
        """
        Applique toutes les règles pertinentes à un fichier.
        
        Args:
            ast: Arbre syntaxique abstrait du fichier
            file_path: Chemin du fichier
            language: Langage du fichier
            
        Returns:
            List[Dict]: Vulnérabilités trouvées
        """
        findings = []
        rules = self.get_rules_for_language(language)
        
        logger.debug(f"Application de {len(rules)} règles sur {file_path}")
        
        for rule in rules:
            # TODO: Implémenter la logique de pattern matching avec tree-sitter
            # Pour l'instant, on simule avec une détection basique
            matches = self._apply_rule(rule, ast, file_path)
            
            for match in matches:
                finding = {
                    "rule_id": rule.id,
                    "message": rule.message,
                    "severity": rule.severity,
                    "file_path": str(file_path),
                    "line": match.get("line", 1),
                    "column": match.get("column", 1),
                    "metadata": rule.metadata,
                    "code_snippet": match.get("snippet", "")
                }
                
                if rule.autofix:
                    finding["fix"] = rule.autofix
                
                findings.append(finding)
        
        return findings
    
    def _apply_rule(self, rule: Rule, ast: Any, file_path: Path) -> List[Dict[str, Any]]:
        """
        Applique une règle spécifique à un AST.
        
        Args:
            rule: Règle à appliquer
            ast: Arbre syntaxique
            file_path: Chemin du fichier
            
        Returns:
            List[Dict]: Correspondances trouvées
        """
        # TODO: Implémenter le vrai pattern matching avec tree-sitter
        # Pour l'instant, retour vide
        return []
    
    def get_all_rules(self) -> Dict[str, Rule]:
        """
        Retourne toutes les règles chargées.
        
        Returns:
            Dict[str, Rule]: Toutes les règles indexées par ID
        """
        return self.rules.copy()