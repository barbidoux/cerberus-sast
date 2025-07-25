"""
Moteur de règles pour Cerberus-SAST.

Ce module gère le chargement et l'application des règles de détection.
"""

import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
import yaml
from pydantic import BaseModel, Field, validator

from cerberus.ast.cerberus_node import CerberusNode
from cerberus.models.finding import Finding, Severity


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
    
    def check_file(self, ast: CerberusNode, file_path: Path, language: str) -> List[Finding]:
        """
        Applique toutes les règles pertinentes à un fichier.
        
        Args:
            ast: CerberusNode racine de l'AST du fichier
            file_path: Chemin du fichier
            language: Langage du fichier
            
        Returns:
            List[Finding]: Vulnérabilités trouvées
        """
        findings = []
        rules = self.get_rules_for_language(language)
        
        logger.debug(f"Application de {len(rules)} règles sur {file_path}")
        
        for rule in rules:
            matches = self._apply_rule(rule, ast, file_path)
            
            for match in matches:
                finding = Finding.from_match(
                    rule_id=rule.id,
                    message=rule.message,
                    severity=Severity(rule.severity),
                    file_path=file_path,
                    match=match,
                    metadata=rule.metadata,
                    fix=rule.autofix
                )
                findings.append(finding)
        
        logger.debug(f"Génération de {len(findings)} findings pour {file_path}")
        return findings
    
    def _apply_rule(self, rule: Rule, ast: CerberusNode, file_path: Path) -> List[Dict[str, Any]]:
        """
        Applique une règle spécifique à un AST.
        
        Args:
            rule: Règle à appliquer
            ast: CerberusNode racine de l'AST
            file_path: Chemin du fichier
            
        Returns:
            List[Dict]: Correspondances trouvées avec métadonnées
        """
        matches = []
        
        try:
            # Gestion des différents types de patterns
            if rule.pattern:
                # Pattern simple
                matches.extend(self._match_single_pattern(rule.pattern, ast))
                
            elif rule.patterns:
                # Logique AND - tous les patterns doivent matcher
                matches.extend(self._match_patterns_and(rule.patterns, ast))
                
            elif rule.pattern_either:
                # Logique OR - au moins un pattern doit matcher  
                matches.extend(self._match_patterns_or(rule.pattern_either, ast))
            
            logger.debug(f"Règle '{rule.id}' appliquée: {len(matches)} correspondances")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'application de la règle '{rule.id}': {e}")
        
        return matches
    
    def _match_single_pattern(self, pattern: str, ast: CerberusNode) -> List[Dict[str, Any]]:
        """
        Recherche un pattern simple dans l'AST.
        
        Args:
            pattern: Pattern à rechercher (ex: 'strcpy($DEST, $SRC)')
            ast: CerberusNode racine
            
        Returns:
            Liste des correspondances trouvées
        """
        matches = []
        
        # Parcours récursif de l'AST pour chercher des correspondances
        nodes_to_check = [ast]
        while nodes_to_check:
            current_node = nodes_to_check.pop(0)
            
            # Vérifier si le nœud actuel correspond au pattern
            variables = {}
            if current_node.matches_pattern(pattern, variables):
                match = {
                    "line": current_node.line,
                    "column": current_node.column,
                    "snippet": current_node.get_context_snippet(1, 1),
                    "variables": variables,
                    "node_type": current_node.type,
                    "node_text": current_node.text
                }
                matches.append(match)
            
            # Ajouter les enfants à la liste de vérification
            nodes_to_check.extend(current_node.children)
        
        return matches
    
    def _match_patterns_and(self, patterns: List[Dict[str, Any]], ast: CerberusNode) -> List[Dict[str, Any]]:
        """
        Applique une logique AND sur plusieurs patterns.
        
        Tous les patterns doivent être trouvés dans le même contexte
        (par exemple, même fonction ou même scope).
        
        Args:
            patterns: Liste des patterns à matcher avec logique AND
            ast: CerberusNode racine
            
        Returns:
            Liste des correspondances où tous les patterns matchent
        """
        matches = []
        
        # Pour l'implémentation initiale, on vérifie simplement que tous les patterns
        # sont présents quelque part dans le fichier
        all_pattern_matches = []
        
        for pattern_config in patterns:
            if 'pattern' in pattern_config:
                pattern_matches = self._match_single_pattern(pattern_config['pattern'], ast)
                all_pattern_matches.append(pattern_matches)
        
        # Si tous les patterns ont au moins une correspondance, on considère la règle comme matchée
        if all_pattern_matches and all(matches for matches in all_pattern_matches):
            # Pour simplifier, on retourne la première correspondance de chaque pattern
            combined_match = {
                "line": all_pattern_matches[0][0]["line"],
                "column": all_pattern_matches[0][0]["column"],
                "snippet": all_pattern_matches[0][0]["snippet"],
                "variables": {},
                "node_type": "patterns_and",
                "node_text": "Multiple patterns matched"
            }
            
            # Combiner les variables de tous les patterns
            for pattern_matches in all_pattern_matches:
                for match in pattern_matches:
                    combined_match["variables"].update(match.get("variables", {}))
            
            matches.append(combined_match)
        
        return matches
    
    def _match_patterns_or(self, patterns: List[Dict[str, Any]], ast: CerberusNode) -> List[Dict[str, Any]]:
        """
        Applique une logique OR sur plusieurs patterns.
        
        Au moins un des patterns doit être trouvé.
        
        Args:
            patterns: Liste des patterns à matcher avec logique OR
            ast: CerberusNode racine
            
        Returns:
            Liste de toutes les correspondances trouvées pour n'importe quel pattern
        """
        matches = []
        
        for pattern_config in patterns:
            if 'pattern' in pattern_config:
                pattern_matches = self._match_single_pattern(pattern_config['pattern'], ast)
                matches.extend(pattern_matches)
        
        return matches
    
    def get_all_rules(self) -> Dict[str, Rule]:
        """
        Retourne toutes les règles chargées.
        
        Returns:
            Dict[str, Rule]: Toutes les règles indexées par ID
        """
        return self.rules.copy()