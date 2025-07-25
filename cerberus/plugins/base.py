"""
Interface abstraite pour les plugins de langage Cerberus-SAST.

Cette classe définit le contrat que chaque plugin doit respecter pour
s'intégrer dans l'écosystème Cerberus.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from pathlib import Path


class LanguagePlugin(ABC):
    """
    Contrat que chaque plugin de langage pour Cerberus-SAST doit respecter.
    """

    def __init__(self):
        """Initialise le plugin."""
        self._config: Dict[str, Any] = {}

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Retourne le nom canonique du langage (ex: 'c', 'python').
        
        Returns:
            str: Identifiant unique du langage en minuscules
        """
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        """
        Retourne la version du plugin.
        
        Returns:
            str: Version au format semver (ex: "1.0.0")
        """
        ...

    @property
    @abstractmethod
    def supported_extensions(self) -> List[str]:
        """
        Retourne la liste des extensions de fichiers supportées.
        
        Returns:
            List[str]: Extensions avec le point (ex: [".c", ".h"])
        """
        ...

    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> None:
        """
        Initialise le plugin avec sa section de configuration
        provenant de .cerberus.yml.
        
        Args:
            config: Configuration spécifique au plugin
        """
        ...

    @abstractmethod
    def get_tree_sitter_language(self) -> Any:
        """
        Retourne l'objet 'Language' de tree-sitter pour ce langage,
        nécessaire au parsing.
        
        Returns:
            Language: Objet Language de tree-sitter
            
        Raises:
            ImportError: Si la grammaire tree-sitter n'est pas installée
        """
        ...

    @abstractmethod
    def get_rule_paths(self) -> List[Path]:
        """
        Retourne une liste de chemins vers les fichiers de règles YAML
        fournis par le plugin.
        
        Returns:
            List[Path]: Chemins absolus vers les fichiers de règles
        """
        ...

    @abstractmethod
    def get_taint_models(self) -> Dict[str, Any]:
        """
        Retourne les modèles de taint (sources, sinks, sanitizers)
        spécifiques à ce langage et à ses frameworks.
        
        Returns:
            Dict contenant:
                - sources: Liste des patterns de sources de données non fiables
                - sinks: Liste des fonctions sensibles
                - sanitizers: Liste des fonctions de nettoyage
                - propagators: Règles de propagation (optionnel)
        """
        ...

    def get_custom_analyzers(self) -> Dict[str, Any]:
        """
        Retourne des analyseurs personnalisés pour ce langage (optionnel).
        
        Returns:
            Dict[str, Any]: Mapping nom -> classe d'analyseur
        """
        return {}

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Valide la configuration du plugin.
        
        Args:
            config: Configuration à valider
            
        Returns:
            bool: True si la configuration est valide
            
        Raises:
            ValueError: Si la configuration est invalide
        """
        return True