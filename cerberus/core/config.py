"""
Module de gestion de la configuration Cerberus-SAST.

Gère le chargement et la validation du fichier .cerberus.yml
"""

import os
import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from pydantic import BaseModel, Field, validator


class RulesetConfig(BaseModel):
    """Configuration d'un ensemble de règles."""
    enabled: bool = True
    severity_threshold: Optional[str] = None
    
    @validator('severity_threshold')
    def validate_severity(cls, v):
        if v and v not in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            raise ValueError(f"Sévérité invalide: {v}")
        return v


class PluginConfig(BaseModel):
    """Configuration spécifique à un plugin."""
    enabled: bool = True
    rulesets: Dict[str, RulesetConfig] = Field(default_factory=dict)
    custom_rules: List[Path] = Field(default_factory=list)
    options: Dict[str, Any] = Field(default_factory=dict)


class ScanConfig(BaseModel):
    """Configuration générale du scan."""
    exclude_paths: List[str] = Field(default_factory=list)
    include_paths: List[str] = Field(default_factory=lambda: ["**/*"])
    fail_on_severity: str = "HIGH"
    max_file_size_mb: int = 10
    parallel_workers: Optional[int] = None
    cache_enabled: bool = True
    
    @validator('fail_on_severity')
    def validate_fail_severity(cls, v):
        if v not in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'NONE']:
            raise ValueError(f"Sévérité fail_on invalide: {v}")
        return v


class CerberusConfig(BaseModel):
    """Configuration principale de Cerberus-SAST."""
    version: str = "1.0"
    scan: ScanConfig = Field(default_factory=ScanConfig)
    plugins: Dict[str, PluginConfig] = Field(default_factory=dict)
    reporting: Dict[str, Any] = Field(default_factory=dict)
    
    @classmethod
    def from_file(cls, config_path: Path) -> "CerberusConfig":
        """
        Charge la configuration depuis un fichier YAML.
        
        Args:
            config_path: Chemin vers le fichier .cerberus.yml
            
        Returns:
            CerberusConfig: Configuration chargée et validée
            
        Raises:
            FileNotFoundError: Si le fichier n'existe pas
            ValueError: Si la configuration est invalide
        """
        if not config_path.exists():
            raise FileNotFoundError(f"Fichier de configuration non trouvé: {config_path}")
            
        with open(config_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f) or {}
            
        return cls(**data)
    
    @classmethod
    def discover(cls, start_path: Path) -> Optional["CerberusConfig"]:
        """
        Découvre automatiquement le fichier .cerberus.yml en remontant
        l'arborescence depuis le chemin donné.
        
        Args:
            start_path: Chemin de départ pour la recherche
            
        Returns:
            Optional[CerberusConfig]: Configuration si trouvée, None sinon
        """
        current = start_path.resolve()
        
        while current != current.parent:
            config_file = current / ".cerberus.yml"
            if config_file.exists():
                return cls.from_file(config_file)
            current = current.parent
            
        return None
    
    @classmethod
    def default(cls) -> "CerberusConfig":
        """
        Retourne une configuration par défaut.
        
        Returns:
            CerberusConfig: Configuration avec les valeurs par défaut
        """
        return cls()
    
    def get_plugin_config(self, plugin_name: str) -> PluginConfig:
        """
        Retourne la configuration d'un plugin spécifique.
        
        Args:
            plugin_name: Nom du plugin
            
        Returns:
            PluginConfig: Configuration du plugin
        """
        if plugin_name not in self.plugins:
            self.plugins[plugin_name] = PluginConfig()
        return self.plugins[plugin_name]
    
    def is_path_excluded(self, path: Path) -> bool:
        """
        Vérifie si un chemin doit être exclu du scan en utilisant des patterns fnmatch.
        
        Cette méthode supporte les patterns glob standards :
        - * : correspond à n'importe quelle séquence de caractères
        - ? : correspond à un caractère unique
        - [seq] : correspond à n'importe quel caractère dans seq
        - **/ : correspond récursivement aux répertoires
        
        Args:
            path: Chemin à vérifier
            
        Returns:
            bool: True si le chemin doit être exclu
        """
        if not self.scan.exclude_paths:
            return False
        
        # Normaliser le chemin pour la comparaison
        normalized_path = path.as_posix()
        
        # Aussi tester le chemin relatif et absolu
        paths_to_test = [
            normalized_path,
            str(path),
            path.name,  # Nom du fichier/dossier seulement
        ]
        
        # Si c'est un chemin absolu, ajouter la version relative
        if path.is_absolute():
            try:
                relative_path = path.relative_to(Path.cwd())
                paths_to_test.append(relative_path.as_posix())
                paths_to_test.append(str(relative_path))
            except ValueError:
                # Impossible de calculer le chemin relatif
                pass
        
        for pattern in self.scan.exclude_paths:
            # Gérer les patterns avec ** (récursifs)
            if '**' in pattern:
                # Convertir le pattern ** en pattern fnmatch
                fnmatch_pattern = pattern.replace('**/', '*/')
                for test_path in paths_to_test:
                    if fnmatch.fnmatch(test_path, fnmatch_pattern):
                        return True
                
                # Test spécial pour les patterns récursifs
                pattern_parts = pattern.split('**')
                if len(pattern_parts) == 2:
                    prefix, suffix = pattern_parts
                    for test_path in paths_to_test:
                        if (test_path.startswith(prefix.rstrip('/')) and 
                            test_path.endswith(suffix.lstrip('/'))):
                            return True
            else:
                # Pattern standard fnmatch
                for test_path in paths_to_test:
                    if fnmatch.fnmatch(test_path, pattern):
                        return True
                    
                    # Test aussi sur le chemin complet avec séparateurs normalisés
                    if fnmatch.fnmatch(test_path.replace('\\', '/'), pattern):
                        return True
        
        return False
    
    def is_path_included(self, path: Path) -> bool:
        """
        Vérifie si un chemin est inclus dans le scan selon les patterns d'inclusion.
        
        Args:
            path: Chemin à vérifier
            
        Returns:
            bool: True si le chemin doit être inclus
        """
        if not self.scan.include_paths:
            return True  # Inclure par défaut si aucun pattern
        
        # Normaliser le chemin pour la comparaison
        normalized_path = path.as_posix()
        
        # Chemins à tester
        paths_to_test = [
            normalized_path,
            str(path),
            path.name,
        ]
        
        # Si c'est un chemin absolu, ajouter la version relative
        if path.is_absolute():
            try:
                relative_path = path.relative_to(Path.cwd())
                paths_to_test.append(relative_path.as_posix())
                paths_to_test.append(str(relative_path))
            except ValueError:
                pass
        
        for pattern in self.scan.include_paths:
            # Gérer les patterns avec ** (récursifs)
            if '**' in pattern:
                fnmatch_pattern = pattern.replace('**/', '*/')
                for test_path in paths_to_test:
                    if fnmatch.fnmatch(test_path, fnmatch_pattern):
                        return True
                
                # Test spécial pour les patterns récursifs
                pattern_parts = pattern.split('**')
                if len(pattern_parts) == 2:
                    prefix, suffix = pattern_parts
                    for test_path in paths_to_test:
                        if (test_path.startswith(prefix.rstrip('/')) and 
                            test_path.endswith(suffix.lstrip('/'))):
                            return True
            else:
                # Pattern standard fnmatch
                for test_path in paths_to_test:
                    if fnmatch.fnmatch(test_path, pattern):
                        return True
                    
                    # Test aussi sur le chemin complet avec séparateurs normalisés
                    if fnmatch.fnmatch(test_path.replace('\\', '/'), pattern):
                        return True
        
        return False
    
    def should_scan_path(self, path: Path) -> bool:
        """
        Détermine si un chemin doit être scanné en tenant compte 
        des patterns d'inclusion et d'exclusion.
        
        Args:
            path: Chemin à vérifier
            
        Returns:
            bool: True si le chemin doit être scanné
        """
        # D'abord vérifier si le chemin est exclu
        if self.is_path_excluded(path):
            return False
        
        # Ensuite vérifier si le chemin est inclus
        return self.is_path_included(path)