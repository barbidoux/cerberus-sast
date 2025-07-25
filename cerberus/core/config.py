"""
Module de gestion de la configuration Cerberus-SAST.

Gère le chargement et la validation du fichier .cerberus.yml
"""

import os
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
        Vérifie si un chemin doit être exclu du scan.
        
        Args:
            path: Chemin à vérifier
            
        Returns:
            bool: True si le chemin doit être exclu
        """
        path_str = str(path)
        for pattern in self.scan.exclude_paths:
            if pattern in path_str:
                return True
        return False