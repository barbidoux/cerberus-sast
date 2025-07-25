"""
Gestionnaire de plugins pour Cerberus-SAST.

Ce module gère la découverte, le chargement et la gestion des plugins.
"""

import logging
from pathlib import Path
from typing import Dict, Optional, List
import importlib.metadata

from cerberus.plugins.base import LanguagePlugin


logger = logging.getLogger(__name__)


class PluginManager:
    """
    Gestionnaire centralisé pour tous les plugins Cerberus.
    """
    
    def __init__(self):
        """Initialise le gestionnaire de plugins."""
        self.plugins: Dict[str, LanguagePlugin] = {}
        self.extension_map: Dict[str, str] = {}  # extension -> plugin_name
        self._discover_plugins()
    
    def _discover_plugins(self):
        """
        Découvre automatiquement les plugins installés via entry_points.
        """
        logger.info("Découverte des plugins...")
        
        # Recherche des entry points dans le groupe 'cerberus.plugins'
        entry_points = importlib.metadata.entry_points()
        
        if hasattr(entry_points, 'select'):  # Python 3.10+
            plugin_entries = entry_points.select(group='cerberus.plugins')
        else:  # Python < 3.10
            plugin_entries = entry_points.get('cerberus.plugins', [])
        
        for entry_point in plugin_entries:
            try:
                # Charger la classe du plugin
                plugin_class = entry_point.load()
                
                # Instancier le plugin
                plugin_instance = plugin_class()
                
                # Valider que c'est bien un LanguagePlugin
                if not isinstance(plugin_instance, LanguagePlugin):
                    logger.error(f"Le plugin '{entry_point.name}' n'implémente pas LanguagePlugin")
                    continue
                
                # Enregistrer le plugin
                plugin_name = plugin_instance.name
                self.plugins[plugin_name] = plugin_instance
                
                # Mapper les extensions
                for ext in plugin_instance.supported_extensions:
                    self.extension_map[ext] = plugin_name
                
                logger.info(f"Plugin '{plugin_name}' découvert (extensions: {plugin_instance.supported_extensions})")
                
            except Exception as e:
                logger.error(f"Erreur lors du chargement du plugin '{entry_point.name}': {e}")
    
    def load_plugin(self, plugin_name: str) -> LanguagePlugin:
        """
        Charge un plugin spécifique.
        
        Args:
            plugin_name: Nom du plugin à charger
            
        Returns:
            LanguagePlugin: Instance du plugin
            
        Raises:
            ValueError: Si le plugin n'existe pas
        """
        if plugin_name not in self.plugins:
            raise ValueError(f"Plugin '{plugin_name}' non trouvé. Plugins disponibles: {list(self.plugins.keys())}")
        
        return self.plugins[plugin_name]
    
    def get_plugin_for_file(self, file_path: Path) -> Optional[LanguagePlugin]:
        """
        Détermine quel plugin utiliser pour un fichier donné.
        
        Args:
            file_path: Chemin du fichier
            
        Returns:
            Optional[LanguagePlugin]: Plugin approprié ou None
        """
        extension = file_path.suffix.lower()
        
        if extension in self.extension_map:
            plugin_name = self.extension_map[extension]
            return self.plugins[plugin_name]
        
        return None
    
    def list_plugins(self) -> List[Dict[str, any]]:
        """
        Liste tous les plugins disponibles.
        
        Returns:
            List[Dict]: Informations sur chaque plugin
        """
        plugin_info = []
        
        for name, plugin in self.plugins.items():
            info = {
                "name": name,
                "version": plugin.version,
                "extensions": plugin.supported_extensions,
                "rules_count": len(plugin.get_rule_paths())
            }
            plugin_info.append(info)
        
        return plugin_info
    
    def get_all_rule_paths(self) -> List[Path]:
        """
        Récupère tous les chemins de règles de tous les plugins.
        
        Returns:
            List[Path]: Liste de tous les chemins de règles
        """
        all_paths = []
        
        for plugin in self.plugins.values():
            all_paths.extend(plugin.get_rule_paths())
        
        return all_paths