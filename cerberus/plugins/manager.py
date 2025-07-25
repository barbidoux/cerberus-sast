"""
Gestionnaire de plugins pour Cerberus-SAST.

Ce module gère la découverte, le chargement et la gestion des plugins.
"""

import logging
import traceback
from pathlib import Path
from typing import Dict, Optional, List, Any
import importlib.metadata

from cerberus.plugins.base import LanguagePlugin


logger = logging.getLogger(__name__)


class PluginLoadingError(Exception):
    """Exception spécifique pour les erreurs de chargement de plugins."""
    pass


class PluginManager:
    """
    Gestionnaire centralisé pour tous les plugins Cerberus avec gestion d'erreurs robuste.
    """
    
    def __init__(self):
        """Initialise le gestionnaire de plugins."""
        self.plugins: Dict[str, LanguagePlugin] = {}
        self.extension_map: Dict[str, str] = {}  # extension -> plugin_name
        self.plugin_errors: Dict[str, str] = {}  # plugin_name -> error_message
        self._discover_plugins()
    
    def _discover_plugins(self):
        """
        Découvre automatiquement les plugins installés via entry_points avec gestion d'erreurs détaillée.
        """
        logger.info("Découverte des plugins...")
        
        try:
            # Recherche des entry points dans le groupe 'cerberus.plugins'
            entry_points = importlib.metadata.entry_points()
            
            if hasattr(entry_points, 'select'):  # Python 3.10+
                plugin_entries = entry_points.select(group='cerberus.plugins')
            else:  # Python < 3.10
                plugin_entries = entry_points.get('cerberus.plugins', [])
            
            if not plugin_entries:
                logger.warning("Aucun plugin trouvé dans le groupe 'cerberus.plugins'")
                return
                
        except Exception as e:
            error_msg = f"Erreur lors de la découverte des entry points: {e}"
            logger.error(error_msg)
            self.plugin_errors["__discovery__"] = error_msg
            return
        
        for entry_point in plugin_entries:
            plugin_name = entry_point.name
            
            try:
                # Étape 1: Charger la classe du plugin
                try:
                    plugin_class = entry_point.load()
                except ImportError as e:
                    error_msg = f"Impossible d'importer le plugin '{plugin_name}': {e}"
                    if "tree_sitter" in str(e).lower():
                        error_msg += "\n  Suggestion: Installez tree-sitter avec 'pip install tree-sitter'"
                    elif "missing" in str(e).lower() or "module" in str(e).lower():
                        error_msg += f"\n  Suggestion: Vérifiez que toutes les dépendances du plugin sont installées"
                    logger.error(error_msg)
                    self.plugin_errors[plugin_name] = error_msg
                    continue
                except AttributeError as e:
                    error_msg = f"Plugin '{plugin_name}' mal configuré: {e}"
                    error_msg += f"\n  Suggestion: Vérifiez la définition de l'entry point dans setup.py/pyproject.toml"
                    logger.error(error_msg)
                    self.plugin_errors[plugin_name] = error_msg
                    continue
                
                # Étape 2: Valider que c'est une classe
                if not isinstance(plugin_class, type):
                    error_msg = f"L'entry point '{plugin_name}' ne pointe pas vers une classe"
                    logger.error(error_msg)
                    self.plugin_errors[plugin_name] = error_msg
                    continue
                
                # Étape 3: Instancier le plugin
                try:
                    plugin_instance = plugin_class()
                except TypeError as e:
                    error_msg = f"Impossible d'instancier le plugin '{plugin_name}': {e}"
                    error_msg += f"\n  Suggestion: Vérifiez que le constructeur du plugin n'a pas de paramètres obligatoires"
                    logger.error(error_msg)
                    self.plugin_errors[plugin_name] = error_msg
                    continue
                except Exception as e:
                    error_msg = f"Erreur lors de l'initialisation du plugin '{plugin_name}': {e}"
                    logger.error(error_msg)
                    self.plugin_errors[plugin_name] = error_msg
                    continue
                
                # Étape 4: Valider que c'est bien un LanguagePlugin
                if not isinstance(plugin_instance, LanguagePlugin):
                    error_msg = f"Le plugin '{plugin_name}' n'hérite pas de LanguagePlugin"
                    error_msg += f"\n  Type trouvé: {type(plugin_instance)}"
                    error_msg += f"\n  Suggestion: Assurez-vous que votre plugin hérite de cerberus.plugins.base.LanguagePlugin"
                    logger.error(error_msg)
                    self.plugin_errors[plugin_name] = error_msg
                    continue
                
                # Étape 5: Valider les propriétés requises
                try:
                    plugin_real_name = plugin_instance.name
                    extensions = plugin_instance.supported_extensions
                    version = plugin_instance.version
                    
                    if not plugin_real_name or not isinstance(plugin_real_name, str):
                        raise ValueError("La propriété 'name' doit être une chaîne non vide")
                    
                    if not extensions or not isinstance(extensions, list):
                        raise ValueError("La propriété 'supported_extensions' doit être une liste non vide")
                    
                    if not all(ext.startswith('.') for ext in extensions):
                        raise ValueError("Toutes les extensions doivent commencer par '.'")
                        
                except Exception as e:
                    error_msg = f"Configuration invalide pour le plugin '{plugin_name}': {e}"
                    error_msg += f"\n  Suggestion: Vérifiez l'implémentation des propriétés name, supported_extensions et version"
                    logger.error(error_msg)
                    self.plugin_errors[plugin_name] = error_msg
                    continue
                
                # Étape 6: Vérifier la méthode get_tree_sitter_language
                try:
                    # Test basique de la méthode (sans l'exécuter car elle peut nécessiter des dépendances)
                    if not hasattr(plugin_instance, 'get_tree_sitter_language'):
                        raise AttributeError("Méthode 'get_tree_sitter_language' manquante")
                    
                    if not callable(getattr(plugin_instance, 'get_tree_sitter_language')):
                        raise AttributeError("'get_tree_sitter_language' n'est pas callable")
                        
                except Exception as e:
                    error_msg = f"Interface invalide pour le plugin '{plugin_name}': {e}"
                    error_msg += f"\n  Suggestion: Implémentez toutes les méthodes abstraites de LanguagePlugin"
                    logger.error(error_msg)
                    self.plugin_errors[plugin_name] = error_msg
                    continue
                
                # Étape 7: Enregistrer le plugin avec succès
                self.plugins[plugin_real_name] = plugin_instance
                
                # Mapper les extensions (avec vérification de conflits)
                for ext in extensions:
                    if ext in self.extension_map:
                        existing_plugin = self.extension_map[ext]
                        logger.warning(f"Conflit d'extension '{ext}': plugin '{plugin_real_name}' remplace '{existing_plugin}'")
                    self.extension_map[ext] = plugin_real_name
                
                logger.info(f"✓ Plugin '{plugin_real_name}' chargé avec succès")
                logger.debug(f"  - Version: {version}")
                logger.debug(f"  - Extensions: {extensions}")
                
                # Nettoyer l'erreur précédente si elle existait
                if plugin_name in self.plugin_errors:
                    del self.plugin_errors[plugin_name]
                
            except Exception as e:
                # Fallback pour toute erreur non gérée
                error_msg = f"Erreur inattendue lors du chargement du plugin '{plugin_name}': {e}"
                error_msg += f"\n  Trace complète:\n{traceback.format_exc()}"
                logger.error(error_msg)
                self.plugin_errors[plugin_name] = error_msg
        
        # Résumé final
        loaded_count = len(self.plugins)
        error_count = len(self.plugin_errors)
        total_extensions = len(self.extension_map)
        
        if loaded_count > 0:
            logger.info(f"✓ {loaded_count} plugin(s) chargé(s) avec succès, {total_extensions} extensions supportées")
        
        if error_count > 0:
            logger.warning(f"⚠ {error_count} plugin(s) en échec")
            
        if loaded_count == 0:
            logger.error("❌ Aucun plugin chargé! Cerberus ne pourra analyser aucun fichier.")
    
    def load_plugin(self, plugin_name: str) -> LanguagePlugin:
        """
        Charge un plugin spécifique avec gestion d'erreurs améliorée.
        
        Args:
            plugin_name: Nom du plugin à charger
            
        Returns:
            LanguagePlugin: Instance du plugin
            
        Raises:
            PluginLoadingError: Si le plugin n'existe pas ou a des erreurs
        """
        if plugin_name not in self.plugins:
            available_plugins = list(self.plugins.keys())
            error_msg = f"Plugin '{plugin_name}' non trouvé."
            
            if available_plugins:
                error_msg += f" Plugins disponibles: {available_plugins}"
            else:
                error_msg += " Aucun plugin disponible."
            
            # Si le plugin a des erreurs de chargement, les inclure
            if plugin_name in self.plugin_errors:
                error_msg += f"\n\nErreur de chargement pour '{plugin_name}':\n{self.plugin_errors[plugin_name]}"
            
            raise PluginLoadingError(error_msg)
        
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
    
    def get_plugin_errors(self) -> Dict[str, str]:
        """
        Retourne les erreurs de chargement des plugins.
        
        Returns:
            Dict[str, str]: Dictionnaire plugin_name -> error_message
        """
        return self.plugin_errors.copy()
    
    def has_plugin_errors(self) -> bool:
        """
        Vérifie s'il y a des erreurs de chargement de plugins.
        
        Returns:
            bool: True s'il y a des erreurs
        """
        return len(self.plugin_errors) > 0
    
    def get_diagnostic_info(self) -> Dict[str, Any]:
        """
        Retourne des informations de diagnostic détaillées sur les plugins.
        
        Returns:
            Dict: Informations de diagnostic
        """
        return {
            "loaded_plugins": {
                name: {
                    "version": plugin.version,
                    "extensions": plugin.supported_extensions,
                    "rules_count": len(plugin.get_rule_paths())
                }
                for name, plugin in self.plugins.items()
            },
            "plugin_errors": self.plugin_errors,
            "extension_mapping": self.extension_map,
            "summary": {
                "loaded_count": len(self.plugins),
                "error_count": len(self.plugin_errors),
                "total_extensions": len(self.extension_map)
            }
        }
    
    def validate_plugin_dependencies(self, plugin_name: str) -> Dict[str, Any]:
        """
        Valide les dépendances d'un plugin spécifique.
        
        Args:
            plugin_name: Nom du plugin à valider
            
        Returns:
            Dict: Résultats de validation
        """
        validation_result = {
            "plugin_name": plugin_name,
            "exists": plugin_name in self.plugins,
            "has_errors": plugin_name in self.plugin_errors,
            "dependencies": {},
            "methods": {},
            "recommendations": []
        }
        
        if plugin_name not in self.plugins:
            if plugin_name in self.plugin_errors:
                validation_result["error"] = self.plugin_errors[plugin_name]
            else:
                validation_result["error"] = "Plugin non trouvé"
            return validation_result
        
        plugin = self.plugins[plugin_name]
        
        # Vérifier les méthodes requises
        required_methods = [
            'get_tree_sitter_language',
            'get_rule_paths',
            'initialize',
            'validate_config'
        ]
        
        for method_name in required_methods:
            validation_result["methods"][method_name] = {
                "exists": hasattr(plugin, method_name),
                "callable": hasattr(plugin, method_name) and callable(getattr(plugin, method_name))
            }
        
        # Tester la méthode Tree-sitter
        try:
            ts_lang = plugin.get_tree_sitter_language()
            validation_result["dependencies"]["tree_sitter"] = {
                "available": ts_lang is not None,
                "type": str(type(ts_lang)) if ts_lang else None
            }
        except ImportError as e:
            validation_result["dependencies"]["tree_sitter"] = {
                "available": False,
                "error": str(e)
            }
            validation_result["recommendations"].append(
                "Installez tree-sitter et les bindings pour ce langage"
            )
        except Exception as e:
            validation_result["dependencies"]["tree_sitter"] = {
                "available": False,
                "error": f"Erreur inattendue: {e}"
            }
        
        # Vérifier les règles
        try:
            rule_paths = plugin.get_rule_paths()
            validation_result["rules"] = {
                "count": len(rule_paths),
                "paths": [str(p) for p in rule_paths],
                "existing": [str(p) for p in rule_paths if p.exists()]
            }
            
            missing_rules = len(rule_paths) - len(validation_result["rules"]["existing"])
            if missing_rules > 0:
                validation_result["recommendations"].append(
                    f"{missing_rules} fichier(s) de règles manquant(s)"
                )
                
        except Exception as e:
            validation_result["rules"] = {"error": str(e)}
            validation_result["recommendations"].append("Erreur lors du chargement des règles")
        
        return validation_result