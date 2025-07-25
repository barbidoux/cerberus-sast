"""
Plugin C pour Cerberus-SAST.

Implémentation de référence d'un plugin de langage.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List
from importlib import resources

from cerberus.plugins.base import LanguagePlugin


logger = logging.getLogger(__name__)


class CPlugin(LanguagePlugin):
    """
    Plugin pour l'analyse de code C/C++.
    """
    
    def __init__(self):
        """Initialise le plugin C."""
        super().__init__()
        self._tree_sitter_language = None
    
    @property
    def name(self) -> str:
        """Retourne le nom du langage."""
        return "c"
    
    @property
    def version(self) -> str:
        """Retourne la version du plugin."""
        return "1.0.0"
    
    @property
    def supported_extensions(self) -> List[str]:
        """Retourne les extensions supportées."""
        return [".c", ".h", ".cc", ".cpp", ".hpp", ".cxx"]
    
    def initialize(self, config: Dict[str, Any]) -> None:
        """
        Initialise le plugin avec sa configuration.
        
        Args:
            config: Configuration spécifique au plugin C
        """
        self._config = config
        logger.info(f"Plugin C initialisé avec config: {config}")
        
        # Valider la configuration
        self.validate_config(config)
    
    def get_tree_sitter_language(self) -> Any:
        """
        Retourne l'objet Language de tree-sitter pour C.
        
        Returns:
            Language: Objet Language pour le parsing C
        """
        if self._tree_sitter_language is None:
            try:
                import tree_sitter_c as tsc
                from tree_sitter import Language
                
                # Créer l'objet Language
                C_LANGUAGE = Language(tsc.language(), "c")
                self._tree_sitter_language = C_LANGUAGE
                
            except ImportError as e:
                logger.error("tree-sitter-c n'est pas installé")
                raise ImportError(
                    "Le plugin C nécessite tree-sitter-c. "
                    "Installez-le avec: pip install tree-sitter-c"
                ) from e
        
        return self._tree_sitter_language
    
    def get_rule_paths(self) -> List[Path]:
        """
        Retourne les chemins vers les fichiers de règles.
        
        Returns:
            List[Path]: Chemins des fichiers de règles YAML
        """
        rule_paths = []
        
        try:
            # Obtenir le chemin du plugin actuel
            plugin_dir = Path(__file__).parent
            rules_dir = plugin_dir / 'rules'
            
            if rules_dir.exists():
                for rule_file in rules_dir.glob('*.yml'):
                    rule_paths.append(rule_file)
                logger.info(f"Chargement de {len(rule_paths)} fichiers de règles depuis {rules_dir}")
            else:
                logger.warning(f"Répertoire de règles non trouvé: {rules_dir}")
                
        except Exception as e:
            logger.error(f"Erreur lors du chargement des règles: {e}")
        
        # Ajouter les règles personnalisées depuis la config
        custom_rules = self._config.get('custom_rules', [])
        for custom_rule in custom_rules:
            rule_path = Path(custom_rule)
            if rule_path.exists():
                rule_paths.append(rule_path)
            else:
                logger.warning(f"Règle personnalisée non trouvée: {custom_rule}")
        
        logger.debug(f"Chemins de règles finaux: {rule_paths}")
        return rule_paths
    
    def get_taint_models(self) -> Dict[str, Any]:
        """
        Retourne les modèles de taint pour C.
        
        Returns:
            Dict: Modèles de sources, sinks et sanitizers
        """
        return {
            "sources": [
                # Entrées utilisateur
                {"pattern": "getenv($VAR)"},
                {"pattern": "argv[$INDEX]"},
                {"pattern": "fgets($BUF, $SIZE, stdin)"},
                {"pattern": "scanf($FORMAT, ...)"},
                {"pattern": "gets($BUF)"},  # Dangereux par nature
                
                # Réseau
                {"pattern": "recv($SOCKET, $BUF, $SIZE, $FLAGS)"},
                {"pattern": "recvfrom($SOCKET, $BUF, $SIZE, $FLAGS, ...)"},
                {"pattern": "read($FD, $BUF, $SIZE)"},
            ],
            "sinks": [
                # Exécution de commandes
                {"pattern": "system($CMD)"},
                {"pattern": "popen($CMD, $MODE)"},
                {"pattern": "execl($PATH, ...)"},
                {"pattern": "execv($PATH, $ARGV)"},
                {"pattern": "execve($PATH, $ARGV, $ENVP)"},
                
                # Buffer operations dangereuses
                {"pattern": "strcpy($DEST, $SRC)"},
                {"pattern": "strcat($DEST, $SRC)"},
                {"pattern": "sprintf($DEST, $FORMAT, ...)"},
                {"pattern": "vsprintf($DEST, $FORMAT, $ARGS)"},
                
                # Injection SQL (si utilisation de libs C SQL)
                {"pattern": "mysql_query($CONN, $QUERY)"},
                {"pattern": "sqlite3_exec($DB, $SQL, ...)"},
            ],
            "sanitizers": [
                # Validation de taille
                {"pattern": "strncpy($DEST, $SRC, $SIZE)"},
                {"pattern": "strncat($DEST, $SRC, $SIZE)"},
                {"pattern": "snprintf($DEST, $SIZE, $FORMAT, ...)"},
                
                # Libération mémoire
                {"pattern": "free($PTR)"},
                
                # Validation d'entrée
                {"pattern": "strlen($STR)"},
                {"pattern": "strnlen($STR, $MAX)"},
            ],
            "propagators": [
                # Copie de données
                {"from": "$SRC", "to": "$DEST", "pattern": "memcpy($DEST, $SRC, $SIZE)"},
                {"from": "$SRC", "to": "$DEST", "pattern": "memmove($DEST, $SRC, $SIZE)"},
                {"from": "$SRC", "to": "return", "pattern": "return $SRC"},
            ]
        }
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Valide la configuration du plugin.
        
        Args:
            config: Configuration à valider
            
        Returns:
            bool: True si valide
            
        Raises:
            ValueError: Si la configuration est invalide
        """
        # Vérifier les options spécifiques au C
        c_standard = config.get('c_standard', 'c11')
        valid_standards = ['c89', 'c90', 'c99', 'c11', 'c17', 'c18']
        
        if c_standard not in valid_standards:
            raise ValueError(
                f"Standard C invalide: {c_standard}. "
                f"Doit être l'un de: {valid_standards}"
            )
        
        return True