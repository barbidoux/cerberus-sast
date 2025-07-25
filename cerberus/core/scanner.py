"""
Module de découverte et de filtrage des fichiers pour Cerberus-SAST.
"""

import logging
import os
from pathlib import Path
from typing import List, Set
import fnmatch

from cerberus.core.config import CerberusConfig


logger = logging.getLogger(__name__)


class FileScanner:
    """
    Gère la découverte et le filtrage des fichiers à analyser.
    """
    
    def __init__(self, config: CerberusConfig):
        """
        Initialise le scanner avec la configuration.
        
        Args:
            config: Configuration Cerberus
        """
        self.config = config
        self.max_file_size = config.scan.max_file_size_mb * 1024 * 1024  # Conversion en bytes
    
    def discover_files(self, root_path: Path, diff_aware: bool = False) -> List[Path]:
        """
        Découvre tous les fichiers à analyser dans le chemin donné.
        
        Args:
            root_path: Chemin racine pour la recherche
            diff_aware: Si True, ne retourne que les fichiers modifiés (Git)
            
        Returns:
            List[Path]: Liste des fichiers à analyser
        """
        if diff_aware:
            return self._get_modified_files(root_path)
        
        return self._get_all_files(root_path)
    
    def _get_all_files(self, root_path: Path) -> List[Path]:
        """
        Récupère tous les fichiers éligibles dans le chemin.
        
        Args:
            root_path: Chemin racine
            
        Returns:
            List[Path]: Fichiers trouvés
        """
        files = []
        
        # Patterns à toujours exclure
        default_excludes = {
            ".git", ".svn", ".hg",  # VCS
            "__pycache__", ".pytest_cache",  # Python
            "node_modules", "bower_components",  # JS
            "target", "build", "dist",  # Build directories
            ".cerberus_cache"  # Notre cache
        }
        
        for dirpath, dirnames, filenames in os.walk(root_path):
            current_dir = Path(dirpath)
            
            # Filtrer les répertoires à exclure
            dirnames[:] = [
                d for d in dirnames 
                if d not in default_excludes and not self._is_excluded(current_dir / d)
            ]
            
            # Traiter les fichiers
            for filename in filenames:
                file_path = current_dir / filename
                
                if self._should_scan_file(file_path):
                    files.append(file_path)
        
        logger.info(f"Découverte terminée: {len(files)} fichiers trouvés")
        return files
    
    def _get_modified_files(self, root_path: Path) -> List[Path]:
        """
        Récupère les fichiers modifiés via Git.
        
        Args:
            root_path: Chemin racine du dépôt
            
        Returns:
            List[Path]: Fichiers modifiés
        """
        try:
            import subprocess
            
            # Vérifier qu'on est dans un dépôt Git
            result = subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                cwd=root_path,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logger.warning("Pas dans un dépôt Git, scan complet")
                return self._get_all_files(root_path)
            
            # Récupérer les fichiers modifiés
            result = subprocess.run(
                ["git", "diff", "--name-only", "--diff-filter=ACM", "HEAD"],
                cwd=root_path,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                modified_files = []
                for line in result.stdout.strip().split('\n'):
                    if line:
                        file_path = root_path / line
                        if file_path.exists() and self._should_scan_file(file_path):
                            modified_files.append(file_path)
                
                logger.info(f"Mode diff: {len(modified_files)} fichiers modifiés")
                return modified_files
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des fichiers modifiés: {e}")
        
        return self._get_all_files(root_path)
    
    def _should_scan_file(self, file_path: Path) -> bool:
        """
        Détermine si un fichier doit être analysé.
        
        Args:
            file_path: Chemin du fichier
            
        Returns:
            bool: True si le fichier doit être analysé
        """
        # Vérifier si le fichier est exclu
        if self._is_excluded(file_path):
            return False
        
        # Vérifier la taille du fichier
        try:
            if file_path.stat().st_size > self.max_file_size:
                logger.debug(f"Fichier trop volumineux ignoré: {file_path}")
                return False
        except OSError:
            return False
        
        # Ignorer les fichiers binaires courants
        binary_extensions = {
            '.exe', '.dll', '.so', '.dylib',  # Exécutables
            '.jpg', '.jpeg', '.png', '.gif', '.ico',  # Images
            '.mp3', '.mp4', '.avi', '.mov',  # Médias
            '.zip', '.tar', '.gz', '.rar',  # Archives
            '.pyc', '.pyo', '.class',  # Bytecode
            '.pdf', '.doc', '.docx'  # Documents
        }
        
        if file_path.suffix.lower() in binary_extensions:
            return False
        
        return True
    
    def _is_excluded(self, path: Path) -> bool:
        """
        Vérifie si un chemin est exclu par la configuration.
        
        Args:
            path: Chemin à vérifier
            
        Returns:
            bool: True si exclu
        """
        path_str = str(path)
        
        for pattern in self.config.scan.exclude_paths:
            # Support des wildcards
            if '*' in pattern or '?' in pattern:
                if fnmatch.fnmatch(path_str, pattern):
                    return True
            # Correspondance simple
            elif pattern in path_str:
                return True
        
        return False