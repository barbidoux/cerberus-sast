"""
Système de cache pour Cerberus-SAST.

Ce module gère le cache des résultats de scan pour éviter de retraiter
les fichiers inchangés et améliorer les performances.
"""

import json
import hashlib
import logging
import pickle
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta

from cerberus.models.finding import Finding


logger = logging.getLogger(__name__)


class CacheManager:
    """
    Gestionnaire de cache pour les résultats de scan.
    
    Le cache utilise un hash SHA-256 du contenu des fichiers pour déterminer
    si un fichier a été modifié depuis le dernier scan.
    """
    
    def __init__(self, cache_dir: Optional[Path] = None, max_age_days: int = 30):
        """
        Initialise le gestionnaire de cache.
        
        Args:
            cache_dir: Répertoire de cache (défaut: .cerberus_cache)
            max_age_days: Âge maximum des entrées de cache en jours
        """
        self.cache_dir = cache_dir or Path(".cerberus_cache")
        self.max_age_days = max_age_days
        
        # Créer le répertoire de cache s'il n'existe pas
        self.cache_dir.mkdir(exist_ok=True)
        
        # Sous-répertoires pour organiser le cache
        self.findings_dir = self.cache_dir / "findings"
        self.ast_dir = self.cache_dir / "ast"
        self.metadata_dir = self.cache_dir / "metadata"
        
        for subdir in [self.findings_dir, self.ast_dir, self.metadata_dir]:
            subdir.mkdir(exist_ok=True)
        
        logger.debug(f"Cache initialisé dans: {self.cache_dir}")
    
    def get_file_hash(self, file_path: Path) -> str:
        """
        Calcule le hash SHA-256 du contenu d'un fichier.
        
        Args:
            file_path: Chemin du fichier
            
        Returns:
            Hash SHA-256 en hexadécimal
        """
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                # Lire par chunks pour les gros fichiers
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.warning(f"Impossible de calculer le hash de {file_path}: {e}")
            return ""
    
    def get_cache_key(self, file_path: Path, plugin_name: str, rules_version: str = "1.0") -> str:
        """
        Génère une clé de cache pour un fichier et un plugin.
        
        Args:
            file_path: Chemin du fichier
            plugin_name: Nom du plugin utilisé
            rules_version: Version des règles
            
        Returns:
            Clé de cache unique
        """
        file_hash = self.get_file_hash(file_path)
        key_elements = [
            str(file_path.resolve()),
            file_hash,
            plugin_name,
            rules_version
        ]
        
        key_string = "|".join(key_elements)
        cache_key = hashlib.sha256(key_string.encode('utf-8')).hexdigest()[:16]
        
        return cache_key
    
    def is_file_cached(self, file_path: Path, plugin_name: str, rules_version: str = "1.0") -> bool:
        """
        Vérifie si un fichier est présent dans le cache et à jour.
        
        Args:
            file_path: Chemin du fichier
            plugin_name: Nom du plugin
            rules_version: Version des règles
            
        Returns:
            True si le fichier est en cache et à jour
        """
        cache_key = self.get_cache_key(file_path, plugin_name, rules_version)
        findings_cache_file = self.findings_dir / f"{cache_key}.json"
        metadata_cache_file = self.metadata_dir / f"{cache_key}.json"
        
        # Vérifier que les fichiers de cache existent
        if not (findings_cache_file.exists() and metadata_cache_file.exists()):
            return False
        
        try:
            # Vérifier l'âge du cache
            cache_age = datetime.now() - datetime.fromtimestamp(findings_cache_file.stat().st_mtime)
            if cache_age > timedelta(days=self.max_age_days):
                logger.debug(f"Cache expiré pour {file_path}")
                return False
            
            # Vérifier que le fichier source n'a pas changé
            with open(metadata_cache_file, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
            
            current_hash = self.get_file_hash(file_path)
            cached_hash = metadata.get('file_hash', '')
            
            if current_hash != cached_hash:
                logger.debug(f"Hash différent pour {file_path} (cached: {cached_hash[:8]}, current: {current_hash[:8]})")
                return False
            
            logger.debug(f"Cache valide pour {file_path}")
            return True
            
        except Exception as e:
            logger.warning(f"Erreur lors de la vérification du cache pour {file_path}: {e}")
            return False
    
    def get_cached_findings(self, file_path: Path, plugin_name: str, rules_version: str = "1.0") -> Optional[List[Finding]]:
        """
        Récupère les findings mis en cache pour un fichier.
        
        Args:
            file_path: Chemin du fichier
            plugin_name: Nom du plugin
            rules_version: Version des règles
            
        Returns:
            Liste des findings ou None si non trouvé
        """
        if not self.is_file_cached(file_path, plugin_name, rules_version):
            return None
        
        cache_key = self.get_cache_key(file_path, plugin_name, rules_version)
        findings_cache_file = self.findings_dir / f"{cache_key}.json"
        
        try:
            with open(findings_cache_file, 'r', encoding='utf-8') as f:
                findings_data = json.load(f)
            
            # Reconstruire les objets Finding
            findings = []
            for finding_dict in findings_data.get('findings', []):
                try:
                    finding = Finding(**finding_dict)
                    findings.append(finding)
                except Exception as e:
                    logger.warning(f"Impossible de reconstruire le finding depuis le cache: {e}")
                    continue
            
            logger.debug(f"Cache hit: {len(findings)} findings pour {file_path}")
            return findings
            
        except Exception as e:
            logger.error(f"Erreur lors de la lecture du cache pour {file_path}: {e}")
            return None
    
    def cache_findings(self, file_path: Path, plugin_name: str, findings: List[Finding], 
                      rules_version: str = "1.0", ast_data: Optional[Any] = None) -> bool:
        """
        Met en cache les findings pour un fichier.
        
        Args:
            file_path: Chemin du fichier
            plugin_name: Nom du plugin
            findings: Findings à mettre en cache
            rules_version: Version des règles
            ast_data: Données AST optionnelles
            
        Returns:
            True si la mise en cache a réussi
        """
        try:
            cache_key = self.get_cache_key(file_path, plugin_name, rules_version)
            findings_cache_file = self.findings_dir / f"{cache_key}.json"
            metadata_cache_file = self.metadata_dir / f"{cache_key}.json"
            
            # Sérialiser les findings
            findings_data = {
                "version": "1.0",
                "cached_at": datetime.now().isoformat(),
                "file_path": str(file_path.resolve()),
                "plugin_name": plugin_name,
                "rules_version": rules_version,
                "findings": [finding.dict() for finding in findings]
            }
            
            # Métadonnées pour validation
            metadata = {
                "file_path": str(file_path.resolve()),
                "file_hash": self.get_file_hash(file_path),
                "file_size": file_path.stat().st_size,
                "file_mtime": file_path.stat().st_mtime,
                "plugin_name": plugin_name,
                "rules_version": rules_version,
                "findings_count": len(findings),
                "cached_at": datetime.now().isoformat()
            }
            
            # Écrire les fichiers de cache
            with open(findings_cache_file, 'w', encoding='utf-8') as f:
                json.dump(findings_data, f, indent=2, ensure_ascii=False)
            
            with open(metadata_cache_file, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
            
            # Cache AST si fourni (utilise pickle pour préserver la structure)
            if ast_data is not None:
                ast_cache_file = self.ast_dir / f"{cache_key}.pkl"
                try:
                    with open(ast_cache_file, 'wb') as f:
                        pickle.dump(ast_data, f)
                except Exception as e:
                    logger.warning(f"Impossible de mettre en cache l'AST: {e}")
            
            logger.debug(f"Cache mis à jour pour {file_path}: {len(findings)} findings")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de la mise en cache pour {file_path}: {e}")
            return False
    
    def get_cached_ast(self, file_path: Path, plugin_name: str, rules_version: str = "1.0") -> Optional[Any]:
        """
        Récupère l'AST mis en cache pour un fichier.
        
        Args:
            file_path: Chemin du fichier
            plugin_name: Nom du plugin
            rules_version: Version des règles
            
        Returns:
            AST ou None si non trouvé
        """
        if not self.is_file_cached(file_path, plugin_name, rules_version):
            return None
        
        cache_key = self.get_cache_key(file_path, plugin_name, rules_version)
        ast_cache_file = self.ast_dir / f"{cache_key}.pkl"
        
        if not ast_cache_file.exists():
            return None
        
        try:
            with open(ast_cache_file, 'rb') as f:
                ast_data = pickle.load(f)
            
            logger.debug(f"AST récupéré du cache pour {file_path}")
            return ast_data
            
        except Exception as e:
            logger.warning(f"Erreur lors de la lecture de l'AST en cache pour {file_path}: {e}")
            return None
    
    def clear_cache(self, max_age_days: Optional[int] = None) -> Tuple[int, int]:
        """
        Nettoie le cache en supprimant les entrées expirées.
        
        Args:
            max_age_days: Âge maximum à conserver (utilise self.max_age_days si None)
            
        Returns:
            Tuple (entrées supprimées, entrées conservées)
        """
        max_age = max_age_days or self.max_age_days
        cutoff_time = datetime.now() - timedelta(days=max_age)
        
        removed_count = 0
        kept_count = 0
        
        # Nettoyer tous les sous-répertoires
        for subdir in [self.findings_dir, self.ast_dir, self.metadata_dir]:
            for cache_file in subdir.glob("*"):
                try:
                    file_mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
                    if file_mtime < cutoff_time:
                        cache_file.unlink()
                        removed_count += 1
                        logger.debug(f"Cache expiré supprimé: {cache_file}")
                    else:
                        kept_count += 1
                except Exception as e:
                    logger.warning(f"Erreur lors de la suppression de {cache_file}: {e}")
        
        logger.info(f"Nettoyage du cache: {removed_count} entrées supprimées, {kept_count} conservées")
        return removed_count, kept_count
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Retourne les statistiques du cache.
        
        Returns:
            Dictionnaire avec les statistiques
        """
        stats = {
            "cache_dir": str(self.cache_dir),
            "max_age_days": self.max_age_days,
            "subdirs": {}
        }
        
        total_size = 0
        total_files = 0
        
        for subdir_name, subdir_path in [
            ("findings", self.findings_dir),
            ("ast", self.ast_dir),
            ("metadata", self.metadata_dir)
        ]:
            files = list(subdir_path.glob("*"))
            subdir_size = sum(f.stat().st_size for f in files if f.is_file())
            
            stats["subdirs"][subdir_name] = {
                "files": len(files),
                "size": subdir_size
            }
            
            total_size += subdir_size
            total_files += len(files)
        
        stats["total_files"] = total_files
        stats["total_size"] = total_size
        stats["total_size_mb"] = round(total_size / (1024 * 1024), 2)
        
        return stats
    
    def invalidate_file_cache(self, file_path: Path, plugin_name: str, rules_version: str = "1.0") -> bool:
        """
        Invalide le cache pour un fichier spécifique.
        
        Args:
            file_path: Chemin du fichier
            plugin_name: Nom du plugin
            rules_version: Version des règles
            
        Returns:
            True si l'invalidation a réussi
        """
        try:
            cache_key = self.get_cache_key(file_path, plugin_name, rules_version)
            
            cache_files = [
                self.findings_dir / f"{cache_key}.json",
                self.ast_dir / f"{cache_key}.pkl",
                self.metadata_dir / f"{cache_key}.json"
            ]
            
            removed_count = 0
            for cache_file in cache_files:
                if cache_file.exists():
                    cache_file.unlink()
                    removed_count += 1
            
            logger.debug(f"Cache invalidé pour {file_path}: {removed_count} fichiers supprimés")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de l'invalidation du cache pour {file_path}: {e}")
            return False