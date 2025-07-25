"""
Configuration centralisée du logging pour Cerberus-SAST.
"""

import logging
import sys
from typing import Optional
from rich.logging import RichHandler


def setup_logging(level: str = "INFO", log_file: Optional[str] = None):
    """
    Configure le système de logging pour Cerberus.
    
    Args:
        level: Niveau de logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Fichier de log optionnel
    """
    # Configuration du format
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    
    # Handlers
    handlers = []
    
    # Handler console avec Rich pour un affichage amélioré
    console_handler = RichHandler(
        rich_tracebacks=True,
        show_time=True,
        show_path=False
    )
    console_handler.setLevel(level)
    handlers.append(console_handler)
    
    # Handler fichier si spécifié
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(logging.Formatter(log_format, datefmt=date_format))
        file_handler.setLevel(logging.DEBUG)  # Toujours DEBUG dans les fichiers
        handlers.append(file_handler)
    
    # Configuration du logger racine
    logging.basicConfig(
        level=level,
        handlers=handlers,
        format="%(message)s",  # Rich gère son propre format
        datefmt=date_format
    )
    
    # Ajuster les niveaux de certains loggers tiers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    
    # Logger de démarrage
    logger = logging.getLogger(__name__)
    logger.debug(f"Logging configuré au niveau {level}")


def get_logger(name: str) -> logging.Logger:
    """
    Retourne un logger configuré pour un module.
    
    Args:
        name: Nom du module (généralement __name__)
        
    Returns:
        logging.Logger: Logger configuré
    """
    return logging.getLogger(name)