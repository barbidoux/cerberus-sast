"""
Cerberus-SAST : Moteur d'analyse de sécurité statique modulaire
"""

__version__ = "1.0.0"
__author__ = "Cerberus Team"

# Importations principales pour faciliter l'utilisation
from cerberus.core.engine import CerberusEngine
from cerberus.plugins.base import LanguagePlugin

__all__ = ["CerberusEngine", "LanguagePlugin", "__version__"]