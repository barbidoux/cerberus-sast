"""
Tests unitaires pour le module de configuration.
"""

import pytest
from pathlib import Path
import tempfile
import yaml

from cerberus.core.config import CerberusConfig, ScanConfig, PluginConfig


class TestCerberusConfig:
    """Tests pour la classe CerberusConfig."""
    
    def test_default_config(self):
        """Test de la configuration par défaut."""
        config = CerberusConfig.default()
        
        assert config.version == "1.0"
        assert config.scan.fail_on_severity == "HIGH"
        assert config.scan.cache_enabled is True
        assert config.scan.max_file_size_mb == 10
    
    def test_load_from_file(self, tmp_path):
        """Test du chargement depuis un fichier."""
        config_data = {
            "version": "1.0",
            "scan": {
                "fail_on_severity": "MEDIUM",
                "exclude_paths": ["**/test/**"],
                "cache_enabled": False
            },
            "plugins": {
                "c": {
                    "enabled": True,
                    "options": {
                        "c_standard": "c11"
                    }
                }
            }
        }
        
        config_file = tmp_path / ".cerberus.yml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        config = CerberusConfig.from_file(config_file)
        
        assert config.scan.fail_on_severity == "MEDIUM"
        assert config.scan.exclude_paths == ["**/test/**"]
        assert config.scan.cache_enabled is False
        assert "c" in config.plugins
        assert config.plugins["c"].enabled is True
        assert config.plugins["c"].options["c_standard"] == "c11"
    
    def test_invalid_severity(self):
        """Test de validation de la sévérité."""
        with pytest.raises(ValueError, match="Sévérité fail_on invalide"):
            ScanConfig(fail_on_severity="INVALID")
    
    def test_discover_config(self, tmp_path):
        """Test de la découverte automatique de configuration."""
        # Créer une structure de répertoires
        project_root = tmp_path / "project"
        subdir = project_root / "src" / "module"
        subdir.mkdir(parents=True)
        
        # Placer le fichier de config à la racine
        config_file = project_root / ".cerberus.yml"
        with open(config_file, 'w') as f:
            yaml.dump({"version": "1.0"}, f)
        
        # Tester la découverte depuis un sous-répertoire
        config = CerberusConfig.discover(subdir)
        assert config is not None
        assert config.version == "1.0"
    
    def test_discover_config_not_found(self, tmp_path):
        """Test quand aucune configuration n'est trouvée."""
        config = CerberusConfig.discover(tmp_path)
        assert config is None
    
    def test_is_path_excluded(self):
        """Test de l'exclusion de chemins."""
        config = CerberusConfig(
            scan=ScanConfig(exclude_paths=["**/test/**", "build/", "*.pyc"])
        )
        
        assert config.is_path_excluded(Path("src/test/test_file.py"))
        assert config.is_path_excluded(Path("build/output.o"))
        assert config.is_path_excluded(Path("module.pyc"))
        assert not config.is_path_excluded(Path("src/main.py"))
    
    def test_get_plugin_config(self):
        """Test de récupération de configuration de plugin."""
        config = CerberusConfig()
        
        # Plugin non configuré - doit créer une config par défaut
        c_config = config.get_plugin_config("c")
        assert isinstance(c_config, PluginConfig)
        assert c_config.enabled is True
        
        # Plugin configuré
        config.plugins["python"] = PluginConfig(enabled=False)
        python_config = config.get_plugin_config("python")
        assert python_config.enabled is False


class TestPluginConfig:
    """Tests pour la classe PluginConfig."""
    
    def test_default_values(self):
        """Test des valeurs par défaut."""
        config = PluginConfig()
        
        assert config.enabled is True
        assert config.rulesets == {}
        assert config.custom_rules == []
        assert config.options == {}
    
    def test_ruleset_validation(self):
        """Test de la validation des rulesets."""
        from cerberus.core.config import RulesetConfig
        
        # Sévérité valide
        ruleset = RulesetConfig(severity_threshold="HIGH")
        assert ruleset.severity_threshold == "HIGH"
        
        # Sévérité invalide
        with pytest.raises(ValueError, match="Sévérité invalide"):
            RulesetConfig(severity_threshold="INVALID")