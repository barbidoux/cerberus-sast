#!/usr/bin/env python3
"""
Script de test pour valider l'implémentation de la Phase 2 de Cerberus-SAST.

Teste les nouvelles commandes CLI, le système de cache et la gestion des baselines.
"""

import sys
import json
import tempfile
import logging
from pathlib import Path

# Ajouter le répertoire racine au PATH pour les imports
sys.path.insert(0, str(Path(__file__).parent))

from cerberus.core.cache import CacheManager
from cerberus.core.baseline import BaselineManager
from cerberus.models.finding import Finding, Severity, Location

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def test_cache_system():
    """Test le système de cache."""
    logger.info("=== Test Système de Cache ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        cache_dir = Path(temp_dir) / "test_cache"
        cache_manager = CacheManager(cache_dir)
        
        # Créer un fichier de test
        test_file = Path(temp_dir) / "test.c"
        test_content = """
#include <stdio.h>
int main() {
    printf("Hello World");
    return 0;
}
"""
        test_file.write_text(test_content)
        
        # Test 1: Hash de fichier
        file_hash = cache_manager.get_file_hash(test_file)
        assert len(file_hash) == 64, "Le hash SHA-256 doit faire 64 caractères"
        logger.info(f"✓ Hash calculé: {file_hash[:16]}...")
        
        # Test 2: Clé de cache
        cache_key = cache_manager.get_cache_key(test_file, "c", "1.0")
        assert len(cache_key) == 16, "La clé de cache doit faire 16 caractères"
        logger.info(f"✓ Clé de cache: {cache_key}")
        
        # Test 3: Fichier non en cache initialement
        assert not cache_manager.is_file_cached(test_file, "c", "1.0")
        logger.info("✓ Fichier correctement détecté comme non en cache")
        
        # Test 4: Mise en cache des findings
        test_findings = [
            Finding(
                rule_id="test-rule-1",
                message="Test finding",
                severity=Severity.HIGH,
                location=Location(
                    file_path=str(test_file),
                    line=3,
                    column=5
                )
            )
        ]
        
        success = cache_manager.cache_findings(test_file, "c", test_findings, "1.0")
        assert success, "La mise en cache doit réussir"
        logger.info("✓ Findings mis en cache")
        
        # Test 5: Fichier maintenant en cache
        assert cache_manager.is_file_cached(test_file, "c", "1.0")
        logger.info("✓ Fichier correctement détecté comme en cache")
        
        # Test 6: Récupération des findings
        cached_findings = cache_manager.get_cached_findings(test_file, "c", "1.0")
        assert cached_findings is not None, "Les findings doivent être récupérés"
        assert len(cached_findings) == 1, "Un finding doit être récupéré"
        assert cached_findings[0].rule_id == "test-rule-1"
        logger.info("✓ Findings récupérés du cache")
        
        # Test 7: Statistiques du cache
        stats = cache_manager.get_cache_stats()
        assert stats['total_files'] > 0, "Le cache doit contenir des fichiers"
        logger.info(f"✓ Stats cache: {stats['total_files']} fichiers, {stats['total_size_mb']} MB")
        
        return True


def test_baseline_system():
    """Test le système de baseline."""
    logger.info("=== Test Système de Baseline ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        baseline_path = Path(temp_dir) / "test_baseline.json"
        baseline_manager = BaselineManager(baseline_path)
        
        # Test 1: Création de findings de test
        test_findings = [
            Finding(
                rule_id="rule-1",
                message="Buffer overflow detected",
                severity=Severity.HIGH,
                location=Location(
                    file_path="/test/file1.c",
                    line=10,
                    column=5
                ),
                variables={"DEST": "buffer", "SRC": "input"}
            ),
            Finding(
                rule_id="rule-2",
                message="Format string vulnerability",
                severity=Severity.MEDIUM,
                location=Location(
                    file_path="/test/file2.c",
                    line=25,
                    column=12
                )
            )
        ]
        
        # Test 2: Création de baseline
        scan_path = Path("/test")
        baseline_data = baseline_manager.create_baseline(test_findings, scan_path)
        
        assert baseline_data['total_findings'] == 2
        assert len(baseline_data['findings']) == 2
        logger.info("✓ Baseline créée avec 2 findings")
        
        # Test 3: Sauvegarde de baseline
        saved_path = baseline_manager.save_baseline(baseline_data)
        assert saved_path.exists()
        logger.info(f"✓ Baseline sauvegardée: {saved_path}")
        
        # Test 4: Chargement de baseline
        loaded_baseline = baseline_manager.load_baseline()
        assert loaded_baseline is not None
        assert loaded_baseline['total_findings'] == 2
        logger.info("✓ Baseline chargée depuis le disque")
        
        # Test 5: Filtrage avec baseline (aucun nouveau finding)
        filtered_findings = baseline_manager.filter_new_findings(test_findings)
        assert len(filtered_findings) == 0
        logger.info("✓ Filtrage baseline: aucun nouveau finding détecté")
        
        # Test 6: Ajout d'un nouveau finding
        new_finding = Finding(
            rule_id="rule-3",
            message="New vulnerability",
            severity=Severity.CRITICAL,
            location=Location(
                file_path="/test/file3.c",
                line=15,
                column=8
            )
        )
        
        all_findings = test_findings + [new_finding]
        filtered_findings = baseline_manager.filter_new_findings(all_findings)
        assert len(filtered_findings) == 1
        assert filtered_findings[0].rule_id == "rule-3"
        logger.info("✓ Filtrage baseline: nouveau finding détecté")
        
        # Test 7: Statistiques de baseline
        stats = baseline_manager.get_baseline_stats()
        assert stats['total_findings'] == 2
        assert stats['by_severity']['HIGH'] == 1
        assert stats['by_severity']['MEDIUM'] == 1
        logger.info("✓ Statistiques baseline correctes")
        
        return True


def test_cli_commands():
    """Test les commandes CLI (tests basiques)."""
    logger.info("=== Test Commandes CLI ===")
    
    try:
        # Import des commandes
        from cerberus.cli.commands import ExitCode, _calculate_exit_code
        
        # Test 1: Calcul des codes de sortie
        results_no_findings = {"findings": []}
        exit_code = _calculate_exit_code(results_no_findings, "HIGH")
        assert exit_code == ExitCode.SUCCESS
        logger.info("✓ Code de sortie SUCCESS pour aucun finding")
        
        # Test 2: Findings non bloquants
        results_low_findings = {
            "findings": [
                {"severity": "LOW", "rule_id": "test-rule"}
            ]
        }
        exit_code = _calculate_exit_code(results_low_findings, "HIGH")
        assert exit_code == ExitCode.SUCCESS
        logger.info("✓ Code de sortie SUCCESS pour findings non bloquants")
        
        # Test 3: Findings bloquants
        results_high_findings = {
            "findings": [
                {"severity": "HIGH", "rule_id": "test-rule"}
            ]
        }
        exit_code = _calculate_exit_code(results_high_findings, "HIGH")
        assert exit_code == ExitCode.FINDINGS_DETECTED
        logger.info("✓ Code de sortie FINDINGS_DETECTED pour findings bloquants")
        
        # Test 4: Seuil NONE
        exit_code = _calculate_exit_code(results_high_findings, "NONE")
        assert exit_code == ExitCode.SUCCESS
        logger.info("✓ Code de sortie SUCCESS avec seuil NONE")
        
        return True
        
    except Exception as e:
        logger.error(f"Erreur lors du test CLI: {e}")
        return False


def test_config_exclusions():
    """Test la logique d'exclusion améliorée."""
    logger.info("=== Test Logique d'Exclusion ===")
    
    try:
        from cerberus.core.config import CerberusConfig, ScanConfig
        
        # Configuration de test avec patterns d'exclusion
        config = CerberusConfig(
            scan=ScanConfig(
                exclude_paths=[
                    "*.tmp",
                    "build/**",
                    "node_modules/*",
                    "*.log"
                ]
            )
        )
        
        # Test 1: Fichier temporaire exclu
        assert config.is_path_excluded(Path("temp.tmp"))
        logger.info("✓ Fichier .tmp correctement exclu")
        
        # Test 2: Répertoire build exclu
        assert config.is_path_excluded(Path("build/output/file.c"))
        logger.info("✓ Répertoire build/** correctement exclu")
        
        # Test 3: node_modules exclu
        assert config.is_path_excluded(Path("node_modules/package/index.js"))
        logger.info("✓ node_modules/* correctement exclu")
        
        # Test 4: Fichier log exclu
        assert config.is_path_excluded(Path("application.log"))
        logger.info("✓ Fichier .log correctement exclu")
        
        # Test 5: Fichier source non exclu
        assert not config.is_path_excluded(Path("src/main.c"))
        logger.info("✓ Fichier source non exclu")
        
        # Test 6: should_scan_path
        assert config.should_scan_path(Path("src/main.c"))
        assert not config.should_scan_path(Path("build/temp.o"))
        logger.info("✓ should_scan_path fonctionne correctement")
        
        return True
        
    except Exception as e:
        logger.error(f"Erreur lors du test d'exclusion: {e}")
        return False


def main():
    """Fonction principale de test."""
    logger.info("Démarrage des tests de la Phase 2 de Cerberus-SAST")
    
    tests = [
        ("Système de Cache", test_cache_system),
        ("Système de Baseline", test_baseline_system),
        ("Commandes CLI", test_cli_commands),
        ("Logique d'Exclusion", test_config_exclusions),
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        logger.info(f"\n{'='*50}")
        logger.info(f"EXÉCUTION: {test_name}")
        logger.info(f"{'='*50}")
        
        try:
            result = test_func()
            results[test_name] = result
            status = "✓ SUCCÈS" if result else "✗ ÉCHEC"
            logger.info(f"{test_name}: {status}")
            
        except Exception as e:
            results[test_name] = False
            logger.error(f"{test_name}: ✗ ERREUR - {e}")
            import traceback
            logger.debug(traceback.format_exc())
    
    # Résumé final
    logger.info(f"\n{'='*50}")
    logger.info("RÉSUMÉ DES TESTS")
    logger.info(f"{'='*50}")
    
    passed = sum(1 for result in results.values() if result)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✓ PASSÉ" if result else "✗ ÉCHEC"
        logger.info(f"{test_name}: {status}")
    
    logger.info(f"\nRésultat final: {passed}/{total} tests passés")
    
    if passed == total:
        logger.info("🎉 Tous les tests sont passés! Phase 2 implémentée avec succès.")
        return 0
    else:
        logger.error("❌ Certains tests ont échoué. Vérifiez les erreurs ci-dessus.")
        return 1


if __name__ == "__main__":
    sys.exit(main())