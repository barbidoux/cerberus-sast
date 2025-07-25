#!/usr/bin/env python3
"""
Script de test pour valider l'implémentation de la Phase 1 de Cerberus-SAST.

Teste le parsing Tree-sitter, CerberusNode et le matching de patterns.
"""

import sys
import logging
from pathlib import Path

# Ajouter le répertoire racine au PATH pour les imports
sys.path.insert(0, str(Path(__file__).parent))

from cerberus.ast.cerberus_node import CerberusNode

# Configuration du logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def test_tree_sitter_parsing():
    """Test le parsing Tree-sitter de base."""
    logger.info("=== Test Tree-sitter parsing ===")
    
    try:
        import tree_sitter
        import tree_sitter_c as tsc
        from tree_sitter import Language
        
        # Code C simple pour test
        c_code = '''
#include <stdio.h>
#include <string.h>

int main() {
    char buffer[64];
    strcpy(buffer, "hello");
    gets(buffer);
    printf(buffer);
    return 0;
}
'''
        
        # Créer le parser
        C_LANGUAGE = Language(tsc.language(), "c")
        parser = tree_sitter.Parser()
        parser.set_language(C_LANGUAGE)
        
        # Parser le code
        tree = parser.parse(bytes(c_code, 'utf-8'))
        
        logger.info(f"AST racine: {tree.root_node.type}")
        logger.info(f"Nombre d'enfants: {len(tree.root_node.children)}")
        
        # Recherche des appels de fonction
        def find_function_calls(node, calls=None):
            if calls is None:
                calls = []
                
            if node.type == 'call_expression':
                func_node = node.child_by_field_name('function')
                if func_node:
                    calls.append(func_node.text.decode('utf-8'))
            
            for child in node.children:
                find_function_calls(child, calls)
            
            return calls
        
        function_calls = find_function_calls(tree.root_node)
        logger.info(f"Appels de fonction trouvés: {function_calls}")
        
        return True, tree, c_code
        
    except ImportError as e:
        logger.error(f"tree-sitter-c non disponible: {e}")
        return False, None, None
    except Exception as e:
        logger.error(f"Erreur lors du test Tree-sitter: {e}")
        return False, None, None


def test_cerberus_node():
    """Test la classe CerberusNode."""
    logger.info("=== Test CerberusNode ===")
    
    success, tree, c_code = test_tree_sitter_parsing()
    if not success:
        logger.error("Impossible de continuer sans Tree-sitter")
        return False
    
    try:
        # Créer un CerberusNode
        root_node = CerberusNode(
            tree_sitter_node=tree.root_node,
            source_code=c_code,
            file_path=Path("test.c")
        )
        
        logger.info(f"CerberusNode créé: {root_node}")
        logger.info(f"Nombre d'enfants: {len(root_node.children)}")
        
        # Test de recherche de descendants
        call_nodes = root_node.find_descendants_by_type('call_expression')
        logger.info(f"Appels de fonction trouvés via CerberusNode: {len(call_nodes)}")
        
        for call_node in call_nodes:
            func_node = call_node.get_child_by_field_name('function')
            if func_node:
                logger.info(f"  - {func_node.text} à la ligne {call_node.line}")
        
        return True, root_node
        
    except Exception as e:
        logger.error(f"Erreur lors du test CerberusNode: {e}")
        return False, None


def test_pattern_matching():
    """Test le matching de patterns."""
    logger.info("=== Test Pattern Matching ===")
    
    success, root_node = test_cerberus_node()
    if not success:
        logger.error("Impossible de continuer sans CerberusNode")
        return False
    
    try:
        # Test des patterns de base
        patterns_to_test = [
            "strcpy($DEST, $SRC)",
            "gets($BUF)",
            "printf($FORMAT)",
        ]
        
        for pattern in patterns_to_test:
            logger.info(f"Test du pattern: {pattern}")
            
            # Rechercher tous les nœuds correspondants
            matches_found = 0
            nodes_to_check = [root_node]
            
            while nodes_to_check:
                current_node = nodes_to_check.pop(0)
                
                variables = {}
                if current_node.matches_pattern(pattern, variables):
                    matches_found += 1
                    logger.info(f"  ✓ Correspondance trouvée à la ligne {current_node.line}")
                    logger.info(f"    Variables: {variables}")
                    logger.info(f"    Snippet: {current_node.text}")
                
                nodes_to_check.extend(current_node.children)
            
            logger.info(f"  Total: {matches_found} correspondances pour '{pattern}'")
        
        return True
        
    except Exception as e:
        logger.error(f"Erreur lors du test pattern matching: {e}")
        return False


def test_full_engine():
    """Test le moteur complet avec un fichier."""
    logger.info("=== Test Moteur Complet ===")
    
    try:
        from cerberus.core.config import CerberusConfig
        from cerberus.core.engine import CerberusEngine
        
        # Configuration minimale pour le test
        config_data = {
            "version": "1.0",
            "scan": {
                "fail_on_severity": "HIGH",
                "cache_enabled": False,
                "parallel_workers": 1
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
        
        config = CerberusConfig(**config_data)
        engine = CerberusEngine(config)
        
        # Test sur le fichier d'exemple
        vulnerable_file = Path("cerberus/examples/vulnerable.c")
        if not vulnerable_file.exists():
            logger.error(f"Fichier de test non trouvé: {vulnerable_file}")
            return False
        
        logger.info(f"Analyse du fichier: {vulnerable_file}")
        results = engine.scan(vulnerable_file)
        
        logger.info(f"Résultats de l'analyse:")
        logger.info(f"  - Fichiers scannés: {results['stats']['files_scanned']}")
        logger.info(f"  - Vulnérabilités trouvées: {results['stats']['total_findings']}")
        logger.info(f"  - Par sévérité: {results['stats']['findings_by_severity']}")
        
        if results['findings']:
            logger.info("Détail des vulnérabilités:")
            for finding in results['findings'][:5]:  # Limite aux 5 premières
                logger.info(f"  - {finding['rule_id']}: {finding['message'][:60]}...")
                logger.info(f"    Ligne {finding['line']}, Sévérité: {finding['severity']}")
        
        return True
        
    except Exception as e:
        logger.error(f"Erreur lors du test du moteur complet: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False


def main():
    """Fonction principale de test."""
    logger.info("Démarrage des tests de la Phase 1 de Cerberus-SAST")
    
    tests = [
        ("Tree-sitter parsing", test_tree_sitter_parsing),
        ("CerberusNode", test_cerberus_node),
        ("Pattern Matching", test_pattern_matching),
        ("Moteur Complet", test_full_engine),
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
        logger.info("🎉 Tous les tests sont passés! Phase 1 implémentée avec succès.")
        return 0
    else:
        logger.error("❌ Certains tests ont échoué. Vérifiez les erreurs ci-dessus.")
        return 1


if __name__ == "__main__":
    sys.exit(main())