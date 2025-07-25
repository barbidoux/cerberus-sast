"""
Encapsulation des nœuds Tree-sitter avec des fonctionnalités étendues.

Ce module fournit la classe CerberusNode qui enrichit les nœuds Tree-sitter
avec des métadonnées et des méthodes utilitaires pour le pattern matching.
"""

import logging
from typing import Optional, List, Dict, Any, Iterator, Union
from pathlib import Path

try:
    import tree_sitter
except ImportError:
    tree_sitter = None


logger = logging.getLogger(__name__)


class CerberusNode:
    """
    Wrapper autour d'un nœud Tree-sitter avec des fonctionnalités étendues.
    
    Cette classe enrichit les nœuds Tree-sitter avec:
    - Navigation parent/enfant améliorée
    - Métadonnées de localisation (chemin, ligne, colonne)
    - Méthodes utilitaires pour le pattern matching
    - Cache des requêtes fréquentes
    """
    
    def __init__(self, 
                 tree_sitter_node: 'tree_sitter.Node',
                 source_code: str,
                 file_path: Path,
                 parent: Optional['CerberusNode'] = None):
        """
        Initialise un CerberusNode.
        
        Args:
            tree_sitter_node: Nœud Tree-sitter original
            source_code: Code source complet du fichier
            file_path: Chemin du fichier source
            parent: Nœud parent CerberusNode (optionnel)
        """
        self._node = tree_sitter_node
        self._source_code = source_code
        self._file_path = file_path
        self._parent = parent
        self._children_cache: Optional[List['CerberusNode']] = None
        self._text_cache: Optional[str] = None
    
    # Propriétés de base du nœud Tree-sitter
    @property
    def type(self) -> str:
        """Type du nœud (identifier, function_call, etc.)."""
        return self._node.type
    
    @property
    def start_point(self) -> tuple:
        """Point de début (ligne, colonne) - indexé à partir de 0."""
        return self._node.start_point
    
    @property
    def end_point(self) -> tuple:
        """Point de fin (ligne, colonne) - indexé à partir de 0."""
        return self._node.end_point
    
    @property
    def start_byte(self) -> int:
        """Offset de début en bytes."""
        return self._node.start_byte
    
    @property
    def end_byte(self) -> int:
        """Offset de fin en bytes."""
        return self._node.end_byte
    
    @property
    def is_named(self) -> bool:
        """Indique si le nœud est nommé (vs token)."""
        return self._node.is_named
    
    @property
    def is_missing(self) -> bool:
        """Indique si le nœud est manquant (erreur de parsing)."""
        return self._node.is_missing
    
    @property
    def has_error(self) -> bool:
        """Indique si le nœud contient une erreur de parsing."""
        return self._node.has_error
    
    # Propriétés étendues Cerberus
    @property
    def file_path(self) -> Path:
        """Chemin du fichier source."""
        return self._file_path
    
    @property
    def parent(self) -> Optional['CerberusNode']:
        """Nœud parent."""
        return self._parent
    
    @property
    def line(self) -> int:
        """Numéro de ligne (indexé à partir de 1)."""
        return self.start_point[0] + 1
    
    @property
    def column(self) -> int:
        """Numéro de colonne (indexé à partir de 1)."""
        return self.start_point[1] + 1
    
    @property
    def text(self) -> str:
        """Texte source correspondant au nœud."""
        if self._text_cache is None:
            self._text_cache = self._source_code[self.start_byte:self.end_byte]
        return self._text_cache
    
    @property
    def children(self) -> List['CerberusNode']:
        """Liste des enfants sous forme de CerberusNode."""
        if self._children_cache is None:
            self._children_cache = [
                CerberusNode(child, self._source_code, self._file_path, self)
                for child in self._node.children
            ]
        return self._children_cache
    
    @property
    def named_children(self) -> List['CerberusNode']:
        """Liste des enfants nommés uniquement."""
        return [child for child in self.children if child.is_named]
    
    def get_child_by_field_name(self, field_name: str) -> Optional['CerberusNode']:
        """
        Récupère un enfant par nom de champ.
        
        Args:
            field_name: Nom du champ (ex: 'function', 'arguments')
            
        Returns:
            CerberusNode correspondant ou None
        """
        ts_child = self._node.child_by_field_name(field_name)
        if ts_child:
            return CerberusNode(ts_child, self._source_code, self._file_path, self)
        return None
    
    def get_children_by_type(self, node_type: str) -> List['CerberusNode']:
        """
        Récupère tous les enfants d'un type donné.
        
        Args:
            node_type: Type de nœud recherché
            
        Returns:
            Liste des enfants correspondants
        """
        return [child for child in self.children if child.type == node_type]
    
    def find_descendants_by_type(self, node_type: str) -> List['CerberusNode']:
        """
        Trouve tous les descendants d'un type donné (recherche récursive).
        
        Args:
            node_type: Type de nœud recherché
            
        Returns:
            Liste de tous les descendants correspondants
        """
        result = []
        if self.type == node_type:
            result.append(self)
        
        for child in self.children:
            result.extend(child.find_descendants_by_type(node_type))
        
        return result
    
    def find_ancestor_by_type(self, node_type: str) -> Optional['CerberusNode']:
        """
        Trouve le premier ancêtre d'un type donné.
        
        Args:
            node_type: Type de nœud recherché
            
        Returns:
            Premier ancêtre correspondant ou None
        """
        current = self.parent
        while current:
            if current.type == node_type:
                return current
            current = current.parent
        return None
    
    def matches_pattern(self, pattern: str, variables: Optional[Dict[str, Any]] = None) -> bool:
        """
        Vérifie si le nœud correspond à un pattern donné.
        
        Cette méthode implémente un matching basique de patterns
        de type 'strcpy($DEST, $SRC)'.
        
        Args:
            pattern: Pattern à matcher
            variables: Dict pour capturer les variables du pattern
            
        Returns:
            True si le pattern correspond
        """
        if variables is None:
            variables = {}
        
        return self._match_pattern_node(pattern.strip(), variables)
    
    def _match_pattern_node(self, pattern: str, variables: Dict[str, Any]) -> bool:
        """
        Implémentation interne du matching de pattern.
        
        Args:
            pattern: Pattern à matcher
            variables: Dict pour capturer les variables
            
        Returns:
            True si le pattern correspond
        """
        # Pattern matching basique pour les fonctions
        if '(' in pattern and ')' in pattern:
            return self._match_function_call_pattern(pattern, variables)
        
        # Pattern simple pour les identifiants
        if pattern.startswith('$'):
            # Variable - capture le texte du nœud
            var_name = pattern[1:]
            variables[var_name] = self.text
            return True
        
        # Match exact du texte
        return self.text == pattern
    
    def _match_function_call_pattern(self, pattern: str, variables: Dict[str, Any]) -> bool:
        """
        Matche un pattern d'appel de fonction.
        
        Args:
            pattern: Pattern type 'strcpy($DEST, $SRC)'
            variables: Dict pour capturer les variables
            
        Returns:
            True si le pattern correspond
        """
        # Vérifier que c'est bien un appel de fonction
        if self.type != 'call_expression':
            return False
        
        # Extraire le nom de fonction du pattern
        func_start = pattern.find('(')
        if func_start == -1:
            return False
        
        expected_func_name = pattern[:func_start].strip()
        
        # Récupérer le nom de fonction du nœud
        function_node = self.get_child_by_field_name('function')
        if not function_node or function_node.text != expected_func_name:
            return False
        
        # Extraire les arguments du pattern
        args_part = pattern[func_start + 1:pattern.rfind(')')].strip()
        if not args_part:
            return True  # Pas d'arguments attendus
        
        pattern_args = [arg.strip() for arg in args_part.split(',')]
        
        # Récupérer les arguments du nœud
        arguments_node = self.get_child_by_field_name('arguments')
        if not arguments_node:
            return len(pattern_args) == 0
        
        actual_args = [child for child in arguments_node.children 
                      if child.type != ',' and child.type != '(' and child.type != ')']
        
        # Vérifier le nombre d'arguments (sauf pour '...')
        if '...' not in pattern_args and len(actual_args) != len(pattern_args):
            return False
        
        # Matcher chaque argument
        for i, pattern_arg in enumerate(pattern_args):
            if pattern_arg == '...':
                # Wildcard - accepte le reste des arguments
                break
            
            if i >= len(actual_args):
                return False
            
            if not actual_args[i]._match_pattern_node(pattern_arg, variables):
                return False
        
        return True
    
    def get_context_snippet(self, lines_before: int = 2, lines_after: int = 2) -> str:
        """
        Récupère un extrait de code avec contexte autour du nœud.
        
        Args:
            lines_before: Nombre de lignes avant
            lines_after: Nombre de lignes après
            
        Returns:
            Extrait de code avec contexte
        """
        source_lines = self._source_code.split('\n')
        start_line = max(0, self.start_point[0] - lines_before)
        end_line = min(len(source_lines), self.end_point[0] + lines_after + 1)
        
        context_lines = []
        for i in range(start_line, end_line):
            line_num = i + 1
            marker = ">>> " if self.start_point[0] <= i <= self.end_point[0] else "    "
            context_lines.append(f"{marker}{line_num:4}: {source_lines[i]}")
        
        return '\n'.join(context_lines)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convertit le nœud en dictionnaire pour sérialisation.
        
        Returns:
            Représentation dict du nœud
        """
        return {
            'type': self.type,
            'text': self.text,
            'start_point': self.start_point,
            'end_point': self.end_point,
            'line': self.line,
            'column': self.column,
            'file_path': str(self.file_path),
            'is_named': self.is_named,
            'is_missing': self.is_missing,
            'has_error': self.has_error,
            'children_count': len(self.children)
        }
    
    def __repr__(self) -> str:
        """Représentation string du nœud."""
        return f"CerberusNode(type='{self.type}', text='{self.text[:50]}...', line={self.line})"
    
    def __str__(self) -> str:
        """String du nœud."""
        return f"{self.type}@{self.line}:{self.column}: {self.text[:100]}"