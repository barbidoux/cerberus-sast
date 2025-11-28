"""
Symbol extractor using Tree-sitter AST.

Extracts functions, classes, methods, and other symbols from source code
across multiple programming languages.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

from cerberus.context.tree_sitter_parser import TreeSitterParser
from cerberus.models.base import SymbolType
from cerberus.models.repo_map import Symbol
from cerberus.utils.logging import ComponentLogger


class SymbolExtractor:
    """Extract code symbols from source files using Tree-sitter."""

    def __init__(self) -> None:
        """Initialize the symbol extractor."""
        self.logger = ComponentLogger("symbol_extractor")
        self.parser = TreeSitterParser()

    def extract_from_file(self, file_path: Path) -> list[Symbol]:
        """
        Extract symbols from a source file.

        Args:
            file_path: Path to the source file

        Returns:
            List of extracted symbols
        """
        language = self.parser.detect_language(file_path)
        if not language:
            return []

        tree = self.parser.parse_file(file_path)
        if not tree:
            return []

        try:
            with open(file_path, "rb") as f:
                source = f.read()
        except OSError:
            return []

        return self._extract_symbols(tree.root_node, language, file_path, source)

    def extract_from_string(
        self, code: str, language: str, file_path: Path
    ) -> list[Symbol]:
        """
        Extract symbols from source code string.

        Args:
            code: Source code string
            language: Programming language
            file_path: File path for symbol metadata

        Returns:
            List of extracted symbols
        """
        tree = self.parser.parse_string(code, language)
        if not tree:
            return []

        source = code.encode("utf-8")
        return self._extract_symbols(tree.root_node, language, file_path, source)

    def extract_imports(self, code: str, language: str) -> list[str]:
        """
        Extract import statements from source code.

        Args:
            code: Source code string
            language: Programming language

        Returns:
            List of imported module/package names
        """
        tree = self.parser.parse_string(code, language)
        if not tree:
            return []

        source = code.encode("utf-8")
        imports: list[str] = []

        if language == "python":
            imports = self._extract_python_imports(tree.root_node, source)
        elif language in ("javascript", "typescript"):
            imports = self._extract_js_imports(tree.root_node, source)

        return imports

    def extract_exports(self, code: str, language: str) -> list[str]:
        """
        Extract export statements from source code.

        Args:
            code: Source code string
            language: Programming language

        Returns:
            List of exported symbol names
        """
        tree = self.parser.parse_string(code, language)
        if not tree:
            return []

        source = code.encode("utf-8")
        exports: list[str] = []

        if language == "python":
            exports = self._extract_python_exports(tree.root_node, source)
        elif language in ("javascript", "typescript"):
            exports = self._extract_js_exports(tree.root_node, source)

        return exports

    def _extract_symbols(
        self,
        node: Any,
        language: str,
        file_path: Path,
        source: bytes,
        parent_class: Optional[str] = None,
    ) -> list[Symbol]:
        """
        Recursively extract symbols from AST node.

        Args:
            node: Tree-sitter node
            language: Programming language
            file_path: File path for symbol metadata
            source: Source code bytes
            parent_class: Parent class name if inside a class

        Returns:
            List of extracted symbols
        """
        symbols: list[Symbol] = []

        # Get extractor for language
        extractors = {
            "python": self._extract_python_symbol,
            "javascript": self._extract_js_symbol,
            "typescript": self._extract_ts_symbol,
            "c": self._extract_c_symbol,
            "cpp": self._extract_cpp_symbol,
            "java": self._extract_java_symbol,
            "go": self._extract_go_symbol,
        }

        extractor = extractors.get(language)
        if not extractor:
            return symbols

        # Check if current node is a symbol
        symbol = extractor(node, file_path, source, parent_class)
        if symbol:
            symbols.append(symbol)

        # Determine new parent class for children
        new_parent = parent_class
        if symbol and symbol.type == SymbolType.CLASS:
            new_parent = symbol.name

        # Recurse into children
        for child in node.children:
            symbols.extend(
                self._extract_symbols(child, language, file_path, source, new_parent)
            )

        return symbols

    # ========== Python Extraction ==========

    def _extract_python_symbol(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
        parent_class: Optional[str],
    ) -> Optional[Symbol]:
        """Extract Python symbol from node."""
        if node.type == "function_definition":
            return self._extract_python_function(node, file_path, source, parent_class)
        elif node.type == "class_definition":
            return self._extract_python_class(node, file_path, source)
        return None

    def _extract_python_function(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
        parent_class: Optional[str],
    ) -> Optional[Symbol]:
        """Extract Python function/method."""
        name = None
        signature = None
        docstring = None

        for child in node.children:
            if child.type == "identifier":
                name = self._get_node_text(child, source)
            elif child.type == "parameters":
                signature = self._get_node_text(child, source)
            elif child.type == "block":
                # Look for docstring in first statement
                for stmt in child.children:
                    if stmt.type == "expression_statement":
                        for expr in stmt.children:
                            if expr.type == "string":
                                docstring = self._get_node_text(expr, source)
                                # Clean up docstring
                                docstring = docstring.strip("\"'")
                                break
                        break

        if not name:
            return None

        # Determine type (method vs function)
        symbol_type = SymbolType.METHOD if parent_class else SymbolType.FUNCTION

        # Determine visibility
        visibility = "public"
        if name.startswith("__") and not name.endswith("__"):
            visibility = "private"
        elif name.startswith("_"):
            visibility = "protected"

        return Symbol(
            name=name,
            type=symbol_type,
            file_path=file_path,
            line=node.start_point[0] + 1,  # Convert to 1-indexed
            signature=signature,
            docstring=docstring,
            parent_class=parent_class,
            visibility=visibility,
        )

    def _extract_python_class(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
    ) -> Optional[Symbol]:
        """Extract Python class."""
        name = None
        docstring = None

        for child in node.children:
            if child.type == "identifier":
                name = self._get_node_text(child, source)
            elif child.type == "block":
                # Look for docstring
                for stmt in child.children:
                    if stmt.type == "expression_statement":
                        for expr in stmt.children:
                            if expr.type == "string":
                                docstring = self._get_node_text(expr, source)
                                docstring = docstring.strip("\"'")
                                break
                        break

        if not name:
            return None

        return Symbol(
            name=name,
            type=SymbolType.CLASS,
            file_path=file_path,
            line=node.start_point[0] + 1,
            docstring=docstring,
        )

    def _extract_python_imports(self, node: Any, source: bytes) -> list[str]:
        """Extract Python imports recursively."""
        imports: list[str] = []

        if node.type == "import_statement":
            for child in node.children:
                if child.type == "dotted_name":
                    imports.append(self._get_node_text(child, source))
        elif node.type == "import_from_statement":
            for child in node.children:
                if child.type == "dotted_name":
                    imports.append(self._get_node_text(child, source))
                    break  # Just get the module name

        for child in node.children:
            imports.extend(self._extract_python_imports(child, source))

        return imports

    def _extract_python_exports(self, node: Any, source: bytes) -> list[str]:
        """Extract Python __all__ exports."""
        exports: list[str] = []

        if node.type == "expression_statement":
            for child in node.children:
                if child.type == "assignment":
                    # Check if it's __all__ assignment
                    name_node = None
                    list_node = None
                    for assign_child in child.children:
                        if assign_child.type == "identifier":
                            name_node = assign_child
                        elif assign_child.type == "list":
                            list_node = assign_child

                    if name_node and list_node:
                        name = self._get_node_text(name_node, source)
                        if name == "__all__":
                            for item in list_node.children:
                                if item.type == "string":
                                    export = self._get_node_text(item, source)
                                    export = export.strip("\"'")
                                    exports.append(export)

        for child in node.children:
            exports.extend(self._extract_python_exports(child, source))

        return exports

    # ========== JavaScript/TypeScript Extraction ==========

    def _extract_js_symbol(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
        parent_class: Optional[str],
    ) -> Optional[Symbol]:
        """Extract JavaScript symbol from node."""
        if node.type == "function_declaration":
            return self._extract_js_function(node, file_path, source)
        elif node.type == "class_declaration":
            return self._extract_js_class(node, file_path, source)
        elif node.type == "method_definition":
            return self._extract_js_method(node, file_path, source, parent_class)
        elif node.type in ("lexical_declaration", "variable_declaration"):
            # Handle: const/let/var handler = (req, res) => { ... }
            return self._extract_js_arrow_function(node, file_path, source)
        elif node.type == "expression_statement":
            # Handle: module.exports.handler = ... or exports.handler = ...
            return self._extract_js_exports_assignment(node, file_path, source)
        return None

    def _extract_ts_symbol(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
        parent_class: Optional[str],
    ) -> Optional[Symbol]:
        """Extract TypeScript symbol from node."""
        # TypeScript adds interface declarations
        if node.type == "interface_declaration":
            return self._extract_ts_interface(node, file_path, source)

        # Handle export statements (export class Foo {})
        if node.type == "export_statement":
            for child in node.children:
                if child.type == "class_declaration":
                    return self._extract_js_class(child, file_path, source)
                elif child.type == "function_declaration":
                    return self._extract_js_function(child, file_path, source)
                elif child.type == "lexical_declaration":
                    return self._extract_js_arrow_function(child, file_path, source)
                # Handle decorated classes in export: export @Component class Foo
                elif child.type == "class":
                    return self._extract_ts_decorated_class(child, file_path, source)

        # Handle decorated class declarations (@Component class Foo {})
        if node.type == "class":
            return self._extract_ts_decorated_class(node, file_path, source)

        # Fall back to JavaScript extraction
        return self._extract_js_symbol(node, file_path, source, parent_class)

    def _extract_js_function(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
    ) -> Optional[Symbol]:
        """Extract JavaScript function declaration."""
        name = None
        signature = None

        for child in node.children:
            if child.type == "identifier":
                name = self._get_node_text(child, source)
            elif child.type == "formal_parameters":
                signature = self._get_node_text(child, source)

        if not name:
            return None

        return Symbol(
            name=name,
            type=SymbolType.FUNCTION,
            file_path=file_path,
            line=node.start_point[0] + 1,
            signature=signature,
        )

    def _extract_js_class(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
    ) -> Optional[Symbol]:
        """Extract JavaScript/TypeScript class declaration."""
        name = None

        for child in node.children:
            # JavaScript uses 'identifier', TypeScript uses 'type_identifier'
            if child.type in ("identifier", "type_identifier"):
                name = self._get_node_text(child, source)
                break

        if not name:
            return None

        return Symbol(
            name=name,
            type=SymbolType.CLASS,
            file_path=file_path,
            line=node.start_point[0] + 1,
        )

    def _extract_js_method(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
        parent_class: Optional[str],
    ) -> Optional[Symbol]:
        """Extract JavaScript method."""
        name = None
        signature = None

        for child in node.children:
            if child.type == "property_identifier":
                name = self._get_node_text(child, source)
            elif child.type == "formal_parameters":
                signature = self._get_node_text(child, source)

        if not name:
            return None

        return Symbol(
            name=name,
            type=SymbolType.METHOD,
            file_path=file_path,
            line=node.start_point[0] + 1,
            signature=signature,
            parent_class=parent_class,
        )

    def _extract_js_arrow_function(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
    ) -> Optional[Symbol]:
        """
        Extract arrow function from variable declaration.

        Handles patterns like:
        - const handler = (req, res) => { ... }
        - let processor = async (data) => { ... }
        - var compute = x => x * 2
        """
        # Look for variable_declarator children
        for child in node.children:
            if child.type == "variable_declarator":
                name = None
                signature = None
                is_arrow_function = False

                for var_child in child.children:
                    if var_child.type == "identifier":
                        name = self._get_node_text(var_child, source)
                    elif var_child.type == "arrow_function":
                        is_arrow_function = True
                        # Extract signature from arrow function
                        for arrow_child in var_child.children:
                            if arrow_child.type == "formal_parameters":
                                signature = self._get_node_text(arrow_child, source)
                            elif arrow_child.type == "identifier":
                                # Single param without parens: x => x * 2
                                signature = f"({self._get_node_text(arrow_child, source)})"

                if name and is_arrow_function:
                    return Symbol(
                        name=name,
                        type=SymbolType.FUNCTION,
                        file_path=file_path,
                        line=node.start_point[0] + 1,
                        signature=signature,
                    )

        return None

    def _extract_js_exports_assignment(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
    ) -> Optional[Symbol]:
        """
        Extract function from module.exports or exports assignment.

        Handles patterns like:
        - module.exports.handler = (event) => { ... }
        - exports.processRequest = async (req, res) => { ... }
        """
        for child in node.children:
            if child.type == "assignment_expression":
                name = None
                signature = None
                is_function = False

                for assign_child in child.children:
                    # Left side: member_expression like module.exports.handler
                    if assign_child.type == "member_expression":
                        # Get the last property (the function name)
                        for mem_child in assign_child.children:
                            if mem_child.type == "property_identifier":
                                potential_name = self._get_node_text(mem_child, source)
                                # Skip 'exports' itself
                                if potential_name not in ("exports", "module"):
                                    name = potential_name

                    # Right side: arrow_function or function_expression
                    elif assign_child.type == "arrow_function":
                        is_function = True
                        for arrow_child in assign_child.children:
                            if arrow_child.type == "formal_parameters":
                                signature = self._get_node_text(arrow_child, source)
                            elif arrow_child.type == "identifier":
                                signature = f"({self._get_node_text(arrow_child, source)})"

                    elif assign_child.type == "function_expression":
                        is_function = True
                        for func_child in assign_child.children:
                            if func_child.type == "formal_parameters":
                                signature = self._get_node_text(func_child, source)

                if name and is_function:
                    return Symbol(
                        name=name,
                        type=SymbolType.FUNCTION,
                        file_path=file_path,
                        line=node.start_point[0] + 1,
                        signature=signature,
                    )

        return None

    def _extract_ts_interface(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
    ) -> Optional[Symbol]:
        """Extract TypeScript interface."""
        name = None

        for child in node.children:
            if child.type == "type_identifier":
                name = self._get_node_text(child, source)
                break

        if not name:
            return None

        return Symbol(
            name=name,
            type=SymbolType.INTERFACE,
            file_path=file_path,
            line=node.start_point[0] + 1,
        )

    def _extract_ts_decorated_class(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
    ) -> Optional[Symbol]:
        """
        Extract TypeScript decorated class.

        Handles patterns like:
        - @Component({}) class Foo {}
        - @Injectable() export class Bar {}
        """
        name = None

        # Look for type_identifier (class name in TS)
        for child in node.children:
            if child.type == "type_identifier":
                name = self._get_node_text(child, source)
                break
            # Some parsers use identifier instead
            elif child.type == "identifier":
                name = self._get_node_text(child, source)
                break

        if not name:
            return None

        return Symbol(
            name=name,
            type=SymbolType.CLASS,
            file_path=file_path,
            line=node.start_point[0] + 1,
        )

    def _extract_js_imports(self, node: Any, source: bytes) -> list[str]:
        """Extract JavaScript/TypeScript imports."""
        imports: list[str] = []

        if node.type == "import_statement":
            for child in node.children:
                if child.type == "string":
                    module = self._get_node_text(child, source)
                    module = module.strip("\"'")
                    imports.append(module)
        elif node.type == "call_expression":
            # Handle require()
            for child in node.children:
                if child.type == "identifier":
                    name = self._get_node_text(child, source)
                    if name == "require":
                        for arg in node.children:
                            if arg.type == "arguments":
                                for arg_child in arg.children:
                                    if arg_child.type == "string":
                                        module = self._get_node_text(arg_child, source)
                                        module = module.strip("\"'")
                                        imports.append(module)

        for child in node.children:
            imports.extend(self._extract_js_imports(child, source))

        return imports

    def _extract_js_exports(self, node: Any, source: bytes) -> list[str]:
        """Extract JavaScript exports."""
        exports: list[str] = []

        if node.type == "export_statement":
            for child in node.children:
                if child.type == "function_declaration":
                    for sub in child.children:
                        if sub.type == "identifier":
                            exports.append(self._get_node_text(sub, source))
                            break
                elif child.type == "class_declaration":
                    for sub in child.children:
                        if sub.type == "identifier":
                            exports.append(self._get_node_text(sub, source))
                            break
                elif child.type == "lexical_declaration":
                    for sub in child.children:
                        if sub.type == "variable_declarator":
                            for var_child in sub.children:
                                if var_child.type == "identifier":
                                    exports.append(self._get_node_text(var_child, source))
                                    break

        for child in node.children:
            exports.extend(self._extract_js_exports(child, source))

        return exports

    # ========== C Extraction ==========

    def _extract_c_symbol(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
        parent_class: Optional[str],
    ) -> Optional[Symbol]:
        """Extract C symbol from node."""
        if node.type == "function_definition":
            return self._extract_c_function(node, file_path, source)
        elif node.type == "struct_specifier":
            return self._extract_c_struct(node, file_path, source)
        return None

    def _extract_c_function(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
    ) -> Optional[Symbol]:
        """Extract C function definition."""
        name = None
        signature = None

        for child in node.children:
            if child.type == "function_declarator":
                for sub in child.children:
                    if sub.type == "identifier":
                        name = self._get_node_text(sub, source)
                    elif sub.type == "parameter_list":
                        signature = self._get_node_text(sub, source)

        if not name:
            return None

        return Symbol(
            name=name,
            type=SymbolType.FUNCTION,
            file_path=file_path,
            line=node.start_point[0] + 1,
            signature=signature,
        )

    def _extract_c_struct(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
    ) -> Optional[Symbol]:
        """Extract C struct definition."""
        name = None

        for child in node.children:
            if child.type == "type_identifier":
                name = self._get_node_text(child, source)
                break

        if not name:
            return None

        return Symbol(
            name=name,
            type=SymbolType.CLASS,  # Treat struct like class
            file_path=file_path,
            line=node.start_point[0] + 1,
        )

    # ========== C++ Extraction ==========

    def _extract_cpp_symbol(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
        parent_class: Optional[str],
    ) -> Optional[Symbol]:
        """Extract C++ symbol from node."""
        # C++ uses same patterns as C plus class
        if node.type == "class_specifier":
            return self._extract_cpp_class(node, file_path, source)

        # Fall back to C extraction
        return self._extract_c_symbol(node, file_path, source, parent_class)

    def _extract_cpp_class(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
    ) -> Optional[Symbol]:
        """Extract C++ class."""
        name = None

        for child in node.children:
            if child.type == "type_identifier":
                name = self._get_node_text(child, source)
                break

        if not name:
            return None

        return Symbol(
            name=name,
            type=SymbolType.CLASS,
            file_path=file_path,
            line=node.start_point[0] + 1,
        )

    # ========== Java Extraction ==========

    def _extract_java_symbol(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
        parent_class: Optional[str],
    ) -> Optional[Symbol]:
        """Extract Java symbol from node."""
        if node.type == "class_declaration":
            return self._extract_java_class(node, file_path, source)
        elif node.type == "method_declaration":
            return self._extract_java_method(node, file_path, source, parent_class)
        return None

    def _extract_java_class(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
    ) -> Optional[Symbol]:
        """Extract Java class declaration."""
        name = None
        visibility = "public"

        for child in node.children:
            if child.type == "identifier":
                name = self._get_node_text(child, source)
            elif child.type == "modifiers":
                mod_text = self._get_node_text(child, source)
                if "private" in mod_text:
                    visibility = "private"
                elif "protected" in mod_text:
                    visibility = "protected"

        if not name:
            return None

        return Symbol(
            name=name,
            type=SymbolType.CLASS,
            file_path=file_path,
            line=node.start_point[0] + 1,
            visibility=visibility,
        )

    def _extract_java_method(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
        parent_class: Optional[str],
    ) -> Optional[Symbol]:
        """Extract Java method declaration."""
        name = None
        signature = None
        visibility = "public"

        for child in node.children:
            if child.type == "identifier":
                name = self._get_node_text(child, source)
            elif child.type == "formal_parameters":
                signature = self._get_node_text(child, source)
            elif child.type == "modifiers":
                mod_text = self._get_node_text(child, source)
                if "private" in mod_text:
                    visibility = "private"
                elif "protected" in mod_text:
                    visibility = "protected"

        if not name:
            return None

        return Symbol(
            name=name,
            type=SymbolType.METHOD,
            file_path=file_path,
            line=node.start_point[0] + 1,
            signature=signature,
            parent_class=parent_class,
            visibility=visibility,
        )

    # ========== Go Extraction ==========

    def _extract_go_symbol(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
        parent_class: Optional[str],
    ) -> Optional[Symbol]:
        """Extract Go symbol from node."""
        if node.type == "function_declaration":
            return self._extract_go_function(node, file_path, source)
        elif node.type == "type_declaration":
            return self._extract_go_type(node, file_path, source)
        return None

    def _extract_go_function(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
    ) -> Optional[Symbol]:
        """Extract Go function declaration."""
        name = None
        signature = None

        for child in node.children:
            if child.type == "identifier":
                name = self._get_node_text(child, source)
            elif child.type == "parameter_list":
                signature = self._get_node_text(child, source)

        if not name:
            return None

        return Symbol(
            name=name,
            type=SymbolType.FUNCTION,
            file_path=file_path,
            line=node.start_point[0] + 1,
            signature=signature,
        )

    def _extract_go_type(
        self,
        node: Any,
        file_path: Path,
        source: bytes,
    ) -> Optional[Symbol]:
        """Extract Go type declaration (struct, interface)."""
        name = None

        for child in node.children:
            if child.type == "type_spec":
                for sub in child.children:
                    if sub.type == "type_identifier":
                        name = self._get_node_text(sub, source)
                        break

        if not name:
            return None

        return Symbol(
            name=name,
            type=SymbolType.CLASS,  # Treat Go types as classes
            file_path=file_path,
            line=node.start_point[0] + 1,
        )

    # ========== Helpers ==========

    def _get_node_text(self, node: Any, source: bytes) -> str:
        """Get text content of a node."""
        return source[node.start_byte : node.end_byte].decode("utf-8")
