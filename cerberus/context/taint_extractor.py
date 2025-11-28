"""
AST-Level Taint Extractor using Tree-sitter.

Extracts taint sources (req.body, req.params, etc.) and sinks (query, exec, etc.)
from source code AST. This is the core of Milestone 7 - solving the limitations
identified in the JS_VALIDATION_REPORT.md.

Key capabilities:
- Extract member_expression nodes for sources (property access patterns)
- Extract call_expression nodes for sinks (method/function calls)
- Detect template literal usage (high-risk indicator)
- Create flow candidates by matching sources to sinks
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from cerberus.context.tree_sitter_parser import TreeSitterParser
from cerberus.models.taint_flow import (
    SourceType,
    SinkType,
    TaintSource,
    TaintSink,
    TaintFlowCandidate,
    LANGUAGE_SOURCE_PATTERNS,
    LANGUAGE_SINK_PATTERNS,
)
from cerberus.utils.logging import ComponentLogger


class TaintExtractor:
    """
    Extracts taint sources and sinks from source code AST.

    Uses Tree-sitter for multi-language AST parsing and pattern matching
    to identify security-relevant code locations.
    """

    # Supported languages for taint extraction
    SUPPORTED_LANGUAGES = {
        "javascript", "typescript", "python", "java",
        "php", "go", "kotlin", "c", "cpp",
    }

    def __init__(self) -> None:
        """Initialize the taint extractor."""
        self.logger = ComponentLogger("taint_extractor")
        self.parser = TreeSitterParser()

    @property
    def supported_languages(self) -> set[str]:
        """Get set of supported languages."""
        return self.SUPPORTED_LANGUAGES

    def extract_from_file(
        self, file_path: Path
    ) -> tuple[list[TaintSource], list[TaintSink]]:
        """
        Extract taint sources and sinks from a source file.

        Args:
            file_path: Path to the source file

        Returns:
            Tuple of (sources, sinks)
        """
        language = self.parser.detect_language(file_path)
        if not language or language not in self.SUPPORTED_LANGUAGES:
            return [], []

        tree = self.parser.parse_file(file_path)
        if not tree:
            return [], []

        try:
            with open(file_path, "rb") as f:
                source = f.read()
        except OSError:
            return [], []

        return self._extract(tree.root_node, language, file_path, source)

    def extract_from_string(
        self, code: str, language: str, file_path: Path
    ) -> tuple[list[TaintSource], list[TaintSink]]:
        """
        Extract taint sources and sinks from source code string.

        Args:
            code: Source code string
            language: Programming language
            file_path: File path for metadata

        Returns:
            Tuple of (sources, sinks)
        """
        if language not in self.SUPPORTED_LANGUAGES:
            return [], []

        tree = self.parser.parse_string(code, language)
        if not tree:
            return [], []

        source = code.encode("utf-8")
        return self._extract(tree.root_node, language, file_path, source)

    def _extract(
        self,
        root_node: Any,
        language: str,
        file_path: Path,
        source: bytes,
    ) -> tuple[list[TaintSource], list[TaintSink]]:
        """
        Extract sources and sinks from AST root node.

        Args:
            root_node: Tree-sitter root node
            language: Programming language
            file_path: File path for metadata
            source: Source code bytes

        Returns:
            Tuple of (sources, sinks)
        """
        sources: list[TaintSource] = []
        sinks: list[TaintSink] = []

        # Track containing functions for better context
        self._traverse_and_extract(
            root_node, language, file_path, source, sources, sinks, None
        )

        return sources, sinks

    def _traverse_and_extract(
        self,
        node: Any,
        language: str,
        file_path: Path,
        source: bytes,
        sources: list[TaintSource],
        sinks: list[TaintSink],
        containing_function: Optional[str],
    ) -> None:
        """
        Recursively traverse AST and extract sources/sinks.

        Args:
            node: Current AST node
            language: Programming language
            file_path: File path
            source: Source code bytes
            sources: List to append sources to
            sinks: List to append sinks to
            containing_function: Name of containing function (if any)
        """
        # Update containing function if we're entering a function
        new_containing = self._get_function_name(node, language, source)
        if new_containing:
            containing_function = new_containing

        # Check for sources (member expressions like req.body.x)
        if self._is_source_node(node, language):
            source_obj = self._extract_source(
                node, language, file_path, source, containing_function
            )
            if source_obj:
                sources.append(source_obj)

        # Check for sinks (call expressions like query(), exec())
        if self._is_sink_node(node, language):
            sink_obj = self._extract_sink(
                node, language, file_path, source, containing_function
            )
            if sink_obj:
                sinks.append(sink_obj)

        # Recurse into children
        for child in node.children:
            self._traverse_and_extract(
                child, language, file_path, source, sources, sinks, containing_function
            )

    def _is_source_node(self, node: Any, language: str) -> bool:
        """Check if node is a potential source."""
        if language in ("javascript", "typescript"):
            return node.type == "member_expression"
        elif language == "python":
            return node.type in ("attribute", "subscript")
        elif language == "java":
            return node.type == "method_invocation"
        elif language == "php":
            return node.type == "subscript_expression"
        elif language == "go":
            return node.type in ("selector_expression", "call_expression")
        return False

    def _is_sink_node(self, node: Any, language: str) -> bool:
        """Check if node is a potential sink (call expression)."""
        if language in ("javascript", "typescript"):
            return node.type == "call_expression"
        elif language == "python":
            return node.type == "call"
        elif language in ("java", "kotlin"):
            return node.type == "method_invocation"
        elif language == "php":
            return node.type in ("function_call_expression", "member_call_expression")
        elif language == "go":
            return node.type == "call_expression"
        elif language in ("c", "cpp"):
            return node.type == "call_expression"
        return False

    def _extract_source(
        self,
        node: Any,
        language: str,
        file_path: Path,
        source: bytes,
        containing_function: Optional[str],
    ) -> Optional[TaintSource]:
        """
        Extract a TaintSource from a member expression node.

        Args:
            node: AST node
            language: Programming language
            file_path: File path
            source: Source code bytes
            containing_function: Containing function name

        Returns:
            TaintSource if pattern matches, None otherwise
        """
        expression = self._get_node_text(node, source)

        # Get source patterns for language
        patterns = LANGUAGE_SOURCE_PATTERNS.get(language, {})

        # Check each pattern
        for pattern, (source_type, cwe_types) in patterns.items():
            if self._matches_source_pattern(expression, pattern, language):
                return TaintSource(
                    expression=expression,
                    source_type=source_type,
                    file_path=file_path,
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    containing_function=containing_function,
                    cwe_types=list(cwe_types),
                    confidence=0.85,
                    language=language,
                )

        return None

    def _matches_source_pattern(
        self, expression: str, pattern: str, language: str
    ) -> bool:
        """Check if expression matches a source pattern."""
        # For JavaScript/TypeScript: req.body, req.params, etc.
        if language in ("javascript", "typescript"):
            # Match patterns like req.body, req.body.username, etc.
            if pattern.startswith("req."):
                return expression.startswith(pattern)
            elif pattern.startswith("process.env"):
                return expression.startswith(pattern)
            return pattern in expression

        # For Python: request.form, request.args, etc.
        elif language == "python":
            if pattern.startswith("request."):
                return expression.startswith(pattern) or pattern in expression
            elif pattern.startswith("os.environ") or pattern.startswith("sys.argv"):
                return pattern in expression
            return pattern in expression

        # For PHP: $_GET, $_POST, etc.
        elif language == "php":
            return expression.startswith(pattern) or pattern in expression

        # For Java/Kotlin: request.getParameter, etc.
        elif language in ("java", "kotlin"):
            return pattern in expression

        # For Go: r.URL.Query, r.FormValue, etc.
        elif language == "go":
            return pattern in expression

        # For C/C++
        elif language in ("c", "cpp"):
            return pattern in expression

        return False

    def _extract_sink(
        self,
        node: Any,
        language: str,
        file_path: Path,
        source: bytes,
        containing_function: Optional[str],
    ) -> Optional[TaintSink]:
        """
        Extract a TaintSink from a call expression node.

        Args:
            node: AST node
            language: Programming language
            file_path: File path
            source: Source code bytes
            containing_function: Containing function name

        Returns:
            TaintSink if pattern matches, None otherwise
        """
        callee = self._get_callee_name(node, language, source)
        if not callee:
            return None

        # Get sink patterns for language
        patterns = LANGUAGE_SINK_PATTERNS.get(language, {})

        # Check each pattern
        for pattern, (sink_type, cwe_types) in patterns.items():
            if self._matches_sink_pattern(callee, pattern, language):
                expression = self._get_node_text(node, source)
                uses_template = self._has_template_literal_arg(node, language, source)

                return TaintSink(
                    callee=callee,
                    expression=expression[:200],  # Truncate long expressions
                    sink_type=sink_type,
                    file_path=file_path,
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    containing_function=containing_function,
                    uses_template_literal=uses_template,
                    cwe_types=list(cwe_types),
                    confidence=0.85,
                    language=language,
                )

        return None

    def _matches_sink_pattern(
        self, callee: str, pattern: str, language: str
    ) -> bool:
        """Check if callee matches a sink pattern."""
        # Direct match (e.g., "exec" matches "exec")
        if callee == pattern:
            return True

        # Match method name (e.g., "query" matches "db.query")
        if callee.endswith(f".{pattern}"):
            return True

        # Match ending (e.g., "execSync" matches pattern "execSync")
        if callee.endswith(pattern):
            return True

        return False

    def _get_callee_name(self, node: Any, language: str, source: bytes) -> Optional[str]:
        """
        Get the callee name from a call expression.

        Handles both direct calls (exec()) and method calls (db.query()).
        """
        if language in ("javascript", "typescript"):
            return self._get_js_callee(node, source)
        elif language == "python":
            return self._get_python_callee(node, source)
        elif language in ("java", "kotlin"):
            return self._get_java_callee(node, source)
        elif language == "php":
            return self._get_php_callee(node, source)
        elif language == "go":
            return self._get_go_callee(node, source)
        elif language in ("c", "cpp"):
            return self._get_c_callee(node, source)

        return None

    def _get_js_callee(self, node: Any, source: bytes) -> Optional[str]:
        """Get callee name for JavaScript/TypeScript call expression."""
        for child in node.children:
            if child.type == "identifier":
                return self._get_node_text(child, source)
            elif child.type == "member_expression":
                # Get the last property (method name)
                # e.g., sequelize.query -> "query"
                for sub in child.children:
                    if sub.type == "property_identifier":
                        return self._get_node_text(sub, source)
                # Fallback: get full expression
                return self._get_node_text(child, source)
        return None

    def _get_python_callee(self, node: Any, source: bytes) -> Optional[str]:
        """Get callee name for Python call expression."""
        for child in node.children:
            if child.type == "identifier":
                return self._get_node_text(child, source)
            elif child.type == "attribute":
                # Get the attribute name (last part)
                for sub in child.children:
                    if sub.type == "identifier":
                        # Get last identifier (the method name)
                        pass
                # Get the full attribute chain
                return self._get_node_text(child, source)
        return None

    def _get_java_callee(self, node: Any, source: bytes) -> Optional[str]:
        """Get callee name for Java method invocation."""
        for child in node.children:
            if child.type == "identifier":
                return self._get_node_text(child, source)
        return None

    def _get_php_callee(self, node: Any, source: bytes) -> Optional[str]:
        """Get callee name for PHP function call."""
        for child in node.children:
            if child.type == "name":
                return self._get_node_text(child, source)
            elif child.type == "qualified_name":
                return self._get_node_text(child, source)
        return None

    def _get_go_callee(self, node: Any, source: bytes) -> Optional[str]:
        """Get callee name for Go call expression."""
        for child in node.children:
            if child.type == "identifier":
                return self._get_node_text(child, source)
            elif child.type == "selector_expression":
                # Get the selector (method name)
                for sub in child.children:
                    if sub.type == "field_identifier":
                        return self._get_node_text(sub, source)
        return None

    def _get_c_callee(self, node: Any, source: bytes) -> Optional[str]:
        """Get callee name for C/C++ call expression."""
        for child in node.children:
            if child.type == "identifier":
                return self._get_node_text(child, source)
        return None

    def _has_template_literal_arg(
        self, node: Any, language: str, source: bytes
    ) -> bool:
        """
        Check if call has template literal argument (HIGH RISK indicator).

        Template literals with interpolation indicate string concatenation
        which is a major SQL/Command injection risk.
        """
        if language in ("javascript", "typescript"):
            return self._has_js_template_literal(node, source)
        elif language == "python":
            return self._has_python_fstring(node, source)
        return False

    def _has_js_template_literal(self, node: Any, source: bytes) -> bool:
        """Check for JavaScript template literal in arguments."""
        # Find arguments node
        for child in node.children:
            if child.type == "arguments":
                return self._node_contains_template_literal(child)
        return False

    def _node_contains_template_literal(self, node: Any) -> bool:
        """Recursively check if node contains template_string."""
        if node.type == "template_string":
            return True
        for child in node.children:
            if self._node_contains_template_literal(child):
                return True
        return False

    def _has_python_fstring(self, node: Any, source: bytes) -> bool:
        """Check for Python f-string in arguments."""
        # Check for formatted_string (f-string) in call arguments
        for child in node.children:
            if child.type == "argument_list":
                return self._node_contains_fstring(child, source)
        return False

    def _node_contains_fstring(self, node: Any, source: bytes) -> bool:
        """Check if node contains f-string."""
        text = self._get_node_text(node, source)
        # Simple check for f-string prefix
        if 'f"' in text or "f'" in text:
            return True
        for child in node.children:
            if self._node_contains_fstring(child, source):
                return True
        return False

    def _get_function_name(
        self, node: Any, language: str, source: bytes
    ) -> Optional[str]:
        """
        Get function name if node is a function definition.

        Returns function name if node defines a function, None otherwise.
        """
        if language in ("javascript", "typescript"):
            if node.type in ("function_declaration", "method_definition"):
                for child in node.children:
                    if child.type in ("identifier", "property_identifier"):
                        return self._get_node_text(child, source)
            elif node.type in ("lexical_declaration", "variable_declaration"):
                # Arrow function: const foo = () => {}
                # Only return name if value is an arrow_function or function
                for child in node.children:
                    if child.type == "variable_declarator":
                        has_function_value = False
                        var_name = None
                        for sub in child.children:
                            if sub.type == "identifier":
                                var_name = self._get_node_text(sub, source)
                            elif sub.type in ("arrow_function", "function", "function_expression"):
                                has_function_value = True
                        if has_function_value and var_name:
                            return var_name
                return None  # Not a function declaration
            elif node.type == "arrow_function":
                # Anonymous arrow function - create synthetic name with line number
                line = node.start_point[0] + 1
                return f"__anonymous_handler_L{line}"
        elif language == "python":
            if node.type == "function_definition":
                for child in node.children:
                    if child.type == "identifier":
                        return self._get_node_text(child, source)
        elif language in ("java", "kotlin"):
            if node.type == "method_declaration":
                for child in node.children:
                    if child.type == "identifier":
                        return self._get_node_text(child, source)

        return None

    def _get_node_text(self, node: Any, source: bytes) -> str:
        """Get text content of a node."""
        return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def create_flow_candidates(
        self,
        sources: list[TaintSource],
        sinks: list[TaintSink],
    ) -> list[TaintFlowCandidate]:
        """
        Create flow candidates by matching sources to sinks.

        Matching criteria:
        1. Must have overlapping CWE types
        2. Must be in same file (for now - inter-file analysis is future work)

        Args:
            sources: List of extracted sources
            sinks: List of extracted sinks

        Returns:
            List of flow candidates
        """
        candidates: list[TaintFlowCandidate] = []

        for source in sources:
            for sink in sinks:
                # Check if in same file
                if source.file_path != sink.file_path:
                    continue

                # Check CWE type overlap
                source_cwes = set(source.cwe_types)
                sink_cwes = set(sink.cwe_types)
                shared_cwes = source_cwes & sink_cwes

                if not shared_cwes:
                    continue

                # Determine if in same function
                in_same_function = (
                    source.containing_function is not None
                    and source.containing_function == sink.containing_function
                )

                # Create candidate
                candidate = TaintFlowCandidate(
                    source=source,
                    sink=sink,
                    in_same_function=in_same_function,
                )

                candidates.append(candidate)

        # Remove duplicates
        seen = set()
        unique_candidates = []
        for c in candidates:
            key = (c.source.location_key, c.sink.location_key)
            if key not in seen:
                seen.add(key)
                unique_candidates.append(c)

        return unique_candidates
