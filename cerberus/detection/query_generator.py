"""
CPGQL Query Generator for Phase III Detection.

Generates CPGQL queries from dynamic specifications using:
- Template-based generation for known vulnerability types
- LLM-assisted generation for complex patterns
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from cerberus.models.spec import DynamicSpec, TaintSpec


@dataclass
class QueryGeneratorConfig:
    """Configuration for query generation."""

    use_llm: bool = True
    max_queries_per_pair: int = 3
    validate_queries: bool = True
    include_sanitizer_checks: bool = True


@dataclass
class CPGQLQuery:
    """Represents a generated CPGQL query."""

    query: str
    source: str
    sink: str
    vulnerability_type: str = ""
    sanitizers: list[str] = field(default_factory=list)
    confidence: float = 0.8
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "query": self.query,
            "source": self.source,
            "sink": self.sink,
            "vulnerability_type": self.vulnerability_type,
            "sanitizers": self.sanitizers,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


class QueryTemplate:
    """Templates for CPGQL queries by vulnerability type."""

    # Base data flow template
    BASE_TEMPLATE = '''
def source = cpg.method.name("{source}").parameter
def sink = cpg.method.name("{sink}").parameter
{sanitizer_filter}
sink.reachableBy(source).map {{ path =>
    Map(
        "source" -> Map("method" -> "{source}", "line" -> path.head.lineNumber.getOrElse(-1)),
        "sink" -> Map("method" -> "{sink}", "line" -> path.last.lineNumber.getOrElse(-1)),
        "trace" -> path.map(n => Map("line" -> n.lineNumber.getOrElse(-1), "code" -> n.code))
    )
}}.toJson
'''

    # SQL Injection specific template
    SQL_INJECTION_TEMPLATE = '''
def source = cpg.method.name("{source}").parameter
def sink = cpg.call.name("{sink}").argument
{sanitizer_filter}
sink.reachableBy(source).map {{ path =>
    Map(
        "vulnerability" -> "SQL_INJECTION",
        "source" -> Map("method" -> "{source}", "line" -> path.head.lineNumber.getOrElse(-1)),
        "sink" -> Map("method" -> "{sink}", "line" -> path.last.lineNumber.getOrElse(-1)),
        "trace" -> path.map(n => Map("line" -> n.lineNumber.getOrElse(-1), "code" -> n.code))
    )
}}.toJson
'''

    # XSS template
    XSS_TEMPLATE = '''
def source = cpg.method.name("{source}").parameter
def sink = cpg.call.name("{sink}").argument
{sanitizer_filter}
sink.reachableBy(source).map {{ path =>
    Map(
        "vulnerability" -> "XSS",
        "source" -> Map("method" -> "{source}", "line" -> path.head.lineNumber.getOrElse(-1)),
        "sink" -> Map("method" -> "{sink}", "line" -> path.last.lineNumber.getOrElse(-1)),
        "trace" -> path.map(n => Map("line" -> n.lineNumber.getOrElse(-1), "code" -> n.code))
    )
}}.toJson
'''

    # Command injection template
    COMMAND_INJECTION_TEMPLATE = '''
def source = cpg.method.name("{source}").parameter
def sink = cpg.call.name("{sink}").argument
{sanitizer_filter}
sink.reachableBy(source).map {{ path =>
    Map(
        "vulnerability" -> "COMMAND_INJECTION",
        "source" -> Map("method" -> "{source}", "line" -> path.head.lineNumber.getOrElse(-1)),
        "sink" -> Map("method" -> "{sink}", "line" -> path.last.lineNumber.getOrElse(-1)),
        "trace" -> path.map(n => Map("line" -> n.lineNumber.getOrElse(-1), "code" -> n.code))
    )
}}.toJson
'''

    TEMPLATES = {
        "CWE-89": SQL_INJECTION_TEMPLATE,
        "CWE-79": XSS_TEMPLATE,
        "CWE-78": COMMAND_INJECTION_TEMPLATE,
    }

    @classmethod
    def get(cls, vulnerability_type: str) -> str:
        """Get template for vulnerability type."""
        return cls.TEMPLATES.get(vulnerability_type, cls.BASE_TEMPLATE)


class QueryGenerator:
    """Generates CPGQL queries from dynamic specifications.

    Can use either:
    - Template-based generation (fast, deterministic)
    - LLM-assisted generation (flexible, context-aware)
    """

    def __init__(self, config: Optional[QueryGeneratorConfig] = None) -> None:
        """Initialize query generator.

        Args:
            config: Generator configuration.
        """
        self.config = config or QueryGeneratorConfig()
        self._llm_gateway: Optional[Any] = None

    def generate_queries(self, spec: DynamicSpec) -> list[CPGQLQuery]:
        """Generate CPGQL queries from specification.

        Args:
            spec: Dynamic specification with sources, sinks, sanitizers.

        Returns:
            List of generated CPGQL queries.
        """
        queries: list[CPGQLQuery] = []

        # Get source-sink pairs with relevant sanitizers
        pairs = self.get_source_sink_pairs(spec, include_sanitizers=True)

        for source, sink, vuln_type, sanitizers in pairs:
            # Generate query from template
            query = self._generate_from_template(source, sink, vuln_type, sanitizers)
            if query:
                queries.append(query)

                # Respect max queries limit
                pair_queries = [
                    q for q in queries
                    if q.source == source.method and q.sink == sink.method
                ]
                if len(pair_queries) >= self.config.max_queries_per_pair:
                    continue

        return queries

    async def generate_queries_async(self, spec: DynamicSpec) -> list[CPGQLQuery]:
        """Generate queries, optionally using LLM.

        Args:
            spec: Dynamic specification.

        Returns:
            List of generated CPGQL queries.
        """
        if not self.config.use_llm or self._llm_gateway is None:
            return self.generate_queries(spec)

        queries: list[CPGQLQuery] = []
        pairs = self.get_source_sink_pairs(spec, include_sanitizers=True)

        for source, sink, vuln_type, sanitizers in pairs:
            try:
                # Try LLM generation
                query = await self._generate_with_llm(source, sink, vuln_type, sanitizers)
                if query:
                    queries.append(query)
            except Exception:
                # Fallback to template
                query = self._generate_from_template(source, sink, vuln_type, sanitizers)
                if query:
                    queries.append(query)

        return queries

    def get_source_sink_pairs(
        self,
        spec: DynamicSpec,
        include_sanitizers: bool = False,
    ) -> list[tuple]:
        """Get all relevant source-sink pairs.

        Pairs sources and sinks. Uses sink's vulnerability types, or common
        types if both have them, or a default if neither has them.

        Args:
            spec: Dynamic specification.
            include_sanitizers: Whether to include sanitizers in result.

        Returns:
            List of (source, sink, vuln_type[, sanitizers]) tuples.
        """
        pairs = []

        for source in spec.sources:
            for sink in spec.sinks:
                # Determine vulnerability types:
                # 1. Use common types if both have them
                # 2. Use sink's types if source has none
                # 3. Use source's types if sink has none
                # 4. Use a generic type if neither has any
                source_vulns = set(source.vulnerability_types) if source.vulnerability_types else set()
                sink_vulns = set(sink.vulnerability_types) if sink.vulnerability_types else set()

                if source_vulns and sink_vulns:
                    vuln_types = source_vulns & sink_vulns
                    if not vuln_types:
                        # No common types - skip this source-sink pair
                        # A source can only flow to sinks of matching vulnerability types
                        continue
                elif sink_vulns:
                    # Source has no specific types - match with all sink types
                    vuln_types = sink_vulns
                elif source_vulns:
                    # Sink has no specific types - match with all source types
                    vuln_types = source_vulns
                else:
                    # Neither has types - use generic data flow
                    vuln_types = {"DATA_FLOW"}

                for vuln_type in vuln_types:
                    if include_sanitizers:
                        # Get sanitizers for this vulnerability type
                        sanitizers = [
                            s for s in spec.sanitizers
                            if vuln_type in s.vulnerability_types
                        ]
                        pairs.append((source, sink, vuln_type, sanitizers))
                    else:
                        pairs.append((source, sink, vuln_type))

        return pairs

    def validate_query(self, query: str) -> bool:
        """Validate CPGQL query syntax.

        Args:
            query: CPGQL query string.

        Returns:
            True if query appears valid.
        """
        # Check for dangerous operations
        dangerous_patterns = [
            r'\.close\s*\(',
            r'\.delete\s*\(',
            r'\.drop\s*\(',
            r'System\.exit',
            r'Runtime\.exec',
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                return False

        # Basic syntax checks
        # Should have cpg. reference with dot notation OR def statement
        has_cpg_ref = 'cpg.' in query or 'def ' in query
        # Should not have obvious syntax errors
        has_balanced_parens = query.count('(') == query.count(')')
        has_balanced_braces = query.count('{') == query.count('}')

        # Must have valid structure
        if not has_cpg_ref:
            return False

        return has_balanced_parens and has_balanced_braces

    def _generate_from_template(
        self,
        source: TaintSpec,
        sink: TaintSpec,
        vuln_type: str,
        sanitizers: list[TaintSpec],
    ) -> Optional[CPGQLQuery]:
        """Generate query from template.

        Args:
            source: Source specification.
            sink: Sink specification.
            vuln_type: Vulnerability type (CWE-XX).
            sanitizers: Relevant sanitizers.

        Returns:
            Generated query or None.
        """
        template = QueryTemplate.get(vuln_type)

        # Build sanitizer filter
        sanitizer_filter = ""
        sanitizer_methods = [s.method for s in sanitizers]
        if sanitizer_methods and self.config.include_sanitizer_checks:
            sanitizer_names = "|".join(sanitizer_methods)
            sanitizer_filter = (
                f'def sanitizers = cpg.method.name("{sanitizer_names}")\n'
            )

        # Fill in template
        query = template.format(
            source=source.method,
            sink=sink.method,
            sanitizer_filter=sanitizer_filter,
        )

        # Validate if configured
        if self.config.validate_queries and not self.validate_query(query):
            return None

        return CPGQLQuery(
            query=query.strip(),
            source=source.method,
            sink=sink.method,
            vulnerability_type=vuln_type,
            sanitizers=sanitizer_methods,
            confidence=min(source.confidence, sink.confidence),
            metadata={
                "source_file": str(source.file_path),
                "sink_file": str(sink.file_path),
                "template_based": True,
            },
        )

    async def _generate_with_llm(
        self,
        source: TaintSpec,
        sink: TaintSpec,
        vuln_type: str,
        sanitizers: list[TaintSpec],
    ) -> Optional[CPGQLQuery]:
        """Generate query using LLM.

        Args:
            source: Source specification.
            sink: Sink specification.
            vuln_type: Vulnerability type.
            sanitizers: Relevant sanitizers.

        Returns:
            Generated query or None.
        """
        if not self._llm_gateway:
            return None

        # Build prompt
        sanitizer_list = ", ".join(s.method for s in sanitizers) or "none"
        prompt = f"""Generate a Joern CPGQL query to find data flows from source to sink.

Source method: {source.method}
Sink method: {sink.method}
Vulnerability type: {vuln_type}
Known sanitizers: {sanitizer_list}

Requirements:
1. Find all calls to the source method
2. Track data flow through the program
3. Identify if data reaches the sink without sanitization
4. Return results as JSON with source, sink, and trace

Generate ONLY the CPGQL query, no explanation:
"""

        from cerberus.llm.providers.models import LLMRequest, Message, Role

        request = LLMRequest(
            messages=[Message(role=Role.USER, content=prompt)],
            temperature=0.0,
        )

        response = await self._llm_gateway.complete(request)

        # Extract query from response
        query_text = self._extract_query(response.content)

        if not query_text:
            return None

        # Validate
        if self.config.validate_queries and not self.validate_query(query_text):
            return None

        return CPGQLQuery(
            query=query_text,
            source=source.method,
            sink=sink.method,
            vulnerability_type=vuln_type,
            sanitizers=[s.method for s in sanitizers],
            confidence=min(source.confidence, sink.confidence) * 0.9,  # Slightly lower for LLM
            metadata={
                "source_file": str(source.file_path),
                "sink_file": str(sink.file_path),
                "llm_generated": True,
            },
        )

    def _extract_query(self, response: str) -> Optional[str]:
        """Extract CPGQL query from LLM response.

        Args:
            response: LLM response text.

        Returns:
            Extracted query or None.
        """
        # Try to extract from code blocks
        code_block_pattern = r'```(?:scala|cpgql)?\s*(.*?)```'
        matches = re.findall(code_block_pattern, response, re.DOTALL)

        if matches:
            return matches[0].strip()

        # If no code blocks, try to find query patterns
        lines = response.strip().split('\n')
        query_lines = []
        in_query = False

        for line in lines:
            if 'def ' in line or 'cpg.' in line:
                in_query = True
            if in_query:
                query_lines.append(line)
                if '.toJson' in line or '.l' in line.rstrip():
                    break

        if query_lines:
            return '\n'.join(query_lines)

        return None
