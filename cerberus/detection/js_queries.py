"""
JavaScript/TypeScript Joern CPGQL Query Generator.

Generates Joern queries for validating taint flows in JavaScript/TypeScript code.
This is part of Milestone 7 - hybrid detection using CPG validation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from cerberus.models.taint_flow import TaintFlowCandidate


class JavaScriptQueryGenerator:
    """
    Generates Joern CPGQL queries for JavaScript/TypeScript taint flows.

    Queries use jssrc2cpg (JavaScript CPG) and can validate:
    - Data flow between source and sink
    - Reachability analysis
    - Sanitizer checks
    """

    @staticmethod
    def generate_reachability_query(
        source_line: int,
        sink_line: int,
        file: str,
        source_pattern: Optional[str] = None,
        sink_pattern: Optional[str] = None,
    ) -> str:
        """
        Generate a reachability query to check if data flows from source to sink.

        Args:
            source_line: Line number of the source
            sink_line: Line number of the sink
            file: Filename (just the basename, not full path)
            source_pattern: Optional pattern to match source expression
            sink_pattern: Optional pattern to match sink callee

        Returns:
            CPGQL query string
        """
        # Build source selector
        source_selector = f'cpg.identifier.lineNumber({source_line})'
        if source_pattern:
            source_selector += f'.name("{source_pattern}")'
        source_selector += f'.where(_.file.name.endsWith("{file}"))'

        # Build sink selector
        sink_selector = f'cpg.call.lineNumber({sink_line})'
        if sink_pattern:
            sink_selector += f'.name("{sink_pattern}")'
        sink_selector += f'.where(_.file.name.endsWith("{file}")).argument'

        query = f'''
def source = {source_selector}
def sink = {sink_selector}
sink.reachableByFlows(source).map {{ flow =>
    Map(
        "source_line" -> {source_line},
        "sink_line" -> {sink_line},
        "trace" -> flow.path.map(n => Map(
            "line" -> n.lineNumber.getOrElse(-1),
            "code" -> n.code.take(100)
        )).toList
    )
}}.take(5).toJson
'''
        return query.strip()

    @staticmethod
    def generate_sql_injection_query(file: str) -> str:
        """
        Generate query to find SQL injection vulnerabilities.

        Looks for flows from req.* to query/execute calls.
        """
        return f'''
def sources = cpg.identifier.name("req").astParent.isCall.argument
    .where(_.file.name.endsWith("{file}"))
def sinks = cpg.call.name("query|execute|raw").argument(1)
    .where(_.file.name.endsWith("{file}"))
sinks.reachableByFlows(sources).map {{ flow =>
    Map(
        "vulnerability" -> "SQL_INJECTION",
        "source_line" -> flow.source.lineNumber.getOrElse(-1),
        "sink_line" -> flow.sink.lineNumber.getOrElse(-1),
        "sink_method" -> flow.sink.astParent.asInstanceOf[Call].name,
        "trace_length" -> flow.path.size
    )
}}.toJson
'''

    @staticmethod
    def generate_command_injection_query(file: str) -> str:
        """
        Generate query to find command injection vulnerabilities.

        Looks for flows from req.* to exec/spawn calls.
        """
        return f'''
def sources = cpg.identifier.name("req").astParent.isCall.argument
    .where(_.file.name.endsWith("{file}"))
def sinks = cpg.call.name("exec|execSync|spawn|spawnSync|system").argument(1)
    .where(_.file.name.endsWith("{file}"))
sinks.reachableByFlows(sources).map {{ flow =>
    Map(
        "vulnerability" -> "COMMAND_INJECTION",
        "source_line" -> flow.source.lineNumber.getOrElse(-1),
        "sink_line" -> flow.sink.lineNumber.getOrElse(-1),
        "sink_method" -> flow.sink.astParent.asInstanceOf[Call].name,
        "trace_length" -> flow.path.size
    )
}}.toJson
'''

    @staticmethod
    def generate_path_traversal_query(file: str) -> str:
        """
        Generate query to find path traversal vulnerabilities.

        Looks for flows from req.* to file system operations.
        """
        return f'''
def sources = cpg.identifier.name("req").astParent.isCall.argument
    .where(_.file.name.endsWith("{file}"))
def sinks = cpg.call.name("readFile|readFileSync|writeFile|writeFileSync|open|createReadStream").argument(1)
    .where(_.file.name.endsWith("{file}"))
sinks.reachableByFlows(sources).map {{ flow =>
    Map(
        "vulnerability" -> "PATH_TRAVERSAL",
        "source_line" -> flow.source.lineNumber.getOrElse(-1),
        "sink_line" -> flow.sink.lineNumber.getOrElse(-1),
        "sink_method" -> flow.sink.astParent.asInstanceOf[Call].name,
        "trace_length" -> flow.path.size
    )
}}.toJson
'''

    @staticmethod
    def generate_xss_query(file: str) -> str:
        """
        Generate query to find XSS vulnerabilities.

        Looks for flows from req.* to DOM manipulation or response methods.
        """
        return f'''
def sources = cpg.identifier.name("req").astParent.isCall.argument
    .where(_.file.name.endsWith("{file}"))
def sinks = cpg.call.name("send|write|innerHTML|outerHTML|document.write").argument(1)
    .where(_.file.name.endsWith("{file}"))
sinks.reachableByFlows(sources).map {{ flow =>
    Map(
        "vulnerability" -> "XSS",
        "source_line" -> flow.source.lineNumber.getOrElse(-1),
        "sink_line" -> flow.sink.lineNumber.getOrElse(-1),
        "sink_method" -> flow.sink.astParent.asInstanceOf[Call].name,
        "trace_length" -> flow.path.size
    )
}}.toJson
'''

    @staticmethod
    def generate_candidate_validation_query(candidate: TaintFlowCandidate) -> str:
        """
        Generate query to validate a specific flow candidate.

        Args:
            candidate: TaintFlowCandidate to validate

        Returns:
            CPGQL query string
        """
        file = candidate.source.file_path.name
        source_line = candidate.source.line
        sink_line = candidate.sink.line
        sink_callee = candidate.sink.callee

        return f'''
def source = cpg.identifier.lineNumber({source_line})
    .where(_.file.name.endsWith("{file}"))
def sink = cpg.call.lineNumber({sink_line})
    .where(_.file.name.endsWith("{file}"))
    .name("{sink_callee}.*")
    .argument
sink.reachableByFlows(source).map {{ flow =>
    Map(
        "validated" -> true,
        "source_line" -> {source_line},
        "sink_line" -> {sink_line},
        "trace" -> flow.path.map(n => Map(
            "line" -> n.lineNumber.getOrElse(-1),
            "code" -> n.code.take(100),
            "label" -> n.label
        )).toList
    )
}}.headOption.getOrElse(Map("validated" -> false)).toJson
'''

    @staticmethod
    def generate_sanitizer_check_query(
        source_line: int,
        sink_line: int,
        file: str,
        sanitizer_patterns: list[str],
    ) -> str:
        """
        Generate query to check if flow passes through sanitizers.

        Args:
            source_line: Source line number
            sink_line: Sink line number
            file: Filename
            sanitizer_patterns: List of sanitizer function name patterns

        Returns:
            CPGQL query string
        """
        sanitizer_regex = "|".join(sanitizer_patterns)

        return f'''
def source = cpg.identifier.lineNumber({source_line})
    .where(_.file.name.endsWith("{file}"))
def sink = cpg.call.lineNumber({sink_line})
    .where(_.file.name.endsWith("{file}")).argument
def sanitizers = cpg.call.name("{sanitizer_regex}")

// Check if any flow passes through a sanitizer
val flows = sink.reachableByFlows(source)
val sanitizedFlows = flows.filter(f => f.path.exists(n =>
    sanitizers.id.toSet.contains(n.id)
))

Map(
    "total_flows" -> flows.size,
    "sanitized_flows" -> sanitizedFlows.size,
    "is_sanitized" -> (sanitizedFlows.size > 0)
).toJson
'''

    @staticmethod
    def generate_full_file_analysis_query(file: str) -> str:
        """
        Generate comprehensive taint analysis query for an entire file.

        This query finds all potential taint flows in a JavaScript file.
        """
        return f'''
// Find all user input sources
def sources = cpg.call.where(_.code(".*req\\.(body|params|query|headers|cookies).*"))
    .where(_.file.name.endsWith("{file}"))
    .argument

// Find all dangerous sinks
def sinks = cpg.call.name("query|execute|exec|execSync|spawn|eval|readFile|readFileSync|writeFile|innerHTML")
    .where(_.file.name.endsWith("{file}"))
    .argument(1)

// Find all flows
sinks.reachableByFlows(sources).map {{ flow =>
    Map(
        "file" -> "{file}",
        "source" -> Map(
            "line" -> flow.source.lineNumber.getOrElse(-1),
            "code" -> flow.source.code.take(50)
        ),
        "sink" -> Map(
            "line" -> flow.sink.lineNumber.getOrElse(-1),
            "code" -> flow.sink.code.take(50),
            "method" -> flow.sink.astParent.asInstanceOf[Call].name
        ),
        "trace_length" -> flow.path.size
    )
}}.toJson
'''

    @classmethod
    def generate_batch_validation_query(
        cls, candidates: list[TaintFlowCandidate]
    ) -> str:
        """
        Generate a single query to validate multiple candidates.

        More efficient than running individual queries for each candidate.
        """
        if not candidates:
            return '{"results": []}.toJson'

        # Group by file for efficiency
        by_file: dict[str, list[TaintFlowCandidate]] = {}
        for c in candidates:
            fname = c.source.file_path.name
            if fname not in by_file:
                by_file[fname] = []
            by_file[fname].append(c)

        # Build query parts for each file
        parts = []
        for file, file_candidates in by_file.items():
            source_lines = list({c.source.line for c in file_candidates})
            sink_lines = list({c.sink.line for c in file_candidates})

            parts.append(f'''
// File: {file}
{{
    def sources_{len(parts)} = cpg.identifier
        .where(_.file.name.endsWith("{file}"))
        .filter(_.lineNumber.exists(l => List({",".join(map(str, source_lines))}).contains(l)))

    def sinks_{len(parts)} = cpg.call
        .where(_.file.name.endsWith("{file}"))
        .filter(_.lineNumber.exists(l => List({",".join(map(str, sink_lines))}).contains(l)))
        .argument

    sinks_{len(parts)}.reachableByFlows(sources_{len(parts)}).map {{ flow =>
        Map(
            "file" -> "{file}",
            "source_line" -> flow.source.lineNumber.getOrElse(-1),
            "sink_line" -> flow.sink.lineNumber.getOrElse(-1),
            "validated" -> true
        )
    }}
}}
''')

        return f'''
val results = List(
{",".join(parts)}
).flatten.toJson
'''
