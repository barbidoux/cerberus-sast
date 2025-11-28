"""
Taint Classification Prompts for Milestone 8: LLM Integration.

Prompts for validating AST-extracted sources and sinks using LLM.
These prompts enable true Neuro-Symbolic analysis by having the LLM
reason about code semantics, not just pattern match.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from cerberus.models.taint_flow import SourceType, SinkType


@dataclass
class SourceClassificationResult:
    """Result of LLM classification for a taint source."""

    is_source: bool
    confidence: float
    source_type: str  # SourceType value string
    cwe_types: list[str]
    reasoning: str
    sanitization_nearby: bool = False

    @classmethod
    def from_json(cls, json_str: str) -> "SourceClassificationResult":
        """Parse source classification from JSON string."""
        try:
            # Extract JSON from response
            json_match = re.search(r'\{[^{}]*\}', json_str, re.DOTALL)
            if json_match:
                json_str = json_match.group()

            data = json.loads(json_str)

            return cls(
                is_source=data.get("is_source", False),
                confidence=float(data.get("confidence", 0.5)),
                source_type=data.get("source_type", "user_input"),
                cwe_types=data.get("cwe_types", []),
                reasoning=data.get("reasoning", ""),
                sanitization_nearby=data.get("sanitization_nearby", False),
            )
        except (json.JSONDecodeError, AttributeError, TypeError):
            return cls(
                is_source=False,
                confidence=0.3,
                source_type="user_input",
                cwe_types=[],
                reasoning=f"Failed to parse response: {json_str[:100]}",
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "is_source": self.is_source,
            "confidence": self.confidence,
            "source_type": self.source_type,
            "cwe_types": self.cwe_types,
            "reasoning": self.reasoning,
            "sanitization_nearby": self.sanitization_nearby,
        }


@dataclass
class SinkClassificationResult:
    """Result of LLM classification for a taint sink."""

    is_sink: bool
    confidence: float
    sink_type: str  # SinkType value string
    cwe_types: list[str]
    reasoning: str
    sanitization_nearby: bool = False

    @classmethod
    def from_json(cls, json_str: str) -> "SinkClassificationResult":
        """Parse sink classification from JSON string."""
        try:
            # Extract JSON from response
            json_match = re.search(r'\{[^{}]*\}', json_str, re.DOTALL)
            if json_match:
                json_str = json_match.group()

            data = json.loads(json_str)

            return cls(
                is_sink=data.get("is_sink", False),
                confidence=float(data.get("confidence", 0.5)),
                sink_type=data.get("sink_type", "dangerous_call"),
                cwe_types=data.get("cwe_types", []),
                reasoning=data.get("reasoning", ""),
                sanitization_nearby=data.get("sanitization_nearby", False),
            )
        except (json.JSONDecodeError, AttributeError, TypeError):
            return cls(
                is_sink=False,
                confidence=0.3,
                sink_type="dangerous_call",
                cwe_types=[],
                reasoning=f"Failed to parse response: {json_str[:100]}",
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "is_sink": self.is_sink,
            "confidence": self.confidence,
            "sink_type": self.sink_type,
            "cwe_types": self.cwe_types,
            "reasoning": self.reasoning,
            "sanitization_nearby": self.sanitization_nearby,
        }


# =============================================================================
# Source Classification Prompt
# =============================================================================

TAINT_SOURCE_SYSTEM_PROMPT = """You are a security expert performing taint analysis on source code.

Your task is to determine if a specific expression is a TAINT SOURCE - a location where untrusted user input enters the application.

## What is a Taint Source?

A taint source is any expression that reads data from an external, untrusted origin:
- HTTP request data (body, params, query, headers, cookies)
- Environment variables
- Database results
- File contents
- User-controlled URLs
- Command-line arguments

## Source Types

- REQUEST_BODY: Data from HTTP request body (req.body, request.form)
- REQUEST_PARAMS: URL path parameters (req.params, @PathVariable)
- REQUEST_QUERY: URL query string (req.query, request.args)
- REQUEST_HEADERS: HTTP headers (req.headers, request.getHeader)
- REQUEST_COOKIES: Cookie values (req.cookies)
- ENVIRONMENT: Environment variables (process.env, os.environ)
- USER_INPUT: Generic user input
- FILE_INPUT: File read operations
- DATABASE_INPUT: Database query results

## Analysis Instructions

1. Look at the expression and its surrounding context
2. Determine if this expression reads from an untrusted external source
3. Consider whether the data could be controlled by an attacker
4. Note any sanitization or validation in the nearby code

## Response Format

Respond with a JSON object:
{
    "is_source": true/false,
    "confidence": 0.0-1.0,
    "source_type": "REQUEST_BODY|REQUEST_PARAMS|REQUEST_QUERY|...",
    "cwe_types": ["CWE-89", "CWE-78", ...],
    "reasoning": "Chain-of-thought explanation",
    "sanitization_nearby": true/false
}"""


def build_source_classification_prompt(
    expression: str,
    code_context: str,
    language: str,
    line: int,
    ast_source_type: str,
) -> dict[str, str]:
    """
    Build a prompt for source classification.

    Args:
        expression: The expression to classify (e.g., "req.body.username")
        code_context: ~50 lines of surrounding code
        language: Programming language
        line: Line number of the expression
        ast_source_type: Source type detected by AST pattern matching

    Returns:
        Dict with system and user prompts
    """
    user_prompt = f"""## Code Context
```{language}
{code_context}
```

## Expression to Analyze
- Line: {line}
- Expression: `{expression}`
- AST-detected type: {ast_source_type}

## Question
Is this expression a TAINT SOURCE (untrusted user input)?

Analyze step by step:
1. What data does this expression access?
2. Is this data controlled by external users/attackers?
3. What vulnerabilities could result if this data reaches a dangerous sink?
4. Is there any validation or sanitization nearby?

Respond with JSON."""

    return {
        "system": TAINT_SOURCE_SYSTEM_PROMPT,
        "user": user_prompt,
    }


# =============================================================================
# Sink Classification Prompt
# =============================================================================

TAINT_SINK_SYSTEM_PROMPT = r"""You are a security expert performing taint analysis on source code.

Your task is to determine if a specific function call is a DANGEROUS SINK - a location where untrusted data could cause security vulnerabilities.

## What is a Taint Sink?

A taint sink is any operation that could be exploited if it receives untrusted input:
- SQL queries (SQL injection - CWE-89)
- Command execution (Command injection - CWE-78)
- Code evaluation (Code injection - CWE-94)
- DOM manipulation (XSS - CWE-79)
- File operations (Path traversal - CWE-22)
- HTTP requests (SSRF - CWE-918)
- Deserialization (Insecure deserialization - CWE-502)

## Sink Types

- SQL_QUERY: Database queries (query, execute, executeQuery)
- COMMAND_EXEC: Shell commands (exec, spawn, system)
- CODE_EXEC: Code evaluation (eval, Function, exec)
- DOM_WRITE: DOM manipulation (innerHTML, document.write)
- FILE_READ: File reading (readFile, open)
- FILE_WRITE: File writing (writeFile, save)
- URL_FETCH: HTTP requests (fetch, axios, requests.get)
- REDIRECT: URL redirects (response.redirect)
- DESERIALIZE: Deserialization (pickle.loads, JSON.parse of user data)

## High-Risk Indicators

Template literals in sink arguments are HIGH RISK:
- `query(\`SELECT * FROM users WHERE id = ${userId}\`)` - SQL injection
- `exec(\`rm ${filename}\`)` - Command injection

## Analysis Instructions

1. Identify what operation this function performs
2. Determine if user-controlled data in the arguments could be dangerous
3. Check for any sanitization or parameterization
4. Note the specific CWE types this sink could enable

## Response Format

Respond with a JSON object:
{
    "is_sink": true/false,
    "confidence": 0.0-1.0,
    "sink_type": "SQL_QUERY|COMMAND_EXEC|CODE_EXEC|...",
    "cwe_types": ["CWE-89"],
    "reasoning": "Chain-of-thought explanation",
    "sanitization_nearby": true/false
}"""


def build_sink_classification_prompt(
    expression: str,
    callee: str,
    code_context: str,
    language: str,
    line: int,
    uses_template_literal: bool,
    ast_sink_type: str,
) -> dict[str, str]:
    """
    Build a prompt for sink classification.

    Args:
        expression: The full call expression
        callee: The function/method being called (e.g., "query", "exec")
        code_context: ~50 lines of surrounding code
        language: Programming language
        line: Line number of the sink
        uses_template_literal: Whether arguments contain template literals
        ast_sink_type: Sink type detected by AST pattern matching

    Returns:
        Dict with system and user prompts
    """
    template_warning = ""
    if uses_template_literal:
        template_warning = """
**WARNING: HIGH RISK INDICATOR**
This sink uses a template literal in its arguments, which typically indicates
direct string interpolation of variables - a common vulnerability pattern.
"""

    user_prompt = f"""## Code Context
```{language}
{code_context}
```

## Call to Analyze
- Line: {line}
- Function: `{callee}`
- Expression: `{expression}`
- AST-detected type: {ast_sink_type}
- Uses template literal: {uses_template_literal}
{template_warning}

## Question
Is this function call a DANGEROUS SINK that could be exploited with untrusted input?

Analyze step by step:
1. What operation does this function perform?
2. Could user-controlled data in the arguments cause harm?
3. Is there any sanitization, validation, or parameterization?
4. What specific vulnerabilities (CWEs) could this enable?

Respond with JSON."""

    return {
        "system": TAINT_SINK_SYSTEM_PROMPT,
        "user": user_prompt,
    }


# =============================================================================
# Batch Classification Prompts (for efficiency)
# =============================================================================

BATCH_SOURCE_SYSTEM_PROMPT = """You are a security expert performing batch taint analysis.

Analyze multiple expressions and determine which ones are TAINT SOURCES (untrusted user input).

For each expression, provide:
- is_source: true/false
- confidence: 0.0-1.0
- source_type: The type of input source
- cwe_types: Relevant vulnerability types
- reasoning: Brief explanation

Respond with a JSON array of results, one per expression."""


def build_batch_source_prompt(
    sources: list[dict[str, Any]],
    language: str,
) -> dict[str, str]:
    """
    Build a prompt for batch source classification.

    Args:
        sources: List of source dicts with expression, line, code_context
        language: Programming language

    Returns:
        Dict with system and user prompts
    """
    items = []
    for i, source in enumerate(sources):
        items.append(f"""
## Expression {i + 1}
- Line: {source.get('line', '?')}
- Expression: `{source.get('expression', '')}`
- AST type: {source.get('ast_type', 'unknown')}
- Context:
```{language}
{source.get('code_context', '')[:500]}
```
""")

    user_prompt = f"""Analyze these {len(sources)} expressions and determine which are TAINT SOURCES:

{"".join(items)}

Respond with a JSON array:
[
    {{"is_source": true/false, "confidence": 0.X, "source_type": "...", "cwe_types": [...], "reasoning": "..."}},
    ...
]"""

    return {
        "system": BATCH_SOURCE_SYSTEM_PROMPT,
        "user": user_prompt,
    }


BATCH_SINK_SYSTEM_PROMPT = """You are a security expert performing batch taint analysis.

Analyze multiple function calls and determine which ones are DANGEROUS SINKS.

For each call, provide:
- is_sink: true/false
- confidence: 0.0-1.0
- sink_type: The type of dangerous operation
- cwe_types: Relevant vulnerability types
- reasoning: Brief explanation
- sanitization_nearby: true/false

Respond with a JSON array of results, one per call."""


def build_batch_sink_prompt(
    sinks: list[dict[str, Any]],
    language: str,
) -> dict[str, str]:
    """
    Build a prompt for batch sink classification.

    Args:
        sinks: List of sink dicts with callee, expression, line, code_context
        language: Programming language

    Returns:
        Dict with system and user prompts
    """
    items = []
    for i, sink in enumerate(sinks):
        template_warning = " **[TEMPLATE LITERAL - HIGH RISK]**" if sink.get('uses_template_literal') else ""
        items.append(f"""
## Call {i + 1}{template_warning}
- Line: {sink.get('line', '?')}
- Function: `{sink.get('callee', '')}`
- Expression: `{sink.get('expression', '')}`
- AST type: {sink.get('ast_type', 'unknown')}
- Context:
```{language}
{sink.get('code_context', '')[:500]}
```
""")

    user_prompt = f"""Analyze these {len(sinks)} function calls and determine which are DANGEROUS SINKS:

{"".join(items)}

Respond with a JSON array:
[
    {{"is_sink": true/false, "confidence": 0.X, "sink_type": "...", "cwe_types": [...], "reasoning": "...", "sanitization_nearby": false}},
    ...
]"""

    return {
        "system": BATCH_SINK_SYSTEM_PROMPT,
        "user": user_prompt,
    }


# =============================================================================
# Helper for parsing batch results
# =============================================================================

def parse_batch_results(
    json_str: str,
    expected_count: int,
    result_class: type,
) -> list:
    """
    Parse batch classification results from JSON string.

    Args:
        json_str: JSON string from LLM response
        expected_count: Expected number of results
        result_class: Either SourceClassificationResult or SinkClassificationResult

    Returns:
        List of classification results
    """
    try:
        # Try to extract JSON array from response
        json_match = re.search(r'\[[\s\S]*\]', json_str)
        if json_match:
            json_str = json_match.group()

        data = json.loads(json_str)

        if not isinstance(data, list):
            data = [data]

        results = []
        for item in data:
            if result_class == SourceClassificationResult:
                results.append(SourceClassificationResult(
                    is_source=item.get("is_source", False),
                    confidence=float(item.get("confidence", 0.5)),
                    source_type=item.get("source_type", "user_input"),
                    cwe_types=item.get("cwe_types", []),
                    reasoning=item.get("reasoning", ""),
                    sanitization_nearby=item.get("sanitization_nearby", False),
                ))
            else:
                results.append(SinkClassificationResult(
                    is_sink=item.get("is_sink", False),
                    confidence=float(item.get("confidence", 0.5)),
                    sink_type=item.get("sink_type", "dangerous_call"),
                    cwe_types=item.get("cwe_types", []),
                    reasoning=item.get("reasoning", ""),
                    sanitization_nearby=item.get("sanitization_nearby", False),
                ))

        # Pad with low-confidence defaults if needed
        while len(results) < expected_count:
            if result_class == SourceClassificationResult:
                results.append(SourceClassificationResult(
                    is_source=False,
                    confidence=0.3,
                    source_type="user_input",
                    cwe_types=[],
                    reasoning="No result from LLM",
                ))
            else:
                results.append(SinkClassificationResult(
                    is_sink=False,
                    confidence=0.3,
                    sink_type="dangerous_call",
                    cwe_types=[],
                    reasoning="No result from LLM",
                ))

        return results[:expected_count]

    except (json.JSONDecodeError, AttributeError, TypeError) as e:
        # Return low-confidence defaults on error
        results = []
        for _ in range(expected_count):
            if result_class == SourceClassificationResult:
                results.append(SourceClassificationResult(
                    is_source=False,
                    confidence=0.3,
                    source_type="user_input",
                    cwe_types=[],
                    reasoning=f"Parse error: {str(e)}",
                ))
            else:
                results.append(SinkClassificationResult(
                    is_sink=False,
                    confidence=0.3,
                    sink_type="dangerous_call",
                    cwe_types=[],
                    reasoning=f"Parse error: {str(e)}",
                ))
        return results
