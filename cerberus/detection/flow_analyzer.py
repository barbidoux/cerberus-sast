"""
Flow Analyzer for Phase III Detection.

Executes CPGQL queries against Joern and extracts data flow traces.
Converts raw query results into structured trace representations.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from cerberus.detection.joern_client import JoernClient, JoernConfig, QueryResult
from cerberus.detection.query_generator import CPGQLQuery
from cerberus.models.base import CodeLocation
from cerberus.models.finding import TraceStep


@dataclass
class FlowAnalyzerConfig:
    """Configuration for flow analysis."""

    max_flows_per_query: int = 100
    timeout: int = 60
    parallel_queries: bool = True
    max_concurrent: int = 5
    deduplicate_flows: bool = True


@dataclass
class DataFlow:
    """Represents a data flow from source to sink."""

    source_method: str
    sink_method: str
    source_location: CodeLocation
    sink_location: CodeLocation
    trace_steps: list[TraceStep] = field(default_factory=list)
    vulnerability_type: str = ""
    confidence: float = 0.8
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "source_method": self.source_method,
            "sink_method": self.sink_method,
            "source_location": self.source_location.to_dict(),
            "sink_location": self.sink_location.to_dict(),
            "trace_steps": [s.to_dict() for s in self.trace_steps],
            "vulnerability_type": self.vulnerability_type,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DataFlow":
        """Deserialize from dictionary."""
        return cls(
            source_method=data.get("source_method", ""),
            sink_method=data.get("sink_method", ""),
            source_location=CodeLocation.from_dict(data["source_location"]),
            sink_location=CodeLocation.from_dict(data["sink_location"]),
            trace_steps=[TraceStep.from_dict(s) for s in data.get("trace_steps", [])],
            vulnerability_type=data.get("vulnerability_type", ""),
            confidence=data.get("confidence", 0.8),
            metadata=data.get("metadata", {}),
        )

    def __hash__(self) -> int:
        """Make DataFlow hashable for deduplication."""
        return hash((
            self.source_method,
            self.sink_method,
            self.source_location.line,
            self.sink_location.line,
        ))

    def __eq__(self, other: object) -> bool:
        """Check equality for deduplication."""
        if not isinstance(other, DataFlow):
            return False
        return (
            self.source_method == other.source_method
            and self.sink_method == other.sink_method
            and self.source_location.line == other.source_location.line
            and self.sink_location.line == other.sink_location.line
        )


@dataclass
class FlowResult:
    """Result from analyzing a single query."""

    query: CPGQLQuery
    flows: list[DataFlow]
    success: bool
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def flow_count(self) -> int:
        """Get number of flows found."""
        return len(self.flows)

    def summary(self) -> dict[str, Any]:
        """Generate result summary."""
        return {
            "success": self.success,
            "flow_count": self.flow_count,
            "execution_time_ms": self.execution_time_ms,
            "source": self.query.source,
            "sink": self.query.sink,
            "vulnerability_type": self.query.vulnerability_type,
            "error": self.error,
        }


class FlowAnalyzer:
    """Analyzes data flows by executing CPGQL queries.

    Executes queries against Joern, parses results, and extracts
    structured trace information.
    """

    def __init__(
        self,
        config: Optional[FlowAnalyzerConfig] = None,
        joern_client: Optional[JoernClient] = None,
    ) -> None:
        """Initialize flow analyzer.

        Args:
            config: Analyzer configuration.
            joern_client: Joern client for query execution.
        """
        self.config = config or FlowAnalyzerConfig()
        self.joern_client = joern_client or JoernClient()

    async def analyze_query(self, query: CPGQLQuery) -> FlowResult:
        """Analyze a single CPGQL query.

        Args:
            query: The query to execute.

        Returns:
            FlowResult with extracted flows or error.
        """
        start_time = time.time()

        try:
            # Execute query
            result = await self.joern_client.query(query.query)

            if not result.success:
                return FlowResult(
                    query=query,
                    flows=[],
                    success=False,
                    error=result.error,
                    execution_time_ms=(time.time() - start_time) * 1000,
                )

            # Parse results
            flows = self._parse_flows(result, query)

            # Apply limits
            if len(flows) > self.config.max_flows_per_query:
                flows = flows[:self.config.max_flows_per_query]

            # Deduplicate if configured
            if self.config.deduplicate_flows:
                flows = list(set(flows))

            return FlowResult(
                query=query,
                flows=flows,
                success=True,
                execution_time_ms=(time.time() - start_time) * 1000,
            )

        except Exception as e:
            return FlowResult(
                query=query,
                flows=[],
                success=False,
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000,
            )

    async def analyze_queries(self, queries: list[CPGQLQuery]) -> list[FlowResult]:
        """Analyze multiple queries.

        Args:
            queries: List of queries to execute.

        Returns:
            List of FlowResults.
        """
        if not queries:
            return []

        if self.config.parallel_queries:
            return await self._analyze_parallel(queries)
        else:
            return await self._analyze_sequential(queries)

    async def _analyze_parallel(self, queries: list[CPGQLQuery]) -> list[FlowResult]:
        """Execute queries in parallel with concurrency limit."""
        semaphore = asyncio.Semaphore(self.config.max_concurrent)

        async def limited_analyze(query: CPGQLQuery) -> FlowResult:
            async with semaphore:
                return await self.analyze_query(query)

        tasks = [limited_analyze(q) for q in queries]
        return await asyncio.gather(*tasks)

    async def _analyze_sequential(self, queries: list[CPGQLQuery]) -> list[FlowResult]:
        """Execute queries sequentially."""
        results = []
        for query in queries:
            result = await self.analyze_query(query)
            results.append(result)
        return results

    def _parse_flows(self, result: QueryResult, query: CPGQLQuery) -> list[DataFlow]:
        """Parse Joern query result into DataFlow objects.

        Args:
            result: Raw query result.
            query: Original query for context.

        Returns:
            List of DataFlow objects.
        """
        flows = []

        try:
            data = result.to_json()
        except Exception:
            return flows

        for item in data:
            flow = self._parse_single_flow(item, query)
            if flow:
                flows.append(flow)

        return flows

    def _parse_single_flow(
        self,
        data: dict[str, Any],
        query: CPGQLQuery,
    ) -> Optional[DataFlow]:
        """Parse a single flow from Joern result.

        Args:
            data: Flow data from Joern.
            query: Original query.

        Returns:
            DataFlow or None if parsing fails.
        """
        try:
            source_data = data.get("source", {})
            sink_data = data.get("sink", {})
            trace_data = data.get("trace", [])

            # Extract source location
            source_file = source_data.get("file", "unknown")
            source_line = source_data.get("line", 0)
            source_location = CodeLocation(
                file_path=Path(source_file),
                line=source_line,
                column=0,
            )

            # Extract sink location
            sink_file = sink_data.get("file", source_file)
            sink_line = sink_data.get("line", 0)
            sink_location = CodeLocation(
                file_path=Path(sink_file),
                line=sink_line,
                column=0,
            )

            # Extract trace steps
            trace_steps = self._parse_trace_steps(trace_data, source_line, sink_line)

            return DataFlow(
                source_method=source_data.get("method", query.source),
                sink_method=sink_data.get("method", query.sink),
                source_location=source_location,
                sink_location=sink_location,
                trace_steps=trace_steps,
                vulnerability_type=query.vulnerability_type,
                confidence=query.confidence,
                metadata={
                    "query": query.query,
                    "sanitizers": query.sanitizers,
                },
            )

        except Exception:
            return None

    def _parse_trace_steps(
        self,
        trace_data: list[dict[str, Any]],
        source_line: int,
        sink_line: int,
    ) -> list[TraceStep]:
        """Parse trace steps from Joern trace data.

        Args:
            trace_data: Raw trace data.
            source_line: Source line number.
            sink_line: Sink line number.

        Returns:
            List of TraceStep objects.
        """
        steps = []

        for i, item in enumerate(trace_data):
            line = item.get("line", 0)
            code = item.get("code", "")
            file_path = item.get("file", "unknown")

            # Determine step type
            if i == 0 or line == source_line:
                step_type = "source"
                description = f"Source: data enters at line {line}"
            elif i == len(trace_data) - 1 or line == sink_line:
                step_type = "sink"
                description = f"Sink: data reaches sensitive operation at line {line}"
            else:
                step_type = "propagation"
                description = f"Data flows through line {line}"

            step = TraceStep(
                location=CodeLocation(
                    file_path=Path(file_path),
                    line=line,
                    column=0,
                ),
                code_snippet=code,
                description=description,
                step_type=step_type,
            )
            steps.append(step)

        return steps
