"""
Detection Engine for Phase III.

Orchestrates the full detection pipeline:
1. Generate CPGQL queries from specifications
2. Execute queries against Joern
3. Extract data flow traces
4. Generate program slices
5. Create Finding objects
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from cerberus.detection.flow_analyzer import (
    DataFlow,
    FlowAnalyzer,
    FlowAnalyzerConfig,
    FlowResult,
)
from cerberus.detection.joern_client import JoernClient, JoernConfig
from cerberus.detection.query_generator import (
    CPGQLQuery,
    QueryGenerator,
    QueryGeneratorConfig,
)
from cerberus.detection.slicer import ProgramSlicer, SlicerConfig, SliceResult
from cerberus.models.base import CodeLocation, Severity
from cerberus.models.finding import Finding, TraceStep
from cerberus.models.spec import DynamicSpec, TaintSpec


# Severity mapping for vulnerability types
SEVERITY_MAP = {
    "CWE-89": Severity.HIGH,      # SQL Injection
    "CWE-79": Severity.MEDIUM,    # XSS
    "CWE-78": Severity.CRITICAL,  # Command Injection
    "CWE-22": Severity.HIGH,      # Path Traversal
    "CWE-918": Severity.HIGH,     # SSRF
    "CWE-611": Severity.HIGH,     # XXE
    "CWE-502": Severity.CRITICAL, # Deserialization
    "CWE-94": Severity.CRITICAL,  # Code Injection
}


@dataclass
class DetectionConfig:
    """Configuration for detection engine."""

    parallel_queries: bool = True
    generate_slices: bool = True
    min_confidence: float = 0.5
    max_findings_per_vuln_type: int = 100
    timeout: int = 300


@dataclass
class DetectionResult:
    """Result from detection phase."""

    findings: list[Finding]
    flows_analyzed: int
    queries_executed: int
    success: bool
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        """Generate detection summary."""
        by_severity = {}
        by_type = {}

        for finding in self.findings:
            sev = finding.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1

            vtype = finding.vulnerability_type
            by_type[vtype] = by_type.get(vtype, 0) + 1

        return {
            "success": self.success,
            "total_findings": len(self.findings),
            "flows_analyzed": self.flows_analyzed,
            "queries_executed": self.queries_executed,
            "execution_time_ms": self.execution_time_ms,
            "by_severity": by_severity,
            "by_vulnerability_type": by_type,
            "error": self.error,
        }


class DetectionEngine:
    """Orchestrates Phase III detection pipeline.

    Coordinates query generation, flow analysis, and finding creation.
    """

    def __init__(
        self,
        config: Optional[DetectionConfig] = None,
        joern_client: Optional[JoernClient] = None,
        llm_gateway: Optional[Any] = None,
    ) -> None:
        """Initialize detection engine.

        Args:
            config: Detection configuration.
            joern_client: Joern client for CPG queries.
            llm_gateway: LLM gateway for query generation (optional).
        """
        self.config = config or DetectionConfig()
        self.joern_client = joern_client or JoernClient()
        self.llm_gateway = llm_gateway

        # Initialize sub-components
        self._query_generator = QueryGenerator(
            config=QueryGeneratorConfig(
                use_llm=llm_gateway is not None,
            )
        )
        self._flow_analyzer = FlowAnalyzer(
            config=FlowAnalyzerConfig(
                parallel_queries=self.config.parallel_queries,
            ),
            joern_client=self.joern_client,
        )
        self._slicer = ProgramSlicer(
            joern_client=self.joern_client,
        )

    async def detect(self, spec: DynamicSpec) -> DetectionResult:
        """Run detection on a dynamic specification.

        Args:
            spec: Dynamic specification from Phase II.

        Returns:
            DetectionResult with findings.
        """
        start_time = time.time()
        findings: list[Finding] = []
        queries_executed = 0
        flows_analyzed = 0

        try:
            # Check Joern availability
            if not await self.joern_client.is_available():
                return DetectionResult(
                    findings=[],
                    flows_analyzed=0,
                    queries_executed=0,
                    success=False,
                    error="Joern server unavailable or connection failed",
                    execution_time_ms=(time.time() - start_time) * 1000,
                )

            # Filter specs by confidence
            filtered_spec = self._filter_by_confidence(spec)

            # Generate queries
            queries = self._query_generator.generate_queries(filtered_spec)
            queries_executed = len(queries)

            if not queries:
                return DetectionResult(
                    findings=[],
                    flows_analyzed=0,
                    queries_executed=0,
                    success=True,
                    execution_time_ms=(time.time() - start_time) * 1000,
                    metadata={"message": "No queries generated - no matching source-sink pairs"},
                )

            # Execute queries and analyze flows
            flow_results = await self._flow_analyzer.analyze_queries(queries)

            # Collect all flows
            all_flows: list[tuple[DataFlow, CPGQLQuery]] = []
            for result in flow_results:
                if result.success:
                    for flow in result.flows:
                        all_flows.append((flow, result.query))

            flows_analyzed = len(all_flows)

            # Generate slices if configured
            slices: dict[DataFlow, SliceResult] = {}
            if self.config.generate_slices and all_flows:
                flows_only = [f for f, _ in all_flows]
                slice_results = await self._slicer.extract_slices(flows_only)
                for flow, slice_result in zip(flows_only, slice_results):
                    if slice_result.success:
                        slices[flow] = slice_result

            # Create findings
            for flow, query in all_flows:
                finding = self._create_finding(
                    flow=flow,
                    query=query,
                    spec=spec,
                    slice_result=slices.get(flow),
                )
                findings.append(finding)

                # Apply per-type limits
                type_count = sum(
                    1 for f in findings
                    if f.vulnerability_type == finding.vulnerability_type
                )
                if type_count >= self.config.max_findings_per_vuln_type:
                    break

            return DetectionResult(
                findings=findings,
                flows_analyzed=flows_analyzed,
                queries_executed=queries_executed,
                success=True,
                execution_time_ms=(time.time() - start_time) * 1000,
            )

        except Exception as e:
            return DetectionResult(
                findings=findings,
                flows_analyzed=flows_analyzed,
                queries_executed=queries_executed,
                success=False,
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000,
            )

    def _filter_by_confidence(self, spec: DynamicSpec) -> DynamicSpec:
        """Filter specification by confidence threshold.

        Args:
            spec: Original specification.

        Returns:
            Filtered specification.
        """
        filtered = DynamicSpec(
            repository=spec.repository,
            version=spec.version,
            generated_at=spec.generated_at,
            metadata=spec.metadata,
        )

        for source in spec.sources:
            if source.confidence >= self.config.min_confidence:
                filtered.add_source(source)

        for sink in spec.sinks:
            if sink.confidence >= self.config.min_confidence:
                filtered.add_sink(sink)

        for sanitizer in spec.sanitizers:
            if sanitizer.confidence >= self.config.min_confidence:
                filtered.add_sanitizer(sanitizer)

        for propagator in spec.propagators:
            if propagator.confidence >= self.config.min_confidence:
                filtered.add_propagator(propagator)

        return filtered

    def _create_finding(
        self,
        flow: DataFlow,
        query: CPGQLQuery,
        spec: DynamicSpec,
        slice_result: Optional[SliceResult] = None,
    ) -> Finding:
        """Create a Finding from a data flow.

        Args:
            flow: The detected data flow.
            query: The query that found this flow.
            spec: The specification used.
            slice_result: Optional program slice.

        Returns:
            Finding object.
        """
        # Get source and sink specs
        source_spec = spec.get_by_method(flow.source_method)
        sink_spec = spec.get_by_method(flow.sink_method)

        # Determine severity
        severity = SEVERITY_MAP.get(flow.vulnerability_type, Severity.MEDIUM)

        # Convert flow trace to Finding trace
        trace = [
            TraceStep(
                location=step.location,
                code_snippet=step.code_snippet,
                description=step.description,
                step_type=step.step_type,
            )
            for step in flow.trace_steps
        ]

        finding = Finding(
            vulnerability_type=flow.vulnerability_type,
            severity=severity,
            confidence=flow.confidence,
            source=source_spec,
            sink=sink_spec,
            trace=trace,
            slice=slice_result.slice if slice_result and slice_result.success else None,
            title=self._generate_title(flow),
            description=self._generate_description(flow),
            remediation=self._generate_remediation(flow.vulnerability_type),
            metadata={
                "query": query.query,
                "source_method": flow.source_method,
                "sink_method": flow.sink_method,
            },
        )

        return finding

    def _generate_title(self, flow: DataFlow) -> str:
        """Generate finding title."""
        vuln_names = {
            "CWE-89": "SQL Injection",
            "CWE-79": "Cross-Site Scripting (XSS)",
            "CWE-78": "Command Injection",
            "CWE-22": "Path Traversal",
            "CWE-918": "Server-Side Request Forgery (SSRF)",
        }
        vuln_name = vuln_names.get(flow.vulnerability_type, flow.vulnerability_type)
        return f"{vuln_name} via {flow.source_method} to {flow.sink_method}"

    def _generate_description(self, flow: DataFlow) -> str:
        """Generate finding description."""
        return (
            f"Potential {flow.vulnerability_type} vulnerability detected. "
            f"Tainted data flows from '{flow.source_method}' "
            f"(line {flow.source_location.line}) to '{flow.sink_method}' "
            f"(line {flow.sink_location.line}) without proper sanitization."
        )

    def _generate_remediation(self, vuln_type: str) -> str:
        """Generate remediation guidance."""
        remediation_map = {
            "CWE-89": (
                "Use parameterized queries or prepared statements. "
                "Never concatenate user input directly into SQL queries."
            ),
            "CWE-79": (
                "Encode output for the appropriate context (HTML, JavaScript, URL). "
                "Use a Content Security Policy (CSP)."
            ),
            "CWE-78": (
                "Avoid passing user input to system commands. "
                "If necessary, use allowlists and strict input validation."
            ),
            "CWE-22": (
                "Validate and sanitize file paths. "
                "Use a whitelist of allowed paths and canonicalize inputs."
            ),
            "CWE-918": (
                "Validate and sanitize URLs. "
                "Use allowlists for permitted hosts and protocols."
            ),
        }
        return remediation_map.get(
            vuln_type,
            "Review the data flow and apply appropriate input validation and output encoding."
        )
