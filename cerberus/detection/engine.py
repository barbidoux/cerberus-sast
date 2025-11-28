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

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

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
from cerberus.models.repo_map import RepoMap
from cerberus.models.spec import DynamicSpec, TaintSpec
from cerberus.models.taint_flow import TaintFlowCandidate, TaintSource, TaintSink


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
        llm_classifier: Optional[Any] = None,  # Milestone 8: LLM Classifier
    ) -> None:
        """Initialize detection engine.

        Args:
            config: Detection configuration.
            joern_client: Joern client for CPG queries.
            llm_gateway: LLM gateway for query generation (optional).
            llm_classifier: LLM classifier for taint validation (optional).
        """
        self.config = config or DetectionConfig()
        self.joern_client = joern_client or JoernClient()
        self.llm_gateway = llm_gateway
        self._classifier = llm_classifier  # Milestone 8

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
            # Check Joern availability - if not available, use LLM-based detection
            joern_available = await self.joern_client.is_available()
            if not joern_available:
                # Fallback to LLM-based detection for V1 validation
                return await self._detect_without_cpg(spec, start_time)

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

            # If no flows found but we have source-sink pairs, create CPG-verified findings
            # This handles cases where Python CPG doesn't support inter-procedural data flow
            if flows_analyzed == 0 and queries:
                cpg_verified_findings = await self._create_cpg_verified_findings(
                    spec=filtered_spec,
                    queries=queries,
                )
                if cpg_verified_findings:
                    return DetectionResult(
                        findings=cpg_verified_findings,
                        flows_analyzed=0,
                        queries_executed=queries_executed,
                        success=True,
                        execution_time_ms=(time.time() - start_time) * 1000,
                        metadata={"detection_mode": "cpg_verified_spec"},
                    )

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

    async def _create_cpg_verified_findings(
        self,
        spec: DynamicSpec,
        queries: list[CPGQLQuery],
    ) -> list[Finding]:
        """Create findings by verifying source-sink pairs exist in CPG.

        This fallback is used when inter-procedural data flow analysis returns no flows,
        which can happen with Python CPG due to limited data flow support.

        Args:
            spec: Dynamic specification with sources and sinks.
            queries: Generated queries (for source-sink pairing info).

        Returns:
            List of CPG-verified findings.
        """
        findings: list[Finding] = []
        verified_pairs: set[tuple[str, str]] = set()

        # Verify each source-sink pair exists in the CPG
        for query in queries:
            pair_key = (query.source, query.sink)
            if pair_key in verified_pairs:
                continue

            # Check source exists in CPG
            source_result = await self.joern_client.query(
                f'cpg.method.name("{query.source}").l.size'
            )
            source_exists = self._parse_count_result(source_result) > 0

            # Check sink exists in CPG (as method or call)
            sink_result = await self.joern_client.query(
                f'cpg.method.name("{query.sink}").l.size + cpg.call.filter(_.code.contains("{query.sink}")).l.size'
            )
            sink_exists = self._parse_count_result(sink_result) > 0

            if source_exists and sink_exists:
                verified_pairs.add(pair_key)

                # Get source and sink specs
                source_spec = spec.get_by_method(query.source)
                sink_spec = spec.get_by_method(query.sink)

                if not source_spec or not sink_spec:
                    continue

                # Determine severity
                severity = SEVERITY_MAP.get(query.vulnerability_type, Severity.MEDIUM)

                # Create finding
                finding = Finding(
                    vulnerability_type=query.vulnerability_type,
                    severity=severity,
                    confidence=min(source_spec.confidence, sink_spec.confidence) * 0.9,  # Slightly lower for spec-based
                    source=source_spec,
                    sink=sink_spec,
                    trace=[
                        TraceStep(
                            location=CodeLocation(
                                file_path=source_spec.file_path,
                                line=source_spec.line,
                                column=0,
                            ),
                            code_snippet=f"Source: {query.source}",
                            description=f"Tainted data enters from {query.source}",
                            step_type="source",
                        ),
                        TraceStep(
                            location=CodeLocation(
                                file_path=sink_spec.file_path,
                                line=sink_spec.line,
                                column=0,
                            ),
                            code_snippet=f"Sink: {query.sink}",
                            description=f"Tainted data reaches dangerous sink {query.sink}",
                            step_type="sink",
                        ),
                    ],
                    title=self._generate_title_from_spec(query.vulnerability_type, query.source, query.sink),
                    description=self._generate_description_from_spec(query.vulnerability_type, query.source, query.sink),
                    remediation=self._generate_remediation(query.vulnerability_type),
                    metadata={
                        "detection_mode": "cpg_verified_spec",
                        "source_method": query.source,
                        "sink_method": query.sink,
                        "source_confidence": source_spec.confidence,
                        "sink_confidence": sink_spec.confidence,
                    },
                )
                findings.append(finding)

        return findings

    def _generate_title_from_spec(self, vuln_type: str, source: str, sink: str) -> str:
        """Generate finding title from spec."""
        vuln_names = {
            "CWE-89": "SQL Injection",
            "CWE-79": "Cross-Site Scripting (XSS)",
            "CWE-78": "Command Injection",
            "CWE-22": "Path Traversal",
            "CWE-918": "Server-Side Request Forgery (SSRF)",
            "CWE-94": "Code Injection",
            "CWE-502": "Insecure Deserialization",
        }
        vuln_name = vuln_names.get(vuln_type, vuln_type)
        return f"Potential {vuln_name}: {source} → {sink}"

    def _generate_description_from_spec(self, vuln_type: str, source: str, sink: str) -> str:
        """Generate finding description from spec."""
        return (
            f"Potential {vuln_type} vulnerability detected. "
            f"Data from '{source}' may flow to dangerous sink '{sink}' "
            f"without proper sanitization. This finding is based on LLM semantic analysis "
            f"verified against the Code Property Graph."
        )

    async def _detect_without_cpg(
        self,
        spec: DynamicSpec,
        start_time: float,
    ) -> DetectionResult:
        """Run detection without CPG (Joern unavailable).

        Creates findings based purely on LLM semantic analysis.
        This is the "trust LLM" mode - used when Joern is unavailable
        or for languages with limited CPG support.

        Args:
            spec: Dynamic specification from Phase II.
            start_time: Detection start time.

        Returns:
            DetectionResult with LLM-based findings.
        """
        findings: list[Finding] = []

        # Filter specs by confidence
        filtered_spec = self._filter_by_confidence(spec)

        # Get source-sink pairs using query generator
        pairs = self._query_generator.get_source_sink_pairs(
            filtered_spec, include_sanitizers=True
        )

        if not pairs:
            return DetectionResult(
                findings=[],
                flows_analyzed=0,
                queries_executed=0,
                success=True,
                execution_time_ms=(time.time() - start_time) * 1000,
                metadata={
                    "detection_mode": "llm_trust",
                    "message": "No source-sink pairs found",
                    "joern_available": False,
                },
            )

        # Create findings for each source-sink pair
        for pair in pairs:
            source, sink, vuln_type = pair[0], pair[1], pair[2]
            sanitizers = pair[3] if len(pair) > 3 else []

            # Skip if sanitizer exists for this vulnerability type
            if sanitizers:
                # There's a sanitizer, reduce confidence
                confidence = min(source.confidence, sink.confidence) * 0.5
            else:
                # No sanitizer, use combined confidence
                confidence = min(source.confidence, sink.confidence) * 0.85

            # Skip low confidence findings
            if confidence < self.config.min_confidence:
                continue

            # Determine severity
            severity = SEVERITY_MAP.get(vuln_type, Severity.MEDIUM)

            # Create finding
            finding = Finding(
                vulnerability_type=vuln_type,
                severity=severity,
                confidence=confidence,
                source=source,
                sink=sink,
                trace=[
                    TraceStep(
                        location=CodeLocation(
                            file_path=source.file_path,
                            line=source.line,
                            column=0,
                        ),
                        code_snippet=f"Source: {source.method}",
                        description=f"Tainted data enters from {source.method}",
                        step_type="source",
                    ),
                    TraceStep(
                        location=CodeLocation(
                            file_path=sink.file_path,
                            line=sink.line,
                            column=0,
                        ),
                        code_snippet=f"Sink: {sink.method}",
                        description=f"Tainted data reaches dangerous sink {sink.method}",
                        step_type="sink",
                    ),
                ],
                title=self._generate_title_from_spec(vuln_type, source.method, sink.method),
                description=self._generate_description_llm_trust(
                    vuln_type, source.method, sink.method, bool(sanitizers)
                ),
                remediation=self._generate_remediation(vuln_type),
                metadata={
                    "detection_mode": "llm_trust",
                    "source_method": source.method,
                    "sink_method": sink.method,
                    "source_confidence": source.confidence,
                    "sink_confidence": sink.confidence,
                    "has_sanitizer": bool(sanitizers),
                    "joern_available": False,
                },
            )
            findings.append(finding)

            # Apply per-type limits
            type_count = sum(
                1 for f in findings
                if f.vulnerability_type == vuln_type
            )
            if type_count >= self.config.max_findings_per_vuln_type:
                continue

        return DetectionResult(
            findings=findings,
            flows_analyzed=0,
            queries_executed=0,
            success=True,
            execution_time_ms=(time.time() - start_time) * 1000,
            metadata={
                "detection_mode": "llm_trust",
                "joern_available": False,
                "pairs_analyzed": len(pairs),
            },
        )

    def _generate_description_llm_trust(
        self,
        vuln_type: str,
        source: str,
        sink: str,
        has_sanitizer: bool,
    ) -> str:
        """Generate finding description for LLM-trust mode."""
        base = (
            f"Potential {vuln_type} vulnerability detected through semantic analysis. "
            f"Data from '{source}' may flow to dangerous sink '{sink}'. "
        )
        if has_sanitizer:
            base += (
                "A potential sanitizer was identified, reducing confidence. "
                "Manual verification is strongly recommended."
            )
        else:
            base += (
                "No sanitizer was identified in the data flow. "
                "This finding is based on LLM semantic analysis without CPG verification."
            )
        return base

    def _parse_count_result(self, result: Any) -> int:
        """Parse count from Joern query result.

        Handles ANSI escape codes in output like:
        '[33mval[0m [36mres23[0m: [32mInt[0m = 1\n'

        Args:
            result: QueryResult from Joern.

        Returns:
            Parsed integer count or 0 if parsing fails.
        """
        import re

        if not result.success or not result.data:
            return 0

        try:
            # Remove ANSI escape codes
            clean = re.sub(r'\x1b\[[0-9;]*m', '', result.data)
            # Find the integer value after '= '
            match = re.search(r'=\s*(\d+)', clean)
            if match:
                return int(match.group(1))
        except (ValueError, AttributeError):
            pass

        return 0

    # ========== Milestone 7: Hybrid Detection ==========

    async def detect_hybrid(
        self,
        repo_map: RepoMap,
        require_joern: bool = True,
        use_llm: bool = True,  # Milestone 8: Enable LLM classification
    ) -> DetectionResult:
        """
        Hybrid detection: Tree-sitter AST extraction + LLM classification + Joern CPG validation.

        This method implements Milestone 7 + 8 - Neuro-Symbolic taint analysis:
        - Phase I: AST extraction of sources/sinks (Tree-sitter)
        - Phase II: LLM classification to validate and enrich (NEW - Milestone 8)
        - Phase III: Flow candidate creation + CPG validation (Joern or heuristics)
        - Phase IV: Finding generation with LLM reasoning

        Args:
            repo_map: Repository map from Phase I
            require_joern: If True, fail if Joern unavailable. If False, use heuristics.
            use_llm: If True, use LLM to validate AST-extracted sources/sinks.

        Returns:
            DetectionResult with findings from hybrid detection.
        """
        from cerberus.context.taint_extractor import TaintExtractor
        from cerberus.detection.js_queries import JavaScriptQueryGenerator

        start_time = time.time()
        findings: list[Finding] = []
        llm_calls = 0

        try:
            # Step 1: Extract taint sources and sinks from all supported files
            extractor = TaintExtractor()
            all_sources: list[TaintSource] = []
            all_sinks: list[TaintSink] = []

            for file_info in repo_map.files:
                if file_info.language in extractor.supported_languages:
                    sources, sinks = extractor.extract_from_file(file_info.path)
                    all_sources.extend(sources)
                    all_sinks.extend(sinks)

            if not all_sources or not all_sinks:
                return DetectionResult(
                    findings=[],
                    flows_analyzed=0,
                    queries_executed=0,
                    success=True,
                    execution_time_ms=(time.time() - start_time) * 1000,
                    metadata={
                        "detection_mode": "hybrid",
                        "sources_found": len(all_sources),
                        "sinks_found": len(all_sinks),
                        "llm_calls": 0,
                        "message": "No source-sink pairs found by AST extraction",
                    },
                )

            # Step 2: LLM Classification (Milestone 8 - Neuro-Symbolic)
            if use_llm and self._classifier:
                validated_sources = await self._classify_sources_with_llm(all_sources)
                validated_sinks = await self._classify_sinks_with_llm(all_sinks)
                llm_calls = len(all_sources) + len(all_sinks)
                mode_suffix = "_llm"
            else:
                # Skip LLM - use all AST-extracted sources/sinks
                validated_sources = all_sources
                validated_sinks = all_sinks
                mode_suffix = ""

            if not validated_sources or not validated_sinks:
                return DetectionResult(
                    findings=[],
                    flows_analyzed=0,
                    queries_executed=0,
                    success=True,
                    execution_time_ms=(time.time() - start_time) * 1000,
                    metadata={
                        "detection_mode": f"hybrid{mode_suffix}",
                        "sources_extracted": len(all_sources),
                        "sources_validated": len(validated_sources),
                        "sinks_extracted": len(all_sinks),
                        "sinks_validated": len(validated_sinks),
                        "llm_calls": llm_calls,
                        "message": "No sources/sinks passed LLM validation",
                    },
                )

            # Step 3: Create flow candidates from LLM-validated sources/sinks
            candidates = extractor.create_flow_candidates(validated_sources, validated_sinks)

            if not candidates:
                return DetectionResult(
                    findings=[],
                    flows_analyzed=0,
                    queries_executed=0,
                    success=True,
                    execution_time_ms=(time.time() - start_time) * 1000,
                    metadata={
                        "detection_mode": f"hybrid{mode_suffix}",
                        "sources_extracted": len(all_sources),
                        "sources_validated": len(validated_sources),
                        "sinks_extracted": len(all_sinks),
                        "sinks_validated": len(validated_sinks),
                        "llm_calls": llm_calls,
                        "message": "No matching CWE types between sources and sinks",
                    },
                )

            # Step 4: Validate candidates with CPG or heuristics
            joern_available = await self.joern_client.is_available()

            if joern_available:
                validated = await self._validate_with_joern(candidates)
                mode = f"hybrid_cpg{mode_suffix}"
            elif require_joern:
                # Joern required but not available
                return DetectionResult(
                    findings=[],
                    flows_analyzed=0,
                    queries_executed=0,
                    success=False,
                    error="Joern CPG server is not available and require_joern=True",
                    execution_time_ms=(time.time() - start_time) * 1000,
                    metadata={"detection_mode": "hybrid_failed", "llm_calls": llm_calls},
                )
            else:
                # Use heuristic fallback
                validated = self._validate_heuristic(candidates)
                mode = f"hybrid_heuristic{mode_suffix}"

            # Step 5: Convert validated candidates to findings
            for candidate in validated:
                if candidate.confidence >= self.config.min_confidence:
                    finding = self._candidate_to_finding(candidate)
                    findings.append(finding)

            return DetectionResult(
                findings=findings,
                flows_analyzed=len(candidates),
                queries_executed=len(validated) if joern_available else 0,
                success=True,
                execution_time_ms=(time.time() - start_time) * 1000,
                metadata={
                    "detection_mode": mode,
                    "sources_extracted": len(all_sources),
                    "sources_validated": len(validated_sources),
                    "sinks_extracted": len(all_sinks),
                    "sinks_validated": len(validated_sinks),
                    "candidates_created": len(candidates),
                    "candidates_validated": len(validated),
                    "joern_available": joern_available,
                    "llm_calls": llm_calls,
                },
            )

        except Exception as e:
            return DetectionResult(
                findings=findings,
                flows_analyzed=0,
                queries_executed=0,
                success=False,
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000,
                metadata={"detection_mode": "hybrid_error", "llm_calls": llm_calls},
            )

    async def _validate_with_joern(
        self,
        candidates: list[TaintFlowCandidate],
    ) -> list[TaintFlowCandidate]:
        """
        Validate flow candidates using Joern CPG.

        Args:
            candidates: List of flow candidates to validate

        Returns:
            List of validated candidates with updated confidence
        """
        from cerberus.detection.js_queries import JavaScriptQueryGenerator
        from cerberus.models.taint_flow import FlowTraceStep

        validated: list[TaintFlowCandidate] = []

        for candidate in candidates:
            # Generate reachability query
            query = JavaScriptQueryGenerator.generate_reachability_query(
                source_line=candidate.source.line,
                sink_line=candidate.sink.line,
                file=candidate.source.file_path.name,
            )

            # Execute query
            result = await self.joern_client.query(query)

            if result.success and result.data:
                # Parse result for flow validation
                try:
                    import json
                    # Try to parse JSON from result
                    data = json.loads(result.data) if isinstance(result.data, str) else result.data
                    if data and isinstance(data, list) and len(data) > 0:
                        # Flow validated by CPG
                        trace_steps = []
                        if "trace" in data[0]:
                            for step in data[0]["trace"]:
                                trace_steps.append(FlowTraceStep(
                                    line=step.get("line", -1),
                                    code=step.get("code", ""),
                                ))
                        candidate.apply_cpg_validation(trace_steps)
                        validated.append(candidate)
                        continue
                except (json.JSONDecodeError, TypeError, KeyError):
                    pass

            # If Joern validation inconclusive, fall back to heuristics
            candidate.apply_heuristic_scoring()
            if candidate.confidence >= self.config.min_confidence:
                validated.append(candidate)

        return validated

    def _validate_heuristic(
        self,
        candidates: list[TaintFlowCandidate],
    ) -> list[TaintFlowCandidate]:
        """
        Validate flow candidates using heuristics (when Joern unavailable).

        Heuristic scoring:
        - Same function: +0.3 confidence
        - Template literal: +0.4 confidence
        - Line proximity (<10): +0.2 confidence
        - Same file: +0.1 confidence

        Args:
            candidates: List of flow candidates

        Returns:
            List of validated candidates with heuristic scores
        """
        validated: list[TaintFlowCandidate] = []

        for candidate in candidates:
            candidate.apply_heuristic_scoring()
            if candidate.confidence >= self.config.min_confidence:
                validated.append(candidate)

        return validated

    def _candidate_to_finding(self, candidate: TaintFlowCandidate) -> Finding:
        """
        Convert a validated TaintFlowCandidate to a Finding.

        Args:
            candidate: Validated flow candidate

        Returns:
            Finding object
        """
        # Determine primary CWE type
        vuln_type = candidate.primary_cwe or "CWE-000"
        severity = SEVERITY_MAP.get(vuln_type, Severity.MEDIUM)

        # Create trace steps
        trace = [
            TraceStep(
                location=CodeLocation(
                    file_path=candidate.source.file_path,
                    line=candidate.source.line,
                    column=candidate.source.column,
                ),
                code_snippet=candidate.source.expression[:100],
                description=f"Tainted data from {candidate.source.source_type.value}",
                step_type="source",
                variable=candidate.source.variable_name,
            ),
        ]

        # Add Joern trace steps if available
        for step in candidate.joern_trace:
            trace.append(TraceStep(
                location=CodeLocation(
                    file_path=candidate.source.file_path,
                    line=step.line,
                    column=step.column,
                ),
                code_snippet=step.code[:100] if step.code else "",
                description="Data propagation",
                step_type="propagation",
            ))

        # Add sink step
        trace.append(TraceStep(
            location=CodeLocation(
                file_path=candidate.sink.file_path,
                line=candidate.sink.line,
                column=candidate.sink.column,
            ),
            code_snippet=candidate.sink.expression[:100],
            description=f"Dangerous sink: {candidate.sink.callee}()",
            step_type="sink",
        ))

        # Generate title and description
        vuln_names = {
            "CWE-89": "SQL Injection",
            "CWE-79": "Cross-Site Scripting (XSS)",
            "CWE-78": "Command Injection",
            "CWE-22": "Path Traversal",
            "CWE-918": "Server-Side Request Forgery (SSRF)",
            "CWE-94": "Code Injection",
        }
        vuln_name = vuln_names.get(vuln_type, vuln_type)

        title = f"{vuln_name}: {candidate.source.expression[:30]} → {candidate.sink.callee}()"

        description = (
            f"Potential {vuln_name} vulnerability detected. "
            f"User input from '{candidate.source.expression}' "
            f"flows to dangerous sink '{candidate.sink.callee}()' "
            f"at line {candidate.sink.line}."
        )

        if candidate.sink.uses_template_literal:
            description += (
                " HIGH RISK: The sink uses a template literal, "
                "indicating direct string interpolation of user input."
            )

        # Create TaintSpec for source and sink
        source_spec = TaintSpec(
            method=candidate.source.expression,
            file_path=candidate.source.file_path,
            line=candidate.source.line,
            label="source",
            confidence=candidate.source.confidence,
            vulnerability_types=candidate.source.cwe_types,
        )

        sink_spec = TaintSpec(
            method=candidate.sink.callee,
            file_path=candidate.sink.file_path,
            line=candidate.sink.line,
            label="sink",
            confidence=candidate.sink.confidence,
            vulnerability_types=candidate.sink.cwe_types,
        )

        return Finding(
            vulnerability_type=vuln_type,
            severity=severity,
            confidence=candidate.confidence,
            source=source_spec,
            sink=sink_spec,
            trace=trace,
            title=title,
            description=description,
            remediation=self._generate_remediation(vuln_type),
            metadata={
                "detection_mode": candidate.detection_mode,
                "confidence_factors": candidate.confidence_factors,
                "in_same_function": candidate.in_same_function,
                "uses_template_literal": candidate.sink.uses_template_literal,
                "joern_validated": candidate.joern_validated,
                "source_type": candidate.source.source_type.value,
                "sink_type": candidate.sink.sink_type.value,
                # Milestone 8: LLM reasoning
                "source_llm_reasoning": candidate.source.llm_reasoning,
                "sink_llm_reasoning": candidate.sink.llm_reasoning,
            },
        )

    # =========================================================================
    # Milestone 8: LLM Classification Methods
    # =========================================================================

    async def _classify_sources_with_llm(
        self,
        sources: list[TaintSource],
    ) -> list[TaintSource]:
        """
        Use LLM to validate and enrich AST-detected sources.

        This implements the Neuro-Symbolic approach: AST finds candidates,
        LLM reasons about whether they're truly taint sources.

        Args:
            sources: List of AST-extracted TaintSource objects

        Returns:
            List of validated TaintSource objects with LLM enrichment
        """
        if not self._classifier:
            return sources  # No classifier, return all sources

        validated: list[TaintSource] = []

        for source in sources:
            # Get code context (~50 lines around source)
            code_context = self._get_code_context(source.file_path, source.line, 25)

            # Classify with LLM
            result = await self._classifier.classify_taint_source(
                source=source,
                code_context=code_context,
                language=source.language,
            )

            if result.is_source and result.confidence >= self.config.min_confidence:
                # Update source with LLM enrichment
                source.confidence = result.confidence
                source.cwe_types = result.cwe_types if result.cwe_types else source.cwe_types
                source.llm_reasoning = result.reasoning
                source.llm_validated = True
                validated.append(source)

        return validated

    async def _classify_sinks_with_llm(
        self,
        sinks: list[TaintSink],
    ) -> list[TaintSink]:
        """
        Use LLM to validate and enrich AST-detected sinks.

        This implements the Neuro-Symbolic approach: AST finds candidates,
        LLM reasons about whether they're truly dangerous sinks.

        Args:
            sinks: List of AST-extracted TaintSink objects

        Returns:
            List of validated TaintSink objects with LLM enrichment
        """
        if not self._classifier:
            return sinks  # No classifier, return all sinks

        validated: list[TaintSink] = []

        for sink in sinks:
            # Get code context (~50 lines around sink)
            code_context = self._get_code_context(sink.file_path, sink.line, 25)

            # Classify with LLM
            result = await self._classifier.classify_taint_sink(
                sink=sink,
                code_context=code_context,
                language=sink.language,
            )

            if result.is_sink and result.confidence >= self.config.min_confidence:
                # Update sink with LLM enrichment
                sink.confidence = result.confidence
                sink.cwe_types = result.cwe_types if result.cwe_types else sink.cwe_types
                sink.llm_reasoning = result.reasoning
                sink.llm_validated = True

                # Reduce confidence if sanitization detected nearby
                if result.sanitization_nearby:
                    sink.confidence *= 0.5

                validated.append(sink)

        return validated

    def _get_code_context(
        self,
        file_path: Path,
        center_line: int,
        context_lines: int = 25,
    ) -> str:
        """
        Extract code context around a specific line.

        Args:
            file_path: Path to the source file
            center_line: Line number to center context around
            context_lines: Number of lines before and after

        Returns:
            String with code context
        """
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            start = max(0, center_line - context_lines - 1)
            end = min(len(lines), center_line + context_lines)

            context_lines_list = []
            for i in range(start, end):
                line_num = i + 1
                context_lines_list.append(f"{line_num:4d}| {lines[i].rstrip()}")

            return "\n".join(context_lines_list)

        except Exception:
            return f"// Unable to read context from {file_path}"

    # =========================================================================
    # Milestone 11: ML-Enhanced Hybrid Detection
    # =========================================================================

    async def detect_hybrid_ml(
        self,
        repo_map: RepoMap,
        require_joern: bool = False,
        skip_tier3_llm: bool = False,
    ) -> DetectionResult:
        """
        ML-enhanced hybrid detection: 3-tier pipeline for maximum accuracy.

        This method implements Milestone 11 - ML-Enhanced Neuro-Symbolic analysis:
        - Tier 1: Pattern-based pre-filter (fast, filters ~70%)
        - Tier 2: CodeBERT classifier (fast ML, ~50ms per candidate)
        - Tier 3: LLM reasoning (only for uncertain cases, ~15%)

        Use skip_tier3_llm=True for fast mode (Tier 1+2 only, no LLM calls).

        Expected performance:
        - True Positive Rate: >90%
        - False Positive Rate: <10%
        - Speed: 6-10x faster than LLM-only

        Args:
            repo_map: Repository map from Phase I
            require_joern: If True, use Joern for CPG validation

        Returns:
            DetectionResult with findings from ML-enhanced detection.
        """
        from cerberus.context.taint_extractor import TaintExtractor
        from cerberus.ml import Tier1Filter, CodeBERTClassifier

        start_time = time.time()
        findings: list[Finding] = []

        # Metrics tracking
        metrics = {
            "candidates_created": 0,
            "tier1_high_conf": 0,
            "tier1_filtered": 0,
            "tier2_vulnerable": 0,
            "tier2_safe": 0,
            "tier2_uncertain": 0,
            "tier3_llm_calls": 0,
            "final_findings": 0,
        }

        try:
            # ========== PHASE I: AST EXTRACTION ==========
            extractor = TaintExtractor()
            all_sources: list[TaintSource] = []
            all_sinks: list[TaintSink] = []

            for file_info in repo_map.files:
                if file_info.language in extractor.supported_languages:
                    sources, sinks = extractor.extract_from_file(file_info.path)
                    all_sources.extend(sources)
                    all_sinks.extend(sinks)

            if not all_sources or not all_sinks:
                return DetectionResult(
                    findings=[],
                    flows_analyzed=0,
                    queries_executed=0,
                    success=True,
                    execution_time_ms=(time.time() - start_time) * 1000,
                    metadata={
                        "detection_mode": "hybrid_ml",
                        "message": "No source-sink pairs found",
                        **metrics,
                    },
                )

            # Create initial flow candidates
            candidates = extractor.create_flow_candidates(all_sources, all_sinks)
            metrics["candidates_created"] = len(candidates)

            if not candidates:
                return DetectionResult(
                    findings=[],
                    flows_analyzed=0,
                    queries_executed=0,
                    success=True,
                    execution_time_ms=(time.time() - start_time) * 1000,
                    metadata={
                        "detection_mode": "hybrid_ml",
                        "message": "No matching candidates",
                        **metrics,
                    },
                )

            # ========== TIER 1: PATTERN-BASED PRE-FILTER ==========
            # Extract unique languages from repo_map for rule loading
            detected_languages = list(set(
                f.language for f in repo_map.files if f.language
            ))
            tier1_filter = Tier1Filter(languages=detected_languages)
            filter_result = tier1_filter.filter_candidates(candidates)

            metrics["tier1_high_conf"] = filter_result.high_confidence_count
            metrics["tier1_filtered"] = filter_result.filtered_count

            # High confidence candidates go directly to findings
            confirmed_candidates = list(filter_result.high_confidence)

            # ========== TIER 2: CODEBERT CLASSIFIER ==========
            if filter_result.needs_ml_review:
                codebert = CodeBERTClassifier()

                # Track if using fallback mode
                if not codebert.is_available():
                    metrics["ml_fallback_mode"] = True
                    logger.warning(
                        "CodeBERT model not available - using heuristic fallback. "
                        "Install PyTorch for better accuracy: pip install torch transformers"
                    )
                else:
                    metrics["ml_fallback_mode"] = False

                ml_results = codebert.classify_batch(filter_result.needs_ml_review)

                needs_llm: list[TaintFlowCandidate] = []

                for result in ml_results:
                    if result.decision == "vulnerable":
                        result.candidate.confidence = result.confidence
                        result.candidate.ml_reasoning = result.reasoning
                        confirmed_candidates.append(result.candidate)
                        metrics["tier2_vulnerable"] += 1
                    elif result.decision == "safe":
                        metrics["tier2_safe"] += 1
                    else:  # uncertain
                        needs_llm.append(result.candidate)
                        metrics["tier2_uncertain"] += 1

                # ========== TIER 3: LLM FOR UNCERTAIN CASES ==========
                if needs_llm and self._classifier and not skip_tier3_llm:
                    # Extract sources and sinks that need LLM validation
                    llm_sources = [c.source for c in needs_llm]
                    llm_sinks = [c.sink for c in needs_llm]

                    # Run LLM classification
                    validated_sources = await self._classify_sources_with_llm(llm_sources)
                    validated_sinks = await self._classify_sinks_with_llm(llm_sinks)
                    metrics["tier3_llm_calls"] = len(llm_sources) + len(llm_sinks)

                    # Re-match validated sources and sinks
                    if validated_sources and validated_sinks:
                        llm_candidates = extractor.create_flow_candidates(
                            validated_sources, validated_sinks
                        )
                        for c in llm_candidates:
                            c.detection_mode = "hybrid_ml_llm"
                        confirmed_candidates.extend(llm_candidates)
                elif skip_tier3_llm:
                    metrics["tier3_skipped"] = len(needs_llm)
                    logger.info(f"Tier 3 LLM skipped (fast mode): {len(needs_llm)} uncertain candidates")

            # ========== VALIDATION (Optional Joern CPG) ==========
            if require_joern:
                joern_available = await self.joern_client.is_available()
                if joern_available:
                    confirmed_candidates = await self._validate_with_joern(confirmed_candidates)
                    mode = "hybrid_ml_cpg"
                else:
                    # Apply heuristic validation
                    confirmed_candidates = self._validate_heuristic(confirmed_candidates)
                    mode = "hybrid_ml_heuristic"
            else:
                mode = "hybrid_ml"

            # ========== FINDING GENERATION ==========
            for candidate in confirmed_candidates:
                if candidate.confidence >= self.config.min_confidence:
                    finding = self._candidate_to_finding(candidate)
                    findings.append(finding)

            metrics["final_findings"] = len(findings)

            return DetectionResult(
                findings=findings,
                flows_analyzed=metrics["candidates_created"],
                queries_executed=metrics["tier3_llm_calls"],
                success=True,
                execution_time_ms=(time.time() - start_time) * 1000,
                metadata={
                    "detection_mode": mode,
                    "sources_extracted": len(all_sources),
                    "sinks_extracted": len(all_sinks),
                    **metrics,
                },
            )

        except Exception as e:
            import traceback
            return DetectionResult(
                findings=findings,
                flows_analyzed=0,
                queries_executed=0,
                success=False,
                error=f"{str(e)}\n{traceback.format_exc()}",
                execution_time_ms=(time.time() - start_time) * 1000,
                metadata={"detection_mode": "hybrid_ml_error", **metrics},
            )
