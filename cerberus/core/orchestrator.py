"""
Scan Orchestrator - Main entry point for the 4-phase NSSCP pipeline.

Coordinates:
- Phase I: Repository Mapping (Context)
- Phase II: Spec Inference
- Phase III: Detection (Joern CPG)
- Phase IV: Verification (Multi-Agent Council) with Feedback Loop
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from cerberus.context.repo_mapper import RepositoryMapper
from cerberus.core.progress import ProgressTracker, ScanProgress
from cerberus.detection.engine import DetectionConfig, DetectionEngine
from cerberus.detection.joern_client import JoernClient, JoernConfig
from cerberus.inference.engine import InferenceConfig, InferenceEngine
from cerberus.models.base import Verdict
from cerberus.models.finding import Finding, ScanResult
from cerberus.models.repo_map import RepoMap
from cerberus.models.spec import DynamicSpec
from cerberus.utils.logging import ComponentLogger
from cerberus.verification.engine import VerificationEngine, VerificationEngineConfig
from cerberus.verification.feedback import SpecUpdate


@dataclass
class OrchestratorConfig:
    """Configuration for the scan orchestrator."""

    # Phase toggles
    run_inference: bool = True
    run_detection: bool = True
    run_verification: bool = True

    # Hybrid detection mode (AST-based taint extraction)
    use_hybrid_detection: bool = False
    use_hybrid_ml: bool = False  # Milestone 11: ML-enhanced 3-tier pipeline (patterns → CodeBERT → LLM)
    skip_tier3_llm: bool = False  # Fast mode: skip Tier 3 LLM for speed (patterns → CodeBERT only)
    require_joern_for_hybrid: bool = False  # If False, use heuristic mode when Joern unavailable

    # Feedback loop settings
    enable_feedback_loop: bool = True
    max_feedback_iterations: int = 3  # HARD LIMIT - never exceed
    convergence_threshold: float = 0.1  # Stop if <10% change

    # Analysis settings
    languages: Optional[list[str]] = None
    exclude_patterns: Optional[list[str]] = None
    max_file_size_mb: int = 10

    # LLM settings
    min_confidence: float = 0.7

    # Joern settings
    joern_endpoint: str = "localhost:8080"
    joern_timeout: int = 300


@dataclass
class OrchestratorResult:
    """Result from orchestrator scan."""

    scan_result: ScanResult
    iterations_run: int = 1
    spec_updates_applied: int = 0
    converged: bool = True
    error: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


class DependencyError(Exception):
    """Raised when a required dependency is unavailable."""

    pass


class ScanOrchestrator:
    """
    Main orchestrator for the 4-phase NSSCP pipeline.

    Coordinates all phases and implements the feedback loop from
    Phase IV (Verification) back to Phase II (Inference).

    Example:
        orchestrator = ScanOrchestrator(config, llm_gateway)
        result = await orchestrator.scan(Path("./my-project"))
    """

    MAX_FEEDBACK_ITERATIONS = 3  # HARD LIMIT - safety against infinite loops

    def __init__(
        self,
        config: Optional[OrchestratorConfig] = None,
        llm_gateway: Optional[Any] = None,
        joern_client: Optional[JoernClient] = None,
        progress_callback: Optional[Callable[[ScanProgress], None]] = None,
    ) -> None:
        """
        Initialize the scan orchestrator.

        Args:
            config: Orchestrator configuration.
            llm_gateway: LLM gateway for inference and verification.
            joern_client: Joern client for CPG analysis.
            progress_callback: Optional callback for progress updates.
        """
        self.config = config or OrchestratorConfig()
        self.llm_gateway = llm_gateway
        self.logger = ComponentLogger("orchestrator")

        # Enforce hard limit on iterations
        if self.config.max_feedback_iterations > self.MAX_FEEDBACK_ITERATIONS:
            self.logger.warning(
                f"max_feedback_iterations ({self.config.max_feedback_iterations}) exceeds "
                f"hard limit ({self.MAX_FEEDBACK_ITERATIONS}), capping to {self.MAX_FEEDBACK_ITERATIONS}"
            )
            self.config.max_feedback_iterations = self.MAX_FEEDBACK_ITERATIONS

        # Initialize Joern client
        self.joern_client = joern_client or JoernClient(
            config=JoernConfig(
                endpoint=self.config.joern_endpoint,
                timeout=self.config.joern_timeout,
            )
        )

        # Initialize progress tracker
        self.progress_tracker = ProgressTracker(callback=progress_callback)

        # Phase components (initialized lazily)
        self._repo_mapper: Optional[RepositoryMapper] = None
        self._inference_engine: Optional[InferenceEngine] = None
        self._detection_engine: Optional[DetectionEngine] = None
        self._verification_engine: Optional[VerificationEngine] = None

    @property
    def repo_mapper(self) -> RepositoryMapper:
        """Lazy initialization of repository mapper."""
        if self._repo_mapper is None:
            self._repo_mapper = RepositoryMapper()
        return self._repo_mapper

    @property
    def inference_engine(self) -> InferenceEngine:
        """Lazy initialization of inference engine."""
        if self._inference_engine is None:
            self._inference_engine = InferenceEngine(
                config=InferenceConfig(
                    min_confidence=self.config.min_confidence,
                    write_output=False,  # Don't write to file during orchestration
                ),
                llm_gateway=self.llm_gateway,
            )
        return self._inference_engine

    @property
    def detection_engine(self) -> DetectionEngine:
        """Lazy initialization of detection engine."""
        if self._detection_engine is None:
            # Milestone 8: Create LLM classifier for hybrid detection
            llm_classifier = None
            if self.llm_gateway and self.config.use_hybrid_detection:
                from cerberus.inference.classifier import LLMClassifier
                llm_classifier = LLMClassifier(gateway=self.llm_gateway)

            self._detection_engine = DetectionEngine(
                config=DetectionConfig(
                    min_confidence=self.config.min_confidence,
                ),
                joern_client=self.joern_client,
                llm_gateway=self.llm_gateway,
                llm_classifier=llm_classifier,  # Milestone 8: Pass classifier
            )
        return self._detection_engine

    @property
    def verification_engine(self) -> VerificationEngine:
        """Lazy initialization of verification engine."""
        if self._verification_engine is None:
            self._verification_engine = VerificationEngine(
                config=VerificationEngineConfig(
                    enable_feedback=self.config.enable_feedback_loop,
                    min_confidence=self.config.min_confidence,
                ),
                llm_gateway=self.llm_gateway,
            )
        return self._verification_engine

    async def scan(
        self,
        path: Path,
        repository_name: Optional[str] = None,
    ) -> OrchestratorResult:
        """
        Run a complete scan on a repository.

        Executes all 4 phases with optional feedback loop.

        Args:
            path: Path to repository root.
            repository_name: Optional name for the repository.

        Returns:
            OrchestratorResult with scan results and metadata.
        """
        self.logger.info(f"Starting scan of {path}")
        start_time = time.time()

        # Initialize scan result
        scan_result = ScanResult(
            repository=repository_name or path.name,
        )

        try:
            # Check dependencies
            await self._check_dependencies()

            # Phase I: Context/Repository Mapping
            self._update_progress("context", 0.0, "Starting repository mapping")
            repo_map = await self._run_phase_i(path)
            scan_result.files_scanned = len(repo_map.files)
            scan_result.lines_scanned = sum(f.lines for f in repo_map.files)
            scan_result.phase_timings["context"] = time.time() - start_time

            if not self.config.run_inference:
                self._update_progress("complete", 1.0, "Scan complete (inference disabled)")
                scan_result.complete()
                return OrchestratorResult(scan_result=scan_result)

            # HYBRID MODE: Use AST-based taint extraction instead of LLM inference
            if self.config.use_hybrid_detection:
                return await self._run_hybrid_scan(repo_map, scan_result, start_time)

            # Phase II: Spec Inference
            phase_start = time.time()
            self._update_progress("inference", 0.0, "Starting spec inference")
            dynamic_spec = await self._run_phase_ii(repo_map)
            scan_result.sources_found = len(dynamic_spec.sources)
            scan_result.sinks_found = len(dynamic_spec.sinks)
            scan_result.sanitizers_found = len(dynamic_spec.sanitizers)
            scan_result.phase_timings["inference"] = time.time() - phase_start

            if not self.config.run_detection:
                self._update_progress("complete", 1.0, "Scan complete (detection disabled)")
                scan_result.complete()
                return OrchestratorResult(scan_result=scan_result)

            # Phase III & IV: Detection and Verification with Feedback Loop
            all_findings: list[Finding] = []
            seen_finding_ids: set[str] = set()
            total_spec_updates = 0
            iteration = 0
            converged = False

            for iteration in range(self.config.max_feedback_iterations):
                self.logger.info(f"Feedback iteration {iteration + 1}/{self.config.max_feedback_iterations}")

                # Phase III: Detection
                phase_start = time.time()
                self._update_progress(
                    "detection",
                    iteration / self.config.max_feedback_iterations,
                    f"Detection iteration {iteration + 1}",
                )
                detection_result = await self._run_phase_iii(dynamic_spec)
                scan_result.phase_timings[f"detection_{iteration + 1}"] = time.time() - phase_start

                if not detection_result.success:
                    scan_result.errors.append({
                        "phase": "detection",
                        "iteration": iteration + 1,
                        "error": detection_result.error,
                    })
                    break

                # Filter out already-seen findings
                new_findings = [
                    f for f in detection_result.findings
                    if f.id not in seen_finding_ids
                ]

                if not new_findings:
                    self.logger.info("No new findings - convergence reached")
                    converged = True
                    break

                if not self.config.run_verification:
                    # No verification - add all as-is
                    all_findings.extend(new_findings)
                    seen_finding_ids.update(f.id for f in new_findings)
                    converged = True
                    break

                # Phase IV: Verification
                phase_start = time.time()
                self._update_progress(
                    "verification",
                    iteration / self.config.max_feedback_iterations,
                    f"Verification iteration {iteration + 1}",
                )
                verification_result = await self._run_phase_iv(new_findings)
                scan_result.phase_timings[f"verification_{iteration + 1}"] = time.time() - phase_start

                # Add verified findings
                for finding in verification_result.findings:
                    if finding.id not in seen_finding_ids:
                        all_findings.append(finding)
                        seen_finding_ids.add(finding.id)

                # Check if feedback loop should continue
                if not self.config.enable_feedback_loop:
                    converged = True
                    break

                spec_updates = verification_result.spec_updates
                if spec_updates is None or spec_updates.total == 0:
                    self.logger.info("No spec updates from feedback - convergence reached")
                    converged = True
                    break

                # Merge spec updates
                total_spec_updates += spec_updates.total
                dynamic_spec = self._merge_specs(dynamic_spec, spec_updates)

                self.logger.info(
                    f"Iteration {iteration + 1} complete: "
                    f"{len(new_findings)} findings processed, "
                    f"{spec_updates.total} new sanitizers discovered"
                )

                # Check convergence threshold
                if len(new_findings) < 1:
                    converged = True
                    break

            # Store all findings
            scan_result.findings = all_findings

            # Complete scan
            scan_result.complete()
            scan_result.phase_timings["total"] = time.time() - start_time

            self._update_progress("complete", 1.0, "Scan complete")

            return OrchestratorResult(
                scan_result=scan_result,
                iterations_run=iteration + 1,
                spec_updates_applied=total_spec_updates,
                converged=converged,
                metadata={
                    "total_duration_seconds": time.time() - start_time,
                    "findings_by_verdict": self._count_by_verdict(all_findings),
                },
            )

        except DependencyError as e:
            scan_result.complete(status="failed")
            scan_result.errors.append({"phase": "startup", "error": str(e)})
            return OrchestratorResult(
                scan_result=scan_result,
                error=str(e),
            )
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            scan_result.complete(status="failed")
            scan_result.errors.append({"phase": "unknown", "error": str(e)})
            return OrchestratorResult(
                scan_result=scan_result,
                error=str(e),
            )

    async def _check_dependencies(self) -> None:
        """Verify required dependencies are available."""
        # Hybrid mode with heuristic fallback doesn't require Joern
        if self.config.use_hybrid_detection and not self.config.require_joern_for_hybrid:
            return

        if self.config.run_detection:
            if not await self.joern_client.is_available():
                raise DependencyError(
                    "Joern server not available. "
                    "Run: docker-compose -f docker-compose.joern.yml up -d"
                )

    async def _run_phase_i(self, path: Path) -> RepoMap:
        """Run Phase I: Repository Mapping."""
        self.logger.info("Phase I: Repository Mapping")
        return await self.repo_mapper.map_repository(
            repo_path=path,
            languages=self.config.languages,
            exclude_patterns=self.config.exclude_patterns,
            max_file_size_mb=self.config.max_file_size_mb,
        )

    async def _run_phase_ii(self, repo_map: RepoMap) -> DynamicSpec:
        """Run Phase II: Spec Inference."""
        self.logger.info("Phase II: Spec Inference")
        result = await self.inference_engine.infer(repo_map)
        return result.spec

    async def _run_phase_iii(self, spec: DynamicSpec) -> Any:
        """Run Phase III: Detection."""
        self.logger.info("Phase III: Detection")
        return await self.detection_engine.detect(spec)

    async def _run_hybrid_scan(
        self,
        repo_map: RepoMap,
        scan_result: ScanResult,
        start_time: float,
    ) -> OrchestratorResult:
        """
        Run hybrid detection mode using AST-based taint extraction + LLM classification.

        This mode implements NEURO-SYMBOLIC analysis:
        1. Extracts sources/sinks directly from AST (Symbolic)
        2. LLM validates and enriches the AST findings (Neural - Milestone 8)
        3. Creates flow candidates based on CWE matching
        4. Validates via Joern CPG or heuristic scoring
        """
        use_llm = self.llm_gateway is not None

        # Determine detection mode
        if self.config.use_hybrid_ml:
            mode_name = "ML-ENHANCED HYBRID (3-tier: patterns → CodeBERT → LLM)"
            progress_msg = "ML-enhanced detection (Tier 1: patterns, Tier 2: CodeBERT, Tier 3: LLM)"
        elif use_llm:
            mode_name = "NEURO-SYMBOLIC"
            progress_msg = "AST extraction + LLM classification"
        else:
            mode_name = "HYBRID (AST-only)"
            progress_msg = "AST-based taint extraction"

        self.logger.info(f"Running {mode_name} detection mode")

        # Phase II: AST-based taint extraction + classification
        phase_start = time.time()
        self._update_progress("inference", 0.0, progress_msg)

        if self.config.use_hybrid_ml:
            # Milestone 11: ML-enhanced 3-tier pipeline
            detection_result = await self.detection_engine.detect_hybrid_ml(
                repo_map,
                require_joern=self.config.require_joern_for_hybrid,
                skip_tier3_llm=self.config.skip_tier3_llm,  # Fast mode skips LLM
            )
        else:
            # Original hybrid detection (with optional LLM)
            detection_result = await self.detection_engine.detect_hybrid(
                repo_map,
                require_joern=self.config.require_joern_for_hybrid,
                use_llm=use_llm,  # Milestone 8: Enable LLM classification
            )
        scan_result.phase_timings["hybrid_detection"] = time.time() - phase_start

        # Extract metadata about sources/sinks
        scan_result.sources_found = detection_result.metadata.get("sources_extracted", 0)
        scan_result.sinks_found = detection_result.metadata.get("sinks_extracted", 0)
        scan_result.sanitizers_found = 0  # Hybrid mode doesn't extract sanitizers yet

        if not detection_result.success:
            scan_result.complete(status="failed")
            scan_result.errors.append({
                "phase": "hybrid_detection",
                "error": detection_result.error,
            })
            return OrchestratorResult(
                scan_result=scan_result,
                error=detection_result.error,
            )

        # Filter findings by confidence
        all_findings = [
            f for f in detection_result.findings
            if f.confidence >= self.config.min_confidence
        ]

        # Optional verification
        if self.config.run_verification and all_findings:
            phase_start = time.time()
            self._update_progress("verification", 0.0, "Verifying findings")
            verification_result = await self._run_phase_iv(all_findings)
            scan_result.phase_timings["verification"] = time.time() - phase_start

            # Use verified findings
            all_findings = [
                f for f in verification_result.findings
                if f.verification is None or f.verification.verdict != Verdict.FALSE_POSITIVE
            ]

        scan_result.findings = all_findings
        scan_result.complete()
        scan_result.phase_timings["total"] = time.time() - start_time

        self._update_progress("complete", 1.0, "Hybrid scan complete")

        return OrchestratorResult(
            scan_result=scan_result,
            iterations_run=1,
            converged=True,
            metadata={
                "detection_mode": detection_result.metadata.get("detection_mode", "hybrid"),
                "total_duration_seconds": time.time() - start_time,
                "candidates_created": detection_result.metadata.get("candidates_created", 0),
                "findings_by_verdict": self._count_by_verdict(all_findings),
                # Milestone 8: LLM metrics
                "llm_calls": detection_result.metadata.get("llm_calls", 0),
                "sources_validated": detection_result.metadata.get("sources_validated", 0),
                "sinks_validated": detection_result.metadata.get("sinks_validated", 0),
            },
        )

    async def _run_phase_iv(self, findings: list[Finding]) -> Any:
        """Run Phase IV: Verification."""
        self.logger.info("Phase IV: Verification")
        return await self.verification_engine.verify(findings)

    def _merge_specs(self, base: DynamicSpec, updates: SpecUpdate) -> DynamicSpec:
        """Merge spec updates into base spec."""
        # Add new sanitizers
        for sanitizer in updates.sanitizers:
            if not any(s.method == sanitizer.method for s in base.sanitizers):
                base.sanitizers.append(sanitizer)
                self.logger.debug(f"Added sanitizer from feedback: {sanitizer.method}")

        # Add new sources (if any)
        for source in updates.sources:
            if not any(s.method == source.method for s in base.sources):
                base.sources.append(source)

        # Add new sinks (if any)
        for sink in updates.sinks:
            if not any(s.method == sink.method for s in base.sinks):
                base.sinks.append(sink)

        return base

    def _update_progress(
        self,
        phase: str,
        progress: float,
        message: str,
    ) -> None:
        """Update progress tracker."""
        self.progress_tracker.update(
            ScanProgress(
                phase=phase,
                phase_progress=progress,
                message=message,
            )
        )

    def _count_by_verdict(self, findings: list[Finding]) -> dict[str, int]:
        """Count findings by verification verdict."""
        counts: dict[str, int] = {
            "true_positive": 0,
            "false_positive": 0,
            "uncertain": 0,
            "unverified": 0,
        }

        for finding in findings:
            if finding.verification is None:
                counts["unverified"] += 1
            elif finding.verification.verdict == Verdict.TRUE_POSITIVE:
                counts["true_positive"] += 1
            elif finding.verification.verdict == Verdict.FALSE_POSITIVE:
                counts["false_positive"] += 1
            else:
                counts["uncertain"] += 1

        return counts
