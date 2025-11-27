"""
Inference Engine - Phase II main orchestrator.

Coordinates candidate extraction, LLM classification, taint propagation,
and spec writing to produce a DynamicSpec for a repository.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cerberus.inference.candidate_extractor import (
    CandidateExtractor,
    ExtractionConfig,
)
from cerberus.inference.classifier import (
    ClassificationResult,
    ClassifierConfig,
    LLMClassifier,
)
from cerberus.inference.propagator import (
    PropagationConfig,
    TaintPropagator,
)
from cerberus.inference.spec_writer import (
    SpecWriter,
    SpecWriterConfig,
)
from cerberus.models.repo_map import RepoMap
from cerberus.models.spec import DynamicSpec, TaintSpec


@dataclass
class InferenceConfig:
    """Configuration for the inference engine."""

    max_candidates: int = 100
    min_confidence: float = 0.7
    write_output: bool = True
    propagate: bool = True
    output_filename: str = "context_rules.json"


@dataclass
class InferenceResult:
    """
    Result of running inference on a repository.

    Contains the generated spec and statistics about the inference process.
    """

    spec: DynamicSpec
    candidates_found: int
    candidates_classified: int
    candidates_confirmed: int
    duration_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        """Generate summary statistics."""
        return {
            "candidates_found": self.candidates_found,
            "candidates_classified": self.candidates_classified,
            "candidates_confirmed": self.candidates_confirmed,
            "duration_ms": self.duration_ms,
            "sources": len(self.spec.sources),
            "sinks": len(self.spec.sinks),
            "sanitizers": len(self.spec.sanitizers),
            "propagators": len(self.spec.propagators),
            "total_specs": self.spec.total_specs,
        }


class InferenceEngine:
    """
    Phase II main orchestrator.

    Coordinates:
    1. Candidate extraction using heuristics
    2. LLM classification of candidates
    3. Taint propagation across call graph
    4. Writing results to context_rules.json
    """

    def __init__(
        self,
        config: Optional[InferenceConfig] = None,
        llm_gateway: Optional[Any] = None,
    ) -> None:
        """
        Initialize the inference engine.

        Args:
            config: Engine configuration
            llm_gateway: Optional LLM gateway for classification
        """
        self.config = config or InferenceConfig()

        # Initialize components
        self.extractor = CandidateExtractor(
            config=ExtractionConfig(
                max_candidates=self.config.max_candidates,
                min_score=0.1,
            )
        )

        self.classifier = LLMClassifier(
            config=ClassifierConfig(
                min_confidence=self.config.min_confidence,
            ),
            gateway=llm_gateway,
        )

        self.propagator = TaintPropagator(
            config=PropagationConfig(
                propagate_through_calls=self.config.propagate,
            )
        )

        self.writer = SpecWriter(
            config=SpecWriterConfig(
                output_filename=self.config.output_filename,
            )
        )

    async def infer(
        self,
        repo_map: RepoMap,
        output_dir: Optional[Path] = None,
        repository_name: Optional[str] = None,
    ) -> InferenceResult:
        """
        Run inference on a repository.

        Args:
            repo_map: Repository map from Phase I
            output_dir: Directory to write output (optional)
            repository_name: Name for the repository in output

        Returns:
            InferenceResult with spec and statistics
        """
        start_time = time.time()

        # Initialize result tracking
        candidates_found = 0
        candidates_classified = 0
        candidates_confirmed = 0
        confirmed_specs: list[TaintSpec] = []
        error_message: Optional[str] = None

        try:
            # Step 1: Extract candidates
            candidates = self.extractor.extract(repo_map)
            candidates_found = len(candidates)

            if candidates:
                # Step 2: Classify candidates with LLM
                classification_results = await self.classifier.classify_batch(candidates)
                candidates_classified = len(classification_results)

                # Step 3: Convert confirmed classifications to TaintSpecs
                for result in classification_results:
                    if result.confirmed:
                        spec = result.to_taint_spec()
                        if spec:
                            confirmed_specs.append(spec)
                            candidates_confirmed += 1

            # Step 4: Propagate taint labels
            if self.config.propagate and confirmed_specs:
                propagation_result = self.propagator.propagate(
                    initial_specs=confirmed_specs,
                    repo_map=repo_map,
                )
                spec = propagation_result.to_dynamic_spec(
                    repository=repository_name or str(repo_map.root_path)
                )
            else:
                # Build spec directly from confirmed specs
                spec = DynamicSpec(
                    repository=repository_name or str(repo_map.root_path),
                    generated_at=datetime.now(timezone.utc),
                )
                for taint_spec in confirmed_specs:
                    if taint_spec.is_source:
                        spec.add_source(taint_spec)
                    elif taint_spec.is_sink:
                        spec.add_sink(taint_spec)
                    elif taint_spec.is_sanitizer:
                        spec.add_sanitizer(taint_spec)
                    elif taint_spec.is_propagator:
                        spec.add_propagator(taint_spec)

            # Step 5: Write output
            if self.config.write_output and output_dir:
                self.writer.write(spec, output_dir)

        except Exception as e:
            error_message = str(e)
            # Create empty spec on error
            spec = DynamicSpec(
                repository=repository_name or "",
                generated_at=datetime.now(timezone.utc),
            )

        # Calculate duration
        duration_ms = (time.time() - start_time) * 1000

        # Build metadata
        metadata: dict[str, Any] = {}
        if error_message:
            metadata["error"] = error_message

        return InferenceResult(
            spec=spec,
            candidates_found=candidates_found,
            candidates_classified=candidates_classified,
            candidates_confirmed=candidates_confirmed,
            duration_ms=duration_ms,
            metadata=metadata,
        )
