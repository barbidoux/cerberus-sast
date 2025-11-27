"""Phase II: Spec Inference Engine - Source/Sink/Sanitizer identification."""

from cerberus.inference.candidate_extractor import (
    Candidate,
    CandidateExtractor,
    CandidateType,
    ExtractionConfig,
    HeuristicMatcher,
)
from cerberus.inference.classifier import (
    ClassificationResult,
    ClassifierConfig,
    LLMClassifier,
)
from cerberus.inference.engine import (
    InferenceConfig,
    InferenceEngine,
    InferenceResult,
)
from cerberus.inference.propagator import (
    PropagationConfig,
    PropagationResult,
    TaintPropagator,
)
from cerberus.inference.spec_writer import (
    SpecWriter,
    SpecWriterConfig,
)

__all__ = [
    "Candidate",
    "CandidateExtractor",
    "CandidateType",
    "ClassificationResult",
    "ClassifierConfig",
    "ExtractionConfig",
    "HeuristicMatcher",
    "InferenceConfig",
    "InferenceEngine",
    "InferenceResult",
    "LLMClassifier",
    "PropagationConfig",
    "PropagationResult",
    "SpecWriter",
    "SpecWriterConfig",
    "TaintPropagator",
]
