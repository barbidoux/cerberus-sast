"""Phase III: Hybrid Detection Engine - CPG-based taint analysis."""

from cerberus.detection.engine import (
    DetectionConfig,
    DetectionEngine,
    DetectionResult,
)
from cerberus.detection.flow_analyzer import (
    DataFlow,
    FlowAnalyzer,
    FlowAnalyzerConfig,
    FlowResult,
)
from cerberus.detection.joern_client import (
    Flow,
    JoernClient,
    JoernConfig,
    JoernError,
    JoernImportError,
    QueryResult,
)
from cerberus.detection.query_generator import (
    CPGQLQuery,
    QueryGenerator,
    QueryGeneratorConfig,
    QueryTemplate,
)
from cerberus.detection.slicer import (
    ProgramSlicer,
    SlicerConfig,
    SliceResult,
)

__all__ = [
    # Engine
    "DetectionConfig",
    "DetectionEngine",
    "DetectionResult",
    # Flow Analyzer
    "DataFlow",
    "FlowAnalyzer",
    "FlowAnalyzerConfig",
    "FlowResult",
    # Joern Client
    "Flow",
    "JoernClient",
    "JoernConfig",
    "JoernError",
    "JoernImportError",
    "QueryResult",
    # Query Generator
    "CPGQLQuery",
    "QueryGenerator",
    "QueryGeneratorConfig",
    "QueryTemplate",
    # Slicer
    "ProgramSlicer",
    "SlicerConfig",
    "SliceResult",
]
