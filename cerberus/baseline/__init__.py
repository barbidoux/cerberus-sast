"""
Baseline Management for Cerberus SAST.

Allows tracking and comparing findings against baselines
to identify new vs. existing vulnerabilities.
"""

from cerberus.baseline.manager import (
    Baseline,
    BaselineConfig,
    BaselineManager,
    BaselineEntry,
    BaselineDiff,
)

__all__ = [
    "Baseline",
    "BaselineConfig",
    "BaselineManager",
    "BaselineEntry",
    "BaselineDiff",
]
