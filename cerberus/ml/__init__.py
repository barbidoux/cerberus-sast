"""
ML Module for Cerberus SAST.

This module provides machine learning components for the ML-enhanced
Neuro-Symbolic pipeline (Milestone 11):

- Tier1Filter: Fast pattern-based pre-filtering
- CodeBERTClassifier: Fine-tuned CodeBERT for vulnerability classification
- TrainingDataGenerator: Generate training data from fixtures

The 3-tier pipeline achieves:
- >90% True Positive rate
- <10% False Positive rate
- 6-10x speedup over LLM-only approach
"""

from cerberus.ml.codebert_classifier import CodeBERTClassifier
from cerberus.ml.tier1_filter import Tier1Filter
from cerberus.ml.training_data import TrainingDataGenerator, TrainingExample

__all__ = [
    "CodeBERTClassifier",
    "Tier1Filter",
    "TrainingDataGenerator",
    "TrainingExample",
]
