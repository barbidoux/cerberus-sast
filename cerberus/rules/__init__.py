"""
Rule loading system for Cerberus SAST.

This module provides external YAML-based rule definitions for taint analysis,
replacing the hardcoded patterns in taint_flow.py.
"""

from cerberus.rules.loader import RuleLoader, RuleSet, TaintRule

__all__ = ["RuleLoader", "RuleSet", "TaintRule"]
