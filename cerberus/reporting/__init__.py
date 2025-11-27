"""
Reporting module for generating scan outputs in various formats.

Provides reporters for:
- SARIF 2.1.0 (GitHub, Azure DevOps, VS Code integration)
- JSON (programmatic consumption)
- HTML (web viewing)
- Markdown (GitHub/GitLab comments, wiki)
- Console (Rich terminal output)
"""

from cerberus.reporting.base import (
    BaseReporter,
    ReportConfig,
    ReporterRegistry,
    ReportMetadata,
)
from cerberus.reporting.console import ConsoleReporter
from cerberus.reporting.html import HTMLReporter
from cerberus.reporting.json_reporter import JSONReporter
from cerberus.reporting.markdown import MarkdownReporter
from cerberus.reporting.sarif import SARIFReporter

__all__ = [
    # Base
    "BaseReporter",
    "ReportConfig",
    "ReporterRegistry",
    "ReportMetadata",
    # Reporters
    "ConsoleReporter",
    "HTMLReporter",
    "JSONReporter",
    "MarkdownReporter",
    "SARIFReporter",
]
