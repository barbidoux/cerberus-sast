"""
Spec Writer for Phase II Spec Inference.

Writes DynamicSpec to context_rules.json with support for
merging, backups, and incremental updates.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cerberus.models.spec import DynamicSpec


@dataclass
class SpecWriterConfig:
    """Configuration for spec writer."""

    output_filename: str = "context_rules.json"
    pretty_print: bool = True
    backup_existing: bool = True
    indent: int = 2


class SpecWriter:
    """
    Writes DynamicSpec to context_rules.json.

    Supports:
    - Pretty printing or compact JSON
    - Backup of existing files
    - Merging with existing specs
    - Loading specs from file
    """

    def __init__(self, config: Optional[SpecWriterConfig] = None) -> None:
        """Initialize writer with optional configuration."""
        self.config = config or SpecWriterConfig()

    def write(
        self,
        spec: DynamicSpec,
        output_dir: Path,
        merge_existing: bool = False,
    ) -> Path:
        """
        Write DynamicSpec to file.

        Args:
            spec: The spec to write
            output_dir: Directory to write to
            merge_existing: If True, merge with existing file

        Returns:
            Path to the written file
        """
        output_path = output_dir / self.config.output_filename

        # Handle existing file
        if output_path.exists():
            if self.config.backup_existing:
                self._backup_file(output_path)

            if merge_existing:
                existing_spec = self.load(output_path)
                existing_spec.merge(spec)
                spec = existing_spec

        # Write the spec
        spec.to_json(output_path)

        # If not pretty print, rewrite compact
        if not self.config.pretty_print:
            self._rewrite_compact(output_path)

        return output_path

    def load(self, path: Path) -> DynamicSpec:
        """
        Load DynamicSpec from file.

        Args:
            path: Path to the spec file

        Returns:
            DynamicSpec (empty if file doesn't exist)
        """
        if not path.exists():
            return DynamicSpec(generated_at=datetime.now(timezone.utc))

        return DynamicSpec.from_json(path)

    def _backup_file(self, path: Path) -> Path:
        """
        Create a backup of an existing file.

        Args:
            path: Path to file to backup

        Returns:
            Path to backup file
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_name = f"{path.stem}.{timestamp}.backup{path.suffix}"
        backup_path = path.parent / backup_name

        shutil.copy2(path, backup_path)
        return backup_path

    def _rewrite_compact(self, path: Path) -> None:
        """
        Rewrite file in compact JSON format.

        Args:
            path: Path to JSON file to rewrite
        """
        with open(path) as f:
            data = json.load(f)

        with open(path, "w") as f:
            json.dump(data, f, separators=(",", ":"))
