"""
Training Data Generator for CodeBERT Fine-Tuning.

This module generates labeled training data from annotated fixtures.
It extracts:
- Vulnerable code patterns (from fixtures with VULNERABILITY comments)
- Safe code patterns (from code without vulnerability markers)

Output format is JSONL suitable for HuggingFace datasets.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class TrainingExample:
    """A single training example for vulnerability classification."""

    # Input features
    source_expression: str
    source_type: str
    sink_expression: str
    sink_type: str
    cwe_types: list[str]
    uses_template_literal: bool
    in_same_function: bool
    in_same_file: bool
    distance_lines: int
    code_context: str

    # Label
    label: int  # 1 = vulnerable, 0 = safe
    label_source: str  # "annotation" | "heuristic" | "manual"

    # Metadata
    file_path: str = ""
    source_line: int = 0
    sink_line: int = 0
    vulnerability_type: str = ""  # e.g., "CWE-78", "CWE-22"

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    def to_text_input(self) -> str:
        """Format as text input for the model."""
        parts = [
            f"Source: {self.source_expression}",
            f"Source Type: {self.source_type}",
            f"Sink: {self.sink_expression}",
            f"Sink Type: {self.sink_type}",
            f"CWE Types: {', '.join(self.cwe_types)}",
            f"Template Literal: {self.uses_template_literal}",
            f"Same Function: {self.in_same_function}",
            f"Same File: {self.in_same_file}",
            f"Distance Lines: {self.distance_lines}",
        ]

        if self.code_context:
            parts.append(f"Code Context:\n{self.code_context[:1000]}")

        return "\n".join(parts)


@dataclass
class AnnotatedVulnerability:
    """Parsed vulnerability annotation from source code."""

    cwe: str
    description: str
    line: int
    file_path: str


class TrainingDataGenerator:
    """
    Generates training data from annotated fixture files.

    Annotations are expected in the format:
    - JavaScript: // VULNERABILITY: CWE-XX - Description (Line XX)
    - Python: # VULNERABILITY: CWE-XX - Description (Line XX)
    """

    # Patterns to match vulnerability annotations
    VULN_PATTERN_JS = re.compile(
        r"//\s*VULNERABILITY:\s*(CWE-\d+)\s*-\s*([^(]+)\s*\(Line\s*(\d+)\)",
        re.IGNORECASE
    )
    VULN_PATTERN_PY = re.compile(
        r"#\s*VULNERABILITY:\s*(CWE-\d+)\s*-\s*([^(]+)\s*\(Line\s*(\d+)\)",
        re.IGNORECASE
    )

    def __init__(
        self,
        fixtures_dir: Optional[Path] = None,
        context_lines: int = 10,
    ):
        """
        Initialize the training data generator.

        Args:
            fixtures_dir: Directory containing annotated fixtures.
            context_lines: Number of lines of context to extract around vulnerable code.
        """
        self.fixtures_dir = fixtures_dir or Path("tests/fixtures")
        self.context_lines = context_lines

    def generate_from_fixtures(
        self,
        output_path: Optional[Path] = None,
    ) -> list[TrainingExample]:
        """
        Generate training data from all fixture files.

        Args:
            output_path: If provided, write JSONL output to this path.

        Returns:
            List of TrainingExample objects.
        """
        examples: list[TrainingExample] = []

        # Find all fixture files
        for file_path in self.fixtures_dir.rglob("*"):
            if file_path.suffix in (".js", ".ts", ".py"):
                file_examples = self._process_file(file_path)
                examples.extend(file_examples)

        logger.info(
            f"Generated {len(examples)} training examples from {self.fixtures_dir}"
        )

        # Split by label
        vulnerable = [e for e in examples if e.label == 1]
        safe = [e for e in examples if e.label == 0]
        logger.info(f"  Vulnerable: {len(vulnerable)}, Safe: {len(safe)}")

        # Write output if path provided
        if output_path:
            self._write_jsonl(examples, output_path)
            logger.info(f"Wrote training data to {output_path}")

        return examples

    def _process_file(self, file_path: Path) -> list[TrainingExample]:
        """Process a single file and extract training examples."""
        try:
            content = file_path.read_text()
            lines = content.split("\n")
        except Exception as e:
            logger.warning(f"Failed to read {file_path}: {e}")
            return []

        # Parse vulnerability annotations
        annotations = self._parse_annotations(file_path, content)

        # Extract vulnerable lines set
        vulnerable_lines = {a.line for a in annotations}

        examples: list[TrainingExample] = []

        # Extract source-sink pairs using TaintExtractor
        try:
            from cerberus.context.taint_extractor import TaintExtractor

            extractor = TaintExtractor()
            sources, sinks = extractor.extract_from_file(file_path)

            # Create flow candidates
            candidates = extractor.create_flow_candidates(sources, sinks)

            for candidate in candidates:
                # Determine label based on annotations
                is_vulnerable = self._is_vulnerable(
                    candidate.sink.line,
                    vulnerable_lines,
                    annotations,
                )

                # Extract code context
                code_context = self._extract_context(
                    lines,
                    candidate.source.line,
                    candidate.sink.line,
                )

                # Find matching annotation for CWE
                vuln_type = ""
                for ann in annotations:
                    if abs(ann.line - candidate.sink.line) <= 3:
                        vuln_type = ann.cwe
                        break

                example = TrainingExample(
                    source_expression=candidate.source.expression,
                    source_type=candidate.source.source_type.value,
                    sink_expression=candidate.sink.expression,
                    sink_type=candidate.sink.sink_type.value,
                    cwe_types=list(candidate.sink.cwe_types),
                    uses_template_literal=candidate.sink.uses_template_literal,
                    in_same_function=candidate.in_same_function,
                    in_same_file=candidate.in_same_file,
                    distance_lines=candidate.distance_lines,
                    code_context=code_context,
                    label=1 if is_vulnerable else 0,
                    label_source="annotation" if is_vulnerable else "heuristic",
                    file_path=str(file_path),
                    source_line=candidate.source.line,
                    sink_line=candidate.sink.line,
                    vulnerability_type=vuln_type,
                )
                examples.append(example)

        except Exception as e:
            logger.warning(f"Failed to extract from {file_path}: {e}")

        return examples

    def _parse_annotations(
        self,
        file_path: Path,
        content: str,
    ) -> list[AnnotatedVulnerability]:
        """Parse vulnerability annotations from file content."""
        annotations: list[AnnotatedVulnerability] = []

        # Choose pattern based on file type
        if file_path.suffix in (".js", ".ts"):
            pattern = self.VULN_PATTERN_JS
        else:
            pattern = self.VULN_PATTERN_PY

        for match in pattern.finditer(content):
            cwe = match.group(1)
            description = match.group(2).strip()
            line = int(match.group(3))

            annotations.append(AnnotatedVulnerability(
                cwe=cwe,
                description=description,
                line=line,
                file_path=str(file_path),
            ))

        return annotations

    def _is_vulnerable(
        self,
        sink_line: int,
        vulnerable_lines: set[int],
        annotations: list[AnnotatedVulnerability],
    ) -> bool:
        """Check if a sink line is marked as vulnerable."""
        # Exact match
        if sink_line in vulnerable_lines:
            return True

        # Check if sink is within 3 lines of annotation (for multi-line code)
        for vuln_line in vulnerable_lines:
            if abs(sink_line - vuln_line) <= 3:
                return True

        return False

    def _extract_context(
        self,
        lines: list[str],
        source_line: int,
        sink_line: int,
    ) -> str:
        """Extract code context around source and sink."""
        # Get range covering both source and sink
        start = max(0, min(source_line, sink_line) - self.context_lines - 1)
        end = min(len(lines), max(source_line, sink_line) + self.context_lines)

        context_lines = lines[start:end]
        return "\n".join(context_lines)

    def _write_jsonl(self, examples: list[TrainingExample], output_path: Path) -> None:
        """Write examples to JSONL file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            for example in examples:
                # Write in HuggingFace format
                record = {
                    "text": example.to_text_input(),
                    "label": example.label,
                    **example.to_dict(),
                }
                f.write(json.dumps(record) + "\n")

    def generate_balanced_dataset(
        self,
        output_path: Path,
        max_examples: int = 10000,
    ) -> tuple[list[TrainingExample], list[TrainingExample]]:
        """
        Generate a balanced dataset with equal vulnerable/safe examples.

        Args:
            output_path: Path to write the dataset.
            max_examples: Maximum total examples (will be split 50/50).

        Returns:
            Tuple of (train_examples, val_examples).
        """
        all_examples = self.generate_from_fixtures()

        vulnerable = [e for e in all_examples if e.label == 1]
        safe = [e for e in all_examples if e.label == 0]

        # Balance the dataset
        min_count = min(len(vulnerable), len(safe), max_examples // 2)

        balanced = vulnerable[:min_count] + safe[:min_count]

        # Shuffle
        import random
        random.shuffle(balanced)

        # Split 80/20
        split_idx = int(len(balanced) * 0.8)
        train = balanced[:split_idx]
        val = balanced[split_idx:]

        # Write train and val files
        train_path = output_path.with_suffix(".train.jsonl")
        val_path = output_path.with_suffix(".val.jsonl")

        self._write_jsonl(train, train_path)
        self._write_jsonl(val, val_path)

        logger.info(f"Train: {len(train)} examples -> {train_path}")
        logger.info(f"Val: {len(val)} examples -> {val_path}")

        return train, val


def generate_synthetic_safe_examples(
    count: int = 100,
) -> list[TrainingExample]:
    """
    Generate synthetic safe code examples for training.

    These are patterns that look like vulnerabilities but are safe:
    - Sanitized inputs
    - Parameterized queries
    - Validated paths
    """
    safe_patterns = [
        # SQL - Parameterized query
        {
            "source_expression": "req.body.username",
            "source_type": "http_body",
            "sink_expression": "db.query",
            "sink_type": "sql_query",
            "cwe_types": ["CWE-89"],
            "code_context": """
const username = req.body.username;
// Safe: Using parameterized query
db.query('SELECT * FROM users WHERE username = ?', [username]);
""",
            "uses_template_literal": False,
        },
        # Command - Escaped input
        {
            "source_expression": "req.query.filename",
            "source_type": "http_query",
            "sink_expression": "exec",
            "sink_type": "command",
            "cwe_types": ["CWE-78"],
            "code_context": """
const filename = req.query.filename;
// Safe: Using shell escape
const escaped = shellEscape([filename]);
exec(`ls ${escaped}`);
""",
            "uses_template_literal": False,
        },
        # Path - Validated path
        {
            "source_expression": "req.params.file",
            "source_type": "http_params",
            "sink_expression": "readFileSync",
            "sink_type": "file_read",
            "cwe_types": ["CWE-22"],
            "code_context": """
const file = req.params.file;
// Safe: Path validated
if (file.includes('..')) {
    return res.status(400).send('Invalid path');
}
const content = fs.readFileSync(path.join('/safe/', file));
""",
            "uses_template_literal": False,
        },
        # XSS - Escaped output
        {
            "source_expression": "req.query.name",
            "source_type": "http_query",
            "sink_expression": "res.send",
            "sink_type": "http_response",
            "cwe_types": ["CWE-79"],
            "code_context": """
const name = req.query.name;
// Safe: HTML escaped
const escaped = escapeHtml(name);
res.send(`<h1>Hello, ${escaped}</h1>`);
""",
            "uses_template_literal": False,
        },
    ]

    examples: list[TrainingExample] = []

    for i in range(count):
        pattern = safe_patterns[i % len(safe_patterns)]

        example = TrainingExample(
            source_expression=pattern["source_expression"],
            source_type=pattern["source_type"],
            sink_expression=pattern["sink_expression"],
            sink_type=pattern["sink_type"],
            cwe_types=pattern["cwe_types"],
            uses_template_literal=pattern["uses_template_literal"],
            in_same_function=True,
            in_same_file=True,
            distance_lines=5,
            code_context=pattern["code_context"],
            label=0,  # Safe
            label_source="synthetic",
            file_path="synthetic",
            source_line=1,
            sink_line=5,
            vulnerability_type="",
        )
        examples.append(example)

    return examples


if __name__ == "__main__":
    # CLI usage
    import argparse

    parser = argparse.ArgumentParser(description="Generate training data from fixtures")
    parser.add_argument(
        "--fixtures",
        type=Path,
        default=Path("tests/fixtures"),
        help="Path to fixtures directory",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/training_data.jsonl"),
        help="Output JSONL path",
    )
    parser.add_argument(
        "--balanced",
        action="store_true",
        help="Generate balanced dataset",
    )

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    generator = TrainingDataGenerator(fixtures_dir=args.fixtures)

    if args.balanced:
        generator.generate_balanced_dataset(args.output)
    else:
        generator.generate_from_fixtures(output_path=args.output)
