"""Tests for training data generator."""

import json
import pytest
from pathlib import Path
from tempfile import TemporaryDirectory

from cerberus.ml.training_data import (
    TrainingDataGenerator,
    TrainingExample,
    AnnotatedVulnerability,
    generate_synthetic_safe_examples,
)


class TestTrainingExample:
    """Tests for TrainingExample dataclass."""

    def test_example_creation(self):
        """Test TrainingExample can be created."""
        example = TrainingExample(
            source_expression="req.query.id",
            source_type="http_query",
            sink_expression="db.query",
            sink_type="sql_query",
            cwe_types=["CWE-89"],
            uses_template_literal=True,
            in_same_function=True,
            in_same_file=True,
            distance_lines=5,
            code_context="const query = `SELECT * FROM users WHERE id = ${id}`",
            label=1,
            label_source="annotation",
        )

        assert example.label == 1
        assert example.source_expression == "req.query.id"

    def test_to_dict(self):
        """Test to_dict serialization."""
        example = TrainingExample(
            source_expression="req.query.id",
            source_type="http_query",
            sink_expression="db.query",
            sink_type="sql_query",
            cwe_types=["CWE-89"],
            uses_template_literal=False,
            in_same_function=True,
            in_same_file=True,
            distance_lines=5,
            code_context="test",
            label=1,
            label_source="annotation",
        )

        d = example.to_dict()
        assert isinstance(d, dict)
        assert d["label"] == 1
        assert d["source_expression"] == "req.query.id"

    def test_to_text_input(self):
        """Test to_text_input formatting."""
        example = TrainingExample(
            source_expression="req.query.id",
            source_type="http_query",
            sink_expression="db.query",
            sink_type="sql_query",
            cwe_types=["CWE-89"],
            uses_template_literal=True,
            in_same_function=True,
            in_same_file=True,
            distance_lines=5,
            code_context="test context",
            label=1,
            label_source="annotation",
        )

        text = example.to_text_input()
        assert "Source: req.query.id" in text
        assert "Sink: db.query" in text
        assert "CWE-89" in text
        assert "Template Literal: True" in text


class TestTrainingDataGenerator:
    """Tests for TrainingDataGenerator class."""

    def test_init_default(self):
        """Test default initialization."""
        generator = TrainingDataGenerator()
        assert generator.fixtures_dir == Path("tests/fixtures")
        assert generator.context_lines == 10

    def test_init_custom_dir(self):
        """Test custom fixtures directory."""
        generator = TrainingDataGenerator(
            fixtures_dir=Path("/custom/fixtures"),
            context_lines=20,
        )
        assert generator.fixtures_dir == Path("/custom/fixtures")
        assert generator.context_lines == 20

    def test_parse_annotations_js(self):
        """Test parsing JavaScript vulnerability annotations."""
        generator = TrainingDataGenerator()

        content = """
// VULNERABILITY: CWE-78 - Command Injection (Line 10)
const exec = require('child_process').exec;

// VULNERABILITY: CWE-89 - SQL Injection (Line 20)
db.query(query);
"""

        annotations = generator._parse_annotations(
            Path("test.js"),
            content,
        )

        assert len(annotations) == 2
        assert annotations[0].cwe == "CWE-78"
        assert annotations[0].line == 10
        assert annotations[1].cwe == "CWE-89"
        assert annotations[1].line == 20

    def test_parse_annotations_py(self):
        """Test parsing Python vulnerability annotations."""
        generator = TrainingDataGenerator()

        content = """
# VULNERABILITY: CWE-78 - Command Injection (Line 15)
os.system(cmd)

# VULNERABILITY: CWE-89 - SQL Injection (Line 25)
cursor.execute(query)
"""

        annotations = generator._parse_annotations(
            Path("test.py"),
            content,
        )

        assert len(annotations) == 2
        assert annotations[0].cwe == "CWE-78"
        assert annotations[0].line == 15

    def test_is_vulnerable_exact_match(self):
        """Test vulnerability detection with exact line match."""
        generator = TrainingDataGenerator()
        vulnerable_lines = {10, 20, 30}
        annotations = []

        assert generator._is_vulnerable(10, vulnerable_lines, annotations) is True
        assert generator._is_vulnerable(20, vulnerable_lines, annotations) is True
        assert generator._is_vulnerable(5, vulnerable_lines, annotations) is False

    def test_is_vulnerable_near_match(self):
        """Test vulnerability detection within tolerance."""
        generator = TrainingDataGenerator()
        vulnerable_lines = {10}
        annotations = []

        # Within 3 lines should match
        assert generator._is_vulnerable(10, vulnerable_lines, annotations) is True
        assert generator._is_vulnerable(11, vulnerable_lines, annotations) is True
        assert generator._is_vulnerable(12, vulnerable_lines, annotations) is True
        assert generator._is_vulnerable(13, vulnerable_lines, annotations) is True

        # Beyond 3 lines should not match
        assert generator._is_vulnerable(14, vulnerable_lines, annotations) is False

    def test_extract_context(self):
        """Test code context extraction."""
        generator = TrainingDataGenerator(context_lines=2)
        lines = ["line1", "line2", "line3", "line4", "line5", "line6", "line7"]

        # Source at line 3, sink at line 5 (1-indexed in real code)
        context = generator._extract_context(lines, 3, 5)

        # Should include lines around source and sink
        assert len(context.split("\n")) >= 2


class TestTrainingDataGeneratorOutput:
    """Tests for training data output."""

    def test_write_jsonl(self):
        """Test JSONL output writing."""
        with TemporaryDirectory() as tmpdir:
            generator = TrainingDataGenerator()
            output_path = Path(tmpdir) / "test.jsonl"

            examples = [
                TrainingExample(
                    source_expression="req.query.id",
                    source_type="http_query",
                    sink_expression="db.query",
                    sink_type="sql_query",
                    cwe_types=["CWE-89"],
                    uses_template_literal=False,
                    in_same_function=True,
                    in_same_file=True,
                    distance_lines=5,
                    code_context="test",
                    label=1,
                    label_source="annotation",
                ),
                TrainingExample(
                    source_expression="req.body.data",
                    source_type="http_body",
                    sink_expression="fs.writeFile",
                    sink_type="file_write",
                    cwe_types=["CWE-22"],
                    uses_template_literal=False,
                    in_same_function=False,
                    in_same_file=True,
                    distance_lines=20,
                    code_context="test2",
                    label=0,
                    label_source="heuristic",
                ),
            ]

            generator._write_jsonl(examples, output_path)

            assert output_path.exists()

            # Read and verify
            with open(output_path) as f:
                lines = f.readlines()

            assert len(lines) == 2

            record1 = json.loads(lines[0])
            assert record1["label"] == 1
            assert "text" in record1


class TestSyntheticSafeExamples:
    """Tests for synthetic safe example generation."""

    def test_generate_synthetic_safe(self):
        """Test generating synthetic safe examples."""
        examples = generate_synthetic_safe_examples(count=10)

        assert len(examples) == 10
        assert all(e.label == 0 for e in examples)
        assert all(e.label_source == "synthetic" for e in examples)

    def test_synthetic_variety(self):
        """Test synthetic examples have variety."""
        examples = generate_synthetic_safe_examples(count=20)

        # Should have different CWE types
        cwe_types = set()
        for e in examples:
            cwe_types.update(e.cwe_types)

        assert len(cwe_types) > 1

    def test_synthetic_safe_patterns(self):
        """Test synthetic examples contain safe patterns."""
        examples = generate_synthetic_safe_examples(count=10)

        # Check that code contexts contain safe patterns
        safe_keywords = ["parameterized", "escape", "validated", "escaped"]

        has_safe_pattern = False
        for e in examples:
            if any(kw in e.code_context.lower() for kw in safe_keywords):
                has_safe_pattern = True
                break

        assert has_safe_pattern
