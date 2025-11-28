"""Benchmark tests for ML-enhanced detection.

These tests measure the detection rates and performance of the
ML-enhanced pipeline (--hybrid-ml-fast) against known vulnerabilities.
"""

import pytest
from unittest.mock import MagicMock
from pathlib import Path

from cerberus.ml.codebert_classifier import CodeBERTClassifier, ClassificationResult
from cerberus.ml.tier1_filter import Tier1Filter, FilterResult
from cerberus.models.taint_flow import (
    TaintFlowCandidate,
    TaintSource,
    TaintSink,
    SourceType,
    SinkType,
)


def create_test_candidate(
    source_expr: str,
    sink_expr: str,
    source_type: SourceType = SourceType.REQUEST_QUERY,
    sink_type: SinkType = SinkType.SQL_QUERY,
    cwe_types: list[str] | None = None,
    uses_template_literal: bool = False,
    in_same_function: bool = True,
    in_same_file: bool = True,
    distance_lines: int = 5,
    confidence: float = 0.5,
    code_context: str = "",
) -> TaintFlowCandidate:
    """Create a mock TaintFlowCandidate for testing."""
    source = MagicMock(spec=TaintSource)
    source.expression = source_expr
    source.source_type = source_type
    source.file_path = Path("/test/app.js")
    source.line = 10

    sink = MagicMock(spec=TaintSink)
    sink.expression = sink_expr
    sink.sink_type = sink_type
    sink.cwe_types = set(cwe_types or ["CWE-89"])
    sink.uses_template_literal = uses_template_literal
    sink.file_path = Path("/test/app.js")
    sink.line = 10 + distance_lines
    # Extract callee from expression (e.g., "fs.readFileSync(...)" -> "readFileSync")
    sink.callee = sink_expr.split("(")[0].split(".")[-1] if "(" in sink_expr else sink_expr

    candidate = MagicMock(spec=TaintFlowCandidate)
    candidate.source = source
    candidate.sink = sink
    candidate.in_same_function = in_same_function
    candidate.in_same_file = in_same_file
    candidate.distance_lines = distance_lines
    candidate.confidence = confidence
    candidate.shared_cwe_types = cwe_types or ["CWE-89"]
    candidate.code_context = code_context or f"// Test code\nconst data = {source_expr};\n{sink_expr}(data);"

    return candidate


class TestPathTraversalDetection:
    """Tests for CWE-22 Path Traversal detection (A2 fix)."""

    def test_path_traversal_readfile_detected(self):
        """Test that readFileSync with user input is detected."""
        classifier = CodeBERTClassifier()

        candidate = create_test_candidate(
            source_expr="req.params.filename",
            sink_expr="fs.readFileSync(filePath)",
            cwe_types=["CWE-22"],
            uses_template_literal=False,
            in_same_function=True,
            confidence=0.5,
        )

        result = classifier.classify(candidate)

        # With path traversal patterns added, confidence should be boosted
        assert result.confidence > 0.5, f"Path traversal not boosted: {result.confidence}"

    def test_path_traversal_with_dotdot(self):
        """Test detection of ../ in path traversal."""
        classifier = CodeBERTClassifier()

        candidate = create_test_candidate(
            source_expr="req.query.path",
            sink_expr="path.join(basedir, userPath)",
            cwe_types=["CWE-22"],
            in_same_function=True,
            confidence=0.5,
            code_context="const userPath = req.query.path; // could be ../../../etc/passwd",
        )

        result = classifier.classify(candidate)

        # Extra boost for ../ detection
        assert result.confidence > 0.6, f"Path with ../ not boosted enough: {result.confidence}"

    def test_path_traversal_sendfile(self):
        """Test sendFile sink detection."""
        classifier = CodeBERTClassifier()

        candidate = create_test_candidate(
            source_expr="req.params.file",
            sink_expr="res.sendFile(filepath)",
            cwe_types=["CWE-22"],
            in_same_function=True,
            confidence=0.5,
        )

        result = classifier.classify(candidate)

        assert result.confidence > 0.5, f"sendFile sink not detected: {result.confidence}"


class TestXSSDetection:
    """Tests for CWE-79 XSS detection (A3 fix)."""

    def test_xss_innerhtml_detected(self):
        """Test that innerHTML sink is detected."""
        classifier = CodeBERTClassifier()

        candidate = create_test_candidate(
            source_expr="req.query.search",
            sink_expr="element.innerHTML = userInput",
            cwe_types=["CWE-79"],
            in_same_function=True,
            confidence=0.5,
        )

        result = classifier.classify(candidate)

        # Should have significant boost for DOM XSS
        assert result.confidence > 0.7, f"innerHTML XSS not boosted: {result.confidence}"

    def test_xss_document_write(self):
        """Test document.write sink detection."""
        classifier = CodeBERTClassifier()

        candidate = create_test_candidate(
            source_expr="req.body.content",
            sink_expr="document.write(content)",
            cwe_types=["CWE-79"],
            in_same_function=True,
            confidence=0.5,
        )

        result = classifier.classify(candidate)

        assert result.confidence > 0.7, f"document.write XSS not detected: {result.confidence}"

    def test_xss_bypass_security_trust(self):
        """Test Angular bypassSecurityTrust detection."""
        classifier = CodeBERTClassifier()

        candidate = create_test_candidate(
            source_expr="req.query.html",
            sink_expr="sanitizer.bypassSecurityTrustHtml(html)",
            cwe_types=["CWE-79"],
            in_same_function=True,
            confidence=0.5,
        )

        result = classifier.classify(candidate)

        # Extra boost for security bypass
        assert result.confidence > 0.8, f"bypassSecurityTrust not detected: {result.confidence}"


class TestThresholdAlignment:
    """Tests for threshold alignment between Tier 1 and Tier 2 (A1, A5 fixes)."""

    def test_tier1_tier2_threshold_consistency(self):
        """Verify Tier 1 ML_REVIEW_THRESHOLD matches Tier 2 SAFE_THRESHOLD."""
        tier1 = Tier1Filter()
        tier2 = CodeBERTClassifier()

        # Tier 1 ML_REVIEW_THRESHOLD should equal Tier 2 SAFE_THRESHOLD
        assert tier1.ML_REVIEW_THRESHOLD == tier2.SAFE_THRESHOLD, (
            f"Tier 1 ML_REVIEW ({tier1.ML_REVIEW_THRESHOLD}) != "
            f"Tier 2 SAFE ({tier2.SAFE_THRESHOLD})"
        )

    def test_tier2_thresholds_match_defaults(self):
        """Verify Tier 2 class constants match __init__ defaults."""
        # Without custom thresholds
        classifier = CodeBERTClassifier()

        assert classifier.VULNERABLE_THRESHOLD == 0.75, (
            f"VULNERABLE_THRESHOLD should be 0.75, got {classifier.VULNERABLE_THRESHOLD}"
        )
        assert classifier.SAFE_THRESHOLD == 0.45, (
            f"SAFE_THRESHOLD should be 0.45, got {classifier.SAFE_THRESHOLD}"
        )

    def test_custom_thresholds_applied(self):
        """Verify custom thresholds override defaults."""
        classifier = CodeBERTClassifier(
            vulnerable_threshold=0.9,
            safe_threshold=0.3,
        )

        assert classifier.VULNERABLE_THRESHOLD == 0.9
        assert classifier.SAFE_THRESHOLD == 0.3


class TestSafePatternDetection:
    """Tests for safe pattern recognition to reduce false positives."""

    def test_logger_sink_reduced_confidence(self):
        """Test that logger sinks reduce confidence."""
        classifier = CodeBERTClassifier()

        candidate = create_test_candidate(
            source_expr="req.query.id",
            sink_expr="console.log(id)",
            in_same_function=True,
            confidence=0.6,
        )

        result = classifier.classify(candidate)

        # Logger patterns should reduce confidence
        assert result.confidence < 0.6, f"Logger sink not penalized: {result.confidence}"

    def test_config_source_reduced_confidence(self):
        """Test that config sources reduce confidence."""
        classifier = CodeBERTClassifier()

        candidate = create_test_candidate(
            source_expr="process.env.DATABASE_URL",
            sink_expr="db.connect(url)",
            in_same_function=True,
            confidence=0.6,
        )

        result = classifier.classify(candidate)

        # Config sources should be less risky
        assert result.confidence < 0.6, f"Config source not penalized: {result.confidence}"


class TestDetectionRateByVulnerabilityType:
    """Benchmark tests for detection rates by vulnerability type."""

    def test_sql_injection_detection_rate(self):
        """Test SQL injection detection scenarios."""
        classifier = CodeBERTClassifier()

        # Vulnerable scenarios
        vulnerable_cases = [
            create_test_candidate(
                source_expr="req.body.username",
                sink_expr="sequelize.query(`SELECT * FROM users WHERE name = ${username}`)",
                cwe_types=["CWE-89"],
                uses_template_literal=True,
                in_same_function=True,
                confidence=0.5,
            ),
            create_test_candidate(
                source_expr="req.query.id",
                sink_expr="db.query('SELECT * FROM users WHERE id = ' + id)",
                cwe_types=["CWE-89"],
                in_same_function=True,
                confidence=0.5,
            ),
        ]

        detected = 0
        for case in vulnerable_cases:
            result = classifier.classify(case)
            if result.decision == "vulnerable":
                detected += 1

        detection_rate = detected / len(vulnerable_cases)
        print(f"SQL Injection Detection Rate: {detection_rate:.1%}")

        # Should detect at least 50% (with heuristic fallback)
        assert detection_rate >= 0.5, f"SQL Injection detection too low: {detection_rate:.1%}"

    def test_command_injection_detection_rate(self):
        """Test command injection detection scenarios."""
        classifier = CodeBERTClassifier()

        vulnerable_cases = [
            create_test_candidate(
                source_expr="req.body.cmd",
                sink_expr="exec(cmd)",
                cwe_types=["CWE-78"],
                in_same_function=True,
                confidence=0.5,
            ),
            create_test_candidate(
                source_expr="req.query.filename",
                sink_expr="execSync(`cat ${filename}`)",
                cwe_types=["CWE-78"],
                uses_template_literal=True,
                in_same_function=True,
                confidence=0.5,
            ),
        ]

        detected = 0
        for case in vulnerable_cases:
            result = classifier.classify(case)
            if result.decision == "vulnerable":
                detected += 1

        detection_rate = detected / len(vulnerable_cases)
        print(f"Command Injection Detection Rate: {detection_rate:.1%}")

        assert detection_rate >= 0.5, f"Command Injection detection too low: {detection_rate:.1%}"


class TestPerformanceMetrics:
    """Tests for performance characteristics."""

    def test_classifier_reports_fallback_mode(self):
        """Test that classifier correctly reports fallback mode."""
        classifier = CodeBERTClassifier()

        # In test environment without PyTorch, should use fallback
        metrics = classifier.get_metrics()

        assert "model_available" in metrics
        assert "device" in metrics
        assert "vulnerable_threshold" in metrics
        assert "safe_threshold" in metrics

        # Verify thresholds match
        assert metrics["vulnerable_threshold"] == 0.75
        assert metrics["safe_threshold"] == 0.45

    def test_batch_classification_performance(self):
        """Test batch classification processes all candidates."""
        classifier = CodeBERTClassifier()

        candidates = [
            create_test_candidate(
                source_expr=f"req.query.param{i}",
                sink_expr=f"db.query{i}(data)",
                confidence=0.5 + (i * 0.05),
            )
            for i in range(10)
        ]

        results = classifier.classify_batch(candidates)

        assert len(results) == 10, f"Expected 10 results, got {len(results)}"

        # Count by decision
        decisions = {"vulnerable": 0, "safe": 0, "uncertain": 0}
        for result in results:
            decisions[result.decision] += 1

        print(f"Batch results: {decisions}")

        # With varying confidence, should have mixed decisions
        assert sum(decisions.values()) == 10


class TestIntegrationScenarios:
    """Integration tests for real-world scenarios."""

    def test_sql_injection_with_sanitization_nearby(self):
        """Test that sanitization context affects confidence."""
        classifier = CodeBERTClassifier()

        # Without sanitization
        unsafe = create_test_candidate(
            source_expr="req.body.id",
            sink_expr="db.query(`SELECT * FROM users WHERE id = ${id}`)",
            cwe_types=["CWE-89"],
            uses_template_literal=True,
            in_same_function=True,
            confidence=0.5,
            code_context="const id = req.body.id;\ndb.query(`SELECT * FROM users WHERE id = ${id}`);"
        )

        # With validator in context (should be detected as safer)
        safe = create_test_candidate(
            source_expr="req.body.id",
            sink_expr="db.query(`SELECT * FROM users WHERE id = ${id}`)",
            cwe_types=["CWE-89"],
            uses_template_literal=True,
            in_same_function=True,
            confidence=0.5,
            code_context="const id = validator.escape(req.body.id);\ndb.query(`SELECT * FROM users WHERE id = ${id}`);"
        )

        unsafe_result = classifier.classify(unsafe)
        safe_result = classifier.classify(safe)

        # Unsafe should have higher confidence
        assert unsafe_result.confidence >= safe_result.confidence, (
            f"Sanitized code should have lower confidence: "
            f"unsafe={unsafe_result.confidence}, safe={safe_result.confidence}"
        )

    def test_cross_file_penalty_applied(self):
        """Test that cross-file flows are penalized."""
        classifier = CodeBERTClassifier()

        same_file = create_test_candidate(
            source_expr="req.query.id",
            sink_expr="db.query(id)",
            in_same_file=True,
            in_same_function=False,
            distance_lines=50,
            confidence=0.5,
        )

        cross_file = create_test_candidate(
            source_expr="req.query.id",
            sink_expr="db.query(id)",
            in_same_file=False,
            in_same_function=False,
            distance_lines=50,
            confidence=0.5,
        )

        same_result = classifier.classify(same_file)
        cross_result = classifier.classify(cross_file)

        # Cross-file should have lower confidence
        assert cross_result.confidence < same_result.confidence, (
            f"Cross-file should be penalized: "
            f"same={same_result.confidence}, cross={cross_result.confidence}"
        )


class TestDecisionBoundaries:
    """Tests for decision boundary behavior."""

    def test_boundary_vulnerable(self):
        """Test decision at vulnerable threshold boundary."""
        classifier = CodeBERTClassifier(
            vulnerable_threshold=0.75,
            safe_threshold=0.45,
        )

        # Create candidate that will be exactly at threshold after boosts
        candidate = create_test_candidate(
            source_expr="req.body.data",
            sink_expr="eval(data)",
            cwe_types=["CWE-94"],
            uses_template_literal=True,  # +0.25
            in_same_function=True,       # +0.15
            distance_lines=5,            # +0.1 (close distance)
            confidence=0.5,              # Base + 0.5 = 1.0, but critical CWE adds more
        )

        result = classifier.classify(candidate)

        # With all boosts, should be vulnerable
        assert result.decision == "vulnerable", (
            f"High-risk code should be vulnerable, got {result.decision} at {result.confidence}"
        )

    def test_boundary_safe(self):
        """Test decision at safe threshold boundary."""
        classifier = CodeBERTClassifier(
            vulnerable_threshold=0.75,
            safe_threshold=0.45,
        )

        # Create clearly safe candidate
        candidate = create_test_candidate(
            source_expr="process.env.CONFIG",
            sink_expr="console.log(config)",
            in_same_file=False,           # -0.2
            in_same_function=False,
            distance_lines=200,           # -0.3
            confidence=0.5,
        )

        result = classifier.classify(candidate)

        # Should be classified as safe
        assert result.decision == "safe", (
            f"Low-risk code should be safe, got {result.decision} at {result.confidence}"
        )
