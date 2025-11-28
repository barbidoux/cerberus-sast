"""
Tier 2: CodeBERT Fast ML Classifier.

This is the second tier of the ML-enhanced pipeline. It uses a fine-tuned
CodeBERT model to classify vulnerability candidates:
- "vulnerable": Confirmed vulnerability (confidence >= 0.75)
- "safe": Confirmed safe code (confidence <= 0.45)
- "uncertain": Needs LLM review (Tier 3)

Performance:
- Speed: ~50ms per candidate (batched)
- VRAM: ~2GB
- Accuracy: ~85% on vulnerability classification
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cerberus.models.taint_flow import TaintFlowCandidate

logger = logging.getLogger(__name__)

# Try to import torch and transformers
TORCH_AVAILABLE = False
TRANSFORMERS_AVAILABLE = False

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    logger.warning("PyTorch not available - CodeBERT classifier will use fallback")

try:
    from transformers import RobertaTokenizer, RobertaForSequenceClassification
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    logger.warning("Transformers not available - CodeBERT classifier will use fallback")


@dataclass
class ClassificationResult:
    """Result from CodeBERT classification."""

    candidate: TaintFlowCandidate
    confidence: float  # 0.0-1.0 probability of being vulnerable
    decision: str      # "vulnerable" | "safe" | "uncertain"
    reasoning: Optional[str] = None


class CodeBERTClassifier:
    """
    Fast ML-based vulnerability classifier using CodeBERT.

    This is Tier 2 of the ML-enhanced pipeline. It provides:
    - Fast classification (~50ms per candidate)
    - Good accuracy (~85% on vulnerability detection)
    - Low VRAM usage (~2GB)

    The classifier outputs three decisions:
    - "vulnerable" (confidence >= 0.75): Direct to findings
    - "safe" (confidence <= 0.45): Filter out
    - "uncertain" (0.45 < confidence < 0.75): Send to Tier 3 LLM

    Note: If PyTorch/Transformers are not available, falls back to
    heuristic-based classification.
    """

    # Classification thresholds
    VULNERABLE_THRESHOLD = 0.75  # Above this = confirmed vulnerable
    SAFE_THRESHOLD = 0.45        # Below this = confirmed safe
    # Between = uncertain, needs LLM review (narrower band = fewer LLM calls)

    def __init__(
        self,
        model_path: Optional[str] = None,
        device: Optional[str] = None,
        vulnerable_threshold: float = 0.75,
        safe_threshold: float = 0.45,
    ):
        """
        Initialize CodeBERT classifier.

        Args:
            model_path: Path to fine-tuned model weights (LoRA).
                       If None, uses base CodeBERT (less accurate).
            device: Device to use ("cuda" or "cpu"). Auto-detected if None.
            vulnerable_threshold: Confidence threshold for "vulnerable" decision
            safe_threshold: Confidence threshold for "safe" decision
        """
        self.model_path = model_path
        self.VULNERABLE_THRESHOLD = vulnerable_threshold
        self.SAFE_THRESHOLD = safe_threshold

        # Initialize model if available
        self.model = None
        self.tokenizer = None
        self.device = None
        self._use_fallback = True

        if TORCH_AVAILABLE and TRANSFORMERS_AVAILABLE:
            try:
                self._initialize_model(model_path, device)
                self._use_fallback = False
                logger.info(f"CodeBERT classifier initialized on {self.device}")
            except Exception as e:
                logger.warning(f"Failed to load CodeBERT model: {e}. Using fallback.")
                self._use_fallback = True
        else:
            logger.info("Using heuristic fallback (PyTorch/Transformers not available)")

    def _initialize_model(self, model_path: Optional[str], device: Optional[str]):
        """Initialize the CodeBERT model."""
        import torch
        from transformers import RobertaTokenizer, RobertaForSequenceClassification

        # Determine device
        if device:
            self.device = torch.device(device)
        elif torch.cuda.is_available():
            self.device = torch.device("cuda")
        else:
            self.device = torch.device("cpu")

        # Load tokenizer
        self.tokenizer = RobertaTokenizer.from_pretrained("microsoft/codebert-base")

        # Load model
        if model_path and Path(model_path).exists():
            # Load fine-tuned model with LoRA weights
            try:
                from peft import PeftModel

                base_model = RobertaForSequenceClassification.from_pretrained(
                    "microsoft/codebert-base",
                    num_labels=2,
                )
                self.model = PeftModel.from_pretrained(base_model, model_path)
                logger.info(f"Loaded fine-tuned model from {model_path}")
            except ImportError:
                logger.warning("PEFT not available, loading base model without LoRA")
                self.model = RobertaForSequenceClassification.from_pretrained(
                    "microsoft/codebert-base",
                    num_labels=2,
                )
        else:
            # Load base CodeBERT (less accurate without fine-tuning)
            self.model = RobertaForSequenceClassification.from_pretrained(
                "microsoft/codebert-base",
                num_labels=2,
            )
            logger.info("Using base CodeBERT (not fine-tuned)")

        self.model.to(self.device)
        self.model.eval()

    def classify(self, candidate: TaintFlowCandidate) -> ClassificationResult:
        """
        Classify a single candidate.

        Args:
            candidate: Taint flow candidate to classify

        Returns:
            ClassificationResult with confidence and decision
        """
        results = self.classify_batch([candidate])
        return results[0] if results else ClassificationResult(
            candidate=candidate,
            confidence=0.5,
            decision="uncertain",
            reasoning="Classification failed",
        )

    def classify_batch(
        self,
        candidates: list[TaintFlowCandidate],
        batch_size: int = 32,
    ) -> list[ClassificationResult]:
        """
        Classify a batch of candidates.

        Args:
            candidates: List of taint flow candidates
            batch_size: Batch size for inference

        Returns:
            List of ClassificationResult for each candidate
        """
        if not candidates:
            return []

        if self._use_fallback:
            return self._classify_heuristic(candidates)

        return self._classify_ml(candidates, batch_size)

    def _classify_ml(
        self,
        candidates: list[TaintFlowCandidate],
        batch_size: int,
    ) -> list[ClassificationResult]:
        """Classify using CodeBERT model."""
        import torch

        results: list[ClassificationResult] = []

        for i in range(0, len(candidates), batch_size):
            batch = candidates[i:i + batch_size]

            # Format inputs
            texts = [self._format_input(c) for c in batch]

            # Tokenize
            inputs = self.tokenizer(
                texts,
                padding=True,
                truncation=True,
                max_length=512,
                return_tensors="pt",
            ).to(self.device)

            # Forward pass
            with torch.no_grad():
                outputs = self.model(**inputs)
                probs = torch.softmax(outputs.logits, dim=-1)

            # Process results
            for j, candidate in enumerate(batch):
                vuln_prob = probs[j, 1].item()  # Probability of "vulnerable" class

                decision = self._decide(vuln_prob)
                reasoning = self._generate_reasoning(candidate, vuln_prob, decision)

                results.append(ClassificationResult(
                    candidate=candidate,
                    confidence=vuln_prob,
                    decision=decision,
                    reasoning=reasoning,
                ))

        logger.info(
            f"CodeBERT classified {len(candidates)} candidates: "
            f"{sum(1 for r in results if r.decision == 'vulnerable')} vulnerable, "
            f"{sum(1 for r in results if r.decision == 'safe')} safe, "
            f"{sum(1 for r in results if r.decision == 'uncertain')} uncertain"
        )

        return results

    def _classify_heuristic(
        self,
        candidates: list[TaintFlowCandidate],
    ) -> list[ClassificationResult]:
        """Fallback heuristic classification when ML model not available."""
        results: list[ClassificationResult] = []

        # Safe patterns (reduce confidence)
        safe_sink_patterns = {
            "log", "debug", "info", "warn", "error", "trace", "console",
            "print", "logger", "assert", "test", "mock", "spy",
        }
        safe_source_patterns = {
            "process.env", "config", "constant", "default", "static",
        }

        # Path traversal patterns (CWE-22) - boost confidence
        path_traversal_sinks = {
            "readfile", "readfilesync", "writefile", "writefilesync",
            "createreadstream", "createwritestream", "unlink", "rmdir",
            "stat", "access", "open", "fs.", "path.join", "path.resolve",
            "sendfile", "download", "serve", "static",
        }
        path_traversal_sources = {
            "req.params", "req.query", "req.body", "filename", "filepath",
            "path", "file", "dir", "directory", "folder",
        }

        # XSS patterns (CWE-79) - boost confidence
        xss_sinks = {
            "innerhtml", "outerhtml", "document.write", "document.writeln",
            "insertadjacenthtml", "bypasssecuritytrusthtml", "bypasssecuritytrustscript",
            "bypasssecuritytrusturl", "res.send", "res.write", "render",
            "dangerouslysetinnerhtml", "v-html",
        }
        xss_sources = {
            "req.query", "req.body", "req.params", "userinput", "search",
            "query", "message", "comment", "name", "title", "content",
        }

        for candidate in candidates:
            # Heuristic confidence calculation - start with base
            confidence = candidate.confidence

            # ====== HIGH-RISK PATTERNS (boost confidence) ======
            if candidate.sink.uses_template_literal:
                confidence += 0.25
            if candidate.in_same_function:
                confidence += 0.15
            if candidate.distance_lines < 10:
                confidence += 0.1

            # CWE-specific boosts
            critical_cwes = {"CWE-78", "CWE-94", "CWE-502"}
            if any(cwe in candidate.sink.cwe_types for cwe in critical_cwes):
                confidence += 0.1

            # ====== PATH TRAVERSAL DETECTION (CWE-22) ======
            sink_lower = candidate.sink.expression.lower()
            source_lower = candidate.source.expression.lower()

            # Check for path traversal patterns
            is_path_traversal_sink = any(p in sink_lower for p in path_traversal_sinks)
            is_path_traversal_source = any(p in source_lower for p in path_traversal_sources)

            # File system sinks with ANY user input are dangerous
            if is_path_traversal_sink:
                confidence += 0.35  # Base boost for file system sink
                # Extra boost if source matches path-like patterns
                if is_path_traversal_source:
                    confidence += 0.15
                # Extra boost if "../" or "..\\" in expression or code context
                code_context = getattr(candidate, "code_context", "") or ""
                if ".." in source_lower or ".." in code_context:
                    confidence += 0.2

            # ====== XSS DETECTION (CWE-79) ======
            # Check for XSS patterns
            is_xss_sink = any(p in sink_lower for p in xss_sinks)
            is_xss_source = any(p in source_lower for p in xss_sources)

            # XSS sinks with ANY user input are dangerous
            if is_xss_sink:
                confidence += 0.25  # Base boost for XSS sink
                # Extra boost if source matches user input patterns
                if is_xss_source:
                    confidence += 0.1
                # Extra boost for DOM XSS patterns
                if "innerhtml" in sink_lower or "document.write" in sink_lower:
                    confidence += 0.15
                # Extra boost for security bypass
                if "bypasssecuritytrust" in sink_lower:
                    confidence += 0.2

            # ====== SAFE PATTERNS (reduce confidence) ======
            # Cross-file flows are less likely to be direct vulnerabilities
            if not candidate.in_same_file:
                confidence -= 0.2

            # Very long distance suggests indirect/unlikely flow
            if candidate.distance_lines > 100:
                confidence -= 0.3
            elif candidate.distance_lines > 50:
                confidence -= 0.15

            # Safe sink patterns (logging, debugging)
            # Use callee name, not full expression, to avoid false positives
            # (e.g., "logPath" in expression shouldn't trigger "log" pattern)
            callee_lower = candidate.sink.callee.lower()
            if any(pattern in callee_lower for pattern in safe_sink_patterns):
                confidence -= 0.4

            # Safe source patterns (config, constants)
            if any(pattern in source_lower for pattern in safe_source_patterns):
                confidence -= 0.3

            # Low-risk CWEs
            low_risk_cwes = {"CWE-20", "CWE-200"}  # Input validation, info disclosure
            if candidate.sink.cwe_types and all(
                cwe in low_risk_cwes for cwe in candidate.sink.cwe_types
            ):
                confidence -= 0.15

            # Penalty for "indirect" flows lacking high-risk indicators
            has_high_risk = (
                candidate.sink.uses_template_literal or
                candidate.in_same_function or
                candidate.distance_lines < 10
            )
            if not has_high_risk:
                confidence -= 0.2  # Push indirect flows toward "safe"

            # Clamp confidence to [0.0, 1.0]
            confidence = max(0.0, min(confidence, 1.0))

            decision = self._decide(confidence)
            reasoning = self._generate_heuristic_reasoning(candidate, confidence, decision)

            results.append(ClassificationResult(
                candidate=candidate,
                confidence=confidence,
                decision=decision,
                reasoning=reasoning,
            ))

        logger.info(
            f"Heuristic classified {len(candidates)} candidates: "
            f"{sum(1 for r in results if r.decision == 'vulnerable')} vulnerable, "
            f"{sum(1 for r in results if r.decision == 'safe')} safe, "
            f"{sum(1 for r in results if r.decision == 'uncertain')} uncertain"
        )

        return results

    def _decide(self, confidence: float) -> str:
        """Make decision based on confidence threshold."""
        if confidence >= self.VULNERABLE_THRESHOLD:
            return "vulnerable"
        elif confidence <= self.SAFE_THRESHOLD:
            return "safe"
        else:
            return "uncertain"

    def _format_input(self, candidate: TaintFlowCandidate) -> str:
        """Format candidate for model input."""
        parts = [
            f"Source: {candidate.source.expression}",
            f"Source Type: {candidate.source.source_type.value}",
            f"Sink: {candidate.sink.expression}",
            f"Sink Type: {candidate.sink.sink_type.value}",
            f"CWE Types: {', '.join(candidate.sink.cwe_types)}",
            f"Template Literal: {candidate.sink.uses_template_literal}",
            f"Same Function: {candidate.in_same_function}",
        ]

        if candidate.code_context:
            parts.append(f"Code Context:\n{candidate.code_context[:1000]}")

        return "\n".join(parts)

    def _generate_reasoning(
        self,
        candidate: TaintFlowCandidate,
        confidence: float,
        decision: str,
    ) -> str:
        """Generate reasoning string for ML classification."""
        reasons = []

        if decision == "vulnerable":
            reasons.append(f"ML model confidence: {confidence:.2%}")
            if candidate.sink.uses_template_literal:
                reasons.append("Template literal detected (high risk)")
            if candidate.in_same_function:
                reasons.append("Source and sink in same function scope")
        elif decision == "safe":
            reasons.append(f"ML model confidence: {confidence:.2%}")
            reasons.append("Pattern unlikely to be exploitable")
        else:
            reasons.append(f"ML model confidence: {confidence:.2%} (uncertain range)")
            reasons.append("Requires LLM analysis for accurate classification")

        return "; ".join(reasons)

    def _generate_heuristic_reasoning(
        self,
        candidate: TaintFlowCandidate,
        confidence: float,
        decision: str,
    ) -> str:
        """Generate reasoning string for heuristic classification."""
        reasons = []

        if decision == "vulnerable":
            reasons.append(f"Heuristic confidence: {confidence:.2%}")
            if candidate.sink.uses_template_literal:
                reasons.append("Template literal pattern")
            if candidate.in_same_function:
                reasons.append("Direct data flow in same function")
        elif decision == "safe":
            reasons.append(f"Heuristic confidence: {confidence:.2%}")
            reasons.append("Low-risk pattern")
        else:
            reasons.append(f"Heuristic confidence: {confidence:.2%}")
            reasons.append("Needs further analysis")

        return " | ".join(reasons)

    def is_available(self) -> bool:
        """Check if ML model is available (not using fallback)."""
        return not self._use_fallback

    def get_device(self) -> str:
        """Get the device being used."""
        if self.device:
            return str(self.device)
        return "cpu (fallback)"

    def get_metrics(self) -> dict:
        """Get classifier configuration and metrics."""
        return {
            "model_available": not self._use_fallback,
            "device": self.get_device(),
            "vulnerable_threshold": self.VULNERABLE_THRESHOLD,
            "safe_threshold": self.SAFE_THRESHOLD,
            "model_path": self.model_path,
        }
