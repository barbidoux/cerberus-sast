"""
LLM Classifier for Phase II Spec Inference.

Uses LLM with classification prompts to confirm or reject
candidate sources, sinks, and sanitizers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from cerberus.inference.candidate_extractor import Candidate, CandidateType
from cerberus.llm.prompts.classification import (
    ClassificationResponse,
    PromptBuilder,
)
from cerberus.llm.providers.models import LLMRequest, LLMResponse, Message, Role
from cerberus.models.base import TaintLabel
from cerberus.models.spec import TaintSpec


@dataclass
class ClassificationResult:
    """
    Result of classifying a candidate with LLM.

    Contains the classification decision, confidence, and reasoning.
    """

    candidate: Candidate
    confirmed: bool
    label: TaintLabel
    confidence: float
    reason: str = ""
    vulnerability_types: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_taint_spec(self) -> Optional[TaintSpec]:
        """
        Convert to TaintSpec if confirmed.

        Returns:
            TaintSpec if confirmed, None otherwise
        """
        if not self.confirmed:
            return None

        return TaintSpec(
            method=self.candidate.symbol.name,
            file_path=self.candidate.symbol.file_path,
            line=self.candidate.symbol.line,
            label=self.label,
            class_name=self.candidate.symbol.parent_class,
            confidence=self.confidence,
            reason=self.reason,
            vulnerability_types=self.vulnerability_types,
            metadata={
                "heuristic_score": self.candidate.score,
                "heuristic_reason": self.candidate.reason,
                **self.metadata,
            },
        )


@dataclass
class ClassifierConfig:
    """Configuration for LLM classifier."""

    min_confidence: float = 0.7
    batch_size: int = 10
    include_code_context: bool = True
    model: Optional[str] = None  # Override LLM model


class LLMClassifier:
    """
    Classifies candidates using LLM with Few-Shot CoT prompts.

    Takes candidates from the CandidateExtractor and uses LLM
    to confirm or reject their classification as sources, sinks,
    or sanitizers.
    """

    def __init__(
        self,
        config: Optional[ClassifierConfig] = None,
        gateway: Optional[Any] = None,  # LLMGateway
    ) -> None:
        """
        Initialize classifier.

        Args:
            config: Classifier configuration
            gateway: Optional LLMGateway instance (for dependency injection)
        """
        self.config = config or ClassifierConfig()
        self.gateway = gateway
        self.prompt_builder = PromptBuilder()

        # Statistics tracking
        self._stats = {
            "total_classifications": 0,
            "confirmed_count": 0,
            "rejected_count": 0,
            "error_count": 0,
        }

    async def classify(
        self,
        candidate: Candidate,
        code_snippet: Optional[str] = None,
    ) -> ClassificationResult:
        """
        Classify a single candidate using LLM.

        Args:
            candidate: The candidate to classify
            code_snippet: Optional code context for the candidate

        Returns:
            ClassificationResult with LLM's decision
        """
        try:
            # Build the prompt
            target_label = candidate.candidate_type.to_taint_label()

            # Get code: prefer snippet, then extract from file, then signature fallback
            code = code_snippet
            if not code:
                code = self._extract_function_source(
                    candidate.symbol.file_path,
                    candidate.symbol.line,
                    candidate.symbol.name,
                )
            if not code:
                code = candidate.symbol.signature or f"def {candidate.symbol.name}():"

            # Detect language from file extension
            language = self._detect_language(candidate.symbol.file_path)

            prompt = self.prompt_builder.build_classification_prompt(
                code=code,
                language=language,
                target_label=target_label,
            )

            # Call LLM
            response = await self._call_llm(prompt)

            # Parse response
            classification = ClassificationResponse.from_json(response.content)

            # Determine if confirmed
            # Confirmed if LLM agrees with heuristic AND confidence is high enough
            is_confirmed = (
                classification.label == target_label and
                classification.confidence >= self.config.min_confidence
            )

            # Track stats
            self._stats["total_classifications"] += 1
            if is_confirmed:
                self._stats["confirmed_count"] += 1
            else:
                self._stats["rejected_count"] += 1

            return ClassificationResult(
                candidate=candidate,
                confirmed=is_confirmed,
                label=classification.label,
                confidence=classification.confidence,
                reason=classification.reason,
                vulnerability_types=classification.vulnerability_types,
            )

        except Exception as e:
            self._stats["total_classifications"] += 1
            self._stats["error_count"] += 1

            return ClassificationResult(
                candidate=candidate,
                confirmed=False,
                label=TaintLabel.NONE,
                confidence=0.0,
                reason=f"Error during classification: {str(e)}",
                metadata={"error": str(e)},
            )

    async def classify_any(
        self,
        candidate: Candidate,
        code_snippet: Optional[str] = None,
    ) -> ClassificationResult:
        """
        Classify a candidate without assuming a target label.

        Uses multi-label classification to determine the most
        appropriate label for the candidate.

        Args:
            candidate: The candidate to classify
            code_snippet: Optional code context

        Returns:
            ClassificationResult with LLM's decision
        """
        try:
            code = code_snippet or candidate.symbol.signature or f"def {candidate.symbol.name}():"
            language = self._detect_language(candidate.symbol.file_path)

            prompt = self.prompt_builder.build_multi_label_prompt(
                code=code,
                language=language,
            )

            response = await self._call_llm(prompt)
            classification = ClassificationResponse.from_json(response.content)

            # For multi-label, confirmed if confidence is high enough
            is_confirmed = classification.confidence >= self.config.min_confidence

            self._stats["total_classifications"] += 1
            if is_confirmed:
                self._stats["confirmed_count"] += 1
            else:
                self._stats["rejected_count"] += 1

            return ClassificationResult(
                candidate=candidate,
                confirmed=is_confirmed,
                label=classification.label,
                confidence=classification.confidence,
                reason=classification.reason,
                vulnerability_types=classification.vulnerability_types,
            )

        except Exception as e:
            self._stats["total_classifications"] += 1
            self._stats["error_count"] += 1

            return ClassificationResult(
                candidate=candidate,
                confirmed=False,
                label=TaintLabel.NONE,
                confidence=0.0,
                reason=f"Error during classification: {str(e)}",
                metadata={"error": str(e)},
            )

    async def classify_batch(
        self,
        candidates: list[Candidate],
        code_snippets: Optional[dict[str, str]] = None,
    ) -> list[ClassificationResult]:
        """
        Classify multiple candidates.

        Args:
            candidates: List of candidates to classify
            code_snippets: Optional dict mapping symbol names to code

        Returns:
            List of ClassificationResults
        """
        results: list[ClassificationResult] = []
        code_snippets = code_snippets or {}

        for candidate in candidates:
            code = code_snippets.get(candidate.symbol.name)
            result = await self.classify(candidate, code_snippet=code)
            results.append(result)

        return results

    async def _call_llm(self, prompt: Any) -> LLMResponse:
        """
        Call the LLM with the given prompt.

        Args:
            prompt: Built prompt with system and user messages

        Returns:
            LLM response
        """
        if self.gateway:
            # Use the provided gateway
            messages = prompt.to_messages()
            request = LLMRequest(
                messages=[Message(role=Role(m["role"]), content=m["content"]) for m in messages],
                model=self.config.model,
                temperature=0.0,  # Deterministic for classification
            )
            return await self.gateway.complete(request)
        else:
            # No gateway - raise for testing (should be mocked)
            raise RuntimeError("No LLM gateway configured")

    def _detect_language(self, file_path: Any) -> str:
        """Detect language from file extension."""
        path_str = str(file_path)

        if path_str.endswith(".py"):
            return "python"
        elif path_str.endswith(".js"):
            return "javascript"
        elif path_str.endswith(".ts"):
            return "typescript"
        elif path_str.endswith(".java"):
            return "java"
        elif path_str.endswith(".go"):
            return "go"
        elif path_str.endswith(".rb"):
            return "ruby"
        elif path_str.endswith(".php"):
            return "php"
        elif path_str.endswith(".c") or path_str.endswith(".h"):
            return "c"
        elif path_str.endswith(".cpp") or path_str.endswith(".hpp"):
            return "cpp"
        elif path_str.endswith(".cs"):
            return "csharp"
        elif path_str.endswith(".rs"):
            return "rust"
        else:
            return "unknown"

    def get_stats(self) -> dict[str, Any]:
        """Get classification statistics."""
        return dict(self._stats)

    def reset_stats(self) -> None:
        """Reset classification statistics."""
        self._stats = {
            "total_classifications": 0,
            "confirmed_count": 0,
            "rejected_count": 0,
            "error_count": 0,
        }

    def _extract_function_source(
        self,
        file_path: Any,
        start_line: int,
        func_name: str,
        max_lines: int = 50,
    ) -> Optional[str]:
        """
        Extract function source code from file.

        Args:
            file_path: Path to the source file
            start_line: Starting line number (1-indexed)
            func_name: Function name for validation
            max_lines: Maximum lines to extract

        Returns:
            Function source code or None if extraction fails
        """
        try:
            from pathlib import Path
            path = Path(file_path) if not isinstance(file_path, Path) else file_path

            if not path.exists():
                return None

            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            # Adjust to 0-indexed
            start_idx = start_line - 1
            if start_idx < 0 or start_idx >= len(lines):
                return None

            # Extract function with proper indentation handling
            func_lines = []
            base_indent = None

            for i in range(start_idx, min(start_idx + max_lines, len(lines))):
                line = lines[i]
                stripped = line.lstrip()

                # First line - get base indentation
                if i == start_idx:
                    base_indent = len(line) - len(stripped)
                    func_lines.append(line.rstrip())
                    continue

                # Empty lines are ok
                if not stripped:
                    func_lines.append("")
                    continue

                # Check indentation - if back to base level, we're done
                current_indent = len(line) - len(stripped)
                if current_indent <= base_indent and stripped and not stripped.startswith("#"):
                    # Check if this is a new function/class definition
                    if stripped.startswith(("def ", "class ", "@")):
                        break

                func_lines.append(line.rstrip())

            if func_lines:
                return "\n".join(func_lines)

            return None

        except Exception:
            return None

    # =========================================================================
    # Milestone 8: Taint Source/Sink Classification Methods
    # =========================================================================

    async def classify_taint_source(
        self,
        source: Any,  # TaintSource
        code_context: str,
        language: str = "javascript",
    ) -> Any:  # SourceClassificationResult
        """
        Classify an AST-extracted taint source using LLM.

        This method validates whether the AST-detected source is truly
        a taint source (untrusted user input) and enriches it with
        LLM-generated reasoning and refined CWE types.

        Args:
            source: TaintSource object from AST extraction
            code_context: ~50 lines of surrounding code
            language: Programming language

        Returns:
            SourceClassificationResult with LLM validation
        """
        from cerberus.llm.prompts.taint_classification import (
            SourceClassificationResult,
            build_source_classification_prompt,
        )

        try:
            # Build the prompt
            prompts = build_source_classification_prompt(
                expression=source.expression,
                code_context=code_context,
                language=language,
                line=source.line,
                ast_source_type=source.source_type.value,
            )

            # Call LLM
            response = await self._call_llm_raw(
                system_prompt=prompts["system"],
                user_prompt=prompts["user"],
            )

            # Parse response
            result = SourceClassificationResult.from_json(response.content)

            # Track stats
            self._stats["total_classifications"] += 1
            if result.is_source:
                self._stats["confirmed_count"] += 1
            else:
                self._stats["rejected_count"] += 1

            return result

        except Exception as e:
            self._stats["total_classifications"] += 1
            self._stats["error_count"] += 1

            return SourceClassificationResult(
                is_source=True,  # Fail open - trust AST on error
                confidence=0.5,
                source_type=source.source_type.value,
                cwe_types=source.cwe_types,
                reasoning=f"LLM classification failed: {str(e)}",
            )

    async def classify_taint_sink(
        self,
        sink: Any,  # TaintSink
        code_context: str,
        language: str = "javascript",
    ) -> Any:  # SinkClassificationResult
        """
        Classify an AST-extracted taint sink using LLM.

        This method validates whether the AST-detected sink is truly
        a dangerous operation and enriches it with LLM-generated
        reasoning and sanitization detection.

        Args:
            sink: TaintSink object from AST extraction
            code_context: ~50 lines of surrounding code
            language: Programming language

        Returns:
            SinkClassificationResult with LLM validation
        """
        from cerberus.llm.prompts.taint_classification import (
            SinkClassificationResult,
            build_sink_classification_prompt,
        )

        try:
            # Build the prompt
            prompts = build_sink_classification_prompt(
                expression=sink.expression,
                callee=sink.callee,
                code_context=code_context,
                language=language,
                line=sink.line,
                uses_template_literal=sink.uses_template_literal,
                ast_sink_type=sink.sink_type.value,
            )

            # Call LLM
            response = await self._call_llm_raw(
                system_prompt=prompts["system"],
                user_prompt=prompts["user"],
            )

            # Parse response
            result = SinkClassificationResult.from_json(response.content)

            # Track stats
            self._stats["total_classifications"] += 1
            if result.is_sink:
                self._stats["confirmed_count"] += 1
            else:
                self._stats["rejected_count"] += 1

            return result

        except Exception as e:
            self._stats["total_classifications"] += 1
            self._stats["error_count"] += 1

            return SinkClassificationResult(
                is_sink=True,  # Fail open - trust AST on error
                confidence=0.5,
                sink_type=sink.sink_type.value,
                cwe_types=sink.cwe_types,
                reasoning=f"LLM classification failed: {str(e)}",
            )

    async def classify_sources_batch(
        self,
        sources: list[Any],  # list[TaintSource]
        code_contexts: dict[str, str],  # {location_key: code_context}
        language: str = "javascript",
        batch_size: int = 6,
    ) -> list[Any]:  # list[SourceClassificationResult]
        """
        Classify multiple taint sources in batched LLM calls.

        More efficient than individual calls for large source lists.

        Args:
            sources: List of TaintSource objects
            code_contexts: Dict mapping source location_key to code context
            language: Programming language
            batch_size: Number of sources per LLM call

        Returns:
            List of SourceClassificationResult objects
        """
        from cerberus.llm.prompts.taint_classification import (
            SourceClassificationResult,
            build_batch_source_prompt,
            parse_batch_results,
        )

        results = []

        for i in range(0, len(sources), batch_size):
            batch = sources[i:i + batch_size]

            # Prepare batch data
            batch_data = []
            for source in batch:
                batch_data.append({
                    "expression": source.expression,
                    "line": source.line,
                    "ast_type": source.source_type.value,
                    "code_context": code_contexts.get(source.location_key, ""),
                })

            try:
                # Build batch prompt
                prompts = build_batch_source_prompt(batch_data, language)

                # Call LLM
                response = await self._call_llm_raw(
                    system_prompt=prompts["system"],
                    user_prompt=prompts["user"],
                )

                # Parse batch results
                batch_results = parse_batch_results(
                    response.content,
                    len(batch),
                    SourceClassificationResult,
                )
                results.extend(batch_results)

            except Exception as e:
                # On error, return conservative results for batch
                for source in batch:
                    results.append(SourceClassificationResult(
                        is_source=True,  # Fail open
                        confidence=0.5,
                        source_type=source.source_type.value,
                        cwe_types=source.cwe_types,
                        reasoning=f"Batch classification failed: {str(e)}",
                    ))

        return results

    async def classify_sinks_batch(
        self,
        sinks: list[Any],  # list[TaintSink]
        code_contexts: dict[str, str],  # {location_key: code_context}
        language: str = "javascript",
        batch_size: int = 6,
    ) -> list[Any]:  # list[SinkClassificationResult]
        """
        Classify multiple taint sinks in batched LLM calls.

        Args:
            sinks: List of TaintSink objects
            code_contexts: Dict mapping sink location_key to code context
            language: Programming language
            batch_size: Number of sinks per LLM call

        Returns:
            List of SinkClassificationResult objects
        """
        from cerberus.llm.prompts.taint_classification import (
            SinkClassificationResult,
            build_batch_sink_prompt,
            parse_batch_results,
        )

        results = []

        for i in range(0, len(sinks), batch_size):
            batch = sinks[i:i + batch_size]

            # Prepare batch data
            batch_data = []
            for sink in batch:
                batch_data.append({
                    "callee": sink.callee,
                    "expression": sink.expression,
                    "line": sink.line,
                    "ast_type": sink.sink_type.value,
                    "uses_template_literal": sink.uses_template_literal,
                    "code_context": code_contexts.get(sink.location_key, ""),
                })

            try:
                # Build batch prompt
                prompts = build_batch_sink_prompt(batch_data, language)

                # Call LLM
                response = await self._call_llm_raw(
                    system_prompt=prompts["system"],
                    user_prompt=prompts["user"],
                )

                # Parse batch results
                batch_results = parse_batch_results(
                    response.content,
                    len(batch),
                    SinkClassificationResult,
                )
                results.extend(batch_results)

            except Exception as e:
                # On error, return conservative results for batch
                for sink in batch:
                    results.append(SinkClassificationResult(
                        is_sink=True,  # Fail open
                        confidence=0.5,
                        sink_type=sink.sink_type.value,
                        cwe_types=sink.cwe_types,
                        reasoning=f"Batch classification failed: {str(e)}",
                    ))

        return results

    async def _call_llm_raw(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> LLMResponse:
        """
        Call LLM with raw system and user prompts.

        Args:
            system_prompt: System prompt content
            user_prompt: User prompt content

        Returns:
            LLM response
        """
        if self.gateway:
            messages = [
                Message(role=Role.SYSTEM, content=system_prompt),
                Message(role=Role.USER, content=user_prompt),
            ]
            request = LLMRequest(
                messages=messages,
                model=self.config.model,
                temperature=0.0,  # Deterministic
            )
            return await self.gateway.complete(request)
        else:
            raise RuntimeError("No LLM gateway configured")
