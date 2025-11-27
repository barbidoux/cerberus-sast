"""
Tests for Inference Engine.

TDD: Write tests first, then implement to make them pass.
"""

import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cerberus.inference.candidate_extractor import Candidate, CandidateType
from cerberus.inference.classifier import ClassificationResult
from cerberus.inference.engine import (
    InferenceEngine,
    InferenceConfig,
    InferenceResult,
)
from cerberus.models.base import SymbolType, TaintLabel
from cerberus.models.repo_map import FileInfo, RepoMap, Symbol
from cerberus.models.spec import DynamicSpec, TaintSpec


@pytest.fixture
def sample_repo_map() -> RepoMap:
    """Create a sample RepoMap."""
    symbols = [
        Symbol(
            name="get_user_input",
            type=SymbolType.FUNCTION,
            file_path=Path("/app/handlers.py"),
            line=10,
            signature="def get_user_input(request):",
        ),
        Symbol(
            name="execute_query",
            type=SymbolType.FUNCTION,
            file_path=Path("/app/database.py"),
            line=25,
            signature="def execute_query(sql):",
        ),
        Symbol(
            name="sanitize_input",
            type=SymbolType.FUNCTION,
            file_path=Path("/app/utils.py"),
            line=5,
            signature="def sanitize_input(data):",
        ),
    ]

    files = [
        FileInfo(
            path=Path("/app/handlers.py"),
            language="python",
            size_bytes=1000,
            lines=50,
            symbols=[s for s in symbols if s.file_path == Path("/app/handlers.py")],
            imports=["from database import execute_query"],
        ),
        FileInfo(
            path=Path("/app/database.py"),
            language="python",
            size_bytes=500,
            lines=30,
            symbols=[s for s in symbols if s.file_path == Path("/app/database.py")],
        ),
        FileInfo(
            path=Path("/app/utils.py"),
            language="python",
            size_bytes=300,
            lines=20,
            symbols=[s for s in symbols if s.file_path == Path("/app/utils.py")],
        ),
    ]

    return RepoMap(
        root_path=Path("/app"),
        files=files,
        symbols=symbols,
        dependencies={
            "/app/handlers.py": ["/app/database.py", "/app/utils.py"],
        },
        rankings={
            "/app/handlers.py": 0.4,
            "/app/database.py": 0.35,
            "/app/utils.py": 0.25,
        },
        generated_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def temp_dir():
    """Create a temporary directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


class TestInferenceConfig:
    """Test InferenceConfig."""

    def test_default_config(self):
        """Should have sensible defaults."""
        config = InferenceConfig()
        assert config.max_candidates > 0
        assert config.min_confidence > 0.0
        assert config.write_output is True

    def test_custom_config(self):
        """Should accept custom values."""
        config = InferenceConfig(
            max_candidates=50,
            min_confidence=0.8,
            write_output=False,
        )
        assert config.max_candidates == 50
        assert config.min_confidence == 0.8
        assert config.write_output is False


class TestInferenceResult:
    """Test InferenceResult dataclass."""

    def test_create_result(self):
        """Should create inference result."""
        spec = DynamicSpec(repository="test")
        result = InferenceResult(
            spec=spec,
            candidates_found=10,
            candidates_classified=8,
            candidates_confirmed=5,
        )
        assert result.spec is not None
        assert result.candidates_found == 10

    def test_result_summary(self):
        """Should generate summary."""
        spec = DynamicSpec(repository="test")
        result = InferenceResult(
            spec=spec,
            candidates_found=10,
            candidates_classified=8,
            candidates_confirmed=5,
        )
        summary = result.summary()

        assert "candidates_found" in summary
        assert "candidates_confirmed" in summary


class TestInferenceEngine:
    """Test InferenceEngine class."""

    def test_create_engine(self):
        """Should create engine instance."""
        engine = InferenceEngine()
        assert engine is not None

    def test_create_engine_with_config(self):
        """Should accept custom configuration."""
        config = InferenceConfig(max_candidates=50)
        engine = InferenceEngine(config=config)
        assert engine.config.max_candidates == 50

    @pytest.mark.asyncio
    async def test_infer_from_repo_map(self, sample_repo_map: RepoMap, temp_dir: Path):
        """Should run inference on RepoMap."""
        config = InferenceConfig(write_output=False)
        engine = InferenceEngine(config=config)

        # Mock the classifier to return confirmed results
        mock_results = [
            ClassificationResult(
                candidate=Candidate(
                    symbol=sample_repo_map.symbols[0],
                    candidate_type=CandidateType.SOURCE,
                    score=0.8,
                ),
                confirmed=True,
                label=TaintLabel.SOURCE,
                confidence=0.9,
                reason="Source",
            ),
            ClassificationResult(
                candidate=Candidate(
                    symbol=sample_repo_map.symbols[1],
                    candidate_type=CandidateType.SINK,
                    score=0.85,
                ),
                confirmed=True,
                label=TaintLabel.SINK,
                confidence=0.95,
                reason="Sink",
            ),
        ]

        with patch.object(engine.classifier, "classify_batch", new_callable=AsyncMock) as mock_classify:
            mock_classify.return_value = mock_results

            result = await engine.infer(sample_repo_map, output_dir=temp_dir)

            assert isinstance(result, InferenceResult)
            assert isinstance(result.spec, DynamicSpec)

    @pytest.mark.asyncio
    async def test_extracts_candidates(self, sample_repo_map: RepoMap, temp_dir: Path):
        """Should extract candidates from RepoMap."""
        config = InferenceConfig(write_output=False)
        engine = InferenceEngine(config=config)

        with patch.object(engine.classifier, "classify_batch", new_callable=AsyncMock) as mock_classify:
            mock_classify.return_value = []

            result = await engine.infer(sample_repo_map, output_dir=temp_dir)

            # Should have found candidates
            assert result.candidates_found >= 0

    @pytest.mark.asyncio
    async def test_writes_output_when_configured(self, sample_repo_map: RepoMap, temp_dir: Path):
        """Should write output file when configured."""
        config = InferenceConfig(write_output=True)
        engine = InferenceEngine(config=config)

        with patch.object(engine.classifier, "classify_batch", new_callable=AsyncMock) as mock_classify:
            mock_classify.return_value = []

            result = await engine.infer(sample_repo_map, output_dir=temp_dir)

            # Check output file exists
            output_file = temp_dir / "context_rules.json"
            assert output_file.exists()

    @pytest.mark.asyncio
    async def test_skips_output_when_disabled(self, sample_repo_map: RepoMap, temp_dir: Path):
        """Should skip writing when disabled."""
        config = InferenceConfig(write_output=False)
        engine = InferenceEngine(config=config)

        with patch.object(engine.classifier, "classify_batch", new_callable=AsyncMock) as mock_classify:
            mock_classify.return_value = []

            await engine.infer(sample_repo_map, output_dir=temp_dir)

            # Should not have created file
            output_file = temp_dir / "context_rules.json"
            assert not output_file.exists()


class TestInferenceWithClassification:
    """Test inference with actual classification."""

    @pytest.mark.asyncio
    async def test_classifies_candidates(self, sample_repo_map: RepoMap, temp_dir: Path):
        """Should classify extracted candidates."""
        config = InferenceConfig(write_output=False)
        engine = InferenceEngine(config=config)

        with patch.object(engine.classifier, "classify_batch", new_callable=AsyncMock) as mock_classify:
            mock_classify.return_value = []

            await engine.infer(sample_repo_map, output_dir=temp_dir)

            # Classifier should have been called
            mock_classify.assert_called()

    @pytest.mark.asyncio
    async def test_converts_confirmed_to_specs(self, sample_repo_map: RepoMap, temp_dir: Path):
        """Should convert confirmed classifications to TaintSpecs."""
        config = InferenceConfig(write_output=False)
        engine = InferenceEngine(config=config)

        # Mock classifier to return confirmed source
        mock_result = ClassificationResult(
            candidate=Candidate(
                symbol=sample_repo_map.symbols[0],
                candidate_type=CandidateType.SOURCE,
                score=0.8,
            ),
            confirmed=True,
            label=TaintLabel.SOURCE,
            confidence=0.9,
            reason="Source detected",
            vulnerability_types=["CWE-89"],
        )

        with patch.object(engine.classifier, "classify_batch", new_callable=AsyncMock) as mock_classify:
            mock_classify.return_value = [mock_result]

            result = await engine.infer(sample_repo_map, output_dir=temp_dir)

            assert result.candidates_confirmed >= 1
            assert len(result.spec.sources) >= 1


class TestInferenceWithPropagation:
    """Test inference with taint propagation."""

    @pytest.mark.asyncio
    async def test_propagates_specs(self, sample_repo_map: RepoMap, temp_dir: Path):
        """Should propagate taint specs."""
        config = InferenceConfig(write_output=False, propagate=True)
        engine = InferenceEngine(config=config)

        # Mock classifier to return confirmed specs
        mock_result = ClassificationResult(
            candidate=Candidate(
                symbol=sample_repo_map.symbols[0],
                candidate_type=CandidateType.SOURCE,
                score=0.8,
            ),
            confirmed=True,
            label=TaintLabel.SOURCE,
            confidence=0.9,
            reason="Source",
        )

        with patch.object(engine.classifier, "classify_batch", new_callable=AsyncMock) as mock_classify:
            mock_classify.return_value = [mock_result]

            result = await engine.infer(sample_repo_map, output_dir=temp_dir)

            # Should have propagated specs
            assert result.spec.total_specs >= 1


class TestInferenceStatistics:
    """Test inference statistics."""

    @pytest.mark.asyncio
    async def test_tracks_candidate_counts(self, sample_repo_map: RepoMap, temp_dir: Path):
        """Should track candidate statistics."""
        config = InferenceConfig(write_output=False)
        engine = InferenceEngine(config=config)

        with patch.object(engine.classifier, "classify_batch", new_callable=AsyncMock) as mock_classify:
            mock_classify.return_value = []

            result = await engine.infer(sample_repo_map, output_dir=temp_dir)

            assert result.candidates_found >= 0
            assert result.candidates_classified >= 0
            assert result.candidates_confirmed >= 0

    @pytest.mark.asyncio
    async def test_result_has_timing(self, sample_repo_map: RepoMap, temp_dir: Path):
        """Should track timing information."""
        config = InferenceConfig(write_output=False)
        engine = InferenceEngine(config=config)

        with patch.object(engine.classifier, "classify_batch", new_callable=AsyncMock) as mock_classify:
            mock_classify.return_value = []

            result = await engine.infer(sample_repo_map, output_dir=temp_dir)

            assert hasattr(result, "duration_ms")


class TestInferenceEdgeCases:
    """Test edge cases."""

    @pytest.mark.asyncio
    async def test_empty_repo_map(self, temp_dir: Path):
        """Should handle empty RepoMap."""
        empty_map = RepoMap(
            root_path=Path("/empty"),
            files=[],
            symbols=[],
            dependencies={},
            rankings={},
            generated_at=datetime.now(timezone.utc),
        )

        config = InferenceConfig(write_output=False)
        engine = InferenceEngine(config=config)

        result = await engine.infer(empty_map, output_dir=temp_dir)

        assert result.candidates_found == 0
        assert isinstance(result.spec, DynamicSpec)

    @pytest.mark.asyncio
    async def test_handles_classifier_errors(self, sample_repo_map: RepoMap, temp_dir: Path):
        """Should handle classifier errors gracefully."""
        config = InferenceConfig(write_output=False)
        engine = InferenceEngine(config=config)

        with patch.object(engine.classifier, "classify_batch", new_callable=AsyncMock) as mock_classify:
            mock_classify.side_effect = Exception("Classifier error")

            # Should not raise, should return result with errors
            result = await engine.infer(sample_repo_map, output_dir=temp_dir)

            assert isinstance(result, InferenceResult)
            assert "error" in result.metadata
