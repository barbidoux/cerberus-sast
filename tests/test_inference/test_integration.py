"""
Integration tests for Phase II Spec Inference.

These tests validate the complete inference pipeline with real LLM calls.
Requires Ollama server running with deepseek-coder-v2 model.

Run with: pytest tests/test_inference/test_integration.py -v -s
"""

import asyncio
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cerberus.core.config import LLMConfig, OllamaConfig
from cerberus.inference.candidate_extractor import CandidateExtractor
from cerberus.inference.classifier import LLMClassifier, ClassifierConfig
from cerberus.inference.engine import InferenceEngine, InferenceConfig
from cerberus.inference.propagator import TaintPropagator
from cerberus.inference.spec_writer import SpecWriter
from cerberus.llm.gateway import LLMGateway
from cerberus.llm.providers.ollama import OllamaProvider
from cerberus.llm.prompts.classification import PromptBuilder
from cerberus.models.base import SymbolType, TaintLabel
from cerberus.models.repo_map import FileInfo, RepoMap, Symbol
from cerberus.models.spec import DynamicSpec

# Ollama server configuration
# Using WSL host IP for accessing Windows Ollama server
OLLAMA_HOST = "172.31.208.1"
OLLAMA_PORT = 11434
OLLAMA_BASE_URL = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}"

# Model to use for tests - deepseek-coder-v2 is good for code analysis
TEST_MODEL = "deepseek-coder-v2:16b-lite-instruct-q4_K_M"


@pytest.fixture
def ollama_config() -> OllamaConfig:
    """Create Ollama configuration for tests."""
    return OllamaConfig(
        base_url=OLLAMA_BASE_URL,
        model=TEST_MODEL,
        timeout=120,
        context_length=4096,
    )


@pytest.fixture
def ollama_provider(ollama_config: OllamaConfig) -> OllamaProvider:
    """Create Ollama provider."""
    return OllamaProvider(ollama_config)


@pytest.fixture
def sample_vulnerable_code() -> dict[str, str]:
    """Sample vulnerable code for testing classification."""
    return {
        "source_function": '''def get_user_input(request):
    """Get user input from HTTP request."""
    user_id = request.args.get('id')
    username = request.form.get('username')
    return user_id, username''',

        "sink_function": '''def execute_query(cursor, query):
    """Execute SQL query on database."""
    cursor.execute(query)
    return cursor.fetchall()''',

        "sanitizer_function": '''def sanitize_html(content):
    """Sanitize HTML content to prevent XSS."""
    import html
    return html.escape(content)''',

        "safe_function": '''def calculate_sum(a, b):
    """Calculate sum of two numbers."""
    return a + b''',

        "command_sink": '''def run_command(cmd):
    """Execute system command."""
    import subprocess
    subprocess.run(cmd, shell=True)''',
    }


@pytest.fixture
def sample_repo_map() -> RepoMap:
    """Create a realistic RepoMap for integration testing."""
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
            signature="def execute_query(cursor, query):",
        ),
        Symbol(
            name="sanitize_html",
            type=SymbolType.FUNCTION,
            file_path=Path("/app/security.py"),
            line=5,
            signature="def sanitize_html(content):",
        ),
        Symbol(
            name="run_command",
            type=SymbolType.FUNCTION,
            file_path=Path("/app/utils.py"),
            line=15,
            signature="def run_command(cmd):",
        ),
        Symbol(
            name="process_request",
            type=SymbolType.FUNCTION,
            file_path=Path("/app/handlers.py"),
            line=30,
            signature="def process_request(request):",
        ),
    ]

    files = [
        FileInfo(
            path=Path("/app/handlers.py"),
            language="python",
            size_bytes=1000,
            lines=50,
            symbols=[s for s in symbols if s.file_path == Path("/app/handlers.py")],
            imports=["from flask import request", "from database import execute_query"],
        ),
        FileInfo(
            path=Path("/app/database.py"),
            language="python",
            size_bytes=500,
            lines=30,
            symbols=[s for s in symbols if s.file_path == Path("/app/database.py")],
            imports=["import sqlite3"],
        ),
        FileInfo(
            path=Path("/app/security.py"),
            language="python",
            size_bytes=300,
            lines=20,
            symbols=[s for s in symbols if s.file_path == Path("/app/security.py")],
            imports=["import html"],
        ),
        FileInfo(
            path=Path("/app/utils.py"),
            language="python",
            size_bytes=400,
            lines=25,
            symbols=[s for s in symbols if s.file_path == Path("/app/utils.py")],
            imports=["import subprocess", "import os"],
        ),
    ]

    return RepoMap(
        root_path=Path("/app"),
        files=files,
        symbols=symbols,
        dependencies={
            "/app/handlers.py": ["/app/database.py", "/app/security.py"],
            "/app/utils.py": [],
        },
        rankings={
            "/app/handlers.py": 0.4,
            "/app/database.py": 0.3,
            "/app/security.py": 0.2,
            "/app/utils.py": 0.1,
        },
        generated_at=datetime.now(timezone.utc),
    )


class TestOllamaConnectivity:
    """Test Ollama server connectivity."""

    @pytest.mark.asyncio
    async def test_ollama_is_available(self, ollama_provider: OllamaProvider):
        """Verify Ollama server is running and model is available."""
        is_available = await ollama_provider.is_available()
        assert is_available, f"Ollama server not available at {OLLAMA_BASE_URL} with model {TEST_MODEL}"

    @pytest.mark.asyncio
    async def test_ollama_basic_completion(self, ollama_provider: OllamaProvider):
        """Test basic completion works."""
        from cerberus.llm.providers.models import LLMRequest, Message, Role

        request = LLMRequest(
            messages=[Message(role=Role.USER, content="Say 'hello' and nothing else.")],
            temperature=0.0,
            max_tokens=10,
        )

        response = await ollama_provider.complete(request)
        assert response.content is not None
        assert len(response.content) > 0
        print(f"\nOllama response: {response.content}")


class TestClassificationPrompts:
    """Test classification prompts with real LLM."""

    @pytest.mark.asyncio
    async def test_classify_source_function(
        self,
        ollama_provider: OllamaProvider,
        sample_vulnerable_code: dict[str, str],
    ):
        """Test classification of a source function."""
        from cerberus.llm.providers.models import LLMRequest, Message, Role

        builder = PromptBuilder()
        prompt = builder.build_classification_prompt(
            code=sample_vulnerable_code["source_function"],
            language="python",
            target_label=TaintLabel.SOURCE,
        )

        # Convert to LLM request
        messages_data = prompt.to_messages()
        messages = [Message(role=Role(m["role"]), content=m["content"]) for m in messages_data]

        request = LLMRequest(
            messages=messages,
            temperature=0.0,
            max_tokens=500,
        )

        response = await ollama_provider.complete(request)
        print(f"\n[SOURCE] Classification response:\n{response.content}")

        # Check if response contains expected classification
        assert "SOURCE" in response.content.upper() or "source" in response.content.lower()

    @pytest.mark.asyncio
    async def test_classify_sink_function(
        self,
        ollama_provider: OllamaProvider,
        sample_vulnerable_code: dict[str, str],
    ):
        """Test classification of a sink function."""
        from cerberus.llm.providers.models import LLMRequest, Message, Role

        builder = PromptBuilder()
        prompt = builder.build_classification_prompt(
            code=sample_vulnerable_code["sink_function"],
            language="python",
            target_label=TaintLabel.SINK,
        )

        messages_data = prompt.to_messages()
        messages = [Message(role=Role(m["role"]), content=m["content"]) for m in messages_data]

        request = LLMRequest(
            messages=messages,
            temperature=0.0,
            max_tokens=500,
        )

        response = await ollama_provider.complete(request)
        print(f"\n[SINK] Classification response:\n{response.content}")

        # Check for sink classification or SQL injection mention
        content_upper = response.content.upper()
        assert "SINK" in content_upper or "SQL" in content_upper or "CWE-89" in response.content

    @pytest.mark.asyncio
    async def test_classify_sanitizer_function(
        self,
        ollama_provider: OllamaProvider,
        sample_vulnerable_code: dict[str, str],
    ):
        """Test classification of a sanitizer function."""
        from cerberus.llm.providers.models import LLMRequest, Message, Role

        builder = PromptBuilder()
        prompt = builder.build_classification_prompt(
            code=sample_vulnerable_code["sanitizer_function"],
            language="python",
            target_label=TaintLabel.SANITIZER,
        )

        messages_data = prompt.to_messages()
        messages = [Message(role=Role(m["role"]), content=m["content"]) for m in messages_data]

        request = LLMRequest(
            messages=messages,
            temperature=0.0,
            max_tokens=500,
        )

        response = await ollama_provider.complete(request)
        print(f"\n[SANITIZER] Classification response:\n{response.content}")

        # Check for sanitizer/escape classification
        content_upper = response.content.upper()
        assert "SANITIZER" in content_upper or "ESCAPE" in content_upper or "XSS" in content_upper

    @pytest.mark.asyncio
    async def test_multi_label_classification(
        self,
        ollama_provider: OllamaProvider,
        sample_vulnerable_code: dict[str, str],
    ):
        """Test multi-label classification mode."""
        from cerberus.llm.providers.models import LLMRequest, Message, Role

        builder = PromptBuilder()
        prompt = builder.build_multi_label_prompt(
            code=sample_vulnerable_code["command_sink"],
            language="python",
        )

        messages_data = prompt.to_messages()
        messages = [Message(role=Role(m["role"]), content=m["content"]) for m in messages_data]

        request = LLMRequest(
            messages=messages,
            temperature=0.0,
            max_tokens=500,
        )

        response = await ollama_provider.complete(request)
        print(f"\n[MULTI-LABEL] Classification response:\n{response.content}")

        # Should identify as sink due to command execution
        content_upper = response.content.upper()
        assert "SINK" in content_upper or "COMMAND" in content_upper or "CWE-78" in response.content


class TestCandidateExtraction:
    """Test candidate extraction on sample repo."""

    def test_extracts_candidates(self, sample_repo_map: RepoMap):
        """Should extract candidates from repo map."""
        extractor = CandidateExtractor()
        candidates = extractor.extract(sample_repo_map)

        print(f"\nExtracted {len(candidates)} candidates:")
        for c in candidates:
            print(f"  - {c.symbol.name}: {c.candidate_type.value} (score: {c.score:.2f})")

        assert len(candidates) > 0
        # Should find our known patterns
        names = [c.symbol.name for c in candidates]
        assert "get_user_input" in names or "execute_query" in names


class TestLLMClassifier:
    """Test LLM classifier with real LLM calls."""

    @pytest.fixture
    def llm_gateway(self, ollama_config: OllamaConfig) -> LLMGateway:
        """Create LLM gateway with Ollama."""
        from cerberus.core.config import LLMConfig, AnthropicConfig, OpenAIConfig

        llm_config = LLMConfig(
            ollama=ollama_config,
            anthropic=AnthropicConfig(api_key="not-used"),
            openai=OpenAIConfig(api_key="not-used"),
            cache_enabled=False,
        )
        return LLMGateway(llm_config)

    @pytest.mark.asyncio
    async def test_classifier_with_gateway(
        self,
        llm_gateway: LLMGateway,
        sample_repo_map: RepoMap,
    ):
        """Test classifier with real LLM gateway."""
        config = ClassifierConfig(min_confidence=0.5)
        classifier = LLMClassifier(config=config, gateway=llm_gateway)

        # Extract candidates first
        extractor = CandidateExtractor()
        candidates = extractor.extract(sample_repo_map)

        if candidates:
            # Classify first candidate
            candidate = candidates[0]
            result = await classifier.classify(
                candidate,
                code_snippet=candidate.symbol.signature,
            )

            print(f"\nClassified {candidate.symbol.name}:")
            print(f"  Label: {result.label.value}")
            print(f"  Confidence: {result.confidence}")
            print(f"  Confirmed: {result.confirmed}")
            print(f"  Reason: {result.reason[:100]}...")

            assert result is not None
            assert result.label in TaintLabel


class TestTaintPropagation:
    """Test taint propagation."""

    def test_propagates_specs(self, sample_repo_map: RepoMap):
        """Test propagation across call graph."""
        from cerberus.models.spec import TaintSpec

        # Create initial specs
        initial_specs = [
            TaintSpec(
                method="get_user_input",
                file_path=Path("/app/handlers.py"),
                line=10,
                label=TaintLabel.SOURCE,
                confidence=0.9,
            ),
            TaintSpec(
                method="execute_query",
                file_path=Path("/app/database.py"),
                line=25,
                label=TaintLabel.SINK,
                confidence=0.9,
            ),
        ]

        propagator = TaintPropagator()
        result = propagator.propagate(initial_specs, sample_repo_map)

        print(f"\nPropagation result:")
        print(f"  Iterations: {result.iterations}")
        print(f"  Converged: {result.converged}")
        print(f"  Total specs: {len(result.propagated_specs)}")

        for spec in result.propagated_specs:
            print(f"  - {spec.method}: {spec.label.value}")

        assert len(result.propagated_specs) >= 2


class TestSpecWriter:
    """Test spec writer functionality."""

    def test_writes_and_loads_spec(self):
        """Test writing and loading spec file."""
        spec = DynamicSpec(repository="test-repo")
        from cerberus.models.spec import TaintSpec

        spec.add_source(TaintSpec(
            method="get_input",
            file_path=Path("/test.py"),
            line=1,
            label=TaintLabel.SOURCE,
            confidence=0.9,
        ))

        with tempfile.TemporaryDirectory() as tmpdir:
            writer = SpecWriter()
            output_path = writer.write(spec, Path(tmpdir))

            print(f"\nWrote spec to: {output_path}")
            print(f"Contents:\n{output_path.read_text()[:500]}")

            # Load and verify
            loaded = writer.load(output_path)
            assert len(loaded.sources) == 1
            assert loaded.sources[0].method == "get_input"


class TestEndToEndInference:
    """End-to-end integration tests."""

    @pytest.fixture
    def llm_gateway(self, ollama_config: OllamaConfig) -> LLMGateway:
        """Create LLM gateway with Ollama."""
        from cerberus.core.config import LLMConfig, AnthropicConfig, OpenAIConfig

        llm_config = LLMConfig(
            ollama=ollama_config,
            anthropic=AnthropicConfig(api_key="not-used"),
            openai=OpenAIConfig(api_key="not-used"),
            cache_enabled=False,
        )
        return LLMGateway(llm_config)

    @pytest.mark.asyncio
    async def test_full_inference_pipeline(
        self,
        sample_repo_map: RepoMap,
        llm_gateway: LLMGateway,
    ):
        """Test complete inference pipeline."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = InferenceConfig(
                max_candidates=5,  # Limit for faster testing
                min_confidence=0.5,
                write_output=True,
                propagate=True,
            )

            engine = InferenceEngine(config=config, llm_gateway=llm_gateway)
            result = await engine.infer(
                sample_repo_map,
                output_dir=Path(tmpdir),
                repository_name="test-integration-repo",
            )

            print(f"\n=== INFERENCE RESULT ===")
            print(f"Candidates found: {result.candidates_found}")
            print(f"Candidates classified: {result.candidates_classified}")
            print(f"Candidates confirmed: {result.candidates_confirmed}")
            print(f"Duration: {result.duration_ms:.2f}ms")
            print(f"\nSpec summary:")
            print(f"  Sources: {len(result.spec.sources)}")
            print(f"  Sinks: {len(result.spec.sinks)}")
            print(f"  Sanitizers: {len(result.spec.sanitizers)}")
            print(f"  Propagators: {len(result.spec.propagators)}")

            # Check output file
            output_file = Path(tmpdir) / "context_rules.json"
            if output_file.exists():
                print(f"\nOutput file ({output_file}):")
                content = output_file.read_text()
                print(content[:1000])

            assert result is not None
            assert result.spec is not None


# Mark all tests in this module as integration tests
pytestmark = pytest.mark.integration
