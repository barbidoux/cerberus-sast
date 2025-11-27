"""
Tests for CPGQL Query Generator.

TDD: Write tests first, then implement to make them pass.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cerberus.detection.query_generator import (
    CPGQLQuery,
    QueryGenerator,
    QueryGeneratorConfig,
    QueryTemplate,
)
from cerberus.models.base import TaintLabel
from cerberus.models.spec import DynamicSpec, TaintSpec


@pytest.fixture
def sample_spec() -> DynamicSpec:
    """Create a sample DynamicSpec for testing."""
    spec = DynamicSpec(repository="test-repo")
    spec.add_source(TaintSpec(
        method="get_user_input",
        file_path=Path("/app/handlers.py"),
        line=10,
        label=TaintLabel.SOURCE,
        confidence=0.95,
        vulnerability_types=["CWE-89", "CWE-79"],
    ))
    spec.add_source(TaintSpec(
        method="read_request",
        file_path=Path("/app/api.py"),
        line=20,
        label=TaintLabel.SOURCE,
        confidence=0.9,
        vulnerability_types=["CWE-89"],
    ))
    spec.add_sink(TaintSpec(
        method="execute_query",
        file_path=Path("/app/database.py"),
        line=25,
        label=TaintLabel.SINK,
        confidence=0.95,
        vulnerability_types=["CWE-89"],
    ))
    spec.add_sink(TaintSpec(
        method="render_html",
        file_path=Path("/app/views.py"),
        line=30,
        label=TaintLabel.SINK,
        confidence=0.85,
        vulnerability_types=["CWE-79"],
    ))
    spec.add_sanitizer(TaintSpec(
        method="escape_sql",
        file_path=Path("/app/utils.py"),
        line=5,
        label=TaintLabel.SANITIZER,
        confidence=0.9,
        vulnerability_types=["CWE-89"],
    ))
    return spec


class TestQueryGeneratorConfig:
    """Test QueryGeneratorConfig."""

    def test_default_config(self):
        """Should have sensible defaults."""
        config = QueryGeneratorConfig()
        assert config.use_llm is True
        assert config.max_queries_per_pair > 0
        assert config.validate_queries is True

    def test_custom_config(self):
        """Should accept custom values."""
        config = QueryGeneratorConfig(
            use_llm=False,
            max_queries_per_pair=5,
            validate_queries=False,
        )
        assert config.use_llm is False
        assert config.max_queries_per_pair == 5


class TestCPGQLQuery:
    """Test CPGQLQuery dataclass."""

    def test_create_query(self):
        """Should create query with required fields."""
        query = CPGQLQuery(
            query="cpg.method.name.l",
            source="get_input",
            sink="execute",
            vulnerability_type="CWE-89",
        )
        assert query.query == "cpg.method.name.l"
        assert query.source == "get_input"
        assert query.sink == "execute"

    def test_query_with_sanitizers(self):
        """Should include sanitizer list."""
        query = CPGQLQuery(
            query="...",
            source="src",
            sink="sink",
            sanitizers=["escape", "validate"],
        )
        assert len(query.sanitizers) == 2

    def test_query_to_dict(self):
        """Should serialize to dictionary."""
        query = CPGQLQuery(
            query="cpg.method.l",
            source="src",
            sink="sink",
            vulnerability_type="CWE-89",
        )
        data = query.to_dict()
        assert "query" in data
        assert "source" in data
        assert "sink" in data


class TestQueryTemplate:
    """Test QueryTemplate for different vulnerability types."""

    def test_sql_injection_template(self):
        """Should have SQL injection query template."""
        template = QueryTemplate.get("CWE-89")
        assert template is not None
        assert "source" in template.lower() or "sink" in template.lower()

    def test_xss_template(self):
        """Should have XSS query template."""
        template = QueryTemplate.get("CWE-79")
        assert template is not None

    def test_command_injection_template(self):
        """Should have command injection template."""
        template = QueryTemplate.get("CWE-78")
        assert template is not None

    def test_unknown_type_returns_generic(self):
        """Should return generic template for unknown types."""
        template = QueryTemplate.get("CWE-999")
        assert template is not None
        assert "reachableBy" in template

    def test_template_has_placeholders(self):
        """Should have source/sink placeholders."""
        template = QueryTemplate.get("CWE-89")
        assert "{source}" in template or "source" in template.lower()
        assert "{sink}" in template or "sink" in template.lower()


class TestQueryGenerator:
    """Test QueryGenerator class."""

    def test_create_generator(self):
        """Should create generator instance."""
        generator = QueryGenerator()
        assert generator is not None

    def test_create_with_config(self):
        """Should accept custom configuration."""
        config = QueryGeneratorConfig(use_llm=False)
        generator = QueryGenerator(config=config)
        assert generator.config.use_llm is False


class TestQueryGeneratorTemplates:
    """Test template-based query generation."""

    def test_generate_from_template(self, sample_spec: DynamicSpec):
        """Should generate queries from templates."""
        config = QueryGeneratorConfig(use_llm=False)
        generator = QueryGenerator(config=config)

        queries = generator.generate_queries(sample_spec)

        assert len(queries) > 0
        # Should have queries for source-sink pairs with matching vuln types
        sql_queries = [q for q in queries if q.vulnerability_type == "CWE-89"]
        assert len(sql_queries) > 0

    def test_generates_for_all_pairs(self, sample_spec: DynamicSpec):
        """Should generate queries for all relevant source-sink pairs."""
        config = QueryGeneratorConfig(use_llm=False)
        generator = QueryGenerator(config=config)

        queries = generator.generate_queries(sample_spec)

        # get_user_input (CWE-89, CWE-79) -> execute_query (CWE-89)
        # get_user_input (CWE-89, CWE-79) -> render_html (CWE-79)
        # read_request (CWE-89) -> execute_query (CWE-89)
        assert len(queries) >= 3

    def test_includes_sanitizers(self, sample_spec: DynamicSpec):
        """Should include sanitizers in generated queries."""
        config = QueryGeneratorConfig(use_llm=False)
        generator = QueryGenerator(config=config)

        queries = generator.generate_queries(sample_spec)

        # SQL injection queries should reference escape_sql
        sql_queries = [q for q in queries if q.vulnerability_type == "CWE-89"]
        has_sanitizer_ref = any("escape_sql" in q.query for q in sql_queries)
        # OR sanitizers list populated
        has_sanitizer_list = any(q.sanitizers for q in sql_queries)
        assert has_sanitizer_ref or has_sanitizer_list

    def test_respects_max_queries(self, sample_spec: DynamicSpec):
        """Should respect max queries per pair limit."""
        config = QueryGeneratorConfig(use_llm=False, max_queries_per_pair=1)
        generator = QueryGenerator(config=config)

        queries = generator.generate_queries(sample_spec)

        # Count queries per source-sink pair
        pair_counts: dict[tuple, int] = {}
        for q in queries:
            pair = (q.source, q.sink)
            pair_counts[pair] = pair_counts.get(pair, 0) + 1

        for count in pair_counts.values():
            assert count <= 1


class TestQueryGeneratorLLM:
    """Test LLM-based query generation."""

    @pytest.mark.asyncio
    async def test_generate_with_llm(self, sample_spec: DynamicSpec):
        """Should use LLM to generate queries."""
        config = QueryGeneratorConfig(use_llm=True)
        generator = QueryGenerator(config=config)

        # Mock LLM gateway
        mock_gateway = AsyncMock()
        mock_gateway.complete.return_value = MagicMock(
            content='''
            def source = cpg.method.name("get_user_input").parameter
            def sink = cpg.method.name("execute_query").parameter
            sink.reachableBy(source).toJson
            '''
        )

        with patch.object(generator, '_llm_gateway', mock_gateway):
            queries = await generator.generate_queries_async(sample_spec)

        assert len(queries) > 0

    @pytest.mark.asyncio
    async def test_llm_fallback_to_template(self, sample_spec: DynamicSpec):
        """Should fallback to template on LLM failure."""
        config = QueryGeneratorConfig(use_llm=True)
        generator = QueryGenerator(config=config)

        # Mock LLM gateway to fail
        mock_gateway = AsyncMock()
        mock_gateway.complete.side_effect = Exception("LLM unavailable")

        with patch.object(generator, '_llm_gateway', mock_gateway):
            queries = await generator.generate_queries_async(sample_spec)

        # Should still get template-based queries
        assert len(queries) > 0


class TestQueryValidation:
    """Test query validation."""

    def test_validates_query_syntax(self):
        """Should validate CPGQL syntax."""
        generator = QueryGenerator()

        valid_query = 'cpg.method.name("test").l'
        assert generator.validate_query(valid_query) is True

        invalid_query = 'cpg method name'  # Missing dots
        assert generator.validate_query(invalid_query) is False

    def test_validates_required_components(self):
        """Should check for source/sink references."""
        generator = QueryGenerator()

        # Should have reachability check - with proper def statements
        good_query = '''
        def source = cpg.method.name("input").parameter
        def sink = cpg.method.name("exec").parameter
        sink.reachableBy(source).toJson
        '''
        assert generator.validate_query(good_query) is True

        # Just listing methods is valid CPGQL
        simple_query = 'cpg.method.l'
        assert generator.validate_query(simple_query) is True

    def test_rejects_dangerous_queries(self):
        """Should reject potentially dangerous queries."""
        generator = QueryGenerator()

        # Queries that might modify the CPG
        dangerous = 'cpg.close()'
        assert generator.validate_query(dangerous) is False


class TestSourceSinkPairing:
    """Test source-sink pair generation."""

    def test_pairs_by_vulnerability_type(self, sample_spec: DynamicSpec):
        """Should pair sources and sinks by vulnerability type."""
        generator = QueryGenerator()

        pairs = generator.get_source_sink_pairs(sample_spec)

        # get_user_input has CWE-89 and CWE-79
        # execute_query has CWE-89
        # render_html has CWE-79
        # So we should have pairs for CWE-89 and CWE-79

        assert len(pairs) > 0

        for source, sink, vuln_type in pairs:
            # Verify vuln type is in both source and sink
            assert vuln_type in source.vulnerability_types
            assert vuln_type in sink.vulnerability_types

    def test_includes_sanitizers_for_pair(self, sample_spec: DynamicSpec):
        """Should include relevant sanitizers for each pair."""
        generator = QueryGenerator()

        pairs = generator.get_source_sink_pairs(sample_spec, include_sanitizers=True)

        for source, sink, vuln_type, sanitizers in pairs:
            if vuln_type == "CWE-89":
                # escape_sql should be included for SQL injection
                sanitizer_methods = [s.method for s in sanitizers]
                assert "escape_sql" in sanitizer_methods


class TestQueryOutput:
    """Test query output formats."""

    def test_generate_returns_cpgql_queries(self, sample_spec: DynamicSpec):
        """Should return CPGQLQuery objects."""
        config = QueryGeneratorConfig(use_llm=False)
        generator = QueryGenerator(config=config)

        queries = generator.generate_queries(sample_spec)

        for q in queries:
            assert isinstance(q, CPGQLQuery)
            assert q.query  # Non-empty query string
            assert q.source  # Source method
            assert q.sink  # Sink method

    def test_query_metadata(self, sample_spec: DynamicSpec):
        """Should include metadata in queries."""
        config = QueryGeneratorConfig(use_llm=False)
        generator = QueryGenerator(config=config)

        queries = generator.generate_queries(sample_spec)

        for q in queries:
            assert q.vulnerability_type  # Should have CWE
            # Metadata is optional but should be a dict
            assert isinstance(q.metadata, dict)
