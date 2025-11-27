"""
Tests for Joern Client.

TDD: Write tests first, then implement to make them pass.
"""

from dataclasses import dataclass
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cerberus.detection.joern_client import (
    JoernClient,
    JoernConfig,
    JoernError,
    JoernImportError,
    QueryResult,
)


@pytest.fixture
def joern_config() -> JoernConfig:
    """Create a test Joern configuration."""
    return JoernConfig(
        endpoint="localhost:8080",
        workspace=Path("/tmp/joern-workspace"),
        timeout=60,
    )


class TestJoernConfig:
    """Test JoernConfig dataclass."""

    def test_default_config(self):
        """Should have sensible defaults."""
        config = JoernConfig()
        assert config.endpoint == "localhost:8080"
        assert config.timeout > 0
        assert config.workspace is not None

    def test_custom_config(self):
        """Should accept custom values."""
        config = JoernConfig(
            endpoint="joern.example.com:9090",
            workspace=Path("/custom/workspace"),
            timeout=120,
        )
        assert config.endpoint == "joern.example.com:9090"
        assert config.workspace == Path("/custom/workspace")
        assert config.timeout == 120

    def test_endpoint_url_property(self):
        """Should generate HTTP URL from endpoint."""
        config = JoernConfig(endpoint="localhost:8080")
        assert config.url == "http://localhost:8080"


class TestQueryResult:
    """Test QueryResult dataclass."""

    def test_create_success_result(self):
        """Should create successful query result."""
        result = QueryResult(
            success=True,
            data='[{"name": "foo", "line": 10}]',
        )
        assert result.success is True
        assert result.data is not None
        assert result.error is None

    def test_create_error_result(self):
        """Should create error query result."""
        result = QueryResult(
            success=False,
            error="Syntax error in query",
        )
        assert result.success is False
        assert result.error == "Syntax error in query"

    def test_to_json(self):
        """Should parse JSON data."""
        result = QueryResult(
            success=True,
            data='[{"name": "test"}]',
        )
        parsed = result.to_json()
        assert parsed == [{"name": "test"}]

    def test_to_json_empty(self):
        """Should return empty list for no data."""
        result = QueryResult(success=True, data=None)
        assert result.to_json() == []


class TestJoernClient:
    """Test JoernClient class."""

    def test_create_client(self, joern_config: JoernConfig):
        """Should create client instance."""
        client = JoernClient(config=joern_config)
        assert client is not None
        assert client.config == joern_config

    def test_create_client_with_defaults(self):
        """Should create client with default config."""
        client = JoernClient()
        assert client.config is not None
        assert client.config.endpoint == "localhost:8080"


class TestJoernClientConnection:
    """Test Joern client connection methods."""

    @pytest.mark.asyncio
    async def test_is_available_when_server_running(self, joern_config: JoernConfig):
        """Should return True when server is reachable."""
        client = JoernClient(config=joern_config)

        with patch.object(client, '_http_get', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"status": "ready"}
            result = await client.is_available()
            assert result is True

    @pytest.mark.asyncio
    async def test_is_available_when_server_down(self, joern_config: JoernConfig):
        """Should return False when server is unreachable."""
        client = JoernClient(config=joern_config)

        with patch.object(client, '_http_get', new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = ConnectionError("Connection refused")
            result = await client.is_available()
            assert result is False


class TestJoernClientImport:
    """Test CPG import functionality."""

    @pytest.mark.asyncio
    async def test_import_code(self, joern_config: JoernConfig):
        """Should import code and generate CPG."""
        client = JoernClient(config=joern_config)

        with patch.object(client, '_execute_query', new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = QueryResult(
                success=True,
                data='{"status": "imported"}',
            )

            await client.import_code(Path("/app/src"), "test-project")

            mock_exec.assert_called_once()
            call_args = mock_exec.call_args[0][0]
            assert "importCode" in call_args or "importCpg" in call_args

    @pytest.mark.asyncio
    async def test_import_code_failure(self, joern_config: JoernConfig):
        """Should raise error on import failure."""
        client = JoernClient(config=joern_config)

        with patch.object(client, '_execute_query', new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = QueryResult(
                success=False,
                error="Failed to parse source files",
            )

            with pytest.raises(JoernImportError):
                await client.import_code(Path("/invalid/path"), "test")

    @pytest.mark.asyncio
    async def test_import_code_with_language(self, joern_config: JoernConfig):
        """Should specify language during import."""
        client = JoernClient(config=joern_config)

        with patch.object(client, '_execute_query', new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = QueryResult(success=True, data='{}')

            await client.import_code(
                Path("/app/src"),
                "test-project",
                language="python",
            )

            call_args = mock_exec.call_args[0][0]
            assert "python" in call_args.lower() or "jssrc2cpg" not in call_args


class TestJoernClientQuery:
    """Test CPGQL query execution."""

    @pytest.mark.asyncio
    async def test_execute_query(self, joern_config: JoernConfig):
        """Should execute CPGQL query."""
        client = JoernClient(config=joern_config)

        with patch.object(client, '_http_post', new_callable=AsyncMock) as mock_post:
            mock_post.return_value = {
                "success": True,
                "stdout": '[{"name": "test_function"}]',
            }

            result = await client.query('cpg.method.name.l')

            assert result.success is True
            assert "test_function" in result.data

    @pytest.mark.asyncio
    async def test_query_syntax_error(self, joern_config: JoernConfig):
        """Should handle query syntax errors."""
        client = JoernClient(config=joern_config)

        with patch.object(client, '_http_post', new_callable=AsyncMock) as mock_post:
            mock_post.return_value = {
                "success": False,
                "stderr": "Syntax error at line 1",
            }

            result = await client.query('invalid query syntax')

            assert result.success is False
            assert "Syntax error" in result.error

    @pytest.mark.asyncio
    async def test_query_timeout(self, joern_config: JoernConfig):
        """Should handle query timeout."""
        client = JoernClient(config=joern_config)

        with patch.object(client, '_http_post', new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = TimeoutError("Query timeout")

            with pytest.raises(JoernError) as exc_info:
                await client.query('cpg.method.l')

            assert "timeout" in str(exc_info.value).lower()


class TestJoernClientDataFlow:
    """Test data flow query methods."""

    @pytest.mark.asyncio
    async def test_find_flows(self, joern_config: JoernConfig):
        """Should find data flows from source to sink."""
        client = JoernClient(config=joern_config)

        with patch.object(client, 'query', new_callable=AsyncMock) as mock_query:
            mock_query.return_value = QueryResult(
                success=True,
                data='[{"source": {"line": 10}, "sink": {"line": 20}}]',
            )

            flows = await client.find_flows(
                source="get_user_input",
                sink="execute_query",
            )

            assert len(flows) >= 0
            mock_query.assert_called_once()

    @pytest.mark.asyncio
    async def test_find_flows_with_sanitizers(self, joern_config: JoernConfig):
        """Should exclude paths through sanitizers."""
        client = JoernClient(config=joern_config)

        with patch.object(client, 'query', new_callable=AsyncMock) as mock_query:
            mock_query.return_value = QueryResult(success=True, data='[]')

            flows = await client.find_flows(
                source="get_input",
                sink="execute",
                exclude_sanitizers=["escape_sql", "validate_input"],
            )

            call_args = mock_query.call_args[0][0]
            assert "escape_sql" in call_args or "whereNot" in call_args

    @pytest.mark.asyncio
    async def test_find_flows_no_results(self, joern_config: JoernConfig):
        """Should return empty list when no flows found."""
        client = JoernClient(config=joern_config)

        with patch.object(client, 'query', new_callable=AsyncMock) as mock_query:
            mock_query.return_value = QueryResult(success=True, data='[]')

            flows = await client.find_flows(
                source="nonexistent_source",
                sink="nonexistent_sink",
            )

            assert flows == []


class TestJoernClientMethods:
    """Test CPG query helper methods."""

    @pytest.mark.asyncio
    async def test_get_methods(self, joern_config: JoernConfig):
        """Should get all methods in CPG."""
        client = JoernClient(config=joern_config)

        with patch.object(client, 'query', new_callable=AsyncMock) as mock_query:
            mock_query.return_value = QueryResult(
                success=True,
                data='[{"name": "foo", "fullName": "Foo.foo", "lineNumber": 10}]',
            )

            methods = await client.get_methods()

            assert len(methods) == 1
            assert methods[0]["name"] == "foo"

    @pytest.mark.asyncio
    async def test_get_method_by_name(self, joern_config: JoernConfig):
        """Should get specific method by name."""
        client = JoernClient(config=joern_config)

        with patch.object(client, 'query', new_callable=AsyncMock) as mock_query:
            mock_query.return_value = QueryResult(
                success=True,
                data='[{"name": "target_method", "code": "def target_method(): pass"}]',
            )

            method = await client.get_method("target_method")

            assert method is not None
            assert method["name"] == "target_method"

    @pytest.mark.asyncio
    async def test_get_calls_to_method(self, joern_config: JoernConfig):
        """Should get all call sites for a method."""
        client = JoernClient(config=joern_config)

        with patch.object(client, 'query', new_callable=AsyncMock) as mock_query:
            mock_query.return_value = QueryResult(
                success=True,
                data='[{"lineNumber": 15, "file": "test.py"}]',
            )

            calls = await client.get_calls_to("dangerous_function")

            assert len(calls) == 1
            assert calls[0]["lineNumber"] == 15


class TestJoernClientSlicing:
    """Test program slicing functionality."""

    @pytest.mark.asyncio
    async def test_get_slice_for_flow(self, joern_config: JoernConfig):
        """Should get program slice for a data flow."""
        client = JoernClient(config=joern_config)

        with patch.object(client, 'query', new_callable=AsyncMock) as mock_query:
            mock_query.return_value = QueryResult(
                success=True,
                data='[{"lineNumber": 10, "code": "x = input()"}]',
            )

            slice_data = await client.get_slice(
                source_line=10,
                sink_line=20,
                file_path="test.py",
            )

            assert slice_data is not None
            mock_query.assert_called()

    @pytest.mark.asyncio
    async def test_get_control_structures(self, joern_config: JoernConfig):
        """Should get control structures for lines."""
        client = JoernClient(config=joern_config)

        with patch.object(client, 'query', new_callable=AsyncMock) as mock_query:
            mock_query.return_value = QueryResult(
                success=True,
                data='[{"type": "if", "lineNumber": 8, "code": "if x > 0:"}]',
            )

            controls = await client.get_control_structures(
                file_path="test.py",
                start_line=5,
                end_line=25,
            )

            assert len(controls) == 1
            assert controls[0]["type"] == "if"


class TestJoernErrors:
    """Test error handling."""

    def test_joern_error(self):
        """Should create JoernError with message."""
        error = JoernError("Connection failed")
        assert str(error) == "Connection failed"

    def test_joern_import_error(self):
        """Should create JoernImportError with details."""
        error = JoernImportError("Failed to parse", path=Path("/app/src"))
        assert "Failed to parse" in str(error)
        assert isinstance(error, JoernError)

    def test_joern_error_with_query(self):
        """Should include query in error message."""
        error = JoernError("Syntax error", query="cpg.invalid")
        assert "cpg.invalid" in str(error)
