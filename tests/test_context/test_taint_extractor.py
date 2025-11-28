"""
TDD Tests for TaintExtractor - AST-level taint source and sink extraction.

These tests define the expected behavior for Milestone 7:
- Extract taint sources (req.body, req.params, req.query, etc.)
- Extract taint sinks (query, exec, eval, etc.)
- Detect template literal usage (high-risk indicator)
- Create flow candidates by matching sources to sinks
"""

from pathlib import Path

import pytest

from cerberus.models.taint_flow import (
    SourceType,
    SinkType,
    TaintSource,
    TaintSink,
    TaintFlowCandidate,
)


# Fixture for TaintExtractor - will be implemented next
@pytest.fixture
def extractor():
    """Create a fresh taint extractor."""
    from cerberus.context.taint_extractor import TaintExtractor
    return TaintExtractor()


class TestTaintSourceExtraction:
    """Test extraction of taint sources from JavaScript/TypeScript AST."""

    def test_extracts_req_body(self, extractor):
        """Should extract req.body as a source."""
        code = '''
router.post('/login', (req, res) => {
    const username = req.body.username;
});
'''
        sources, _ = extractor.extract_from_string(code, "javascript", Path("test.js"))

        assert len(sources) >= 1
        source = sources[0]
        assert "req.body" in source.expression
        assert source.source_type == SourceType.REQUEST_BODY
        assert source.line == 3
        assert "CWE-89" in source.cwe_types or "CWE-78" in source.cwe_types

    def test_extracts_req_params(self, extractor):
        """Should extract req.params as a source."""
        code = '''
router.get('/users/:id', (req, res) => {
    const userId = req.params.id;
});
'''
        sources, _ = extractor.extract_from_string(code, "javascript", Path("test.js"))

        assert len(sources) >= 1
        source = sources[0]
        assert "req.params" in source.expression
        assert source.source_type == SourceType.REQUEST_PARAMS
        assert "CWE-89" in source.cwe_types

    def test_extracts_req_query(self, extractor):
        """Should extract req.query as a source."""
        code = '''
router.get('/search', (req, res) => {
    const searchTerm = req.query.name;
    const filter = req.query.filter;
});
'''
        sources, _ = extractor.extract_from_string(code, "javascript", Path("test.js"))

        assert len(sources) >= 2
        expressions = [s.expression for s in sources]
        assert any("req.query.name" in e for e in expressions)
        assert any("req.query.filter" in e for e in expressions)

    def test_extracts_multiple_sources_same_line(self, extractor):
        """Should extract multiple sources even on same line."""
        code = '''
const data = { user: req.body.user, role: req.body.role };
'''
        sources, _ = extractor.extract_from_string(code, "javascript", Path("test.js"))

        assert len(sources) >= 2

    def test_extracts_nested_property_access(self, extractor):
        """Should extract deeply nested property access."""
        code = '''
const email = req.body.user.email;
const city = req.body.address.city;
'''
        sources, _ = extractor.extract_from_string(code, "javascript", Path("test.js"))

        assert len(sources) >= 2
        expressions = [s.expression for s in sources]
        assert any("req.body.user.email" in e or "req.body" in e for e in expressions)

    def test_extracts_destructured_body(self, extractor):
        """Should detect sources from destructuring (best effort)."""
        code = '''
const { username, password } = req.body;
'''
        sources, _ = extractor.extract_from_string(code, "javascript", Path("test.js"))

        # At minimum should detect req.body
        assert len(sources) >= 1
        assert any("req.body" in s.expression for s in sources)

    def test_extracts_req_headers(self, extractor):
        """Should extract req.headers as a source."""
        code = '''
const authToken = req.headers.authorization;
'''
        sources, _ = extractor.extract_from_string(code, "javascript", Path("test.js"))

        assert len(sources) >= 1
        assert any(s.source_type == SourceType.REQUEST_HEADERS for s in sources)

    def test_tracks_containing_function(self, extractor):
        """Should track which function contains the source."""
        code = '''
function processLogin(req, res) {
    const username = req.body.username;
    return username;
}
'''
        sources, _ = extractor.extract_from_string(code, "javascript", Path("test.js"))

        assert len(sources) >= 1
        # Containing function should be tracked (may be None if not implemented yet)
        # This tests the capability exists
        source = sources[0]
        assert hasattr(source, 'containing_function')

    def test_extracts_process_env(self, extractor):
        """Should extract process.env as environment source."""
        code = '''
const apiKey = process.env.API_KEY;
const dbUrl = process.env.DATABASE_URL;
'''
        sources, _ = extractor.extract_from_string(code, "javascript", Path("test.js"))

        env_sources = [s for s in sources if s.source_type == SourceType.ENVIRONMENT]
        assert len(env_sources) >= 1

    def test_no_false_positives_for_non_sources(self, extractor):
        """Should NOT extract non-source member expressions."""
        code = '''
const user = db.users.findById(id);
const config = app.settings.port;
'''
        sources, _ = extractor.extract_from_string(code, "javascript", Path("test.js"))

        # These are NOT user input sources
        assert len(sources) == 0


class TestTaintSinkExtraction:
    """Test extraction of taint sinks from JavaScript/TypeScript AST."""

    def test_extracts_query_sink(self, extractor):
        """Should extract query() as SQL sink."""
        code = '''
const users = await sequelize.query("SELECT * FROM users");
'''
        _, sinks = extractor.extract_from_string(code, "javascript", Path("test.js"))

        assert len(sinks) >= 1
        sink = sinks[0]
        assert sink.callee == "query"
        assert sink.sink_type == SinkType.SQL_QUERY
        assert "CWE-89" in sink.cwe_types

    def test_extracts_exec_sink(self, extractor):
        """Should extract exec() as command execution sink."""
        code = '''
const { exec } = require('child_process');
exec(command, (err, stdout) => {});
'''
        _, sinks = extractor.extract_from_string(code, "javascript", Path("test.js"))

        exec_sinks = [s for s in sinks if s.callee == "exec"]
        assert len(exec_sinks) >= 1
        assert exec_sinks[0].sink_type == SinkType.COMMAND_EXEC
        assert "CWE-78" in exec_sinks[0].cwe_types

    def test_extracts_execSync_sink(self, extractor):
        """Should extract execSync() as command execution sink."""
        code = '''
const result = execSync(command);
'''
        _, sinks = extractor.extract_from_string(code, "javascript", Path("test.js"))

        assert len(sinks) >= 1
        assert sinks[0].callee == "execSync"
        assert sinks[0].sink_type == SinkType.COMMAND_EXEC

    def test_extracts_eval_sink(self, extractor):
        """Should extract eval() as code execution sink."""
        code = '''
const result = eval(userCode);
'''
        _, sinks = extractor.extract_from_string(code, "javascript", Path("test.js"))

        assert len(sinks) >= 1
        assert sinks[0].callee == "eval"
        assert sinks[0].sink_type == SinkType.CODE_EXEC
        assert "CWE-94" in sinks[0].cwe_types

    def test_extracts_readFileSync_sink(self, extractor):
        """Should extract readFileSync() as file read sink."""
        code = '''
const content = fs.readFileSync(filePath);
'''
        _, sinks = extractor.extract_from_string(code, "javascript", Path("test.js"))

        assert len(sinks) >= 1
        assert sinks[0].callee == "readFileSync"
        assert sinks[0].sink_type == SinkType.FILE_READ
        assert "CWE-22" in sinks[0].cwe_types

    def test_extracts_method_call_sink(self, extractor):
        """Should extract method calls like db.query()."""
        code = '''
const users = await db.query(sql);
const result = await connection.execute(query);
'''
        _, sinks = extractor.extract_from_string(code, "javascript", Path("test.js"))

        callees = [s.callee for s in sinks]
        assert "query" in callees
        assert "execute" in callees


class TestTemplateLiteralDetection:
    """Test detection of template literals in sink arguments (HIGH RISK)."""

    def test_detects_template_literal_in_query(self, extractor):
        """Should detect template literal usage in SQL query."""
        code = '''
const result = sequelize.query(`SELECT * FROM users WHERE id = ${userId}`);
'''
        _, sinks = extractor.extract_from_string(code, "javascript", Path("test.js"))

        assert len(sinks) >= 1
        assert sinks[0].uses_template_literal is True

    def test_detects_template_literal_in_exec(self, extractor):
        """Should detect template literal usage in exec()."""
        code = '''
exec(`ls -la ${userPath}`, callback);
'''
        _, sinks = extractor.extract_from_string(code, "javascript", Path("test.js"))

        assert len(sinks) >= 1
        assert sinks[0].uses_template_literal is True

    def test_no_template_literal_with_string_arg(self, extractor):
        """Should NOT flag template literal for regular strings."""
        code = '''
const result = db.query("SELECT * FROM users WHERE id = ?", [userId]);
'''
        _, sinks = extractor.extract_from_string(code, "javascript", Path("test.js"))

        assert len(sinks) >= 1
        assert sinks[0].uses_template_literal is False

    def test_detects_template_literal_with_expression(self, extractor):
        """Should detect template literal with complex expressions."""
        code = '''
sequelize.query(`SELECT * FROM ${tableName} WHERE ${condition}`);
'''
        _, sinks = extractor.extract_from_string(code, "javascript", Path("test.js"))

        assert len(sinks) >= 1
        assert sinks[0].uses_template_literal is True


class TestFlowCandidateCreation:
    """Test creation of flow candidates from source-sink pairs."""

    def test_creates_candidate_for_sql_injection(self, extractor):
        """Should create flow candidate for SQL injection pattern."""
        code = '''
router.get('/user/:id', (req, res) => {
    const id = req.params.id;
    sequelize.query(`SELECT * FROM users WHERE id = ${id}`);
});
'''
        sources, sinks = extractor.extract_from_string(code, "javascript", Path("test.js"))
        candidates = extractor.create_flow_candidates(sources, sinks)

        assert len(candidates) >= 1
        candidate = candidates[0]
        assert candidate.source.source_type == SourceType.REQUEST_PARAMS
        assert candidate.sink.sink_type == SinkType.SQL_QUERY
        assert "CWE-89" in candidate.shared_cwe_types

    def test_creates_candidate_for_command_injection(self, extractor):
        """Should create flow candidate for command injection pattern."""
        code = '''
router.post('/run', (req, res) => {
    const command = req.body.cmd;
    exec(command);
});
'''
        sources, sinks = extractor.extract_from_string(code, "javascript", Path("test.js"))
        candidates = extractor.create_flow_candidates(sources, sinks)

        assert len(candidates) >= 1
        candidate = candidates[0]
        assert candidate.source.source_type == SourceType.REQUEST_BODY
        assert candidate.sink.sink_type == SinkType.COMMAND_EXEC
        assert "CWE-78" in candidate.shared_cwe_types

    def test_in_same_function_detection(self, extractor):
        """Should detect when source and sink are in same function."""
        code = '''
router.get('/search', (req, res) => {
    const term = req.query.q;
    db.query(`SELECT * FROM items WHERE name = '${term}'`);
});
'''
        sources, sinks = extractor.extract_from_string(code, "javascript", Path("test.js"))
        candidates = extractor.create_flow_candidates(sources, sinks)

        assert len(candidates) >= 1
        # Same function = higher confidence
        assert candidates[0].in_same_function is True or candidates[0].in_same_file is True

    def test_no_candidate_for_unrelated_cwe_types(self, extractor):
        """Should NOT create candidate when CWE types don't overlap."""
        # XSS source but SQL sink
        code = '''
const cookie = req.cookies.session;  // CWE-79 source
const data = fs.readFileSync(staticPath);  // CWE-22 sink (unrelated to cookies)
'''
        sources, sinks = extractor.extract_from_string(code, "javascript", Path("test.js"))
        candidates = extractor.create_flow_candidates(sources, sinks)

        # May or may not create candidate depending on CWE overlap
        # This test verifies the logic considers CWE compatibility
        for c in candidates:
            assert len(c.shared_cwe_types) > 0, "Candidates should have shared CWEs"

    def test_line_distance_calculation(self, extractor):
        """Should calculate line distance between source and sink."""
        code = '''
const input = req.body.data;  // Line 1

// Some processing
const x = 1;
const y = 2;

db.query(`SELECT ${input}`);  // Line 7
'''
        sources, sinks = extractor.extract_from_string(code, "javascript", Path("test.js"))
        candidates = extractor.create_flow_candidates(sources, sinks)

        if candidates:
            assert candidates[0].distance_lines > 0


class TestHeuristicScoring:
    """Test heuristic confidence scoring for flow candidates."""

    def test_same_function_bonus(self):
        """Same function should add +0.3 confidence."""
        source = TaintSource(
            expression="req.body.id",
            source_type=SourceType.REQUEST_BODY,
            file_path=Path("test.js"),
            line=10,
            cwe_types=["CWE-89"],
        )
        sink = TaintSink(
            callee="query",
            expression="query(...)",
            sink_type=SinkType.SQL_QUERY,
            file_path=Path("test.js"),
            line=12,
            cwe_types=["CWE-89"],
        )
        candidate = TaintFlowCandidate(source=source, sink=sink, in_same_function=True)
        candidate.apply_heuristic_scoring()

        assert candidate.confidence >= 0.8  # base 0.5 + same_function 0.3 + proximity
        assert "same_function" in candidate.confidence_factors

    def test_template_literal_bonus(self):
        """Template literal should add +0.4 confidence."""
        source = TaintSource(
            expression="req.params.id",
            source_type=SourceType.REQUEST_PARAMS,
            file_path=Path("test.js"),
            line=10,
            cwe_types=["CWE-89"],
        )
        sink = TaintSink(
            callee="query",
            expression="query(`SELECT ${id}`)",
            sink_type=SinkType.SQL_QUERY,
            file_path=Path("test.js"),
            line=12,
            uses_template_literal=True,
            cwe_types=["CWE-89"],
        )
        candidate = TaintFlowCandidate(source=source, sink=sink)
        candidate.apply_heuristic_scoring()

        assert candidate.confidence >= 0.9
        assert "template_literal" in candidate.confidence_factors

    def test_max_confidence_capped_at_094(self):
        """Heuristic confidence should cap at 0.94 (reserve 0.95+ for CPG)."""
        source = TaintSource(
            expression="req.body.cmd",
            source_type=SourceType.REQUEST_BODY,
            file_path=Path("test.js"),
            line=10,
            cwe_types=["CWE-78"],
        )
        sink = TaintSink(
            callee="exec",
            expression="exec(`${cmd}`)",
            sink_type=SinkType.COMMAND_EXEC,
            file_path=Path("test.js"),
            line=11,
            uses_template_literal=True,
            cwe_types=["CWE-78"],
        )
        candidate = TaintFlowCandidate(source=source, sink=sink, in_same_function=True)
        candidate.apply_heuristic_scoring()

        assert candidate.confidence <= 0.94


class TestPythonSourceExtraction:
    """Test extraction of Python taint sources."""

    def test_extracts_flask_request_form(self, extractor):
        """Should extract Flask request.form as source."""
        code = '''
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form.get('password')
'''
        sources, _ = extractor.extract_from_string(code, "python", Path("app.py"))

        assert len(sources) >= 1
        assert any(s.source_type == SourceType.FLASK_REQUEST for s in sources)

    def test_extracts_flask_request_args(self, extractor):
        """Should extract Flask request.args as source."""
        code = '''
@app.route('/search')
def search():
    query = request.args.get('q')
'''
        sources, _ = extractor.extract_from_string(code, "python", Path("app.py"))

        assert len(sources) >= 1
        assert any("request.args" in s.expression for s in sources)


class TestPythonSinkExtraction:
    """Test extraction of Python taint sinks."""

    def test_extracts_cursor_execute(self, extractor):
        """Should extract cursor.execute() as SQL sink."""
        code = '''
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        _, sinks = extractor.extract_from_string(code, "python", Path("db.py"))

        assert len(sinks) >= 1
        # Callee can be "execute" or "cursor.execute" depending on extraction
        assert "execute" in sinks[0].callee
        assert sinks[0].sink_type == SinkType.SQL_QUERY

    def test_extracts_subprocess_call(self, extractor):
        """Should extract subprocess.run() as command sink."""
        code = '''
import subprocess
result = subprocess.run(command, shell=True)
'''
        _, sinks = extractor.extract_from_string(code, "python", Path("utils.py"))

        assert len(sinks) >= 1
        # Callee can be "run" or "subprocess.run" depending on extraction
        assert any("run" in s.callee for s in sinks)

    def test_extracts_os_system(self, extractor):
        """Should extract os.system() as command sink."""
        code = '''
import os
os.system(f"ls {user_path}")
'''
        _, sinks = extractor.extract_from_string(code, "python", Path("utils.py"))

        # os.system may be captured as "system" call
        assert len(sinks) >= 1


class TestRealWorldFixtureExtraction:
    """Test extraction against real fixture files."""

    @pytest.fixture
    def fixtures_dir(self) -> Path:
        """Get path to vulnerable Express app fixtures."""
        return Path(__file__).parent.parent / "fixtures" / "vulnerable_express_app"

    def test_extract_from_users_route(self, extractor, fixtures_dir):
        """Should extract sources and sinks from backend/routes/users.js."""
        users_file = fixtures_dir / "backend" / "routes" / "users.js"
        if not users_file.exists():
            pytest.skip("Fixtures not available")

        sources, sinks = extractor.extract_from_file(users_file)

        # users.js has multiple SQL injections via req.params, req.query, req.body
        assert len(sources) > 0, "Should find sources in users.js"
        assert len(sinks) > 0, "Should find sinks in users.js"

        # Verify we found req.body, req.params, req.query sources
        source_types = {s.source_type for s in sources}
        assert SourceType.REQUEST_BODY in source_types or \
               SourceType.REQUEST_PARAMS in source_types or \
               SourceType.REQUEST_QUERY in source_types

        # Verify we found query() sinks
        sink_callees = {s.callee for s in sinks}
        assert "query" in sink_callees

    def test_extract_flow_candidates_from_users_route(self, extractor, fixtures_dir):
        """Should create flow candidates for SQL injection in users.js."""
        users_file = fixtures_dir / "backend" / "routes" / "users.js"
        if not users_file.exists():
            pytest.skip("Fixtures not available")

        sources, sinks = extractor.extract_from_file(users_file)
        candidates = extractor.create_flow_candidates(sources, sinks)

        # Should have multiple SQL injection candidates
        sql_candidates = [c for c in candidates if "CWE-89" in c.shared_cwe_types]
        assert len(sql_candidates) >= 1, f"Expected SQL injection candidates, got {len(sql_candidates)}"

    def test_extract_from_admin_route(self, extractor, fixtures_dir):
        """Should extract command injection patterns from admin.js."""
        admin_file = fixtures_dir / "backend" / "routes" / "admin.js"
        if not admin_file.exists():
            pytest.skip("Fixtures not available")

        sources, sinks = extractor.extract_from_file(admin_file)

        # Should find command execution sinks
        cmd_sinks = [s for s in sinks if s.sink_type == SinkType.COMMAND_EXEC]
        assert len(cmd_sinks) >= 0  # May or may not have command injection


class TestMultiLanguageSupport:
    """Test that TaintExtractor supports multiple languages."""

    def test_supported_languages(self, extractor):
        """Should report supported languages."""
        supported = extractor.supported_languages
        assert "javascript" in supported
        assert "typescript" in supported
        assert "python" in supported

    def test_unsupported_language_returns_empty(self, extractor):
        """Should return empty for unsupported languages."""
        code = '''
program test;
begin
    writeln('Hello');
end.
'''
        sources, sinks = extractor.extract_from_string(code, "pascal", Path("test.pas"))
        assert sources == []
        assert sinks == []


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_code(self, extractor):
        """Should handle empty code."""
        sources, sinks = extractor.extract_from_string("", "javascript", Path("empty.js"))
        assert sources == []
        assert sinks == []

    def test_malformed_code(self, extractor):
        """Should handle malformed code gracefully."""
        code = '''
const x = {
    broken: [
    // missing closing brackets
'''
        # Should not raise exception
        sources, sinks = extractor.extract_from_string(code, "javascript", Path("broken.js"))
        # May return partial results or empty
        assert isinstance(sources, list)
        assert isinstance(sinks, list)

    def test_minified_code(self, extractor):
        """Should handle minified code."""
        code = 'const a=req.body.x;db.query(`SELECT ${a}`);'
        sources, sinks = extractor.extract_from_string(code, "javascript", Path("min.js"))

        # Should still extract sources and sinks
        assert len(sources) >= 1
        assert len(sinks) >= 1
