"""
Tests for JavaScript/TypeScript heuristic patterns in candidate extraction.
TDD: Define expected behavior for Express.js and Angular patterns.
"""

import pytest

from cerberus.inference.candidate_extractor import HeuristicMatcher


@pytest.fixture
def matcher() -> HeuristicMatcher:
    """Create a fresh heuristic matcher."""
    return HeuristicMatcher()


class TestExpressJsSourcePatterns:
    """Test source detection for Express.js patterns."""

    def test_req_body_access(self, matcher):
        """Should detect req.body as a source."""
        # These are common Express handler signatures
        assert matcher.match_source_pattern("getRequestBody") >= 0.7
        assert matcher.match_source_pattern("getBody") >= 0.6

    def test_req_params_access(self, matcher):
        """Should detect req.params as a source."""
        assert matcher.match_source_pattern("getParams") >= 0.6
        assert matcher.match_source_pattern("readParams") >= 0.6

    def test_req_query_access(self, matcher):
        """Should detect req.query as a source."""
        assert matcher.match_source_pattern("getQuery") >= 0.6
        assert matcher.match_source_pattern("parseQuery") >= 0.6

    def test_req_headers_access(self, matcher):
        """Should detect header access as a source."""
        assert matcher.match_source_pattern("getHeader") >= 0.6
        assert matcher.match_source_pattern("readHeaders") >= 0.6

    def test_req_cookies_access(self, matcher):
        """Should detect cookie access as a source."""
        assert matcher.match_source_pattern("getCookie") >= 0.6
        assert matcher.match_source_pattern("parseCookies") >= 0.6


class TestExpressJsSinkPatterns:
    """Test sink detection for Express.js patterns."""

    def test_exec_patterns(self, matcher):
        """Should detect exec/spawn as sinks."""
        assert matcher.match_sink_pattern("exec") >= 0.7
        assert matcher.match_sink_pattern("execSync") >= 0.7
        assert matcher.match_sink_pattern("spawn") >= 0.6
        assert matcher.match_sink_pattern("spawnSync") >= 0.6

    def test_sequelize_raw_query(self, matcher):
        """Should detect Sequelize raw queries as sinks."""
        assert matcher.match_sink_pattern("sequelizeQuery") >= 0.6
        assert matcher.match_sink_pattern("rawQuery") >= 0.7

    def test_fs_operations(self, matcher):
        """Should detect filesystem operations as sinks."""
        assert matcher.match_sink_pattern("readFileSync") >= 0.6
        assert matcher.match_sink_pattern("writeFileSync") >= 0.6
        assert matcher.match_sink_pattern("unlinkSync") >= 0.6

    def test_res_render(self, matcher):
        """Should detect res.render as a sink."""
        assert matcher.match_sink_pattern("render") >= 0.4

    def test_res_download(self, matcher):
        """Should detect res.download as a sink."""
        assert matcher.match_sink_pattern("download") >= 0.4

    def test_res_sendfile(self, matcher):
        """Should detect res.sendFile as a sink."""
        assert matcher.match_sink_pattern("sendFile") >= 0.4


class TestAngularSinkPatterns:
    """Test sink detection for Angular patterns."""

    def test_bypass_security_trust(self, matcher):
        """Should detect bypassSecurityTrust* as sinks."""
        assert matcher.match_sink_pattern("bypassSecurityTrustHtml") >= 0.9
        assert matcher.match_sink_pattern("bypassSecurityTrustScript") >= 0.9
        assert matcher.match_sink_pattern("bypassSecurityTrustStyle") >= 0.9
        assert matcher.match_sink_pattern("bypassSecurityTrustUrl") >= 0.9
        assert matcher.match_sink_pattern("bypassSecurityTrustResourceUrl") >= 0.9

    def test_innerhtml_binding(self, matcher):
        """Should detect innerHTML as a sink."""
        assert matcher.match_sink_pattern("innerHTML") >= 0.8
        assert matcher.match_sink_pattern("outerHTML") >= 0.7


class TestAngularSourcePatterns:
    """Test source detection for Angular patterns."""

    def test_activated_route_params(self, matcher):
        """Should detect ActivatedRoute params as sources."""
        assert matcher.match_source_pattern("getRouteParams") >= 0.6
        assert matcher.match_source_pattern("routeParams") >= 0.5

    def test_http_client(self, matcher):
        """Should detect HttpClient responses as sources."""
        # These may introduce external data
        assert matcher.match_source_pattern("fetchData") >= 0.3
        assert matcher.match_source_pattern("getData") >= 0.3


class TestJavaScriptSanitizerPatterns:
    """Test sanitizer detection for JavaScript patterns."""

    def test_escape_html_patterns(self, matcher):
        """Should detect HTML escape functions."""
        assert matcher.match_sanitizer_pattern("escapeHtml") >= 0.8
        assert matcher.match_sanitizer_pattern("sanitizeHtml") >= 0.9

    def test_dompurify_patterns(self, matcher):
        """Should detect DOMPurify usage."""
        assert matcher.match_sanitizer_pattern("purify") >= 0.7
        assert matcher.match_sanitizer_pattern("DOMPurify") >= 0.8

    def test_validator_patterns(self, matcher):
        """Should detect validator functions."""
        assert matcher.match_sanitizer_pattern("validateInput") >= 0.8
        assert matcher.match_sanitizer_pattern("isValid") >= 0.3


class TestJavaScriptImportPatterns:
    """Test import pattern recognition for JavaScript."""

    def test_express_imports_as_source(self, matcher):
        """Should recognize Express imports for source context."""
        from cerberus.inference.candidate_extractor import CandidateType
        score = matcher.score_from_imports(
            ["express", "body-parser"],
            CandidateType.SOURCE
        )
        assert score > 0

    def test_sequelize_imports_as_sink(self, matcher):
        """Should recognize Sequelize imports for sink context."""
        from cerberus.inference.candidate_extractor import CandidateType
        score = matcher.score_from_imports(
            ["sequelize", "mysql2"],
            CandidateType.SINK
        )
        assert score > 0

    def test_child_process_imports_as_sink(self, matcher):
        """Should recognize child_process imports for sink context."""
        from cerberus.inference.candidate_extractor import CandidateType
        score = matcher.score_from_imports(
            ["child_process"],
            CandidateType.SINK
        )
        assert score > 0

    def test_dom_sanitizer_imports(self, matcher):
        """Should recognize sanitization imports."""
        from cerberus.inference.candidate_extractor import CandidateType
        score = matcher.score_from_imports(
            ["dompurify", "sanitize-html"],
            CandidateType.SANITIZER
        )
        assert score > 0

    def test_express_validator_imports(self, matcher):
        """Should recognize express-validator imports."""
        from cerberus.inference.candidate_extractor import CandidateType
        score = matcher.score_from_imports(
            ["express-validator"],
            CandidateType.SANITIZER
        )
        assert score > 0
