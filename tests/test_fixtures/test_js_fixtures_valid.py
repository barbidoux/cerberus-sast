"""
Tests to validate JavaScript/TypeScript fixtures are correctly structured.
These tests ensure our test fixtures are valid before using them for SAST validation.
"""

import json
import re
from pathlib import Path

import pytest

# Path to vulnerable Express app fixtures
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "vulnerable_express_app"


class TestFixtureStructure:
    """Verify fixture directory structure is correct."""

    def test_fixtures_directory_exists(self):
        """Fixture directory must exist."""
        assert FIXTURES_DIR.exists(), f"Fixtures directory not found: {FIXTURES_DIR}"
        assert FIXTURES_DIR.is_dir(), f"Expected directory, got file: {FIXTURES_DIR}"

    def test_package_json_exists(self):
        """package.json must exist and be valid JSON."""
        package_json = FIXTURES_DIR / "package.json"
        assert package_json.exists(), "package.json not found"

        content = package_json.read_text()
        data = json.loads(content)  # Will raise if invalid JSON

        assert "name" in data
        assert "dependencies" in data
        assert "express" in data["dependencies"]

    def test_backend_structure_exists(self):
        """Backend directory structure must exist."""
        backend_dir = FIXTURES_DIR / "backend"
        assert backend_dir.exists(), "backend/ directory not found"

        required_files = [
            "app.js",
            "routes/users.js",
            "routes/products.js",
            "routes/admin.js",
            "models/User.js",
            "middleware/auth.js",
            "utils/shell.js",
            "utils/file.js",
        ]

        for file_path in required_files:
            full_path = backend_dir / file_path
            assert full_path.exists(), f"Required file not found: {file_path}"

    def test_frontend_structure_exists(self):
        """Frontend directory structure must exist."""
        frontend_dir = FIXTURES_DIR / "frontend"
        assert frontend_dir.exists(), "frontend/ directory not found"

        required_files = [
            "angular.json",
            "src/app/search/search.component.ts",
            "src/app/admin/admin.component.ts",
            "src/app/user/user.component.ts",
            "src/services/api.service.ts",
        ]

        for file_path in required_files:
            full_path = frontend_dir / file_path
            assert full_path.exists(), f"Required file not found: {file_path}"

    def test_expected_findings_exists(self):
        """EXPECTED_FINDINGS.md must exist."""
        expected_findings = FIXTURES_DIR / "EXPECTED_FINDINGS.md"
        assert expected_findings.exists(), "EXPECTED_FINDINGS.md not found"


class TestJavaScriptFilesValid:
    """Verify JavaScript files are syntactically valid."""

    @pytest.fixture
    def js_files(self) -> list[Path]:
        """Get all JavaScript files in fixtures."""
        return list(FIXTURES_DIR.rglob("*.js"))

    @pytest.fixture
    def ts_files(self) -> list[Path]:
        """Get all TypeScript files in fixtures."""
        return list(FIXTURES_DIR.rglob("*.ts"))

    def test_js_files_exist(self, js_files):
        """At least one JavaScript file must exist."""
        assert len(js_files) > 0, "No JavaScript files found in fixtures"

    def test_ts_files_exist(self, ts_files):
        """At least one TypeScript file must exist."""
        assert len(ts_files) > 0, "No TypeScript files found in fixtures"

    def test_js_files_are_readable(self, js_files):
        """All JavaScript files must be readable text files."""
        for js_file in js_files:
            content = js_file.read_text(encoding="utf-8")
            assert len(content) > 0, f"Empty file: {js_file}"
            # Check for basic JavaScript syntax markers
            assert any(
                marker in content
                for marker in ["const ", "let ", "var ", "function ", "require(", "module.exports"]
            ), f"File doesn't look like JavaScript: {js_file}"

    def test_ts_files_are_readable(self, ts_files):
        """All TypeScript files must be readable text files."""
        for ts_file in ts_files:
            content = ts_file.read_text(encoding="utf-8")
            assert len(content) > 0, f"Empty file: {ts_file}"
            # Check for TypeScript/Angular markers
            assert any(
                marker in content
                for marker in ["import ", "export ", "@Component", "@Injectable", "interface ", "class "]
            ), f"File doesn't look like TypeScript: {ts_file}"


class TestExpectedFindingsDocument:
    """Verify EXPECTED_FINDINGS.md is properly structured."""

    @pytest.fixture
    def expected_findings_content(self) -> str:
        """Load EXPECTED_FINDINGS.md content."""
        expected_findings = FIXTURES_DIR / "EXPECTED_FINDINGS.md"
        return expected_findings.read_text()

    def test_has_summary_table(self, expected_findings_content):
        """Document must have a summary table."""
        assert "## Summary" in expected_findings_content
        assert "| Category | Count |" in expected_findings_content

    def test_has_vulnerability_sections(self, expected_findings_content):
        """Document must have sections for each CWE type."""
        required_cwes = [
            "CWE-89",
            "CWE-78",
            "CWE-79",
            "CWE-22",
            "CWE-798",
            "CWE-918",
            "CWE-94",
        ]
        for cwe in required_cwes:
            assert cwe in expected_findings_content, f"Missing section for {cwe}"

    def test_total_count_documented(self, expected_findings_content):
        """Total vulnerability count must be documented."""
        # Look for **Total** row in summary table
        assert "**Total**" in expected_findings_content

    def test_line_numbers_present(self, expected_findings_content):
        """Vulnerability entries must include line numbers."""
        # Line numbers should appear in the format "| N | file.js | NN |"
        line_pattern = r"\|\s*\d+\s*\|\s*[\w/.-]+\s*\|\s*\d+"
        matches = re.findall(line_pattern, expected_findings_content)
        assert len(matches) >= 30, f"Expected at least 30 line-numbered entries, found {len(matches)}"


class TestVulnerabilityPatternsPresent:
    """Verify vulnerability patterns are actually in the code."""

    def test_sql_injection_patterns_exist(self):
        """SQL injection patterns must be present in routes."""
        users_route = FIXTURES_DIR / "backend" / "routes" / "users.js"
        content = users_route.read_text()

        # Must have string interpolation in SQL
        assert "${" in content, "No template literal SQL injection found"
        assert "sequelize.query" in content, "No sequelize.query found"

    def test_command_injection_patterns_exist(self):
        """Command injection patterns must be present."""
        admin_route = FIXTURES_DIR / "backend" / "routes" / "admin.js"
        content = admin_route.read_text()

        assert "exec(" in content or "execSync(" in content, "No exec/execSync found"
        assert "spawn(" in content, "No spawn found"

    def test_xss_patterns_exist(self):
        """XSS patterns must be present in both backend and frontend."""
        # Backend XSS
        app_js = FIXTURES_DIR / "backend" / "app.js"
        app_content = app_js.read_text()
        assert "res.send(`" in app_content, "No res.send template literal found"

        # Frontend XSS
        search_component = FIXTURES_DIR / "frontend" / "src" / "app" / "search" / "search.component.ts"
        search_content = search_component.read_text()
        assert "innerHTML" in search_content, "No innerHTML found in frontend"

    def test_path_traversal_patterns_exist(self):
        """Path traversal patterns must be present."""
        file_utils = FIXTURES_DIR / "backend" / "utils" / "file.js"
        content = file_utils.read_text()

        assert "path.join" in content, "No path.join found"
        assert "fs.readFileSync" in content, "No fs.readFileSync found"

    def test_hardcoded_secrets_exist(self):
        """Hardcoded credentials must be present."""
        auth_middleware = FIXTURES_DIR / "backend" / "middleware" / "auth.js"
        content = auth_middleware.read_text()

        assert "JWT_SECRET" in content, "No JWT_SECRET found"
        assert any(
            secret in content
            for secret in ["secret", "password", "key", "token"]
        ), "No hardcoded secret patterns found"

    def test_ssrf_patterns_exist(self):
        """SSRF patterns must be present."""
        api_service = FIXTURES_DIR / "frontend" / "src" / "services" / "api.service.ts"
        content = api_service.read_text()

        assert "http.get(" in content or "http.post(" in content, "No HttpClient calls found"

    def test_code_injection_patterns_exist(self):
        """Code injection patterns must be present."""
        search_component = FIXTURES_DIR / "frontend" / "src" / "app" / "search" / "search.component.ts"
        content = search_component.read_text()

        assert "eval(" in content, "No eval() found"
        assert "new Function(" in content, "No new Function() found"


class TestSafeExamplesPresent:
    """Verify safe code examples are present for false positive testing."""

    def test_safe_sql_example_exists(self):
        """Parameterized query example must exist."""
        users_route = FIXTURES_DIR / "backend" / "routes" / "users.js"
        content = users_route.read_text()

        # Look for parameterized query pattern
        assert "replacements:" in content or "Safe example" in content, "No safe SQL example found"

    def test_safe_file_example_exists(self):
        """Safe file operation example must exist."""
        file_utils = FIXTURES_DIR / "backend" / "utils" / "file.js"
        content = file_utils.read_text()

        assert "safeReadFile" in content or "Safe example" in content, "No safe file example found"

    def test_safe_api_examples_exist(self):
        """Safe API call examples must exist."""
        api_service = FIXTURES_DIR / "frontend" / "src" / "services" / "api.service.ts"
        content = api_service.read_text()

        # Safe pattern: fixed API path, not user-controlled
        assert "/api/users" in content, "No safe API endpoint found"
