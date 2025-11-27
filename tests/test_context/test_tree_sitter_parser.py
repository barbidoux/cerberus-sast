"""
Tests for Tree-sitter parser.

TDD: Write tests first, then implement to make them pass.
"""

import tempfile
from pathlib import Path

import pytest

from cerberus.context.tree_sitter_parser import (
    LANGUAGE_EXTENSIONS,
    TREE_SITTER_LANGUAGES,
    TreeSitterParser,
)


class TestLanguageMappings:
    """Test language extension and Tree-sitter mappings."""

    def test_python_extension_mapping(self):
        """Python extensions should map to python language."""
        assert LANGUAGE_EXTENSIONS[".py"] == "python"
        assert LANGUAGE_EXTENSIONS[".pyi"] == "python"

    def test_javascript_extension_mapping(self):
        """JavaScript extensions should map to javascript language."""
        assert LANGUAGE_EXTENSIONS[".js"] == "javascript"
        assert LANGUAGE_EXTENSIONS[".jsx"] == "javascript"
        assert LANGUAGE_EXTENSIONS[".mjs"] == "javascript"

    def test_typescript_extension_mapping(self):
        """TypeScript extensions should map to typescript language."""
        assert LANGUAGE_EXTENSIONS[".ts"] == "typescript"
        assert LANGUAGE_EXTENSIONS[".tsx"] == "typescript"

    def test_c_cpp_extension_mapping(self):
        """C/C++ extensions should map correctly."""
        assert LANGUAGE_EXTENSIONS[".c"] == "c"
        assert LANGUAGE_EXTENSIONS[".h"] == "c"
        assert LANGUAGE_EXTENSIONS[".cpp"] == "cpp"
        assert LANGUAGE_EXTENSIONS[".hpp"] == "cpp"

    def test_java_extension_mapping(self):
        """Java extensions should map to java."""
        assert LANGUAGE_EXTENSIONS[".java"] == "java"

    def test_go_extension_mapping(self):
        """Go extensions should map to go."""
        assert LANGUAGE_EXTENSIONS[".go"] == "go"

    def test_tree_sitter_language_mapping(self):
        """Tree-sitter language names should be mapped correctly."""
        assert TREE_SITTER_LANGUAGES["python"] == "python"
        assert TREE_SITTER_LANGUAGES["javascript"] == "javascript"
        assert TREE_SITTER_LANGUAGES["csharp"] == "c_sharp"  # Special case


class TestTreeSitterParserInit:
    """Test TreeSitterParser initialization."""

    def test_creates_parser_instance(self):
        """Parser should initialize without errors."""
        parser = TreeSitterParser()
        assert parser is not None

    def test_parsers_dict_empty_initially(self):
        """Parser cache should be empty on init."""
        parser = TreeSitterParser()
        assert parser._parsers == {}


class TestLanguageDetection:
    """Test language detection from file paths."""

    @pytest.fixture
    def parser(self):
        return TreeSitterParser()

    def test_detect_python(self, parser):
        """Should detect Python from .py extension."""
        assert parser.detect_language(Path("test.py")) == "python"

    def test_detect_javascript(self, parser):
        """Should detect JavaScript from .js extension."""
        assert parser.detect_language(Path("app.js")) == "javascript"

    def test_detect_typescript(self, parser):
        """Should detect TypeScript from .ts extension."""
        assert parser.detect_language(Path("app.ts")) == "typescript"

    def test_detect_c(self, parser):
        """Should detect C from .c extension."""
        assert parser.detect_language(Path("main.c")) == "c"

    def test_detect_cpp(self, parser):
        """Should detect C++ from .cpp extension."""
        assert parser.detect_language(Path("main.cpp")) == "cpp"

    def test_detect_java(self, parser):
        """Should detect Java from .java extension."""
        assert parser.detect_language(Path("Main.java")) == "java"

    def test_detect_unknown(self, parser):
        """Should return None for unknown extensions."""
        assert parser.detect_language(Path("readme.md")) is None
        assert parser.detect_language(Path("config.yaml")) is None

    def test_detect_case_insensitive(self, parser):
        """Should detect language regardless of extension case."""
        assert parser.detect_language(Path("test.PY")) == "python"
        assert parser.detect_language(Path("app.JS")) == "javascript"


class TestParseString:
    """Test parsing source code strings."""

    @pytest.fixture
    def parser(self):
        return TreeSitterParser()

    def test_parse_python_string(self, parser):
        """Should parse valid Python code."""
        code = """
def hello():
    print("Hello, World!")
"""
        tree = parser.parse_string(code, "python")
        assert tree is not None
        assert tree.root_node is not None
        assert tree.root_node.type == "module"

    def test_parse_javascript_string(self, parser):
        """Should parse valid JavaScript code."""
        code = """
function hello() {
    console.log("Hello, World!");
}
"""
        tree = parser.parse_string(code, "javascript")
        assert tree is not None
        assert tree.root_node is not None
        assert tree.root_node.type == "program"

    def test_parse_c_string(self, parser):
        """Should parse valid C code."""
        code = """
int main() {
    return 0;
}
"""
        tree = parser.parse_string(code, "c")
        assert tree is not None
        assert tree.root_node is not None

    def test_parse_invalid_language(self, parser):
        """Should return None for unsupported language."""
        code = "some code"
        tree = parser.parse_string(code, "nonexistent_language")
        assert tree is None


class TestParseBytes:
    """Test parsing source code bytes."""

    @pytest.fixture
    def parser(self):
        return TreeSitterParser()

    def test_parse_python_bytes(self, parser):
        """Should parse Python code as bytes."""
        code = b"def foo(): pass"
        tree = parser.parse_bytes(code, "python")
        assert tree is not None
        assert tree.root_node.type == "module"

    def test_parse_utf8_bytes(self, parser):
        """Should handle UTF-8 encoded content."""
        code = 'def greet(): return "Hello, 世界"'.encode("utf-8")
        tree = parser.parse_bytes(code, "python")
        assert tree is not None


class TestParseFile:
    """Test parsing source files."""

    @pytest.fixture
    def parser(self):
        return TreeSitterParser()

    def test_parse_python_file(self, parser):
        """Should parse a Python file."""
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write("def hello(): pass")
            f.flush()
            path = Path(f.name)

        tree = parser.parse_file(path)
        assert tree is not None
        assert tree.root_node.type == "module"
        path.unlink()

    def test_parse_javascript_file(self, parser):
        """Should parse a JavaScript file."""
        with tempfile.NamedTemporaryFile(suffix=".js", delete=False, mode="w") as f:
            f.write("function hello() {}")
            f.flush()
            path = Path(f.name)

        tree = parser.parse_file(path)
        assert tree is not None
        assert tree.root_node.type == "program"
        path.unlink()

    def test_parse_with_language_override(self, parser):
        """Should respect language override."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
            f.write("def hello(): pass")
            f.flush()
            path = Path(f.name)

        # Without override, should fail (unknown extension)
        tree = parser.parse_file(path)
        assert tree is None

        # With override, should succeed
        tree = parser.parse_file(path, language="python")
        assert tree is not None
        path.unlink()

    def test_parse_nonexistent_file(self, parser):
        """Should return None for nonexistent files."""
        tree = parser.parse_file(Path("/nonexistent/file.py"))
        assert tree is None

    def test_parse_unsupported_extension(self, parser):
        """Should return None for unsupported file types."""
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False, mode="w") as f:
            f.write("# README")
            f.flush()
            path = Path(f.name)

        tree = parser.parse_file(path)
        assert tree is None
        path.unlink()


class TestParseRepository:
    """Test repository-wide parsing."""

    @pytest.fixture
    def parser(self):
        return TreeSitterParser()

    @pytest.fixture
    def temp_repo(self):
        """Create a temporary repository structure."""
        import shutil
        import tempfile

        repo_dir = Path(tempfile.mkdtemp())

        # Create Python files
        (repo_dir / "src").mkdir()
        (repo_dir / "src" / "main.py").write_text("def main(): pass")
        (repo_dir / "src" / "utils.py").write_text("def helper(): pass")

        # Create JavaScript files
        (repo_dir / "frontend").mkdir()
        (repo_dir / "frontend" / "app.js").write_text("function app() {}")

        # Create non-code files (should be ignored)
        (repo_dir / "README.md").write_text("# Project")
        (repo_dir / "config.yaml").write_text("key: value")

        yield repo_dir
        shutil.rmtree(repo_dir)

    def test_parse_all_supported_files(self, parser, temp_repo):
        """Should parse all supported files in repo."""
        trees = parser.parse_repository(temp_repo)
        assert len(trees) == 3  # 2 Python + 1 JavaScript

    def test_exclude_patterns(self, parser, temp_repo):
        """Should respect exclude patterns."""
        trees = parser.parse_repository(temp_repo, exclude_patterns=["*.js"])
        assert len(trees) == 2  # Only Python files

        trees = parser.parse_repository(temp_repo, exclude_patterns=["src/*"])
        assert len(trees) == 1  # Only JavaScript

    def test_filter_by_language(self, parser, temp_repo):
        """Should filter by language list."""
        trees = parser.parse_repository(temp_repo, languages=["python"])
        assert len(trees) == 2  # Only Python files

        trees = parser.parse_repository(temp_repo, languages=["javascript"])
        assert len(trees) == 1  # Only JavaScript

    def test_max_file_size(self, parser, temp_repo):
        """Should skip files over size limit."""
        # Create a large file
        large_content = "x = 1\n" * 100000  # ~600KB
        (temp_repo / "large.py").write_text(large_content)

        # Should include with high limit
        trees = parser.parse_repository(temp_repo, max_file_size_mb=10)
        assert any("large.py" in str(p) for p in trees.keys())

        # Should exclude with low limit
        trees = parser.parse_repository(temp_repo, max_file_size_mb=0.001)
        assert not any("large.py" in str(p) for p in trees.keys())


class TestSupportedLanguages:
    """Test supported languages queries."""

    @pytest.fixture
    def parser(self):
        return TreeSitterParser()

    def test_get_supported_languages(self, parser):
        """Should return set of supported languages."""
        languages = parser.get_supported_languages()
        assert "python" in languages
        assert "javascript" in languages
        assert "typescript" in languages
        assert "c" in languages
        assert "cpp" in languages
        assert "java" in languages
        assert "go" in languages

    def test_get_extensions_for_language(self, parser):
        """Should return extensions for a language."""
        python_exts = parser.get_extensions_for_language("python")
        assert ".py" in python_exts
        assert ".pyi" in python_exts

        js_exts = parser.get_extensions_for_language("javascript")
        assert ".js" in js_exts
        assert ".jsx" in js_exts


class TestASTNodeAccess:
    """Test accessing AST node structure."""

    @pytest.fixture
    def parser(self):
        return TreeSitterParser()

    def test_access_root_node(self, parser):
        """Should be able to access root node."""
        tree = parser.parse_string("def foo(): pass", "python")
        root = tree.root_node
        assert root is not None
        assert root.type == "module"

    def test_access_children(self, parser):
        """Should be able to access child nodes."""
        tree = parser.parse_string("def foo(): pass", "python")
        root = tree.root_node
        assert len(root.children) > 0
        # First child should be function_definition
        func_def = root.children[0]
        assert func_def.type == "function_definition"

    def test_access_node_text(self, parser):
        """Should be able to extract node text."""
        code = "def foo(): pass"
        tree = parser.parse_string(code, "python")
        root = tree.root_node
        func_def = root.children[0]
        # Get function name
        for child in func_def.children:
            if child.type == "identifier":
                assert child.text.decode("utf-8") == "foo"
                break

    def test_node_position(self, parser):
        """Should have correct node positions."""
        code = "def foo():\n    pass"
        tree = parser.parse_string(code, "python")
        func_def = tree.root_node.children[0]
        assert func_def.start_point[0] == 0  # Line 0
        assert func_def.start_point[1] == 0  # Column 0
