"""Pytest configuration and shared fixtures."""

import pytest
from pathlib import Path
import tempfile
import shutil


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    temp = tempfile.mkdtemp()
    yield Path(temp)
    shutil.rmtree(temp, ignore_errors=True)


@pytest.fixture
def sample_python_file(temp_dir):
    """Create a sample Python file for testing."""
    code = '''
def vulnerable_function(user_input):
    """A function with potential SQL injection."""
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return execute_query(query)


class UserController:
    """Controller for user operations."""

    def get_user(self, request):
        """Get user by ID from request."""
        user_id = request.params.get("id")
        return self.db.query(f"SELECT * FROM users WHERE id = {user_id}")

    def sanitize_input(self, value):
        """Sanitize user input."""
        return value.replace("'", "''").replace(";", "")
'''
    file_path = temp_dir / "sample.py"
    file_path.write_text(code)
    return file_path


@pytest.fixture
def sample_javascript_file(temp_dir):
    """Create a sample JavaScript file for testing."""
    code = '''
function processUserInput(req, res) {
    const userId = req.query.id;
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    db.query(query, (err, result) => {
        res.json(result);
    });
}

class AuthController {
    authenticate(username, password) {
        const query = "SELECT * FROM users WHERE username = '" + username + "'";
        return this.db.execute(query);
    }
}

module.exports = { processUserInput, AuthController };
'''
    file_path = temp_dir / "sample.js"
    file_path.write_text(code)
    return file_path


@pytest.fixture
def mock_llm_response():
    """Create a mock LLM response factory."""
    def _create_response(content: str, tokens: int = 100):
        return {
            "content": content,
            "model": "test-model",
            "provider": "mock",
            "tokens_used": tokens,
            "finish_reason": "stop",
        }
    return _create_response
