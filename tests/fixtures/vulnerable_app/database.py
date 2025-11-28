"""
Database utilities with additional SQL injection vulnerabilities.

Contains:
- CWE-89: Multiple SQL Injection variants
- CWE-798: Hardcoded database credentials
- CWE-312: Cleartext storage of sensitive information
"""

import sqlite3
from typing import Any, Optional


# CWE-798: Hardcoded database credentials
DB_CONFIG = {
    "host": "localhost",
    "port": 3306,
    "user": "root",
    "password": "root_password_123!",
    "database": "vulnerable_app",
}

# CWE-312: Sensitive data in plaintext
ENCRYPTION_KEY = "aes256_secret_key_do_not_share"


class Database:
    """Database class with multiple SQL injection vulnerabilities."""

    def __init__(self, db_path: str = "app.db"):
        self.db_path = db_path
        # CWE-798: Hardcoded credentials
        self.admin_password = "supersecret"

    def connect(self):
        """Create database connection."""
        return sqlite3.connect(self.db_path)

    # CWE-89: SQL Injection in SELECT
    def find_user_by_email(self, email: str) -> Optional[tuple]:
        """Find user by email - VULNERABLE."""
        conn = self.connect()
        cursor = conn.cursor()

        # VULNERABLE: String formatting in SQL
        query = "SELECT id, name, email FROM users WHERE email = '%s'" % email
        cursor.execute(query)

        result = cursor.fetchone()
        conn.close()
        return result

    # CWE-89: SQL Injection in UPDATE
    def update_user_status(self, user_id: str, status: str) -> None:
        """Update user status - VULNERABLE."""
        conn = self.connect()
        cursor = conn.cursor()

        # VULNERABLE: f-string in SQL UPDATE
        query = f"UPDATE users SET status = '{status}' WHERE id = {user_id}"
        cursor.execute(query)

        conn.commit()
        conn.close()

    # CWE-89: SQL Injection in DELETE
    def delete_user(self, username: str) -> None:
        """Delete user by username - VULNERABLE."""
        conn = self.connect()
        cursor = conn.cursor()

        # VULNERABLE: String concatenation in SQL DELETE
        query = "DELETE FROM users WHERE username = '" + username + "'"
        cursor.execute(query)

        conn.commit()
        conn.close()

    # CWE-89: SQL Injection in INSERT
    def create_user(self, name: str, email: str, password: str) -> int:
        """Create new user - VULNERABLE."""
        conn = self.connect()
        cursor = conn.cursor()

        # VULNERABLE: Direct string interpolation in INSERT
        query = f"INSERT INTO users (name, email, password) VALUES ('{name}', '{email}', '{password}')"
        cursor.execute(query)

        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return user_id

    # CWE-89: SQL Injection in ORDER BY
    def get_users_sorted(self, sort_column: str) -> list:
        """Get users sorted by column - VULNERABLE."""
        conn = self.connect()
        cursor = conn.cursor()

        # VULNERABLE: User-controlled ORDER BY clause
        query = f"SELECT * FROM users ORDER BY {sort_column}"
        cursor.execute(query)

        results = cursor.fetchall()
        conn.close()
        return results

    # CWE-89: SQL Injection with LIKE
    def search_products(self, keyword: str, category: str) -> list:
        """Search products - VULNERABLE."""
        conn = self.connect()
        cursor = conn.cursor()

        # VULNERABLE: Multiple injection points
        query = f"SELECT * FROM products WHERE name LIKE '%{keyword}%' AND category = '{category}'"
        cursor.execute(query)

        results = cursor.fetchall()
        conn.close()
        return results

    # CWE-89: Second-order SQL Injection
    def log_user_action(self, user_id: int, action: str) -> None:
        """Log user action - Contains stored injection vulnerability."""
        conn = self.connect()
        cursor = conn.cursor()

        # First query stores the action (could be malicious SQL)
        cursor.execute(
            f"INSERT INTO action_log (user_id, action) VALUES ({user_id}, '{action}')"
        )

        conn.commit()
        conn.close()

    def replay_actions(self, user_id: int) -> None:
        """Replay user actions - VULNERABLE to second-order injection."""
        conn = self.connect()
        cursor = conn.cursor()

        # Get stored actions
        cursor.execute(f"SELECT action FROM action_log WHERE user_id = {user_id}")
        actions = cursor.fetchall()

        # VULNERABLE: Executing stored user data as SQL
        for action in actions:
            cursor.execute(action[0])

        conn.commit()
        conn.close()


class SessionManager:
    """Session management with vulnerabilities."""

    # CWE-798: Hardcoded session secret
    SECRET_KEY = "session_secret_key_123"

    def __init__(self):
        self.sessions = {}

    def validate_session(self, session_token: str) -> bool:
        """Validate session - VULNERABLE to SQL Injection."""
        db = Database()
        conn = db.connect()
        cursor = conn.cursor()

        # VULNERABLE: Session token in SQL query
        query = f"SELECT * FROM sessions WHERE token = '{session_token}' AND active = 1"
        cursor.execute(query)

        result = cursor.fetchone()
        conn.close()
        return result is not None


def raw_query(query: str, params: tuple = ()) -> list:
    """Execute raw SQL query - VULNERABLE by design."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # VULNERABLE: Executing arbitrary SQL
    cursor.execute(query)

    results = cursor.fetchall()
    conn.close()
    return results
