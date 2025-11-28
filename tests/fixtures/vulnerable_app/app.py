"""
Vulnerable Flask Application for Cerberus SAST V1 Validation Testing.

This application intentionally contains security vulnerabilities:
- CWE-89: SQL Injection
- CWE-78: OS Command Injection
- CWE-79: Cross-Site Scripting (XSS)
- CWE-22: Path Traversal
- CWE-798: Hardcoded Credentials
- CWE-502: Insecure Deserialization

DO NOT DEPLOY THIS APPLICATION IN PRODUCTION.
"""

import os
import pickle
import sqlite3
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)

# CWE-798: Hardcoded Credentials
DATABASE_PASSWORD = "super_secret_password_123"
API_KEY = "sk-1234567890abcdef1234567890abcdef"
ADMIN_USER = "admin"
ADMIN_PASS = "admin123"


def get_db_connection():
    """Get database connection."""
    conn = sqlite3.connect("users.db")
    return conn


@app.route("/")
def index():
    """Home page."""
    return "<h1>Vulnerable Test Application</h1>"


# CWE-89: SQL Injection
@app.route("/user")
def get_user():
    """Get user by ID - VULNERABLE to SQL Injection."""
    user_id = request.args.get("id", "")

    conn = get_db_connection()
    cursor = conn.cursor()

    # VULNERABLE: Direct string interpolation in SQL query
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)

    user = cursor.fetchone()
    conn.close()

    if user:
        return f"User: {user[1]}"
    return "User not found"


# CWE-89: Another SQL Injection variant
@app.route("/search")
def search_users():
    """Search users - VULNERABLE to SQL Injection."""
    name = request.args.get("name", "")

    conn = get_db_connection()
    cursor = conn.cursor()

    # VULNERABLE: String concatenation in SQL query
    query = "SELECT * FROM users WHERE name LIKE '%" + name + "%'"
    cursor.execute(query)

    users = cursor.fetchall()
    conn.close()

    return str(users)


# CWE-78: OS Command Injection
@app.route("/ping")
def ping_host():
    """Ping a host - VULNERABLE to Command Injection."""
    host = request.args.get("host", "localhost")

    # VULNERABLE: User input directly in shell command
    result = os.system(f"ping -c 1 {host}")

    return f"Ping result: {result}"


# CWE-78: Another Command Injection variant
@app.route("/lookup")
def dns_lookup():
    """DNS lookup - VULNERABLE to Command Injection."""
    domain = request.args.get("domain", "")

    # VULNERABLE: User input in subprocess command
    output = subprocess.check_output(f"nslookup {domain}", shell=True)

    return output.decode()


# CWE-79: Reflected XSS
@app.route("/greet")
def greet():
    """Greet user - VULNERABLE to XSS."""
    name = request.args.get("name", "Guest")

    # VULNERABLE: User input directly in HTML response
    return f"<h1>Hello, {name}!</h1>"


# CWE-79: Stored XSS via template
@app.route("/profile")
def profile():
    """User profile - VULNERABLE to XSS."""
    bio = request.args.get("bio", "")

    # VULNERABLE: User input rendered in template without escaping
    template = f"""
    <html>
    <head><title>Profile</title></head>
    <body>
        <h1>User Profile</h1>
        <div class="bio">{bio}</div>
    </body>
    </html>
    """
    return render_template_string(template)


# CWE-22: Path Traversal
@app.route("/download")
def download_file():
    """Download file - VULNERABLE to Path Traversal."""
    filename = request.args.get("file", "")

    # VULNERABLE: No path sanitization
    filepath = os.path.join("/var/www/files", filename)

    try:
        with open(filepath, "r") as f:
            content = f.read()
        return content
    except FileNotFoundError:
        return "File not found"


# CWE-22: Another Path Traversal variant
@app.route("/view")
def view_log():
    """View log file - VULNERABLE to Path Traversal."""
    log_name = request.args.get("log", "app.log")

    # VULNERABLE: User-controlled path without validation
    log_path = f"/var/log/{log_name}"

    with open(log_path, "r") as f:
        return f.read()


# CWE-502: Insecure Deserialization
@app.route("/load", methods=["POST"])
def load_data():
    """Load serialized data - VULNERABLE to Insecure Deserialization."""
    data = request.get_data()

    # VULNERABLE: Deserializing untrusted data
    obj = pickle.loads(data)

    return f"Loaded object: {obj}"


# CWE-502: Another Deserialization variant
@app.route("/session")
def load_session():
    """Load session from cookie - VULNERABLE to Insecure Deserialization."""
    import base64

    session_data = request.cookies.get("session", "")

    if session_data:
        # VULNERABLE: Deserializing user-controlled session data
        decoded = base64.b64decode(session_data)
        session = pickle.loads(decoded)
        return f"Session: {session}"

    return "No session"


# Additional vulnerability: Weak password hash
def hash_password(password):
    """Hash password - VULNERABLE: Using MD5."""
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()


# Additional vulnerability: Debug mode enabled
def init_app():
    """Initialize application with insecure settings."""
    # VULNERABLE: Debug mode in production
    app.debug = True
    app.secret_key = "development_key"


class UserManager:
    """User management class with vulnerabilities."""

    def __init__(self):
        # CWE-798: Hardcoded credentials in class
        self.db_password = "mysql_password_2024"
        self.admin_token = "token_abc123xyz"

    def authenticate(self, username, password):
        """Authenticate user - VULNERABLE to SQL Injection."""
        conn = get_db_connection()
        cursor = conn.cursor()

        # VULNERABLE: SQL Injection in authentication
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        cursor.execute(query)

        user = cursor.fetchone()
        conn.close()

        return user is not None

    def execute_command(self, cmd):
        """Execute system command - VULNERABLE to Command Injection."""
        # VULNERABLE: Executing user-provided command
        return os.popen(cmd).read()


if __name__ == "__main__":
    init_app()
    app.run(host="0.0.0.0", port=5000)
