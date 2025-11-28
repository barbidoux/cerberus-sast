"""
Vulnerable Test Application for Cerberus SAST V1 Validation.

This package contains intentionally vulnerable Python code for testing
Cerberus SAST's detection capabilities.

Vulnerability Types:
- CWE-89: SQL Injection
- CWE-78: OS Command Injection
- CWE-79: Cross-Site Scripting (XSS)
- CWE-22: Path Traversal
- CWE-798: Hardcoded Credentials
- CWE-502: Insecure Deserialization
- CWE-327: Broken Cryptography
- CWE-94: Code Injection

WARNING: DO NOT DEPLOY IN PRODUCTION
"""

__version__ = "1.0.0"
__author__ = "Cerberus SAST Test Team"
