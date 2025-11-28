# Expected Security Findings

This document lists all intentional vulnerabilities in the test application
that Cerberus SAST should detect.

## Summary

| CWE | Vulnerability Type | Count |
|-----|-------------------|-------|
| CWE-89 | SQL Injection | 12 |
| CWE-78 | OS Command Injection | 8 |
| CWE-79 | Cross-Site Scripting (XSS) | 2 |
| CWE-22 | Path Traversal | 6 |
| CWE-798 | Hardcoded Credentials | 8 |
| CWE-502 | Insecure Deserialization | 5 |
| CWE-327 | Broken Cryptography | 4 |
| CWE-94 | Code Injection | 3 |
| **Total** | | **48** |

---

## app.py

### CWE-89: SQL Injection
1. `get_user()` - Line ~45: `f"SELECT * FROM users WHERE id = '{user_id}'"`
2. `search_users()` - Line ~58: String concatenation in SQL LIKE query
3. `UserManager.authenticate()` - Line ~145: Auth bypass via SQL injection

### CWE-78: OS Command Injection
1. `ping_host()` - Line ~68: `os.system(f"ping -c 1 {host}")`
2. `dns_lookup()` - Line ~77: `subprocess.check_output(f"nslookup {domain}")`
3. `UserManager.execute_command()` - Line ~155: `os.popen(cmd).read()`

### CWE-79: Cross-Site Scripting
1. `greet()` - Line ~83: `f"<h1>Hello, {name}!</h1>"`
2. `profile()` - Line ~92: User bio in render_template_string

### CWE-22: Path Traversal
1. `download_file()` - Line ~106: Unsanitized filename in os.path.join
2. `view_log()` - Line ~119: User-controlled log path

### CWE-798: Hardcoded Credentials
1. Line ~23: `DATABASE_PASSWORD = "super_secret_password_123"`
2. Line ~24: `API_KEY = "sk-1234567890abcdef..."`
3. Line ~25-26: `ADMIN_USER` and `ADMIN_PASS`
4. `UserManager.__init__()` - Line ~142: `db_password` and `admin_token`

### CWE-502: Insecure Deserialization
1. `load_data()` - Line ~127: `pickle.loads(data)`
2. `load_session()` - Line ~136: `pickle.loads(decoded)`

---

## database.py

### CWE-89: SQL Injection
1. `find_user_by_email()` - Line ~41: `% email` string formatting
2. `update_user_status()` - Line ~52: f-string in UPDATE
3. `delete_user()` - Line ~62: String concatenation in DELETE
4. `create_user()` - Line ~72: f-string in INSERT
5. `get_users_sorted()` - Line ~82: User-controlled ORDER BY
6. `search_products()` - Line ~92: Multiple injection points
7. `log_user_action()` - Line ~102: First-order injection
8. `replay_actions()` - Line ~113: Second-order injection
9. `SessionManager.validate_session()` - Line ~130: Token in SQL

### CWE-798: Hardcoded Credentials
1. Line ~18-24: `DB_CONFIG` with password
2. Line ~27: `ENCRYPTION_KEY`
3. `Database.__init__()` - Line ~35: `admin_password`
4. `SessionManager` - Line ~124: `SECRET_KEY`

---

## utils.py

### CWE-78: OS Command Injection
1. `SystemUtils.run_command()` - Line ~19: `os.popen(cmd).read()`
2. `SystemUtils.check_host()` - Line ~24: `subprocess.run` with shell=True
3. `SystemUtils.get_file_info()` - Line ~33: `subprocess.check_output`
4. `SystemUtils.compress_file()` - Line ~39: `os.system(f"tar...")`
5. `SystemUtils.process_image()` - Line ~44: `subprocess.call` with shell
6. `SystemUtils.backup_database()` - Line ~51: `os.system` with password

### CWE-22: Path Traversal
1. `FileManager.read_file()` - Line ~59: `os.path.join` without validation
2. `FileManager.write_file()` - Line ~65: f-string path
3. `FileManager.delete_file()` - Line ~71: String concatenation path
4. `FileManager.list_directory()` - Line ~77: User-controlled directory
5. `FileManager.copy_file()` - Line ~83: Both paths user-controlled

### CWE-502: Insecure Deserialization
1. `DataSerializer.load_object()` - Line ~94: `pickle.loads(data)`
2. `DataSerializer.load_from_file()` - Line ~99: `pickle.load(f)`
3. `DataSerializer.load_base64_object()` - Line ~105: decode + pickle.loads
4. `DataSerializer.load_session()` - Line ~111: session deserialization

### CWE-327: Broken Cryptography
1. `CryptoUtils.hash_password_md5()` - Line ~120: MD5 hash
2. `CryptoUtils.hash_password_sha1()` - Line ~125: SHA1 hash
3. `CryptoUtils.simple_encrypt()` - Line ~130: XOR "encryption"
4. `CryptoUtils.generate_token()` - Line ~138: random instead of secrets

### CWE-94: Code Injection
1. `CodeExecutor.evaluate()` - Line ~147: `eval(expression)`
2. `CodeExecutor.execute()` - Line ~152: `exec(code)`
3. `CodeExecutor.compile_and_run()` - Line ~157: compile + exec

---

## Validation Criteria

A successful Cerberus SAST V1 validation should:

1. **Detection Rate**: Identify >= 80% of vulnerabilities (39/48)
2. **False Positive Rate**: < 5% false positives
3. **Severity Accuracy**: Correctly classify severity levels
4. **Trace Quality**: Provide accurate source-to-sink traces

## Expected Output Files

- `reports/v1_validation/findings.json` - Detailed JSON findings
- `reports/v1_validation/findings.sarif` - SARIF 2.1.0 format
- `reports/v1_validation/report.html` - Interactive HTML report
- `reports/v1_validation/report.md` - Markdown summary
