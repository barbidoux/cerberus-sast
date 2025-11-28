"""
Utility functions with command injection and file handling vulnerabilities.

Contains:
- CWE-78: OS Command Injection
- CWE-22: Path Traversal
- CWE-502: Insecure Deserialization
- CWE-327: Broken Cryptography
"""

import os
import pickle
import subprocess
import hashlib
import base64
from typing import Any, Optional


# CWE-78: Command Injection variants
class SystemUtils:
    """System utilities with command injection vulnerabilities."""

    @staticmethod
    def run_command(cmd: str) -> str:
        """Execute shell command - VULNERABLE."""
        # VULNERABLE: Direct command execution
        return os.popen(cmd).read()

    @staticmethod
    def check_host(hostname: str) -> bool:
        """Check if host is reachable - VULNERABLE."""
        # VULNERABLE: User input in subprocess with shell=True
        result = subprocess.run(
            f"ping -c 1 {hostname}",
            shell=True,
            capture_output=True,
        )
        return result.returncode == 0

    @staticmethod
    def get_file_info(filepath: str) -> str:
        """Get file information - VULNERABLE."""
        # VULNERABLE: User input in command
        output = subprocess.check_output(f"ls -la {filepath}", shell=True)
        return output.decode()

    @staticmethod
    def compress_file(filename: str, archive_name: str) -> None:
        """Compress file - VULNERABLE."""
        # VULNERABLE: Multiple injection points
        os.system(f"tar -czf {archive_name} {filename}")

    @staticmethod
    def process_image(image_path: str, output_path: str) -> None:
        """Process image with ImageMagick - VULNERABLE."""
        # VULNERABLE: Command injection via filename
        subprocess.call(
            f"convert {image_path} -resize 100x100 {output_path}",
            shell=True,
        )

    @staticmethod
    def backup_database(db_name: str, backup_path: str) -> None:
        """Backup database - VULNERABLE."""
        # VULNERABLE: User-controlled database name in command
        cmd = f"mysqldump -u root -p'password' {db_name} > {backup_path}"
        os.system(cmd)


# CWE-22: Path Traversal variants
class FileManager:
    """File management with path traversal vulnerabilities."""

    BASE_PATH = "/var/www/uploads"

    def read_file(self, filename: str) -> str:
        """Read file content - VULNERABLE."""
        # VULNERABLE: No path validation
        path = os.path.join(self.BASE_PATH, filename)
        with open(path, "r") as f:
            return f.read()

    def write_file(self, filename: str, content: str) -> None:
        """Write file content - VULNERABLE."""
        # VULNERABLE: Path traversal in write operation
        path = f"{self.BASE_PATH}/{filename}"
        with open(path, "w") as f:
            f.write(content)

    def delete_file(self, filename: str) -> bool:
        """Delete file - VULNERABLE."""
        # VULNERABLE: No validation before delete
        filepath = self.BASE_PATH + "/" + filename
        os.remove(filepath)
        return True

    def list_directory(self, subdir: str) -> list:
        """List directory contents - VULNERABLE."""
        # VULNERABLE: User-controlled directory path
        dir_path = os.path.join(self.BASE_PATH, subdir)
        return os.listdir(dir_path)

    def copy_file(self, source: str, dest: str) -> None:
        """Copy file - VULNERABLE."""
        # VULNERABLE: Both source and dest are user-controlled
        import shutil
        src_path = os.path.join(self.BASE_PATH, source)
        dst_path = os.path.join(self.BASE_PATH, dest)
        shutil.copy(src_path, dst_path)


# CWE-502: Insecure Deserialization variants
class DataSerializer:
    """Data serialization with deserialization vulnerabilities."""

    @staticmethod
    def load_object(data: bytes) -> Any:
        """Load pickled object - VULNERABLE."""
        # VULNERABLE: Deserializing untrusted data
        return pickle.loads(data)

    @staticmethod
    def load_from_file(filepath: str) -> Any:
        """Load object from file - VULNERABLE."""
        # VULNERABLE: Loading pickle from file
        with open(filepath, "rb") as f:
            return pickle.load(f)

    @staticmethod
    def load_base64_object(encoded: str) -> Any:
        """Load base64-encoded pickle - VULNERABLE."""
        # VULNERABLE: Decoding and deserializing user input
        data = base64.b64decode(encoded)
        return pickle.loads(data)

    @staticmethod
    def load_session(session_data: str) -> dict:
        """Load session from string - VULNERABLE."""
        # VULNERABLE: Deserializing session data
        decoded = base64.b64decode(session_data)
        return pickle.loads(decoded)


# CWE-327: Broken Cryptography
class CryptoUtils:
    """Cryptographic utilities with weak implementations."""

    @staticmethod
    def hash_password_md5(password: str) -> str:
        """Hash password with MD5 - VULNERABLE."""
        # VULNERABLE: MD5 is cryptographically broken
        return hashlib.md5(password.encode()).hexdigest()

    @staticmethod
    def hash_password_sha1(password: str) -> str:
        """Hash password with SHA1 - VULNERABLE."""
        # VULNERABLE: SHA1 is cryptographically weak
        return hashlib.sha1(password.encode()).hexdigest()

    @staticmethod
    def simple_encrypt(data: str, key: str) -> str:
        """Simple XOR encryption - VULNERABLE."""
        # VULNERABLE: XOR is not secure encryption
        result = []
        for i, char in enumerate(data):
            result.append(chr(ord(char) ^ ord(key[i % len(key)])))
        return "".join(result)

    @staticmethod
    def generate_token() -> str:
        """Generate authentication token - VULNERABLE."""
        import random
        # VULNERABLE: Using random instead of secrets
        return str(random.randint(100000, 999999))


# CWE-94: Code Injection
class CodeExecutor:
    """Code execution utilities - VULNERABLE."""

    @staticmethod
    def evaluate(expression: str) -> Any:
        """Evaluate expression - VULNERABLE."""
        # VULNERABLE: eval with user input
        return eval(expression)

    @staticmethod
    def execute(code: str) -> None:
        """Execute code - VULNERABLE."""
        # VULNERABLE: exec with user input
        exec(code)

    @staticmethod
    def compile_and_run(code: str) -> Any:
        """Compile and run code - VULNERABLE."""
        # VULNERABLE: Compiling and executing user code
        compiled = compile(code, "<string>", "exec")
        exec(compiled)


def unsafe_yaml_load(yaml_string: str) -> Any:
    """Load YAML unsafely - VULNERABLE."""
    import yaml
    # VULNERABLE: yaml.load without safe_load
    return yaml.load(yaml_string, Loader=yaml.Loader)


def format_string(template: str, **kwargs) -> str:
    """Format string - VULNERABLE to format string attacks."""
    # VULNERABLE: User-controlled format string
    return template.format(**kwargs)
