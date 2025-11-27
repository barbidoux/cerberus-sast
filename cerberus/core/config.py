"""
Hierarchical configuration management for Cerberus SAST.

Configuration priority (highest to lowest):
1. CLI arguments
2. Environment variables (CERBERUS_*)
3. Project config (.cerberus.yml)
4. User config (~/.cerberus/config.yml)
5. Default values
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class OllamaConfig(BaseModel):
    """Configuration for Ollama LLM provider."""

    base_url: str = "http://localhost:11434"
    model: str = "qwen2.5-coder:32b"
    timeout: int = 120
    context_length: int = 32768


class AnthropicConfig(BaseModel):
    """Configuration for Anthropic Claude provider."""

    api_key: Optional[str] = None
    model: str = "claude-sonnet-4-20250514"
    timeout: int = 60
    max_tokens: int = 4096


class OpenAIConfig(BaseModel):
    """Configuration for OpenAI GPT provider."""

    api_key: Optional[str] = None
    model: str = "gpt-4-turbo"
    timeout: int = 60
    max_tokens: int = 4096


class LLMConfig(BaseModel):
    """Configuration for LLM gateway and providers."""

    default_provider: str = "ollama"
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    anthropic: AnthropicConfig = Field(default_factory=AnthropicConfig)
    openai: OpenAIConfig = Field(default_factory=OpenAIConfig)
    retry_max_attempts: int = 3
    retry_backoff_factor: float = 2.0
    cache_enabled: bool = True
    cache_ttl: int = 3600

    @field_validator("default_provider")
    @classmethod
    def validate_provider(cls, v: str) -> str:
        """Validate default provider is supported."""
        valid_providers = {"ollama", "anthropic", "openai"}
        if v not in valid_providers:
            raise ValueError(f"Invalid provider: {v}. Must be one of {valid_providers}")
        return v


class JoernConfig(BaseModel):
    """Configuration for Joern CPG analysis."""

    endpoint: str = "localhost:8080"
    workspace: Path = Path("./.cerberus/workspace")
    docker_image: str = "joernio/joern:latest"
    memory_limit: str = "8g"
    timeout: int = 300
    auto_start: bool = True

    @field_validator("workspace", mode="before")
    @classmethod
    def validate_workspace(cls, v: Any) -> Path:
        """Ensure workspace is a Path."""
        if isinstance(v, str):
            return Path(v)
        return v


class VerificationConfig(BaseModel):
    """Configuration for Phase IV verification."""

    enabled: bool = True
    council_mode: bool = True
    confidence_threshold: float = 0.7
    max_iterations: int = 3
    timeout_per_finding: int = 60

    @field_validator("confidence_threshold")
    @classmethod
    def validate_threshold(cls, v: float) -> float:
        """Validate confidence threshold is in valid range."""
        if not 0.0 <= v <= 1.0:
            raise ValueError("confidence_threshold must be between 0.0 and 1.0")
        return v


class AnalysisConfig(BaseModel):
    """Configuration for code analysis."""

    languages: list[str] = Field(default_factory=lambda: ["auto"])
    exclude_patterns: list[str] = Field(
        default_factory=lambda: [
            "**/node_modules/**",
            "**/vendor/**",
            "**/.git/**",
            "**/dist/**",
            "**/build/**",
            "**/__pycache__/**",
            "**/*.min.js",
            "**/*.min.css",
        ]
    )
    max_file_size_mb: int = 10
    max_files: int = 10000
    follow_symlinks: bool = False


class ReportingConfig(BaseModel):
    """Configuration for report generation."""

    formats: list[str] = Field(default_factory=lambda: ["sarif", "console"])
    output_dir: Path = Path("./cerberus-output")
    include_code_snippets: bool = True
    max_snippet_lines: int = 10
    sarif_version: str = "2.1.0"

    @field_validator("output_dir", mode="before")
    @classmethod
    def validate_output_dir(cls, v: Any) -> Path:
        """Ensure output_dir is a Path."""
        if isinstance(v, str):
            return Path(v)
        return v

    @field_validator("formats")
    @classmethod
    def validate_formats(cls, v: list[str]) -> list[str]:
        """Validate report formats."""
        valid_formats = {"sarif", "json", "html", "console", "markdown"}
        for fmt in v:
            if fmt not in valid_formats:
                raise ValueError(f"Invalid format: {fmt}. Must be one of {valid_formats}")
        return v


class SecurityConfig(BaseModel):
    """Security-related configuration."""

    allow_cloud_llm: bool = False
    redact_secrets: bool = True
    api_require_auth: bool = True
    api_token_expiry: int = 3600
    api_rate_limit: int = 100


class LoggingConfig(BaseModel):
    """Configuration for logging."""

    level: str = "INFO"
    file: Optional[Path] = None
    json_format: bool = False
    max_file_size_mb: int = 10
    backup_count: int = 5

    @field_validator("level")
    @classmethod
    def validate_level(cls, v: str) -> str:
        """Validate logging level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v_upper = v.upper()
        if v_upper not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return v_upper

    @field_validator("file", mode="before")
    @classmethod
    def validate_file(cls, v: Any) -> Optional[Path]:
        """Ensure file is a Path or None."""
        if v is None:
            return None
        if isinstance(v, str):
            return Path(v)
        return v


class CerberusConfig(BaseSettings):
    """
    Main configuration model with hierarchical loading.

    Loads configuration from:
    1. Default values (lowest priority)
    2. User config file (~/.cerberus/config.yml)
    3. Project config file (.cerberus.yml)
    4. Environment variables (CERBERUS_*)
    5. CLI arguments (highest priority)
    """

    model_config = SettingsConfigDict(
        env_prefix="CERBERUS_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # Project settings
    project_name: str = "cerberus-scan"
    output_dir: Path = Path("./cerberus-output")

    # Component configurations
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    joern: JoernConfig = Field(default_factory=JoernConfig)
    verification: VerificationConfig = Field(default_factory=VerificationConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    @field_validator("output_dir", mode="before")
    @classmethod
    def validate_output_dir(cls, v: Any) -> Path:
        """Ensure output_dir is a Path."""
        if isinstance(v, str):
            return Path(v)
        return v

    @classmethod
    def load(
        cls,
        cli_args: Optional[dict[str, Any]] = None,
        project_path: Optional[Path] = None,
    ) -> CerberusConfig:
        """
        Load configuration from multiple sources with priority.

        Args:
            cli_args: Command-line arguments (highest priority)
            project_path: Path to project directory for .cerberus.yml

        Returns:
            Merged configuration
        """
        config_dict: dict[str, Any] = {}
        project_path = project_path or Path.cwd()

        # 1. Load user config (~/.cerberus/config.yml)
        user_config_path = Path.home() / ".cerberus" / "config.yml"
        if user_config_path.exists():
            with open(user_config_path) as f:
                user_config = yaml.safe_load(f) or {}
                config_dict = _deep_merge(config_dict, user_config)

        # 2. Load project config (.cerberus.yml)
        project_config_path = project_path / ".cerberus.yml"
        if project_config_path.exists():
            with open(project_config_path) as f:
                project_config = yaml.safe_load(f) or {}
                config_dict = _deep_merge(config_dict, project_config)

        # 3. Apply environment variables (handled by pydantic-settings)
        # This happens automatically during model instantiation

        # 4. Apply CLI arguments (highest priority)
        if cli_args:
            cli_config = _flatten_cli_args(cli_args)
            config_dict = _deep_merge(config_dict, cli_config)

        # Handle environment variables for API keys
        if os.environ.get("ANTHROPIC_API_KEY"):
            config_dict.setdefault("llm", {}).setdefault("anthropic", {})[
                "api_key"
            ] = os.environ["ANTHROPIC_API_KEY"]
        if os.environ.get("OPENAI_API_KEY"):
            config_dict.setdefault("llm", {}).setdefault("openai", {})[
                "api_key"
            ] = os.environ["OPENAI_API_KEY"]

        return cls(**config_dict)

    def ensure_directories(self) -> None:
        """Create all required directories."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.joern.workspace.mkdir(parents=True, exist_ok=True)
        self.reporting.output_dir.mkdir(parents=True, exist_ok=True)
        if self.logging.file:
            self.logging.file.parent.mkdir(parents=True, exist_ok=True)

    def to_yaml(self, path: Path) -> None:
        """Write configuration to YAML file."""
        with open(path, "w") as f:
            yaml.dump(self.model_dump(mode="json"), f, default_flow_style=False, sort_keys=False)

    def get_effective_provider(self) -> str:
        """Get the effective LLM provider based on config and availability."""
        if self.security.allow_cloud_llm:
            return self.llm.default_provider
        # If cloud LLMs not allowed, force Ollama
        return "ollama"


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """
    Deep merge two dictionaries.

    Args:
        base: Base dictionary
        override: Dictionary with values to override

    Returns:
        Merged dictionary
    """
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _flatten_cli_args(args: dict[str, Any]) -> dict[str, Any]:
    """
    Convert flat CLI arguments to nested config structure.

    Examples:
        {"llm_provider": "ollama"} -> {"llm": {"default_provider": "ollama"}}
        {"output_format": "json"} -> {"reporting": {"formats": ["json"]}}
    """
    result: dict[str, Any] = {}

    # Map CLI args to config structure
    mappings = {
        "verbose": ("logging", "level", lambda v: "DEBUG" if v else "INFO"),
        "quiet": ("logging", "level", lambda v: "ERROR" if v else None),
        "output": ("reporting", "output_dir", Path),
        "format": ("reporting", "formats", lambda v: [v] if v else None),
        "output_format": ("reporting", "formats", lambda v: [v] if v else None),
        "languages": ("analysis", "languages", lambda v: v.split(",") if v else None),
        "exclude": ("analysis", "exclude_patterns", list),
        "no_verify": ("verification", "enabled", lambda v: not v),
        "council": ("verification", "council_mode", bool),
        "config": None,  # Handled separately
    }

    for key, value in args.items():
        if value is None:
            continue

        if key in mappings and mappings[key] is not None:
            section, subkey, transform = mappings[key]
            transformed = transform(value) if callable(transform) else value
            if transformed is not None:
                result.setdefault(section, {})[subkey] = transformed
        elif key not in mappings:
            # Direct assignment for unmapped keys
            result[key] = value

    return result


def get_default_config() -> CerberusConfig:
    """Get configuration with all defaults."""
    return CerberusConfig()


def validate_config(config: CerberusConfig) -> list[str]:
    """
    Validate configuration and return list of warnings.

    Returns:
        List of warning messages (empty if all valid)
    """
    warnings: list[str] = []

    # Check LLM provider availability
    if config.llm.default_provider == "anthropic" and not config.llm.anthropic.api_key:
        warnings.append("Anthropic selected but no API key configured")
    if config.llm.default_provider == "openai" and not config.llm.openai.api_key:
        warnings.append("OpenAI selected but no API key configured")

    # Check cloud LLM usage
    if config.llm.default_provider in ("anthropic", "openai") and not config.security.allow_cloud_llm:
        warnings.append(
            f"Cloud LLM '{config.llm.default_provider}' selected but allow_cloud_llm=False. "
            "Will fall back to Ollama."
        )

    # Check verification settings
    if config.verification.council_mode and not config.verification.enabled:
        warnings.append("Council mode enabled but verification disabled")

    return warnings
