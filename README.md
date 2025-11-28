# Cerberus SAST

**AI-Driven Static Application Security Testing with Neuro-Symbolic Pipeline**

[![CI](https://github.com/cerberus-sast/cerberus/workflows/CI/badge.svg)](https://github.com/cerberus-sast/cerberus/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![V1 Validated](https://img.shields.io/badge/V1-Validated-green.svg)](reports/V1_VALIDATION_REPORT.md)

Cerberus is a next-generation static application security testing (SAST) tool that combines the precision of Code Property Graph (CPG) analysis with the semantic understanding of Large Language Models (LLMs). It achieves high accuracy through its innovative **Neuro-Symbolic Self-Configuring Pipeline (NSSCP)**.

## V1 Status: Validated

Cerberus V1 has been validated on November 28, 2025. The system successfully detected **18 vulnerabilities** in a deliberately vulnerable Python application:

| Metric | Value |
|--------|-------|
| Files Scanned | 4 |
| Lines Analyzed | 662 |
| Findings | 18 (12 CRITICAL, 6 HIGH) |
| Scan Duration | ~31 seconds |
| Vulnerability Types | CWE-78, CWE-89, CWE-94, CWE-22 |

See the full [V1 Validation Report](reports/V1_VALIDATION_REPORT.md) for details.

## Key Features

- **Self-Configuring**: Automatically infers sources, sinks, and sanitizers without manual rule writing
- **Neuro-Symbolic Analysis**: Combines LLM reasoning with CPG graph precision
- **Multi-Agent Verification**: Attacker/Defender/Judge council validates each finding
- **Feedback Loop**: Verification results improve detection through iterative refinement
- **Local-First**: Runs entirely on local infrastructure (Ollama) for data sovereignty
- **Multiple Output Formats**: JSON, SARIF 2.1.0, HTML, Markdown, Console

## Architecture

Cerberus implements a 4-phase pipeline:

```
Phase I: Context          Phase II: Inference      Phase III: Detection    Phase IV: Verification
   |                           |                         |                        |
   v                           v                         v                        v
+-------------+           +-------------+           +-------------+          +-------------+
| Repository  |    -->    |    Spec     |    -->    |   Hybrid    |    -->   |  Multi-Agent|
|   Mapper    |           |  Inference  |           |   Engine    |          |   Council   |
+-------------+           +-------------+           +-------------+          +-------------+
                               ^                                                   |
                               |                                                   |
                               +<---------  Feedback Loop  <-----------------------+
```

| Phase | Function | Technology |
|-------|----------|------------|
| I. Context | Structural map of codebase | Tree-sitter, PageRank |
| II. Inference | Identify Sources/Sinks/Sanitizers | LLM (DeepSeek/Qwen), Few-Shot CoT |
| III. Detection | Taint analysis via CPG queries | Joern v4.0.450 (CPGQL) |
| IV. Verification | Filter false positives | Multi-Agent Council |

## Quick Start

### Installation

```bash
# Install from source
git clone https://github.com/cerberus-sast/cerberus
cd cerberus
pip install -e ".[dev]"
```

### Start Joern Server

```bash
# Using Docker (recommended for CI/CD)
docker-compose -f docker-compose.joern.yml up -d

# Or run Joern directly (native installation)
export JAVA_HOME=/path/to/jdk-17
./joern --server --server-host 0.0.0.0 --server-port 8080
```

### Configure Cerberus

Create `~/.cerberus/config.yml`:

```yaml
llm:
  default_provider: ollama
  ollama:
    base_url: "http://localhost:11434"
    model: "deepseek-coder-v2:16b-lite-instruct-q4_K_M"
    timeout: 120

joern:
  endpoint: "localhost:8080"
  timeout: 300

verification:
  enabled: true
  confidence_threshold: 0.7
```

### Run a Scan

```bash
# Basic scan
cerberus scan /path/to/repository

# With specific output formats
cerberus scan /path/to/repository --format sarif --format json --output-dir ./results

# Scan with minimum severity filter
cerberus scan /path/to/repository --min-severity HIGH
```

### Example Output

```
╔═════════════════════════════════════════════════════════════════════╗
║   ██████╗███████╗██████╗ ██████╗ ███████╗██████╗ ██╗   ██╗███████╗  ║
║  ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██║   ██║██╔════╝  ║
║  ██║     █████╗  ██████╔╝██████╔╝█████╗  ██████╔╝██║   ██║███████╗  ║
║  ██║     ██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██╗██║   ██║╚════██║  ║
║  ╚██████╗███████╗██║  ██║██████╔╝███████╗██║  ██║╚██████╔╝███████║  ║
║   ╚═════╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝  ║
║                                                                     ║
║  Neuro-Symbolic Self-Configuring Security Scanner                   ║
╚═════════════════════════════════════════════════════════════════════╝

Findings: 18
┏━━━━━━━━━━┳━━━━━━━┓
┃ Severity ┃ Count ┃
┡━━━━━━━━━━╇━━━━━━━┩
│ CRITICAL │ 12    │
│ HIGH     │ 6     │
└──────────┴───────┘
```

## Configuration

### Configuration Hierarchy

1. Environment variables (`CERBERUS_LLM__ANTHROPIC__API_KEY`)
2. Project config (`.cerberus.yml` in project root)
3. User config (`~/.cerberus/config.yml`)
4. Default values

### Full Configuration Example

See [examples/cerberus.example.yml](examples/cerberus.example.yml) for a complete configuration template.

```yaml
# .cerberus.yml
project_name: "my-project"

llm:
  default_provider: ollama  # ollama, anthropic, openai
  ollama:
    base_url: "http://localhost:11434"
    model: "deepseek-coder-v2:16b-lite-instruct-q4_K_M"

joern:
  endpoint: "localhost:8080"
  timeout: 300

verification:
  enabled: true
  council_mode: true
  confidence_threshold: 0.7
  max_iterations: 3

analysis:
  languages:
    - auto
  exclude_patterns:
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/.git/**"

reporting:
  formats:
    - sarif
    - json
    - html
  output_dir: "./cerberus-results"
```

## CI/CD Integration

### GitHub Actions

Add `ANTHROPIC_API_KEY` to your repository secrets, then use the workflow:

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  cerberus:
    runs-on: ubuntu-latest
    services:
      joern:
        image: joernio/joern:latest
        ports: ["8080:8080"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install cerberus-sast
      - run: cerberus scan . --format sarif --output-dir ./results
        env:
          CERBERUS_LLM__ANTHROPIC__API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ./results/cerberus-results.sarif
```

See [.github/workflows/cerberus-scan.yml](.github/workflows/cerberus-scan.yml) for a complete workflow.

### GitLab CI

See [.gitlab-ci.example.yml](.gitlab-ci.example.yml) for GitLab CI configuration.

## Output Formats

| Format | Use Case | Command |
|--------|----------|---------|
| SARIF | IDE integration, GitHub Security | `--format sarif` |
| JSON | Programmatic processing | `--format json` |
| HTML | Human-readable reports | `--format html` |
| Markdown | PR comments, documentation | `--format markdown` |
| Console | Terminal output | (default) |

## Supported Vulnerability Types

| CWE | Name | Severity |
|-----|------|----------|
| CWE-78 | OS Command Injection | CRITICAL |
| CWE-89 | SQL Injection | HIGH |
| CWE-94 | Code Injection | CRITICAL |
| CWE-22 | Path Traversal | HIGH |

## Hardware Requirements

| Configuration | RAM | GPU VRAM | Notes |
|---------------|-----|----------|-------|
| Minimum | 32GB | 12GB | RTX 4070, 4-bit 14B models |
| Recommended | 64GB | 24GB | RTX 3090/4090, DeepSeek Coder V2 |
| Optimal | 128GB | 48GB+ | Apple M2/M3 Ultra or dual-GPU |

## Supported Languages

Currently validated:
- Python

Planned support:
- JavaScript/TypeScript
- Java
- Go
- C/C++

## Development

### Setup

```bash
git clone https://github.com/cerberus-sast/cerberus
cd cerberus
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Running Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=cerberus

# Integration tests (requires Joern)
pytest -m integration
```

### Code Quality

```bash
black cerberus tests
ruff check cerberus tests
mypy cerberus
```

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture and component details
- [SPECIFICATIONS.md](SPECIFICATIONS.md) - Research and theoretical foundations
- [V1 Validation Report](reports/V1_VALIDATION_REPORT.md) - V1 test results
- [Test Report](reports/TEST_REPORT.md) - Detailed test analysis

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Joern](https://joern.io/) - Code Property Graph analysis
- [Tree-sitter](https://tree-sitter.github.io/) - Incremental parsing
- [Ollama](https://ollama.ai/) - Local LLM inference
- [DeepSeek](https://www.deepseek.com/) - DeepSeek Coder V2 model
