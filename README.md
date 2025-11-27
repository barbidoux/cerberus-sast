# Cerberus SAST

**AI-Driven Static Application Security Testing with Neuro-Symbolic Pipeline**

[![CI](https://github.com/cerberus-sast/cerberus/workflows/CI/badge.svg)](https://github.com/cerberus-sast/cerberus/actions)
[![codecov](https://codecov.io/gh/cerberus-sast/cerberus/branch/main/graph/badge.svg)](https://codecov.io/gh/cerberus-sast/cerberus)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Cerberus is a next-generation static application security testing (SAST) tool that combines the precision of Code Property Graph (CPG) analysis with the semantic understanding of Large Language Models (LLMs). It achieves **<5% false positive rates** through its innovative Neuro-Symbolic Self-Configuring Pipeline (NSSCP).

## Key Features

- **Self-Configuring**: Automatically infers sources, sinks, and sanitizers without manual rule writing
- **Neuro-Symbolic Analysis**: Combines LLM reasoning with CPG graph precision
- **Multi-Agent Verification**: Attacker/Defender/Judge council validates each finding
- **Feedback Loop**: Verification results improve detection through iterative refinement
- **Local-First**: Runs entirely on local infrastructure for data sovereignty
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
| II. Inference | Identify Sources/Sinks/Sanitizers | LLM (Qwen/DeepSeek), Joern |
| III. Detection | Taint analysis via CPG queries | Joern (CPGQL) |
| IV. Verification | Filter false positives | Multi-Agent Council |

## Quick Start

### Installation

```bash
# Install from PyPI
pip install cerberus-sast

# Or install from source
git clone https://github.com/cerberus-sast/cerberus
cd cerberus
pip install -e ".[dev]"
```

### Start Joern Server

```bash
# Using Docker (recommended)
docker-compose -f docker-compose.joern.yml up -d

# Or run Joern directly
joern --server --server-host 0.0.0.0 --server-port 8080
```

### Run a Scan

```bash
# Basic scan
cerberus scan /path/to/repository

# With specific output format
cerberus scan /path/to/repository --output sarif --output-file results.sarif

# With verification (requires LLM)
cerberus scan /path/to/repository --verify --llm-provider ollama

# Scan specific languages
cerberus scan /path/to/repository --languages python javascript
```

### Using the API

```bash
# Start the API server
cerberus api --host 0.0.0.0 --port 8000

# Or using Docker
docker-compose up -d
```

Then access the API at `http://localhost:8000`:

```bash
# Start a scan
curl -X POST http://localhost:8000/scans \
  -H "Content-Type: application/json" \
  -d '{"repository_path": "/path/to/repo"}'

# Check status
curl http://localhost:8000/scans/{scan_id}

# Get findings
curl http://localhost:8000/scans/{scan_id}/findings
```

## Configuration

Create a `.cerberus.yml` in your project root:

```yaml
# Languages to scan (auto-detected if not specified)
languages:
  - python
  - javascript
  - java

# Patterns to exclude
exclude:
  - "**/node_modules/**"
  - "**/venv/**"
  - "**/.git/**"

# Verification settings
verification:
  enabled: true
  min_confidence: 0.7

# Feedback loop settings
feedback:
  enabled: true
  max_iterations: 3  # Hard limit to prevent infinite loops

# LLM provider configuration
llm:
  provider: ollama  # ollama, anthropic, openai
  model: qwen2.5-coder:14b

# Output settings
output:
  formats:
    - json
    - sarif
  min_severity: medium
```

## Output Formats

### SARIF (Static Analysis Results Interchange Format)

Standard format for IDE integration and CI/CD pipelines:

```bash
cerberus scan /repo --output sarif --output-file results.sarif
```

### JSON

Detailed JSON output with full trace information:

```bash
cerberus scan /repo --output json --output-file results.json
```

### HTML

Interactive HTML report with styling:

```bash
cerberus scan /repo --output html --output-file report.html
```

### Markdown

GitHub-flavored markdown for PR comments:

```bash
cerberus scan /repo --output markdown --output-file report.md
```

## Baseline Management

Track and compare findings across scans:

```bash
# Create a baseline from a scan
cerberus baseline create --name v1.0 --scan-id abc123

# Compare new scan against baseline
cerberus baseline compare --name v1.0 --scan-id def456

# List baselines
cerberus baseline list
```

## Docker Deployment

### Full Stack

```bash
# Start Cerberus API + Joern
docker-compose up -d

# With Ollama for local LLM
docker-compose --profile llm up -d
```

### Joern Only

```bash
# For development with native Cerberus
docker-compose -f docker-compose.joern.yml up -d
```

## Development

### Setup

```bash
# Clone repository
git clone https://github.com/cerberus-sast/cerberus
cd cerberus

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install with dev dependencies
pip install -e ".[dev]"

# Start Joern for testing
docker-compose -f docker-compose.joern.yml up -d
```

### Running Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=cerberus

# Specific module
pytest tests/test_detection/

# Integration tests (requires Joern)
pytest -m integration
```

### Code Quality

```bash
# Format code
black cerberus tests

# Lint
ruff check cerberus tests

# Type check
mypy cerberus
```

## Hardware Requirements

| Configuration | RAM | GPU VRAM | Notes |
|---------------|-----|----------|-------|
| Minimum | 32GB | 12GB | RTX 4070, 4-bit 14B models |
| Recommended | 64GB | 24GB | RTX 3090/4090, Qwen 2.5 Coder 32B |
| Optimal | 128GB | 48GB+ | Apple M2/M3 Ultra or dual-GPU |

## Supported Languages

- Python
- JavaScript/TypeScript
- Java
- Go
- C/C++
- PHP
- Ruby
- Rust

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`pytest`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Joern](https://joern.io/) - Code Property Graph analysis
- [Tree-sitter](https://tree-sitter.github.io/) - Incremental parsing
- [Ollama](https://ollama.ai/) - Local LLM inference
