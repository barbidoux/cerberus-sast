# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cerberus SAST is a next-generation, local, AI-driven static application security testing tool. It implements a **Neuro-Symbolic Self-Configuring Pipeline (NSSCP)** that combines LLM semantic reasoning with Code Property Graph (CPG) precision.

**Current Status: V1 Validated** (November 28, 2025)
- 18 vulnerabilities detected in test application
- 4-phase pipeline operational
- CLI and reporting fully functional

### Core Philosophy

- **Self-Configuring**: Autonomously infers Sources, Sinks, and Sanitizers without manual rule writing
- **Neuro-Symbolic**: Fuses LLM reasoning (DeepSeek Coder V2, Qwen 2.5) with CPG graph analysis (Joern)
- **Agentic**: Uses verification loops where findings are hypotheses validated by reasoning agents
- **Local-First**: Runs entirely on local infrastructure (Ollama) for data sovereignty

## Architecture: The Four-Phase Pipeline

| Phase | Component | Function | Technology |
|-------|-----------|----------|------------|
| I. Context | Repository Mapper | Structural map of codebase | Tree-sitter, PageRank |
| II. Inference | Spec Inference Engine | Identify Sources/Sinks/Sanitizers | LLM (Few-Shot CoT), Joern |
| III. Detection | Hybrid Graph Engine | Taint analysis via CPG queries | Joern v4.0.450 (CPGQL) |
| IV. Verification | Reasoning Agent | Filter false positives | Multi-Agent Council |

### Key Components

```
cerberus/
├── cli/              # CLI commands (scan, etc.)
├── context/          # Phase I - Repository mapping
│   └── repo_mapper.py
├── inference/        # Phase II - Spec inference
│   ├── engine.py
│   ├── classifier.py
│   └── candidate_extractor.py
├── detection/        # Phase III - CPG-based detection
│   ├── engine.py
│   └── joern_client.py   # Async HTTP client for Joern
├── verification/     # Phase IV - LLM verification
│   └── engine.py
├── core/             # Orchestration and config
│   ├── orchestrator.py   # Main 4-phase coordinator
│   └── config.py         # YAML configuration loading
├── llm/              # LLM gateway with failover
│   └── gateway.py
├── models/           # Data models
│   ├── finding.py
│   ├── spec.py
│   └── repo_map.py
└── reporting/        # Output formatters
    └── formatters/
```

### Feedback Loop

The Verification Agent (Phase IV) feeds back to Spec Inference (Phase II). When a false positive is caused by a missed sanitizer, that function is added to the sanitizer list and detection reruns. Hard limit: 3 iterations.

## Technology Stack

```
Parser:          Tree-sitter (incremental parsing, Python bindings)
Graph Database:  Joern v4.0.450 (native or Docker)
LLM Inference:   Ollama (primary) → Anthropic → OpenAI (fallback chain)
Orchestrator:    Python 3.12 async
CLI:             Click + Rich (progress bars, tables)
```

## Key Technical Details

### Joern v4.0.450 Async API

Joern uses a UUID-based async HTTP API:
```python
# POST /query returns UUID
response = requests.post("http://localhost:8080/query", json={"query": "cpg.method.l"})
uuid = response.json()["uuid"]

# Poll GET /result/{uuid} for results
result = requests.get(f"http://localhost:8080/result/{uuid}")
```

See `cerberus/detection/joern_client.py` for the full implementation.

### Python CPG Limitations

Joern's Python frontend (pysrc2cpg) has limited support for inter-procedural data flow analysis. The detection engine compensates with **CPG-verified spec-based findings**:
1. Verify source/sink methods exist in CPG
2. Generate findings based on LLM semantic analysis
3. Trust LLM classification confidence scores

### Configuration Loading

Configuration hierarchy (highest priority first):
1. Environment variables (`CERBERUS_LLM__ANTHROPIC__API_KEY`)
2. Project config (`.cerberus.yml`)
3. User config (`~/.cerberus/config.yml`)
4. Default values

Key config sections:
- `llm`: Provider settings (ollama, anthropic, openai)
- `joern`: CPG server endpoint and timeout
- `verification`: Council mode, confidence thresholds
- `analysis`: Languages, exclude patterns
- `reporting`: Output formats and directory

## Documentation

- **[ARCHITECTURE.md](ARCHITECTURE.md)**: Complete system architecture
- **[SPECIFICATIONS.md](SPECIFICATIONS.md)**: Research and theoretical foundations
- **[reports/V1_VALIDATION_REPORT.md](reports/V1_VALIDATION_REPORT.md)**: V1 validation results
- **[reports/TEST_REPORT.md](reports/TEST_REPORT.md)**: Detailed test analysis

## Key Concepts

### Code Property Graph (CPG)
Unified graph combining:
- **AST**: Hierarchical code structure
- **CFG**: Execution order (paths, loops, conditions)
- **PDG**: Data flow and control dependencies

### Repository Map
Compressed codebase representation using:
1. Tree-sitter parsing for symbol extraction
2. Dependency graph construction (imports, calls, inheritance)
3. PageRank for file relevance scoring

### Dynamic Specification
Output of Phase II - a spec unique to each repository:
```json
{
  "sources": [{"method": "get_user", "file": "app.py", "line": 44}],
  "sinks": [{"method": "run_command", "file": "utils.py", "line": 24, "cwe": "CWE-78"}],
  "sanitizers": []
}
```

### LLM-as-Judge Verification
Structured Chain-of-Thought for each finding:
1. Trace Verification: Does tainted data actually reach the sink?
2. Sanitization Check: Is data modified by validation/encoding?
3. Logic Check: Do conditions prevent execution?
4. Verdict: True Positive or False Positive

## Test Fixtures

The `tests/fixtures/vulnerable_app/` directory contains a deliberately vulnerable Flask application:

| File | Lines | Vulnerabilities |
|------|-------|-----------------|
| app.py | ~250 | Command injection, code injection |
| utils.py | ~200 | Command execution, file operations |
| database.py | ~200 | SQL injection, unsafe queries |

## Build Commands

```bash
# Install dependencies
pip install -e ".[dev]"

# Start Joern (native)
export JAVA_HOME=/path/to/jdk-17
./joern --server --server-host 0.0.0.0 --server-port 8080

# Start Joern (Docker)
docker-compose -f docker-compose.joern.yml up -d

# Run scan
cerberus scan /path/to/code

# Run tests
pytest
pytest --cov=cerberus

# Linting
black cerberus tests
ruff check cerberus
mypy cerberus
```

## Hardware Requirements

- **Minimum**: 32GB RAM, 12GB VRAM GPU (RTX 4070) - runs 4-bit 14B models
- **Recommended**: 64GB RAM, 24GB VRAM GPU (RTX 3090/4090) - runs DeepSeek Coder V2 16B
- **Optimal**: Apple M2/M3 Ultra 128GB or dual-GPU workstation

## Development Guidelines

- Python 3.11+ required (3.12 recommended)
- Use Tree-sitter for all code parsing (not regex)
- CPG queries via Joern's CPGQL (Scala-based DSL)
- LLM prompts should use Few-Shot + Chain-of-Thought patterns
- All findings are hypotheses until verified by the Reasoning Agent
- Never exceed 3 feedback loop iterations (hard limit in orchestrator)
- Use async/await for all I/O operations
