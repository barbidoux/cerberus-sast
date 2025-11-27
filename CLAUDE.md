# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cerberus SAST is a next-generation, local, AI-driven static application security testing tool. It implements a **Neuro-Symbolic Self-Configuring Pipeline (NSSCP)** that combines LLM semantic reasoning with Code Property Graph (CPG) precision to achieve <5% false positive rates.

### Core Philosophy

- **Self-Configuring**: Autonomously infers Sources, Sinks, and Sanitizers without manual rule writing
- **Neuro-Symbolic**: Fuses LLM reasoning (Qwen 2.5 Coder, DeepSeek V2) with CPG graph analysis (Joern)
- **Agentic**: Uses verification loops where findings are hypotheses validated by reasoning agents
- **Local-First**: Runs entirely on local infrastructure for data sovereignty

## Architecture: The Four-Phase Pipeline

| Phase | Component | Function | Technology |
|-------|-----------|----------|------------|
| I. Context | Repository Mapper | Structural map of codebase | Tree-sitter, PageRank |
| II. Inference | Spec Inference Engine | Identify Sources/Sinks/Sanitizers | Qwen 2.5 Coder, Joern |
| III. Detection | Hybrid Graph Engine | Taint analysis via CPG queries | Joern (CPGQL), OverflowDB |
| IV. Verification | Reasoning Agent | Filter false positives | DeepSeek V2, LLMxCPG |

### Feedback Loop

The Verification Agent (Phase IV) feeds back to Spec Inference (Phase II). When a false positive is caused by a missed sanitizer, that function is added to the sanitizer list and detection reruns.

## Technology Stack

```
Parser:          Tree-sitter (incremental parsing, Python bindings)
Graph Database:  Joern via Docker (CPG: AST + CFG + PDG)
LLM Inference:   Ollama (primary) → Anthropic → OpenAI (fallback chain)
Vector Store:    ChromaDB (code embeddings for RAG)
Orchestrator:    Python async with FastAPI (server mode)
```

## Documentation

- **[ARCHITECTURE.md](ARCHITECTURE.md)**: Complete system architecture with component details, data models, API contracts, and deployment instructions
- **[SPECIFICATIONS.md](SPECIFICATIONS.md)**: Original research and theoretical foundations

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
Output of Phase II - a `context_rules.json` unique to each repository:
```json
{
  "sources": ["APIController.handle_request", "IngestManager.read"],
  "sinks": ["DatabaseWrapper.run_query", "os.system"],
  "sanitizers": ["Validator.clean", "escape_html"]
}
```

### LLM-as-Judge Verification
Structured Chain-of-Thought for each finding:
1. Trace Verification: Does tainted data actually reach the sink?
2. Sanitization Check: Is data modified by validation/encoding?
3. Logic Check: Do conditions prevent execution?
4. Verdict: True Positive or False Positive

## Build Commands

```bash
# Install dependencies
pip install -e ".[dev]"

# Run Joern via Docker
docker run --rm -it -v $(pwd):/code joernio/joern

# Start vLLM inference server
python -m vllm.entrypoints.openai.api_server --model Qwen/Qwen2.5-Coder-32B-Instruct

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
- **Recommended**: 64GB RAM, 24GB VRAM GPU (RTX 3090/4090) - runs Qwen 2.5 Coder 32B (4-bit)
- **Optimal**: Apple M2/M3 Ultra 128GB or dual-GPU workstation

## Development Guidelines

- Python 3.11+ required
- Use Tree-sitter for all code parsing (not regex)
- CPG queries via Joern's CPGQL (Scala-based DSL)
- LLM prompts should use Few-Shot + Chain-of-Thought patterns
- All findings are hypotheses until verified by the Reasoning Agent
