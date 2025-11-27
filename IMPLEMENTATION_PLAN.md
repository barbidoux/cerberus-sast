# Cerberus SAST - Implementation Plan

> **Reference document for implementing Cerberus SAST from zero to production.**
>
> Based on [ARCHITECTURE.md](ARCHITECTURE.md) and [SPECIFICATIONS.md](SPECIFICATIONS.md)

---

## Overview

| Attribute | Value |
|-----------|-------|
| **Total Milestones** | 7 |
| **Total Python Modules** | ~55 |
| **Core Technologies** | Python 3.11+, Tree-sitter, Joern, Ollama, ChromaDB, FastAPI |

---

## Implementation Status

| Milestone | Description | Status | Progress |
|-----------|-------------|--------|----------|
| **M0** | Project Foundation | ✅ Complete | 100% |
| **M1** | Data Models | ✅ Complete | 100% |
| **M2** | Shared Infrastructure | 🔄 In Progress | 20% |
| **M3** | Phase I: Context Engine | 🔄 Partial | 30% |
| **M4** | Phase II: Spec Inference | ⏳ Pending | 0% |
| **M5** | Phase III: Detection | ⏳ Pending | 0% |
| **M6** | Phase IV: Verification | ⏳ Pending | 0% |
| **M7** | Production Hardening | ⏳ Pending | 0% |

---

## Milestone 0: Project Foundation ✅

### Completed Components

| File | Lines | Description | Status |
|------|-------|-------------|--------|
| `pyproject.toml` | 199 | Dependencies, scripts, tooling | ✅ |
| `cerberus/__init__.py` | 13 | Package version and exports | ✅ |
| `cerberus/__main__.py` | 6 | CLI entry point | ✅ |
| `cerberus/core/config.py` | 402 | Hierarchical configuration (Pydantic) | ✅ |
| `cerberus/cli/commands.py` | 451 | Click CLI with all commands | ✅ |
| `cerberus/utils/logging.py` | 260 | Rich console + JSON logging | ✅ |
| `cerberus/utils/async_utils.py` | 386 | Retry, rate limiting, caching | ✅ |
| `.cerberus.yml.example` | 190 | Configuration template | ✅ |

### Directory Structure
```
cerberus-sast/
├── cerberus/
│   ├── __init__.py              ✅
│   ├── __main__.py              ✅
│   ├── cli/
│   │   ├── __init__.py          ✅
│   │   └── commands.py          ✅
│   ├── core/
│   │   ├── __init__.py          ✅
│   │   └── config.py            ✅
│   ├── context/
│   │   ├── __init__.py          ✅
│   │   └── tree_sitter_parser.py ✅
│   ├── inference/
│   │   └── __init__.py          ✅
│   ├── detection/
│   │   └── __init__.py          ✅
│   ├── verification/
│   │   └── __init__.py          ✅
│   ├── llm/
│   │   ├── __init__.py          ✅
│   │   ├── providers/__init__.py ✅
│   │   └── prompts/__init__.py  ✅
│   ├── models/
│   │   ├── __init__.py          ✅
│   │   ├── base.py              ✅
│   │   ├── repo_map.py          ✅
│   │   ├── spec.py              ✅
│   │   └── finding.py           ✅
│   ├── reporting/
│   │   └── __init__.py          ✅
│   └── utils/
│       ├── __init__.py          ✅
│       ├── logging.py           ✅
│       └── async_utils.py       ✅
├── tests/
│   ├── __init__.py              ✅
│   ├── conftest.py              ✅
│   └── test_*/                  ✅
├── docker/                      ✅ (empty)
├── docs/                        ✅ (empty)
├── pyproject.toml               ✅
├── .cerberus.yml.example        ✅
└── .gitignore                   ✅
```

---

## Milestone 1: Data Models ✅

### Completed Components

| File | Lines | Description | Status |
|------|-------|-------------|--------|
| `cerberus/models/base.py` | 285 | Core enums and CodeLocation | ✅ |
| `cerberus/models/repo_map.py` | 318 | Symbol, FileInfo, RepoMap | ✅ |
| `cerberus/models/spec.py` | 365 | TaintSpec, DynamicSpec | ✅ |
| `cerberus/models/finding.py` | 688 | Finding, ProgramSlice, VerificationResult | ✅ |

### Key Types Defined

```python
# Base types (cerberus/models/base.py)
class Severity(Enum)          # CRITICAL, HIGH, MEDIUM, LOW, INFO
class TaintLabel(Enum)        # SOURCE, SINK, SANITIZER, PROPAGATOR
class Verdict(Enum)           # TRUE_POSITIVE, FALSE_POSITIVE, UNCERTAIN
class SymbolType(Enum)        # FUNCTION, METHOD, CLASS, VARIABLE, etc.
class VulnerabilityType(Enum) # CWE-89 (SQLi), CWE-79 (XSS), etc.
class CodeLocation            # file_path, line, column

# Phase I output (cerberus/models/repo_map.py)
class Symbol                  # Code symbol with location
class FileInfo                # File metadata and symbols
class RepoMap                 # Complete repository map

# Phase II output (cerberus/models/spec.py)
class TaintSpec               # Single taint specification
class DynamicSpec             # context_rules.json model

# Phase III/IV output (cerberus/models/finding.py)
class TraceStep               # Step in vulnerability trace
class SliceLine               # Line in program slice
class ProgramSlice            # 90% reduced code context
class VerificationResult      # Multi-Agent Council output
class Finding                 # Complete vulnerability finding
class ScanResult              # Complete scan output
```

---

## Milestone 2: Shared Infrastructure 🔄

### Components to Implement

| File | Description | Status |
|------|-------------|--------|
| `cerberus/llm/providers/base.py` | Abstract LLM provider | ⏳ |
| `cerberus/llm/providers/ollama.py` | Ollama provider | ⏳ |
| `cerberus/llm/providers/anthropic.py` | Anthropic Claude provider | ⏳ |
| `cerberus/llm/providers/openai.py` | OpenAI GPT provider | ⏳ |
| `cerberus/llm/gateway.py` | Unified LLM interface with failover | ⏳ |
| `cerberus/detection/joern_client.py` | Joern CPG client | ⏳ |
| `cerberus/context/vector_store.py` | ChromaDB integration | ⏳ |

### LLM Provider Architecture
```
┌─────────────────────────────────────────────────────┐
│                   LLMGateway                        │
│  ┌─────────────────────────────────────────────┐   │
│  │  Provider Chain (failover order):           │   │
│  │  1. OllamaProvider (local, primary)         │   │
│  │  2. AnthropicProvider (cloud fallback)      │   │
│  │  3. OpenAIProvider (cloud fallback)         │   │
│  └─────────────────────────────────────────────┘   │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────┐  │
│  │ ResponseCache│  │ RetryPolicy │  │ RateLimiter│ │
│  └─────────────┘  └──────────────┘  └──────────┘  │
└─────────────────────────────────────────────────────┘
```

---

## Milestone 3: Phase I - Context Engine 🔄

### Components

| File | Description | Status |
|------|-------------|--------|
| `cerberus/context/tree_sitter_parser.py` | Universal AST parser | ✅ |
| `cerberus/context/symbol_extractor.py` | Symbol extraction from AST | ⏳ |
| `cerberus/context/pagerank.py` | File importance ranking | ⏳ |
| `cerberus/context/repo_mapper.py` | Phase I coordinator | ⏳ |
| `cerberus/context/vector_store.py` | ChromaDB for RAG | ⏳ |

### Supported Languages (12 total)
| Language | Extensions | Tree-sitter |
|----------|------------|-------------|
| C | `.c`, `.h` | ✅ |
| C++ | `.cpp`, `.cc`, `.hpp` | ✅ |
| Java | `.java` | ✅ |
| JavaScript | `.js`, `.jsx`, `.mjs` | ✅ |
| TypeScript | `.ts`, `.tsx` | ✅ |
| Python | `.py`, `.pyi` | ✅ |
| Kotlin | `.kt`, `.kts` | ✅ |
| PHP | `.php` | ✅ |
| Go | `.go` | ✅ |
| Swift | `.swift` | ✅ |
| Ruby | `.rb` | ✅ |
| C# | `.cs` | ✅ |

### Phase I Pipeline
```
Input: Repository Path
    │
    ▼
┌─────────────────────────────────┐
│  1. Tree-sitter Parser          │  Parse all files → ASTs
└─────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────┐
│  2. Symbol Extractor            │  Extract functions, classes
└─────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────┐
│  3. Dependency Graph Builder    │  Map imports → file dependencies
└─────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────┐
│  4. PageRank Calculator         │  Rank files by importance
└─────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────┐
│  5. Vector Store Indexer        │  Index for semantic search
└─────────────────────────────────┘
    │
    ▼
Output: RepoMap (repo_map.json)
```

---

## Milestone 4: Phase II - Spec Inference ⏳

### Components

| File | Description | Status |
|------|-------------|--------|
| `cerberus/inference/candidate_extractor.py` | Find potential sources/sinks | ⏳ |
| `cerberus/inference/classifier.py` | LLM-based classification | ⏳ |
| `cerberus/inference/propagator.py` | Taint label propagation | ⏳ |
| `cerberus/inference/spec_writer.py` | Generate context_rules.json | ⏳ |

### Phase II Pipeline
```
Input: RepoMap + CPG
    │
    ▼
┌─────────────────────────────────┐
│  1. Candidate Extraction        │  CPGQL queries for candidates
└─────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────┐
│  2. LLM Classification          │  Few-Shot CoT prompting
│     - Source?                   │
│     - Sink?                     │
│     - Sanitizer?                │
└─────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────┐
│  3. Taint Propagation           │  Iterate until fixpoint
└─────────────────────────────────┘
    │
    ▼
Output: DynamicSpec (context_rules.json)
```

---

## Milestone 5: Phase III - Detection ⏳

### Components

| File | Description | Status |
|------|-------------|--------|
| `cerberus/detection/joern_client.py` | Joern CPG client | ⏳ |
| `cerberus/detection/query_generator.py` | LLM-driven CPGQL generation | ⏳ |
| `cerberus/detection/flow_analyzer.py` | Execute queries, extract traces | ⏳ |
| `cerberus/detection/slicer.py` | Program slicing (90% reduction) | ⏳ |

### Phase III Pipeline
```
Input: DynamicSpec + CPG
    │
    ▼
┌─────────────────────────────────┐
│  1. Query Generation            │  LLM generates CPGQL
└─────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────┐
│  2. Flow Analysis               │  Execute queries on CPG
└─────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────┐
│  3. Trace Extraction            │  Build vulnerability traces
└─────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────┐
│  4. Program Slicing             │  Extract minimal context
└─────────────────────────────────┘
    │
    ▼
Output: List[Finding] (unverified)
```

---

## Milestone 6: Phase IV - Verification ⏳

### Components

| File | Description | Status |
|------|-------------|--------|
| `cerberus/verification/attacker_agent.py` | Formulate exploit theories | ⏳ |
| `cerberus/verification/defender_agent.py` | Argue for code safety | ⏳ |
| `cerberus/verification/judge_agent.py` | Render final verdict | ⏳ |
| `cerberus/verification/council.py` | Multi-Agent orchestrator | ⏳ |
| `cerberus/verification/feedback.py` | Feedback loop to Phase II | ⏳ |

### Multi-Agent Council
```
                    ┌─────────────────┐
                    │  Program Slice  │
                    │   + Finding     │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
         ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  ATTACKER AGENT │ │                 │ │  DEFENDER AGENT │
│                 │ │                 │ │                 │
│ "How can this   │ │                 │ │ "Why is this    │
│  be exploited?" │ │                 │ │  code safe?"    │
│                 │ │                 │ │                 │
│ Output:         │ │                 │ │ Output:         │
│ - Exploit input │ │                 │ │ - Defense lines │
│ - Attack trace  │ │                 │ │ - Sanitization  │
│ - Impact        │ │                 │ │ - Reasoning     │
└────────┬────────┘ │                 │ └────────┬────────┘
         │          │                 │          │
         └──────────┼─────────────────┼──────────┘
                    │                 │
                    ▼                 │
           ┌─────────────────┐        │
           │   JUDGE AGENT   │        │
           │                 │        │
           │ Verdict:        │        │
           │ - TRUE_POSITIVE │        │
           │ - FALSE_POSITIVE│        │
           │ - UNCERTAIN     │        │
           │                 │        │
           │ + Confidence    │        │
           └────────┬────────┘        │
                    │                 │
                    ▼                 │
           FALSE_POSITIVE?────────────┘
           (missed sanitizer)
                    │
                    ▼
           Add to DynamicSpec.sanitizers
           Re-run Detection
```

---

## Milestone 7: Production Hardening ⏳

### Components

| File | Description | Status |
|------|-------------|--------|
| `cerberus/cli/server.py` | FastAPI server | ⏳ |
| `cerberus/core/pipeline.py` | End-to-end orchestrator | ⏳ |
| `cerberus/reporting/sarif.py` | SARIF report generator | ⏳ |
| `cerberus/reporting/json_report.py` | JSON report generator | ⏳ |
| `cerberus/reporting/html_report.py` | HTML report generator | ⏳ |
| `cerberus/reporting/console.py` | Console output | ⏳ |
| `docker/Dockerfile` | Container build | ⏳ |
| `docker/docker-compose.yml` | Multi-container setup | ⏳ |

### API Endpoints
```
POST   /api/v1/scans              # Start new scan
GET    /api/v1/scans/{id}         # Get scan status
GET    /api/v1/scans/{id}/results # Get scan results
DELETE /api/v1/scans/{id}         # Cancel scan
WS     /api/v1/scans/{id}/stream  # Real-time progress
```

---

## Dependencies Graph

```
M0: Foundation
    │
    ▼
M1: Data Models
    │
    ▼
M2: Shared Infrastructure ◄── Required by all phases
    │
    ├───────────────────────────────────────┐
    ▼                                       │
M3: Phase I (Context) ──────────────────────┤
    │                                       │
    ▼                                       │
M4: Phase II (Inference) ◄── Requires M3    │
    │                                       │
    ▼                                       │
M5: Phase III (Detection) ◄── Requires M4 + Joern
    │                                       │
    ▼                                       │
M6: Phase IV (Verification) ◄── Requires M5 + LLM
    │                                       │
    ▼                                       │
M7: Production ◄── Requires all phases ─────┘
```

---

## Quick Commands

```bash
# Install in development mode
pip install -e ".[dev]"

# Run CLI
cerberus --help
cerberus scan ./my-project
cerberus server --port 8080

# Run tests
pytest
pytest --cov=cerberus

# Linting
black cerberus tests
ruff check cerberus
mypy cerberus
```

---

## Files Reference

### Configuration
| File | Purpose |
|------|---------|
| `pyproject.toml` | Project metadata, dependencies |
| `.cerberus.yml.example` | User configuration template |
| `~/.cerberus/config.yml` | User-level defaults |
| `.cerberus.yml` | Project-level config |

### Key Outputs
| File | Phase | Content |
|------|-------|---------|
| `repo_map.json` | I | Repository structure |
| `context_rules.json` | II | Sources, sinks, sanitizers |
| `findings.json` | III | Unverified findings |
| `results.sarif` | IV | Verified results (SARIF) |

---

*Document Version: 1.0*
*Last Updated: 2025-01-15*
