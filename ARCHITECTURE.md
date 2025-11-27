# Cerberus SAST - Production Architecture Document

## Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [System Architecture Overview](#2-system-architecture-overview)
3. [Supported Languages](#3-supported-languages)
4. [Component Deep-Dives](#4-component-deep-dives)
5. [Shared Infrastructure](#5-shared-infrastructure)
6. [Data Models](#6-data-models)
7. [API Contracts](#7-api-contracts)
8. [Deployment Architecture](#8-deployment-architecture)
9. [Scalability Strategy](#9-scalability-strategy)
10. [Error Handling & Resilience](#10-error-handling--resilience)
11. [Security Considerations](#11-security-considerations)
12. [Implementation Roadmap](#12-implementation-roadmap)
13. [File Structure](#13-file-structure)

---

## 1. Executive Summary

### 1.1 Vision
Cerberus SAST is a next-generation, local, AI-driven static application security testing tool implementing a **Neuro-Symbolic Self-Configuring Pipeline (NSSCP)**. It fuses LLM semantic reasoning with Code Property Graph (CPG) precision to achieve industry-leading accuracy.

### 1.2 Core Objectives
| Objective | Target | Mechanism |
|-----------|--------|-----------|
| **False Positive Rate** | <5% | Multi-Agent Council verification |
| **Self-Configuration** | Zero manual rules | LLM-driven Source/Sink/Sanitizer inference |
| **Data Sovereignty** | 100% local by default | Ollama + local Joern deployment |
| **Language Coverage** | 12 languages | Joern CPG multi-language support |

### 1.3 Design Principles
1. **Context-First Mapping**: Understand codebase structure before analysis (prevents LLM context overflow)
2. **Dynamic Specification**: Rediscover Sources/Sinks for every scan (no hardcoded rules)
3. **Graph-Based Execution**: Offload data flow analysis to Joern CPG (deterministic, fast)
4. **Agentic Verification**: Every finding is a hypothesis validated by reasoning agents

### 1.4 Target Users
- Security engineers performing code audits
- DevSecOps teams integrating SAST into CI/CD
- Security researchers analyzing large codebases
- Development teams seeking low-noise vulnerability detection

---

## 2. System Architecture Overview

### 2.1 High-Level Pipeline
```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            CERBERUS SAST PIPELINE                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   PHASE I    │───▶│   PHASE II   │───▶│  PHASE III   │───▶│   PHASE IV   │  │
│  │   Context    │    │  Inference   │    │  Detection   │    │ Verification │  │
│  │   Engine     │    │   Engine     │    │   Engine     │    │    Agent     │  │
│  │              │    │              │    │              │    │              │  │
│  │ - Tree-sitter│    │ - Candidate  │    │ - CPGQL Gen  │    │ - Attacker   │  │
│  │ - PageRank   │    │   Extraction │    │ - Flow       │    │ - Defender   │  │
│  │ - Vector     │    │ - LLM Class. │    │   Analysis   │    │ - Judge      │  │
│  │   Store      │    │ - Taint Prop │    │ - Slicing    │    │              │  │
│  └──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                   ▲                                       │          │
│         │                   │                                       │          │
│         │                   └───────────────────────────────────────┘          │
│         │                              FEEDBACK LOOP                           │
│         │                    (Missed sanitizers → re-inference)                │
│         ▼                                                                      │
│  ┌───────────────────────────────────────────────────────────────────────────┐ │
│  │                         SHARED INFRASTRUCTURE                              │ │
│  │                                                                            │ │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌─────────┐  ┌───────────┐  │ │
│  │  │   Joern   │  │    LLM    │  │  Vector   │  │ Config  │  │  Report   │  │ │
│  │  │  Server   │  │  Gateway  │  │   Store   │  │ Manager │  │ Generator │  │ │
│  │  │  Manager  │  │           │  │ (ChromaDB)│  │         │  │           │  │ │
│  │  └───────────┘  └───────────┘  └───────────┘  └─────────┘  └───────────┘  │ │
│  │                                                                            │ │
│  └───────────────────────────────────────────────────────────────────────────┘ │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Data Flow Summary
```
Source Code
    │
    ▼
[Phase I: Context Engine]
    │── Parse with Tree-sitter ──▶ AST
    │── Extract symbols ──────────▶ Dependency Graph
    │── Apply PageRank ───────────▶ File Rankings
    │── Generate embeddings ──────▶ Vector Store
    │
    ▼
[Phase II: Spec Inference]
    │── Query CPG for candidates ─▶ Interesting Functions
    │── LLM classification ───────▶ Source/Sink/Sanitizer labels
    │── Propagate taint labels ───▶ Call Graph Annotation
    │
    ▼
    ├──────────────────────────────▶ context_rules.json
    │
[Phase III: Detection]
    │── Generate CPGQL queries ───▶ Data Flow Queries
    │── Execute on Joern ─────────▶ Vulnerability Traces
    │── Extract program slices ───▶ Minimal Code Context
    │
    ▼
[Phase IV: Verification]
    │── Attacker formulates exploit
    │── Defender argues safety
    │── Judge renders verdict
    │
    ▼
    ├── TRUE_POSITIVE ────────────▶ Final Report
    └── FALSE_POSITIVE ───────────▶ Feedback Loop (update specs)
```

---

## 3. Supported Languages

Cerberus leverages Joern's multi-language CPG generation capabilities.

| Language | Maturity | Parser Backend | Notes |
|----------|----------|----------------|-------|
| **C/C++** | Very High | Eclipse CDT | Full support including macros |
| **Java** | Very High | JavaParser | Includes annotation processing |
| **JavaScript** | High | GraalVM | ES6+ support |
| **Python** | High | JavaCC | Python 3.x syntax |
| **x86/x64** | High | Ghidra | Binary analysis |
| **JVM Bytecode** | Medium | Soot | .class and .jar files |
| **Kotlin** | Medium | IntelliJ PSI | Interop with Java CPG |
| **PHP** | Medium | PHP-Parser | PHP 7/8 syntax |
| **Go** | Medium | go.parser | Standard library coverage |
| **Swift** | Medium | SwiftSyntax | iOS/macOS projects |
| **Ruby** | Medium-Low | ANTLR | Rails framework aware |
| **C#** | Medium-Low | Roslyn | .NET Core/Framework |

### Language Detection
```python
LANGUAGE_EXTENSIONS = {
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".java": "java",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".py": "python",
    ".kt": "kotlin", ".kts": "kotlin",
    ".php": "php",
    ".go": "go",
    ".swift": "swift",
    ".rb": "ruby",
    ".cs": "csharp",
}
```

---

## 4. Component Deep-Dives

### 4.1 Phase I: Context Engine (Repository Mapper)

**Purpose**: Build structural understanding of the codebase before any security analysis begins. This solves the "Context Window Overflow" problem by intelligently selecting what code to show the LLM.

#### 4.1.1 Subcomponents

```
┌─────────────────────────────────────────────────────────────┐
│                     CONTEXT ENGINE                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────┐      ┌─────────────────┐              │
│  │  Tree-sitter    │─────▶│    Symbol       │              │
│  │  Parser         │      │    Extractor    │              │
│  └─────────────────┘      └────────┬────────┘              │
│                                    │                        │
│                                    ▼                        │
│  ┌─────────────────┐      ┌─────────────────┐              │
│  │   Dependency    │◀─────│   Definitions   │              │
│  │   Graph Builder │      │   & References  │              │
│  └────────┬────────┘      └─────────────────┘              │
│           │                                                 │
│           ▼                                                 │
│  ┌─────────────────┐      ┌─────────────────┐              │
│  │   PageRank      │─────▶│   File          │              │
│  │   Ranker        │      │   Rankings      │              │
│  └─────────────────┘      └─────────────────┘              │
│                                                             │
│  ┌─────────────────┐      ┌─────────────────┐              │
│  │   Embedding     │─────▶│   Vector Store  │              │
│  │   Generator     │      │   (ChromaDB)    │              │
│  └─────────────────┘      └─────────────────┘              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### 4.1.2 Tree-sitter Parser
```python
class TreeSitterParser:
    """Universal AST generation using Tree-sitter."""

    def __init__(self):
        self.parsers: Dict[str, tree_sitter.Parser] = {}
        self._load_languages()

    def parse_file(self, file_path: Path) -> Optional[tree_sitter.Tree]:
        """Parse a single file into an AST."""
        language = self._detect_language(file_path)
        if language not in self.parsers:
            return None

        with open(file_path, 'rb') as f:
            content = f.read()

        return self.parsers[language].parse(content)

    def parse_repository(self, repo_path: Path) -> Dict[Path, tree_sitter.Tree]:
        """Parse all supported files in a repository."""
        trees = {}
        for file_path in self._discover_files(repo_path):
            if tree := self.parse_file(file_path):
                trees[file_path] = tree
        return trees
```

#### 4.1.3 Symbol Extractor
Extracts definitions and references from ASTs:
- **Definitions**: Classes, functions, methods, global variables
- **References**: Function calls, imports, type annotations

#### 4.1.4 PageRank Ranker
Applies the PageRank algorithm to the dependency graph to score file importance:
```python
def calculate_pagerank(
    graph: nx.DiGraph,
    damping: float = 0.85,
    iterations: int = 100
) -> Dict[str, float]:
    """Calculate PageRank scores for all nodes in the dependency graph."""
    return nx.pagerank(graph, alpha=damping, max_iter=iterations)
```

**Ranking Purpose**: When LLM context is limited, prioritize files with highest PageRank (most interconnected/central to the codebase).

#### 4.1.5 Vector Store Manager
```python
class VectorStoreManager:
    """Manages ChromaDB collections for semantic code search."""

    COLLECTIONS = {
        "functions": "Function-level embeddings",
        "classes": "Class-level embeddings",
        "files": "File-level summaries"
    }

    def __init__(self, persist_dir: Path):
        self.client = chromadb.PersistentClient(path=str(persist_dir))
        self.embedding_model = "jina-embeddings-v2-code"

    async def index_codebase(self, repo_map: RepoMap) -> None:
        """Index all code elements for RAG queries."""
        ...

    async def search(
        self,
        query: str,
        collection: str = "functions",
        top_k: int = 10
    ) -> List[SearchResult]:
        """Semantic search across code elements."""
        ...
```

#### 4.1.6 Outputs
| Output | Format | Description |
|--------|--------|-------------|
| `repo_map.json` | JSON | Structural map with symbols and dependencies |
| `file_rankings.json` | JSON | PageRank scores per file |
| ChromaDB collections | Binary | Vector embeddings for RAG |

---

### 4.2 Phase II: Spec Inference Engine

**Purpose**: Autonomously discover Sources, Sinks, and Sanitizers without manual rule writing. This is the "Self-Configuring" core of NSSCP.

#### 4.2.1 Architecture
```
┌──────────────────────────────────────────────────────────────────┐
│                    SPEC INFERENCE ENGINE                         │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌────────────────┐                                              │
│  │   Candidate    │◀──── CPGQL queries for:                     │
│  │   Extractor    │      - Public/external methods              │
│  │                │      - I/O interaction points               │
│  └───────┬────────┘      - High PageRank functions              │
│          │                                                       │
│          ▼                                                       │
│  ┌────────────────┐      ┌─────────────────────────────────┐    │
│  │      LLM       │─────▶│ Classification:                 │    │
│  │   Classifier   │      │ - SOURCE: Untrusted input       │    │
│  │                │      │ - SINK: Sensitive operation     │    │
│  │ (Few-shot CoT) │      │ - SANITIZER: Validation/clean   │    │
│  └───────┬────────┘      │ - PROPAGATOR: Passes taint      │    │
│          │               │ - NONE: Not security-relevant   │    │
│          │               └─────────────────────────────────┘    │
│          ▼                                                       │
│  ┌────────────────┐                                              │
│  │     Taint      │──── Propagate labels across call graph      │
│  │   Propagator   │     If Source flows into function that      │
│  │                │     returns data → mark as PROPAGATOR       │
│  └───────┬────────┘                                              │
│          │                                                       │
│          ▼                                                       │
│  ┌────────────────┐      ┌─────────────────────────────────┐    │
│  │ Specification  │─────▶│     context_rules.json          │    │
│  │    Writer      │      └─────────────────────────────────┘    │
│  └────────────────┘                                              │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### 4.2.2 Candidate Extraction CPGQL Queries
```scala
// Find public methods in controller-like classes
cpg.typeDecl
  .name(".*Controller.*|.*Handler.*|.*Endpoint.*")
  .method
  .isPublic

// Find methods interacting with I/O
cpg.method
  .where(_.call.name("read|write|execute|query|send|recv"))

// Find methods with external parameters
cpg.method
  .parameter
  .typeFullName(".*Request.*|.*Input.*|.*String.*")
```

#### 4.2.3 LLM Classification Prompt
```
You are a security expert analyzing code for potential vulnerabilities.

Analyze the following function and classify it:
- SOURCE: Accepts untrusted external input (HTTP params, file reads, env vars)
- SINK: Executes sensitive operations (SQL, file I/O, command exec, crypto)
- SANITIZER: Validates or cleans data (escaping, encoding, type checking)
- PROPAGATOR: Passes tainted data through without modification
- NONE: Not security-relevant

Function signature: {signature}
Function body:
```{language}
{function_code}
```

Reasoning (step by step):
1. What is the purpose of this function?
2. Does it receive data from external/untrusted sources?
3. Does it perform sensitive operations that could be exploited?
4. Does it validate, sanitize, or transform data?
5. Does it simply pass data through to other functions?

Classification: [SOURCE|SINK|SANITIZER|PROPAGATOR|NONE]
Confidence: [HIGH|MEDIUM|LOW]
Reason: <one-line explanation>
```

#### 4.2.4 Taint Propagation Algorithm
```python
def propagate_taint_labels(
    call_graph: nx.DiGraph,
    initial_labels: Dict[str, TaintLabel]
) -> Dict[str, TaintLabel]:
    """
    Propagate taint labels across the call graph.

    Rules:
    1. If a SOURCE calls a function that returns data → PROPAGATOR
    2. If a PROPAGATOR flows to a SINK → potential vulnerability path
    3. If data passes through SANITIZER → taint is cleared
    """
    labels = initial_labels.copy()
    changed = True

    while changed:
        changed = False
        for caller, callee in call_graph.edges():
            if labels.get(caller) == TaintLabel.SOURCE:
                if callee not in labels or labels[callee] == TaintLabel.NONE:
                    # Check if callee returns caller's data
                    if returns_input_data(caller, callee):
                        labels[callee] = TaintLabel.PROPAGATOR
                        changed = True

    return labels
```

#### 4.2.5 Dynamic Specification Output
```json
{
  "version": "1.0",
  "generated_at": "2025-01-15T10:30:00Z",
  "repository": "/path/to/repo",
  "sources": [
    {
      "method": "get_user_input",
      "class": "RequestHandler",
      "file": "src/handlers/request.py",
      "line": 42,
      "parameter_index": 0,
      "confidence": 0.95,
      "reason": "Retrieves data from HTTP request parameters"
    }
  ],
  "sinks": [
    {
      "method": "execute_query",
      "class": "DatabaseManager",
      "file": "src/db/manager.py",
      "line": 128,
      "parameter_index": 0,
      "confidence": 0.98,
      "reason": "Executes SQL query string directly"
    }
  ],
  "sanitizers": [
    {
      "method": "escape_sql",
      "class": "SecurityUtils",
      "file": "src/utils/security.py",
      "line": 55,
      "confidence": 0.92,
      "reason": "Escapes SQL special characters"
    }
  ],
  "propagators": [
    {
      "method": "process_request",
      "class": "RequestHandler",
      "file": "src/handlers/request.py",
      "line": 67,
      "confidence": 0.88,
      "reason": "Passes user input to internal processing without modification"
    }
  ]
}
```

---

### 4.3 Phase III: Hybrid Graph Engine (Detection)

**Purpose**: Execute taint analysis using the dynamically generated specifications against Joern's CPG.

#### 4.3.1 Architecture
```
┌──────────────────────────────────────────────────────────────────┐
│                   HYBRID GRAPH ENGINE                            │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  context_rules.json                                              │
│         │                                                        │
│         ▼                                                        │
│  ┌────────────────┐                                              │
│  │    Query       │──── LLM generates CPGQL from specs          │
│  │   Generator    │                                              │
│  └───────┬────────┘                                              │
│          │                                                       │
│          ▼                                                       │
│  ┌────────────────┐      ┌─────────────────────────────────┐    │
│  │    Query       │─────▶│  Joern Server                   │    │
│  │   Executor     │      │  (cpgqls-client)                │    │
│  │                │◀─────│                                 │    │
│  └───────┬────────┘      └─────────────────────────────────┘    │
│          │                                                       │
│          ▼                                                       │
│  ┌────────────────┐                                              │
│  │    Trace       │──── Extract source→sink paths               │
│  │   Extractor    │     with intermediate steps                 │
│  └───────┬────────┘                                              │
│          │                                                       │
│          ▼                                                       │
│  ┌────────────────┐      ┌─────────────────────────────────┐    │
│  │   Program      │─────▶│  Minimal code context           │    │
│  │   Slicer       │      │  for verification               │    │
│  └────────────────┘      └─────────────────────────────────┘    │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### 4.3.2 CPGQL Query Generation Prompt
```
Generate a Joern CPGQL query to find data flows from source to sink.

Source: {source_method} in {source_class}
Sink: {sink_method} in {sink_class}
Language: {language}

Requirements:
1. Find all calls to the source method
2. Track data flow through the program
3. Identify if data reaches the sink without sanitization
4. Return the complete trace with line numbers

Context:
- Known sanitizers: {sanitizers_list}
- The query should exclude paths that pass through sanitizers

Generate ONLY the CPGQL query, no explanation:
```

#### 4.3.3 Example Generated CPGQL
```scala
// Find SQL injection paths
def source = cpg.method.name("get_user_input").parameter
def sink = cpg.method.name("execute_query").parameter
def sanitizer = cpg.method.name("escape_sql")

sink.reachableBy(source)
  .whereNot(_.reachableBy(sanitizer))
  .map { path =>
    Map(
      "source" -> path.head.location.toJson,
      "sink" -> path.last.location.toJson,
      "trace" -> path.map(_.location.toJson)
    )
  }
  .toJson
```

#### 4.3.4 Program Slicer
Extracts minimal code context for verification (90% reduction vs full files while retaining 100% vulnerability-relevant context):

```python
@dataclass
class ProgramSlice:
    """Minimal code context for a potential vulnerability."""

    source_location: CodeLocation
    sink_location: CodeLocation

    # Lines directly on the trace
    trace_lines: List[SliceLine]

    # Variable definitions used in the trace
    variable_definitions: List[VariableDefinition]

    # Control structures governing the trace
    control_structures: List[ControlStructure]  # if, while, for, try

    # Function boundaries for context
    function_context: Dict[str, FunctionContext]

    def to_code_string(self) -> str:
        """Render slice as readable code with annotations."""
        ...
```

#### 4.3.5 Outputs
| Output | Description |
|--------|-------------|
| Raw Findings | List of source→sink paths with traces |
| Program Slices | Minimal code context per finding |

---

### 4.4 Phase IV: Verification Agent (Multi-Agent Council)

**Purpose**: Filter false positives through adversarial semantic reasoning, achieving <5% FP rate.

#### 4.4.1 Multi-Agent Council Architecture
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          MULTI-AGENT COUNCIL                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│                              INPUT                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 1. Trace: Source → ... → Sink path                                  │   │
│  │ 2. Program Slice: Minimal code context                              │   │
│  │ 3. Vulnerability Definition: CWE description                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      ATTACKER AGENT                                  │   │
│  │                                                                      │   │
│  │  Role: Security researcher attempting to exploit the code           │   │
│  │                                                                      │   │
│  │  Tasks:                                                              │   │
│  │  1. Formulate concrete attack input                                 │   │
│  │  2. Trace how input reaches the sink                                │   │
│  │  3. Describe security impact                                        │   │
│  │                                                                      │   │
│  │  Output: Exploit theory or "No viable attack"                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      DEFENDER AGENT                                  │   │
│  │                                                                      │   │
│  │  Role: Security engineer defending the code                         │   │
│  │                                                                      │   │
│  │  Tasks:                                                              │   │
│  │  1. Point to specific lines preventing exploitation                 │   │
│  │  2. Identify sanitization or validation                             │   │
│  │  3. Explain logical conditions blocking attack                      │   │
│  │                                                                      │   │
│  │  Output: Defense argument or "Code is vulnerable"                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       JUDGE AGENT                                    │   │
│  │                                                                      │   │
│  │  Role: Final arbiter reviewing the debate                           │   │
│  │                                                                      │   │
│  │  Tasks:                                                              │   │
│  │  1. Evaluate attacker's exploit viability                           │   │
│  │  2. Assess defender's evidence                                      │   │
│  │  3. Check for edge cases both missed                                │   │
│  │                                                                      │   │
│  │  Output: TRUE_POSITIVE or FALSE_POSITIVE + confidence + reasoning   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│                          VERDICT                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                      │   │
│  │  TRUE_POSITIVE ──────▶ Add to final report                          │   │
│  │                                                                      │   │
│  │  FALSE_POSITIVE ─────▶ Feedback Loop:                               │   │
│  │                        - If missed sanitizer → add to specs         │   │
│  │                        - Trigger re-inference (Phase II)            │   │
│  │                        - Re-run detection (Phase III)               │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 4.4.2 Attacker Agent Prompt
```
You are a security researcher trying to exploit this code.

Vulnerability Type: {cwe_id} - {cwe_name}
{cwe_description}

Code Slice:
```{language}
{program_slice}
```

Data Flow Trace:
{trace_formatted}

Your task: Formulate a concrete attack
1. What specific input would you provide to exploit this?
2. Trace exactly how your input reaches the dangerous sink
3. What is the security impact if successful?

If you cannot formulate a viable attack, explain specifically why:
- What prevents the attack?
- Is there validation/sanitization you cannot bypass?
- Are there logical conditions that make exploitation impossible?

Response format:
EXPLOITABLE: [YES/NO]
ATTACK_INPUT: <specific malicious input>
ATTACK_TRACE: <step-by-step path through code>
IMPACT: <security consequence>
REASONING: <detailed explanation>
```

#### 4.4.3 Defender Agent Prompt
```
You are a security engineer defending this code.

Vulnerability Type: {cwe_id} - {cwe_name}

Code Slice:
```{language}
{program_slice}
```

Attacker's claim:
{attacker_argument}

Your task: Argue why this code is safe (if it is)
1. Point to SPECIFIC LINE NUMBERS that prevent exploitation
2. Identify any sanitization, validation, or encoding
3. Explain logical conditions that block the attack
4. Note any security controls the attacker missed

If the code IS genuinely vulnerable, acknowledge it and explain why the attacker is correct.

Response format:
SAFE: [YES/NO]
DEFENSE_LINES: <line numbers with explanation>
SANITIZATION: <any validation/encoding present>
LOGIC_BARRIERS: <conditions preventing exploit>
REASONING: <detailed explanation>
```

#### 4.4.4 Judge Agent Prompt
```
You are the final arbiter in a security vulnerability debate.

Vulnerability: {cwe_id} - {cwe_name}

Code:
```{language}
{program_slice}
```

ATTACKER ARGUMENT:
{attacker_full_response}

DEFENDER ARGUMENT:
{defender_full_response}

Your task: Render a final verdict
1. Is the attacker's exploit theory technically viable?
2. Does the defender's evidence actually prevent the attack?
3. Are there edge cases or conditions either party missed?
4. Consider: type coercion, encoding issues, race conditions, error handling

IMPORTANT: Be conservative. If there's reasonable doubt, lean toward TRUE_POSITIVE.

Response format:
VERDICT: [TRUE_POSITIVE|FALSE_POSITIVE]
CONFIDENCE: [0.0-1.0]
ATTACKER_VALIDITY: <assessment of attack viability>
DEFENDER_VALIDITY: <assessment of defense strength>
MISSED_CONSIDERATIONS: <anything both parties overlooked>
FINAL_REASONING: <comprehensive explanation of verdict>
```

#### 4.4.5 Feedback Loop Implementation
```python
class FeedbackLoop:
    """Handles feedback from verification to spec inference."""

    async def process_false_positive(
        self,
        finding: Finding,
        verification: VerificationResult
    ) -> Optional[SpecUpdate]:
        """
        Analyze FP to determine if specs need updating.

        Returns SpecUpdate if a missed sanitizer/validator was identified.
        """
        if not verification.missed_sanitizer:
            return None

        # Extract the missed sanitizer from judge reasoning
        sanitizer = self._extract_sanitizer_info(verification)

        return SpecUpdate(
            update_type=UpdateType.ADD_SANITIZER,
            target=sanitizer,
            reason=verification.judge_reasoning,
            confidence=verification.confidence
        )

    async def trigger_reanalysis(
        self,
        spec_update: SpecUpdate,
        affected_findings: List[Finding]
    ) -> List[Finding]:
        """Re-run detection for findings affected by spec update."""
        # Update context_rules.json
        await self.spec_writer.add_sanitizer(spec_update.target)

        # Re-run Phase III detection for affected source-sink pairs
        new_findings = await self.detection_engine.reanalyze(
            affected_findings,
            updated_specs=True
        )

        return new_findings
```

---

## 5. Shared Infrastructure

### 5.1 LLM Gateway

**Purpose**: Unified interface for all LLM interactions with automatic failover.

```
┌─────────────────────────────────────────────────────────────────┐
│                        LLM GATEWAY                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  Provider Chain                          │   │
│  │                                                          │   │
│  │  ┌──────────┐   ┌──────────┐   ┌──────────┐            │   │
│  │  │  Ollama  │──▶│Anthropic │──▶│  OpenAI  │            │   │
│  │  │ (Primary)│   │(Fallback)│   │(Fallback)│            │   │
│  │  └──────────┘   └──────────┘   └──────────┘            │   │
│  │                                                          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  Features:                                                      │
│  ├── Automatic failover on timeout/error                       │
│  ├── Rate limiting per provider                                │
│  ├── Response caching (configurable TTL)                       │
│  ├── Token usage tracking                                      │
│  ├── Prompt template management                                │
│  └── Retry with exponential backoff                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### Interface
```python
class LLMGateway:
    """Unified LLM interface with provider failover."""

    def __init__(self, config: LLMConfig):
        self.providers = [
            OllamaProvider(config.ollama),
            AnthropicProvider(config.anthropic),
            OpenAIProvider(config.openai),
        ]
        self.cache = ResponseCache(ttl=config.cache_ttl)
        self.rate_limiter = RateLimiter(config.rate_limits)

    async def complete(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 4096
    ) -> LLMResponse:
        """Generate completion with automatic failover."""
        ...

    async def classify(
        self,
        prompt: str,
        options: List[str],
        model: Optional[str] = None
    ) -> Classification:
        """Classify input into predefined categories."""
        ...

    async def generate_code(
        self,
        prompt: str,
        language: str,
        model: Optional[str] = None
    ) -> str:
        """Generate code with syntax validation."""
        ...
```

#### Provider Configuration
```yaml
llm:
  default_provider: ollama

  ollama:
    base_url: "http://localhost:11434"
    model: "qwen2.5-coder:32b"
    timeout: 120

  anthropic:
    api_key: "${ANTHROPIC_API_KEY}"
    model: "claude-3-5-sonnet-20241022"
    timeout: 60

  openai:
    api_key: "${OPENAI_API_KEY}"
    model: "gpt-4-turbo"
    timeout: 60

  retry:
    max_attempts: 3
    backoff_factor: 2

  cache:
    enabled: true
    ttl: 3600  # 1 hour
```

---

### 5.2 Joern Server Manager

**Purpose**: Manage Joern lifecycle, CPG generation, and query execution.

```python
class JoernManager:
    """Manages Joern server and CPG operations."""

    def __init__(self, config: JoernConfig):
        self.endpoint = config.endpoint
        self.client = CPGQLSClient(
            self.endpoint,
            auth_credentials=(config.username, config.password)
        )
        self.docker_client = docker.from_env()

    async def start_server(self) -> None:
        """Start Joern server via Docker if not running."""
        if not self._is_server_running():
            self.docker_client.containers.run(
                "joernio/joern:latest",
                command=["joern", "--server", "--server-host", "0.0.0.0"],
                ports={"8080/tcp": 8080},
                volumes={str(self.workspace): {"bind": "/workspace", "mode": "rw"}},
                detach=True,
                name="cerberus-joern"
            )
            await self._wait_for_server()

    async def import_code(self, path: Path, project_name: str) -> None:
        """Import codebase and generate CPG."""
        query = import_code_query(str(path), project_name)
        result = await self._execute(query)
        if not result.success:
            raise JoernImportError(result.stderr)

    async def query(self, cpgql: str) -> QueryResult:
        """Execute CPGQL query against the CPG."""
        # Validate query syntax before execution
        if not self._validate_cpgql(cpgql):
            raise InvalidQueryError(cpgql)

        result = self.client.execute(cpgql)
        return QueryResult(
            success=result.get("success", False),
            data=result.get("stdout"),
            error=result.get("stderr")
        )

    async def find_flows(
        self,
        source: str,
        sink: str,
        exclude_sanitizers: List[str] = None
    ) -> List[Flow]:
        """Find data flows from source to sink."""
        sanitizer_filter = ""
        if exclude_sanitizers:
            sanitizer_names = "|".join(exclude_sanitizers)
            sanitizer_filter = f'.whereNot(_.reachableBy(cpg.method.name("{sanitizer_names}")))'

        query = f"""
        def source = cpg.method.name("{source}").parameter
        def sink = cpg.method.name("{sink}").parameter
        sink.reachableBy(source){sanitizer_filter}.toJson
        """

        result = await self.query(query)
        return [Flow.from_json(f) for f in json.loads(result.data)]

    async def get_slice(self, flow: Flow) -> ProgramSlice:
        """Extract program slice for a given flow."""
        query = f"""
        cpg.method.name("{flow.sink_method}")
          .controlStructure
          .code
          .l
        """
        # ... additional slice extraction logic
```

---

### 5.3 Configuration Manager

**Purpose**: Centralized configuration with multiple sources and validation.

```python
@dataclass
class CerberusConfig:
    """Main configuration model."""

    # Core settings
    project_name: str = "cerberus-scan"
    output_dir: Path = Path("./cerberus-output")

    # Analysis settings
    languages: List[str] = field(default_factory=lambda: ["auto"])
    exclude_patterns: List[str] = field(default_factory=list)
    max_file_size_mb: int = 10

    # LLM settings
    llm: LLMConfig = field(default_factory=LLMConfig)

    # Joern settings
    joern: JoernConfig = field(default_factory=JoernConfig)

    # Verification settings
    verification: VerificationConfig = field(default_factory=VerificationConfig)

    # Reporting settings
    report_formats: List[str] = field(default_factory=lambda: ["sarif", "console"])

    @classmethod
    def load(cls, cli_args: dict, project_path: Path) -> "CerberusConfig":
        """Load configuration from multiple sources (priority order)."""
        config = {}

        # 5. Default values
        config.update(cls._get_defaults())

        # 4. User config (~/.cerberus/config.yml)
        user_config = Path.home() / ".cerberus" / "config.yml"
        if user_config.exists():
            config.update(cls._load_yaml(user_config))

        # 3. Project config (.cerberus.yml)
        project_config = project_path / ".cerberus.yml"
        if project_config.exists():
            config.update(cls._load_yaml(project_config))

        # 2. Environment variables
        config.update(cls._load_env())

        # 1. CLI arguments (highest priority)
        config.update({k: v for k, v in cli_args.items() if v is not None})

        return cls(**config)
```

#### Configuration File Format
```yaml
# .cerberus.yml
project_name: my-project

analysis:
  languages:
    - python
    - javascript
  exclude_patterns:
    - "**/test/**"
    - "**/node_modules/**"
    - "**/*.min.js"
  max_file_size_mb: 5

llm:
  default_provider: ollama
  ollama:
    model: "qwen2.5-coder:32b"
  cache:
    enabled: true
    ttl: 3600

joern:
  endpoint: "localhost:8080"
  workspace: "./.cerberus/workspace"

verification:
  enabled: true
  council_mode: true  # Enable multi-agent council
  confidence_threshold: 0.7

reporting:
  formats:
    - sarif
    - html
    - console
  output_dir: "./security-reports"
```

---

### 5.4 Report Generator

**Purpose**: Generate reports in multiple formats.

#### Supported Formats
| Format | Use Case | Standard |
|--------|----------|----------|
| **SARIF** | CI/CD integration, GitHub/GitLab | OASIS SARIF 2.1.0 |
| **JSON** | Programmatic access | Custom schema |
| **HTML** | Human review | Interactive report |
| **Console** | Terminal output | Rich formatting |
| **Markdown** | Documentation | GitHub-flavored |

#### SARIF Output Structure
```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Cerberus SAST",
          "version": "1.0.0",
          "informationUri": "https://github.com/cerberus-sast/cerberus",
          "rules": [
            {
              "id": "CWE-89",
              "name": "SQL Injection",
              "shortDescription": {
                "text": "SQL Injection vulnerability detected"
              },
              "fullDescription": {
                "text": "User-controlled input flows to SQL query without sanitization"
              },
              "defaultConfiguration": {
                "level": "error"
              },
              "properties": {
                "precision": "high",
                "security-severity": "9.8"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "CWE-89",
          "level": "error",
          "message": {
            "text": "SQL Injection: User input from 'get_user_input' flows to 'execute_query' without sanitization"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "src/db/manager.py"
                },
                "region": {
                  "startLine": 128,
                  "startColumn": 5
                }
              }
            }
          ],
          "codeFlows": [
            {
              "threadFlows": [
                {
                  "locations": [
                    {
                      "location": {
                        "physicalLocation": {
                          "artifactLocation": {"uri": "src/handlers/request.py"},
                          "region": {"startLine": 42}
                        },
                        "message": {"text": "Source: user input received"}
                      }
                    },
                    {
                      "location": {
                        "physicalLocation": {
                          "artifactLocation": {"uri": "src/db/manager.py"},
                          "region": {"startLine": 128}
                        },
                        "message": {"text": "Sink: SQL query executed"}
                      }
                    }
                  ]
                }
              ]
            }
          ],
          "properties": {
            "cerberus": {
              "verification": {
                "verdict": "TRUE_POSITIVE",
                "confidence": 0.92,
                "attacker_argument": "...",
                "defender_argument": "...",
                "judge_reasoning": "..."
              }
            }
          }
        }
      ]
    }
  ]
}
```

---

## 6. Data Models

### 6.1 Core Models

```python
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Dict, Optional, Any
from datetime import datetime


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TaintLabel(Enum):
    SOURCE = "source"
    SINK = "sink"
    SANITIZER = "sanitizer"
    PROPAGATOR = "propagator"
    NONE = "none"


class Verdict(Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"


@dataclass
class CodeLocation:
    """Location in source code."""
    file_path: Path
    line: int
    column: int
    end_line: Optional[int] = None
    end_column: Optional[int] = None

    def to_uri(self) -> str:
        return f"{self.file_path}:{self.line}:{self.column}"


@dataclass
class Symbol:
    """Code symbol (function, class, variable)."""
    name: str
    type: str  # FUNCTION, CLASS, METHOD, VARIABLE
    file_path: Path
    line: int
    signature: Optional[str] = None
    docstring: Optional[str] = None
    references: List[CodeLocation] = field(default_factory=list)


@dataclass
class FileInfo:
    """Information about a source file."""
    path: Path
    language: str
    size_bytes: int
    lines: int
    symbols: List[Symbol] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)


@dataclass
class RepoMap:
    """Repository structural map."""
    root_path: Path
    files: List[FileInfo]
    symbols: List[Symbol]
    dependencies: Dict[str, List[str]]  # file -> [imported files]
    rankings: Dict[str, float]  # file -> PageRank score
    generated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class TaintSpec:
    """Single taint specification entry."""
    method: str
    class_name: Optional[str]
    file_path: Path
    line: int
    label: TaintLabel
    parameter_index: Optional[int] = None
    confidence: float = 0.0
    reason: str = ""


@dataclass
class DynamicSpec:
    """Complete dynamic specification for a repository."""
    version: str = "1.0"
    repository: str = ""
    generated_at: datetime = field(default_factory=datetime.utcnow)
    sources: List[TaintSpec] = field(default_factory=list)
    sinks: List[TaintSpec] = field(default_factory=list)
    sanitizers: List[TaintSpec] = field(default_factory=list)
    propagators: List[TaintSpec] = field(default_factory=list)

    def to_json(self) -> str:
        """Serialize to JSON."""
        ...

    @classmethod
    def from_json(cls, data: str) -> "DynamicSpec":
        """Deserialize from JSON."""
        ...


@dataclass
class TraceStep:
    """Single step in a vulnerability trace."""
    location: CodeLocation
    code_snippet: str
    description: str
    step_type: str  # source, propagation, sink


@dataclass
class SliceLine:
    """Single line in a program slice."""
    line_number: int
    code: str
    is_trace: bool  # Part of the direct trace
    annotation: Optional[str] = None


@dataclass
class ProgramSlice:
    """Minimal code context for verification."""
    source_location: CodeLocation
    sink_location: CodeLocation
    trace_lines: List[SliceLine]
    variable_definitions: List[Dict[str, Any]]
    control_structures: List[Dict[str, Any]]

    def to_code_string(self) -> str:
        """Render as readable code with line numbers."""
        lines = []
        for sl in sorted(self.trace_lines, key=lambda x: x.line_number):
            marker = ">>>" if sl.is_trace else "   "
            annotation = f"  // {sl.annotation}" if sl.annotation else ""
            lines.append(f"{marker} {sl.line_number:4d}: {sl.code}{annotation}")
        return "\n".join(lines)


@dataclass
class VerificationResult:
    """Result from the Multi-Agent Council."""
    verdict: Verdict
    confidence: float

    attacker_exploitable: bool
    attacker_input: Optional[str]
    attacker_trace: Optional[str]
    attacker_impact: Optional[str]
    attacker_reasoning: str

    defender_safe: bool
    defender_lines: List[int]
    defender_sanitization: Optional[str]
    defender_reasoning: str

    judge_reasoning: str
    missed_considerations: Optional[str] = None


@dataclass
class Finding:
    """Complete vulnerability finding."""
    id: str
    vulnerability_type: str  # CWE-XXX
    severity: Severity
    confidence: float

    source: TaintSpec
    sink: TaintSpec
    trace: List[TraceStep]

    slice: ProgramSlice

    verification: Optional[VerificationResult] = None

    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    scan_id: str = ""

    def is_verified_positive(self) -> bool:
        """Check if finding is a verified true positive."""
        return (
            self.verification is not None
            and self.verification.verdict == Verdict.TRUE_POSITIVE
        )


@dataclass
class ScanResult:
    """Complete scan result."""
    scan_id: str
    repository: str
    started_at: datetime
    completed_at: Optional[datetime]

    findings: List[Finding]

    # Statistics
    files_scanned: int
    lines_scanned: int
    sources_found: int
    sinks_found: int
    sanitizers_found: int

    # Timing
    phase_timings: Dict[str, float]  # phase -> seconds

    def summary(self) -> Dict[str, Any]:
        """Generate summary statistics."""
        verified = [f for f in self.findings if f.is_verified_positive()]
        return {
            "total_findings": len(self.findings),
            "verified_positives": len(verified),
            "by_severity": {
                s.value: len([f for f in verified if f.severity == s])
                for s in Severity
            },
            "by_type": self._group_by_type(verified),
        }
```

---

## 7. API Contracts

### 7.1 CLI Interface

```bash
# Main scan command
cerberus scan <path> [options]

Options:
  -o, --output PATH          Output file path
  -f, --format FORMAT        Output format: sarif|json|html|console|markdown
  -c, --config PATH          Configuration file path
  --fail-on SEVERITY         Exit with error if findings >= severity
  --exclude PATTERN          Glob patterns to exclude (can be repeated)
  --languages LANGS          Comma-separated list of languages
  --no-verify                Skip verification phase
  --council/--no-council     Enable/disable multi-agent council
  -v, --verbose              Verbose output
  -q, --quiet                Suppress non-error output

# Server mode
cerberus server [options]

Options:
  --host HOST                Bind host (default: 127.0.0.1)
  --port PORT                Bind port (default: 8080)
  --workers N                Number of worker processes

# Utility commands
cerberus languages           List supported languages
cerberus version             Show version information
cerberus init                Initialize .cerberus.yml in current directory
cerberus baseline create     Create baseline of existing findings
cerberus baseline update     Update baseline with current findings
```

#### Exit Codes
| Code | Meaning |
|------|---------|
| 0 | Success, no findings above threshold |
| 1 | Findings found above --fail-on threshold |
| 2 | Configuration or input error |
| 3 | Runtime error |

---

### 7.2 REST API (Server Mode)

#### Authentication
```http
POST /api/v1/auth/token
Content-Type: application/json

{
  "username": "string",
  "password": "string"
}

Response:
{
  "access_token": "string",
  "token_type": "bearer",
  "expires_in": 3600
}
```

#### Scan Endpoints

```yaml
# Start a new scan
POST /api/v1/scans
Authorization: Bearer <token>
Content-Type: application/json

Request:
{
  "path": "/path/to/code",
  "config": {
    "languages": ["python", "javascript"],
    "exclude_patterns": ["**/test/**"],
    "verification": {
      "enabled": true,
      "council_mode": true
    }
  }
}

Response: 201 Created
{
  "scan_id": "uuid",
  "status": "queued",
  "created_at": "2025-01-15T10:30:00Z"
}

---

# Get scan status
GET /api/v1/scans/{scan_id}
Authorization: Bearer <token>

Response: 200 OK
{
  "scan_id": "uuid",
  "status": "running",  # queued|running|completed|failed
  "progress": 0.45,
  "current_phase": "detection",
  "findings_count": 12,
  "started_at": "2025-01-15T10:30:05Z",
  "estimated_completion": "2025-01-15T10:35:00Z"
}

---

# Get scan results
GET /api/v1/scans/{scan_id}/results
Authorization: Bearer <token>

Response: 200 OK
{
  "scan_id": "uuid",
  "status": "completed",
  "completed_at": "2025-01-15T10:34:52Z",
  "summary": {
    "total_findings": 15,
    "verified_positives": 12,
    "by_severity": {
      "critical": 2,
      "high": 5,
      "medium": 3,
      "low": 2
    }
  },
  "findings": [
    {
      "id": "finding-uuid",
      "vulnerability_type": "CWE-89",
      "severity": "critical",
      "confidence": 0.95,
      "source": {...},
      "sink": {...},
      "trace": [...],
      "verification": {...}
    }
  ],
  "metadata": {
    "files_scanned": 150,
    "lines_scanned": 25000,
    "duration_seconds": 287
  }
}

---

# Get specific finding
GET /api/v1/scans/{scan_id}/findings/{finding_id}
Authorization: Bearer <token>

Response: 200 OK
{
  "id": "finding-uuid",
  "vulnerability_type": "CWE-89",
  ...
  "slice": {
    "code": "...",
    "source_location": {...},
    "sink_location": {...}
  },
  "verification": {
    "verdict": "TRUE_POSITIVE",
    "confidence": 0.95,
    "attacker_argument": "...",
    "defender_argument": "...",
    "judge_reasoning": "..."
  }
}

---

# Re-verify a finding
POST /api/v1/scans/{scan_id}/findings/{finding_id}/verify
Authorization: Bearer <token>

Response: 200 OK
{
  "verdict": "TRUE_POSITIVE",
  "confidence": 0.92,
  "reasoning": "..."
}

---

# Export results
GET /api/v1/scans/{scan_id}/export?format=sarif
Authorization: Bearer <token>

Response: 200 OK
Content-Type: application/json
(SARIF document)
```

#### WebSocket for Real-time Updates
```javascript
// Connect to scan progress stream
ws = new WebSocket("ws://localhost:8080/api/v1/scans/{scan_id}/stream")

// Messages received:
{
  "type": "progress",
  "phase": "detection",
  "progress": 0.67,
  "message": "Analyzing file 45/67"
}

{
  "type": "finding",
  "finding_id": "uuid",
  "preview": {
    "vulnerability_type": "CWE-89",
    "severity": "critical",
    "file": "src/db/manager.py",
    "line": 128
  }
}

{
  "type": "completed",
  "summary": {...}
}
```

---

## 8. Deployment Architecture

### 8.1 Docker Compose Stack

```yaml
version: "3.8"

services:
  cerberus:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    volumes:
      - ./data:/data
      - ./workspace:/workspace
    environment:
      - CERBERUS_JOERN_ENDPOINT=joern:8080
      - CERBERUS_OLLAMA_ENDPOINT=ollama:11434
      - CERBERUS_CHROMADB_ENDPOINT=chromadb:8000
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}
      - OPENAI_API_KEY=${OPENAI_API_KEY:-}
    depends_on:
      joern:
        condition: service_healthy
      ollama:
        condition: service_started
      chromadb:
        condition: service_started
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  joern:
    image: joernio/joern:latest
    command: ["joern", "--server", "--server-host", "0.0.0.0", "--server-port", "8080"]
    ports:
      - "8081:8080"
    volumes:
      - joern_workspace:/workspace
      - ./workspace:/code:ro
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    deploy:
      resources:
        limits:
          memory: 8G

  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
    volumes:
      - ollama_models:/root/.ollama
    environment:
      - OLLAMA_KEEP_ALIVE=24h
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]

  chromadb:
    image: chromadb/chroma:latest
    ports:
      - "8082:8000"
    volumes:
      - chroma_data:/chroma/chroma
    environment:
      - ANONYMIZED_TELEMETRY=false

volumes:
  joern_workspace:
  ollama_models:
  chroma_data:

networks:
  default:
    name: cerberus-network
```

### 8.2 Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[all]"

# Copy application code
COPY cerberus/ cerberus/

# Create non-root user
RUN useradd -m cerberus
USER cerberus

# Expose port
EXPOSE 8080

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command
CMD ["cerberus", "server", "--host", "0.0.0.0", "--port", "8080"]
```

### 8.3 Hardware Requirements

| Tier | RAM | GPU | Storage | Models | Use Case |
|------|-----|-----|---------|--------|----------|
| **Minimum** | 32GB | 12GB VRAM (RTX 4070) | 100GB SSD | Qwen 14B (4-bit) | Small projects (<100k LOC) |
| **Recommended** | 64GB | 24GB VRAM (RTX 3090/4090) | 250GB NVMe | Qwen 32B (4-bit) | Medium projects (<500k LOC) |
| **Optimal** | 128GB | 48GB+ VRAM or Apple M2/M3 Ultra | 500GB NVMe | Qwen 32B (FP16) | Large repos (1M+ LOC), multi-agent |

### 8.4 Network Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         DEPLOYMENT TOPOLOGY                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    EXTERNAL ACCESS                               │   │
│  │                                                                  │   │
│  │  ┌──────────┐      ┌──────────┐      ┌──────────┐              │   │
│  │  │   CLI    │      │  CI/CD   │      │  Web UI  │              │   │
│  │  │  Client  │      │ Pipeline │      │ (future) │              │   │
│  │  └────┬─────┘      └────┬─────┘      └────┬─────┘              │   │
│  │       │                 │                 │                     │   │
│  └───────┼─────────────────┼─────────────────┼─────────────────────┘   │
│          │                 │                 │                         │
│          └─────────────────┼─────────────────┘                         │
│                            │                                           │
│                       Port 8080                                        │
│                            │                                           │
│  ┌─────────────────────────┼───────────────────────────────────────┐   │
│  │                    INTERNAL NETWORK                              │   │
│  │                         │                                        │   │
│  │                    ┌────▼────┐                                   │   │
│  │                    │Cerberus │                                   │   │
│  │                    │ Server  │                                   │   │
│  │                    └────┬────┘                                   │   │
│  │                         │                                        │   │
│  │          ┌──────────────┼──────────────┐                        │   │
│  │          │              │              │                        │   │
│  │     ┌────▼────┐   ┌─────▼─────┐  ┌────▼────┐                   │   │
│  │     │  Joern  │   │  Ollama   │  │ChromaDB │                   │   │
│  │     │ :8081   │   │  :11434   │  │ :8082   │                   │   │
│  │     └─────────┘   └───────────┘  └─────────┘                   │   │
│  │                                                                  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Scalability Strategy

### 9.1 Map-Reduce for Large Repositories

For repositories exceeding available memory, Cerberus employs a Map-Reduce strategy:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        MAP-REDUCE PIPELINE                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                     MODULE DETECTION                             │   │
│  │                                                                  │   │
│  │  Analyze repository structure to identify independent modules:   │   │
│  │  - Separate packages/directories                                 │   │
│  │  - Low coupling between modules                                  │   │
│  │  - Clear public interfaces                                       │   │
│  │                                                                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                          │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                        MAP PHASE                                 │   │
│  │                                                                  │   │
│  │  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐         │   │
│  │  │Module A │   │Module B │   │Module C │   │Module D │   ...   │   │
│  │  │         │   │         │   │         │   │         │         │   │
│  │  │ - CPG   │   │ - CPG   │   │ - CPG   │   │ - CPG   │         │   │
│  │  │ - Specs │   │ - Specs │   │ - Specs │   │ - Specs │         │   │
│  │  │ - Finds │   │ - Finds │   │ - Finds │   │ - Finds │         │   │
│  │  └─────────┘   └─────────┘   └─────────┘   └─────────┘         │   │
│  │       │             │             │             │               │   │
│  │       └─────────────┴─────────────┴─────────────┘               │   │
│  │                              │                                   │   │
│  └──────────────────────────────┼──────────────────────────────────┘   │
│                                 │                                       │
│                                 ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                       REDUCE PHASE                               │   │
│  │                                                                  │   │
│  │  1. Extract public interfaces from each module                   │   │
│  │  2. Treat interfaces as Sources/Sinks for cross-module analysis │   │
│  │  3. Aggregate all findings                                       │   │
│  │  4. De-duplicate and merge verification results                  │   │
│  │                                                                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 9.2 Incremental Analysis

```python
class IncrementalAnalyzer:
    """Analyze only changed files when possible."""

    async def analyze_incremental(
        self,
        repo_path: Path,
        baseline_scan_id: str
    ) -> ScanResult:
        """Perform incremental analysis based on git diff."""

        # Get changed files since baseline
        changed_files = await self._get_changed_files(repo_path, baseline_scan_id)

        if not changed_files:
            return self._load_baseline_results(baseline_scan_id)

        # Determine affected scope
        affected_specs = self._find_affected_specs(changed_files)
        affected_findings = self._find_affected_findings(changed_files)

        # Re-analyze affected portions
        if affected_specs:
            # Spec changes require re-inference
            new_specs = await self.inference_engine.analyze(changed_files)
            await self._merge_specs(new_specs)

        # Re-run detection for affected findings
        new_findings = await self.detection_engine.analyze(
            files=changed_files,
            existing_findings=affected_findings
        )

        # Merge with baseline
        return self._merge_results(baseline_scan_id, new_findings)

    def _get_changed_files(self, repo_path: Path, baseline_scan_id: str) -> List[Path]:
        """Get list of files changed since baseline scan."""
        baseline = self._load_baseline(baseline_scan_id)

        result = subprocess.run(
            ["git", "diff", "--name-only", baseline.commit_hash, "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True
        )

        return [repo_path / f for f in result.stdout.strip().split("\n") if f]
```

### 9.3 Caching Strategy

| Cache | Location | TTL | Invalidation |
|-------|----------|-----|--------------|
| LLM responses | Memory/Redis | 1 hour | Prompt hash change |
| CPG | Joern workspace | Until code change | File modification |
| Embeddings | ChromaDB | Persistent | File modification |
| Specifications | Disk | Per-scan | Re-inference trigger |

---

## 10. Error Handling & Resilience

### 10.1 Error Categories and Strategies

| Error Type | Detection | Strategy | User Impact |
|------------|-----------|----------|-------------|
| **Joern parse failure** | Exception from CPG import | Skip file, log warning, continue | Partial coverage |
| **LLM timeout** | Request timeout | Retry 3x with exponential backoff | Delayed results |
| **LLM rate limit** | 429 response | Switch to fallback provider | Transparent |
| **LLM hallucination** | CPGQL syntax validation | Regenerate with corrective prompt | Slight delay |
| **Out of memory** | MemoryError | Reduce batch size, enable disk spillover | Slower analysis |
| **Network failure** | Connection errors | Offline mode with cached models | Limited LLM features |
| **Invalid configuration** | Validation errors | Clear error message, exit | No analysis |

### 10.2 Retry Logic

```python
class RetryPolicy:
    """Configurable retry policy for resilient operations."""

    def __init__(
        self,
        max_attempts: int = 3,
        backoff_factor: float = 2.0,
        max_backoff: float = 60.0,
        retryable_exceptions: tuple = (TimeoutError, ConnectionError)
    ):
        self.max_attempts = max_attempts
        self.backoff_factor = backoff_factor
        self.max_backoff = max_backoff
        self.retryable_exceptions = retryable_exceptions

    async def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with retry logic."""
        last_exception = None

        for attempt in range(self.max_attempts):
            try:
                return await func(*args, **kwargs)
            except self.retryable_exceptions as e:
                last_exception = e
                if attempt < self.max_attempts - 1:
                    wait_time = min(
                        self.backoff_factor ** attempt,
                        self.max_backoff
                    )
                    logger.warning(
                        f"Attempt {attempt + 1} failed: {e}. "
                        f"Retrying in {wait_time}s..."
                    )
                    await asyncio.sleep(wait_time)

        raise last_exception
```

### 10.3 Graceful Degradation

```python
class GracefulDegradation:
    """Handle failures gracefully with fallback behavior."""

    async def analyze_with_fallbacks(self, files: List[Path]) -> ScanResult:
        """Analyze files with graceful degradation on failures."""

        results = ScanResult()

        for file in files:
            try:
                # Full analysis pipeline
                finding = await self._full_analysis(file)
                results.add(finding)

            except JoernParseError as e:
                # Fallback: Skip file, log warning
                logger.warning(f"Could not parse {file}: {e}")
                results.add_skipped(file, reason=str(e))

            except LLMUnavailableError:
                # Fallback: Pattern-based detection only
                logger.warning("LLM unavailable, using pattern matching only")
                finding = await self._pattern_only_analysis(file)
                finding.confidence *= 0.5  # Lower confidence
                results.add(finding)

            except VerificationError as e:
                # Fallback: Report unverified finding
                logger.warning(f"Verification failed: {e}")
                finding = await self._detection_only(file)
                finding.verification = None
                results.add(finding)

        return results
```

---

## 11. Security Considerations

### 11.1 Data Protection

| Concern | Mitigation |
|---------|------------|
| **Code confidentiality** | All analysis runs locally by default; no code leaves the system |
| **LLM data exposure** | Ollama (local) is primary; cloud fallbacks are opt-in and use API only (no training) |
| **Credential leakage** | Secret detection warns if credentials found; never includes secrets in reports |
| **Report security** | SARIF reports contain code snippets - handle as confidential |

### 11.2 Secure Configuration

```yaml
# Secure defaults in .cerberus.yml
security:
  # Only use local LLM by default
  allow_cloud_llm: false

  # Sanitize reports
  redact_secrets: true
  redact_file_paths: false

  # API security
  api:
    require_auth: true
    token_expiry: 3600
    rate_limit: 100  # requests per minute
```

### 11.3 Joern Isolation

```yaml
# Docker security for Joern
joern:
  image: joernio/joern:latest
  security_opt:
    - no-new-privileges:true
  read_only: true
  tmpfs:
    - /tmp
  volumes:
    - ./workspace:/workspace:ro  # Read-only code access
    - joern_data:/joern-data      # Writable workspace
  cap_drop:
    - ALL
```

### 11.4 API Authentication

```python
class JWTAuth:
    """JWT-based authentication for API server."""

    def __init__(self, secret_key: str, algorithm: str = "HS256"):
        self.secret_key = secret_key
        self.algorithm = algorithm

    def create_token(self, user_id: str, expires_in: int = 3600) -> str:
        """Create JWT token."""
        payload = {
            "sub": user_id,
            "exp": datetime.utcnow() + timedelta(seconds=expires_in),
            "iat": datetime.utcnow()
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def verify_token(self, token: str) -> Optional[str]:
        """Verify JWT token and return user_id."""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )
            return payload.get("sub")
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token expired")
        except jwt.InvalidTokenError:
            raise AuthenticationError("Invalid token")
```

---

## 12. Implementation Roadmap

### Phase 1: Foundation (Week 1-2)
- [ ] Project structure and CLI skeleton (Click)
- [ ] Configuration management (Pydantic)
- [ ] Joern client wrapper (`cpgqls-client`)
- [ ] Basic LLM gateway (Ollama provider)
- [ ] Logging and error handling infrastructure

### Phase 2: Context Engine (Week 3-4)
- [ ] Tree-sitter integration for multi-language parsing
- [ ] Symbol extraction from ASTs
- [ ] Dependency graph construction (NetworkX)
- [ ] PageRank implementation
- [ ] ChromaDB vector store integration
- [ ] Embedding generation

### Phase 3: Spec Inference (Week 5-6)
- [ ] CPGQL candidate extraction queries
- [ ] LLM classification prompts and parsing
- [ ] Taint propagation algorithm
- [ ] Dynamic specification writer
- [ ] `context_rules.json` format

### Phase 4: Detection Engine (Week 7-8)
- [ ] CPGQL query generation via LLM
- [ ] Query validation and execution
- [ ] Flow analysis result parsing
- [ ] Program slicer implementation
- [ ] Trace extraction and formatting

### Phase 5: Verification Agent (Week 9-10)
- [ ] Attacker agent implementation
- [ ] Defender agent implementation
- [ ] Judge agent implementation
- [ ] Multi-agent council orchestration
- [ ] Feedback loop to spec inference
- [ ] Confidence scoring

### Phase 6: Production Hardening (Week 11-12)
- [ ] REST API server (FastAPI)
- [ ] WebSocket for real-time updates
- [ ] Report generation (SARIF, JSON, HTML)
- [ ] Authentication and authorization
- [ ] Docker Compose deployment
- [ ] Performance optimization
- [ ] Documentation and examples

---

## 13. File Structure

```
cerberus-sast/
├── cerberus/
│   ├── __init__.py
│   ├── __main__.py                    # Entry point
│   │
│   ├── cli/
│   │   ├── __init__.py
│   │   ├── commands.py                # Click CLI commands
│   │   └── server.py                  # FastAPI server
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py                  # Configuration management
│   │   ├── pipeline.py                # Main analysis pipeline
│   │   └── orchestrator.py            # Phase orchestration
│   │
│   ├── context/
│   │   ├── __init__.py
│   │   ├── repo_mapper.py             # Repository mapping coordinator
│   │   ├── tree_sitter_parser.py      # Tree-sitter integration
│   │   ├── symbol_extractor.py        # Symbol extraction
│   │   ├── pagerank.py                # PageRank implementation
│   │   └── vector_store.py            # ChromaDB integration
│   │
│   ├── inference/
│   │   ├── __init__.py
│   │   ├── candidate_extractor.py     # CPGQL candidate queries
│   │   ├── classifier.py              # LLM classification
│   │   ├── propagator.py              # Taint propagation
│   │   └── spec_writer.py             # Dynamic spec generation
│   │
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── joern_client.py            # Joern server client
│   │   ├── query_generator.py         # CPGQL generation
│   │   ├── flow_analyzer.py           # Data flow analysis
│   │   └── slicer.py                  # Program slicing
│   │
│   ├── verification/
│   │   ├── __init__.py
│   │   ├── council.py                 # Multi-agent orchestration
│   │   ├── attacker_agent.py          # Attacker agent
│   │   ├── defender_agent.py          # Defender agent
│   │   ├── judge_agent.py             # Judge agent
│   │   └── feedback.py                # Feedback loop handling
│   │
│   ├── llm/
│   │   ├── __init__.py
│   │   ├── gateway.py                 # Unified LLM interface
│   │   ├── providers/
│   │   │   ├── __init__.py
│   │   │   ├── base.py                # Provider base class
│   │   │   ├── ollama.py              # Ollama provider
│   │   │   ├── anthropic.py           # Anthropic provider
│   │   │   └── openai.py              # OpenAI provider
│   │   └── prompts/
│   │       ├── __init__.py
│   │       ├── classification.py      # Source/sink classification
│   │       ├── query_gen.py           # CPGQL generation
│   │       └── verification.py        # Attacker/defender/judge
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── base.py                    # Base model classes
│   │   ├── repo_map.py                # Repository map models
│   │   ├── spec.py                    # Dynamic specification models
│   │   ├── finding.py                 # Finding and result models
│   │   └── slice.py                   # Program slice models
│   │
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── base.py                    # Reporter base class
│   │   ├── sarif.py                   # SARIF output
│   │   ├── json_report.py             # JSON output
│   │   ├── html_report.py             # HTML output
│   │   ├── console.py                 # Console output
│   │   └── templates/                 # HTML templates
│   │
│   └── utils/
│       ├── __init__.py
│       ├── logging.py                 # Logging configuration
│       ├── async_utils.py             # Async utilities
│       └── git.py                     # Git integration
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py                    # Pytest fixtures
│   ├── test_context/
│   ├── test_inference/
│   ├── test_detection/
│   ├── test_verification/
│   └── fixtures/                      # Test code samples
│
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
│
├── docs/
│   ├── ARCHITECTURE.md                # This document
│   ├── API.md                         # API documentation
│   └── CONTRIBUTING.md
│
├── .cerberus.yml.example              # Example configuration
├── pyproject.toml                     # Project configuration
├── README.md
├── CLAUDE.md                          # Claude Code guidance
└── SPECIFICATIONS.md                  # Original specifications
```

---

## Appendix A: CPGQL Quick Reference

```scala
// Node types
cpg.method                    // All methods
cpg.call                      // All function calls
cpg.parameter                 // All parameters
cpg.identifier                // All identifiers
cpg.literal                   // All literals
cpg.typeDecl                  // All type declarations

// Filtering
.name("pattern")              // Filter by name (regex)
.nameExact("exact")           // Filter by exact name
.signature(".*int.*")         // Filter by signature
.isPublic / .isPrivate        // Visibility filters

// Data flow
.reachableBy(source)          // All nodes reachable from source
.reachableByFlows(source)     // Data flow paths from source
.controlledBy(condition)      // Nodes controlled by condition

// Traversal
.caller                       // Methods calling this
.callee                       // Methods called by this
.parameter                    // Parameters of method
.argument                     // Arguments of call

// Output
.toJson                       // Output as JSON
.l                            // Output as list
.p                            // Pretty print
```

---

## Appendix B: CWE Coverage

Cerberus targets detection of these vulnerability categories:

| CWE | Name | Detection Method |
|-----|------|------------------|
| CWE-78 | OS Command Injection | Source→exec/system sink |
| CWE-79 | Cross-site Scripting | Source→HTML output sink |
| CWE-89 | SQL Injection | Source→SQL query sink |
| CWE-94 | Code Injection | Source→eval/exec sink |
| CWE-119 | Buffer Overflow | Unsafe memory operations |
| CWE-200 | Information Exposure | Sensitive data→log/output |
| CWE-22 | Path Traversal | Source→file path sink |
| CWE-352 | CSRF | Form without token |
| CWE-434 | Unrestricted Upload | File upload without validation |
| CWE-502 | Deserialization | Untrusted data→deserialize |
| CWE-611 | XXE | XML parsing without protection |
| CWE-918 | SSRF | User input→URL fetch |

---

*Document Version: 1.0*
*Last Updated: 2025-01-15*
*Generated for: Cerberus SAST v1.0*
