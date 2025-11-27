# **Cerberus SAST: Architecting a Self-Configuring, Neuro-Symbolic Application Security Pipeline**

## **Executive Summary**

The modern software development lifecycle (SDLC) has outpaced the capabilities of traditional security assurance methodologies. For over two decades, the industry has relied on Static Application Security Testing (SAST) tools predicated on rigid, manually curated rulesets. These deterministic engines operate on a fundamental assumption: that the security architect can predict every potential data flow, entry point (Source), and hazardous execution point (Sink) within an application. In an era of microservices, polyglot repositories, and rapid framework evolution, this assumption has collapsed. The resulting "Configuration Gap" leaves vast swathes of application logic unmonitored, while the lack of semantic context in rule-based checkers generates False Positive (FP) rates often exceeding 50%, forcing engineering teams to choose between velocity and security.1

This report presents a comprehensive architectural blueprint for a next-generation, local, AI-driven security analysis tool designed to transcend these limitations. The proposed system is **Self-Configuring**, autonomously inferring the unique logic and data flow patterns of the target application without manual query generation. It is **Neuro-Symbolic**, fusing the probabilistic reasoning capabilities of Large Language Models (LLMs) with the mathematical precision of Code Property Graphs (CPGs). Finally, it is **Agentic**, employing recursive verification loops to achieve a target false positive rate of less than 5%.

By leveraging recent breakthroughs in open-source LLMs (specifically Qwen 2.5 Coder and DeepSeek Coder V2), high-performance graph databases (Joern), and advanced repository mapping algorithms (Tree-sitter driven PageRank), this architecture can be deployed entirely within a local infrastructure. This ensures data sovereignty, eliminates cloud latency, and provides a scalable, exhaustive, and precise mechanism for vulnerability discovery. The following chapters detail the theoretical foundations, component design, and implementation strategies required to construct this autonomous pipeline.

---

## **1\. The Crisis of Deterministic Analysis and the Neuro-Symbolic Imperative**

### **1.1 The Stagnation of Rule-Based SAST**

To understand the necessity of a self-configuring architecture, one must first dissect the failure modes of traditional SAST. Conventional static analysis relies on *Taint Tracking*, a technique that monitors the flow of untrusted data (Taint) from a Source to a Sink. If the data reaches a Sink without passing through a Sanitizer, a vulnerability is flagged.3

However, the efficacy of Taint Tracking is strictly bound by the quality of its *Taint Specifications*—the predefined list of what constitutes a Source, Sink, or Sanitizer. In commercial tools (e.g., Fortify, Checkmarx, CodeQL), these specifications are hardcoded by the vendor. They cover standard libraries (e.g., javax.servlet.http.HttpServletRequest), but fail catastrophically when encountering:

* **Custom Frameworks:** If an organization wraps incoming requests in a proprietary IngestManager class, standard tools will not recognize it as a Source, leading to False Negatives (FNs).1  
* **Internal APIs:** In large monoliths or microservices, data often flows through internal utility layers. Without explicit rules for these internal boundaries, the analysis chain is broken.3  
* **Contextual Sanitization:** Deterministic tools struggle to recognize sanitization that doesn't look like a standard filter function. For instance, an if condition that checks type(input) \== int is a valid sanitizer for SQL Injection, but a rule-based engine looking for escapeSQLString() will miss it, flagging a False Positive.6

The result is a "Configuration Gap" where security teams spend exorbitant amounts of time manually writing custom queries—a non-scalable solution. Furthermore, the inability of static engines to understand *intent* and *semantics* leads to an avalanche of noise. Industry benchmarks consistently show that without heavy tuning, conventional SAST tools suffer from poor precision, often overwhelming developers with alerts that are technically reachable but logically impossible.8

### **1.2 The Neuro-Symbolic Renaissance**

The solution lies in **Neuro-Symbolic AI**, a hybrid approach that marries the two dominant paradigms of artificial intelligence: *Symbolic AI* (logic, graphs, formal verification) and *Connectionist AI* (Neural Networks, LLMs).1

In a security context, LLMs provide the "Neuro" capability: they possess "Common Sense" and semantic understanding. An LLM can read a function named fetch\_user\_input\_from\_socket and infer that it is likely a Source, even if it has never seen the code before. It can read a comment saying "This function sanitizes the input" and understand the developer's intent.8

However, LLMs suffer from hallucinations and a limited context window. They cannot reliably track data flow across 50 files in a million-line repository. This is where the "Symbolic" capability enters. Tools like **Joern** generate **Code Property Graphs (CPGs)**, which are graph-based representations of code that combine Abstract Syntax Trees (ASTs), Control Flow Graphs (CFGs), and Program Dependence Graphs (PDGs). A CPG allows for mathematically rigorous, exhaustive reachability analysis.11

The proposed **Self-Configuring Pipeline** leverages the LLM to *generate the rules* (Specifications) dynamically by reading the code, and the CPG to *execute the analysis* exhaustively. This symbiotic relationship covers the blind spots of both technologies: the LLM provides the adaptability that the CPG lacks, and the CPG provides the scalability and ground truth that the LLM lacks.13

### **1.3 Defining the Target State: \<5% False Positives**

Achieving a sub-5% false positive rate—a figure significantly lower than the industry standard—requires a fundamental architectural shift. It demands that the system typically performed by a human analyst: Verification.  
In a manual triage process, a human reviews a raw finding by examining the code path, checking for logical contradictions (e.g., "This path requires admin=true but the input is hardcoded to guest"), and verifying sanitization. The "Agentic" aspect of our architecture automates this. By extracting the specific Slice of code responsible for a vulnerability and presenting it to a reasoning engine (LLM), we can filter out findings that are theoretically reachable but practically impossible.8 Research indicates that such "Post-Refinement" or "LLM-as-Judge" strategies can reduce false positives by over 43-90%, bringing the \<5% goal within reach.1

---

## **2\. Architectural Principles of the Self-Configuring Pipeline (NSSCP)**

The **Neuro-Symbolic Self-Configuring Pipeline (NSSCP)** is not a single monolithic scanner but a distributed system of specialized agents and engines operating in a feedback loop. It is designed to run locally, respecting data privacy and eliminating the latency and cost of cloud-based inference.

### **2.1 Design Philosophy: Local, Modular, and Scalable**

To satisfy the requirement of local execution without reliance on hardcoded rules, the architecture adopts the following principles:

1. **Context-First Mapping:** Before analysis begins, the system must understand the "Shape" of the codebase. This prevents the "Context Window Overflow" problem inherent in LLMs.16  
2. **Dynamic Specification:** The system must never assume it knows the sources and sinks. It must rediscover them for every scan.1  
3. **Graph-Based Execution:** Heavy data flow analysis must be offloaded to optimized graph databases, not performed by the LLM token-by-token.12  
4. **Agentic Verification:** Every finding is a *hypothesis* that must be verified by a reasoning agent before reporting.8

### **2.2 High-Level Component Architecture**

The pipeline is divided into four distinct phases, each powered by specific technologies optimized for local deployment.

| Phase | Component Name | Primary Function | Core Technology |
| :---- | :---- | :---- | :---- |
| **I. Context** | **Repository Mapper** | Generates a structural map of the codebase to guide agents. | Tree-sitter, PageRank, Python 21 |
| **II. Inference** | **Spec Inference Engine** | Autonomously identifies Sources, Sinks, and Sanitizers. | Qwen 2.5 Coder, Joern 23 |
| **III. Detection** | **Hybrid Graph Engine** | Translates specs into queries and executes taint analysis. | Joern (CPGQL), OverflowDB 11 |
| **IV. Verification** | **Reasoning Agent** | Filters false positives via semantic logic and slicing. | DeepSeek V2, LLMxCPG 26 |

### **2.3 The Feedback Loop**

Unlike a linear pipeline, the NSSCP operates cyclically. The **Verification Agent** (Phase IV) feeds back into the **Spec Inference Engine** (Phase II). If the verifier determines that a detected path is a False Positive because of a missed sanitizer (e.g., clean\_data()), this function is added to the "Sanitizer" list, and the Detection Engine runs again. This continuous learning loop allows the tool to "Self-Configure" more accurately with each iteration.8

---

## **3\. Phase I: The Context Engine – Mapping the Territory**

The first challenge in AI-driven analysis is scale. Passing a million lines of code to an LLM is impossible. We need a way to "Map" the repository so that the AI knows where to look. This is the role of the **Context Engine**.

### **3.1 The Repository Map Strategy**

Recent innovations in AI coding assistants, particularly **Aider** and **RepoMapper**, have introduced the concept of a **Repository Map** (Repo Map). A Repo Map is a compressed representation of the codebase that captures the relationships between files and symbols without including the full implementation details.22

Implementation Mechanism:  
To generate this map locally and efficiently, we utilize Tree-sitter, a parser generator tool and incremental parsing library.

1. **Universal Parsing:** Tree-sitter parses the source code of every file into a concrete syntax tree (CST). Unlike regex-based scanning, this provides a true structural understanding of the code.27  
2. **Symbol Extraction:** We traverse the syntax trees to extract "Definitions" (classes, functions, global variables) and "References" (calls to those definitions).  
3. **Graph Construction:** We build a lightweight graph where nodes represent files or symbols, and edges represent dependencies (imports, calls, inheritance).21

### **3.2 Algorithmic Ranking via PageRank**

In a large repository, not all files are equal. A utils.js file might be referenced by 90% of the codebase, making it highly relevant for context. A singular test script might be referenced by nothing. To capture this "Relevance," we apply the **PageRank** algorithm to the dependency graph.21

PageRank assigns a centrality score to each node. When the LLM later needs to understand the "Authentication Logic," the Context Engine uses these scores to prioritize which files to present in the context window. It selects the most interconnected (central) files first, ensuring the LLM sees the backbone of the application structure rather than peripheral scripts. This technique effectively solves the scalability problem for the initial "understanding" phase.27

### **3.3 Integration with Vector Stores (RAG)**

While the Repo Map provides structural context, we also need semantic search. The Context Engine chunks the code (by function/method) and embeds it using a code-optimized embedding model (e.g., stella\_en\_400M or jina-embeddings-v2). These embeddings are stored in a local vector database (e.g., **ChromaDB** or **FAISS**). This allows the subsequent agents to perform Retrieval-Augmented Generation (RAG) queries like "Show me all functions that handle SQL execution".30

---

## **4\. Phase II: The Code Property Graph (CPG) – The Symbolic Backbone**

While the Repo Map is excellent for LLM navigation, it is insufficient for precise data flow analysis. For this, we require a rigorous mathematical model of the code: the **Code Property Graph (CPG)**.

### **4.1 The CPG Architecture**

The CPG, pioneered by the researchers behind **Joern**, creates a unified graph that overlays three distinct representations of the program 26:

1. **Abstract Syntax Tree (AST):** Represents the hierarchical structure of the code (blocks, statements, expressions).  
2. **Control Flow Graph (CFG):** Represents the order of execution (paths, loops, conditions).  
3. **Program Dependence Graph (PDG):** Represents the flow of data (Data Dependency) and the impact of conditions on execution (Control Dependency).

By merging these, the CPG enables complex queries such as: "Find all paths where variable x (defined in AST) flows to function y (via PDG) without passing through function z (via CFG)."

### **4.2 Local Deployment with Joern**

For the NSSCP, we utilize **Joern** as the underlying graph database engine. Joern is open-source, runs locally via Docker, and supports C/C++, Java, Python, JavaScript, and more. It uses **OverflowDB**, a graph database optimized for keeping large graphs in memory while spilling to disk if necessary, enabling it to handle repositories with millions of lines of code on consumer hardware.11

The Role of the CPG:  
The CPG serves as the "Ground Truth" for the pipeline. While the LLM infers what to look for (the specifications), the CPG determines if it exists (the reachability). This decoupling is critical for performance; using an LLM to trace data flow token-by-token is slow and error-prone (hallucinations), whereas a graph traversal is deterministic and milliseconds fast.12

---

## **5\. Phase III: Autonomous Specification Inference – The "Self-Configuring" Engine**

This phase distinguishes the NSSCP from traditional tools. Instead of relying on a static list of rules, the **Spec Inference Engine** autonomously models the application's logic to discover sources and sinks.

### **5.1 The Inference Workflow**

The "Self-Configuration" process is an iterative interaction between the CPG and the Inference LLM.

Step 1: Candidate Extraction (Symbolic Filtering)  
First, we use the CPG to identify "Candidate Functions." We query the graph for all functions that:

* Have external visibility (public methods in controllers).  
* Interact with low-level I/O libraries (file system, network sockets, database drivers).  
* Have high PageRank centrality scores (from Phase I).  
  This creates a filtered list of potentially interesting functions, drastically reducing the search space for the LLM.3

Step 2: Semantic Classification (Neural Reasoning)  
We then feed these candidates to the Inference LLM (e.g., Qwen 2.5 Coder 32B). The prompt includes the function signature, its docstring (if available), and the variable names of its arguments. The LLM is tasked with a classification problem:

* *Is this a Source?* (Does it accept untrusted input?)  
* *Is this a Sink?* (Does it execute a sensitive operation?)  
* *Is this a Sanitizer?* (Does it validate/clean data?)

Prompt Engineering Strategy:  
To maximize accuracy, we use a Few-Shot Prompt with Chain-of-Thought (CoT) instructions.

* *Input:* def get\_user\_query(request): return request.args.get('q')  
* *Prompt:* "Analyze the function get\_user\_query. Based on its name and implementation, it retrieves data from a request object. In web contexts, this is typically an entry point for untrusted data. Therefore, classify as Source.".14

Step 3: Internal API Resolution  
Crucially, the engine must identify internal APIs. If get\_user\_query calls internal\_helper, and internal\_helper returns the data, then internal\_helper is also a source. The Inference Engine propagates these labels across the call graph. If a Source flows into a function, and that function returns the data, the function is promoted to a "Taint Propagator".4

### **5.2 Dynamic Specification Generation**

The output of this phase is a **Dynamic Specification File** (e.g., context\_rules.json). This file is unique to the specific repository being analyzed.

* *Example Content:*  
  JSON  
  {  
    "sources":,  
    "sinks":  
  }

This file effectively "configures" the detection engine, ensuring exhaustive coverage of the application's custom logic.1

---

## **6\. Phase IV: Hybrid Vulnerability Detection – From Specs to Queries**

With the rules defined, the system must now find the violations. We employ a **Translation Agent** to bridge the gap between the JSON specifications and the complex query language of the graph database.

### **6.1 LLM-Driven Query Generation (CPGQL)**

Writing CPGQL (Joern's query language) is complex. Instead of hardcoding templates, we use a fine-tuned LLM (or a specialized prompt on a general coder model) to translate the Dynamic Specifications into CPGQL queries.33

**The Translation Process:**

1. **Input:** A Source/Sink pair from context\_rules.json.  
2. **Instruction:** "Generate a Joern query to find all data flow paths from APIController.handle\_request to DatabaseWrapper.run\_query."  
3. **Generation:** The LLM outputs the Scala code:  
   Scala  
   cpg.method("handle\_request").call  
     .argument  
     .reachableByFlows(cpg.method("run\_query").call.argument)

4. **Execution:** The system executes this query against the local Joern instance.

This approach is highly scalable because the heavy lifting—traversing the millions of potential paths in the graph—is done by the optimized C++ logic of the graph database, not the LLM. The LLM acts only as the interface.11

### **6.2 The Slicing Strategy (LLMxCPG)**

When Joern identifies a path, it returns a "Trace"—a sequence of line numbers. However, a raw trace is often insufficient for verification. We need the Program Slice.  
A Program Slice contains the detected path plus the relevant context: the variable definitions, the control structures (if, while) governing the path, and any intervening function calls. We utilize the CPG to extract this slice programmatically.  
Research from the LLMxCPG framework demonstrates that CPG-based slicing can reduce the code volume by 90% compared to sending full files, while retaining 100% of the vulnerability-relevant context. This is the key to enabling the next phase: Agentic Verification.26

---

## **7\. Phase V: The Verification Agent – Achieving \<5% False Positives**

The static analysis engine (Joern) acts as a high-recall filter. It will find *potential* vulnerabilities, but it will also flag false positives due to infeasible paths or complex sanitization it doesn't understand. To achieve the \<5% FP target, we deploy the **Verification Agent**.

### **7.1 The "LLM-as-Judge" Architecture**

The Verification Agent is a high-reasoning LLM (e.g., DeepSeek V2 or Llama 3\) tasked with reviewing the findings. It acts as a virtual security auditor.

**Input:**

1. **The Trace:** The sequence of steps from Source to Sink.  
2. **The Slice:** The minimal code context extracted in Phase IV.  
3. **The Vulnerability Definition:** A description of the flaw (e.g., "SQL Injection occurs when untrusted data is concatenated into a query string").

Reasoning Process (Chain-of-Thought):  
We utilize a structured reasoning prompt that forces the agent to think step-by-step:

1. **Trace Verification:** "Does the variable user\_input actually reach the execute() function?"  
2. **Sanitization Check:** "Is user\_input modified? Look for validation functions like is\_numeric() or encoding functions like base64\_encode()."  
3. **Logic Check:** "Are there if conditions that prevent execution? (e.g., if (false) exec(user\_input))."  
4. **Verdict:** "Classify as True Positive or False Positive."

### **7.2 Empirical Validation of Precision**

The efficacy of this approach is supported by recent research. **AdaTaint** 1 demonstrated a **43.7% reduction** in false positives by combining static analysis with neuro-symbolic reasoning. **LLMxCPG** 26 showed that providing precise slices allows LLMs to classify vulnerabilities with high accuracy, filtering out noise that confuses traditional scanners. **ZeroFalse** 8 further confirms that providing CWE-specific context to the LLM significantly boosts precision.

### **7.3 Agentic Adversarial Verification (The Council)**

To further drive down FPs, we can implement a **Multi-Agent Council**:

* **The Attacker Agent:** Tries to formulate a specific input string that would exploit the code slice.  
* **The Defender Agent:** Argues why the code is safe (pointing to specific lines).  
* The Judge Agent: Reviews the debate. If the Attacker cannot produce a viable exploit theory, the finding is discarded.  
  This adversarial dynamic mimics a real-world code review and provides a robust filter against "theoretical" but "practically impossible" bugs.20

---

## **8\. Implementation Strategy & Operationalization**

Constructing this pipeline locally requires careful selection of hardware and software components.

### **8.1 Hardware Requirements**

Local execution of 30B+ parameter models and large graph databases requires significant compute.

* **Minimum:** 32GB RAM, NVIDIA GPU with 12GB VRAM (e.g., RTX 4070). Capable of running quantized (4-bit) 14B models.  
* **Recommended:** 64GB RAM, NVIDIA GPU with 24GB VRAM (e.g., RTX 3090/4090). Capable of running **Qwen 2.5 Coder 32B (4-bit)**, which is the current sweet spot for coding performance.36  
* **Optimal:** Apple Studio (M2/M3 Ultra) with 128GB Unified Memory, or Dual-GPU workstations. Allows for unquantized models and concurrent agent execution.

### **8.2 The Software Stack (Dockerized)**

The entire pipeline should be containerized for reproducibility.

1. **Graph Database:** joernio/joern:latest. Provides the CPG generation and query interface.38  
2. **Inference Server:** vllm/vllm-openai. A high-throughput server for hosting the LLM locally, exposing an OpenAI-compatible API. This allows the agents to swap models easily.39  
3. **Orchestrator:** A Python application using LangChain or LlamaIndex to manage the agents. It handles the logic of: Repo Map \-\> Spec Inference \-\> Joern Query \-\> Verification.  
4. **Vector Store:** chromadb (embedded) for storing code embeddings for RAG.

### **8.3 Handling Scale: The Map-Reduce Strategy**

For repositories exceeding millions of lines of code, a single CPG may be too large for memory. We employ a **Map-Reduce** strategy:

* **Map:** The Repo Mapper identifies "Modules" (independent sub-directories). The Spec Inference and CPG generation run on each module in parallel.  
* **Reduce:** The "Public Interface" of each module is treated as a Source/Sink for other modules. The Spec Inference engine aggregates these interfaces to trace cross-module flows.16

### **8.4 Model Selection Benchmarks**

Based on current benchmarks (late 2025):

* **Qwen 2.5 Coder 32B:** The preferred model for **Spec Inference** and **Query Generation**. It outperforms GPT-4 on some coding benchmarks and has excellent instruction following.23  
* **DeepSeek Coder V2:** Excellent for **Verification** due to its massive context window (128k) and strong reasoning capabilities. It is ideal for analyzing large code slices.23

## **Conclusion**

The architecture outlined in this report represents a definitive move away from the brittle, manual, and noisy world of traditional SAST. By embracing a **Self-Configuring, Neuro-Symbolic** design, we create a tool that adapts to the application it scans, writing its own rules and verifying its own findings.

The combination of **Repo Mapping** for context, **CPGs** for exhaustive ground truth, **LLMs** for semantic inference, and **Agentic Verification** for precision creates a pipeline that is both scalable and accurate. With the availability of powerful open-source models like Qwen and DeepSeek, and robust tools like Joern, this architecture is not just a theoretical ideal but a practical reality that can be built and deployed locally today, securing the software of tomorrow.

---

## **Appendix: Component & Technology Selection Matrix**

| Component | Recommended Tool | Alternative | Reason for Recommendation |
| :---- | :---- | :---- | :---- |
| **Parser** | **Tree-sitter** | ANTLR | Fastest incremental parsing; massive language support; Python bindings.27 |
| **Graph DB** | **Joern (OverflowDB)** | Neo4j | Optimized specifically for code (CPG); creates specific security graphs (PDG) natively.12 |
| **Repo Map** | **RepoMapper / Aider** | Ctags | Uses PageRank for relevance; captures full signatures needed for LLM context.21 |
| **LLM (Code)** | **Qwen 2.5 Coder 32B** | CodeLlama 34B | Current SOTA for open-source coding; excellent instruction following for CPGQL.41 |
| **LLM (Logic)** | **DeepSeek V2** | Llama 3 70B | MoE architecture provides high performance at lower inference cost; large context window.23 |
| **Inference** | **vLLM** | Ollama | Higher throughput for batch processing; efficient KV cache management.39 |

#### **Sources des citations**

1. LLM-Driven Adaptive Source–Sink Identification and False Positive Mitigation for Static Analysis | Sciety Labs (Experimental), consulté le novembre 27, 2025, [https://sciety-labs.elifesciences.org/articles/by?article\_doi=10.20944/preprints202509.0917.v1](https://sciety-labs.elifesciences.org/articles/by?article_doi=10.20944/preprints202509.0917.v1)  
2. Hacking with AI SASTs: An overview of 'AI Security Engineers' / 'LLM Security Scanners' for Penetration Testers and Security Teams | Joshua.Hu, consulté le novembre 27, 2025, [https://joshua.hu/llm-engineer-review-sast-security-ai-tools-pentesters](https://joshua.hu/llm-engineer-review-sast-security-ai-tools-pentesters)  
3. Leveraging Semantic Relations in Code and Data to Enhance Taint Analysis of Embedded Systems | USENIX, consulté le novembre 27, 2025, [https://www.usenix.org/system/files/usenixsecurity24-zhao.pdf](https://www.usenix.org/system/files/usenixsecurity24-zhao.pdf)  
4. QLPro: Automated Code Vulnerability Discovery via LLM and Static Code Analysis Integration \- arXiv, consulté le novembre 27, 2025, [https://arxiv.org/html/2506.23644v1](https://arxiv.org/html/2506.23644v1)  
5. E\&V: Prompting Large Language Models to Perform Static Analysis by Pseudo-code Execution and Verification \- arXiv, consulté le novembre 27, 2025, [https://arxiv.org/html/2312.08477v1](https://arxiv.org/html/2312.08477v1)  
6. How To Address SAST False Positives In Application Security Testing \- Mend.io, consulté le novembre 27, 2025, [https://www.mend.io/blog/sast-false-positives/](https://www.mend.io/blog/sast-false-positives/)  
7. Leveraging Semantic Relations in Code and Data to Enhance Taint Analysis of Embedded Systems | USENIX, consulté le novembre 27, 2025, [https://www.usenix.org/system/files/usenixsecurity24\_slides-zhao.pdf](https://www.usenix.org/system/files/usenixsecurity24_slides-zhao.pdf)  
8. ZeroFalse: Improving Precision in Static Analysis with LLMs \- arXiv, consulté le novembre 27, 2025, [https://arxiv.org/html/2510.02534v1](https://arxiv.org/html/2510.02534v1)  
9. iris-sast/iris: A neurosymbolic framework for vulnerability detection in code \- GitHub, consulté le novembre 27, 2025, [https://github.com/iris-sast/iris](https://github.com/iris-sast/iris)  
10. LLM-Enhanced Static Analysis for Precise Identification of Vulnerable OSS Versions \- arXiv, consulté le novembre 27, 2025, [https://arxiv.org/html/2408.07321v1](https://arxiv.org/html/2408.07321v1)  
11. \[Research\] “LLMxCPG: Context-Aware Vulnerability Detection Through Code Property Graph-Guided Large Language Models” Paper Review (EN) \- hackyboiz, consulté le novembre 27, 2025, [https://hackyboiz.github.io/2025/09/22/l0ch/llmxcpg\_paper\_review/en/](https://hackyboiz.github.io/2025/09/22/l0ch/llmxcpg_paper_review/en/)  
12. Code Property Graph | Joern Documentation, consulté le novembre 27, 2025, [https://docs.joern.io/code-property-graph/](https://docs.joern.io/code-property-graph/)  
13. LLM-Driven Adaptive Source-Sink Identification and False ... \- arXiv, consulté le novembre 27, 2025, [https://arxiv.org/abs/2511.04023](https://arxiv.org/abs/2511.04023)  
14. LLM-Driven Adaptive Source–Sink Identification and False Positive Mitigation for Static Analysis \- Preprints.org, consulté le novembre 27, 2025, [https://www.preprints.org/manuscript/202509.0917](https://www.preprints.org/manuscript/202509.0917)  
15. The Hitchhiker's Guide to Program Analysis, Part II: Deep Thoughts by LLMs \- arXiv, consulté le novembre 27, 2025, [https://arxiv.org/html/2504.11711v1](https://arxiv.org/html/2504.11711v1)  
16. Towards Realistic Project-Level Code Generation via Multi-Agent Collaboration and Semantic Architecture Modeling \- arXiv, consulté le novembre 27, 2025, [https://arxiv.org/html/2511.03404v1](https://arxiv.org/html/2511.03404v1)  
17. Passing repo code to an LLM: Does architectural context help or is it more noise? \- Reddit, consulté le novembre 27, 2025, [https://www.reddit.com/r/ChatGPTCoding/comments/1flq10j/passing\_repo\_code\_to\_an\_llm\_does\_architectural/](https://www.reddit.com/r/ChatGPTCoding/comments/1flq10j/passing_repo_code_to_an_llm_does_architectural/)  
18. LLM-Assisted Static Analysis for Detecting Security Vulnerabilities \- arXiv, consulté le novembre 27, 2025, [https://arxiv.org/html/2405.17238v1](https://arxiv.org/html/2405.17238v1)  
19. Vercation: Precise Vulnerable Open-source Software Version Identification based on Static Analysis and LLM \- arXiv, consulté le novembre 27, 2025, [https://arxiv.org/html/2408.07321v2](https://arxiv.org/html/2408.07321v2)  
20. RedTeamLLM: an Agentic AI framework for offensive security \- arXiv, consulté le novembre 27, 2025, [https://arxiv.org/html/2505.06913v1](https://arxiv.org/html/2505.06913v1)  
21. pdavis68/RepoMapper: A tool to produce a map of a codebase within a git repository. Based entirely on the "Repo Map" functionality in Aider.chat \- GitHub, consulté le novembre 27, 2025, [https://github.com/pdavis68/RepoMapper](https://github.com/pdavis68/RepoMapper)  
22. Repository map \- Aider, consulté le novembre 27, 2025, [https://aider.chat/docs/repomap.html](https://aider.chat/docs/repomap.html)  
23. DeepSeek-Coder-V2: Breaking the Barrier of Closed-Source Models in Code Intelligence \- GitHub, consulté le novembre 27, 2025, [https://github.com/deepseek-ai/DeepSeek-Coder-V2](https://github.com/deepseek-ai/DeepSeek-Coder-V2)  
24. LLM-Driven Adaptive Source–Sink Identification and False Positive Mitigation for Static Analysis \- arXiv, consulté le novembre 27, 2025, [https://arxiv.org/html/2511.04023v1](https://arxiv.org/html/2511.04023v1)  
25. Automated Static Vulnerability Detection via a Holistic Neuro-symbolic Approach \- arXiv, consulté le novembre 27, 2025, [https://arxiv.org/html/2504.16057v1](https://arxiv.org/html/2504.16057v1)  
26. LLMxCPG: Context-Aware Vulnerability Detection Through Code Property Graph-Guided Large Language Models \- USENIX, consulté le novembre 27, 2025, [https://www.usenix.org/system/files/usenixsecurity25-lekssays.pdf](https://www.usenix.org/system/files/usenixsecurity25-lekssays.pdf)  
27. Building a better repository map with tree sitter \- Aider, consulté le novembre 27, 2025, [https://aider.chat/2023/10/22/repomap.html](https://aider.chat/2023/10/22/repomap.html)  
28. Using The Tree-Sitter Library In Python To Build A Custom Tool For Parsing Source Code And Extracting Call Graphs | Volito, consulté le novembre 27, 2025, [https://volito.digital/using-the-tree-sitter-library-in-python-to-build-a-custom-tool-for-parsing-source-code-and-extracting-call-graphs/](https://volito.digital/using-the-tree-sitter-library-in-python-to-build-a-custom-tool-for-parsing-source-code-and-extracting-call-graphs/)  
29. Repo Map \- Awesome MCP Servers, consulté le novembre 27, 2025, [https://mcpservers.org/servers/pdavis68/RepoMapper](https://mcpservers.org/servers/pdavis68/RepoMapper)  
30. What is RAG? \- Retrieval-Augmented Generation AI Explained \- AWS, consulté le novembre 27, 2025, [https://aws.amazon.com/what-is/retrieval-augmented-generation/](https://aws.amazon.com/what-is/retrieval-augmented-generation/)  
31. Building My Own Sovereign RAG for Secure Code Analysis \- Adler Medrado, consulté le novembre 27, 2025, [https://adlermedrado.com.br/posts/sovereign-rag/](https://adlermedrado.com.br/posts/sovereign-rag/)  
32. LLMxCPG: Context-Aware Vulnerability Detection Through Code Property Graph-Guided Large Language Models \- arXiv, consulté le novembre 27, 2025, [https://arxiv.org/html/2507.16585v1](https://arxiv.org/html/2507.16585v1)  
33. QCRI/LLMxCPG-Q · Hugging Face, consulté le novembre 27, 2025, [https://huggingface.co/QCRI/LLMxCPG-Q](https://huggingface.co/QCRI/LLMxCPG-Q)  
34. \[2507.16585\] LLMxCPG: Context-Aware Vulnerability Detection Through Code Property Graph-Guided Large Language Models \- arXiv, consulté le novembre 27, 2025, [https://arxiv.org/abs/2507.16585](https://arxiv.org/abs/2507.16585)  
35. Introducing AI SAST That Thinks Like a Security Engineer | Blog | Endor Labs, consulté le novembre 27, 2025, [https://www.endorlabs.com/learn/introducing-ai-sast-that-thinks-like-a-security-engineer](https://www.endorlabs.com/learn/introducing-ai-sast-that-thinks-like-a-security-engineer)  
36. Qwen-2.5 Coder 32B: The Ultimate Coding Assistant? Full Test Vs Sonnet 3.5 \- YouTube, consulté le novembre 27, 2025, [https://www.youtube.com/watch?v=GVaVzWdUmGY](https://www.youtube.com/watch?v=GVaVzWdUmGY)  
37. Qwen 2.5 Coder 7b for auto-completion : r/LocalLLaMA \- Reddit, consulté le novembre 27, 2025, [https://www.reddit.com/r/LocalLLaMA/comments/1fuenxc/qwen\_25\_coder\_7b\_for\_autocompletion/](https://www.reddit.com/r/LocalLLaMA/comments/1fuenxc/qwen_25_coder_7b_for_autocompletion/)  
38. Quickstart | Joern Documentation, consulté le novembre 27, 2025, [https://docs.joern.io/quickstart/](https://docs.joern.io/quickstart/)  
39. LLMXCPG: Context-Aware Vulnerability Detection Through Code Property Graph-Guided Large Language Models | PDF | Variable (Computer Science) \- Scribd, consulté le novembre 27, 2025, [https://www.scribd.com/document/919337693/2507-16585v1](https://www.scribd.com/document/919337693/2507-16585v1)  
40. What I Learned Developing with LLMs \- OpsLevel, consulté le novembre 27, 2025, [https://www.opslevel.com/resources/what-i-learned-developing-with-llms](https://www.opslevel.com/resources/what-i-learned-developing-with-llms)  
41. Qwen/Qwen2.5-Coder-32B-Instruct \- Hugging Face, consulté le novembre 27, 2025, [https://huggingface.co/Qwen/Qwen2.5-Coder-32B-Instruct](https://huggingface.co/Qwen/Qwen2.5-Coder-32B-Instruct)  
42. DeepSeek-Coder-V2 Tutorial: Examples, Installation, Benchmarks | DataCamp, consulté le novembre 27, 2025, [https://www.datacamp.com/tutorial/deepseek-coder-v2](https://www.datacamp.com/tutorial/deepseek-coder-v2)