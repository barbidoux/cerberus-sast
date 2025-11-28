"""
Classification prompts for Source/Sink/Sanitizer inference.

Uses Few-Shot Chain-of-Thought patterns for accurate classification
of code elements in the taint analysis pipeline.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from cerberus.models.base import TaintLabel


@dataclass
class ClassificationResponse:
    """
    Structured response from classification.

    Contains the classification label, confidence score,
    reasoning, and relevant vulnerability types.
    """

    label: TaintLabel
    confidence: float = 0.0
    reason: str = ""
    vulnerability_types: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "label": self.label.value,
            "confidence": self.confidence,
            "reason": self.reason,
            "vulnerability_types": self.vulnerability_types,
        }

    @classmethod
    def from_json(cls, json_str: str) -> "ClassificationResponse":
        """
        Parse classification response from JSON string.

        Args:
            json_str: JSON string from LLM response

        Returns:
            ClassificationResponse instance
        """
        try:
            # Try to extract JSON from the response
            # Handle cases where JSON is embedded in text
            json_match = re.search(r'\{[^{}]*\}', json_str, re.DOTALL)
            if json_match:
                json_str = json_match.group()

            data = json.loads(json_str)

            # Parse label (handle both upper and lower case)
            label_str = data.get("label", "NONE").upper()
            try:
                label = TaintLabel.from_string(label_str.lower())
            except (ValueError, KeyError):
                label = TaintLabel.NONE

            return cls(
                label=label,
                confidence=float(data.get("confidence", 0.5)),
                reason=data.get("reason", ""),
                vulnerability_types=data.get("vulnerability_types", []),
            )
        except (json.JSONDecodeError, AttributeError, TypeError):
            # Return low-confidence NONE for unparseable responses
            return cls(
                label=TaintLabel.NONE,
                confidence=0.3,
                reason=f"Failed to parse response: {json_str[:100]}",
                vulnerability_types=[],
            )


@dataclass
class FewShotExample:
    """
    A few-shot example for classification prompts.

    Contains code, its classification, and reasoning to
    demonstrate the expected analysis pattern.
    """

    code: str
    language: str
    label: TaintLabel
    reason: str
    vulnerability_types: list[str] = field(default_factory=list)

    def format_for_prompt(self) -> str:
        """Format example for inclusion in prompt."""
        vuln_str = ", ".join(self.vulnerability_types) if self.vulnerability_types else "N/A"
        return f"""Example ({self.language}):
```{self.language}
{self.code}
```

Classification:
{{
    "label": "{self.label.value.upper()}",
    "confidence": 0.95,
    "reason": "{self.reason}",
    "vulnerability_types": {json.dumps(self.vulnerability_types)}
}}"""


# =============================================================================
# Few-Shot Examples for SOURCE Classification
# =============================================================================

SOURCE_EXAMPLES: list[FewShotExample] = [
    # Python examples
    FewShotExample(
        code="""def get_user_input(request):
    user_id = request.args.get('id')
    return user_id""",
        language="python",
        label=TaintLabel.SOURCE,
        reason="This function reads user-controlled data from HTTP request parameters. The 'id' parameter comes from untrusted user input and could contain malicious values.",
        vulnerability_types=["CWE-89", "CWE-79"],
    ),
    FewShotExample(
        code="""def read_config():
    with open('config.json') as f:
        return json.load(f)""",
        language="python",
        label=TaintLabel.SOURCE,
        reason="Reads data from a file. While internal, file content could be modified by attackers with file system access.",
        vulnerability_types=["CWE-22"],
    ),
    FewShotExample(
        code="""def get_env_var(name):
    return os.environ.get(name, '')""",
        language="python",
        label=TaintLabel.SOURCE,
        reason="Reads from environment variables. Environment variables can be controlled in certain contexts and should be validated.",
        vulnerability_types=["CWE-78"],
    ),
    # Java example
    FewShotExample(
        code="""public String getParameter(HttpServletRequest request) {
    return request.getParameter("username");
}""",
        language="java",
        label=TaintLabel.SOURCE,
        reason="Retrieves user-supplied data from HTTP request. The username parameter is user-controlled and should be treated as tainted.",
        vulnerability_types=["CWE-89", "CWE-79", "CWE-78"],
    ),
    # JavaScript/Express.js examples
    FewShotExample(
        code="""function getUserData(req) {
    const { name, email } = req.body;
    return { name, email };
}""",
        language="javascript",
        label=TaintLabel.SOURCE,
        reason="Extracts data from HTTP request body. Request body content is user-controlled and represents untrusted input.",
        vulnerability_types=["CWE-89", "CWE-79"],
    ),
    FewShotExample(
        code="""router.get('/users/:id', (req, res) => {
    const userId = req.params.id;
    const query = req.query.filter;
    return { userId, query };
});""",
        language="javascript",
        label=TaintLabel.SOURCE,
        reason="Express.js route handler reading from URL params (req.params.id) and query string (req.query.filter). Both are user-controlled and should be validated.",
        vulnerability_types=["CWE-89", "CWE-22", "CWE-78"],
    ),
    FewShotExample(
        code="""const handler = async (req, res) => {
    const { username, password } = req.body;
    const token = req.headers.authorization;
    const sessionId = req.cookies.session;
    // Process login...
};""",
        language="javascript",
        label=TaintLabel.SOURCE,
        reason="Express handler accessing multiple user-controlled inputs: request body, headers, and cookies. All these are untrusted sources.",
        vulnerability_types=["CWE-89", "CWE-79", "CWE-798"],
    ),
    # TypeScript/Angular examples
    FewShotExample(
        code="""constructor(private route: ActivatedRoute) {
    this.route.params.subscribe(params => {
        this.userId = params['id'];
    });
}""",
        language="typescript",
        label=TaintLabel.SOURCE,
        reason="Angular component reading route parameters via ActivatedRoute. URL parameters are user-controlled and can contain malicious values.",
        vulnerability_types=["CWE-79", "CWE-22"],
    ),
    FewShotExample(
        code="""async fetchUserProfile(userId: string): Promise<User> {
    const response = await this.http.get<User>(`/api/users/${userId}`);
    return response;
}""",
        language="typescript",
        label=TaintLabel.SOURCE,
        reason="HTTP client fetching external data. Responses from external APIs should be treated as potentially untrusted sources.",
        vulnerability_types=["CWE-79", "CWE-918"],
    ),
]

# =============================================================================
# Few-Shot Examples for SINK Classification
# =============================================================================

SINK_EXAMPLES: list[FewShotExample] = [
    # Python examples
    FewShotExample(
        code="""def execute_query(cursor, query):
    cursor.execute(query)
    return cursor.fetchall()""",
        language="python",
        label=TaintLabel.SINK,
        reason="Executes a SQL query directly. If the query contains untrusted data, this enables SQL injection attacks.",
        vulnerability_types=["CWE-89"],
    ),
    FewShotExample(
        code="""def read_file(path):
    with open(path, 'r') as f:
        return f.read()""",
        language="python",
        label=TaintLabel.SINK,
        reason="Opens a file using a path parameter. If path is user-controlled, attackers can read arbitrary files (path traversal).",
        vulnerability_types=["CWE-22"],
    ),
    FewShotExample(
        code="""def run_subprocess(command):
    subprocess.run(command, shell=True)""",
        language="python",
        label=TaintLabel.SINK,
        reason="Runs command with shell=True. Shell interpretation of user input enables command injection.",
        vulnerability_types=["CWE-78"],
    ),
    # Java example
    FewShotExample(
        code="""public void runCommand(String cmd) {
    Runtime.getRuntime().exec(cmd);
}""",
        language="java",
        label=TaintLabel.SINK,
        reason="Executes a system command. If cmd contains user input, attackers can execute arbitrary commands.",
        vulnerability_types=["CWE-78"],
    ),
    # JavaScript/Node.js sinks
    FewShotExample(
        code="""function renderHtml(content) {
    document.getElementById('output').innerHTML = content;
}""",
        language="javascript",
        label=TaintLabel.SINK,
        reason="Sets innerHTML with potentially untrusted content. This enables cross-site scripting (XSS) attacks.",
        vulnerability_types=["CWE-79"],
    ),
    FewShotExample(
        code="""async function fetchUrl(url) {
    const response = await fetch(url);
    return response.json();
}""",
        language="javascript",
        label=TaintLabel.SINK,
        reason="Makes HTTP request to a URL. If URL is user-controlled, this enables Server-Side Request Forgery (SSRF).",
        vulnerability_types=["CWE-918"],
    ),
    FewShotExample(
        code="""const { exec } = require('child_process');
router.post('/backup', (req, res) => {
    const { filename } = req.body;
    exec(`tar -czf /backups/${filename}.tar.gz /data`);
});""",
        language="javascript",
        label=TaintLabel.SINK,
        reason="Command injection via child_process.exec(). User input (filename) is interpolated directly into shell command without sanitization.",
        vulnerability_types=["CWE-78"],
    ),
    FewShotExample(
        code="""User.findByUsername = async function(username) {
    const query = `SELECT * FROM Users WHERE username = '${username}'`;
    const [users] = await sequelize.query(query);
    return users[0];
};""",
        language="javascript",
        label=TaintLabel.SINK,
        reason="SQL injection via Sequelize raw query. User input is directly interpolated into SQL string instead of using parameterized queries.",
        vulnerability_types=["CWE-89"],
    ),
    FewShotExample(
        code="""router.get('/logs', (req, res) => {
    const filename = req.query.file;
    const logPath = path.join('/var/log', filename);
    const content = fs.readFileSync(logPath, 'utf8');
    res.send(content);
});""",
        language="javascript",
        label=TaintLabel.SINK,
        reason="Path traversal via fs.readFileSync(). path.join does not prevent '../' sequences, allowing attackers to read arbitrary files.",
        vulnerability_types=["CWE-22"],
    ),
    FewShotExample(
        code="""function executeCode(code) {
    return eval(code);
}""",
        language="javascript",
        label=TaintLabel.SINK,
        reason="Code injection via eval(). Executing user-controlled code allows arbitrary code execution.",
        vulnerability_types=["CWE-94"],
    ),
    # TypeScript/Angular sinks
    FewShotExample(
        code="""displayResults(results: string): void {
    this.resultsHtml = this.sanitizer.bypassSecurityTrustHtml(results);
}""",
        language="typescript",
        label=TaintLabel.SINK,
        reason="Angular XSS via bypassSecurityTrustHtml. This explicitly bypasses Angular's built-in XSS protection, allowing script injection.",
        vulnerability_types=["CWE-79"],
    ),
    FewShotExample(
        code="""@ViewChild('container') container: ElementRef;

render(html: string): void {
    this.container.nativeElement.innerHTML = html;
}""",
        language="typescript",
        label=TaintLabel.SINK,
        reason="Angular XSS via direct DOM manipulation. Setting innerHTML on nativeElement bypasses Angular's sanitization.",
        vulnerability_types=["CWE-79"],
    ),
    FewShotExample(
        code="""async proxyRequest(targetUrl: string): Observable<any> {
    return this.http.get(targetUrl);
}""",
        language="typescript",
        label=TaintLabel.SINK,
        reason="SSRF vulnerability. Making HTTP requests to user-controlled URLs allows attackers to access internal services.",
        vulnerability_types=["CWE-918"],
    ),
]

# =============================================================================
# Few-Shot Examples for SANITIZER Classification
# =============================================================================

SANITIZER_EXAMPLES: list[FewShotExample] = [
    # Python examples
    FewShotExample(
        code="""def escape_html(text):
    return html.escape(text)""",
        language="python",
        label=TaintLabel.SANITIZER,
        reason="Escapes HTML special characters. This prevents XSS by neutralizing script injection attempts.",
        vulnerability_types=["CWE-79"],
    ),
    FewShotExample(
        code="""def normalize_path(path):
    abs_path = os.path.abspath(path)
    if not abs_path.startswith(ALLOWED_DIR):
        raise ValueError("Path traversal detected")
    return abs_path""",
        language="python",
        label=TaintLabel.SANITIZER,
        reason="Validates file path against allowed directory. Prevents path traversal by rejecting paths outside allowed scope.",
        vulnerability_types=["CWE-22"],
    ),
    # Java example
    FewShotExample(
        code="""public String sanitizeSql(String input) {
    return input.replaceAll("['\";]", "");
}""",
        language="java",
        label=TaintLabel.SANITIZER,
        reason="Removes SQL metacharacters from input. This helps prevent SQL injection, though parameterized queries are preferred.",
        vulnerability_types=["CWE-89"],
    ),
    # JavaScript/Node.js sanitizers
    FewShotExample(
        code=r"""function validateEmail(email) {
    const pattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!pattern.test(email)) {
        throw new Error('Invalid email');
    }
    return email;
}""",
        language="javascript",
        label=TaintLabel.SANITIZER,
        reason="Validates email format with strict regex. Invalid input is rejected, ensuring only well-formed data passes through.",
        vulnerability_types=["CWE-89", "CWE-79"],
    ),
    FewShotExample(
        code="""const DOMPurify = require('dompurify');

function sanitizeHtml(dirtyHtml) {
    return DOMPurify.sanitize(dirtyHtml);
}""",
        language="javascript",
        label=TaintLabel.SANITIZER,
        reason="DOMPurify sanitizes HTML by removing dangerous elements and attributes. This prevents XSS while preserving safe HTML.",
        vulnerability_types=["CWE-79"],
    ),
    FewShotExample(
        code="""const { escape } = require('validator');

function escapeUserInput(input) {
    return escape(input);
}""",
        language="javascript",
        label=TaintLabel.SANITIZER,
        reason="Uses validator library's escape function to encode HTML entities. Prevents XSS by neutralizing special characters.",
        vulnerability_types=["CWE-79"],
    ),
    FewShotExample(
        code="""const { body, validationResult } = require('express-validator');

const validateUser = [
    body('username').isAlphanumeric().trim().escape(),
    body('email').isEmail().normalizeEmail(),
];""",
        language="javascript",
        label=TaintLabel.SANITIZER,
        reason="Express-validator middleware that validates and sanitizes input. Combines validation (isAlphanumeric, isEmail) with sanitization (trim, escape, normalizeEmail).",
        vulnerability_types=["CWE-89", "CWE-79"],
    ),
    FewShotExample(
        code="""function validateId(id) {
    const numId = parseInt(id, 10);
    if (isNaN(numId) || numId < 0) {
        throw new Error('Invalid ID');
    }
    return numId;
}""",
        language="javascript",
        label=TaintLabel.SANITIZER,
        reason="Validates and converts input to integer. Prevents SQL injection by ensuring only numeric values are used.",
        vulnerability_types=["CWE-89"],
    ),
    # TypeScript/Angular sanitizers
    FewShotExample(
        code="""sanitizeSearchTerm(term: string): string {
    return term.replace(/[<>\"'&]/g, '');
}""",
        language="typescript",
        label=TaintLabel.SANITIZER,
        reason="Removes dangerous characters that could enable XSS. While basic, this prevents common injection patterns.",
        vulnerability_types=["CWE-79"],
    ),
    FewShotExample(
        code="""validatePath(userPath: string): string {
    const normalized = path.normalize(userPath);
    const resolved = path.resolve(this.uploadDir, normalized);
    if (!resolved.startsWith(this.uploadDir)) {
        throw new Error('Path traversal detected');
    }
    return resolved;
}""",
        language="typescript",
        label=TaintLabel.SANITIZER,
        reason="Path traversal protection using path normalization and prefix checking. Ensures files stay within allowed directory.",
        vulnerability_types=["CWE-22"],
    ),
]

# =============================================================================
# Few-Shot Examples for PROPAGATOR Classification
# =============================================================================

PROPAGATOR_EXAMPLES: list[FewShotExample] = [
    FewShotExample(
        code="""def transform(data):
    return data.lower()""",
        language="python",
        label=TaintLabel.PROPAGATOR,
        reason="Transforms data but doesn't sanitize it. Taint flows through - lowercase conversion doesn't prevent injection.",
        vulnerability_types=[],
    ),
    FewShotExample(
        code="""function concat(a, b) {
    return a + b;
}""",
        language="javascript",
        label=TaintLabel.PROPAGATOR,
        reason="Concatenates values without sanitization. If either input is tainted, the output is also tainted.",
        vulnerability_types=[],
    ),
]

# =============================================================================
# Few-Shot Examples for NONE Classification
# =============================================================================

NONE_EXAMPLES: list[FewShotExample] = [
    FewShotExample(
        code="""def add(a, b):
    return a + b""",
        language="python",
        label=TaintLabel.NONE,
        reason="Simple arithmetic operation. No external data sources, no security-sensitive operations, just computation.",
        vulnerability_types=[],
    ),
    FewShotExample(
        code="""public int getLength(String s) {
    return s != null ? s.length() : 0;
}""",
        language="java",
        label=TaintLabel.NONE,
        reason="Returns string length. This is a pure computation with no security implications.",
        vulnerability_types=[],
    ),
]


@dataclass
class ClassificationPrompt:
    """
    Builder for classification prompts targeting a specific taint label.

    Uses few-shot examples and chain-of-thought reasoning to guide
    the LLM toward accurate classifications.
    """

    target_label: TaintLabel
    few_shot_count: int = 3

    def build_system_prompt(self) -> str:
        """Build the system prompt with instructions."""
        label_name = self.target_label.value.upper()

        return f"""You are an expert security analyst specializing in static application security testing (SAST). Your task is to analyze code and determine if a function is a {label_name} in the context of taint analysis.

## Definitions

- **SOURCE**: A function that introduces untrusted data into the application (e.g., user input, file reads, environment variables)
- **SINK**: A function where tainted data could cause harm if not sanitized (e.g., SQL execution, command execution, HTML rendering)
- **SANITIZER**: A function that validates, escapes, or transforms data to make it safe for specific sinks
- **PROPAGATOR**: A function that passes tainted data through without sanitizing it
- **NONE**: A function with no security relevance (pure computation, internal logic)

## Your Task

Analyze the provided code and determine if it is a {label_name}.

Think step by step:
1. What does this function do?
2. Does it introduce, consume, or transform potentially tainted data?
3. What vulnerability types could be relevant?
4. What is your confidence level?

## Response Format

Respond with a JSON object containing:
- "label": One of SOURCE, SINK, SANITIZER, PROPAGATOR, or NONE
- "confidence": A float between 0.0 and 1.0
- "reason": A brief explanation of your reasoning
- "vulnerability_types": Array of relevant CWE IDs (e.g., ["CWE-89", "CWE-79"])

Example response:
{{
    "label": "{label_name}",
    "confidence": 0.85,
    "reason": "This function...",
    "vulnerability_types": ["CWE-89"]
}}"""

    def build_user_prompt(self, code: str, language: str = "unknown") -> str:
        """Build the user prompt with code to analyze."""
        return f"""Analyze this {language} code and classify it:

```{language}
{code}
```

Is this function a {self.target_label.value.upper()}? Provide your analysis as JSON."""

    def get_examples(self) -> list[FewShotExample]:
        """Get relevant few-shot examples for this classification."""
        examples: list[FewShotExample] = []

        # Get positive examples for target label
        if self.target_label == TaintLabel.SOURCE:
            positive = SOURCE_EXAMPLES
        elif self.target_label == TaintLabel.SINK:
            positive = SINK_EXAMPLES
        elif self.target_label == TaintLabel.SANITIZER:
            positive = SANITIZER_EXAMPLES
        elif self.target_label == TaintLabel.PROPAGATOR:
            positive = PROPAGATOR_EXAMPLES
        else:
            positive = NONE_EXAMPLES

        # Add positive examples
        examples.extend(positive[:self.few_shot_count])

        # Ensure we have the requested count
        # Add from other categories if needed (as negative examples)
        if len(examples) < self.few_shot_count:
            remaining = self.few_shot_count - len(examples)
            all_examples = SOURCE_EXAMPLES + SINK_EXAMPLES + SANITIZER_EXAMPLES + NONE_EXAMPLES
            for ex in all_examples:
                if ex not in examples:
                    examples.append(ex)
                    remaining -= 1
                    if remaining <= 0:
                        break

        return examples[:self.few_shot_count]


@dataclass
class BuiltPrompt:
    """A fully constructed prompt ready for LLM invocation."""

    system_message: str
    user_message: str
    examples: list[FewShotExample] = field(default_factory=list)

    def to_messages(self) -> list[dict[str, str]]:
        """Convert to LLM message format."""
        messages = [
            {"role": "system", "content": self.system_message}
        ]

        # Add few-shot examples as conversation turns
        for example in self.examples:
            messages.append({
                "role": "user",
                "content": f"Analyze this {example.language} code:\n```{example.language}\n{example.code}\n```"
            })
            messages.append({
                "role": "assistant",
                "content": json.dumps({
                    "label": example.label.value.upper(),
                    "confidence": 0.95,
                    "reason": example.reason,
                    "vulnerability_types": example.vulnerability_types,
                }, indent=2)
            })

        # Add the actual user message
        messages.append({"role": "user", "content": self.user_message})

        return messages


class PromptBuilder:
    """Builder for assembling complete classification prompts."""

    def build_classification_prompt(
        self,
        code: str,
        language: str,
        target_label: TaintLabel,
        context: Optional[dict[str, Any]] = None,
        few_shot_count: int = 3,
    ) -> BuiltPrompt:
        """
        Build a complete prompt for classifying code.

        Args:
            code: The code to analyze
            language: Programming language
            target_label: The taint label to classify against
            context: Optional additional context (imports, file info, etc.)
            few_shot_count: Number of few-shot examples

        Returns:
            BuiltPrompt ready for LLM invocation
        """
        prompt = ClassificationPrompt(
            target_label=target_label,
            few_shot_count=few_shot_count,
        )

        system_message = prompt.build_system_prompt()
        user_message = prompt.build_user_prompt(code, language)
        examples = prompt.get_examples()

        # Add context if provided
        if context:
            context_str = "\n\nAdditional context:\n"
            for key, value in context.items():
                context_str += f"- {key}: {value}\n"
            user_message += context_str

        return BuiltPrompt(
            system_message=system_message,
            user_message=user_message,
            examples=examples,
        )

    def build_multi_label_prompt(
        self,
        code: str,
        language: str,
        context: Optional[dict[str, Any]] = None,
        few_shot_count: int = 3,
    ) -> BuiltPrompt:
        """
        Build a prompt for classifying code into any taint label.

        This is used when we want the LLM to determine the most
        appropriate label rather than checking against a specific one.

        Args:
            code: The code to analyze
            language: Programming language
            context: Optional additional context
            few_shot_count: Number of few-shot examples per category

        Returns:
            BuiltPrompt ready for LLM invocation
        """
        system_message = """You are an expert security analyst specializing in static application security testing (SAST). Your task is to analyze code and classify functions according to their role in taint analysis.

## Classification Labels

- **SOURCE**: A function that introduces untrusted data into the application
  - Examples: User input handlers, file readers, environment variable access, database reads

- **SINK**: A function where tainted data could cause harm if not sanitized
  - Examples: SQL execution, command execution, HTML rendering, file operations

- **SANITIZER**: A function that validates, escapes, or transforms data to make it safe
  - Examples: HTML escaping, SQL parameterization, input validation, encoding

- **PROPAGATOR**: A function that passes tainted data through without sanitizing
  - Examples: String concatenation, data transformation, wrapper functions

- **NONE**: A function with no security relevance
  - Examples: Pure computation, internal logic, utility functions

## Analysis Process

Think step by step:
1. What does this function do? What are its inputs and outputs?
2. Does it read external data (SOURCE)?
3. Does it perform a security-sensitive operation (SINK)?
4. Does it validate or sanitize data (SANITIZER)?
5. Does it simply pass data through (PROPAGATOR)?
6. Or is it unrelated to data flow (NONE)?

## Response Format

Respond with a JSON object:
{
    "label": "SOURCE|SINK|SANITIZER|PROPAGATOR|NONE",
    "confidence": 0.0 to 1.0,
    "reason": "Brief explanation of your reasoning",
    "vulnerability_types": ["CWE-XX", ...] // Relevant CWEs if applicable
}"""

        user_message = f"""Analyze this {language} code and classify it according to its role in taint analysis:

```{language}
{code}
```

Determine if this is a SOURCE, SINK, SANITIZER, PROPAGATOR, or NONE. Provide your analysis as JSON."""

        # Gather diverse examples
        examples = []
        examples.extend(SOURCE_EXAMPLES[:1])
        examples.extend(SINK_EXAMPLES[:1])
        examples.extend(SANITIZER_EXAMPLES[:1])
        examples = examples[:few_shot_count]

        # Add context if provided
        if context:
            context_str = "\n\nAdditional context:\n"
            for key, value in context.items():
                context_str += f"- {key}: {value}\n"
            user_message += context_str

        return BuiltPrompt(
            system_message=system_message,
            user_message=user_message,
            examples=examples,
        )
