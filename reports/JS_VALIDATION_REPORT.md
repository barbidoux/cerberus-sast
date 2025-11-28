# JavaScript/TypeScript Validation Report

**Date**: 2025-11-28
**Target**: OWASP Juice Shop + Custom Vulnerable Express App Fixtures

## Summary

| Metric | Result |
|--------|--------|
| E2E Tests | ✅ 14/14 passed |
| Full Test Suite | ✅ 950/951 passed |
| Juice Shop Scan | ⚠️ Runs, 0 findings |
| Custom Fixtures Scan | ⚠️ Runs, 0 findings |

## What Works

### ✅ Pipeline Execution
- All 4 phases execute without errors
- TypeScript files parsed correctly (62 files from Juice Shop routes)
- Symbol extraction works for named functions (265 symbols from Juice Shop)
- Inference engine runs and returns specs
- Detection engine handles LLM-trust fallback mode

### ✅ Symbol Extraction
Successfully extracts:
- Named function declarations: `function login() {}`
- Named arrow functions: `const authMiddleware = (req, res) => {}`
- Classes and methods
- Imports and exports

### ✅ Heuristic Matching
Correctly identifies patterns when naming conventions match:
- **Sinks**: `runCommand`, `execSync`, `writeFile`, `query`
- **Sanitizers**: `validateInput`, `escapeHtml`, `sanitize`
- **Sources**: `getBody`, `parseQuery`, `readParams`

### ✅ E2E Tests
All 14 tests pass covering:
- Phase I: Repository mapping for JS/TS
- Phase II: Inference with mocked LLM
- Heuristic pattern matching
- LLM-trust detection mode
- Full pipeline integration

## Known Limitations

### ⚠️ Inline Anonymous Functions Not Extracted
Real Express.js code typically uses inline arrow functions:
```javascript
router.get('/search', async (req, res) => {
    const searchTerm = req.query.name;  // Source here
    const query = `SELECT * FROM users WHERE name = '${searchTerm}'`;  // Sink here
});
```
These anonymous functions don't become named symbols for classification.

**Impact**: Route handler vulnerabilities not detected

### ⚠️ Property Access Sources Not Detected
Express.js sources use property access, not function calls:
- `req.body.email` - Direct property access
- `req.params.id` - Direct property access
- `req.query.name` - Direct property access

Our heuristic matcher looks for function NAMES like `getBody()`, `parseQuery()`.

**Impact**: 0 sources detected in both Juice Shop and custom fixtures

### ⚠️ Method Call Sinks Detection Limited
Dangerous sinks are often method calls on objects:
- `sequelize.query(...)` - Method on Sequelize instance
- `exec(...)` - Method from child_process

Our matcher correctly identifies `query` and `exec` patterns, but only for symbols
with those names - not method calls inside other functions.

**Impact**: Sinks only detected when exported as named functions

## Juice Shop Scan Details

```
Files scanned: 62
Lines analyzed: 4,267
Symbols extracted: 265
Duration: 17.59s

Spec Inference:
  Sources:    0
  Sinks:      0
  Sanitizers: 2

Findings: 0
```

### Sample Vulnerability Not Detected

**File**: `/tmp/juice-shop/routes/login.ts` (line 34)
```typescript
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`
)
```

**Why Not Detected**:
1. `req.body.email` is property access, not a function call
2. `models.sequelize.query()` is inside `login()` function, not a symbol itself
3. No data flow analysis to track `req.body.email` → query string

## Custom Fixtures Scan Details

```
Files scanned: 8
Lines analyzed: 584
Symbols extracted: 16

Spec Inference:
  Sources:    0
  Sinks:      3 (runCommand, writeUserFile, safeReadFile)
  Sanitizers: 1 (safeReadFile)

Findings: 0
```

**Why 0 findings**: Even with sinks detected, no sources were found to create source-sink pairs.

## Recommendations

### Short-term: Improve Symbol Extraction
1. Extract function bodies and scan for source patterns (`req.body.*`, `req.params.*`)
2. Track method calls as potential sinks regardless of context

### Medium-term: AST-Level Analysis
1. Find property access patterns: `req.body.*`, `req.params.*`, `req.query.*`
2. Track variable assignments to trace tainted data
3. Match method calls: `*.query()`, `*.exec()`, `child_process.*`

### Long-term: Full Data Flow Analysis
1. Implement inter-procedural data flow tracking
2. Use Joern CPG for precise taint analysis
3. Build call graphs to trace data across functions

## Conclusion

The Cerberus pipeline is **architecturally sound** and executes correctly on real-world
JavaScript/TypeScript codebases. The current limitation is at the **heuristic detection
level** - the pattern matching assumes naming conventions that real-world code often
doesn't follow.

The system works best with:
- Codebases using explicit helper functions (`getBody()`, `parseQuery()`)
- Named function exports for security-sensitive operations
- Libraries with well-named source/sink functions

For production SAST on real-world codebases like Juice Shop, the detection strategy
needs to evolve from **function-name heuristics** to **AST-level pattern analysis**.
