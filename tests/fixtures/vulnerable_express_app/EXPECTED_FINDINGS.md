# Expected Findings - Vulnerable Express App

This document serves as the ground truth for Cerberus SAST validation.
All vulnerabilities are intentionally planted for testing purposes.

## Summary

| Category | Count |
|----------|-------|
| CWE-89: SQL Injection | 10 |
| CWE-78: Command Injection | 8 |
| CWE-79: Cross-Site Scripting (XSS) | 11 |
| CWE-22: Path Traversal | 6 |
| CWE-798: Hardcoded Credentials | 4 |
| CWE-918: Server-Side Request Forgery (SSRF) | 7 |
| CWE-94: Code Injection | 4 |
| **Total** | **50** |

---

## Backend Vulnerabilities

### CWE-89: SQL Injection (10 findings)

| # | File | Line | Pattern | Source |
|---|------|------|---------|--------|
| 1 | backend/routes/users.js | 13 | `sequelize.query(\`SELECT...${searchTerm}\`)` | req.query.name |
| 2 | backend/routes/users.js | 21 | `sequelize.query(\`SELECT...${userId}\`)` | req.params.id |
| 3 | backend/routes/users.js | 29 | `sequelize.query(\`SELECT...${username}...${password}\`)` | req.body |
| 4 | backend/routes/users.js | 40 | `sequelize.query(\`UPDATE...${email}...${userId}\`)` | req.body.email |
| 5 | backend/routes/users.js | 48 | `sequelize.query(\`DELETE...${userId}\`)` | req.params.id |
| 6 | backend/routes/users.js | 56 | `sequelize.query(\`SELECT...ORDER BY ${sortBy}\`)` | req.query.sort |
| 7 | backend/routes/users.js | 65 | `sequelize.query(\`UPDATE...${bio}\`)` | req.body.bio |
| 8 | backend/routes/products.js | 14 | `sequelize.query(\`SELECT...${category}...${minPrice}...${maxPrice}\`)` | req.query |
| 9 | backend/routes/products.js | 70 | `sequelize.query(\`INSERT...${content}...${rating}\`)` | req.body |
| 10 | backend/routes/products.js | 78 | `sequelize.query(\`DELETE...IN (${idList})\`)` | req.body.ids |

### CWE-78: Command Injection (8 findings)

| # | File | Line | Pattern | Source |
|---|------|------|---------|--------|
| 1 | backend/routes/admin.js | 14 | `exec(\`tar...${filename}\`)` | req.body.filename |
| 2 | backend/routes/admin.js | 26 | `execSync(command)` | req.query.cmd |
| 3 | backend/routes/admin.js | 33 | `spawn('convert', [inputFile, outputFile])` | req.body |
| 4 | backend/routes/admin.js | 42 | `exec(\`ping...${host}\`)` | req.query.host |
| 5 | backend/routes/admin.js | 73 | `exec(\`git clone...${branch}...${repoUrl}\`)` | req.body |
| 6 | backend/utils/shell.js | 10 | `exec(command)` | command param |
| 7 | backend/utils/shell.js | 17 | `execSync(command)` | command param |
| 8 | backend/utils/shell.js | 27 | `exec(\`ffmpeg...${inputPath}...${options}...${outputPath}\`)` | params |

### CWE-79: XSS - Server Side (4 findings)

| # | File | Line | Pattern | Source |
|---|------|------|---------|--------|
| 1 | backend/app.js | 35 | `res.send(\`...${query}...\`)` | req.query.q |
| 2 | backend/app.js | 41 | `res.send(\`...${name}...\`)` | req.params.name |
| 3 | backend/routes/products.js | 24-29 | `res.send(\`...${product.name}...${product.description}...\`)` | database |
| 4 | backend/routes/products.js | 66-68 | Stored XSS via review content | req.body.content |

### CWE-22: Path Traversal (6 findings)

| # | File | Line | Pattern | Source |
|---|------|------|---------|--------|
| 1 | backend/routes/admin.js | 50 | `fs.readFileSync(path.join('/var/log', filename))` | req.query.file |
| 2 | backend/routes/admin.js | 58 | `res.download(\`/uploads/${requestedFile}\`)` | req.query.path |
| 3 | backend/routes/admin.js | 65 | `fs.writeFileSync(path.join('/configs', filename))` | req.body.filename |
| 4 | backend/routes/admin.js | 81 | `fs.readdirSync(dir)` | req.query.dir |
| 5 | backend/utils/file.js | 14 | `fs.readFileSync(path.join(UPLOAD_DIR, filename))` | filename param |
| 6 | backend/utils/file.js | 38 | `fs.readFileSync(userPath)` | userPath param |

### CWE-798: Hardcoded Credentials (4 findings)

| # | File | Line | Pattern |
|---|------|------|---------|
| 1 | backend/app.js | 19 | `const JWT_SECRET = "super_secret_key_123"` |
| 2 | backend/app.js | 22 | `const API_KEY = "sk-1234567890abcdef"` |
| 3 | backend/middleware/auth.js | 9 | `const JWT_SECRET = "my_super_secret_jwt_key_2024"` |
| 4 | backend/middleware/auth.js | 12 | `const ADMIN_PASSWORD = "admin123!@#"` |

### CWE-918: SSRF - Backend (3 findings)

| # | File | Line | Pattern | Source |
|---|------|------|---------|--------|
| 1 | backend/app.js | 48 | `fetch(url)` | req.query.url |
| 2 | backend/routes/products.js | 38 | `fetch(imageUrl)` | req.body.imageUrl |
| 3 | backend/routes/products.js | 47 | `fetch(webhookUrl)` | req.body.webhookUrl |

### CWE-94: Code Injection - Backend (2 findings)

| # | File | Line | Pattern | Source |
|---|------|------|---------|--------|
| 1 | backend/app.js | 56 | `eval(expression)` | req.body.expression |
| 2 | backend/routes/products.js | 58 | `new Function('price', \`return ${template}\`)` | req.body.template |

---

## Frontend Vulnerabilities (Angular/TypeScript)

### CWE-79: XSS - DOM (7 findings)

| # | File | Line | Pattern | Source |
|---|------|------|---------|--------|
| 1 | frontend/src/app/search/search.component.ts | 43 | `innerHTML = html` | method param |
| 2 | frontend/src/app/search/search.component.ts | 48 | `resultsHtml = \`...${searchQuery}...\`` | user input |
| 3 | frontend/src/app/search/search.component.ts | 54 | `document.write(\`...${content}...\`)` | method param |
| 4 | frontend/src/app/admin/admin.component.ts | 36 | `bypassSecurityTrustHtml(data.content)` | API response |
| 5 | frontend/src/app/admin/admin.component.ts | 65 | `container.innerHTML = html` | method param |
| 6 | frontend/src/app/user/user.component.ts | 38-43 | `profileDiv.innerHTML = \`...${user}...\`` | fetch response |
| 7 | frontend/src/app/user/user.component.ts | 56 | `insertAdjacentHTML('beforeend', content)` | method param |

### CWE-918: SSRF - Frontend (4 findings)

| # | File | Line | Pattern | Source |
|---|------|------|---------|--------|
| 1 | frontend/src/app/admin/admin.component.ts | 48 | `bypassSecurityTrustResourceUrl(userUrl)` | method param |
| 2 | frontend/src/services/api.service.ts | 17 | `http.get(userUrl)` | method param |
| 3 | frontend/src/services/api.service.ts | 32 | `http.get(\`${imageServer}/avatars/...\`)` | method param |
| 4 | frontend/src/services/api.service.ts | 38 | `http.post(webhookUrl, payload)` | method param |

### CWE-94: Code Injection - Frontend (2 findings)

| # | File | Line | Pattern | Source |
|---|------|------|---------|--------|
| 1 | frontend/src/app/search/search.component.ts | 59 | `eval(userScript)` | method param |
| 2 | frontend/src/app/search/search.component.ts | 64 | `new Function('data', code)` | method param |

---

## Detection Metrics

### Acceptance Criteria

| Metric | Target | Calculation |
|--------|--------|-------------|
| True Positive Rate | ≥ 70% | TP / (TP + FN) ≥ 35/50 |
| False Positive Rate | ≤ 30% | FP / (TP + FP) ≤ 30% |
| CWE Coverage | ≥ 6/7 | Unique CWEs detected |

### Vulnerability Type Weighting

| CWE | Priority | Detection Requirement |
|-----|----------|----------------------|
| CWE-89 | Critical | Must detect ≥ 7/10 |
| CWE-78 | Critical | Must detect ≥ 5/8 |
| CWE-79 | High | Must detect ≥ 7/11 |
| CWE-22 | High | Must detect ≥ 4/6 |
| CWE-798 | Medium | Must detect ≥ 3/4 |
| CWE-918 | Medium | Must detect ≥ 4/7 |
| CWE-94 | Medium | Must detect ≥ 2/4 |

---

## Notes

1. **Safe Examples**: Files contain deliberately safe patterns to test false positive resistance:
   - `backend/routes/users.js:74-78` - Parameterized query
   - `backend/utils/shell.js:51-54` - Array-based spawn
   - `backend/utils/file.js:50-61` - Path validation
   - `frontend/src/services/api.service.ts:49-55` - Fixed base URLs

2. **Line Numbers**: May shift if files are edited. Always verify against actual file content.

3. **Vulnerability Chains**: Some vulnerabilities form chains (e.g., SQL injection → data → XSS). Count each node independently.

4. **Model-Specific Detection**: LLM-based detection may identify additional true vulnerabilities not listed here. Document and verify manually.
