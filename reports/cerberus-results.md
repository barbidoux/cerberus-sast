# Cerberus SAST Scan Report

✅ **Status:** COMPLETED

| Property | Value |
|----------|-------|
| Repository | `vulnerable_app` |
| Scan ID | `2ea37a93-e527-4c63-8dc3-33e8659df730` |
| Duration | 30.57s |
| Generated | 2025-11-28 06:44:02 UTC |

## Summary

| Metric | Value |
|--------|-------|
| Files Scanned | 4 |
| Lines Analyzed | 662 |
| Total Findings | 18 |

### Findings by Severity

🔴 **CRITICAL:** 12 | 🟠 **HIGH:** 6

### Verification Results

| Verdict | Count |
|---------|-------|
| True Positive | 0 |
| False Positive | 0 |
| Uncertain | 0 |
| Unverified | 18 |

## Spec Inference

| Type | Count |
|------|-------|
| Sources | 3 |
| Sinks | 6 |
| Sanitizers | 0 |

## Findings

### 1. 🔴 [CRITICAL] CWE-78

> Potential CWE-78 vulnerability detected. Data from 'get_user' may flow to dangerous sink 'run_command' without proper sanitization. This finding is based on LLM semantic analysis verified against the Code Property Graph.

**Source:** `get_user` at `tests/fixtures/vulnerable_app/app.py:44`

**Sink:** `run_command` at `tests/fixtures/vulnerable_app/utils.py:24`

<details>
<summary>Trace</summary>

- **source**: `tests/fixtures/vulnerable_app/app.py:44`
  ```
  Source: get_user
  ```
- **sink**: `tests/fixtures/vulnerable_app/utils.py:24`
  ```
  Sink: run_command
  ```

</details>

### 2. 🔴 [CRITICAL] CWE-94

> Potential CWE-94 vulnerability detected. Data from 'get_user' may flow to dangerous sink 'evaluate' without proper sanitization. This finding is based on LLM semantic analysis verified against the Code Property Graph.

**Source:** `get_user` at `tests/fixtures/vulnerable_app/app.py:44`

**Sink:** `evaluate` at `tests/fixtures/vulnerable_app/utils.py:182`

<details>
<summary>Trace</summary>

- **source**: `tests/fixtures/vulnerable_app/app.py:44`
  ```
  Source: get_user
  ```
- **sink**: `tests/fixtures/vulnerable_app/utils.py:182`
  ```
  Sink: evaluate
  ```

</details>

### 3. 🔴 [CRITICAL] CWE-78

> Potential CWE-78 vulnerability detected. Data from 'get_user' may flow to dangerous sink 'execute_command' without proper sanitization. This finding is based on LLM semantic analysis verified against the Code Property Graph.

**Source:** `get_user` at `tests/fixtures/vulnerable_app/app.py:44`

**Sink:** `execute_command` at `tests/fixtures/vulnerable_app/app.py:231`

<details>
<summary>Trace</summary>

- **source**: `tests/fixtures/vulnerable_app/app.py:44`
  ```
  Source: get_user
  ```
- **sink**: `tests/fixtures/vulnerable_app/app.py:231`
  ```
  Sink: execute_command
  ```

</details>

### 4. 🔴 [CRITICAL] CWE-94

> Potential CWE-94 vulnerability detected. Data from 'get_user' may flow to dangerous sink 'execute' without proper sanitization. This finding is based on LLM semantic analysis verified against the Code Property Graph.

**Source:** `get_user` at `tests/fixtures/vulnerable_app/app.py:44`

**Sink:** `execute` at `tests/fixtures/vulnerable_app/utils.py:188`

<details>
<summary>Trace</summary>

- **source**: `tests/fixtures/vulnerable_app/app.py:44`
  ```
  Source: get_user
  ```
- **sink**: `tests/fixtures/vulnerable_app/utils.py:188`
  ```
  Sink: execute
  ```

</details>

### 5. 🟠 [HIGH] CWE-89

> Potential CWE-89 vulnerability detected. Data from 'get_user' may flow to dangerous sink 'raw_query' without proper sanitization. This finding is based on LLM semantic analysis verified against the Code Property Graph.

**Source:** `get_user` at `tests/fixtures/vulnerable_app/app.py:44`

**Sink:** `raw_query` at `tests/fixtures/vulnerable_app/database.py:177`

<details>
<summary>Trace</summary>

- **source**: `tests/fixtures/vulnerable_app/app.py:44`
  ```
  Source: get_user
  ```
- **sink**: `tests/fixtures/vulnerable_app/database.py:177`
  ```
  Sink: raw_query
  ```

</details>

### 6. 🟠 [HIGH] CWE-22

> Potential CWE-22 vulnerability detected. Data from 'get_user' may flow to dangerous sink 'write_file' without proper sanitization. This finding is based on LLM semantic analysis verified against the Code Property Graph.

**Source:** `get_user` at `tests/fixtures/vulnerable_app/app.py:44`

**Sink:** `write_file` at `tests/fixtures/vulnerable_app/utils.py:83`

<details>
<summary>Trace</summary>

- **source**: `tests/fixtures/vulnerable_app/app.py:44`
  ```
  Source: get_user
  ```
- **sink**: `tests/fixtures/vulnerable_app/utils.py:83`
  ```
  Sink: write_file
  ```

</details>

### 7. 🔴 [CRITICAL] CWE-78

> Potential CWE-78 vulnerability detected. Data from 'get_users_sorted' may flow to dangerous sink 'run_command' without proper sanitization. This finding is based on LLM semantic analysis verified against the Code Property Graph.

**Source:** `get_users_sorted` at `tests/fixtures/vulnerable_app/database.py:95`

**Sink:** `run_command` at `tests/fixtures/vulnerable_app/utils.py:24`

<details>
<summary>Trace</summary>

- **source**: `tests/fixtures/vulnerable_app/database.py:95`
  ```
  Source: get_users_sorted
  ```
- **sink**: `tests/fixtures/vulnerable_app/utils.py:24`
  ```
  Sink: run_command
  ```

</details>

### 8. 🔴 [CRITICAL] CWE-94

> Potential CWE-94 vulnerability detected. Data from 'get_users_sorted' may flow to dangerous sink 'evaluate' without proper sanitization. This finding is based on LLM semantic analysis verified against the Code Property Graph.

**Source:** `get_users_sorted` at `tests/fixtures/vulnerable_app/database.py:95`

**Sink:** `evaluate` at `tests/fixtures/vulnerable_app/utils.py:182`

<details>
<summary>Trace</summary>

- **source**: `tests/fixtures/vulnerable_app/database.py:95`
  ```
  Source: get_users_sorted
  ```
- **sink**: `tests/fixtures/vulnerable_app/utils.py:182`
  ```
  Sink: evaluate
  ```

</details>

### 9. 🔴 [CRITICAL] CWE-78

> Potential CWE-78 vulnerability detected. Data from 'get_users_sorted' may flow to dangerous sink 'execute_command' without proper sanitization. This finding is based on LLM semantic analysis verified against the Code Property Graph.

**Source:** `get_users_sorted` at `tests/fixtures/vulnerable_app/database.py:95`

**Sink:** `execute_command` at `tests/fixtures/vulnerable_app/app.py:231`

<details>
<summary>Trace</summary>

- **source**: `tests/fixtures/vulnerable_app/database.py:95`
  ```
  Source: get_users_sorted
  ```
- **sink**: `tests/fixtures/vulnerable_app/app.py:231`
  ```
  Sink: execute_command
  ```

</details>

### 10. 🔴 [CRITICAL] CWE-94

> Potential CWE-94 vulnerability detected. Data from 'get_users_sorted' may flow to dangerous sink 'execute' without proper sanitization. This finding is based on LLM semantic analysis verified against the Code Property Graph.

**Source:** `get_users_sorted` at `tests/fixtures/vulnerable_app/database.py:95`

**Sink:** `execute` at `tests/fixtures/vulnerable_app/utils.py:188`

<details>
<summary>Trace</summary>

- **source**: `tests/fixtures/vulnerable_app/database.py:95`
  ```
  Source: get_users_sorted
  ```
- **sink**: `tests/fixtures/vulnerable_app/utils.py:188`
  ```
  Sink: execute
  ```

</details>

### 11. 🟠 [HIGH] CWE-89

> Potential CWE-89 vulnerability detected. Data from 'get_users_sorted' may flow to dangerous sink 'raw_query' without proper sanitization. This finding is based on LLM semantic analysis verified against the Code Property Graph.

**Source:** `get_users_sorted` at `tests/fixtures/vulnerable_app/database.py:95`

**Sink:** `raw_query` at `tests/fixtures/vulnerable_app/database.py:177`

<details>
<summary>Trace</summary>

- **source**: `tests/fixtures/vulnerable_app/database.py:95`
  ```
  Source: get_users_sorted
  ```
- **sink**: `tests/fixtures/vulnerable_app/database.py:177`
  ```
  Sink: raw_query
  ```

</details>

### 12. 🟠 [HIGH] CWE-22

> Potential CWE-22 vulnerability detected. Data from 'get_users_sorted' may flow to dangerous sink 'write_file' without proper sanitization. This finding is based on LLM semantic analysis verified against the Code Property Graph.

**Source:** `get_users_sorted` at `tests/fixtures/vulnerable_app/database.py:95`

**Sink:** `write_file` at `tests/fixtures/vulnerable_app/utils.py:83`

<details>
<summary>Trace</summary>

- **source**: `tests/fixtures/vulnerable_app/database.py:95`
  ```
  Source: get_users_sorted
  ```
- **sink**: `tests/fixtures/vulnerable_app/utils.py:83`
  ```
  Sink: write_file
  ```

</details>

### 13. 🔴 [CRITICAL] CWE-78

> Potential CWE-78 vulnerability detected. Data from 'read_file' may flow to dangerous sink 'run_command' without proper sanitization. This finding is based on LLM semantic analysis verified against the Code Property Graph.

**Source:** `read_file` at `tests/fixtures/vulnerable_app/utils.py:76`

**Sink:** `run_command` at `tests/fixtures/vulnerable_app/utils.py:24`

<details>
<summary>Trace</summary>

- **source**: `tests/fixtures/vulnerable_app/utils.py:76`
  ```
  Source: read_file
  ```
- **sink**: `tests/fixtures/vulnerable_app/utils.py:24`
  ```
  Sink: run_command
  ```

</details>

### 14. 🔴 [CRITICAL] CWE-94

> Potential CWE-94 vulnerability detected. Data from 'read_file' may flow to dangerous sink 'evaluate' without proper sanitization. This finding is based on LLM semantic analysis verified against the Code Property Graph.

**Source:** `read_file` at `tests/fixtures/vulnerable_app/utils.py:76`

**Sink:** `evaluate` at `tests/fixtures/vulnerable_app/utils.py:182`

<details>
<summary>Trace</summary>

- **source**: `tests/fixtures/vulnerable_app/utils.py:76`
  ```
  Source: read_file
  ```
- **sink**: `tests/fixtures/vulnerable_app/utils.py:182`
  ```
  Sink: evaluate
  ```

</details>

### 15. 🔴 [CRITICAL] CWE-78

> Potential CWE-78 vulnerability detected. Data from 'read_file' may flow to dangerous sink 'execute_command' without proper sanitization. This finding is based on LLM semantic analysis verified against the Code Property Graph.

**Source:** `read_file` at `tests/fixtures/vulnerable_app/utils.py:76`

**Sink:** `execute_command` at `tests/fixtures/vulnerable_app/app.py:231`

<details>
<summary>Trace</summary>

- **source**: `tests/fixtures/vulnerable_app/utils.py:76`
  ```
  Source: read_file
  ```
- **sink**: `tests/fixtures/vulnerable_app/app.py:231`
  ```
  Sink: execute_command
  ```

</details>

### 16. 🔴 [CRITICAL] CWE-94

> Potential CWE-94 vulnerability detected. Data from 'read_file' may flow to dangerous sink 'execute' without proper sanitization. This finding is based on LLM semantic analysis verified against the Code Property Graph.

**Source:** `read_file` at `tests/fixtures/vulnerable_app/utils.py:76`

**Sink:** `execute` at `tests/fixtures/vulnerable_app/utils.py:188`

<details>
<summary>Trace</summary>

- **source**: `tests/fixtures/vulnerable_app/utils.py:76`
  ```
  Source: read_file
  ```
- **sink**: `tests/fixtures/vulnerable_app/utils.py:188`
  ```
  Sink: execute
  ```

</details>

### 17. 🟠 [HIGH] CWE-89

> Potential CWE-89 vulnerability detected. Data from 'read_file' may flow to dangerous sink 'raw_query' without proper sanitization. This finding is based on LLM semantic analysis verified against the Code Property Graph.

**Source:** `read_file` at `tests/fixtures/vulnerable_app/utils.py:76`

**Sink:** `raw_query` at `tests/fixtures/vulnerable_app/database.py:177`

<details>
<summary>Trace</summary>

- **source**: `tests/fixtures/vulnerable_app/utils.py:76`
  ```
  Source: read_file
  ```
- **sink**: `tests/fixtures/vulnerable_app/database.py:177`
  ```
  Sink: raw_query
  ```

</details>

### 18. 🟠 [HIGH] CWE-22

> Potential CWE-22 vulnerability detected. Data from 'read_file' may flow to dangerous sink 'write_file' without proper sanitization. This finding is based on LLM semantic analysis verified against the Code Property Graph.

**Source:** `read_file` at `tests/fixtures/vulnerable_app/utils.py:76`

**Sink:** `write_file` at `tests/fixtures/vulnerable_app/utils.py:83`

<details>
<summary>Trace</summary>

- **source**: `tests/fixtures/vulnerable_app/utils.py:76`
  ```
  Source: read_file
  ```
- **sink**: `tests/fixtures/vulnerable_app/utils.py:83`
  ```
  Sink: write_file
  ```

</details>

---

*Generated by Cerberus SAST v1.0.0*
*Neuro-Symbolic Self-Configuring Security Scanner*