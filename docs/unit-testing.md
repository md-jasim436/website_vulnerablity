# Unit Testing Strategy — Website Vulnerability Scanner

## Overview

Unit testing involves testing individual scanner modules, utility functions, and risk scoring logic of the Website Vulnerability Scanner in isolation using mock data and virtual environments.

---

## Testing Framework & Tools

- **Framework:** `pytest` (8.x)
- **Flask Test Client:** `pytest-flask`
- **Mocking Library:** `unittest.mock` / `pytest-mock`

---

## What to Test

### 1. Security Scanner Modules
- **SQL Scanner (`tests/unit/test_sql_scanner.py`):**
  - Verify regex pattern matching against simulated DB error response strings (MySQL, PostgreSQL, SQLite).
  - Verify return dictionary structure contains payload, parameter, evidence, and issue name.
- **XSS Scanner (`tests/unit/test_xss_scanner.py`):**
  - Test payload marker reflection detection in raw HTML strings.
  - Verify proper handling when payload is safely HTML-encoded (`&lt;script&gt;`).
- **Security Headers (`tests/unit/test_security_headers.py`):**
  - Test response header dictionary parser against complete, partial, and missing header maps.
- **Cookie Checker (`tests/unit/test_cookies.py`):**
  - Test detection of missing `HttpOnly`, `Secure`, and `SameSite` flags on mock set-cookie headers.

### 2. Risk Engine (`tests/unit/test_risk_engine.py`)
- Test scoring logic with various combinations of findings:
  - SQLi finding present -> Expect `HIGH`
  - XSS finding present -> Expect `HIGH`
  - No SQLi/XSS, HTTP target -> Expect `MEDIUM`
  - All security checks passed -> Expect `LOW`

### 3. URL Validation & SSRF Guard (`tests/unit/test_ssrf_guard.py`)
- Test URL format validation logic.
- Verify private IP addresses (`127.0.0.1`, `10.0.0.1`, `192.168.1.1`, `169.254.169.254`) return validation failure.

---

## Best Practices

- **Zero Network External Calls:** Mock all HTTP network calls (`requests.get`, `requests.post`) and Playwright browser instances during unit tests.
- **Test File Naming:** `test_[module_name].py`.
- **Fast Execution:** Entire unit test suite should execute in under 5 seconds.

---

## Running Unit Tests

Run the test suite locally:
```bash
pytest tests/unit/ -v
```
