# Quality Gate Criteria — Website Vulnerability Scanner

## Overview

A Quality Gate is a set of strict conditions that the codebase must meet before it can be merged into the main branch or deployed to production. This ensures that changes do not degrade system stability, compromise security boundaries, or break vulnerability scanner modules.

---

## Pre-Merge Quality Gate (Pull Requests)

Before any code is merged into the repository, it must pass the following automated checks:

1. **Code Linting & Formatting:** Python code passes `flake8` / `black` checks with zero fatal errors or syntax violations.
2. **Automated Unit Tests:** 100% of existing unit tests in `tests/unit/` must pass using `pytest`.
3. **Module Isolation Verification:** Every scanner module (`sql_scanner.py`, `xss_scanner.py`, `https_checker.py`, `security_headers.py`, `cookies.py`) must pass standalone execution tests.
4. **Code Coverage:** New backend code must maintain or increase overall test coverage (Target: >80%).
5. **Dependency Vulnerability Scan:** No high or critical vulnerabilities in Python dependencies (`pip audit`).

---

## Pre-Deployment Quality Gate (Staging / Production)

Before deploying a release to a live staging or production environment:

1. **End-to-End Test Execution:** Complete scan workflow tested against a controlled local target site (`POST /api/scan` -> Crawl -> Modules -> MongoDB -> Report rendering).
2. **SSRF Guard Verification:** Automated test verifies that requests targeting `127.0.0.1`, `localhost`, and `169.254.169.254` are blocked with 403 Forbidden.
3. **Database Index Check:** MongoDB collections verify that indexes on `created_at`, `url`, and `risk_level` exist.
4. **Peer Review:** Code reviewed and approved by lead security developer.

---

## Enforcement

Quality Gates should be automated via CI/CD pipelines (e.g., GitHub Actions). If any gate fails, deployment is automatically halted until resolved.
