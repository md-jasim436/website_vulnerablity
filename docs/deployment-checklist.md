# Deployment Checklist — Website Vulnerability Scanner

## Overview

This checklist must be followed meticulously before, during, and after deploying a new release or update of the Website Vulnerability Scanner application.

---

## Phase 1: Pre-Deployment Verification

- [ ] All Quality Gates passed (unit, integration, and E2E tests).
- [ ] Dependencies updated and audited (`pip audit`).
- [ ] Environment configuration verified (`.env` with production `MONGO_URI`, `SECRET_KEY`, `CORS_ORIGIN`).
- [ ] Playwright browser binaries installed on production host (`playwright install chromium`).
- [ ] SSRF defense pre-resolution rules verified.
- [ ] MongoDB database connection and indexes verified.

---

## Phase 2: Deployment Execution

- [ ] 1. Pull latest code from deployment branch.
- [ ] 2. Update virtual environment dependencies (`pip install -r requirements.txt`).
- [ ] 3. Run database index setup script (`python -c "from backend.database import init_db_indexes, get_db; init_db_indexes(get_db())"`).
- [ ] 4. Restart Flask backend application server (Gunicorn / uWSGI).
- [ ] 5. Monitor startup logs for initialization errors.

---

## Phase 3: Post-Deployment Smoke Tests

Perform these manual verification checks immediately after deployment:

- [ ] **Home Page Loads:** Verify dark theme UI, scan options, and form render cleanly at `/`.
- [ ] **Target Validation:** Enter invalid URL -> Verify error message displays.
- [ ] **SSRF Defense:** Enter `http://127.0.0.1` -> Verify request blocked with 403 Forbidden.
- [ ] **Core Scan Execution:** Execute Quick Scan on authorized target (`https://testphp.vulnweb.com/`). Verify progress bar and live terminal logs.
- [ ] **Report View:** Verify report page renders summary metrics, risk badge, and findings cards.
- [ ] **PDF Download:** Verify PDF report generation succeeds.
- [ ] **History & Dashboard:** Verify scan record appears in History and updates Dashboard charts.

---

## Rollback Plan

- If critical post-deployment smoke tests fail, immediately revert backend service to the previous stable release commit.
- Restart application server and verify previous version functionality.
