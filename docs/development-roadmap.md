# Development Roadmap — Website Vulnerability Scanner

## Role of This File

This file defines the phased build sequence for the Website Vulnerability Scanner application. The AI agent and developers must always build features according to the active phase. Do not skip phases or introduce out-of-scope features before foundational components are complete.

---

## Roadmap Overview

```
Phase 1 — Project Foundation & Supabase Setup
Phase 2 — Playwright Web Crawler & Surface Discovery
Phase 3 — Security Vulnerability Scanner Modules
Phase 4 — Centralized Risk Engine & Supabase Persistence
Phase 5 — Live Terminal Log Streaming & Progress Tracking
Phase 6 — Scan Report View & PDF Generation
Phase 7 — Analytics Dashboard & Scan History
Phase 8 — Vercel Deployment, Security Hardening & Testing
```

---

## Phase Breakdown & Deliverables

### Phase 1 — Project Foundation & Supabase Setup
**Goal:** Establish project directory structure, setup Python environment, Flask API core, Supabase schema migration via MCP, and UI layout shell.
**Deliverables:**
- [x] Apply Supabase database migration via MCP (`public.scans` table, RLS policies, indexes)
- [ ] Create project folder structure (`backend/`, `frontend/`, `docs/`, `tests/`)
- [ ] Setup `requirements.txt`, `.env.example`, and `vercel.json`
- [ ] Initialize `backend/app.py` with CORS, blueprint registration, and health endpoint (`/api/health`)
- [ ] Setup Supabase connection client in `backend/database.py`
- [ ] Create base HTML/CSS layout with cyber dark theme tokens (`frontend/css/main.css`)

### Phase 2 — Playwright Web Crawler & Surface Discovery
**Goal:** Implement browser automation with Playwright to crawl SPA sites and collect links, forms, inputs, and parameters.
**Deliverables:**
- [ ] Implement `backend/scanner/crawler.py` using Playwright headless browser
- [ ] Crawl target URL, follow internal links up to configured scan depth (Quick, Normal, Deep)
- [ ] Extract page title, forms (`action`, `method`), input fields (`name`, `type`), and URL query parameters
- [ ] URL deduplication and domain host scope constraint logic

### Phase 3 — Security Vulnerability Scanner Modules
**Goal:** Build independent, modular vulnerability scanners for SQL Injection, Reflected XSS, HTTPS, Headers, and Cookies.
**Deliverables:**
- [ ] Implement `backend/scanner/sql_scanner.py` (controlled test string injection & DB error regex matcher)
- [ ] Implement `backend/scanner/xss_scanner.py` (unique reflection marker payload injector & DOM validator)
- [ ] Implement `backend/scanner/https_checker.py` (HTTPS scheme, SSL certificate validity & redirect inspector)
- [ ] Implement `backend/scanner/security_headers.py` (CSP, HSTS, X-Frame-Options, X-Content-Type-Options check)
- [ ] Implement `backend/scanner/cookies.py` (HttpOnly, Secure, SameSite flag inspector)

### Phase 4 — Centralized Risk Engine & Supabase Persistence
**Goal:** Score findings into HIGH/MEDIUM/LOW risk levels and persist full scan documents in Supabase.
**Deliverables:**
- [ ] Implement `backend/risk_engine.py` scoring algorithm
- [ ] Save scan records into Supabase `scans` table with status flags (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`)
- [ ] Create API route `POST /api/scan` to initiate scan asynchronously

### Phase 5 — Live Terminal Log Streaming & Progress Tracking
**Goal:** Provide real-time UI log output during scan execution.
**Deliverables:**
- [ ] Implement log streaming buffer in scan runner
- [ ] Create status polling endpoint `GET /api/scan/<scan_id>/status`
- [ ] Build terminal console component in `frontend/pages/index.html` with color-coded log lines

### Phase 6 — Scan Report View & PDF Generation
**Goal:** Build readable report UI and server-side PDF report downloads.
**Deliverables:**
- [ ] Create `frontend/pages/report.html` & `frontend/js/report.js`
- [ ] Render Summary Metric Cards (Overall Risk Badge, Links, Forms, Findings count)
- [ ] Implement `backend/reports/report_generator.py` using ReportLab for downloadable PDF reports

### Phase 7 — Analytics Dashboard & Scan History
**Goal:** Provide system-wide scan history and aggregated risk metrics.
**Deliverables:**
- [ ] Create `frontend/pages/history.html` & `frontend/js/history.js` using Supabase JS client
- [ ] Create `frontend/pages/dashboard.html` & `frontend/js/dashboard.js` with Chart.js

### Phase 8 — Vercel Deployment, Security Hardening & Testing
**Goal:** Hardening, SSRF validation, full test suite execution, and Vercel cloud deployment.
**Deliverables:**
- [ ] SSRF validation blocking localhost, private IP subnets, and DNS resolution traps
- [ ] Run full pytest test suite
- [ ] Deploy to Vercel via Vercel CLI / Git integration
- [ ] Post-deployment smoke test verification

---

## Current Phase Tracker

```
Phase 1 — Project Foundation & Supabase Setup [IN PROGRESS]
Phase 2 — Playwright Web Crawler Module    [ ] TODO
Phase 3 — Vulnerability Scanner Modules    [ ] TODO
Phase 4 — Risk Engine & Persistence        [ ] TODO
Phase 5 — Live Terminal & Progress UI      [ ] TODO
Phase 6 — Report UI & PDF Generator        [ ] TODO
Phase 7 — Dashboard & Scan History         [ ] TODO
Phase 8 — Vercel Deployment & Hardening    [ ] TODO
```
