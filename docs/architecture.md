# System Architecture — Website Vulnerability Scanner

## Role of This File

This file defines the structural blueprint of the Website Vulnerability Scanner. All folder structures, API blueprints, background execution patterns, scanner modules, Supabase PostgreSQL database connections, and Vercel hosting rules defined here are **final and canonical**.

---

## High-Level Architecture

```
┌───────────────────────────────────────────────────────────────┐
│              CLIENT LAYER (SPA Hosted on Vercel)              │
│              Vanilla HTML5 + CSS3 + JS (ES6+)                 │
│  ┌──────────────┐  ┌─────────────────┐  ┌──────────────────┐  │
│  │   New Scan   │  │   Live Terminal │  │   Scan Report    │  │
│  │  Form / Scope│  │   Log Console   │  │   & PDF Export   │  │
│  └──────────────┘  └─────────────────┘  └──────────────────┘  │
│  ┌──────────────┐  ┌─────────────────┐                        │
│  │   Dashboard  │  │   Scan History  │                        │
│  │   Analytics  │  │   & Filters     │                        │
│  └──────────────┘  └─────────────────┘                        │
└───────────────────────────────────────────────────────────────┘
                                 │
                   HTTP / JSON   │  Live Progress Polling
                                 ▼
┌───────────────────────────────────────────────────────────────┐
│               FLASK BACKEND ENGINE (Serverless/API)           │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                     Flask Core API                      │  │
│  │  scan_routes │ report_routes │ dashboard_routes │ hist  │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                │                              │
│       ┌────────────────────────┼────────────────────────┐     │
│       ▼                        ▼                        ▼     │
│  ┌──────────────┐       ┌──────────────┐       ┌────────────┐ │
│  │  Playwright  │       │  Security    │       │   Risk     │ │
│  │   Crawler    │       │   Modules    │       │   Engine   │ │
│  │  (Links,     │       │ (SQLi, XSS,  │       │ (LOW, MED, │ │
│  │ Forms, Params│       │ Headers,     │       │   HIGH)    │ │
│  │  Discovery)  │       │ Cookies, HTTPS│      └────────────┘ │
│  └──────────────┘       └──────────────┘                      │
└───────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌───────────────────────────────────────────────────────────────┐
│                 SUPABASE DATABASE LAYER (PostgreSQL)          │
│               https://twwijjhjamnvkmwuegcv.supabase.co        │
│    Table: public.scans (UUID, JSONB findings, RLS Enabled)   │
└───────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌───────────────────────────────────────────────────────────────┐
│                      VERCEL HOSTING LAYER                     │
│                  Vercel Edge Network & Serverless             │
└───────────────────────────────────────────────────────────────┘
```

---

## Folder Structure — CANONICAL (NEVER DEVIATE)

```
website-vulnerability-scanner/
├── backend/
│   ├── app.py                      ← Flask entry point & blueprint registration
│   ├── config.py                   ← Environment configuration settings
│   ├── database.py                 ← Supabase Python client initialization & helpers
│   ├── risk_engine.py              ← Risk scoring rule algorithm
│   │
│   ├── routes/                     ← Flask API Route Blueprints
│   │   ├── scan_routes.py          ← POST /api/scan, GET /api/scan/<id>/status
│   │   ├── report_routes.py        ← GET /api/reports/<id>, PDF download
│   │   ├── dashboard_routes.py     ← GET /api/dashboard statistics
│   │   └── history_routes.py       ← GET /api/history scan listings
│   │
│   ├── scanner/                    ← Core Vulnerability Scanning Engine
│   │   ├── crawler.py              ← Playwright headless browser crawler
│   │   ├── sql_scanner.py          ← SQL injection payload tester & error matcher
│   │   ├── xss_scanner.py          ← Reflected XSS payload marker tester
│   │   ├── https_checker.py        ← HTTPS & TLS validator
│   │   ├── security_headers.py     ← HTTP response header analyzer
│   │   └── cookies.py              ← Cookie security flag inspector
│   │
│   └── reports/
│       └── report_generator.py     ← PDF/HTML report builder (ReportLab)
│
├── frontend/
│   ├── css/
│   │   ├── main.css                ← CSS variables & theme tokens
│   │   └── components.css          ← Cards, buttons, terminal, badges
│   │
│   ├── js/
│   │   ├── api.js                  ← Centralized fetch API & Supabase JS client wrapper
│   │   ├── app.js                  ← Navigation & common initializers
│   │   ├── scan.js                 ← Scan form submission & terminal log stream
│   │   ├── report.js               ← Report view rendering & PDF download
│   │   ├── history.js              ← History table filtering & retrieval
│   │   └── dashboard.js            ← Dashboard analytics charts
│   │
│   └── pages/
│       ├── index.html              ← Home / New Scan page
│       ├── report.html             ← Scan detail report view
│       ├── history.html            ← Past scans history view
│       └── dashboard.html          ← Analytics dashboard view
│
├── vercel.json                     ← Vercel deployment configuration
├── docs/                           ← System documentation
├── tests/                          ← Pytest unit and integration test suite
├── .env.example                    ← Example environment file with Supabase keys
├── requirements.txt                ← Python package dependencies
└── README.md                       ← Project overview & quickstart guide
```

---

## Route Architecture

### REST API Routes (Flask Blueprints)

| Endpoint | Method | Purpose | Request Payload / Params |
|---|---|---|---|
| `/api/health` | GET | Check API & Supabase health | None |
| `/api/scan` | POST | Trigger a new web scan | `{ url, depth, checks }` |
| `/api/scan/<scan_id>/status` | GET | Poll real-time scan progress & logs | None |
| `/api/scan/<scan_id>` | GET | Fetch completed scan from Supabase | None |
| `/api/reports/<scan_id>` | GET | Fetch detailed report data | None |
| `/api/reports/<scan_id>/pdf` | GET | Download report in PDF format | None |
| `/api/history` | GET | List past scan summaries from Supabase | `?limit=20&page=1&risk=HIGH` |
| `/api/dashboard` | GET | Fetch aggregated Supabase stats | None |

### Frontend Page Routes (Vercel Static Hosting)

| URL Path | Page Template | Purpose |
|---|---|---|
| `/` or `/index.html` | `frontend/pages/index.html` | URL entry, scan options, live log terminal |
| `/report.html?id=<id>` | `frontend/pages/report.html` | Detailed vulnerability report view |
| `/history.html` | `frontend/pages/history.html` | Filterable list of previous scans from Supabase |
| `/dashboard.html` | `frontend/pages/dashboard.html` | Overall security metrics & charts |

---

## Data Flow Architecture

### 1. Scan Initiation & Execution Flow
```
User submits Target URL (e.g., https://example.com)
    │
    ▼
Frontend validates URL format -> POST /api/scan
    │
    ▼
Flask validates target URL (SSRF check: blocks 127.0.0.1, private IPs)
    │
    ▼
Flask creates scan record in Supabase `scans` table (status = "RUNNING")
    │
    ▼
Launch Background Worker / Thread:
    │
    ├── 1. Playwright Crawler opens target -> extracts Title, Links, Forms, Params
    ├── 2. SQL Injection Scanner tests inputs with test payloads
    ├── 3. XSS Scanner tests inputs with reflection markers
    ├── 4. HTTPS Checker validates TLS connection
    ├── 5. Security Header Checker checks response headers
    ├── 6. Cookie Checker checks HttpOnly, Secure, SameSite flags
    └── 7. Risk Engine scores findings -> assigns LOW / MEDIUM / HIGH
    │
    ▼
Update scan record in Supabase `scans` table (status = "COMPLETED", risk_level = "HIGH/MEDIUM/LOW")
    │
    ▼
Frontend receives completion signal -> renders Report view
```

### 2. Vercel & Supabase Cloud Integration
```
Vercel Edge Network (Hosts Frontend SPA + API Routing)
    │
    ├── REST API requests -> Flask Backend / Serverless Worker
    │                            │
    │                            ▼
    └── Supabase JS Client / Py Client -> Supabase PostgreSQL (https://twwijjhjamnvkmwuegcv.supabase.co)
                                              (Stores Scans, RLS Enforced)
```

---

## System Boundaries & Security Rules

| Boundary | Enforcement Rule |
|---|---|
| Frontend ↔ Supabase | Frontend uses `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` for direct read operations when needed. |
| Backend ↔ Supabase | Flask backend uses Supabase Python client or REST API to insert/update scan documents. |
| Target Scope | Scanner only crawls internal links matching the initial domain host. |
| SSRF Safeguard | Target host IP is pre-resolved before crawling. Requests to `localhost`, `127.0.0.1`, `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`, and cloud metadata services (`169.254.169.254`) are rejected immediately. |
| Playwright Resource Limits | Max concurrency bounded to 3 browser contexts. Navigation timeout set to 15,000 ms. |
| Supabase Row Level Security | RLS is enabled on `public.scans` with explicit SELECT, INSERT, and UPDATE policies. |
