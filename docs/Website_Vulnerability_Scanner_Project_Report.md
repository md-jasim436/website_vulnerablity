# Website Vulnerability Scanner — Detailed Project Report

## 1. Executive Summary

The **Website Vulnerability Scanner** is an end-to-end, full-stack web security assessment platform engineered for authorized security testing, educational learning, and developer pre-deployment checks. The platform allows users to input a target website URL, crawl the target application using Playwright browser automation, discover internal links, forms, input fields, and URL query parameters, execute specialized vulnerability assessment modules (SQL Injection indicators, Reflected XSS markers, HTTPS transport security, HTTP Security Headers, and Cookie security flags), calculate an aggregated risk classification, persist scan records in a **Supabase PostgreSQL database**, and present human-readable reports and downloadable PDFs through an intuitive dark-themed security dashboard hosted on **Vercel**.

---

## 2. Problem Statement

Manual web application security assessment is tedious, repetitive, and error-prone. Security evaluators and developers must manually inspect target web applications to:
1. Discover all reachable pages and internal hyper-links.
2. Identify input fields, submission forms, and URL query parameters.
3. Check transport layer security (HTTPS) and SSL configuration.
4. Verify response headers for missing security controls (CSP, HSTS, X-Frame-Options).
5. Inspect cookie security flags (`HttpOnly`, `Secure`, `SameSite`).
6. Test form fields and URL parameters for injection vulnerabilities.

This application automates these reconnaissance and initial assessment tasks in a unified, automated cloud workflow.

---

## 3. Project Objectives

- **URL Validation & SSRF Guard:** Accept target URLs, validate syntax, and enforce strict SSRF defenses against private network scanning.
- **Browser Automation Crawling:** Utilize Playwright headless browser to render JavaScript-heavy Single Page Applications (SPAs) and harvest links, forms, inputs, and parameters.
- **SQL Injection Detection:** Test inputs with controlled payloads and inspect HTTP responses for database error signatures.
- **Reflected XSS Detection:** Inject unique test markers into form fields and parameters to evaluate unescaped DOM reflection.
- **HTTPS & Transport Evaluation:** Check HTTPS usage, SSL certificate validity, and HTTP-to-HTTPS redirect enforcement.
- **Security Header Inspection:** Evaluate mandatory response headers including CSP, HSTS, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy.
- **Cookie Security Inspection:** Examine cookies for critical security attributes (`HttpOnly`, `Secure`, `SameSite`).
- **Risk Scoring Engine:** Compute a centralized security risk score (**LOW**, **MEDIUM**, or **HIGH**) based on aggregated module findings.
- **Supabase Cloud Persistence:** Store scan documents, findings, metrics, and execution logs in Supabase PostgreSQL (`https://twwijjhjamnvkmwuegcv.supabase.co`).
- **Vercel Cloud Deployment:** Host the frontend static SPA and API routes seamlessly on Vercel Edge Network.

---

## 4. System Scope

### In Scope
- URL validation, normalization, and SSRF filtering.
- Playwright-based headless crawling with configurable depth (Quick, Normal, Deep).
- Extraction of links, forms, input parameters, and query strings.
- Automated SQL injection indicator scanning.
- Automated Reflected XSS marker reflection scanning.
- HTTPS/TLS transport security verification.
- Response header security configuration analysis.
- Cookie security flag analysis.
- Centralized risk level scoring engine.
- Supabase PostgreSQL persistence with Row Level Security (RLS).
- Real-time scan log terminal and progress bar.
- Interactive HTML report views, downloadable PDF reports, and Vercel hosting.

### Out of Scope
- Complete or guaranteed vulnerability discovery (false positives/negatives may occur).
- Destructive exploit execution or payload execution against target backends.
- Authentication bypass or multi-step session authenticated penetration testing.
- Source code static analysis (SAST) or binary analysis.
- Unrestricted internet-wide or un-authorized target scanning.

---

## 5. Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| Frontend | Vanilla HTML5, CSS3, JavaScript (ES6+) | Lightweight, dark-themed responsive UI |
| Database | Supabase (PostgreSQL) | PostgreSQL cloud database with JSONB support & RLS |
| Cloud Hosting | Vercel | Zero-config static & serverless deployment |
| Visualization | Chart.js 4.x | Donut & Bar charts for risk & category metrics |
| Backend API | Python 3.10+, Flask 3.x | REST API server & blueprint routing |
| Browser Automation | Playwright for Python | Headless Chromium rendering & SPA crawling |
| HTTP Requests | Requests & urllib3 | Fast network checks for headers, cookies & SSL |
| Report Generation | ReportLab 4.x | Server-side PDF report creation |
| Testing | pytest, pytest-flask | Automated unit & integration testing framework |

---

## 6. Architecture & System Structure

```
┌───────────────────────────────────────────────────────────────┐
│               FRONTEND USER INTERFACE (Vercel)                │
│             HTML5 + Vanilla CSS3 + JavaScript (ES6+)          │
│   New Scan Form │ Live Terminal Logs │ Report View │ Dashboard│
└───────────────────────────────────────────────────────────────┘
                                │
                   HTTP / REST  │  Progress Polling
                                ▼
┌───────────────────────────────────────────────────────────────┐
│                    FLASK BACKEND ENGINE                       │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                    Flask Blueprints                     │  │
│  │    scan_routes  │  report_routes  │  dashboard_routes   │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                │                              │
│       ┌────────────────────────┼────────────────────────┐     │
│       ▼                        ▼                        ▼     │
│  ┌──────────────┐       ┌──────────────┐       ┌────────────┐ │
│  │  Playwright  │       │  Security    │       │   Risk     │ │
│  │   Crawler    │       │   Modules    │       │   Engine   │ │
│  └──────────────┘       └──────────────┘       └────────────┘ │
└───────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌───────────────────────────────────────────────────────────────┐
│                 SUPABASE DATABASE LAYER (PostgreSQL)          │
│             https://twwijjhjamnvkmwuegcv.supabase.co          │
│                  Table: public.scans (RLS Enabled)            │
└───────────────────────────────────────────────────────────────┘
```

---

## 7. Main Project Modules

### 7.1 Flask Core & API Blueprints (`backend/routes/`)
Initializes Flask app, configures CORS, connects to Supabase via official Python client, registers API blueprints (`scan_routes`, `report_routes`, `dashboard_routes`, `history_routes`), and manages request routes.

### 7.2 Web Crawler (`backend/scanner/crawler.py`)
Launches Playwright headless Chromium browser to navigate target web pages, execute client-side JavaScript, follow internal links matching target domain, and collect forms, input names, and query parameters while enforcing depth limits.

### 7.3 SQL Injection Scanner (`backend/scanner/sql_scanner.py`)
Injects controlled test strings (e.g. `'`, `1' OR '1'='1`) into discovered form inputs and query parameters, inspecting returned HTTP response bodies for database error signatures (MySQL, PostgreSQL, SQLite, MSSQL).

### 7.4 Reflected XSS Scanner (`backend/scanner/xss_scanner.py`)
Injects unique HTML test markers into input fields and parameters, validating whether markers are reflected verbatim into DOM response content without HTML entity encoding.

### 7.5 HTTPS Checker (`backend/scanner/https_checker.py`)
Inspects scheme protocols, validates TLS certificate details, and tests HTTP-to-HTTPS redirect enforcement.

### 7.6 Security Header Checker (`backend/scanner/security_headers.py`)
Evaluates HTTP response headers for missing or misconfigured security policies (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).

### 7.7 Cookie Checker (`backend/scanner/cookies.py`)
Inspects set cookies for missing `HttpOnly`, `Secure`, and `SameSite` flags.

### 7.8 Risk Scoring Engine (`backend/risk_engine.py`)
Combines module findings and calculates an aggregated risk score (**LOW**, **MEDIUM**, or **HIGH**).

### 7.9 Database Storage (`backend/database.py`)
Manages Supabase PostgreSQL connection and persists complete scan documents, crawl results, module findings, logs, and timestamps.

### 7.10 Report Generator (`backend/reports/report_generator.py`)
Builds interactive report UIs and generates downloadable PDF summary reports using ReportLab.

---

## 8. Complete Project File Directory Tree

```
website-vulnerability-scanner/
├── backend/
│   ├── app.py
│   ├── config.py
│   ├── database.py
│   ├── risk_engine.py
│   ├── routes/
│   │   ├── scan_routes.py
│   │   ├── report_routes.py
│   │   ├── dashboard_routes.py
│   │   └── history_routes.py
│   ├── scanner/
│   │   ├── crawler.py
│   │   ├── sql_scanner.py
│   │   ├── xss_scanner.py
│   │   ├── https_checker.py
│   │   ├── security_headers.py
│   │   └── cookies.py
│   └── reports/
│       └── report_generator.py
├── frontend/
│   ├── css/
│   │   ├── main.css
│   │   └── components.css
│   ├── js/
│   │   ├── api.js
│   │   ├── app.js
│   │   ├── scan.js
│   │   ├── report.js
│   │   ├── history.js
│   │   └── dashboard.js
│   └── pages/
│       ├── index.html
│       ├── report.html
│       ├── history.html
│       └── dashboard.html
├── vercel.json
├── docs/
├── tests/
├── .env.example
├── requirements.txt
└── README.md
```

---

## 9. API Specifications

### `POST /api/scan`
- **Purpose:** Initiates a new web vulnerability scan.
- **Payload:**
```json
{
  "url": "https://example.com/",
  "depth": "quick",
  "checks": { "sql": true, "xss": true, "https": true, "headers": true, "cookies": true }
}
```

### `GET /api/scan/<scan_id>/status`
- **Purpose:** Polls real-time progress and live terminal logs from Supabase.

### `GET /api/reports/<scan_id>`
- **Purpose:** Retrieves full scan findings and details for report display.

### `GET /api/reports/<scan_id>/pdf`
- **Purpose:** Downloads generated PDF report file.

### `GET /api/history`
- **Purpose:** Fetches filterable list of previous scans from Supabase.

### `GET /api/dashboard`
- **Purpose:** Returns aggregated security statistics and risk metrics for dashboard charts.

---

## 10. Security & SSRF Protection

1. **Target Permission:** Users must scan only targets for which they hold explicit permission.
2. **SSRF Safeguards:** All target hostnames undergo DNS pre-resolution. Requests to loopback addresses (`127.0.0.1`), private IP subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), or metadata services (`169.254.169.254`) are rejected immediately.
3. **Supabase Row Level Security:** RLS policies restrict table queries and guarantee database access safety.

---

## 11. Conclusion

The Website Vulnerability Scanner integrates modern browser automation, multi-module security scanning, RESTful API architecture, Supabase PostgreSQL cloud database storage, Vercel hosting, and sleek dark-mode UI reporting into an efficient web security tool.
