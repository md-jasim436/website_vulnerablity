# Backend Design — Website Vulnerability Scanner

## Role of This File

This file defines the backend API design, Flask blueprints, scanner module implementations, Supabase PostgreSQL access layer, SSRF security controls, and error handling for the Website Vulnerability Scanner backend. AI agents and developers must implement server-side logic in strict accordance with this design.

---

## Backend Application Structure

```
backend/
├── app.py                      ← Flask entry point, registers blueprints & CORS
├── config.py                   ← App configuration loading from environment
├── database.py                 ← Supabase client initialization & helpers
├── risk_engine.py              ← Risk scoring logic
├── routes/
│   ├── scan_routes.py          ← Scan creation & status polling APIs
│   ├── report_routes.py        ← Report detail & PDF export APIs
│   ├── dashboard_routes.py     ← Dashboard analytics APIs
│   └── history_routes.py       ← Scan history listing APIs
├── scanner/
│   ├── crawler.py              ← Playwright web crawling & element discovery
│   ├── sql_scanner.py          ← SQL injection detection module
│   ├── xss_scanner.py          ← Reflected XSS detection module
│   ├── https_checker.py        ← HTTPS & TLS verification module
│   ├── security_headers.py     ← HTTP response headers evaluation module
│   └── cookies.py              ← Cookie security attributes inspector
└── reports/
    └── report_generator.py     ← PDF report generation using ReportLab
```

---

## Supabase Client Integration (`backend/database.py`)

Database operations use the official Supabase Python SDK to interact with the `scans` PostgreSQL table.

```python
import os
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL", "https://twwijjhjamnvkmwuegcv.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", os.getenv("SUPABASE_ANON_KEY"))

supabase_client: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def get_supabase():
    return supabase_client
```

---

## Data Operation Patterns with Supabase

### 1. Creating a New Scan Document
```python
def create_scan(url, depth, checks):
    data = {
        "url": url,
        "depth": depth,
        "checks_requested": checks,
        "status": "RUNNING",
        "logs": [f"[{datetime.now().strftime('%H:%M:%S')}] INFO Scan initiated for {url}"]
    }
    response = get_supabase().table("scans").insert(data).execute()
    return response.data[0]["id"]
```

### 2. Updating Scan Findings & Status
```python
def update_scan_results(scan_id, crawl_results, findings, risk_level, logs):
    update_payload = {
        "crawl_results": crawl_results,
        "findings": findings,
        "risk_level": risk_level,
        "status": "COMPLETED",
        "completed_at": datetime.now().isoformat(),
        "logs": logs
    }
    get_supabase().table("scans").update(update_payload).eq("id", scan_id).execute()
```

---

## Scanner Engine Modules Design

### 1. Crawler Engine (`backend/scanner/crawler.py`)
- **Technology:** Playwright Headless Chromium.
- **Workflow:**
  1. Launch Playwright browser instance in headless mode.
  2. Open new context & navigate to Target URL.
  3. Wait for network idle or DOM content loaded state (timeout: 15s).
  4. Extract Page Title, Final URL, Discovered Links (`<a>` tags matching domain host).
  5. Extract Page Forms (`<form>` tags: action, method, inputs).
  6. Extract Form Inputs (input names, types, default values).
  7. Extract URL Query Parameters (`?param=value`).
  8. Enforce depth & page count limits (Quick: max 5 pages; Normal: max 15 pages; Deep: max 30 pages).
  9. Clean up browser context on completion or error.

### 2. SQL Injection Scanner (`backend/scanner/sql_scanner.py`)
- Injects controlled test strings into inputs (`'`, `"`, `1' OR '1'='1`).
- Inspects response bodies for database error signatures (MySQL, PostgreSQL, SQLite, MSSQL).
- Reports possible SQL Injection with evidence snippet.

### 3. XSS Scanner (`backend/scanner/xss_scanner.py`)
- Injects unique test markers with HTML tags (`<script>alert("XSS")</script>`).
- Checks if un-escaped markers reflect back in rendered DOM.

### 4. HTTPS Checker (`backend/scanner/https_checker.py`)
- Inspects scheme protocols, SSL certificate validity, and HTTP-to-HTTPS redirect enforcement.

### 5. Security Header Checker (`backend/scanner/security_headers.py`)
- Evaluates CSP, HSTS, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy.

### 6. Cookie Checker (`backend/scanner/cookies.py`)
- Inspects cookies for missing `HttpOnly`, `Secure`, and `SameSite` flags.

---

## Risk Engine Scoring Algorithm (`backend/risk_engine.py`)

```python
def calculate_risk(findings):
    has_sqli = len(findings.get('sql', [])) > 0
    has_xss = len(findings.get('xss', [])) > 0
    is_http = not findings.get('https', {}).get('is_https', True)
    missing_headers = len(findings.get('headers', {}).get('missing', []))
    insecure_cookies = len(findings.get('cookies', {}).get('insecure', []))
    
    if has_sqli or has_xss:
        return "HIGH"
    elif is_http or missing_headers >= 3 or insecure_cookies >= 2:
        return "MEDIUM"
    else:
        return "LOW"
```

---

## SSRF Security Controls (`backend/routes/scan_routes.py`)

```python
import socket
from urllib.parse import urlparse
import ipaddress

BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
]

def validate_target_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False, "Invalid URL scheme. Only http and https are permitted."
        
    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid target hostname."
        
    try:
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)
        for net in BLOCKED_NETWORKS:
            if ip in net:
                return False, f"Forbidden scan destination ({ip_str}). Local and private networks cannot be scanned."
    except Exception as e:
        return False, f"DNS resolution failed for hostname: {hostname}"
        
    return True, "URL Validated"
```
