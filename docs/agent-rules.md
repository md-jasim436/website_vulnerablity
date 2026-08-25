# Agent Rules — Website Vulnerability Scanner

## Role of This File

This file defines mandatory operating rules for the AI development agent and human engineers building the Website Vulnerability Scanner. These rules govern code quality, Flask API architecture, Supabase integration, Vercel deployment standards, and security boundaries. Every rule applies without exception.

---

## Prime Directive

> "Build production-quality, fast, modular, and secure code. Every API endpoint must validate input parameters, enforce SSRF target protection, and return standard JSON error responses. Scanner modules must run independently with isolated error handling. Database interactions must utilize Supabase PostgreSQL with RLS enabled. Deployment must be optimized for Vercel."

---

## Code Quality Rules — NEVER VIOLATE

| Rule | Detail |
|---|---|
| Python 3.10+ Standards | Use type hints where appropriate, clean function docstrings, and modular design. |
| Single Supabase Instance | Import database instance strictly via `from backend.database import get_supabase`. Never call `create_client()` inside route handlers or modules. |
| Decoupled Modules | Scanner modules (`crawler.py`, `sql_scanner.py`, etc.) must accept target data and return dictionaries without directly depending on Flask HTTP request contexts. |
| Isolated Error Handling | Enclose scanner calls in `try...except` blocks so a failure in one scanner module never halts remaining checks. |
| SSRF Target Restriction | Validate every target URL before execution. Reject requests targeting `localhost`, `127.0.0.1`, private IP subnets (`10.0.0.0/8`, `192.168.0.0/16`), or metadata IPs (`169.254.169.254`). |
| No Magic Numbers | Extract timeouts, depth limits, and ports into `config.py` or `.env`. |
| Supabase Row Level Security | Always enforce RLS policies on Supabase PostgreSQL tables. |
| Vercel Deployment Ready | Keep static frontend files in `frontend/` and Flask entry points compatible with `vercel.json`. |
| Max File Length: 250 Lines | Break large blueprint files into smaller module helpers if line count exceeds 250 lines. |
| Friendly UI Error Messages | Never expose raw Python tracebacks or database errors to the frontend UI. Show human-readable alert toasts. |
| Immediate Documentation | Whenever an API route, collection field, or architectural decision changes, immediately update the `docs/` folder. |

---

## Naming Conventions — EXACT

### Python Files & Functions
```
Blueprints:       snake_case + _routes suffix scan_routes.py, report_routes.py
Modules:          snake_case                  crawler.py, sql_scanner.py, risk_engine.py
Functions:        snake_case                  run_scan(), check_sqli(), calculate_risk()
Classes:          PascalCase                  PlaywrightCrawler, RiskEngine
Constants:        UPPER_SNAKE_CASE            DEFAULT_TIMEOUT_MS, BLOCKED_IPS
```

### Frontend Files & JavaScript
```
Pages:            lowercase                   index.html, report.html, history.html
JS Files:         lowercase                   scan.js, report.js, api.js
CSS Files:        lowercase                   main.css, components.css
JS Variables:     camelCase                   let scanId = ""; const isRunning = true;
JS Handlers:      handle prefix               const handleStartScan = () => {}
```

### Supabase Database
```
Tables:           snake_case (plural)         scans
Columns:          snake_case                  final_url, checks_requested, risk_level, created_at
```

---

## Flask & Supabase Pattern — REQUIRED

```python
# backend/routes/scan_routes.py
from flask import Blueprint, request, jsonify
from backend.database import get_supabase

scan_bp = Blueprint('scan', __name__)

@scan_bp.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"status": "error", "message": "Target URL is required"}), 400
        
    url = data['url']
    # Insert scan request into Supabase
    res = get_supabase().table("scans").insert({
        "url": url,
        "status": "RUNNING",
        "depth": data.get("depth", "quick")
    }).execute()
    
    scan_id = res.data[0]["id"]
    return jsonify({"status": "success", "scan_id": scan_id}), 202
```
