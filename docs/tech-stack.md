# Technology Stack — Website Vulnerability Scanner

## Role of This File

This file defines every software framework, Python package, frontend utility, database, hosting platform, and tool used in the Website Vulnerability Scanner. Developers and AI agents must use **exactly these tools and libraries**. Do not substitute or add unapproved libraries without explicit authorization.

---

## Core Framework & Runtime

| Layer | Technology | Version | Purpose |
|---|---|---|---|
| Runtime | Python | 3.10+ | Primary server execution environment |
| Framework | Flask | 3.x | Lightweight Web API & Blueprint Routing |
| CORS | Flask-CORS | 4.x | Cross-Origin Resource Sharing handling |
| Environment | python-dotenv | 1.x | Loading `.env` environment configuration |

---

## Backend & Database Layer (Supabase)

| Technology | Version | Purpose |
|---|---|---|
| Database | Supabase (PostgreSQL) | Latest | PostgreSQL cloud database with JSONB support |
| Python Client | `supabase` | 2.x | Supabase Python Client SDK |
| JavaScript Client | `@supabase/supabase-js` | 2.x | Supabase Client for Frontend SPA |
| Live Project URL | `https://twwijjhjamnvkmwuegcv.supabase.co` | Supabase Cloud API Endpoint |

### Supabase Python Client Setup — `backend/database.py`
```python
import os
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL", "https://twwijjhjamnvkmwuegcv.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", os.getenv("SUPABASE_ANON_KEY"))

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def get_supabase():
    return supabase
```

> **Rule:** Create the Supabase client instance only once in `backend/database.py`. All blueprints and modules import `get_supabase()`.

---

## Hosting & Deployment (Vercel)

| Technology | Purpose |
|---|---|
| Vercel Static Hosting | Frontend SPA (HTML5/CSS3/Vanilla JS) hosting |
| Vercel Serverless Functions | Serverless API route handling |
| Vercel CLI | Command-line deployment & environment variable management |

### Vercel Deployment Configuration — `vercel.json`
```json
{
  "version": 2,
  "builds": [
    {
      "src": "frontend/**",
      "use": "@vercel/static"
    },
    {
      "src": "backend/app.py",
      "use": "@vercel/python"
    }
  ],
  "routes": [
    {
      "src": "/api/(.*)",
      "dest": "backend/app.py"
    },
    {
      "src": "/(.*)",
      "dest": "frontend/$1"
    }
  ]
}
```

---

## Browser Automation & Network Scanner

| Library | Version | Purpose |
|---|---|---|
| Playwright for Python | 1.x | Headless browser engine for crawling JS-heavy websites |
| Requests | 2.x | Fast HTTP requests for header, cookie, and HTTPS checks |
| urllib3 | 2.x | Low-level HTTP request handling & SSL verification |

---

## Frontend Tech Stack

| Technology | Version | Purpose |
|---|---|---|
| HTML | HTML5 | Semantic page markup & layout structure |
| CSS | CSS3 (Vanilla) | Custom cyber dark design system with CSS variables |
| JavaScript | Vanilla ES6+ | Dynamic DOM manipulation, API client, & log polling |
| Supabase JS SDK | 2.x | Real-time queries & history data retrieval |
| Typography | Google Fonts (Inter + JetBrains Mono) | Clean modern typography & code terminal font |
| Icons | Lucide / FontAwesome | UI icons for status, risks, and navigation |
| Charts | Chart.js | 4.x | Dashboard analytics charts (donut & bar charts) |

---

## Environment Variables Configuration — `.env` / Vercel Env

```env
# Server Configuration
FLASK_APP=backend/app.py
FLASK_ENV=development
PORT=5000
SECRET_KEY=super-secret-key-change-in-production

# Supabase Database Configuration
SUPABASE_URL=https://twwijjhjamnvkmwuegcv.supabase.co
SUPABASE_ANON_KEY=sb_publishable_Mdu3046xmiHuYYqkJu_n0w_diK_Vleh
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key_here

# Scanner Settings
PLAYWRIGHT_HEADLESS=true
CRAWL_TIMEOUT_MS=15000
MAX_CONCURRENT_SCANS=3
```

---

## Complete Setup & Install Commands

```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install \
  flask \
  flask-cors \
  supabase \
  playwright \
  requests \
  python-dotenv \
  reportlab \
  pytest \
  pytest-flask

playwright install chromium
```

---

## What Is Intentionally Excluded & Why

| Excluded Technology | Reason |
|---|---|
| MongoDB / PyMongo | Supabase (PostgreSQL with JSONB) replaced MongoDB to provide enterprise SQL capabilities, RLS security policies, built-in REST API, and native Vercel integration. |
| React / Angular / Vue | Vanilla HTML/CSS/JS is lightweight, loads instantly, and has zero build overhead for Vercel static deployment. |
| Selenium (Alone) | Unable to handle modern SPA sites as cleanly or fast as Playwright headless Chromium. |
