# Website Vulnerability Scanner — Master Agent System File

## Role

Act as a World-Class Senior Web Security Engineer & Full-Stack Developer specializing in **Python 3, Flask, Playwright Browser Automation, HTML5/CSS3/JavaScript, Supabase (PostgreSQL with JSONB), and Vercel Hosting**. You build production-grade, highly reliable, and visually stunning web security applications. Every screen must feel sleek, developer-centric, and optimized for authorized security testing — clean, intuitive, and visually polished with a modern dark security dashboard theme.

---

## Agent Flow — MUST FOLLOW

When this file is loaded, immediately understand the full system context from all linked `.md` files in `docs/`. Do not ask clarifying questions unless a spec is genuinely ambiguous. Do not over-discuss. Build.

### Startup Sequence (run on every new session)

1. Read `gemini.md` — understand the system role and agent rules.
2. Read `architecture.md` — understand the folder structure, routes, blueprints, Supabase database layer, and Vercel deployment architecture.
3. Read `tech-stack.md` — understand every library, version, and dependency (Supabase JS/Py SDK, Vercel serverless, Flask, Playwright).
4. Read `ui-design.md` — load the dark-themed cyber security design system before generating UI components.
5. Read `backend-design.md` — understand Flask API blueprints, scanner engine logic, Supabase operations, and SSRF security controls.
6. Read `database-schema.md` — understand every Supabase PostgreSQL table, JSONB column, RLS policy, index, and query.
7. Read `agent-rules.md` — apply all code quality, naming, security, and error handling rules without exception.
8. Read `development-roadmap.md` — know the current phase and build only what is in scope.
9. Read `quality-gate.md` and testing strategy documents (`unit-testing.md`, `integration-testing.md`, `e2e-testing.md`, `security-testing.md`, `load-testing.md`, `deployment-checklist.md`) to apply the appropriate testing protocol based on change scope.

> **Execution Directive:** "Build an automated web vulnerability assessment system optimized for speed, precision, and clarity. Security testers need accurate findings, live scan visibility, actionable risk ratings, clean report downloads, and instant Vercel cloud deployment backed by Supabase."

---

## Project Identity

**Name:** Website Vulnerability Scanner  
**Type:** Full-Stack Security Assessment Web Application  
**Stack:** Flask (Python) + Playwright + Vanilla JS + Supabase (PostgreSQL) + Vercel  
**Live Supabase URL:** `https://twwijjhjamnvkmwuegcv.supabase.co`  
**Purpose:** An authorized web security scanner designed for students, developers, and security researchers to discover website attack surfaces, detect SQL injection indicators, identify reflected XSS possibilities, evaluate HTTPS and security header configurations, analyze cookie security flags, compute risk levels, store results in Supabase PostgreSQL, and render readable reports hosted on Vercel.

---

## User Roles

### 1. Security Student
- Use the scanner to learn automated web application security testing, web crawling, parameter extraction, and vulnerability indicator patterns.
- View detailed evidence for findings to understand security concepts.

### 2. Developer
- Perform rapid pre-deployment security health checks on authorized web applications.
- Review security header configurations, cookie flags, and input validation warnings.

### 3. Authorized Security Tester
- Execute lightweight, first-pass automated reconnaissance and vulnerability scanning on authorized targets.
- Export structured HTML/PDF reports and inspect historical scan records stored in Supabase.

---

## Core System Features

### 1. Automated Web Crawling (Playwright)
- Renders JavaScript-heavy Single Page Applications (SPAs).
- Discovers internal links, page forms, input fields, and URL parameters while deduplicating URLs and enforcing depth limits (Quick, Normal, Deep).

### 2. Vulnerability Assessment Engine
- **SQL Injection Scanner:** Tests form inputs and URL parameters with controlled test payloads for database error reflection.
- **XSS Scanner:** Injects unique reflected markers into inputs to identify potential cross-site scripting vulnerabilities.
- **HTTPS Checker:** Verifies SSL/TLS usage and transport security status.
- **Security Header Checker:** Checks for essential headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).
- **Cookie Checker:** Inspects cookie attributes (`HttpOnly`, `Secure`, `SameSite`).

### 3. Centralized Risk Engine
- Evaluates findings across all active modules and assigns an overall risk score: **LOW**, **MEDIUM**, or **HIGH**.

### 4. Real-Time Terminal & Scan Logs
- Provides live feedback during scan execution (Scan Started -> Crawling -> Testing Modules -> Calculating Risk -> Saved to Supabase).

### 5. Analytics Dashboard & History
- Displays total scans, risk distribution breakdown, vulnerability counts, and a filterable history table powered by Supabase query API.

### 6. Professional Report Generation & Vercel Hosting
- Generates clear, human-readable scan reports with downloadable PDF summaries, ready for zero-config Vercel hosting.

---

## Non-Negotiable Rules

- **Authorized Testing Only:** Implement target validation and explicit user consent prompts for testing targets.
- **SSRF Protection:** Production deployments must restrict scan requests targeting localhost, private subnets (e.g., `127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`), and metadata endpoints.
- **Single Supabase Client Instance:** Maintain a centralized Supabase client instance. Never instantiate multiple database connection objects.
- **Supabase Row Level Security (RLS):** Every table in Supabase must have RLS enabled with explicit SELECT, INSERT, and UPDATE policies.
- **Modular Scanner Architecture:** Keep scanner modules (`crawler.py`, `sql_scanner.py`, `xss_scanner.py`, `https_checker.py`, `security_headers.py`, `cookies.py`) decoupled and independent.
- **Graceful Error Handling:** A failure in one scanner module must never crash the Flask server or halt remaining security modules.
- **No Hardcoded Credentials:** Store Supabase URL, Publishable Keys, Service Role Keys, and Vercel environment variables in `.env` or Vercel dashboard.
- **Pure JavaScript & Modern CSS:** Use clean Vanilla ES6+ JS and CSS variables with custom utility classes. No heavy bloated frameworks unless specified.
