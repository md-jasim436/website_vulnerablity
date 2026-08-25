# Test Credentials & Target Environments — Website Vulnerability Scanner

## Overview

This document provides authorized test environments, mock target sites, sample request payloads, and live Supabase cloud database credentials for developing and testing the Website Vulnerability Scanner.

---

## Live Supabase Cloud Project Configuration

The database table `public.scans` is live on Supabase with RLS policies and performance indexes active.

```env
SUPABASE_URL=https://twwijjhjamnvkmwuegcv.supabase.co
SUPABASE_ANON_KEY=sb_publishable_Mdu3046xmiHuYYqkJu_n0w_diK_Vleh
```

---

## Authorized Online Training Targets

The following sites are explicitly designed and hosted by security organizations for authorized vulnerability scanner testing:

### 1. Acunetix TestPHP VulnWeb
- **URL:** `http://testphp.vulnweb.com/`
- **Purpose:** Test SQL Injection, Reflected XSS, Form & Parameter discovery.
- **Expected Risk Level:** `HIGH`

### 2. Altoro Mutual (IBM Test Target)
- **URL:** `http://demo.testfire.net/`
- **Purpose:** Test banking form scanning, link harvesting, and header inspection.
- **Expected Risk Level:** `HIGH` / `MEDIUM`

---

## Local & Vercel Development Environment Setup

### Local `.env` Configuration
```env
FLASK_APP=backend/app.py
FLASK_ENV=development
PORT=5000

# Supabase Credentials
SUPABASE_URL=https://twwijjhjamnvkmwuegcv.supabase.co
SUPABASE_ANON_KEY=sb_publishable_Mdu3046xmiHuYYqkJu_n0w_diK_Vleh

# Scanner Settings
PLAYWRIGHT_HEADLESS=true
CRAWL_TIMEOUT_MS=15000
MAX_CONCURRENT_SCANS=3
```

### Sample API Scan Request Payload (`POST /api/scan`)
```json
{
  "url": "http://testphp.vulnweb.com/",
  "depth": "quick",
  "checks": {
    "sql": true,
    "xss": true,
    "https": true,
    "headers": true,
    "cookies": true
  }
}
```
