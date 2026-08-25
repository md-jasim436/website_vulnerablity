# Load & Performance Testing — Website Vulnerability Scanner

## Overview

Load and performance testing evaluates how the Website Vulnerability Scanner platform behaves under concurrent scan requests, high network traffic, and heavy browser context creation.

---

## Tools

- **Framework:** Locust or k6

---

## Load Scenarios to Test

### 1. Concurrent Scan Requests
- **Scenario:** Simulate 5 to 10 concurrent users submitting `POST /api/scan` requests simultaneously.
- **Metrics to Watch:**
  - Background queueing behavior.
  - Playwright browser instance memory footprint (Chromium process count).
  - Flask API response latency (must remain < 300ms for status polling).

### 2. Status Polling Load
- **Scenario:** Simulate 50 active client browsers polling `GET /api/scan/<scan_id>/status` every 2 seconds.
- **Metrics to Watch:**
  - PyMongo read performance and connection pool utilization.
  - Server CPU and RAM usage.

---

## System Resource Thresholds

- **API Response Latency:** 95% of API requests (`GET /status`, `GET /history`, `GET /dashboard`) must complete under 200ms.
- **Browser Context Bounding:** Maximum concurrent Playwright browser contexts capped at 3 per worker node to prevent RAM exhaustion.
- **Timeout Enforcement:** Crawl navigation timeout hard-capped at 15,000 ms.
