# Security Testing Strategy — Website Vulnerability Scanner

## Overview

Because the Website Vulnerability Scanner accepts target web URLs and performs automated network requests, rigorous security testing must be conducted on the scanner platform itself to prevent SSRF vulnerabilities, database injection attacks, and resource exhaustion.

---

## Areas of Security Focus

### 1. Server-Side Request Forgery (SSRF) Prevention
- **Threat:** An attacker inputs `http://127.0.0.1:27017` or `http://169.254.169.254/latest/meta-data/` to scan internal services or cloud metadata.
- **Verification Tests:**
  - Submit `http://127.0.0.1` -> Expect `403 Forbidden` ("Local and private network scanning forbidden").
  - Submit `http://localhost:5000` -> Expect `403 Forbidden`.
  - Submit `http://192.168.1.1` -> Expect `403 Forbidden`.
  - Submit `http://169.254.169.254` -> Expect `403 Forbidden`.
  - Submit DNS rebinding domain resolving to `127.0.0.1` -> Pre-resolution check verifies IP before fetching.

### 2. Input Sanitization & Payload Rendering Safety
- **Threat:** A target website page title contains `<script>alert(1)</script>` or malicious HTML, which gets stored in MongoDB and rendered in the frontend Report view (Stored XSS in Scanner).
- **Verification Tests:**
  - Seed MongoDB with XSS payload string in `title` and `evidence` fields.
  - Open `report.html` in browser -> Verify content is safely rendered using `textContent` or escaped HTML templates, not `innerHTML`.

### 3. MongoDB Injection Defense
- **Threat:** Malicious payload in query string attempts NoSQL injection in PyMongo queries.
- **Verification Tests:**
  - Verify all PyMongo queries filter using explicit dictionary keys (e.g. `db.scans.find_one({"_id": ObjectId(scan_id)})`) rather than raw unvalidated user input strings.

### 4. Dependency Vulnerability Management
- Run `pip audit` and `npm audit` to detect vulnerable packages.

---

## Action Plan

- Conduct SSRF penetration test before every release.
- Ensure all frontend rendering uses secure DOM escaping.
- Restrict scanner engine egress traffic in production deployment environments.
