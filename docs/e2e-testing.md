# End-to-End (E2E) Testing Strategy — Website Vulnerability Scanner

## Overview

End-to-End (E2E) testing simulates full real-world scan workflows from the user's perspective, verifying that the entire application stack — Frontend HTML/JS -> Flask API -> Playwright Crawler -> Scanner Modules -> MongoDB -> Report View — functions seamlessly.

---

## Tools

- **Framework:** Playwright for Node.js / Python or Cypress

---

## Critical E2E Scenarios to Test

### 1. Complete Scan Lifecycle Flow
- **Step 1:** Navigate to `http://localhost:5000/index.html`.
- **Step 2:** Enter target URL `https://testphp.vulnweb.com/`.
- **Step 3:** Select Scope `Quick Scan`, check all security modules, and click "Start Security Scan".
- **Step 4:** Verify progress bar animates and live terminal console streams log lines (`Initiating crawl...`, `Discovered links...`).
- **Step 5:** Wait for scan completion -> Verify redirection to `report.html?id=<scan_id>`.
- **Step 6:** Verify Summary metrics, Risk Badge (`HIGH`), vulnerability findings cards, and header/cookie tables render correct backend data.
- **Step 7:** Click "Download PDF Report" -> Verify browser downloads PDF document.

### 2. Scan History & Filtering Flow
- **Step 1:** Navigate to `history.html`.
- **Step 2:** Verify list of previous scan cards/rows loads from MongoDB.
- **Step 3:** Enter search query `vulnweb` -> Verify table filters results dynamically.
- **Step 4:** Select Risk filter `HIGH` -> Verify only High risk scans display.

### 3. Analytics Dashboard Flow
- **Step 1:** Navigate to `dashboard.html`.
- **Step 2:** Verify Donut chart and Category Bar chart render without visual glitches or JS console errors.

---

## Execution Command

```bash
npx playwright test tests/e2e/
```
