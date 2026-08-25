# Integration Testing Strategy — Website Vulnerability Scanner

## Overview

Integration testing verifies that different subsystems of the Website Vulnerability Scanner — Flask API endpoints, PyMongo database helpers, background worker threads, and report generators — interact correctly.

---

## Testing Framework & Tools

- **Framework:** `pytest` + `pytest-flask`
- **Database:** Local MongoDB test instance (`mongodb://localhost:27017/vulnerability_scanner_test`) or `mongomock`

---

## Key Integration Workflows to Test

### 1. API ↔ Database Integration (`tests/integration/test_api_db.py`)
- Test `POST /api/scan`:
  - Valid payload creates scan document in MongoDB with status `PENDING` / `RUNNING`.
  - Returns `202 Accepted` with valid `scan_id`.
- Test `GET /api/scan/<scan_id>`:
  - Retrieves saved scan document matching ID.
  - Returns `404 Not Found` for non-existent scan IDs.

### 2. Flask ↔ Risk Engine ↔ Report API (`tests/integration/test_report_flow.py`)
- Seed MongoDB with completed scan findings.
- Request `GET /api/reports/<scan_id>` -> Verify JSON structure contains aggregated metrics, risk level, and module details.
- Request `GET /api/reports/<scan_id>/pdf` -> Verify response header contains `Content-Type: application/pdf` and non-empty binary payload.

### 3. Dashboard Analytics Aggregation (`tests/integration/test_dashboard_api.py`)
- Seed MongoDB with multiple mock scan records (High, Medium, Low risk).
- Request `GET /api/dashboard` -> Verify aggregated counts match seeded data.

---

## Best Practices

- **Database Cleanup:** Use a `pytest` fixture to clean up the test database (`db.scans.delete_many({})`) before and after each test run.
- **Isolated Config:** Use test configuration settings (`FLASK_ENV=testing`).
- **Execution:** Run integration tests:
```bash
pytest tests/integration/ -v
```
