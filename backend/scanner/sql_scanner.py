import re
import time
import requests
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger(__name__)

# ─── SQL Error Signatures ────────────────────────────────────────────────────
SQL_ERRORS = [
    (r"you have an error in your sql syntax", "MySQL"),
    (r"warning: mysql_", "MySQL"),
    (r"mysql_fetch_array\(\)", "MySQL"),
    (r"mysql_num_rows\(\)", "MySQL"),
    (r"supplied argument is not a valid MySQL result", "MySQL"),
    (r"unclosed quotation mark after the character string", "MSSQL"),
    (r"microsoft OLE DB provider for ODBC drivers", "MSSQL"),
    (r"microsoft OLE DB provider for SQL Server", "MSSQL"),
    (r"\[Microsoft\]\[ODBC SQL Server Driver\]", "MSSQL"),
    (r"SQLSTATE\[", "Generic SQL"),
    (r"quoted string not properly terminated", "Oracle"),
    (r"ora-[0-9]{5}", "Oracle"),
    (r"oracle error", "Oracle"),
    (r"pg_query\(\): query failed", "PostgreSQL"),
    (r"syntax error at or near", "PostgreSQL"),
    (r"operator does not exist", "PostgreSQL"),
    (r"pg_exec\(\) query failed", "PostgreSQL"),
    (r"sqlite3::sqlexception", "SQLite"),
    (r"sqlite_error", "SQLite"),
    (r"sqlite\.exception", "SQLite"),
    (r"sql syntax.*mysql", "MySQL"),
    (r"database error", "Generic SQL"),
    (r"DB Error:", "Generic SQL"),
    (r"Warning: pg_", "PostgreSQL"),
]

# ─── Error-Based Payloads ────────────────────────────────────────────────────
ERROR_PAYLOADS = [
    "'",
    "\"",
    "1' OR '1'='1",
    "1' OR '1'='1'--",
    "1' AND 1=1--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' OR 1=1#",
    "\" OR \"\"=\"",
    "1; DROP TABLE users--",
]

# ─── Time-Based Blind Payloads (grouped by DB) ───────────────────────────────
TIME_PAYLOADS = [
    # MySQL
    ("1' AND SLEEP(4)-- -", "MySQL", 4),
    ("1 AND SLEEP(4)-- -", "MySQL", 4),
    # MSSQL
    ("1'; WAITFOR DELAY '0:0:4'--", "MSSQL", 4),
    # PostgreSQL
    ("1'; SELECT pg_sleep(4)--", "PostgreSQL", 4),
    # SQLite
    ("1' AND randomblob(100000000)='1", "SQLite", 3),
]

# ─── Boolean-Based Payload Pairs ─────────────────────────────────────────────
BOOL_PAYLOAD_PAIRS = [
    # (true_payload, false_payload)
    ("1' OR 1=1-- -", "1' OR 1=2-- -"),
    ("' OR 'a'='a", "' OR 'a'='b"),
    ("1 OR 1=1", "1 OR 1=2"),
]

# Input types to skip (non-injectable)
SKIP_INPUT_TYPES = {"submit", "button", "image", "reset", "file", "checkbox", "radio"}


def _check_sql_errors(text: str):
    """Check response text for SQL error signatures. Returns (found, db_type, evidence)."""
    for pattern, db_type in SQL_ERRORS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return True, db_type, match.group(0)
    return False, None, None


def _test_time_based(session, method, url, data, param_name, base_time, logs):
    """Test a single parameter for time-based blind SQL injection."""
    findings = []
    for payload, db_type, sleep_secs in TIME_PAYLOADS:
        test_data = data.copy()
        test_data[param_name] = payload
        try:
            start = time.time()
            if method == "POST":
                res = session.post(url, data=test_data, timeout=sleep_secs + 8, verify=False)
            else:
                res = session.get(url, params=test_data, timeout=sleep_secs + 8, verify=False)
            elapsed = time.time() - start

            # Triggered if response took significantly longer than baseline
            if elapsed >= (sleep_secs - 0.5) and elapsed > (base_time + 2.0):
                finding = {
                    "type": "SQL Injection (Time-Based Blind)",
                    "severity": "HIGH",
                    "url": url,
                    "parameter": param_name,
                    "payload": payload,
                    "database_type": db_type,
                    "evidence": f"Response delay of {elapsed:.2f}s detected (baseline: {base_time:.2f}s, expected sleep: {sleep_secs}s)",
                    "description": f"Time-based blind {db_type} SQL injection detected via parameter '{param_name}'. Response delayed by {elapsed:.2f}s."
                }
                findings.append(finding)
                logs.append(f"[WARN] Time-Based SQLi detected on {url} (Param: {param_name}, DB: {db_type}, Delay: {elapsed:.2f}s)")
                break  # One confirmed per param is enough
        except Exception as e:
            logs.append(f"[DEBUG] Time-based SQLi test error on {url} param={param_name}: {str(e)}")
    return findings


def _test_boolean_based(session, method, url, data, param_name, logs):
    """Test a single parameter for boolean-based blind SQL injection."""
    findings = []
    for true_payload, false_payload in BOOL_PAYLOAD_PAIRS:
        try:
            # True condition
            true_data = data.copy()
            true_data[param_name] = true_payload
            if method == "POST":
                true_res = session.post(url, data=true_data, timeout=8, verify=False)
            else:
                true_res = session.get(url, params=true_data, timeout=8, verify=False)

            # False condition
            false_data = data.copy()
            false_data[param_name] = false_payload
            if method == "POST":
                false_res = session.post(url, data=false_data, timeout=8, verify=False)
            else:
                false_res = session.get(url, params=false_data, timeout=8, verify=False)

            true_len = len(true_res.text)
            false_len = len(false_res.text)
            diff = abs(true_len - false_len)

            # Significant length difference suggests boolean-based injection
            if diff > 100 and true_res.status_code != false_res.status_code or diff > 500:
                finding = {
                    "type": "SQL Injection (Boolean-Based Blind)",
                    "severity": "HIGH",
                    "url": url,
                    "parameter": param_name,
                    "payload": f"TRUE: {true_payload} | FALSE: {false_payload}",
                    "database_type": "Generic SQL",
                    "evidence": f"Response length difference: {diff} bytes (true={true_len}, false={false_len})",
                    "description": f"Boolean-based blind SQL injection detected via parameter '{param_name}'. Significant response difference observed between true/false conditions."
                }
                findings.append(finding)
                logs.append(f"[WARN] Boolean-Based SQLi detected on {url} (Param: {param_name}, Diff: {diff} bytes)")
                break
        except Exception as e:
            logs.append(f"[DEBUG] Boolean-based SQLi test error on {url} param={param_name}: {str(e)}")
    return findings


def run_sql_scan(crawl_results: dict) -> dict:
    findings = []
    logs = []
    tested_combos = set()

    logs.append("[INFO] Initializing SQL Injection Vulnerability Scanner...")

    forms = crawl_results.get("forms", [])
    discovered_links = crawl_results.get("discovered_links", [])

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; WebsiteVulnerabilityScanner/2.0)"
    })

    # ── 1. Test URL Query Parameters ─────────────────────────────────────────
    for link in discovered_links:
        parsed = urlparse(link)
        if not parsed.query:
            continue

        params = parse_qs(parsed.query)
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", ""))

        # Baseline response time
        try:
            base_start = time.time()
            session.get(link, timeout=10, verify=False)
            base_time = time.time() - base_start
        except Exception:
            base_time = 1.0

        for param in params:
            combo_key = (base_url, param)
            if combo_key in tested_combos:
                continue
            tested_combos.add(combo_key)

            param_already_found = False

            # 1a. Error-based detection
            for payload in ERROR_PAYLOADS:
                if param_already_found:
                    break
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                test_query = urlencode(test_params)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, ""))
                try:
                    res = session.get(test_url, timeout=8, verify=False)
                    found, db_type, evidence = _check_sql_errors(res.text)
                    if found:
                        findings.append({
                            "type": "SQL Injection (Error-Based)",
                            "severity": "HIGH",
                            "url": link,
                            "parameter": param,
                            "payload": payload,
                            "database_type": db_type,
                            "evidence": evidence,
                            "description": f"Error-based {db_type} SQL injection via URL parameter '{param}'."
                        })
                        logs.append(f"[WARN] Error-Based SQLi on {link} (Param: {param}, DB: {db_type})")
                        param_already_found = True
                except Exception as e:
                    logs.append(f"[DEBUG] Error-based SQL test failed: {str(e)}")

            if param_already_found:
                continue

            # 1b. Time-based blind detection
            base_data = {k: v[0] for k, v in params.items()}
            time_results = _test_time_based(session, "GET", base_url, base_data, param, base_time, logs)
            findings.extend(time_results)
            if time_results:
                continue

            # 1c. Boolean-based blind detection
            bool_results = _test_boolean_based(session, "GET", base_url, base_data, param, logs)
            findings.extend(bool_results)

    # ── 2. Test Form Inputs ───────────────────────────────────────────────────
    for form in forms:
        action = form.get("action")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])

        if not action:
            continue

        # Baseline response time for this form
        try:
            base_start = time.time()
            baseline_data = {i.get("name"): i.get("value", "test") for i in inputs if i.get("name")}
            if method == "POST":
                session.post(action, data=baseline_data, timeout=10, verify=False)
            else:
                session.get(action, params=baseline_data, timeout=10, verify=False)
            base_time = time.time() - base_start
        except Exception:
            base_time = 1.0

        for inp in inputs:
            inp_name = inp.get("name")
            inp_type = (inp.get("type") or "text").lower()

            if not inp_name or inp_type in SKIP_INPUT_TYPES:
                continue

            combo_key = (action, inp_name)
            if combo_key in tested_combos:
                continue
            tested_combos.add(combo_key)

            param_already_found = False

            # Build base data with realistic values for other inputs
            def build_data(target_payload):
                d = {}
                for other in inputs:
                    n = other.get("name")
                    if not n:
                        continue
                    t = (other.get("type") or "text").lower()
                    if n == inp_name:
                        d[n] = target_payload
                    elif t == "email":
                        d[n] = "test@example.com"
                    elif t == "password":
                        d[n] = "TestPass123!"
                    else:
                        d[n] = other.get("value") or "test"
                return d

            # 2a. Error-based detection
            for payload in ERROR_PAYLOADS:
                if param_already_found:
                    break
                data = build_data(payload)
                try:
                    if method == "POST":
                        res = session.post(action, data=data, timeout=8, verify=False)
                    else:
                        res = session.get(action, params=data, timeout=8, verify=False)

                    found, db_type, evidence = _check_sql_errors(res.text)
                    if found:
                        findings.append({
                            "type": "SQL Injection (Error-Based)",
                            "severity": "HIGH",
                            "url": action,
                            "parameter": inp_name,
                            "payload": payload,
                            "database_type": db_type,
                            "evidence": evidence,
                            "description": f"Error-based {db_type} SQL injection via form input '{inp_name}' at {action}."
                        })
                        logs.append(f"[WARN] Error-Based SQLi in form at {action} (Input: {inp_name})")
                        param_already_found = True
                except Exception as e:
                    logs.append(f"[DEBUG] Error-based form SQL test failed: {str(e)}")

            if param_already_found:
                continue

            # 2b. Time-based blind detection on forms
            base_data = build_data("test")
            time_results = _test_time_based(session, method, action, base_data, inp_name, base_time, logs)
            findings.extend(time_results)
            if time_results:
                continue

            # 2c. Boolean-based blind detection on forms
            bool_results = _test_boolean_based(session, method, action, base_data, inp_name, logs)
            findings.extend(bool_results)

    logs.append(f"[INFO] SQL Injection Scan complete. {len(findings)} findings detected.")
    return {"findings": findings, "logs": logs}
