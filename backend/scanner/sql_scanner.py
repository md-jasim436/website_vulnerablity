import re
import requests
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger(__name__)

# Common SQL Error Signatures
SQL_ERRORS = [
    (r"you have an error in your sql syntax", "MySQL"),
    (r"warning: mysql_", "MySQL"),
    (r"unclosed quotation mark after the character string", "MSSQL"),
    (r"quoted string not properly terminated", "Oracle"),
    (r"pg_query\(\): query failed", "PostgreSQL"),
    (r"sqlite3::sqlexception", "SQLite"),
    (r"sqlite_error", "SQLite"),
    (r"syntax error at or near", "PostgreSQL"),
    (r"operator does not exist", "PostgreSQL"),
    (r"ora-[0-9]{5}", "Oracle"),
    (r"microsoft OLE DB provider for ODBC drivers", "MSSQL")
]

PAYLOADS = ["'", "\"", "1' OR '1'='1", "1' AND 1=1 --", "' UNION SELECT NULL--"]

def run_sql_scan(crawl_results: dict) -> dict:
    findings = []
    logs = []
    
    logs.append("[INFO] Initializing SQL Injection Vulnerability Scanner...")
    
    forms = crawl_results.get("forms", [])
    query_params = crawl_results.get("query_params", [])
    discovered_links = crawl_results.get("discovered_links", [])
    
    session = requests.Session()
    session.headers.update({"User-Agent": "WebsiteVulnerabilityScanner/1.0"})
    
    # 1. Test Query Parameters in URLs
    tested_params = set()
    for link in discovered_links:
        parsed = urlparse(link)
        if not parsed.query:
            continue
            
        params = parse_qs(parsed.query)
        for param in params:
            param_key = (link.split('?')[0], param)
            if param_key in tested_params:
                continue
            tested_params.add(param_key)
            
            for payload in PAYLOADS:
                test_params = params.copy()
                test_params[param] = payload
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))
                
                try:
                    res = session.get(test_url, timeout=7, verify=False)
                    for pattern, db_type in SQL_ERRORS:
                        if re.search(pattern, res.text, re.IGNORECASE):
                            evidence = re.search(pattern, res.text, re.IGNORECASE).group(0)
                            finding = {
                                "type": "SQL Injection",
                                "severity": "HIGH",
                                "url": link,
                                "parameter": param,
                                "payload": payload,
                                "database_type": db_type,
                                "evidence": evidence,
                                "description": f"Possible {db_type} SQL Injection detected via query parameter '{param}'."
                            }
                            findings.append(finding)
                            logs.append(f"[WARN] SQL Injection detected on {link} (Param: {param}, DB: {db_type})")
                            break
                    if findings and findings[-1]["url"] == link and findings[-1]["parameter"] == param:
                        break
                except Exception as e:
                    logs.append(f"[DEBUG] Error testing SQL payload on {test_url}: {str(e)}")

    # 2. Test Form Inputs
    for form in forms:
        action = form.get("action")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])
        
        for inp in inputs:
            inp_name = inp.get("name")
            if not inp_name or inp.get("type") in ["submit", "button", "hidden"]:
                continue
                
            for payload in PAYLOADS:
                data = {}
                for other_inp in inputs:
                    name = other_inp.get("name")
                    if not name:
                        continue
                    data[name] = payload if name == inp_name else "test"
                    
                try:
                    if method == "POST":
                        res = session.post(action, data=data, timeout=7, verify=False)
                    else:
                        res = session.get(action, params=data, timeout=7, verify=False)
                        
                    for pattern, db_type in SQL_ERRORS:
                        if re.search(pattern, res.text, re.IGNORECASE):
                            evidence = re.search(pattern, res.text, re.IGNORECASE).group(0)
                            finding = {
                                "type": "SQL Injection",
                                "severity": "HIGH",
                                "url": action,
                                "parameter": inp_name,
                                "payload": payload,
                                "database_type": db_type,
                                "evidence": evidence,
                                "description": f"Possible {db_type} SQL Injection detected in form input '{inp_name}' at {action}."
                            }
                            findings.append(finding)
                            logs.append(f"[WARN] SQL Injection detected in form at {action} (Input: {inp_name})")
                            break
                    if findings and findings[-1]["url"] == action and findings[-1]["parameter"] == inp_name:
                        break
                except Exception as e:
                    logs.append(f"[DEBUG] Error testing SQL payload on form {action}: {str(e)}")

    logs.append(f"[INFO] SQL Injection Scan complete. {len(findings)} findings detected.")
    return {"findings": findings, "logs": logs}
