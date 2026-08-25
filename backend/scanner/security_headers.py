import requests
import logging

logger = logging.getLogger(__name__)

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS", "HIGH"),
    ("Content-Security-Policy", "CSP", "HIGH"),
    ("X-Content-Type-Options", "X-Content-Type-Options", "MEDIUM"),
    ("X-Frame-Options", "X-Frame-Options", "MEDIUM"),
    ("Referrer-Policy", "Referrer-Policy", "LOW"),
    ("Permissions-Policy", "Permissions-Policy", "LOW")
]

INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]

def run_security_headers_scan(target_url: str) -> dict:
    logs = []
    logs.append(f"[INFO] Evaluating Security Headers for {target_url}...")
    
    present_headers = {}
    missing_headers = []
    info_leaks = []
    
    try:
        res = requests.get(target_url, timeout=10, verify=False, allow_redirects=True)
        headers = res.headers
        
        # Check standard security headers
        for header_name, alias, risk in SECURITY_HEADERS:
            matched_key = next((k for k in headers if k.lower() == header_name.lower()), None)
            if matched_key:
                present_headers[alias] = {
                    "header": header_name,
                    "value": headers[matched_key],
                    "status": "PRESENT"
                }
                logs.append(f"[INFO] Header PRESENT: {header_name}")
            else:
                missing_headers.append({
                    "header": header_name,
                    "alias": alias,
                    "risk": risk,
                    "status": "MISSING",
                    "recommendation": f"Configure {header_name} response header."
                })
                logs.append(f"[WARN] Header MISSING: {header_name} (Risk Impact: {risk})")

        # Check information leakage headers
        for info_header in INFO_LEAK_HEADERS:
            matched_key = next((k for k in headers if k.lower() == info_header.lower()), None)
            if matched_key:
                info_leaks.append({
                    "header": info_header,
                    "value": headers[matched_key],
                    "recommendation": f"Remove or obfuscate {info_header} header to prevent server info disclosure."
                })
                logs.append(f"[WARN] Server Info Leak Header Found: {info_header}={headers[matched_key]}")

    except Exception as e:
        logs.append(f"[ERROR] Security Headers check failed for {target_url}: {str(e)}")

    result = {
        "present": present_headers,
        "missing": missing_headers,
        "info_leaks": info_leaks
    }
    
    logs.append(f"[INFO] Security Headers Scan complete. ({len(present_headers)} present, {len(missing_headers)} missing)")
    return {"result": result, "logs": logs}
