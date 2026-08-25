import requests
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger(__name__)

XSS_PAYLOADS = [
    '<script>alert("xss_test_marker")</script>',
    '"><script>alert("xss_test_marker")</script>',
    '"><svg/onload=alert("xss_test_marker")>',
    '"><img src=x onerror=alert("xss_test_marker")>'
]

MARKER = "xss_test_marker"

def run_xss_scan(crawl_results: dict) -> dict:
    findings = []
    logs = []
    
    logs.append("[INFO] Initializing Reflected XSS Vulnerability Scanner...")
    
    forms = crawl_results.get("forms", [])
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
            
            for payload in XSS_PAYLOADS:
                test_params = params.copy()
                test_params[param] = payload
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))
                
                try:
                    res = session.get(test_url, timeout=7, verify=False)
                    if MARKER in res.text and payload in res.text:
                        finding = {
                            "type": "Reflected XSS",
                            "severity": "MEDIUM",
                            "url": link,
                            "parameter": param,
                            "payload": payload,
                            "description": f"Reflected XSS vulnerability detected via URL parameter '{param}'."
                        }
                        findings.append(finding)
                        logs.append(f"[WARN] Reflected XSS detected on {link} (Param: {param})")
                        break
                except Exception as e:
                    logs.append(f"[DEBUG] Error testing XSS on {test_url}: {str(e)}")

    # 2. Test Form Inputs
    for form in forms:
        action = form.get("action")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])
        
        for inp in inputs:
            inp_name = inp.get("name")
            if not inp_name or inp.get("type") in ["submit", "button", "hidden"]:
                continue
                
            for payload in XSS_PAYLOADS:
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
                        
                    if MARKER in res.text and payload in res.text:
                        finding = {
                            "type": "Reflected XSS",
                            "severity": "MEDIUM",
                            "url": action,
                            "parameter": inp_name,
                            "payload": payload,
                            "description": f"Reflected XSS vulnerability detected in form input '{inp_name}' at {action}."
                        }
                        findings.append(finding)
                        logs.append(f"[WARN] Reflected XSS detected in form at {action} (Input: {inp_name})")
                        break
                except Exception as e:
                    logs.append(f"[DEBUG] Error testing XSS on form {action}: {str(e)}")

    logs.append(f"[INFO] Reflected XSS Scan complete. {len(findings)} findings detected.")
    return {"findings": findings, "logs": logs}
