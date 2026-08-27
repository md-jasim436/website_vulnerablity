import requests
import logging

logger = logging.getLogger(__name__)

# ─── Required Security Headers ───────────────────────────────────────────────
SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS", "HIGH"),
    ("Content-Security-Policy", "CSP", "HIGH"),
    ("X-Content-Type-Options", "X-Content-Type-Options", "MEDIUM"),
    ("X-Frame-Options", "X-Frame-Options", "MEDIUM"),
    ("Referrer-Policy", "Referrer-Policy", "LOW"),
    ("Permissions-Policy", "Permissions-Policy", "LOW"),
    ("Cross-Origin-Opener-Policy", "COOP", "LOW"),
    ("Cross-Origin-Resource-Policy", "CORP", "LOW"),
]

# ─── Info-Leak Headers ───────────────────────────────────────────────────────
INFO_LEAK_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Runtime",
    "X-Generator",
    "X-Drupal-Cache",
]

# ─── Dangerous CSP Directives ────────────────────────────────────────────────
DANGEROUS_CSP_DIRECTIVES = [
    ("'unsafe-inline'", "Allows inline scripts/styles — defeats XSS protection", "HIGH"),
    ("'unsafe-eval'", "Allows eval() / Function() — enables code injection", "HIGH"),
    ("'unsafe-hashes'", "Allows hashed inline event handlers — weakens CSP", "MEDIUM"),
    ("data:", "Allows data: URIs — can be used for XSS in some browsers", "MEDIUM"),
    ("http:", "Allows loading resources over plain HTTP — allows MitM injection", "HIGH"),
    ("*", "Wildcard source — allows any origin, defeats CSP", "HIGH"),
]


def _analyze_csp(csp_value: str) -> list:
    """
    Analyze Content-Security-Policy header value for dangerous directives.
    Returns list of warning dicts.
    """
    warnings = []
    csp_lower = csp_value.lower()

    for directive, description, severity in DANGEROUS_CSP_DIRECTIVES:
        if directive.lower() in csp_lower:
            warnings.append({
                "directive": directive,
                "severity": severity,
                "description": description,
                "recommendation": f"Remove '{directive}' from your Content-Security-Policy to strengthen XSS protection."
            })

    return warnings


def run_security_headers_scan(target_url: str) -> dict:
    logs = []
    logs.append(f"[INFO] Evaluating Security Headers for {target_url}...")

    present_headers = {}
    missing_headers = []
    info_leaks = []
    csp_warnings = []

    try:
        res = requests.get(target_url, timeout=10, verify=False, allow_redirects=True)
        headers = res.headers

        # ── Check standard security headers ──────────────────────────────────
        for header_name, alias, risk in SECURITY_HEADERS:
            matched_key = next((k for k in headers if k.lower() == header_name.lower()), None)
            if matched_key:
                header_value = headers[matched_key]
                present_headers[alias] = {
                    "header": header_name,
                    "value": header_value,
                    "status": "PRESENT"
                }
                logs.append(f"[INFO] Header PRESENT: {header_name}")

                # ── CSP Quality Analysis ──────────────────────────────────────
                if header_name.lower() == "content-security-policy":
                    csp_issues = _analyze_csp(header_value)
                    if csp_issues:
                        csp_warnings.extend(csp_issues)
                        for issue in csp_issues:
                            logs.append(
                                f"[WARN] CSP Weakness: '{issue['directive']}' found in CSP — {issue['description']} (Risk: {issue['severity']})"
                            )
                    else:
                        logs.append("[INFO] CSP appears well-configured. No dangerous directives detected.")

            else:
                missing_headers.append({
                    "header": header_name,
                    "alias": alias,
                    "risk": risk,
                    "status": "MISSING",
                    "recommendation": f"Configure the '{header_name}' response header to improve security posture."
                })
                logs.append(f"[WARN] Header MISSING: {header_name} (Risk Impact: {risk})")

        # ── Check information leakage headers ─────────────────────────────────
        for info_header in INFO_LEAK_HEADERS:
            matched_key = next((k for k in headers if k.lower() == info_header.lower()), None)
            if matched_key:
                info_leaks.append({
                    "header": info_header,
                    "value": headers[matched_key],
                    "severity": "MEDIUM",
                    "recommendation": f"Remove or obfuscate the '{info_header}' header to prevent server fingerprinting."
                })
                logs.append(f"[WARN] Server Info Leak: {info_header}={headers[matched_key]}")

    except Exception as e:
        logs.append(f"[ERROR] Security Headers check failed for {target_url}: {str(e)}")

    result = {
        "present": present_headers,
        "missing": missing_headers,
        "info_leaks": info_leaks,
        "csp_warnings": csp_warnings,
    }

    logs.append(
        f"[INFO] Security Headers Scan complete. "
        f"({len(present_headers)} present, {len(missing_headers)} missing, "
        f"{len(info_leaks)} info leaks, {len(csp_warnings)} CSP warnings)"
    )
    return {"result": result, "logs": logs}
