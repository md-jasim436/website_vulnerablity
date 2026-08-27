import logging

logger = logging.getLogger(__name__)


class RiskEngine:
    """
    Calculates a comprehensive risk level and numeric risk score
    based on aggregated scan findings across all scanner modules.

    Risk Levels: HIGH (score ≥ 70) | MEDIUM (score 30–69) | LOW (score < 30)
    Risk Score:  0–100 numeric score for granular comparison
    """

    @staticmethod
    def calculate_risk(findings: dict) -> dict:
        sql_findings   = findings.get("sql", [])
        xss_findings   = findings.get("xss", [])
        https_data     = findings.get("https", {})
        headers_data   = findings.get("headers", {})
        cookies_data   = findings.get("cookies", {})

        risk_score = 0
        risk_factors = []
        force_high = False  # SQLi/XSS always forces HIGH regardless of score

        # ── Critical: SQLi / XSS Findings ───────────────────────────────────
        if sql_findings:
            # Any SQL injection = immediately HIGH risk
            sql_score = min(40, 30 + len(sql_findings) * 5)
            risk_score += sql_score
            force_high = True
            risk_factors.append({
                "category": "SQL Injection",
                "severity": "CRITICAL",
                "score": sql_score,
                "detail": f"{len(sql_findings)} SQL injection finding(s) detected."
            })

        if xss_findings:
            # Any XSS = HIGH risk (score pushes above 70 threshold)
            xss_score = min(40, 30 + len(xss_findings) * 5)
            risk_score += xss_score
            force_high = True
            risk_factors.append({
                "category": "Cross-Site Scripting (XSS)",
                "severity": "HIGH",
                "score": xss_score,
                "detail": f"{len(xss_findings)} reflected XSS finding(s) detected."
            })

        # ── High: No HTTPS / Invalid SSL ─────────────────────────────────────
        is_https = https_data.get("is_https", True)
        cert_valid = https_data.get("certificate_valid", True)

        if not is_https:
            risk_score += 25
            risk_factors.append({
                "category": "Missing HTTPS",
                "severity": "HIGH",
                "score": 25,
                "detail": "Target is served over plain HTTP. All traffic is unencrypted."
            })
        elif not cert_valid:
            risk_score += 15
            risk_factors.append({
                "category": "Invalid SSL Certificate",
                "severity": "HIGH",
                "score": 15,
                "detail": "SSL certificate is invalid, self-signed, or expired."
            })

        # ── Medium: No HTTP→HTTPS redirect ────────────────────────────────────
        redirects_to_https = https_data.get("redirects_to_https", True)
        if is_https and not redirects_to_https:
            risk_score += 8
            risk_factors.append({
                "category": "HTTPS Redirect Not Enforced",
                "severity": "MEDIUM",
                "score": 8,
                "detail": "Site uses HTTPS but does not redirect plain HTTP requests to HTTPS."
            })

        # ── Missing Security Headers ──────────────────────────────────────────
        missing_headers = headers_data.get("missing", [])
        high_missing = [h for h in missing_headers if h.get("risk") == "HIGH"]
        medium_missing = [h for h in missing_headers if h.get("risk") == "MEDIUM"]

        if high_missing:
            h_score = min(20, len(high_missing) * 8)
            risk_score += h_score
            names = ", ".join(h["header"] for h in high_missing)
            risk_factors.append({
                "category": "Missing Critical Security Headers",
                "severity": "HIGH",
                "score": h_score,
                "detail": f"Missing headers: {names}"
            })

        if medium_missing:
            m_score = min(10, len(medium_missing) * 4)
            risk_score += m_score
            names = ", ".join(h["header"] for h in medium_missing)
            risk_factors.append({
                "category": "Missing Recommended Security Headers",
                "severity": "MEDIUM",
                "score": m_score,
                "detail": f"Missing headers: {names}"
            })

        # ── CSP Weakness (present but dangerous directives) ───────────────────
        csp_warnings = headers_data.get("csp_warnings", [])
        high_csp = [w for w in csp_warnings if w.get("severity") == "HIGH"]
        medium_csp = [w for w in csp_warnings if w.get("severity") == "MEDIUM"]

        if high_csp:
            csp_score = min(15, len(high_csp) * 6)
            risk_score += csp_score
            directives = ", ".join(w["directive"] for w in high_csp)
            risk_factors.append({
                "category": "Weak Content Security Policy (CSP)",
                "severity": "HIGH",
                "score": csp_score,
                "detail": f"CSP contains dangerous directive(s): {directives}"
            })
        elif medium_csp:
            csp_score = min(6, len(medium_csp) * 3)
            risk_score += csp_score
            directives = ", ".join(w["directive"] for w in medium_csp)
            risk_factors.append({
                "category": "Weak Content Security Policy (CSP)",
                "severity": "MEDIUM",
                "score": csp_score,
                "detail": f"CSP contains potentially dangerous directive(s): {directives}"
            })

        # ── Server Info Leaks ─────────────────────────────────────────────────
        info_leaks = headers_data.get("info_leaks", [])
        if info_leaks:
            leak_score = min(8, len(info_leaks) * 3)
            risk_score += leak_score
            headers_leaked = ", ".join(f"{l['header']}: {l['value']}" for l in info_leaks)
            risk_factors.append({
                "category": "Server Information Disclosure",
                "severity": "MEDIUM",
                "score": leak_score,
                "detail": f"Server headers leaking technology info: {headers_leaked}"
            })

        # ── Insecure Cookies ──────────────────────────────────────────────────
        insecure_cookies = cookies_data.get("insecure", [])
        if insecure_cookies:
            cookie_score = min(10, len(insecure_cookies) * 4)
            risk_score += cookie_score
            risk_factors.append({
                "category": "Insecure Cookie Configuration",
                "severity": "MEDIUM",
                "score": cookie_score,
                "detail": f"{len(insecure_cookies)} cookie(s) missing HttpOnly/Secure/SameSite flags."
            })

        # ── Clamp score to 0–100 and assign label ─────────────────────────────
        risk_score = min(100, max(0, risk_score))

        if force_high or risk_score >= 70:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        logger.info(f"Risk Engine: score={risk_score}, level={risk_level}, factors={len(risk_factors)}")

        return {
            "level": risk_level,
            "score": risk_score,
            "factors": risk_factors,
        }


def calculate_risk(findings: dict):
    """
    Public interface. Returns a dict with:
      - level: "HIGH" | "MEDIUM" | "LOW"
      - score: int 0-100
      - factors: list of contributing risk factors
    For backward compatibility, also returns the level string when accessed as a string.
    """
    return RiskEngine.calculate_risk(findings)
