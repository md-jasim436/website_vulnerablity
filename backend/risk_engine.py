import logging

logger = logging.getLogger(__name__)

class RiskEngine:
    @staticmethod
    def calculate_risk(findings: dict) -> str:
        """
        Calculates system-wide risk level (HIGH, MEDIUM, LOW) based on aggregated scan findings.
        """
        sql_findings = findings.get("sql", [])
        xss_findings = findings.get("xss", [])
        https_data = findings.get("https", {})
        headers_data = findings.get("headers", {})
        cookies_data = findings.get("cookies", {})

        has_sqli = len(sql_findings) > 0
        has_xss = len(xss_findings) > 0
        is_http = not https_data.get("is_https", True)
        missing_headers_count = len(headers_data.get("missing", []))
        insecure_cookies_count = len(cookies_data.get("insecure", []))

        # Risk scoring evaluation matrix
        if has_sqli or has_xss:
            return "HIGH"
        elif is_http or missing_headers_count >= 3 or insecure_cookies_count >= 2:
            return "MEDIUM"
        else:
            return "LOW"

def calculate_risk(findings: dict) -> str:
    return RiskEngine.calculate_risk(findings)
