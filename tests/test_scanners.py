import pytest
from backend.risk_engine import calculate_risk
from backend.scanner.security_headers import run_security_headers_scan
from backend.scanner.cookies import run_cookies_scan
from backend.scanner.https_checker import run_https_check

def test_risk_engine_high_risk_sqli():
    findings = {
        "sql": [{"type": "SQL Injection", "severity": "HIGH"}],
        "xss": [],
        "https": {"is_https": True},
        "headers": {"missing": []},
        "cookies": {"insecure": []}
    }
    result = calculate_risk(findings)
    assert result["level"] == "HIGH"

def test_risk_engine_high_risk_xss():
    findings = {
        "sql": [],
        "xss": [{"type": "Reflected XSS", "severity": "HIGH"},
                {"type": "Reflected XSS", "severity": "HIGH"},
                {"type": "Reflected XSS", "severity": "HIGH"},
                {"type": "Reflected XSS", "severity": "HIGH"},
                {"type": "Reflected XSS", "severity": "HIGH"}],
        "https": {"is_https": True},
        "headers": {"missing": []},
        "cookies": {"insecure": []}
    }
    result = calculate_risk(findings)
    assert result["level"] == "HIGH"

def test_risk_engine_medium_risk_http():
    findings = {
        "sql": [],
        "xss": [],
        "https": {"is_https": False},
        "headers": {"missing": []},
        "cookies": {"insecure": []}
    }
    result = calculate_risk(findings)
    assert result["level"] == "MEDIUM"

def test_risk_engine_low_risk_clean():
    findings = {
        "sql": [],
        "xss": [],
        "https": {"is_https": True},
        "headers": {"missing": [{"header": "Permissions-Policy", "risk": "LOW"}]},
        "cookies": {"insecure": []}
    }
    result = calculate_risk(findings)
    assert result["level"] == "LOW"

def test_security_headers_structure():
    res = run_security_headers_scan("https://example.com")
    assert "result" in res
    assert "logs" in res
    assert "present" in res["result"]
    assert "missing" in res["result"]
    assert "info_leaks" in res["result"]

def test_cookies_scan_structure():
    res = run_cookies_scan("https://example.com")
    assert "result" in res
    assert "logs" in res
    assert "cookies" in res["result"]
    assert "insecure" in res["result"]

def test_https_check_structure():
    res = run_https_check("https://example.com")
    assert "result" in res
    assert "logs" in res
    assert "is_https" in res["result"]
    assert "certificate_valid" in res["result"]
