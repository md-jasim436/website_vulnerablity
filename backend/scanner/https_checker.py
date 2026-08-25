import ssl
import socket
import requests
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

def run_https_check(target_url: str) -> dict:
    logs = []
    logs.append(f"[INFO] Initializing HTTPS & TLS Security Checker for {target_url}...")
    
    parsed = urlparse(target_url)
    is_https_scheme = parsed.scheme.lower() == "https"
    hostname = parsed.hostname
    port = parsed.port or (443 if is_https_scheme else 80)
    
    certificate_valid = False
    cert_details = {}
    redirects_to_https = False
    
    # 1. Check HTTP to HTTPS Redirect if initial scheme is http
    if not is_https_scheme:
        logs.append(f"[WARN] Target URL scheme is HTTP: {target_url}")
        try:
            res = requests.get(target_url, allow_redirects=True, timeout=7)
            if urlparse(res.url).scheme.lower() == "https":
                redirects_to_https = True
                logs.append(f"[INFO] Target automatically redirects to HTTPS: {res.url}")
            else:
                logs.append(f"[WARN] Target does NOT enforce HTTPS redirection!")
        except Exception as e:
            logs.append(f"[WARN] Failed to test HTTP redirect: {str(e)}")

    # 2. Check SSL Certificate if hostname is reachable via SSL
    if hostname:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=7) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    certificate_valid = True
                    cert_details = {
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "version": cert.get("version"),
                        "notBefore": cert.get("notBefore"),
                        "notAfter": cert.get("notAfter")
                    }
                    logs.append(f"[INFO] SSL Certificate verified for {hostname}")
        except Exception as e:
            logs.append(f"[WARN] SSL Certificate validation failed for {hostname}: {str(e)}")
            certificate_valid = False

    result = {
        "target_url": target_url,
        "is_https": is_https_scheme or certificate_valid,
        "certificate_valid": certificate_valid,
        "redirects_to_https": redirects_to_https,
        "cert_details": cert_details
    }
    
    logs.append(f"[INFO] HTTPS Check complete. (Is HTTPS: {result['is_https']}, SSL Valid: {certificate_valid})")
    return {"result": result, "logs": logs}
