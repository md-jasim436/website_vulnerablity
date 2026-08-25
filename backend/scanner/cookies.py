import requests
import logging

logger = logging.getLogger(__name__)

def run_cookies_scan(target_url: str) -> dict:
    logs = []
    logs.append(f"[INFO] Inspecting Cookie Security Flags for {target_url}...")
    
    cookies_inspected = []
    insecure_cookies = []
    
    try:
        res = requests.get(target_url, timeout=10, verify=False, allow_redirects=True)
        cookies = res.cookies
        
        for cookie in cookies:
            is_httponly = cookie.has_nonstandard_attr('httponly') or cookie.has_nonstandard_attr('HttpOnly')
            is_secure = cookie.secure
            samesite = cookie.get_nonstandard_attr('samesite') or cookie.get_nonstandard_attr('SameSite') or "None"
            
            cookie_info = {
                "name": cookie.name,
                "domain": cookie.domain,
                "path": cookie.path,
                "httponly": is_httponly,
                "secure": is_secure,
                "samesite": samesite
            }
            cookies_inspected.append(cookie_info)
            
            missing_flags = []
            if not is_httponly:
                missing_flags.append("HttpOnly")
            if not is_secure:
                missing_flags.append("Secure")
            if str(samesite).lower() not in ["strict", "lax"]:
                missing_flags.append("SameSite (Strict/Lax)")
                
            if missing_flags:
                insecure_cookies.append({
                    "name": cookie.name,
                    "domain": cookie.domain,
                    "missing_flags": missing_flags,
                    "description": f"Cookie '{cookie.name}' is missing security flags: {', '.join(missing_flags)}."
                })
                logs.append(f"[WARN] Insecure Cookie found: '{cookie.name}' missing {', '.join(missing_flags)}")
            else:
                logs.append(f"[INFO] Cookie '{cookie.name}' has all required security flags set.")

    except Exception as e:
        logs.append(f"[ERROR] Cookie Security inspection failed: {str(e)}")

    result = {
        "inspected_count": len(cookies_inspected),
        "cookies": cookies_inspected,
        "insecure": insecure_cookies
    }
    
    logs.append(f"[INFO] Cookie Scan complete. ({len(cookies_inspected)} cookies inspected, {len(insecure_cookies)} insecure)")
    return {"result": result, "logs": logs}
